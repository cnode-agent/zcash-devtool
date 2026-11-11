//! Durable, fenced single-flight for final epoch evidence. Only short SQL
//! statements own the writer lock; a heartbeat renews ownership while proving.

use crate::control::Control;
use anyhow::{Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::mpsc,
    thread,
    time::Duration,
};

const LEASE_SECONDS: u64 = 30;

/// Includes the resolved Tachyon/Ragu revisions (and every other locked input).
/// Changing the cache schema or dependency lock cannot silently reuse evidence.
pub fn namespace(network: &str) -> String {
    hex::encode(
        Sha256::new()
            .chain_update(b"epoch-buckets-v2\0")
            .chain_update(network)
            .chain_update(include_str!("../../../Cargo.lock"))
            .finalize(),
    )
}

pub struct Cache {
    path: PathBuf,
    conn: Connection,
}
#[derive(Clone)]
pub struct Key {
    pub namespace: String,
    pub epoch: u32,
    pub depth: u32,
    pub bits: u32,
    pub context: String,
    pub generation: i64,
}
pub type Payload = (Vec<u8>, Vec<u8>);

impl Cache {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS evidence_generation(id INTEGER PRIMARY KEY CHECK(id=1), value INTEGER NOT NULL);
            INSERT OR IGNORE INTO evidence_generation VALUES(1,0);
            CREATE TABLE IF NOT EXISTS completed_epochs(
                namespace TEXT NOT NULL,epoch INTEGER NOT NULL,generation INTEGER NOT NULL,
                first_hash TEXT NOT NULL,next_hash TEXT NOT NULL,context TEXT NOT NULL,profiles INTEGER NOT NULL CHECK(profiles>0),
                PRIMARY KEY(namespace,epoch));
            CREATE TABLE IF NOT EXISTS bucket_jobs(
                namespace TEXT NOT NULL, epoch INTEGER NOT NULL, depth INTEGER NOT NULL, bits INTEGER NOT NULL,
                context TEXT NOT NULL, generation INTEGER NOT NULL,
                owner TEXT, expires INTEGER NOT NULL DEFAULT 0, pcd BLOB, members BLOB,
                PRIMARY KEY(namespace,epoch,depth,bits,context),
                CHECK((pcd IS NULL) = (members IS NULL)));")?;
        Ok(Self {
            path: path.into(),
            conn,
        })
    }
    pub fn generation(&self) -> Result<i64> {
        Ok(self.conn.query_row(
            "SELECT value FROM evidence_generation WHERE id=1",
            [],
            |r| r.get(0),
        )?)
    }
    pub fn invalidate(&self) -> Result<()> {
        // Fence all active builders before removing evidence; an old process
        // cannot renew or publish even if it finishes after this transaction.
        self.conn.execute_batch(
            "BEGIN IMMEDIATE;
            UPDATE evidence_generation SET value=value+1 WHERE id=1;
            DELETE FROM bucket_jobs;
            DELETE FROM completed_epochs;
            COMMIT;",
        )?;
        Ok(())
    }
    /// This is a completion receipt, not a proof cache hit: no proof bytes are
    /// returned. Payments still verify every proof they load. Keeping receipts
    /// makes each new boundary prewarm incremental across long-lived networks.
    pub fn completed_epoch(
        &self,
        namespace: &str,
        epoch: u32,
        first_hash: &str,
        next_hash: &str,
    ) -> Result<Option<u32>> {
        Ok(self.conn.query_row("SELECT profiles FROM completed_epochs e WHERE namespace=?1 AND epoch=?2
            AND first_hash=?3 AND next_hash=?4 AND generation=(SELECT value FROM evidence_generation WHERE id=1)
            AND profiles>0 AND profiles=(SELECT count(*) FROM bucket_jobs j WHERE j.namespace=e.namespace AND j.epoch=e.epoch
                AND j.context=e.context AND j.generation=e.generation AND j.pcd IS NOT NULL)",
            params![namespace,epoch,first_hash,next_hash],|r|r.get(0)).optional()?)
    }
    pub fn complete_epoch(
        &self,
        key: &Key,
        first_hash: &str,
        next_hash: &str,
        profiles: u32,
    ) -> Result<()> {
        ensure!(self.conn.execute("INSERT INTO completed_epochs(namespace,epoch,generation,first_hash,next_hash,context,profiles)
            SELECT ?1,?2,?3,?4,?5,?6,?7 WHERE (SELECT value FROM evidence_generation WHERE id=1)=?3
            AND (SELECT count(*) FROM bucket_jobs WHERE namespace=?1 AND epoch=?2 AND generation=?3 AND context=?6 AND pcd IS NOT NULL)=?7
            ON CONFLICT(namespace,epoch) DO UPDATE SET generation=excluded.generation,first_hash=excluded.first_hash,
                next_hash=excluded.next_hash,context=excluded.context,profiles=excluded.profiles",
            params![key.namespace,key.epoch,key.generation,first_hash,next_hash,key.context,profiles])? == 1,
            "epoch evidence changed before completion");
        Ok(())
    }
    pub fn load(&self, key: &Key) -> Result<Option<Payload>> {
        ensure!(
            self.generation()? == key.generation,
            "epoch evidence invalidated by reorg"
        );
        Ok(self.conn.query_row("SELECT pcd,members FROM bucket_jobs WHERE
            namespace=?1 AND epoch=?2 AND depth=?3 AND bits=?4 AND context=?5 AND generation=?6 AND pcd IS NOT NULL",
            params![key.namespace,key.epoch,key.depth,key.bits,key.context,key.generation],
            |r| Ok((r.get(0)?,r.get(1)?))).optional()?)
    }
    pub fn reject(&self, key: &Key, payload: &Payload) -> Result<()> {
        // Compare the bytes, so rejecting an old read cannot erase a replacement.
        self.conn.execute(
            "DELETE FROM bucket_jobs WHERE namespace=?1 AND epoch=?2 AND depth=?3 AND bits=?4
            AND context=?5 AND generation=?6 AND pcd=?7 AND members=?8",
            params![
                key.namespace,
                key.epoch,
                key.depth,
                key.bits,
                key.context,
                key.generation,
                payload.0,
                payload.1
            ],
        )?;
        Ok(())
    }
    pub fn claim(&self, key: &Key) -> Result<Option<Lease>> {
        ensure!(
            self.generation()? == key.generation,
            "epoch evidence invalidated by reorg"
        );
        let owner = hex::encode(crate::note::random_seed());
        let changed = self.conn.execute("INSERT INTO bucket_jobs(namespace,epoch,depth,bits,context,generation,owner,expires)
            SELECT ?1,?2,?3,?4,?5,?6,?7,unixepoch()+?8 WHERE (SELECT value FROM evidence_generation WHERE id=1)=?6
            ON CONFLICT(namespace,epoch,depth,bits,context) DO UPDATE SET owner=excluded.owner,expires=excluded.expires,generation=excluded.generation
            WHERE bucket_jobs.pcd IS NULL AND bucket_jobs.expires<=unixepoch()",
            params![key.namespace,key.epoch,key.depth,key.bits,key.context,key.generation,owner,LEASE_SECONDS])?;
        if changed == 0 {
            return Ok(None);
        }
        let (stop, receiver) = mpsc::channel();
        let path = self.path.clone();
        let heartbeat_key = key.clone();
        let heartbeat_owner = owner.clone();
        let heartbeat = thread::spawn(move || {
            let conn = match Connection::open(path) {
                Ok(conn) => conn,
                Err(error) => {
                    eprintln!("epoch evidence heartbeat could not open database: {error}");
                    return;
                }
            };
            let _ = conn.busy_timeout(Duration::from_millis(500));
            let normal_interval = Duration::from_secs(LEASE_SECONDS / 3);
            let mut interval = normal_interval;
            while receiver
                .recv_timeout(interval)
                .is_err_and(|e| e == mpsc::RecvTimeoutError::Timeout)
            {
                match renew(&conn, &heartbeat_key, &heartbeat_owner) {
                    Ok(1) => {
                        interval = normal_interval;
                    }
                    Ok(_) => {
                        eprintln!("epoch evidence lease expired or invalidated during proving");
                        break;
                    }
                    // Short contention is expected while other processes save
                    // nodes. Retry only SQLite's busy/locked condition, within
                    // the existing lease; never renew an expired ownership token.
                    Err(rusqlite::Error::SqliteFailure(error, _))
                        if matches!(
                            error.code,
                            rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                        ) =>
                    {
                        interval = Duration::from_millis(250);
                    }
                    Err(error) => {
                        eprintln!("epoch evidence heartbeat failed: {error}");
                        break;
                    }
                }
            }
        });
        Ok(Some(Lease {
            path: self.path.clone(),
            key: key.clone(),
            owner,
            stop,
            heartbeat: Some(heartbeat),
        }))
    }
    /// Verify on every load, including after waiting for another process. A
    /// malformed row is a miss, never permission to return an unverified proof.
    pub fn get_or_build<T>(
        &self,
        key: &Key,
        control: &Control,
        mut verify: impl FnMut(&Payload) -> Result<Option<T>>,
        build: impl FnOnce() -> Result<Payload>,
    ) -> Result<T> {
        loop {
            control.check()?;
            if let Some(payload) = self.load(key)? {
                if let Some(value) = verify(&payload)? {
                    control.record_cache(
                        "bucket",
                        true,
                        (payload.0.len() + payload.1.len()) as u64,
                    );
                    ensure!(
                        self.generation()? == key.generation,
                        "epoch evidence invalidated during verification"
                    );
                    return Ok(value);
                }
                self.reject(key, &payload)?;
            }
            if let Some(lease) = self.claim(key)? {
                control.record_cache("bucket", false, 0);
                let payload = build()?;
                let value = verify(&payload)?
                    .ok_or_else(|| anyhow::anyhow!("built epoch evidence failed verification"))?;
                lease.publish(&payload)?;
                return Ok(value);
            }
            control.stage(format!(
                "Waiting for epoch {} profile {}/{} evidence…",
                key.epoch, key.depth, key.bits
            ))?;
            thread::sleep(Duration::from_millis(100));
        }
    }
}
fn renew(conn: &Connection, key: &Key, owner: &str) -> rusqlite::Result<usize> {
    conn.execute("UPDATE bucket_jobs SET expires=unixepoch()+?8 WHERE namespace=?1 AND epoch=?2 AND depth=?3 AND bits=?4
        AND context=?5 AND generation=?6 AND owner=?7 AND pcd IS NULL AND expires>unixepoch()
        AND (SELECT value FROM evidence_generation WHERE id=1)=?6",
        params![key.namespace,key.epoch,key.depth,key.bits,key.context,key.generation,owner,LEASE_SECONDS])
}
pub struct Lease {
    path: PathBuf,
    key: Key,
    owner: String,
    stop: mpsc::Sender<()>,
    heartbeat: Option<thread::JoinHandle<()>>,
}
impl Lease {
    pub fn publish(&self, payload: &Payload) -> Result<()> {
        let conn = Connection::open(&self.path)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        let k = &self.key;
        ensure!(conn.execute("UPDATE bucket_jobs SET pcd=?8,members=?9,owner=NULL,expires=0
            WHERE namespace=?1 AND epoch=?2 AND depth=?3 AND bits=?4 AND context=?5 AND generation=?6 AND owner=?7
            AND expires>unixepoch() AND (SELECT value FROM evidence_generation WHERE id=1)=?6",
            params![k.namespace,k.epoch,k.depth,k.bits,k.context,k.generation,self.owner,payload.0,payload.1])? == 1,
            "epoch evidence lease expired or was invalidated; refusing stale proof publication");
        Ok(())
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(thread) = self.heartbeat.take() {
            let _ = thread.join();
        }
        if let Ok(conn) = Connection::open(&self.path) {
            let _ = conn.busy_timeout(Duration::from_secs(5));
            let _ = conn.execute(
                "DELETE FROM bucket_jobs WHERE owner=? AND pcd IS NULL",
                [&self.owner],
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    fn key(cache: &Cache, bits: u32) -> Result<Key> {
        Ok(Key {
            namespace: namespace("test-network"),
            epoch: 17,
            depth: 3,
            bits,
            context: "canonical-members-and-anchors".into(),
            generation: cache.generation()?,
        })
    }
    fn verified(payload: &Payload) -> Result<Option<Vec<u8>>> {
        Ok((payload.0 == b"verified" && payload.1 == b"members").then(|| payload.0.clone()))
    }
    fn payload() -> Payload {
        (b"verified".to_vec(), b"members".to_vec())
    }
    #[test]
    #[ignore = "invoked in separate processes by the concurrency/crash tests"]
    fn child() -> Result<()> {
        let path = PathBuf::from(std::env::var_os("EVIDENCE_TEST_DB").unwrap());
        let cache = Cache::open(&path)?;
        if std::env::var_os("EVIDENCE_TEST_CRASH").is_some() {
            let _lease = cache.claim(&key(&cache, 0)?)?.unwrap();
            // A real process exit, without dropping the lease or running cleanup.
            std::process::exit(17);
        }
        for bits in 0..7 {
            let k = key(&cache, bits)?;
            cache.get_or_build(&k, &Control::new(true), verified, || {
                cache.conn.execute("INSERT INTO builds VALUES(?)", [bits])?;
                thread::sleep(Duration::from_millis(40));
                Ok(payload())
            })?;
        }
        Ok(())
    }
    fn child_command(path: &Path) -> Result<Command> {
        let mut cmd = Command::new(std::env::current_exe()?);
        cmd.args(["--exact", "evidence::tests::child", "--ignored"])
            .env("EVIDENCE_TEST_DB", path)
            .stdout(Stdio::null());
        Ok(cmd)
    }
    #[test]
    fn seventeen_processes_four_workers_build_each_profile_once() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("cache.sqlite");
        let cache = Cache::open(&path)?;
        cache
            .conn
            .execute("CREATE TABLE builds(bits INTEGER)", [])?;
        for group in (0..17).step_by(4) {
            let mut children = Vec::new();
            for _ in group..(group + 4).min(17) {
                children.push(child_command(&path)?.spawn()?);
            }
            for mut child in children {
                ensure!(child.wait()?.success(), "cache child failed");
            }
        }
        let counts: Vec<(u32, u32)> = cache
            .conn
            .prepare("SELECT bits,count(*) FROM builds GROUP BY bits ORDER BY bits")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        assert_eq!(counts, (0..7).map(|b| (b, 1)).collect::<Vec<_>>());
        Ok(())
    }
    #[test]
    fn crash_stale_lease_corruption_and_reorg_are_recoverable() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("cache.sqlite");
        let cache = Cache::open(&path)?;
        assert_eq!(
            child_command(&path)?
                .env("EVIDENCE_TEST_CRASH", "1")
                .status()?
                .code(),
            Some(17)
        );
        let k = key(&cache, 0)?;
        assert!(cache.claim(&k)?.is_none());
        // Advance the durable lease clock without a 30-second sleep in the test.
        cache.conn.execute("UPDATE bucket_jobs SET expires=0", [])?;
        let old = cache.claim(&k)?.unwrap();
        cache.conn.execute("UPDATE bucket_jobs SET expires=0", [])?;
        let replacement = cache.claim(&k)?.unwrap();
        replacement.publish(&payload())?;
        assert!(old.publish(&payload()).is_err());
        assert_eq!(
            cache.get_or_build(&k, &Control::new(true), verified, || panic!(
                "warm proof rebuilt"
            ))?,
            b"verified"
        );
        cache.conn.execute("UPDATE bucket_jobs SET pcd=x'00'", [])?;
        let mut builds = 0;
        cache.get_or_build(&k, &Control::new(true), verified, || {
            builds += 1;
            Ok(payload())
        })?;
        assert_eq!(builds, 1);
        cache.complete_epoch(&k, "first", "next", 1)?;
        assert_eq!(
            cache.completed_epoch(&k.namespace, k.epoch, "first", "next")?,
            Some(1)
        );
        assert_eq!(
            cache.completed_epoch(&k.namespace, k.epoch, "first", "different-fork")?,
            None
        );
        assert_eq!(
            cache.completed_epoch(&namespace("another-network"), k.epoch, "first", "next")?,
            None
        );
        let active = cache.claim(&key(&cache, 1)?)?.unwrap();
        cache.invalidate()?;
        assert_eq!(
            cache.completed_epoch(&k.namespace, k.epoch, "first", "next")?,
            None
        );
        assert!(active.publish(&payload()).is_err());
        assert!(cache.load(&k).is_err());
        let new = key(&cache, 0)?;
        assert!(cache.load(&new)?.is_none());
        cache.get_or_build(&new, &Control::new(true), verified, || Ok(payload()))?;
        Ok(())
    }
    #[test]
    fn live_heartbeat_keeps_long_build_owned() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let cache = Cache::open(&dir.path().join("cache.sqlite"))?;
        let k = key(&cache, 0)?;
        let lease = cache.claim(&k)?.unwrap();
        let path = cache.path.clone();
        let contender = thread::spawn(move || {
            thread::sleep(Duration::from_secs(7));
            let conn = Connection::open(path).unwrap();
            conn.execute_batch("BEGIN IMMEDIATE").unwrap();
            // Simulate a slow checkpoint/other writer overlapping a heartbeat.
            thread::sleep(Duration::from_secs(10));
            conn.execute_batch("COMMIT").unwrap();
        });
        thread::sleep(Duration::from_secs(LEASE_SECONDS + 2));
        assert!(cache.claim(&k)?.is_none());
        contender.join().unwrap();
        lease.publish(&payload())?;
        Ok(())
    }
    #[test]
    fn heartbeat_renews_without_holding_a_writer_transaction() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("cache.sqlite");
        let cache = Cache::open(&path)?;
        let k = key(&cache, 0)?;
        let lease = cache.claim(&k)?.unwrap();
        let another = Connection::open(&path)?;
        another.execute_batch("BEGIN IMMEDIATE; CREATE TABLE unrelated(value INTEGER); COMMIT;")?;
        assert_eq!(renew(&another, &k, &lease.owner)?, 1);
        cache.invalidate()?;
        assert_eq!(renew(&another, &k, &lease.owner)?, 0);
        Ok(())
    }
}
