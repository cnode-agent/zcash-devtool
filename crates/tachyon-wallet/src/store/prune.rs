//! Offline `prune`: discards the cached lineages of spent notes, and with
//! `--compact` rewrites the database to return their space to the file
//! system. Stop every other process using the wallet first: prune refuses to
//! run beside one.

use super::Store;
use crate::control::Control;
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, ErrorCode, OpenFlags};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const DATABASE: &str = "tachyon.sqlite";
const COMPACTING: &str = "tachyon.sqlite.compact";
/// How long other wallet commands wait for the database lock (`Store::open`).
const WRITER_BUSY_TIMEOUT: Duration = Duration::from_secs(1);

/// Deletes every cached lineage of a spent note, one batch per transaction,
/// and with `compact` replaces the database with a compacted copy.
pub fn prune(dir: &Path, compact: bool, control: &Control) -> Result<Value> {
    let started = Instant::now();
    let path = dir.join(DATABASE);
    control.stage("Opening wallet database…")?;
    let store = Store::open(dir, false).map_err(locked)?;
    store.config()?;
    let conn = &store.conn;
    conn.busy_timeout(Duration::ZERO)?;
    // In rollback mode even an empty write transaction commits only once
    // no other connection reads.
    store.commit().map_err(locked)?;
    let wal = journal_mode(conn)? == "wal";
    if wal {
        // A reader or writer still inside the WAL keeps it from truncating.
        let busy: i64 = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))?;
        ensure!(busy == 0, "{}", HELD);
    }
    // Rollback mode: EXCLUSIVE fails while any other connection reads or writes.
    conn.execute_batch("BEGIN EXCLUSIVE").map_err(locked)?;
    control.stage("Measuring wallet database…")?;
    let before = Usage::measure(&store, &path)?;
    control.stage("Discarding cached proofs of spent notes…")?;
    let deleted = store.prune_spent_proofs(|| {
        control.check()?;
        conn.execute_batch("COMMIT; BEGIN EXCLUSIVE")
            .map_err(locked)
    })?;
    store.commit()?;
    let free_pages: u64 = conn.query_row("PRAGMA freelist_count", [], |row| row.get(0))?;
    let quick_check = if compact && (free_pages > 0 || wal) {
        control.stage("Compacting wallet database…")?;
        Some(replace_with_compacted(store, dir, wal)?)
    } else {
        drop(store);
        None
    };
    let check = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let after = Usage::measure_connection(&check, &path)?;
    Ok(json!({
        "rows_before": before.rows,
        "rows_deleted": deleted,
        "rows_after": after.rows,
        "bytes_before": before.bytes,
        "bytes_after": after.bytes,
        "free_bytes_before": before.free_bytes,
        "free_bytes_after": after.free_bytes,
        "tables_before": before.tables,
        "tables_after": after.tables,
        "compacted": quick_check.is_some(),
        "quick_check": quick_check,
        "elapsed_ms": u64::try_from(started.elapsed().as_millis())?,
    }))
}

const HELD: &str = "another process holds the wallet; stop the writer first";

/// Names a lock held by another connection as the refusal it is.
fn locked(error: impl Into<anyhow::Error>) -> anyhow::Error {
    let error = error.into();
    let busy = error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<rusqlite::Error>(),
            Some(rusqlite::Error::SqliteFailure(e, _))
                if matches!(e.code, ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
        )
    });
    if busy { error.context(HELD) } else { error }
}

fn journal_mode(conn: &Connection) -> Result<String> {
    Ok(conn
        .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))?
        .to_ascii_lowercase())
}

/// `VACUUM INTO` a private sibling, check it, then rename it over the
/// database. The original stays untouched until the rename, so a failure at
/// any earlier step leaves the wallet as it was.
fn replace_with_compacted(store: Store, dir: &Path, wal: bool) -> Result<String> {
    let path = dir.join(DATABASE);
    let temporary = Temporary(dir.join(COMPACTING));
    let conn = &store.conn;
    if wal {
        // Back to the rollback journal the wallet creates; SQLite removes
        // the WAL itself once this connection is the only one.
        ensure!(
            conn.query_row("PRAGMA journal_mode=DELETE", [], |row| row
                .get::<_, String>(0))?
                .eq_ignore_ascii_case("delete"),
            "{}",
            HELD
        );
    }
    // Writers stay out from the copy through the rename.
    conn.execute_batch("BEGIN IMMEDIATE").map_err(locked)?;
    // Our own name, under our lock: anything there is a stale leftover.
    match fs::symlink_metadata(&temporary.0) {
        Ok(metadata) => {
            ensure!(
                metadata.is_file(),
                "{} is not a regular file",
                temporary.0.display()
            );
            fs::remove_file(&temporary.0)?;
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    {
        let copy = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_URI,
        )?;
        copy.busy_timeout(Duration::ZERO)?;
        // Existing wallets get the hygiene of new ones (see `Store::open`).
        let auto_vacuum: i64 = copy.query_row("PRAGMA auto_vacuum", [], |row| row.get(0))?;
        if auto_vacuum == 0 {
            copy.execute_batch("PRAGMA auto_vacuum=INCREMENTAL")?;
        }
        // VACUUM INTO refuses any existing file, even an empty one, so
        // SQLite creates it, with the private wallet file's mode (`modeof`).
        let target = format!(
            "file:{}?modeof={}",
            uri_path(&temporary.0)?,
            uri_path(&path)?
        );
        copy.execute("VACUUM INTO ?1", [target]).map_err(locked)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temporary.0, fs::Permissions::from_mode(0o600))?;
    }
    let quick_check = {
        let compacted =
            Connection::open_with_flags(&temporary.0, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let result: String = compacted.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
        ensure!(
            result == "ok",
            "the compacted copy fails quick_check ({result}); the wallet is unchanged"
        );
        for table in tables(conn)? {
            let (original, copied) = (count(conn, &table)?, count(&compacted, &table)?);
            ensure!(
                original == copied,
                "the compacted copy has {copied} rows in {table}, not {original}; the wallet is unchanged"
            );
        }
        result
    };
    // A journal would be replayed into the compacted file by the next opener.
    ensure!(
        !sibling(&path, "-journal").exists(),
        "a rollback journal appeared beside the wallet; the wallet is unchanged"
    );
    fs::File::open(&temporary.0)?.sync_all()?;
    fs::rename(&temporary.0, &path)?;
    temporary.renamed();
    fs::File::open(dir)?.sync_all()?;
    // Left by a WAL the compacted file (in rollback mode) never reads.
    for suffix in ["-wal", "-shm"] {
        match fs::remove_file(sibling(&path, suffix)) {
            Err(error) if error.kind() != ErrorKind::NotFound => return Err(error.into()),
            _ => {}
        }
    }
    // A writer that opened the old file is waiting on this lock; let it time
    // out rather than write to the unlinked file once the lock is released.
    std::thread::sleep(WRITER_BUSY_TIMEOUT * 2);
    conn.execute_batch("ROLLBACK")?;
    Ok(quick_check)
}

/// `path`, absolute and percent-encoded for an SQLite `file:` URI.
fn uri_path(path: &Path) -> Result<String> {
    let absolute = std::path::absolute(path)?;
    let text = absolute.to_str().context("wallet path is not UTF-8")?;
    let mut encoded = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"/-._~".contains(&byte) {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    Ok(encoded)
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    name.into()
}

/// Removes an unfinished compacted copy.
struct Temporary(PathBuf);

impl Temporary {
    fn renamed(self) {
        std::mem::forget(self);
    }
}

impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn tables(conn: &Connection) -> Result<Vec<String>> {
    conn.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'")?
        .query_map([], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()
        .map_err(Into::into)
}

fn count(conn: &Connection, table: &str) -> Result<u64> {
    let quoted = table.replace('"', "\"\"");
    Ok(
        conn.query_row(&format!("SELECT count(*) FROM \"{quoted}\""), [], |row| {
            row.get(0)
        })?,
    )
}

struct Usage {
    rows: u64,
    bytes: u64,
    free_bytes: u64,
    /// Allocated bytes per table, its indexes included, where SQLite has dbstat.
    tables: Option<BTreeMap<String, u64>>,
}

impl Usage {
    fn measure(store: &Store, path: &Path) -> Result<Self> {
        Self::measure_connection(&store.conn, path)
    }

    fn measure_connection(conn: &Connection, path: &Path) -> Result<Self> {
        let has_proofs: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='spendable_proofs')",
            [],
            |row| row.get(0),
        )?;
        let rows = if has_proofs {
            count(conn, "spendable_proofs")?
        } else {
            0
        };
        let mut bytes = fs::metadata(path)?.len();
        if let Ok(metadata) = fs::metadata(sibling(path, "-wal")) {
            bytes += metadata.len();
        }
        let page_size: u64 = conn.query_row("PRAGMA page_size", [], |row| row.get(0))?;
        let free_pages: u64 = conn.query_row("PRAGMA freelist_count", [], |row| row.get(0))?;
        Ok(Self {
            rows,
            bytes,
            free_bytes: free_pages * page_size,
            tables: table_bytes(conn)?,
        })
    }
}

fn table_bytes(conn: &Connection) -> Result<Option<BTreeMap<String, u64>>> {
    let owners: BTreeMap<String, String> = conn
        .prepare("SELECT name, tbl_name FROM sqlite_schema WHERE type IN ('table', 'index')")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let Some(mut statement) = conn
        .prepare("SELECT name, pgsize FROM dbstat WHERE aggregate=TRUE")
        .optional_no_such_table()?
    else {
        return Ok(None);
    };
    let mut tables = BTreeMap::new();
    for row in statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?))
    })? {
        let (name, bytes) = row?;
        let owner = owners.get(&name).cloned().unwrap_or(name);
        *tables.entry(owner).or_insert(0) += bytes;
    }
    Ok(Some(tables))
}

/// A build without the dbstat virtual table reports no per-table sizes.
trait NoSuchTable<T> {
    fn optional_no_such_table(self) -> Result<Option<T>>;
}

impl<T> NoSuchTable<T> for rusqlite::Result<T> {
    fn optional_no_such_table(self) -> Result<Option<T>> {
        match self {
            Ok(value) => Ok(Some(value)),
            Err(rusqlite::Error::SqliteFailure(_, Some(message)))
                if message.starts_with("no such table") =>
            {
                Ok(None)
            }
            Err(error) => Err(error.into()),
        }
    }
}
