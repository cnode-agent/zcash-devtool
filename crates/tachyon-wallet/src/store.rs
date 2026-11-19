//! One SQLite writer lock covers selection and durable reservation of inputs.

use crate::{chain::{Block, TachyonStamp}, funding_balance::Snapshot, note::Receipt};
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};
use udon::field::Field;
use zcash_tachyon::{Anchor, EpochIndex, QrProfile, Tachygram, constants::EPOCH_SIZE, pasta::Fp};

mod prune;
pub use prune::prune;

/// zstd frame magic; older wallets still hold plain JSON receipt rows.
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

fn encode_note(receipt: &Receipt) -> Result<Vec<u8>> {
    Ok(zstd::stream::encode_all(
        serde_json::to_vec(receipt)?.as_slice(),
        3,
    )?)
}

fn decode_note_json(bytes: &[u8]) -> Result<String> {
    if bytes.starts_with(&ZSTD_MAGIC) {
        Ok(String::from_utf8(zstd::stream::decode_all(bytes)?)?)
    } else {
        Ok(std::str::from_utf8(bytes)?.to_owned())
    }
}

fn decode_note(bytes: &[u8]) -> Result<Receipt> {
    Ok(serde_json::from_str(&decode_note_json(bytes)?)?)
}

#[derive(Debug, Default, Clone, Copy)]
pub struct CompactStats {
    pub blocks: u64,
    pub members: u64,
    pub pending: u64,
}

/// Cached lineages deleted per statement (each one is about 512 KiB).
pub(crate) const PRUNE_BATCH: usize = 1024;

/// Most lineages one sync deletes, inside its single transaction. A larger
/// backlog clears over the following syncs, or at once with `prune`.
pub(crate) const PRUNE_SYNC_LIMIT: usize = 1024;

/// The cached `NoteSpendable` lineages of notes with a spent nullifier, which
/// are never read again: a rewind that unspends a note discards every
/// lineage. Driven by the cached proofs (a covering scan of their note_id
/// index), each probing the nullifier primary key: the cost follows the
/// cached proofs, not the nullifier history. `DELETE … LIMIT` needs
/// SQLITE_ENABLE_UPDATE_DELETE_LIMIT, which the bundled SQLite lacks, hence
/// the rowid subquery.
pub(crate) const PRUNE_SPENT_PROOFS: &str = "DELETE FROM spendable_proofs WHERE rowid IN (
    SELECT p.rowid FROM spendable_proofs p
    WHERE EXISTS (SELECT 1 FROM note_nullifiers n
                  WHERE n.note_id=p.note_id AND n.spent_height IS NOT NULL)
    LIMIT ?)";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub rpc_url: String,
    pub cookie_file: Option<PathBuf>,
    pub activation: u32,
    pub activation_hash: String,
    pub genesis: String,
    pub network_id: String,
    pub seed: [u8; 32],
    /// Missing on existing wallets, which retain their activation-based history.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub birthday_height: Option<u32>,
}

#[derive(Serialize, Deserialize)]
pub struct Pending {
    pub txid: String,
    pub raw: String,
    pub expiry: u32,
    pub source: String,
    pub receipt: Option<Receipt>,
}

pub struct StoredOperation {
    pub id: String,
    pub txid: String,
    pub request: serde_json::Value,
}

pub struct Store {
    conn: Connection,
    read_only: bool,
}

/// Chain evidence access for proofs: tests may use an in-memory slice, while
/// production reads only the epochs it needs from SQLite and uses the proof
/// cache. Cached proofs are serialized with ragu's versioned wire format.
pub enum ChainData<'a> {
    Blocks(&'a [Block]),
    Store(&'a Store),
}

impl<'a> From<&'a [Block]> for ChainData<'a> {
    fn from(blocks: &'a [Block]) -> Self {
        Self::Blocks(blocks)
    }
}

impl<'a> From<&'a Vec<Block>> for ChainData<'a> {
    fn from(blocks: &'a Vec<Block>) -> Self {
        Self::Blocks(blocks)
    }
}

impl<'a> From<&'a Store> for ChainData<'a> {
    fn from(store: &'a Store) -> Self {
        Self::Store(store)
    }
}

impl<'a> From<&'a ChainData<'a>> for ChainData<'a> {
    fn from(chain: &'a ChainData<'a>) -> Self {
        match chain {
            Self::Blocks(blocks) => Self::Blocks(blocks),
            Self::Store(store) => Self::Store(store),
        }
    }
}

impl ChainData<'_> {
    pub fn tip(&self) -> Result<Block> {
        match self {
            Self::Blocks(blocks) => blocks.last().cloned().context("wallet has not synced"),
            Self::Store(store) => store.tip()?.context("wallet has not synced"),
        }
    }

    /// All blocks in `epoch`, plus the first block of the next epoch when the
    /// epoch has closed. Only this range is read, never the whole chain.
    pub fn epoch_blocks(&self, epoch: u32) -> Result<Vec<Block>> {
        let blocks = match self {
            Self::Blocks(blocks) => blocks
                .iter()
                .filter(|block| block.epoch == epoch || block.epoch == epoch + 1)
                .cloned()
                .collect(),
            Self::Store(store) => {
                let start = self.epoch_start(epoch)?;
                store.blocks_range(start, start.saturating_add(EPOCH_SIZE))?
            }
        };
        // Proving needs every tachygram; a thin copy would prove the wrong sets.
        ensure!(
            !blocks.iter().any(|b| b.epoch == epoch && b.is_thin()),
            "epoch {epoch} was synced thin, without its tachygrams: only the OSS can prove it"
        );
        Ok(blocks)
    }

    fn epoch_start(&self, epoch: u32) -> Result<u32> {
        self.tip()?
            .activation_height
            .checked_add(epoch.checked_mul(EPOCH_SIZE).context("epoch overflow")?)
            .context("epoch height overflow")
    }

    /// The entry anchor of `epoch` (`sntl_epoch`).
    ///
    /// This is the boundary anchor that `SpendableLift` reaches after the
    /// preceding epoch closes. It is distinct from an ordinary anchor in the
    /// same epoch, and anchor spans must never cross it.
    pub fn epoch_sentinel(&self, epoch: u32) -> Result<Anchor> {
        let first = match self {
            Self::Blocks(blocks) => blocks.iter().find(|block| block.epoch == epoch).cloned(),
            Self::Store(store) => store.block(self.epoch_start(epoch)?)?,
        };
        first.context("missing epoch start block")?.entry()
    }

    /// The stamp that created `cm`, its epoch and its preceding anchor.
    pub fn creation(&self, cm: Tachygram) -> Result<Option<(u32, Anchor, Vec<Tachygram>)>> {
        let id = hex::encode(Fp::from(cm).to_bytes());
        let blocks: Vec<Block> = match self {
            Self::Blocks(blocks) => blocks.to_vec(),
            Self::Store(store) => {
                // The compact per-note index survives chain compaction; the
                // tachygram index is the fallback while the block is still full.
                let height = match store.note_height(&id)? {
                    Some(height) => Some(height),
                    None => store.tachygram_height(&id)?,
                };
                match height {
                    Some(height) => store.block(height)?.into_iter().collect(),
                    None => Vec::new(),
                }
            }
        };
        for block in blocks {
            let mut cursor = block.entry()?;
            for stamp in &block.stamps {
                let members = stamp.members()?;
                if members.contains(&cm) {
                    return Ok(Some((block.epoch, cursor, members)));
                }
                cursor = cursor.next_stamp(EpochIndex::new(block.epoch), &stamp.commitment()?)?;
            }
        }
        Ok(None)
    }

    /// Whether `value` is published in the synced chain.
    pub fn published(&self, value: Tachygram) -> Result<bool> {
        let id = hex::encode(Fp::from(value).to_bytes());
        match self {
            Self::Blocks(blocks) => Ok(blocks
                .iter()
                .flat_map(|block| &block.stamps)
                .any(|stamp| stamp.tachygrams.contains(&id))),
            Self::Store(store) => Ok(store.conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM note_nullifiers
                               WHERE nullifier=? AND spent_height IS NOT NULL)",
                [hex::decode(&id)?],
                |row| row.get(0),
            )?),
        }
    }

    /// The profiles of `epoch`'s cached buckets. Unverified: check each bucket.
    pub fn bucket_profiles(&self, epoch: u32) -> Result<Vec<QrProfile>> {
        match self {
            Self::Blocks(_) => Ok(Vec::new()),
            Self::Store(store) => store.bucket_profiles(epoch),
        }
    }

    pub fn bucket_proof(&self, epoch: u32, profile: QrProfile) -> Result<Option<Vec<u8>>> {
        match self {
            Self::Blocks(_) => Ok(None),
            Self::Store(store) => store.bucket_proof(epoch, profile),
        }
    }

    pub fn put_buckets(&self, epoch: u32, buckets: &[(QrProfile, Vec<u8>)]) -> Result<()> {
        match self {
            Self::Blocks(_) => Ok(()),
            Self::Store(store) => store.put_buckets(epoch, buckets),
        }
    }

    pub fn spendable_proof_bytes(&self, note_id: &str) -> Result<Option<Vec<u8>>> {
        match self {
            Self::Blocks(_) => Ok(None),
            Self::Store(store) => store.spendable_proof(note_id),
        }
    }

    pub fn put_spendable_proof_bytes(&self, note_id: &str, pcd: &[u8]) -> Result<()> {
        match self {
            Self::Blocks(_) => Ok(()),
            Self::Store(store) => store.put_spendable_proof(note_id, pcd),
        }
    }
}

/// Never overwrite receipt files, and create private data with restrictive permissions.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .context("cannot create private file (it may already exist)")?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

impl Store {
    pub fn open(dir: &Path, initialize: bool) -> Result<Self> {
        Self::open_with_mode(dir, initialize, false)
    }
    pub fn open_readonly(dir: &Path) -> Result<Self> {
        Self::open_with_mode(dir, false, true)
    }
    fn open_with_mode(dir: &Path, initialize: bool, read_only: bool) -> Result<Self> {
        if initialize && !dir.exists() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(dir)?;
            }
            #[cfg(not(unix))]
            fs::create_dir_all(dir)?;
        }
        let metadata = fs::symlink_metadata(dir).context("wallet does not exist; run init")?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "wallet must be a real directory"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                metadata.permissions().mode() & 0o077 == 0,
                "wallet directory must be private (chmod 700)"
            );
        }
        let path = dir.join("tachyon.sqlite");
        if initialize {
            write_private(&path, &[])?;
        }
        ensure!(
            fs::symlink_metadata(&path)?.is_file(),
            "wallet database must be a regular file"
        );
        let flags = if read_only {
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
        } else {
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
        };
        let conn = Connection::open_with_flags(path, flags)?;
        conn.busy_timeout(Duration::from_secs(1))?;
        if initialize {
            // Only settable before the first table: lets `PRAGMA
            // incremental_vacuum` return freed pages without a full VACUUM.
            conn.execute_batch("PRAGMA auto_vacuum=INCREMENTAL;")?;
        }
        if read_only {
            conn.execute_batch("PRAGMA foreign_keys=ON;")?;
        } else {
            // This wallet deletes only public or derived data (blocks,
            // tachygrams, cached proofs) and never keys, notes or pending
            // transactions. Secure deletion zeroes every freed page and writes
            // it to the rollback journal, so pruning a capped batch of 1024
            // proofs (512 MiB) cost ~10s and a 540 MiB journal; without it the
            // same delete is metadata only.
            conn.execute_batch(
                "PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA secure_delete=OFF; BEGIN IMMEDIATE;",
            )?;
        }
        if initialize {
            conn.execute_batch(
                "CREATE TABLE config (id INTEGER PRIMARY KEY CHECK(id=1), data TEXT NOT NULL);
                CREATE TABLE blocks (
                    height INTEGER PRIMARY KEY, hash BLOB NOT NULL, prev BLOB NOT NULL,
                    activation_height INTEGER NOT NULL, pool_height INTEGER NOT NULL,
                    epoch INTEGER NOT NULL, epoch_length INTEGER NOT NULL,
                    anchor_before BLOB NOT NULL, epoch_start_anchor BLOB,
                    anchor_after BLOB NOT NULL);
                CREATE TABLE notes (id TEXT PRIMARY KEY, data TEXT NOT NULL);
                CREATE TABLE pending (txid TEXT PRIMARY KEY, data TEXT NOT NULL);",
            )?;
        }
        let store = Self { conn, read_only };
        if !read_only {
            store.ensure_pending_meta()?;
        }
        Ok(store)
    }
    /// Keep the transaction payloads in `pending` for recovery and rebroadcast,
    /// while maintaining a small metadata index for hot-path status and
    /// reservation checks. Existing wallets are migrated once.
    fn ensure_pending_meta(&self) -> Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS pending_meta (
                txid TEXT PRIMARY KEY,
                expiry INTEGER NOT NULL,
                source TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS pending_meta_by_expiry ON pending_meta(expiry, source);",
        )?;
        let migrated: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM metadata WHERE key='pending_meta_v1'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if migrated.is_some() {
            return Ok(());
        }
        let mut rows = self.conn.prepare("SELECT data FROM pending")?;
        let mut pending = rows.query([])?;
        let mut insert = self
            .conn
            .prepare("INSERT OR IGNORE INTO pending_meta(txid, expiry, source) VALUES(?, ?, ?)")?;
        while let Some(row) = pending.next()? {
            let data: String = row.get(0)?;
            let entry: Pending = serde_json::from_str(&data)?;
            insert.execute(params![entry.txid, entry.expiry, entry.source])?;
        }
        self.conn.execute(
            "INSERT INTO metadata(key, value) VALUES('pending_meta_v1', '1')
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            [],
        )?;
        Ok(())
    }
    pub fn commit(&self) -> Result<()> {
        self.conn.execute_batch("COMMIT")?;
        Ok(())
    }
    pub fn set_config(&self, config: &Config) -> Result<()> {
        self.conn.execute(
            "INSERT INTO config VALUES(1, ?)",
            [serde_json::to_string(config)?],
        )?;
        Ok(())
    }
    pub fn config(&self) -> Result<Config> {
        let json: String = self
            .conn
            .query_row("SELECT data FROM config WHERE id=1", [], |r| r.get(0))?;
        let config: Config = serde_json::from_str(&json)?;
        ensure!(config.version == 1, "unsupported wallet database version");
        Ok(config)
    }
    pub fn network_identity_valid(&self, config: &Config) -> Result<bool> {
        self.ensure_indexes()?;
        let expected = format!("{}:{}", config.genesis, config.activation_hash);
        let cached: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM metadata WHERE key='network_identity_v1'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        Ok(cached.as_deref() == Some(expected.as_str()))
    }
    pub fn mark_network_identity_valid(&self, config: &Config) -> Result<()> {
        self.ensure_indexes()?;
        self.conn.execute(
            "INSERT INTO metadata VALUES('network_identity_v1', ?)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            [format!("{}:{}", config.genesis, config.activation_hash)],
        )?;
        Ok(())
    }
    pub fn blocks(&self) -> Result<Vec<Block>> {
        self.ensure_indexes()?;
        let mut blocks = self.read_headers(None)?;
        // Backfills retain the already downloaded suffix. Until the gap closes,
        // only the contiguous prefix is usable by balance/proof construction.
        if let Some(gap) = blocks.windows(2).position(|pair| {
            pair[0].height.checked_add(1) != Some(pair[1].height)
                || pair[1].previous_block_hash != pair[0].hash
                || pair[1].anchor_before != pair[0].anchor_after
        }) {
            blocks.truncate(gap + 1);
        }
        Ok(blocks)
    }
    /// Headers and stamps (without members) for all blocks or one range.
    fn read_headers(&self, range: Option<(u32, u32)>) -> Result<Vec<Block>> {
        let (start, end) = range.unwrap_or((0, u32::MAX));
        let mut blocks: Vec<Block> = self
            .conn
            .prepare(
                "SELECT height, hash, prev, activation_height, pool_height, epoch,
                        epoch_length, anchor_before, epoch_start_anchor, anchor_after
                 FROM blocks WHERE height BETWEEN ? AND ? ORDER BY height",
            )?
            .query_map(params![start, end], |row| {
                let height: u32 = row.get(0)?;
                let epoch_start: Option<Vec<u8>> = row.get(8)?;
                Ok(Block {
                    hash: hex::encode(row.get::<_, Vec<u8>>(1)?),
                    previous_block_hash: hex::encode(row.get::<_, Vec<u8>>(2)?),
                    height,
                    activation_height: row.get(3)?,
                    pool_height: row.get(4)?,
                    epoch: row.get(5)?,
                    epoch_length: row.get(6)?,
                    anchor_before: hex::encode(row.get::<_, Vec<u8>>(7)?),
                    epoch_start_anchor: epoch_start.map(hex::encode),
                    anchor_after: hex::encode(row.get::<_, Vec<u8>>(9)?),
                    stamps: Vec::new(),
                    transactions: Vec::new(),
                })
            })?
            .collect::<rusqlite::Result<_>>()?;
        let mut stamps: BTreeMap<u32, Vec<TachyonStamp>> = BTreeMap::new();
        {
            let mut statement = self.conn.prepare(
                "SELECT height, transaction_index, txid, tachygram_set FROM chain_stamps
                 WHERE height BETWEEN ? AND ? ORDER BY height, idx",
            )?;
            let mut rows = statement.query(params![start, end])?;
            while let Some(row) = rows.next()? {
                let height: u32 = row.get(0)?;
                stamps.entry(height).or_default().push(TachyonStamp {
                    transaction_index: row.get::<_, u32>(1)? as usize,
                    txid: hex::encode(row.get::<_, Vec<u8>>(2)?),
                    tachygram_set: hex::encode(row.get::<_, Vec<u8>>(3)?),
                    tachygrams: Vec::new(),
                });
            }
        }
        for block in &mut blocks {
            if let Some(found) = stamps.remove(&block.height) {
                block.stamps = found;
            }
        }
        self.attach_members(&mut blocks)?;
        Ok(blocks)
    }
    pub fn first_height(&self) -> Result<Option<u32>> {
        self.conn
            .query_row("SELECT MIN(height) FROM blocks", [], |row| row.get(0))
            .optional()
            .map(|value| value.flatten())
            .map_err(Into::into)
    }
    pub fn tip(&self) -> Result<Option<Block>> {
        self.ensure_indexes()?;
        // Backfills may leave a cached suffix above a gap. Only the contiguous
        // prefix is usable as wallet evidence; walking heights in SQL avoids
        // deserializing that suffix or the whole chain.
        let height: Option<u32> = self
            .conn
            .query_row(
                "WITH RECURSIVE contiguous(height) AS (
                    SELECT MIN(height) FROM blocks
                    UNION ALL
                    SELECT contiguous.height + 1 FROM contiguous
                    JOIN blocks ON blocks.height = contiguous.height + 1
                 )
                 SELECT MAX(height) FROM contiguous",
                [],
                |row| row.get::<_, Option<u32>>(0),
            )
            .optional()?
            .flatten();
        height.map(|height| self.block(height)).transpose().map(Option::flatten)
    }
    pub fn blocks_range(&self, start: u32, end: u32) -> Result<Vec<Block>> {
        self.ensure_indexes()?;
        self.read_headers(Some((start, end)))
    }
    fn index_block(&self, block: &Block) -> Result<()> {
        let mut note_height = self.conn.prepare_cached(
            "INSERT OR IGNORE INTO note_heights SELECT id, ?2 FROM notes WHERE id = ?1",
        )?;
        let mut note_stamp = self.conn.prepare_cached(
            "INSERT OR IGNORE INTO chain_note_stamps
             SELECT ?1, ?2, ?3 WHERE EXISTS(SELECT 1 FROM notes WHERE id = ?1)",
        )?;
        let mut spent = self.conn.prepare_cached(
            "UPDATE note_nullifiers SET spent_height=?
             WHERE spent_height IS NULL AND nullifier=?",
        )?;
        for (index, stamp) in block.stamps.iter().enumerate() {
            for member in &stamp.tachygrams {
                note_height.execute(params![member, block.height])?;
                note_stamp.execute(params![member, block.height, index as u32])?;
                spent.execute(params![block.height, hex::decode(member)?])?;
            }
        }
        for txid in &block.transactions {
            self.conn.execute(
                "INSERT INTO block_transactions VALUES(?, ?) ON CONFLICT DO NOTHING",
                params![txid, block.height],
            )?;
        }
        Ok(())
    }
    /// Additive, one-time index migration for existing wallets. Steady-state
    /// sync only indexes the blocks it appends.
    fn ensure_indexes(&self) -> Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS block_transactions (txid TEXT NOT NULL, height INTEGER NOT NULL, PRIMARY KEY(txid, height));
             CREATE INDEX IF NOT EXISTS transactions_by_height ON block_transactions(height);
             CREATE TABLE IF NOT EXISTS note_nullifiers (
                note_id TEXT NOT NULL, epoch INTEGER NOT NULL, nullifier BLOB NOT NULL UNIQUE,
                spent_height INTEGER, PRIMARY KEY(note_id, epoch));
             CREATE INDEX IF NOT EXISTS note_nullifiers_by_spend ON note_nullifiers(spent_height);
             CREATE TABLE IF NOT EXISTS note_heights (id TEXT PRIMARY KEY, height INTEGER NOT NULL);
             CREATE INDEX IF NOT EXISTS note_heights_by_height ON note_heights(height);
             CREATE TABLE IF NOT EXISTS chain_members (
                height INTEGER NOT NULL, stamp INTEGER NOT NULL, idx INTEGER NOT NULL,
                value BLOB NOT NULL, PRIMARY KEY(height, stamp, idx)) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS chain_note_stamps (
                note_id TEXT PRIMARY KEY, height INTEGER NOT NULL, stamp INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS note_absent (id TEXT PRIMARY KEY);
             CREATE TABLE IF NOT EXISTS chain_blocks (
                height INTEGER PRIMARY KEY, hash BLOB NOT NULL, prev BLOB NOT NULL,
                activation_height INTEGER NOT NULL, pool_height INTEGER NOT NULL,
                epoch INTEGER NOT NULL, epoch_length INTEGER NOT NULL,
                anchor_before BLOB NOT NULL, epoch_start_anchor BLOB,
                anchor_after BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS chain_stamps (
                height INTEGER NOT NULL, idx INTEGER NOT NULL,
                transaction_index INTEGER NOT NULL, txid BLOB NOT NULL,
                tachygram_set BLOB NOT NULL, PRIMARY KEY(height, idx)) WITHOUT ROWID;",
        )?;
        // Wallets written before the compact member store keep their stamp
        // members in `blocks.data` and the `tachygrams` index: move them once.
        if self.table_exists("tachygrams")? {
            self.migrate_chain_members()?;
        }
        if self.table_exists("blocks")? && self.table_has_column("blocks", "data")? {
            self.migrate_block_columns()?;
        }
        self.migrate_nullifier_blobs()?;
        self.migrate_notes_compression()?;
        // Read-only opens must not write: only stamp missing flags.
        for flag in ["chain_index_v1", "note_heights_v1"] {
            let present: Option<String> = self
                .conn
                .query_row(
                    "SELECT value FROM metadata WHERE key=?",
                    [flag],
                    |row| row.get(0),
                )
                .optional()?;
            if present.is_none() {
                self.conn.execute(
                    "INSERT OR IGNORE INTO metadata VALUES(?, '1')",
                    [flag],
                )?;
            }
        }
        Ok(())
    }
    /// Moves stamp members out of the JSON blocks and the text index into
    /// `chain_members` as 32-byte blobs, then drops the old index table.
    fn migrate_chain_members(&self) -> Result<()> {
        let notes: HashSet<String> = self
            .conn
            .prepare("SELECT id FROM notes")?
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        let mut updates = Vec::new();
        if self.table_exists("blocks")? {
            let mut select = self
                .conn
                .prepare("SELECT height, data FROM blocks ORDER BY height")?;
            let mut rows = select.query([])?;
            while let Some(row) = rows.next()? {
                let height: u32 = row.get(0)?;
                let data: String = row.get(1)?;
                let block: Block = serde_json::from_str(&data)?;
                if !block.stamps.iter().any(|stamp| !stamp.tachygrams.is_empty()) {
                    continue;
                }
                for (index, stamp) in block.stamps.iter().enumerate() {
                    for (position, member) in stamp.tachygrams.iter().enumerate() {
                        self.conn.execute(
                            "INSERT OR IGNORE INTO chain_members VALUES(?, ?, ?, ?)",
                            params![height, index as u32, position as u32, hex::decode(member)?],
                        )?;
                        if notes.contains(member) {
                            self.conn.execute(
                                "INSERT OR IGNORE INTO note_heights VALUES(?, ?)",
                                params![member, height],
                            )?;
                            self.conn.execute(
                                "INSERT OR IGNORE INTO chain_note_stamps VALUES(?, ?, ?)",
                                params![member, height, index as u32],
                            )?;
                        }
                    }
                }
                updates.push((height, Self::stripped(&block)?));
            }
        }
        for (height, data) in updates {
            self.conn.execute(
                "UPDATE blocks SET data=? WHERE height=?",
                params![data, height],
            )?;
        }
        self.conn.execute("DROP TABLE tachygrams", [])?;
        Ok(())
    }
    fn table_has_column(&self, table: &str, column: &str) -> Result<bool> {
        Ok(self
            .conn
            .prepare(&format!("PRAGMA table_info({table})"))?
            .query_map([], |row| row.get::<_, String>(1))?
            .filter_map(|name| name.ok())
            .any(|name| name == column))
    }
    /// Replaces the JSON block rows with typed header/stamp columns.
    fn migrate_block_columns(&self) -> Result<()> {
        let mut select = self
            .conn
            .prepare("SELECT height, data FROM blocks ORDER BY height")?;
        let mut rows = select.query([])?;
        let mut blocks = Vec::new();
        while let Some(row) = rows.next()? {
            let height: u32 = row.get(0)?;
            let data: String = row.get(1)?;
            let block: Block = serde_json::from_str(&data)?;
            blocks.push((height, block));
        }
        drop(rows);
        drop(select);
        self.conn
            .execute_batch("CREATE TABLE IF NOT EXISTS chain_blocks (height INTEGER PRIMARY KEY, hash BLOB NOT NULL, prev BLOB NOT NULL, activation_height INTEGER NOT NULL, pool_height INTEGER NOT NULL, epoch INTEGER NOT NULL, epoch_length INTEGER NOT NULL, anchor_before BLOB NOT NULL, epoch_start_anchor BLOB, anchor_after BLOB NOT NULL);")?;
        for (height, block) in &blocks {
            self.conn.execute(
                "INSERT OR REPLACE INTO chain_blocks VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![
                    height,
                    hex::decode(&block.hash)?,
                    hex::decode(&block.previous_block_hash)?,
                    block.activation_height,
                    block.pool_height,
                    block.epoch,
                    block.epoch_length,
                    hex::decode(&block.anchor_before)?,
                    block
                        .epoch_start_anchor
                        .as_deref()
                        .map(hex::decode)
                        .transpose()?,
                    hex::decode(&block.anchor_after)?
                ],
            )?;
            self.conn
                .execute("DELETE FROM chain_stamps WHERE height=?", [height])?;
            for (index, stamp) in block.stamps.iter().enumerate() {
                self.conn.execute(
                    "INSERT INTO chain_stamps VALUES(?, ?, ?, ?, ?)",
                    params![
                        height,
                        index as u32,
                        stamp.transaction_index as u32,
                        hex::decode(&stamp.txid)?,
                        hex::decode(&stamp.tachygram_set)?
                    ],
                )?;
            }
        }
        self.conn.execute_batch(
            "DROP TABLE blocks; ALTER TABLE chain_blocks RENAME TO blocks;",
        )?;
        Ok(())
    }
    /// Compresses receipt JSON once; rows stay readable by their frame magic.
    fn migrate_notes_compression(&self) -> Result<()> {
        let done: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM metadata WHERE key='notes_zstd_v1'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if done.is_some() {
            return Ok(());
        }
        let rows: Vec<(String, Vec<u8>)> = if self.table_exists("notes")? {
            self.conn
                .prepare("SELECT id, data FROM notes")?
                .query_map([], |row| {
                    let data: rusqlite::types::Value = row.get(1)?;
                    let bytes = match data {
                        rusqlite::types::Value::Text(text) => text.into_bytes(),
                        rusqlite::types::Value::Blob(bytes) => bytes,
                        _ => {
                            return Err(rusqlite::Error::InvalidColumnType(
                                1,
                                "data".into(),
                                rusqlite::types::Type::Null,
                            ))
                        }
                    };
                    Ok((row.get(0)?, bytes))
                })?
                .collect::<rusqlite::Result<_>>()?
        } else {
            Vec::new()
        };
        let mut update = self.conn.prepare("UPDATE notes SET data=? WHERE id=?")?;
        for (id, data) in rows {
            if data.starts_with(&ZSTD_MAGIC) {
                continue;
            }
            let receipt: Receipt = serde_json::from_slice(&data)?;
            update.execute(params![encode_note(&receipt)?, id])?;
        }
        self.conn.execute(
            "INSERT OR IGNORE INTO metadata VALUES('notes_zstd_v1', '1')",
            [],
        )?;
        Ok(())
    }
    /// Stores per-epoch nullifiers as 32-byte blobs instead of hex text.
    fn migrate_nullifier_blobs(&self) -> Result<()> {
        let done: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM metadata WHERE key='nullifiers_blob_v1'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if done.is_some() {
            return Ok(());
        }
        let rows: Vec<(String, u32, String, Option<u32>)> = if self
            .table_exists("note_nullifiers")?
        {
            self.conn
                .prepare("SELECT note_id, epoch, nullifier, spent_height FROM note_nullifiers")?
                .query_map([], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                })?
                .collect::<rusqlite::Result<_>>()?
        } else {
            Vec::new()
        };
        if rows.is_empty() {
            // Nothing to convert; SQLite's dynamic typing accepts blobs later.
            self.conn.execute(
                "INSERT OR IGNORE INTO metadata VALUES('nullifiers_blob_v1', '1')",
                [],
            )?;
            return Ok(());
        }
        self.conn.execute_batch(
            "DROP TABLE IF EXISTS note_nullifiers_v2;
             CREATE TABLE note_nullifiers_v2 (
                note_id TEXT NOT NULL, epoch INTEGER NOT NULL,
                nullifier BLOB NOT NULL UNIQUE, spent_height INTEGER,
                PRIMARY KEY(note_id, epoch));
             CREATE INDEX note_nullifiers_v2_by_spend ON note_nullifiers_v2(spent_height);",
        )?;
        {
            let mut insert = self.conn.prepare(
                "INSERT OR IGNORE INTO note_nullifiers_v2 VALUES(?, ?, ?, ?)",
            )?;
            for (note_id, epoch, nullifier, spent_height) in &rows {
                insert.execute(params![note_id, epoch, hex::decode(nullifier)?, spent_height])?;
            }
        }
        self.conn.execute_batch(
            "DROP TABLE note_nullifiers;
             ALTER TABLE note_nullifiers_v2 RENAME TO note_nullifiers;
             DROP INDEX IF EXISTS note_nullifiers_v2_by_spend;
             CREATE INDEX IF NOT EXISTS note_nullifiers_by_spend
                ON note_nullifiers(spent_height);",
        )?;
        self.conn.execute(
            "INSERT OR IGNORE INTO metadata VALUES('nullifiers_blob_v1', '1')",
            [],
        )?;
        Ok(())
    }
    /// A block's JSON without its stamp members; they live in `chain_members`.
    fn stripped(block: &Block) -> Result<String> {
        let mut stored = block.clone();
        for stamp in &mut stored.stamps {
            stamp.tachygrams.clear();
        }
        Ok(serde_json::to_string(&stored)?)
    }
    /// Fills each block's stamps from `chain_members`, in stamp/index order.
    fn attach_members(&self, blocks: &mut [Block]) -> Result<()> {
        let Some(first) = blocks.first().map(|block| block.height) else {
            return Ok(());
        };
        let last = blocks.last().map(|block| block.height).unwrap_or(first);
        let mut members: BTreeMap<u32, Vec<(usize, Vec<u8>)>> = BTreeMap::new();
        {
            let mut statement = self.conn.prepare(
                "SELECT height, stamp, value FROM chain_members
                 WHERE height BETWEEN ? AND ? ORDER BY height, stamp, idx",
            )?;
            let mut rows = statement.query(params![first, last])?;
            while let Some(row) = rows.next()? {
                members
                    .entry(row.get(0)?)
                    .or_default()
                    .push((row.get(1)?, row.get(2)?));
            }
        }
        for block in blocks {
            let Some(stamps) = members.get(&block.height) else {
                continue;
            };
            for (index, value) in stamps {
                if let Some(stamp) = block.stamps.get_mut(*index) {
                    stamp.tachygrams.push(hex::encode(value));
                }
            }
        }
        Ok(())
    }
    /// Whether some block of `epoch` was synced thin, so the tachygram index
    /// misses its spends.
    pub fn thin_epoch(&self, epoch: u32) -> Result<bool> {
        if !self.table_exists("thin_blocks")? {
            return Ok(false);
        }
        Ok(self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM thin_blocks WHERE epoch=?)",
            [epoch],
            |row| row.get(0),
        )?)
    }
    /// The height that published one of the wallet's own note commitments.
    pub fn note_height(&self, id: &str) -> Result<Option<u32>> {
        self.ensure_notes_resolved()?;
        self.conn
            .query_row("SELECT height FROM note_heights WHERE id=?", [id], |row| {
                row.get(0)
            })
            .optional()
            .map_err(Into::into)
    }
    /// Where a published value sits, scanning the member table. Rare path:
    /// wallet notes and nullifiers are indexed during `put_block`.
    fn note_location(&self, id: &str) -> Result<Option<(u32, u32)>> {
        let value = hex::decode(id)?;
        self.conn
            .query_row(
                "SELECT height, stamp FROM chain_members WHERE value=? LIMIT 1",
                [value],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(Into::into)
    }
    pub fn tachygram_height(&self, id: &str) -> Result<Option<u32>> {
        self.ensure_indexes()?;
        Ok(self.note_location(id)?.map(|(height, _)| height))
    }
    /// Indexes receipts that arrived after their block, in one pass over the
    /// retained members. Notes it cannot find are remembered as absent, so
    /// balances do not rescan for notes that are simply not mined yet.
    pub fn resolve_notes(&self) -> Result<u64> {
        if self.read_only {
            return Ok(0);
        }
        self.ensure_indexes()?;
        let unresolved: Vec<String> = self
            .conn
            .prepare(
                "SELECT notes.id FROM notes
                 WHERE NOT EXISTS (SELECT 1 FROM note_heights WHERE note_heights.id=notes.id)
                   AND NOT EXISTS (SELECT 1 FROM note_absent WHERE note_absent.id=notes.id)",
            )?
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        if unresolved.is_empty() {
            return Ok(0);
        }
        let mut wanted: HashMap<Vec<u8>, String> = HashMap::new();
        for id in &unresolved {
            if let Ok(value) = hex::decode(id) {
                wanted.insert(value, id.clone());
            }
        }
        let mut resolved = 0;
        {
            let mut statement = self.conn.prepare(
                "SELECT height, stamp, value FROM chain_members ORDER BY height, stamp, idx",
            )?;
            let mut rows = statement.query([])?;
            while let Some(row) = rows.next()? {
                let value: Vec<u8> = row.get(2)?;
                let Some(id) = wanted.remove(&value) else {
                    continue;
                };
                let height: u32 = row.get(0)?;
                let stamp: u32 = row.get(1)?;
                self.conn.execute(
                    "INSERT OR IGNORE INTO note_heights VALUES(?, ?)",
                    params![id, height],
                )?;
                self.conn.execute(
                    "INSERT OR IGNORE INTO chain_note_stamps VALUES(?, ?, ?)",
                    params![id, height, stamp],
                )?;
                resolved += 1;
                if wanted.is_empty() {
                    break;
                }
            }
        }
        for id in wanted.values() {
            self.conn.execute(
                "INSERT OR IGNORE INTO note_absent VALUES(?)",
                [id],
            )?;
        }
        Ok(resolved)
    }
    /// Resolves late-imported receipts once, only when some note is neither
    /// indexed nor known to be absent.
    fn ensure_notes_resolved(&self) -> Result<()> {
        if self.read_only {
            return Ok(());
        }
        self.ensure_indexes()?;
        let pending: bool = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM notes n
             WHERE NOT EXISTS (SELECT 1 FROM note_heights h WHERE h.id=n.id)
               AND NOT EXISTS (SELECT 1 FROM note_absent a WHERE a.id=n.id))",
            [],
            |row| row.get(0),
        )?;
        if pending {
            self.resolve_notes()?;
        }
        Ok(())
    }
    pub fn has_transaction(&self, txid: &str) -> Result<bool> {
        self.ensure_indexes()?;
        Ok(self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM block_transactions WHERE txid=?)",
            [txid],
            |row| row.get(0),
        )?)
    }
    /// Records one of this wallet's transactions as mined at `height`. Only
    /// the wallet's own transactions are recorded: sync no longer downloads
    /// every block's transaction list.
    pub fn put_transaction(&self, txid: &str, height: u32) -> Result<()> {
        self.ensure_indexes()?;
        self.conn.execute(
            "INSERT INTO block_transactions VALUES(?, ?) ON CONFLICT DO NOTHING",
            params![txid, height],
        )?;
        Ok(())
    }
    /// The heights in `start..=end` that have a stored block.
    pub fn block_heights(&self, start: u32, end: u32) -> Result<BTreeSet<u32>> {
        Ok(self
            .conn
            .prepare("SELECT height FROM blocks WHERE height BETWEEN ? AND ?")?
            .query_map(params![start, end], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?)
    }
    pub fn block_by_txid(&self, txid: &str) -> Result<Option<Block>> {
        self.ensure_indexes()?;
        let height: Option<u32> = self
            .conn
            .query_row(
                "SELECT MIN(height) FROM block_transactions WHERE txid=?",
                [txid],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        height
            .map(|height| self.block(height))
            .transpose()
            .map(Option::flatten)
    }
    pub fn block(&self, height: u32) -> Result<Option<Block>> {
        self.ensure_indexes()?;
        let mut blocks = self.read_headers(Some((height, height)))?;
        Ok(blocks.pop())
    }
    pub fn clear_funding_snapshot(&self) -> Result<()> {
        if self.table_exists("funding_snapshot")? {
            self.conn.execute("DELETE FROM funding_snapshot", [])?;
        }
        Ok(())
    }
    fn ensure_proof_tables(&self) -> Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS epoch_proofs (
                epoch INTEGER NOT NULL, depth INTEGER NOT NULL, bits INTEGER NOT NULL,
                pcd BLOB NOT NULL, members BLOB NOT NULL,
                PRIMARY KEY(epoch, depth, bits));
             CREATE TABLE IF NOT EXISTS spendable_proofs (
                note_id TEXT PRIMARY KEY, pcd BLOB NOT NULL);",
        )?;
        Ok(())
    }
    pub fn bucket_profiles(&self, epoch: u32) -> Result<Vec<QrProfile>> {
        self.ensure_proof_tables()?;
        self.conn
            .prepare("SELECT depth, bits FROM epoch_proofs WHERE epoch=?")?
            .query_map([epoch], |row| {
                Ok(QrProfile {
                    depth: row.get(0)?,
                    bits: row.get(1)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()
            .map_err(Into::into)
    }
    pub fn bucket_proof(&self, epoch: u32, profile: QrProfile) -> Result<Option<Vec<u8>>> {
        self.ensure_proof_tables()?;
        self.conn
            .query_row(
                "SELECT pcd FROM epoch_proofs WHERE epoch=? AND depth=? AND bits=?",
                params![epoch, profile.depth, profile.bits],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }
    /// Replaces every cached bucket of `epoch`.
    pub fn put_buckets(&self, epoch: u32, buckets: &[(QrProfile, Vec<u8>)]) -> Result<()> {
        self.ensure_proof_tables()?;
        self.conn
            .execute("DELETE FROM epoch_proofs WHERE epoch=?", [epoch])?;
        for (profile, pcd) in buckets {
            // `members` is legacy: a row is trusted by its header and proof alone.
            self.conn.execute(
                "INSERT INTO epoch_proofs VALUES(?, ?, ?, ?, x'')",
                params![epoch, profile.depth, profile.bits, pcd],
            )?;
        }
        Ok(())
    }
    pub fn spendable_proof(&self, note_id: &str) -> Result<Option<Vec<u8>>> {
        self.ensure_proof_tables()?;
        self.conn
            .query_row(
                "SELECT pcd FROM spendable_proofs WHERE note_id=?",
                [note_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(Into::into)
    }
    pub fn put_spendable_proof(&self, note_id: &str, pcd: &[u8]) -> Result<()> {
        self.ensure_proof_tables()?;
        self.conn.execute(
            "INSERT INTO spendable_proofs VALUES(?, ?)
             ON CONFLICT(note_id) DO UPDATE SET pcd=excluded.pcd",
            params![note_id, pcd],
        )?;
        Ok(())
    }
    /// Deletes the cached lineages of spent notes, at most `limit` of them
    /// (all with `None`), [`PRUNE_BATCH`] rows per statement, calling
    /// `between` after each full batch short of the limit. Creates no table.
    pub fn prune_spent_proofs(
        &self,
        limit: Option<usize>,
        mut between: impl FnMut() -> Result<()>,
    ) -> Result<u64> {
        if !(self.table_exists("spendable_proofs")? && self.table_exists("note_nullifiers")?) {
            return Ok(0);
        }
        let mut statement = self.conn.prepare(PRUNE_SPENT_PROOFS)?;
        let mut total = 0;
        loop {
            let batch = limit.map_or(PRUNE_BATCH, |limit| PRUNE_BATCH.min(limit - total));
            if batch == 0 {
                break;
            }
            let deleted = statement.execute([batch])?;
            total += deleted;
            if deleted < batch || limit == Some(total) {
                break;
            }
            between()?;
        }
        Ok(u64::try_from(total)?)
    }
    pub fn clear_chain(&self) -> Result<()> {
        self.ensure_proof_tables()?;
        self.conn.execute("DELETE FROM blocks", [])?;
        self.conn.execute("DELETE FROM block_transactions", [])?;
        if self.table_exists("chain_members")? {
            self.conn.execute("DELETE FROM chain_members", [])?;
            self.conn.execute("DELETE FROM chain_note_stamps", [])?;
        }
        if self.table_exists("chain_stamps")? {
            self.conn.execute("DELETE FROM chain_stamps", [])?;
        }
        self.conn.execute("DELETE FROM epoch_proofs", [])?;
        self.conn.execute("DELETE FROM spendable_proofs", [])?;
        if self.table_exists("thin_blocks")? {
            self.conn.execute("DELETE FROM thin_blocks", [])?;
        }
        if self.table_exists("note_nullifiers")? {
            self.conn
                .execute("UPDATE note_nullifiers SET spent_height=NULL", [])?;
        }
        if self.table_exists("note_heights")? {
            self.conn.execute("DELETE FROM note_heights", [])?;
        }
        self.clear_funding_snapshot()
    }
    /// Reclaims pages freed by deletes. Needs temporary disk space about the
    /// size of the database; call outside any transaction.
    pub fn vacuum(&self) -> Result<()> {
        self.conn.execute_batch("VACUUM")?;
        Ok(())
    }

    /// Drops old stamp members, keeping whole stamps that created a still-unspent
    /// note and every stamp of the last `keep_epochs` epochs. Blocks stay as
    /// headers/stamps; their members are reattached from `chain_members` on read.
    pub fn compact_chain(&self, keep_epochs: u32) -> Result<CompactStats> {
        self.ensure_indexes()?;
        let Some(tip) = self.tip()? else {
            return Ok(CompactStats::default());
        };
        let mut stats = CompactStats::default();
        // Receipts past their expiry can never be mined; keep the rest.
        if self.table_exists("pending_meta")? {
            // Expired receipts and their operation records can never be mined.
            // Delete the child rows first: `operations` references `pending`.
            if self.table_exists("operations")? {
                self.conn.execute(
                    "DELETE FROM operations WHERE txid IN
                     (SELECT txid FROM pending_meta WHERE expiry < ?)",
                    [tip.height],
                )?;
            }
            stats.pending = u64::try_from(self.conn.execute(
                "DELETE FROM pending WHERE txid IN
                 (SELECT txid FROM pending_meta WHERE expiry < ?)",
                [tip.height],
            )?).unwrap_or(0);
            self.conn.execute(
                "DELETE FROM pending_meta WHERE NOT EXISTS
                 (SELECT 1 FROM pending p WHERE p.txid = pending_meta.txid)",
                [],
            )?;
        }
        let cutoff = tip.epoch.saturating_sub(keep_epochs);
        if cutoff == 0 {
            return Ok(stats);
        }
        let cutoff_height = tip
            .activation_height
            .checked_add(cutoff.checked_mul(EPOCH_SIZE).context("epoch overflow")?)
            .context("height overflow")?;
        // Old transaction rows only served pending detection; receipts that
        // old expired long ago, and the chain itself carries the proofs.
        self.conn
            .execute("DELETE FROM block_transactions WHERE height < ?", [cutoff_height])?;
        // A receipt imported after its block is indexed on first lookup; index
        // it now, while its stamp still has its members.
        self.resolve_notes()?;
        // Stamps holding an unspent note's commitment must stay complete.
        let mut keep: HashMap<u32, Vec<u32>> = HashMap::new();
        {
            let mut statement = self.conn.prepare(
                "SELECT ns.height, ns.stamp FROM chain_note_stamps ns
                 WHERE NOT EXISTS (SELECT 1 FROM note_nullifiers nn
                                   WHERE nn.note_id = ns.note_id AND nn.spent_height IS NOT NULL)",
            )?;
            let mut rows = statement.query([])?;
            while let Some(row) = rows.next()? {
                keep.entry(row.get(0)?).or_default().push(row.get(1)?);
            }
        }
        let mut heights: Vec<(u32, u32)> = self
            .conn
            .prepare(
                "SELECT height, epoch FROM blocks
                 WHERE height < ?1
                   AND EXISTS(SELECT 1 FROM chain_members m WHERE m.height = blocks.height)
                 ORDER BY height",
            )?
            .query_map([cutoff_height], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        if heights.is_empty() {
            return Ok(CompactStats::default());
        }
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS thin_blocks (height INTEGER PRIMARY KEY, epoch INTEGER NOT NULL);
             CREATE INDEX IF NOT EXISTS thin_blocks_by_epoch ON thin_blocks(epoch);",
        )?;
        for (height, epoch) in heights {
            let deleted = match keep.get(&height) {
                Some(stamps) if !stamps.is_empty() => {
                    let list = stamps
                        .iter()
                        .map(u32::to_string)
                        .collect::<Vec<_>>()
                        .join(",");
                    self.conn.execute(
                        &format!(
                            "DELETE FROM chain_members WHERE height=? AND stamp NOT IN ({list})"
                        ),
                        [height],
                    )?
                }
                _ => self
                    .conn
                    .execute("DELETE FROM chain_members WHERE height=?", [height])?,
            };
            if deleted > 0 {
                stats.blocks += 1;
                stats.members += u64::try_from(deleted).unwrap_or(0);
                self.conn.execute(
                    "INSERT OR REPLACE INTO thin_blocks VALUES(?, ?)",
                    params![height, epoch],
                )?;
            }
        }
        Ok(stats)
    }
    pub fn notes(&self) -> Result<Vec<Receipt>> {
        self.conn
            .prepare("SELECT data FROM notes ORDER BY id")?
            .query_map([], |row| row.get::<_, Vec<u8>>(0))?
            .map(|row| decode_note(&row?))
            .collect()
    }
    pub fn unresolved_notes(&self) -> Result<Vec<Receipt>> {
        self.ensure_notes_resolved()?;
        self.conn
            .prepare(
                "SELECT data FROM notes
                 WHERE NOT EXISTS (SELECT 1 FROM note_heights WHERE note_heights.id=notes.id)
                 ORDER BY id",
            )?
            .query_map([], |row| row.get::<_, Vec<u8>>(0))?
            .map(|row| decode_note(&row?))
            .collect()
    }
    pub fn confirmed_unspent_note_rows(&self) -> Result<Vec<(String, String)>> {
        self.ensure_notes_resolved()?;
        self.conn
            .prepare(
                "SELECT notes.id, notes.data FROM notes
                 WHERE EXISTS (SELECT 1 FROM note_heights WHERE note_heights.id=notes.id)
                 AND NOT EXISTS (
                    SELECT 1 FROM note_nullifiers
                    WHERE note_nullifiers.note_id=notes.id
                    AND note_nullifiers.spent_height IS NOT NULL
                 ) ORDER BY notes.id",
            )?
            .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)))?
            .map(|row| {
                let (id, data) = row?;
                Ok((id, decode_note_json(&data)?))
            })
            .collect::<Result<Vec<_>>>()
    }
    pub fn note(&self, id: &str) -> Result<Option<Receipt>> {
        let data: Option<Vec<u8>> = self
            .conn
            .query_row("SELECT data FROM notes WHERE id=?", [id], |row| row.get(0))
            .optional()?;
        data.map(|data| decode_note(&data)).transpose()
    }
    pub fn confirmed_notes_without_nullifier(&self, epoch: u32) -> Result<Vec<Receipt>> {
        self.ensure_notes_resolved()?;
        self.conn
            .prepare(
                "SELECT notes.data FROM notes
                 LEFT JOIN note_nullifiers nn ON nn.note_id=notes.id AND nn.epoch=?
                 WHERE nn.note_id IS NULL
                 AND EXISTS (SELECT 1 FROM note_heights WHERE id=notes.id)
                 AND NOT EXISTS (
                    SELECT 1 FROM note_nullifiers spent
                    WHERE spent.note_id=notes.id AND spent.spent_height IS NOT NULL
                 ) ORDER BY notes.id",
            )?
            .query_map([epoch], |row| row.get::<_, Vec<u8>>(0))?
            .map(|row| decode_note(&row?))
            .collect()
    }
    pub fn notes_without_nullifier(&self, epoch: u32) -> Result<Vec<Receipt>> {
        self.ensure_indexes()?;
        self.conn
            .prepare(
                "SELECT notes.data FROM notes
                 LEFT JOIN note_nullifiers nn ON nn.note_id=notes.id AND nn.epoch=?
                 WHERE nn.note_id IS NULL
                 AND NOT EXISTS (
                    SELECT 1 FROM note_nullifiers spent
                    WHERE spent.note_id=notes.id AND spent.spent_height IS NOT NULL
                 ) ORDER BY notes.id",
            )?
            .query_map([epoch], |row| row.get::<_, Vec<u8>>(0))?
            .map(|row| decode_note(&row?))
            .collect()
    }
    pub fn note_nullifier_epochs(&self, note_id: &str) -> Result<BTreeSet<u32>> {
        self.ensure_indexes()?;
        Ok(self
            .conn
            .prepare("SELECT epoch FROM note_nullifiers WHERE note_id=?")?
            .query_map([note_id], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?)
    }
    pub fn put_note_nullifier(
        &self,
        note_id: &str,
        epoch: u32,
        nullifier: &str,
        spent_height: Option<u32>,
    ) -> Result<()> {
        self.ensure_indexes()?;
        self.conn.execute(
            "INSERT INTO note_nullifiers VALUES(?, ?, ?, ?) ON CONFLICT DO NOTHING",
            params![note_id, epoch, hex::decode(nullifier)?, spent_height],
        )?;
        Ok(())
    }
    pub fn spent_note_ids(&self) -> Result<BTreeSet<String>> {
        self.ensure_indexes()?;
        Ok(self
            .conn
            .prepare("SELECT DISTINCT note_id FROM note_nullifiers WHERE spent_height IS NOT NULL")?
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?)
    }
    pub fn mined_note_ids(&self) -> Result<BTreeSet<String>> {
        self.ensure_notes_resolved()?;
        Ok(self
            .conn
            .prepare(
                "SELECT DISTINCT notes.id FROM notes
                 JOIN note_heights ON note_heights.id=notes.id",
            )?
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?)
    }
    pub fn pending(&self) -> Result<Vec<Pending>> {
        self.read_all("SELECT data FROM pending ORDER BY txid")
    }
    /// Sources of pending operations that have not expired at `tip_height`.
    /// This reads the small metadata index, never the raw transaction blobs.
    pub fn reserved_sources(&self, tip_height: Option<u32>) -> Result<BTreeSet<String>> {
        let mut sources = BTreeSet::new();
        if !self.table_exists("pending_meta")? {
            for pending in self.pending()? {
                if tip_height.is_none_or(|height| height <= pending.expiry) {
                    sources.insert(pending.source);
                }
            }
            return Ok(sources);
        }
        if let Some(height) = tip_height {
            let mut statement = self
                .conn
                .prepare("SELECT source FROM pending_meta WHERE expiry >= ?")?;
            for source in statement.query_map([height], |row| row.get(0))? {
                sources.insert(source?);
            }
        } else {
            let mut statement = self.conn.prepare("SELECT source FROM pending_meta")?;
            for source in statement.query_map([], |row| row.get(0))? {
                sources.insert(source?);
            }
        }
        Ok(sources)
    }
    pub fn pending_summaries(&self) -> Result<Vec<(String, u32, String)>> {
        if !self.table_exists("pending_meta")? {
            return Ok(self
                .pending()?
                .into_iter()
                .map(|pending| (pending.txid, pending.expiry, pending.source))
                .collect());
        }
        Ok(self
            .conn
            .prepare("SELECT txid, expiry, source FROM pending_meta ORDER BY txid")?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?)
    }
    pub fn pending_by_txid(&self, txid: &str) -> Result<Option<Pending>> {
        let data: Option<String> = self
            .conn
            .query_row("SELECT data FROM pending WHERE txid=?", [txid], |row| {
                row.get(0)
            })
            .optional()?;
        data.map(|data| serde_json::from_str(&data).map_err(Into::into))
            .transpose()
    }
    /// All mined transaction IDs in the wallet's canonical synced chain.
    ///
    /// Loading this set once avoids re-running `tip()` and a transaction lookup
    /// for every historical pending row during balance snapshots.
    pub fn mined_txids(&self) -> Result<HashSet<String>> {
        self.conn
            .prepare("SELECT txid FROM block_transactions")?
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<HashSet<_>>>()
            .map_err(Into::into)
    }
    pub fn operation(&self, id: &str) -> Result<Option<StoredOperation>> {
        if !self.table_exists("operations")? {
            return Ok(None);
        }
        let row: Option<(String, String)> = self
            .conn
            .query_row(
                "SELECT txid, request FROM operations WHERE id=?",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        row.map(|(txid, request)| {
            Ok(StoredOperation {
                id: id.into(),
                txid,
                request: serde_json::from_str(&request)?,
            })
        })
        .transpose()
    }
    pub fn operation_ids(&self) -> Result<std::collections::BTreeMap<String, String>> {
        if !self.table_exists("operations")? {
            return Ok(Default::default());
        }
        Ok(self
            .conn
            .prepare("SELECT txid, id FROM operations")?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?)
    }
    pub fn put_operation(&self, operation: &StoredOperation) -> Result<()> {
        // The ID, signed bytes, input reservation and receipts commit atomically before broadcast.
        // Create lazily so older v1 wallets need no reset or eager migration.
        self.conn.execute_batch("CREATE TABLE IF NOT EXISTS operations (
            id TEXT PRIMARY KEY, txid TEXT NOT NULL UNIQUE REFERENCES pending(txid), request TEXT NOT NULL
        );")?;
        self.conn.execute(
            "INSERT INTO operations VALUES(?, ?, ?)",
            params![
                operation.id,
                operation.txid,
                serde_json::to_string(&operation.request)?
            ],
        )?;
        Ok(())
    }
    fn table_exists(&self, table: &str) -> Result<bool> {
        Ok(self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?)",
            [table],
            |row| row.get(0),
        )?)
    }
    pub fn funding_snapshot(&self) -> Result<Option<Snapshot>> {
        if !self.table_exists("funding_snapshot")? {
            return Ok(None);
        }
        self.conn
            .query_row("SELECT data FROM funding_snapshot WHERE id=1", [], |row| {
                row.get::<_, String>(0)
            })
            .optional()?
            .map(|data| Ok(serde_json::from_str(&data)?))
            .transpose()
    }
    pub fn put_funding_snapshot(&self, snapshot: &Snapshot) -> Result<()> {
        if self.funding_snapshot()?.as_ref() == Some(snapshot) {
            return Ok(());
        }
        // Additive, lazy migration: existing v1 wallets remain readable before their next sync.
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS funding_snapshot (id INTEGER PRIMARY KEY CHECK(id=1), data TEXT NOT NULL);"
        )?;
        self.conn.execute(
            "INSERT INTO funding_snapshot VALUES(1, ?) ON CONFLICT(id) DO UPDATE SET data=excluded.data",
            [serde_json::to_string(snapshot)?],
        )?;
        Ok(())
    }
    fn read_all<T: serde::de::DeserializeOwned>(&self, sql: &str) -> Result<Vec<T>> {
        self.conn
            .prepare(sql)?
            .query_map([], |row| row.get::<_, String>(0))?
            .map(|row| Ok(serde_json::from_str(&row?)?))
            .collect()
    }
    pub fn put_block(&self, block: &Block) -> Result<()> {
        self.ensure_indexes()?;
        // Replace this height's header, stamps and members (reorg refetches reuse it).
        self.conn.execute(
            "INSERT OR REPLACE INTO blocks VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                block.height,
                hex::decode(&block.hash)?,
                hex::decode(&block.previous_block_hash)?,
                block.activation_height,
                block.pool_height,
                block.epoch,
                block.epoch_length,
                hex::decode(&block.anchor_before)?,
                block
                    .epoch_start_anchor
                    .as_deref()
                    .map(hex::decode)
                    .transpose()?,
                hex::decode(&block.anchor_after)?
            ],
        )?;
        self.conn
            .execute("DELETE FROM chain_stamps WHERE height=?", [block.height])?;
        for (index, stamp) in block.stamps.iter().enumerate() {
            self.conn.execute(
                "INSERT INTO chain_stamps VALUES(?, ?, ?, ?, ?)",
                params![
                    block.height,
                    index as u32,
                    stamp.transaction_index as u32,
                    hex::decode(&stamp.txid)?,
                    hex::decode(&stamp.tachygram_set)?
                ],
            )?;
        }
        self.conn
            .execute("DELETE FROM chain_members WHERE height=?", [block.height])?;
        {
            let mut insert = self
                .conn
                .prepare_cached("INSERT OR IGNORE INTO chain_members VALUES(?, ?, ?, ?)")?;
            for (index, stamp) in block.stamps.iter().enumerate() {
                for (position, member) in stamp.tachygrams.iter().enumerate() {
                    insert.execute(params![
                        block.height,
                        index as u32,
                        position as u32,
                        hex::decode(member)?
                    ])?;
                }
            }
        }
        self.index_block(block)?;
        if block.is_thin() {
            // Created on first use, so read-only commands work on older wallets.
            self.conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS thin_blocks (height INTEGER PRIMARY KEY, epoch INTEGER NOT NULL);
                 CREATE INDEX IF NOT EXISTS thin_blocks_by_epoch ON thin_blocks(epoch);",
            )?;
            self.conn.execute(
                "INSERT OR IGNORE INTO thin_blocks VALUES(?, ?)",
                params![block.height, block.epoch],
            )?;
            // A spend in this block is invisible here: drop the epoch's
            // unspent rows, to check them again through the OSS. Later
            // epochs' rows go too (left by a rewind): a note with a row for
            // the current epoch is never checked again.
            self.conn.execute(
                "DELETE FROM note_nullifiers WHERE epoch>=? AND spent_height IS NULL",
                [block.epoch],
            )?;
        } else if self.table_exists("thin_blocks")? {
            self.conn
                .execute("DELETE FROM thin_blocks WHERE height=?", [block.height])?;
        }
        Ok(())
    }
    pub fn rewind(&self, height: u32) -> Result<()> {
        self.conn
            .execute("DELETE FROM blocks WHERE height > ?", [height])?;
        if self.table_exists("thin_blocks")? {
            self.conn
                .execute("DELETE FROM thin_blocks WHERE height > ?", [height])?;
        }
        self.conn
            .execute("DELETE FROM block_transactions WHERE height > ?", [height])?;
        if self.table_exists("chain_stamps")? {
            self.conn
                .execute("DELETE FROM chain_stamps WHERE height > ?", [height])?;
        }
        if self.table_exists("chain_members")? {
            self.conn
                .execute("DELETE FROM chain_members WHERE height > ?", [height])?;
            self.conn
                .execute("DELETE FROM chain_note_stamps WHERE height > ?", [height])?;
        }
        if self
            .funding_snapshot()?
            .is_some_and(|snapshot| snapshot.height > height)
        {
            self.conn.execute("DELETE FROM funding_snapshot", [])?;
        }
        if self.table_exists("note_nullifiers")? {
            self.conn.execute(
                "UPDATE note_nullifiers SET spent_height=NULL WHERE spent_height > ?",
                [height],
            )?;
        }
        if self.table_exists("note_heights")? {
            self.conn
                .execute("DELETE FROM note_heights WHERE height > ?", [height])?;
        }
        self.rewind_proofs(height)
    }
    fn rewind_proofs(&self, _height: u32) -> Result<()> {
        self.ensure_proof_tables()?;
        // Reorgs are rare; discard lineages rather than risk reusing one from a
        // removed transition. Cached buckets are checked against the chain on load.
        self.conn.execute("DELETE FROM spendable_proofs", [])?;
        Ok(())
    }
    pub fn put_note(&self, receipt: &Receipt) -> Result<()> {
        let existing: Option<Vec<u8>> = self
            .conn
            .query_row("SELECT data FROM notes WHERE id=?", [receipt.id()?], |r| {
                r.get(0)
            })
            .optional()?;
        if let Some(existing) = existing {
            let mut previous: Receipt = decode_note(&existing)?;
            let mut incoming = receipt.clone();
            let locator = incoming.locator.take().or(previous.locator.take());
            previous.locator = None;
            ensure!(
                previous == incoming,
                "conflicting receipt for this commitment"
            );
            incoming.locator = locator;
            self.conn.execute(
                "UPDATE notes SET data=? WHERE id=?",
                params![encode_note(&incoming)?, receipt.id()?],
            )?;
        } else {
            self.conn.execute(
                "INSERT INTO notes VALUES(?, ?)",
                params![receipt.id()?, encode_note(receipt)?],
            )?;
        }
        // Its height is indexed when the block arrives, or by `resolve_notes`
        // when the receipt is imported after its block.
        Ok(())
    }
    pub fn reserve(&self, pending: &Pending) -> Result<()> {
        self.conn.execute(
            "INSERT INTO pending VALUES(?, ?)",
            params![pending.txid, serde_json::to_string(pending)?],
        )?;
        self.conn.execute(
            "INSERT OR REPLACE INTO pending_meta(txid, expiry, source) VALUES(?, ?, ?)",
            params![pending.txid, pending.expiry, pending.source],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_metadata_migrates_without_touching_payloads() -> Result<()> {
        let directory = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        let store = Store::open(directory.path(), true)?;
        store.commit()?;
        let pending = Pending {
            txid: "legacy-tx".into(),
            raw: "large transaction payload".into(),
            expiry: 10,
            source: "notes:legacy-note".into(),
            receipt: None,
        };
        store.conn.execute(
            "INSERT INTO pending VALUES(?, ?)",
            params![pending.txid, serde_json::to_string(&pending)?],
        )?;
        store.conn.execute("DROP TABLE pending_meta", [])?;
        store
            .conn
            .execute("DELETE FROM metadata WHERE key='pending_meta_v1'", [])?;
        drop(store);

        let store = Store::open(directory.path(), false)?;
        assert_eq!(
            store.reserved_sources(Some(10))?,
            BTreeSet::from(["notes:legacy-note".to_string()])
        );
        assert!(store.reserved_sources(Some(11))?.is_empty());
        Ok(())
    }

    fn private_store() -> Result<(tempfile::TempDir, Store)> {
        let directory = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        let store = Store::open(directory.path(), true)?;
        Ok((directory, store))
    }

    /// Notes `from..from + spent + kept`, the first `spent` spent, each with
    /// a cached lineage.
    fn lineages(store: &Store, from: usize, spent: usize, kept: usize) -> Result<()> {
        for i in from..from + spent + kept {
            let id = format!("{i:064x}");
            let nullifier = format!("{:064x}", (i + 1) << 32);
            store.put_note_nullifier(&id, 0, &nullifier, (i < from + spent).then_some(9))?;
            store.put_spendable_proof(&id, &[1; 16])?;
        }
        Ok(())
    }

    #[test]
    fn capped_prune_deletes_at_most_its_limit_and_converges() -> Result<()> {
        let (_directory, store) = private_store()?;
        let spent = 2 * PRUNE_BATCH + 300;
        lineages(&store, 0, spent, 3)?;
        let proofs = || -> Result<usize> {
            Ok(store
                .conn
                .query_row("SELECT count(*) FROM spendable_proofs", [], |row| {
                    row.get(0)
                })?)
        };
        let unreachable = || -> Result<()> { unreachable!("no full batch below the limit") };
        assert_eq!(store.prune_spent_proofs(Some(0), unreachable)?, 0);
        assert_eq!(store.prune_spent_proofs(Some(100), unreachable)?, 100);
        // Across a batch boundary: one full batch, then the rest of the limit.
        let mut between = 0;
        let limit = PRUNE_BATCH + 50;
        let deleted = store.prune_spent_proofs(Some(limit), || {
            between += 1;
            Ok(())
        })?;
        assert_eq!((deleted, between), (limit as u64, 1));
        let mut left = spent - 100 - limit;
        assert_eq!(proofs()?, left + 3);
        // As sync calls it: exactly the cap while more remain, then the rest.
        while left > 0 {
            let expected = left.min(PRUNE_SYNC_LIMIT);
            let deleted = store.prune_spent_proofs(Some(PRUNE_SYNC_LIMIT), || Ok(()))?;
            assert_eq!(deleted, expected as u64);
            left -= expected;
            assert_eq!(proofs()?, left + 3);
        }
        assert_eq!(
            store.prune_spent_proofs(Some(PRUNE_SYNC_LIMIT), || Ok(()))?,
            0
        );
        assert_eq!(proofs()?, 3);

        // Without a limit, as prune calls it: every row, between full batches.
        lineages(&store, spent + 3, spent, 3)?;
        let mut between = 0;
        let deleted = store.prune_spent_proofs(None, || {
            between += 1;
            Ok(())
        })?;
        assert_eq!((deleted, between), (spent as u64, spent / PRUNE_BATCH));
        assert_eq!(proofs()?, 6);
        Ok(())
    }

    /// The delete follows the cached proofs and probes each one's nullifiers
    /// by note: it never scans the nullifier history.
    #[test]
    fn prune_plan_probes_nullifiers_by_note() -> Result<()> {
        let (_directory, store) = private_store()?;
        lineages(&store, 0, 20, 20)?;
        let plan: Vec<String> = store
            .conn
            .prepare(&format!("EXPLAIN QUERY PLAN {PRUNE_SPENT_PROOFS}"))?
            .query_map([PRUNE_BATCH], |row| row.get(3))?
            .collect::<rusqlite::Result<_>>()?;
        // `n` from SQLite 3.36, `note_nullifiers AS n` before it.
        let nullifiers = |detail: &&String| {
            detail
                .split_whitespace()
                .any(|word| word == "n" || word == "note_nullifiers")
        };
        assert!(
            plan.iter()
                .filter(nullifiers)
                .all(|detail| detail.starts_with("SEARCH") && detail.contains("(note_id=?)")),
            "{plan:?}"
        );
        assert!(plan.iter().any(|detail| nullifiers(&detail)), "{plan:?}");
        Ok(())
    }

    /// Pruning must not zero and journal every freed proof page: secure
    /// deletion made a capped batch of 1024 proofs ~10s with a 540 MiB journal.
    #[test]
    fn write_connections_do_not_zero_deleted_pages() -> Result<()> {
        let (_directory, store) = private_store()?;
        let secure_delete: i64 = store
            .conn
            .query_row("PRAGMA secure_delete", [], |row| row.get(0))?;
        assert_eq!(secure_delete, 0);
        Ok(())
    }
}
