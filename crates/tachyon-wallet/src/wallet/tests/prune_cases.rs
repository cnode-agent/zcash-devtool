use super::*;
use crate::store::{PRUNE_SPENT_PROOFS, PRUNE_SYNC_LIMIT};
use rand::RngExt;
use rusqlite::{Connection, OpenFlags};
use std::path::Path;

/// One cached `NoteSpendable` PCD as `Pcd::to_bytes` writes it.
const PROOF_BYTES: usize = 524_688;

fn run_prune(dir: &Path, compact: bool) -> Result<Value> {
    command(
        dir,
        Operation::Prune {
            compact,
            sizes: false,
        },
    )
}

fn run_prune_sizes(dir: &Path, compact: bool) -> Result<Value> {
    command(
        dir,
        Operation::Prune {
            compact,
            sizes: true,
        },
    )
}

fn lineage(dir: &Path, note: &str) -> Result<Option<Vec<u8>>> {
    // Dropped without a commit: nothing it creates persists.
    Store::open(dir, false)?.spendable_proof(note)
}

fn put_lineage(dir: &Path, note: &str, pcd: &[u8]) -> Result<()> {
    let store = Store::open(dir, false)?;
    store.put_spendable_proof(note, pcd)?;
    store.commit()
}

fn database(dir: &Path) -> Result<Connection> {
    Ok(Connection::open_with_flags(
        dir.join("tachyon.sqlite"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?)
}

fn row_counts(dir: &Path) -> Result<BTreeMap<String, u64>> {
    let conn = database(dir)?;
    let names: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")?
        .query_map([], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    names
        .into_iter()
        .map(|name| {
            let count = conn.query_row(&format!("SELECT count(*) FROM \"{name}\""), [], |row| {
                row.get(0)
            })?;
            Ok((name, count))
        })
        .collect()
}

fn pragma(dir: &Path, name: &str) -> Result<String> {
    Ok(
        database(dir)?.query_row(&format!("PRAGMA {name}"), [], |row| {
            row.get::<_, rusqlite::types::Value>(0)
                .map(|value| match value {
                    rusqlite::types::Value::Integer(n) => n.to_string(),
                    rusqlite::types::Value::Text(text) => text,
                    other => format!("{other:?}"),
                })
        })?,
    )
}

fn file_digest(dir: &Path) -> Result<String> {
    Ok(hex::encode(Sha256::digest(std::fs::read(
        dir.join("tachyon.sqlite"),
    )?)))
}

/// A wallet as a binary without pruning leaves it: a mined note, a payment
/// still pending with its operation ID, and `notes` imported notes. The first
/// `spent` of them are spent and keep a cached lineage of `bytes`, as do the
/// next `kept`, which are unspent. Lineages are random bytes: prune never
/// decodes them. Returns the unspent notes that hold a lineage.
fn backlog(
    node: &Node,
    dir: &Path,
    notes: usize,
    spent: usize,
    kept: usize,
    bytes: usize,
) -> Result<Vec<String>> {
    let funding = init_wallet(node, dir)?;
    install_funding(node, &funding, &[1_000_000, 500_000])?;
    let shield = |amount| Operation::Shield {
        amount_zat: Some(amount),
        txid: None,
        index: None,
    };
    command_with_id(dir, shield(400_000), Some("backlog-mined"))?;
    node.mine()?;
    command(dir, SYNC)?;
    command_with_id(dir, shield(300_000), Some("backlog-pending"))?;
    let address = command(dir, Operation::Address)?;
    let network = address["network_id"].as_str().unwrap();
    let recipient = address["tachyon_address"].as_str().unwrap();
    let store = Store::open(dir, false)?;
    let tip = store.tip()?.unwrap();
    let mut rng = rand::rng();
    let mut pcd = vec![0; bytes];
    let mut unspent = Vec::new();
    for i in 0..notes {
        let receipt = Receipt::new(network, recipient, 1_000 + u64::try_from(i)?)?;
        let id = receipt.id()?;
        store.put_note(&receipt)?;
        let nullifier = hex::encode(Sha256::digest(format!("backlog nullifier {i}")));
        let is_spent = i < spent;
        store.put_note_nullifier(&id, tip.epoch, &nullifier, is_spent.then_some(tip.height))?;
        if i < spent + kept {
            rng.fill(&mut pcd[..]);
            store.put_spendable_proof(&id, &pcd)?;
            if !is_spent {
                unspent.push(id);
            }
        }
    }
    store.commit()?;
    Ok(unspent)
}

/// Sync discards a note's lineage once its spend is recorded, both when a
/// block's index marks the nullifier and when the note's first nullifier row
/// is written already spent (creation and spend found in one sync).
#[test]
fn sync_discards_spent_lineages_however_the_spend_is_found() -> Result<()> {
    let node = Node::start()?;
    let temp = tempfile::tempdir()?;
    let (alice, stale) = (temp.path().join("alice"), temp.path().join("stale"));
    let funding = init_wallet(&node, &alice)?;
    install_funding(&node, &funding, &[1_000_000])?;
    command(
        &alice,
        Operation::Shield {
            amount_zat: Some(800_000),
            txid: None,
            index: None,
        },
    )?;
    // Holds the note's receipt, but not the block that mines it.
    copy_wallet(&alice, &stale)?;
    node.mine()?;
    command(&alice, SYNC)?;
    let note = command(&alice, Operation::BalanceSummary)?["notes"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let to = command(&alice, Operation::Address)?["tachyon_address"]
        .as_str()
        .unwrap()
        .to_owned();
    command(
        &alice,
        Operation::Send {
            to,
            amount_zat: 100_000,
        },
    )?;
    assert!(lineage(&alice, &note)?.is_some(), "the payment cached it");
    node.mine()?;
    command(&alice, SYNC)?;
    assert!(
        Store::open_readonly(&alice)?
            .spent_note_ids()?
            .contains(&note)
    );
    assert_eq!(lineage(&alice, &note)?, None);

    // An unspent note's lineage survives sync.
    let change = command(&alice, Operation::BalanceSummary)?["notes"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    put_lineage(&alice, &change, &[7; 64])?;
    command(&alice, SYNC)?;
    assert_eq!(lineage(&alice, &change)?, Some(vec![7; 64]));

    put_lineage(&stale, &note, &[7; 64])?;
    command(&stale, SYNC)?;
    assert!(
        Store::open_readonly(&stale)?
            .spent_note_ids()?
            .contains(&note)
    );
    assert_eq!(lineage(&stale, &note)?, None);
    Ok(())
}

#[test]
fn prune_deletes_only_spent_lineages_and_a_second_run_is_a_no_op() -> Result<()> {
    let node = Node::start()?;
    let temp = tempfile::tempdir()?;
    let dir = temp.path().join("wallet");
    let kept = backlog(&node, &dir, 20, 15, 1, PROOF_BYTES)?;
    let kept_lineage = lineage(&dir, &kept[0])?;
    let before = row_counts(&dir)?;
    for table in [
        "blocks",
        "notes",
        "note_nullifiers",
        "tachygrams",
        "pending",
        "operations",
    ] {
        assert!(before[table] > 0, "the fixture has no {table}");
    }
    let summary = command(&dir, Operation::BalanceSummary)?;

    let pruned = run_prune_sizes(&dir, false)?;
    assert_eq!(pruned["rows_before"], 16, "{pruned}");
    assert_eq!(pruned["rows_deleted"], 15, "{pruned}");
    assert_eq!(pruned["rows_after"], 1, "{pruned}");
    assert_eq!(pruned["compacted"], false);
    assert_eq!(pruned["quick_check"], Value::Null);
    let proofs = pruned["tables_before"]["spendable_proofs"]
        .as_u64()
        .unwrap();
    assert!(proofs >= 16 * PROOF_BYTES as u64, "{pruned}");
    // Without --compact the file keeps its size; the space is free pages.
    assert_eq!(pruned["bytes_after"], pruned["bytes_before"]);
    assert!(pruned["free_bytes_after"].as_u64().unwrap() >= 15 * PROOF_BYTES as u64);
    let mut expected = before.clone();
    expected.insert("spendable_proofs".into(), 1);
    assert_eq!(row_counts(&dir)?, expected);
    assert_eq!(lineage(&dir, &kept[0])?, kept_lineage);
    assert_eq!(command(&dir, Operation::BalanceSummary)?, summary);

    let digest = file_digest(&dir)?;
    let again = run_prune(&dir, false)?;
    assert_eq!(again["rows_deleted"], 0, "{again}");
    assert_eq!(again["rows_after"], 1, "{again}");
    assert_eq!(file_digest(&dir)?, digest);
    assert_eq!(row_counts(&dir)?, expected);
    Ok(())
}

#[test]
fn prune_reports_table_sizes_only_with_sizes() -> Result<()> {
    let node = Node::start()?;
    let temp = tempfile::tempdir()?;
    let dir = temp.path().join("wallet");
    backlog(&node, &dir, 4, 2, 1, 1024)?;
    let pruned = run_prune(&dir, false)?;
    assert_eq!(pruned["rows_deleted"], 2, "{pruned}");
    assert_eq!(pruned["sizes"], false, "{pruned}");
    assert_eq!(pruned["tables_before"], Value::Null, "{pruned}");
    assert_eq!(pruned["tables_after"], Value::Null, "{pruned}");
    for key in [
        "rows_before",
        "rows_after",
        "bytes_before",
        "bytes_after",
        "free_bytes_before",
        "free_bytes_after",
    ] {
        assert!(pruned[key].is_u64(), "{key}: {pruned}");
    }
    let sized = run_prune_sizes(&dir, false)?;
    assert_eq!(sized["sizes"], true, "{sized}");
    for key in ["tables_before", "tables_after"] {
        for table in [
            "blocks",
            "notes",
            "note_nullifiers",
            "spendable_proofs",
            "pending",
            "operations",
        ] {
            assert!(
                sized[key][table].as_u64().unwrap() > 0,
                "{key}.{table}: {sized}"
            );
        }
    }
    Ok(())
}

/// Each sync deletes at most [`PRUNE_SYNC_LIMIT`] lineages, so a backlog
/// clears over several syncs; `prune` deletes it all in one command.
#[test]
fn sync_prunes_at_most_its_cap_while_prune_takes_every_row() -> Result<()> {
    let node = Node::start()?;
    let temp = tempfile::tempdir()?;
    let (synced, pruned) = (temp.path().join("synced"), temp.path().join("pruned"));
    let spent = 2 * PRUNE_SYNC_LIMIT + 52;
    backlog(&node, &synced, spent + 1, spent, 1, 16)?;
    copy_wallet(&synced, &pruned)?;
    let proofs =
        |dir| -> Result<usize> { Ok(usize::try_from(row_counts(dir)?["spendable_proofs"])?) };
    let mut left = spent;
    while left > 0 {
        command(&synced, SYNC)?;
        left -= left.min(PRUNE_SYNC_LIMIT);
        assert_eq!(proofs(&synced)?, left + 1);
    }
    // Converged: the unspent note's lineage stays.
    command(&synced, SYNC)?;
    assert_eq!(proofs(&synced)?, 1);

    let result = run_prune(&pruned, false)?;
    assert_eq!(result["rows_deleted"], spent, "{result}");
    assert_eq!(proofs(&pruned)?, 1);
    Ok(())
}

#[test]
fn prune_without_lineages_changes_nothing() -> Result<()> {
    let node = Node::start()?;
    let temp = tempfile::tempdir()?;
    let dir = temp.path().join("wallet");
    init_wallet(&node, &dir)?;
    let (digest, tables) = (file_digest(&dir)?, row_counts(&dir)?);
    assert!(!tables.contains_key("spendable_proofs"));
    for compact in [false, true] {
        let pruned = run_prune(&dir, compact)?;
        assert_eq!(pruned["rows_before"], 0, "{pruned}");
        assert_eq!(pruned["rows_deleted"], 0, "{pruned}");
        assert_eq!(pruned["rows_after"], 0, "{pruned}");
        assert_eq!(pruned["compacted"], false, "{pruned}");
        assert_eq!(file_digest(&dir)?, digest);
        assert_eq!(row_counts(&dir)?, tables);
    }
    // New wallets can return free pages without a full VACUUM.
    assert_eq!(pragma(&dir, "auto_vacuum")?, "2");
    Ok(())
}

#[test]
fn prune_compact_returns_the_space_and_the_wallet_still_works() -> Result<()> {
    let node = Node::start()?;
    let temp = tempfile::tempdir()?;
    let dir = temp.path().join("wallet");
    let kept = backlog(&node, &dir, 20, 15, 1, PROOF_BYTES)?;
    // As a wallet created before new wallets enabled incremental vacuum.
    Connection::open(dir.join("tachyon.sqlite"))?
        .execute_batch("PRAGMA auto_vacuum=NONE; VACUUM;")?;
    assert_eq!(pragma(&dir, "auto_vacuum")?, "0");
    let kept_lineage = lineage(&dir, &kept[0])?;
    let before = row_counts(&dir)?;
    let address = command(&dir, Operation::Address)?;
    let summary = command(&dir, Operation::BalanceSummary)?;

    let pruned = run_prune(&dir, true)?;
    assert_eq!(pruned["rows_deleted"], 15, "{pruned}");
    assert_eq!(pruned["rows_after"], 1, "{pruned}");
    assert_eq!(pruned["compacted"], true, "{pruned}");
    assert_eq!(pruned["quick_check"], "ok", "{pruned}");
    assert_eq!(pruned["free_bytes_after"], 0, "{pruned}");
    let (bytes_before, bytes_after) = (
        pruned["bytes_before"].as_u64().unwrap(),
        pruned["bytes_after"].as_u64().unwrap(),
    );
    assert!(
        bytes_before - bytes_after >= 15 * PROOF_BYTES as u64,
        "{pruned}"
    );
    let path = dir.join("tachyon.sqlite");
    assert_eq!(std::fs::metadata(&path)?.len(), bytes_after);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&path)?.permissions().mode() & 0o777,
            0o600
        );
    }
    let files: Vec<String> = std::fs::read_dir(&dir)?
        .map(|entry| Ok(entry?.file_name().to_string_lossy().into_owned()))
        .collect::<Result<_>>()?;
    assert_eq!(files, ["tachyon.sqlite"]);
    assert_eq!(pragma(&dir, "quick_check")?, "ok");
    assert_eq!(pragma(&dir, "auto_vacuum")?, "2");
    let mut expected = before.clone();
    expected.insert("spendable_proofs".into(), 1);
    assert_eq!(row_counts(&dir)?, expected);
    assert_eq!(lineage(&dir, &kept[0])?, kept_lineage);

    let digest = file_digest(&dir)?;
    let again = run_prune(&dir, true)?;
    assert_eq!(again["rows_deleted"], 0, "{again}");
    assert_eq!(again["compacted"], false, "{again}");
    assert_eq!(file_digest(&dir)?, digest);

    assert_eq!(command(&dir, Operation::Address)?, address);
    assert_eq!(command(&dir, Operation::BalanceSummary)?, summary);
    assert_eq!(command(&dir, SYNC)?["caught_up"], true);
    Ok(())
}

#[test]
fn prune_refuses_while_another_connection_holds_the_wallet() -> Result<()> {
    let node = Node::start()?;
    let temp = tempfile::tempdir()?;
    let dir = temp.path().join("wallet");
    backlog(&node, &dir, 4, 2, 0, 1024)?;
    let path = dir.join("tachyon.sqlite");
    for writer in [true, false] {
        let other = Connection::open(&path)?;
        if writer {
            other.execute_batch("BEGIN IMMEDIATE")?;
        } else {
            other.execute_batch("BEGIN")?;
            other.query_row("SELECT count(*) FROM blocks", [], |row| {
                row.get::<_, u64>(0)
            })?;
        }
        for compact in [false, true] {
            let error = run_prune(&dir, compact).unwrap_err();
            assert!(
                format!("{error:#}").contains("stop the writer first"),
                "writer={writer} compact={compact}: {error:?}"
            );
        }
    }
    assert_eq!(row_counts(&dir)?["spendable_proofs"], 2);

    // A WAL another connection still reads refuses too; once it is gone,
    // --compact returns the wallet to its rollback journal.
    let other = Connection::open(&path)?;
    let mode: String = other.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
    assert_eq!(mode, "wal");
    other.execute("INSERT INTO metadata VALUES('wal-test', '1')", [])?;
    other.execute_batch("BEGIN")?;
    other.query_row("SELECT count(*) FROM blocks", [], |row| {
        row.get::<_, u64>(0)
    })?;
    let error = run_prune(&dir, true).unwrap_err();
    assert!(
        format!("{error:#}").contains("stop the writer first"),
        "{error:#}"
    );
    drop(other);
    let pruned = run_prune(&dir, true)?;
    assert_eq!(pruned["rows_deleted"], 2, "{pruned}");
    assert_eq!(pruned["compacted"], true, "{pruned}");
    assert_eq!(pragma(&dir, "journal_mode")?, "delete");
    for suffix in ["-wal", "-shm", "-journal"] {
        assert!(
            !dir.join(format!("tachyon.sqlite{suffix}")).exists(),
            "{suffix}"
        );
    }
    assert_eq!(
        database(&dir)?.query_row(
            "SELECT value FROM metadata WHERE key='wal-test'",
            [],
            |row| { row.get::<_, String>(0) }
        )?,
        "1"
    );
    Ok(())
}

/// The storage benchmark on the synthetic fixture of the pruning brief:
/// 2,000 notes with one nullifier row each (1,500 spent), and 1,500 cached
/// lineages of 524,688 bytes. Writes about 0.8 GB:
///
/// cargo test --release -p tachyon-wallet --lib prune_benchmark -- --ignored --nocapture
///
/// With TACHYON_PRUNE_BENCH_KEEP=<dir>, a copy of the unpruned wallet is
/// left there for the CLI (its node is gone: only offline commands work).
#[test]
#[ignore = "writes a 0.8 GB fixture"]
fn prune_benchmark() -> Result<()> {
    let node = Node::start()?;
    let temp = tempfile::tempdir()?;
    let dir = temp.path().join("wallet");
    let started = std::time::Instant::now();
    backlog(&node, &dir, 2_000, 1_500, 0, PROOF_BYTES)?;
    eprintln!("fixture built in {:.1}s", started.elapsed().as_secs_f64());
    if let Some(keep) = std::env::var_os("TACHYON_PRUNE_BENCH_KEEP") {
        copy_wallet(&dir, Path::new(&keep))?;
    }
    let path = dir.join("tachyon.sqlite");
    eprintln!("file bytes before: {}", std::fs::metadata(&path)?.len());
    eprintln!(
        "rows before: {}",
        serde_json::to_string(&row_counts(&dir)?)?
    );
    {
        let conn = database(&dir)?;
        let mut plan = conn.prepare(&format!("EXPLAIN QUERY PLAN {PRUNE_SPENT_PROOFS}"))?;
        let rows = plan
            .query_map([crate::store::PRUNE_BATCH], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(3)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        eprintln!("query plan (SQLite {}):", rusqlite::version());
        for (id, parent, detail) in rows {
            eprintln!("  {id} {parent} {detail}");
        }
    }
    let address = command(&dir, Operation::Address)?;
    let summary = command(&dir, Operation::BalanceSummary)?;
    let started = std::time::Instant::now();
    let pruned = run_prune(&dir, true)?;
    let wall = started.elapsed();
    eprintln!("prune --compact wall time: {:.3}s", wall.as_secs_f64());
    eprintln!("prune --compact output: {pruned}");
    eprintln!("file bytes after: {}", std::fs::metadata(&path)?.len());
    eprintln!("rows after: {}", serde_json::to_string(&row_counts(&dir)?)?);
    eprintln!("quick_check after: {}", pragma(&dir, "quick_check")?);
    assert_eq!(pruned["rows_deleted"], 1_500);
    assert_eq!(command(&dir, Operation::Address)?, address);
    let after = command(&dir, Operation::BalanceSummary)?;
    assert_eq!(after, summary);
    eprintln!("address after: {}", command(&dir, Operation::Address)?);
    eprintln!("balance-summary after: {after}");
    let started = std::time::Instant::now();
    let synced = command(&dir, SYNC)?;
    eprintln!(
        "sync after ({:.2}s): {synced}",
        started.elapsed().as_secs_f64()
    );
    assert_eq!(synced["caught_up"], true);

    // The first syncs after an upgrade: the same backlog is discarded inside
    // sync's own transaction, at most PRUNE_SYNC_LIMIT rows per sync.
    let node = Node::start()?;
    let dir = temp.path().join("synced");
    backlog(&node, &dir, 2_000, 1_500, 0, PROOF_BYTES)?;
    // One capped delete under sync's conditions (Store::open's BEGIN
    // IMMEDIATE, rollback journal, synchronous=FULL), in both file formats:
    // its journal holds the pages it changes, not the freed pages.
    for legacy in [false, true] {
        let copy = temp
            .path()
            .join(if legacy { "legacy" } else { "incremental" });
        copy_wallet(&dir, &copy)?;
        if legacy {
            Connection::open(copy.join("tachyon.sqlite"))?
                .execute_batch("PRAGMA auto_vacuum=NONE; VACUUM;")?;
        }
        let store = Store::open(&copy, false)?;
        let started = std::time::Instant::now();
        let deleted = store.prune_spent_proofs(Some(PRUNE_SYNC_LIMIT), || Ok(()))?;
        let elapsed = started.elapsed();
        let journal = std::fs::metadata(copy.join("tachyon.sqlite-journal"))?.len();
        store.commit()?;
        eprintln!(
            "capped delete, auto_vacuum={}: {deleted} rows in {:.3}s, journal {journal} bytes",
            if legacy { "NONE" } else { "INCREMENTAL" },
            elapsed.as_secs_f64()
        );
        assert_eq!(deleted, PRUNE_SYNC_LIMIT as u64);
        assert!(journal < 16 << 20, "journal {journal} bytes");
    }
    let started = std::time::Instant::now();
    let synced = command(&dir, SYNC)?;
    let first = started.elapsed();
    eprintln!(
        "first sync over the backlog ({:.2}s): {synced}",
        first.as_secs_f64()
    );
    assert!(first < Duration::from_secs(30), "{first:?}");
    assert_eq!(
        row_counts(&dir)?["spendable_proofs"],
        (1_500 - PRUNE_SYNC_LIMIT) as u64
    );
    let started = std::time::Instant::now();
    command(&dir, SYNC)?;
    eprintln!(
        "second sync over the backlog: {:.2}s",
        started.elapsed().as_secs_f64()
    );
    assert_eq!(row_counts(&dir)?["spendable_proofs"], 0);
    Ok(())
}
