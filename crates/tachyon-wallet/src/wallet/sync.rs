//! Birthday checkpoints and bounded backfills of contiguous public evidence.

use super::*;
use crate::{
    chain::{self, Block},
    rpc::{self, RpcError},
};
use oss_core::MAX_BLOCKS;
use std::{collections::BTreeMap, sync::Mutex};

/// Remote mode: the OSS and the first height it archives. Tachyon blocks from
/// that height up come from the OSS (design §4.3).
pub(crate) type Archive<'a> = Option<(&'a Oss, u32)>;

pub(super) fn epoch_start(height: u32, activation: u32) -> Result<u32> {
    let offset = height
        .checked_sub(activation)
        .context("height precedes NuTachyon activation")?;
    Ok(height - offset % EPOCH_SIZE)
}

pub(super) fn checkpoint(
    rpc: &Rpc,
    archive: Archive,
    height: u32,
    activation: u32,
) -> Result<Block> {
    rpc.control.stage(format!(
        "Loading trusted epoch checkpoint at height {height}…"
    ))?;
    let block = fetch_block(rpc, archive, height, false)?;
    chain::validate_checkpoint(&block, activation)?;
    ensure!(
        rpc.hash(height)? == block.hash,
        "checkpoint changed during initialization; retry"
    );
    Ok(block)
}

/// `thin` asks the OSS to leave out the tachygrams; the node always sends them.
// privacy: the OSS sees which heights this wallet syncs, so where its history
// starts and when it is online.
fn fetch_block(rpc: &Rpc, archive: Archive, height: u32, thin: bool) -> Result<Block> {
    match archive {
        Some((oss, from)) if height >= from => oss.block(height, thin),
        _ => rpc.block(height),
    }
    .with_context(|| format!(
        "cannot obtain Tachyon evidence at height {height}; if it has been pruned, use an archive node or an OSS that archived it"
    ))
}

#[derive(Default)]
pub(crate) struct SyncCache {
    blocks: std::collections::BTreeMap<u32, Block>,
    validated: std::collections::BTreeSet<(u32, String, String, bool)>,
    fetches: usize,
    validations: usize,
}

impl SyncCache {
    fn fetch(&mut self, rpc: &Rpc, archive: Archive, height: u32, thin: bool) -> Result<Block> {
        let hash = rpc.hash(height)?;
        if let Some(block) = self.blocks.get(&height)
            && block.hash == hash
            && (thin || !block.is_thin())
        {
            return Ok(block.clone());
        }
        let block = fetch_block(rpc, archive, height, thin)?;
        ensure!(block.hash == hash, "Tachyon block changed during fetch");
        self.blocks.insert(height, block.clone());
        self.fetches += 1;
        Ok(block)
    }

    /// `thin`: the block may be a thin copy.
    fn validate(
        &mut self,
        block: &Block,
        previous: Option<&Block>,
        activation: u32,
        thin: bool,
    ) -> Result<()> {
        let key = (
            block.height,
            block.hash.clone(),
            previous.map(|block| block.hash.clone()).unwrap_or_default(),
            block.is_thin(),
        );
        if self.validated.contains(&key) {
            return Ok(());
        }
        if thin {
            chain::validate_thin(block, previous, activation)?;
        } else {
            chain::validate(block, previous, activation)?;
        }
        self.validated.insert(key);
        self.validations += 1;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn stats(&self) -> (usize, usize) {
        (self.fetches, self.validations)
    }
}

/// Blocks `from..=to` from the OSS, each checked against the node's hash at
/// its height (design §4.3). The `getblockhash` batch and the `oss_blocks`
/// calls go out at once. A page `sync-many` already fetched for another
/// wallet comes from the cache, which is not locked during requests.
fn fetch_page(
    cache: &Mutex<SyncCache>,
    rpc: &Rpc,
    oss: &Oss,
    from: u32,
    to: u32,
    thin: bool,
) -> Result<BTreeMap<u32, Block>> {
    let cached: BTreeMap<u32, Block> = {
        let cache = cache.lock().unwrap();
        (from..=to)
            .filter_map(|h| cache.blocks.get(&h).filter(|b| thin || !b.is_thin()))
            .map(|block| (block.height, block.clone()))
            .collect()
    };
    let complete = cached.len() == (from..=to).count();
    let (hashes, fetched) = std::thread::scope(|scope| {
        let fetched = (!complete).then(|| scope.spawn(|| oss_range(oss, from, to, thin)));
        let hashes = rpc.hashes(from, to);
        let fetched = fetched.map(|f| f.join().expect("the OSS fetch does not panic"));
        (hashes, fetched.transpose())
    });
    let hashes = hashes?;
    let matches = |blocks: &BTreeMap<u32, Block>| {
        (from..=to)
            .zip(&hashes)
            .all(|(h, hash)| blocks.get(&h).is_some_and(|block| block.hash == *hash))
    };
    let fetched = match fetched? {
        Some(fetched) => fetched,
        None if matches(&cached) => return Ok(cached),
        // The chain moved since another wallet cached this page.
        None => oss_range(oss, from, to, thin)?,
    };
    ensure!(matches(&fetched), "Tachyon block changed during fetch");
    let mut cache = cache.lock().unwrap();
    cache.fetches += fetched.len();
    cache.blocks.extend(fetched.clone());
    Ok(fetched)
}

/// Blocks `from..=to` from the OSS, in as many calls as its size limit takes.
fn oss_range(oss: &Oss, from: u32, to: u32, thin: bool) -> Result<BTreeMap<u32, Block>> {
    let mut blocks = BTreeMap::new();
    let mut next = from;
    while next <= to {
        for block in oss.blocks(next, to - next + 1, thin)? {
            next = block.height + 1;
            blocks.insert(block.height, block);
        }
    }
    Ok(blocks)
}

/// Hints only narrow the search. Aggregation can put a leaf transaction's
/// commitment in another transaction's stamp in the same block, so only the
/// commitment is checked.
fn contains_receipt(block: &Block, receipt: &Receipt) -> Result<bool> {
    let cm = receipt.id()?;
    Ok(block
        .stamps
        .iter()
        .any(|stamp| stamp.tachygrams.contains(&cm)))
}

/// The full block at `height`, if it holds the receipt's note commitment:
/// from the node, or from the OSS if the node pruned it. A block other than
/// `expected` is a stale hint, and is not downloaded.
fn located_block(
    rpc: &Rpc,
    archive: Archive,
    height: u32,
    expected: Option<&str>,
    receipt: &Receipt,
    config: &Config,
    tip: u32,
) -> Result<Option<Block>> {
    if height < config.activation || height > tip {
        return Ok(None);
    }
    rpc.privacy(&format!(
        "asked the node about block {height}, out of order: it may hold a payment to this wallet"
    ));
    let hash = rpc.hash(height)?;
    if expected.is_some_and(|expected| expected != hash) {
        return Ok(None);
    }
    let block = match (rpc.block(height), archive) {
        (Err(error), Some((oss, from))) if height >= from && error.is::<RpcError>() => {
            rpc.control.privacy(&format!(
                "asked the OSS for block {height} in full: it may hold a payment to this wallet"
            ));
            oss.block(height, false)?
        }
        (result, _) => result?,
    };
    // The subsequent contiguous sync validates the transitions from our
    // checkpoint. This lookup alone never makes a note spendable.
    ensure!(
        hash == block.hash && rpc.hash(height)? == block.hash,
        "receipt block changed during lookup; retry sync"
    );
    Ok(contains_receipt(&block, receipt)?.then_some(block))
}

pub(super) fn locate(
    rpc: &Rpc,
    archive: Archive,
    receipt: &Receipt,
    config: &Config,
    tip: u32,
) -> Result<Option<Block>> {
    let Some(locator) = &receipt.locator else {
        return Ok(None);
    };
    if let Some(height) = locator.height
        && let Some(block) = located_block(
            rpc,
            archive,
            height,
            locator.block_hash.as_deref(),
            receipt,
            config,
            tip,
        )?
    {
        return Ok(Some(block));
    }
    // A reorg can move the same transaction to another height. Ignore the
    // stale hint and resolve the txid against the node's current chain.
    rpc.privacy("asked the node about the transaction that paid a received note");
    let (height, hash) = match rpc.call::<Value>("getrawtransaction", json!([locator.txid, 1])) {
        Ok(result) => {
            // Mempool or side chain: no height or blockhash.
            let (Some(hash), Some(height)) = (result["blockhash"].as_str(), result["height"].as_u64()) else {
                return Ok(None);
            };
            let height = u32::try_from(height)?;
            if height > tip || height < config.activation || rpc.hash(height)? != hash {
                return Ok(None); // Newer than this sync snapshot, or reorganized.
            }
            (height, Some(hash.to_owned()))
        }
        // A pruned node forgets mined transactions; the OSS indexes them.
        Err(error) if rpc::not_found(&error) => {
            let (Some((oss, _)), Some(_)) = (archive, rpc.pruned_below()?) else {
                return Ok(None);
            };
            rpc.control.privacy(
                "asked the OSS where the transaction that paid a received note was mined: it can link this wallet to it",
            );
            match oss.transactions(std::slice::from_ref(&locator.txid))?[..] {
                [Some(height)] => (height, None),
                _ => return Ok(None),
            }
        }
        Err(error) => return Err(error.context("cannot locate receipt transaction; supply --txid/--height if the node lacks historical transaction lookup")),
    };
    let block = located_block(rpc, archive, height, hash.as_deref(), receipt, config, tip)?;
    ensure!(
        block.is_some(),
        "receipt transaction does not contain the note commitment in its block; correct its locator"
    );
    Ok(block)
}

/// Records which of this wallet's pending sends are mined at or below `last`
/// (design §4.3), by ID: sync no longer downloads every block's transaction
/// list. Only sends that could be mined from `synced_from` on are asked
/// about; an earlier sync found any mined below it.
fn find_mined_sends(
    store: &Store,
    rpc: &Rpc,
    archive: Archive,
    synced_from: u32,
    last: &Block,
) -> Result<()> {
    let mut txids = Vec::new();
    for (txid, expiry, _) in store.pending_summaries()? {
        if (expiry == 0 || expiry >= synced_from) && !store.has_transaction(&txid)? {
            txids.push(txid);
        }
    }
    if txids.is_empty() {
        return Ok(());
    }
    let mined = |txid: &str, height: u32, hash: Option<&str>| -> Result<()> {
        if height <= last.height
            && let Some(block) = store.block(height)?
            && hash.is_none_or(|hash| hash == block.hash)
        {
            store.put_transaction(txid, height)?;
        }
        Ok(())
    };
    let mut forgotten = Vec::new();
    // Zakura answers at most 1000 calls per batch.
    for chunk in txids.chunks(1000) {
        // privacy: no warning: the node got these transactions from this wallet.
        let answers = rpc.batch(
            "getrawtransaction",
            chunk.iter().map(|txid| json!([txid, 1])).collect(),
        )?;
        for (txid, answer) in chunk.iter().zip(answers) {
            match answer {
                Ok(tx) => {
                    if let (Some(height), Some(hash)) =
                        (tx["height"].as_u64(), tx["blockhash"].as_str())
                    {
                        mined(txid, u32::try_from(height)?, Some(hash))?;
                    }
                }
                Err(error) if rpc::not_found(&error) => forgotten.push(txid.clone()),
                Err(error) => return Err(error),
            }
        }
    }
    // "Not found" is ambiguous only if the node pruned heights this sync covers.
    if forgotten.is_empty() {
        return Ok(());
    }
    let (Some((oss, _)), Some(pruned)) = (archive, rpc.pruned_below()?) else {
        return Ok(());
    };
    if pruned <= synced_from {
        return Ok(());
    }
    rpc.control.privacy(&format!(
        "asked the OSS where {} of this wallet's transactions were mined, because the node pruned them: it can link this wallet to them",
        forgotten.len()
    ));
    // The OSS's word alone: the node no longer has the block's transactions.
    for (txid, height) in forgotten.iter().zip(oss.transactions(&forgotten)?) {
        if let Some(height) = height {
            mined(txid, height, None)?;
        }
    }
    Ok(())
}

pub(super) fn progress(height: u32, first: u32, stop: u32, tip: u32) -> String {
    format!("Fetching block {height} (batch heights {first}–{stop}; node tip {tip})…")
}

pub(super) fn sync(
    store: &Store,
    config: &Config,
    max_blocks: u32,
    from_height: Option<u32>,
    control: &Control,
    oss: Option<&Oss>,
) -> Result<Value> {
    let cache = std::sync::Arc::new(std::sync::Mutex::new(SyncCache::default()));
    sync_with_cache(store, config, max_blocks, from_height, control, &cache, oss)
}

pub(crate) fn sync_with_cache(
    store: &Store,
    config: &Config,
    max_blocks: u32,
    from_height: Option<u32>,
    control: &Control,
    cache: &std::sync::Arc<std::sync::Mutex<SyncCache>>,
    oss: Option<&Oss>,
) -> Result<Value> {
    let rpc = rpc(config, control)?;
    let funding_address = transaction::funding_address(config.seed)?;
    let funding = AddressUtxos::fetch(&rpc, &funding_address)?;
    let tip = funding.height;
    ensure!(
        tip >= config.activation,
        "node tip precedes NuTachyon activation"
    );
    // Remote mode syncs no further than the OSS has archived.
    let (archive, synced_tip) = match oss {
        Some(oss) => {
            let (from, oss_tip) = oss.archive(tip, &config.genesis)?;
            (Some((oss, from)), oss_tip.min(tip))
        }
        None => (None, tip),
    };
    control.stage("Loading saved chain inputs…")?;
    let initial_start = store.first_height()?.context("wallet has no checkpoint")?;
    let original_last = store.tip()?.context("wallet has no checkpoint")?;
    let original_hash = if original_last.height <= tip {
        Some(rpc.hash(original_last.height)?)
    } else {
        None
    };
    if !(store.network_identity_valid(config)?
        && original_hash.as_deref() == Some(original_last.hash.as_str()))
    {
        ensure!(
            rpc.hash(0)? == config.genesis
                && rpc.hash(config.activation)? == config.activation_hash,
            "network identity changed (including possible regenesis); use a separate wallet directory"
        );
        store.mark_network_identity_valid(config)?;
    }
    let mut reorg = false;
    let mut first = initial_start;
    let mut last = Some(original_last.clone());
    while let Some(candidate) = last.clone() {
        control.check()?;
        let matches = if candidate.height > tip {
            false
        } else {
            let hash = if candidate.height == original_last.height {
                original_hash.clone().expect("original tip was hashed")
            } else {
                rpc.hash(candidate.height)?
            };
            hash == candidate.hash
        };
        if matches {
            break;
        }
        last = if candidate.height == initial_start {
            None
        } else {
            store.block(candidate.height - 1)?
        };
    }
    if let Some(last) = last.clone() {
        if last.height != original_last.height {
            store.rewind(last.height)?;
            reorg = true;
        }
    } else {
        // A checkpoint is pinned to a block, not an eternally trusted height.
        // Re-bootstrap on the configured node after a reorg crossing it.
        reorg = true;
        let height = epoch_start(initial_start.min(tip), config.activation)?;
        let block = checkpoint(&rpc, archive, height, config.activation)?;
        store.clear_chain()?;
        store.put_block(&block)?;
        first = height;
        last = Some(block);
    }
    let last = last.expect("checkpoint was retained or reloaded");
    let mut needed_start = first;
    if let Some(height) = from_height {
        ensure!(height <= tip, "search height is above the node tip");
        needed_start = needed_start.min(epoch_start(height, config.activation)?);
    }
    // Full blocks that hold receipts, from the node.
    let mut located = std::collections::BTreeMap::new();
    for mut receipt in store.unresolved_notes()? {
        control.check()?;
        receipt.check_owner(&SpendingKey::from(config.seed), &config.network_id)?;
        if let Some(block) = locate(&rpc, archive, &receipt, config, tip)? {
            needed_start = needed_start.min(epoch_start(block.height, config.activation)?);
            let locator = receipt
                .locator
                .as_mut()
                .expect("located receipts have a locator");
            locator.height = Some(block.height);
            locator.block_hash = Some(block.hash.clone());
            store.put_note(&receipt)?;
            // A receipt can arrive after its block was synced thin.
            if store
                .block(block.height)?
                .is_some_and(|stored| stored.is_thin())
            {
                fill(store, &block, config.activation)?;
            }
            located.insert(block.height, block);
        }
    }
    let backfill = needed_start < first;
    let previous = if backfill {
        let block = checkpoint(&rpc, archive, needed_start, config.activation)?;
        store.put_block(&block)?;
        store.clear_funding_snapshot()?;
        // Keep the cached suffix on disk and reconnect it as the bounded
        // backfill advances. No wallet notes or reservations are discarded.
        Some(block)
    } else {
        Some(last)
    };
    let start = previous.as_ref().expect("sync has a checkpoint").height;
    let stop = start.saturating_add(max_blocks).min(synced_tip);
    // Thin sync: closed epochs come from the OSS without their tachygrams.
    // Receipts' blocks stay full, and spends in thin epochs are looked up at
    // the end. A rescan (`--from-height`) fetches full blocks.
    let current_epoch = synced_tip.saturating_sub(config.activation) / EPOCH_SIZE;
    let thin = |height: u32| {
        archive.is_some_and(|(_, from)| height >= from)
            && (height - config.activation) / EPOCH_SIZE < current_epoch
    };
    let fetch_thin = |height| from_height.is_none() && thin(height);
    // Remote heights not stored yet, in pages of up to `MAX_BLOCKS` that never
    // mix thin and full blocks.
    let stored = store.block_heights(start.saturating_add(1), stop)?;
    let mut pages: Vec<(u32, u32, bool)> = Vec::new();
    if let Some((_, from)) = archive {
        for height in start.saturating_add(1).max(from)..=stop {
            if stored.contains(&height) {
                continue;
            }
            let thin = fetch_thin(height);
            match pages.last_mut() {
                Some((first, last, page_thin))
                    if *last + 1 == height
                        && *page_thin == thin
                        && height - *first < MAX_BLOCKS =>
                {
                    *last = height;
                }
                _ => pages.push((height, height, thin)),
            }
        }
    }
    control.stage(format!(
        "Syncing heights {}–{stop} (node tip {tip})…",
        start.saturating_add(1).min(stop)
    ))?;
    let previous = std::thread::scope(|scope| -> Result<Option<Block>> {
        // The next page is fetched while this thread validates and stores
        // the one before (design §4.3).
        let (sender, arrivals) = std::sync::mpsc::sync_channel(1);
        if let Some((oss, _)) = archive
            && !pages.is_empty()
        {
            let background = control.background();
            let (rpc, oss) = (rpc.fork(&background)?, oss.fork(&background)?);
            let pages = &pages;
            scope.spawn(move || {
                for &(first, last, thin) in pages {
                    let page = fetch_page(cache, &rpc, &oss, first, last, thin);
                    let failed = page.is_err();
                    if sender.send(page).is_err() || failed {
                        break;
                    }
                }
            });
        }
        let mut previous = previous;
        let (mut ahead, mut received) = (BTreeMap::new(), 0);
        for height in start.saturating_add(1)..=stop {
            control.stage(progress(height, start.saturating_add(1), stop, tip))?;
            let block = if let Some(cached) = store.block(height)? {
                if rpc.hash(height)? == cached.hash {
                    cached
                } else {
                    store.rewind(height - 1)?;
                    reorg = true;
                    cache
                        .lock()
                        .unwrap()
                        .fetch(&rpc, archive, height, fetch_thin(height))?
                }
            } else if archive.is_some_and(|(_, from)| height >= from) {
                while !ahead.contains_key(&height)
                    && pages
                        .get(received)
                        .is_some_and(|&(first, ..)| first <= height)
                {
                    ahead.extend(arrivals.recv().context("the page fetcher stopped")??);
                    received += 1;
                }
                match ahead.remove(&height) {
                    Some(block) => block,
                    // Unplanned: a reorg rewound blocks that were stored.
                    None => {
                        cache
                            .lock()
                            .unwrap()
                            .fetch(&rpc, archive, height, fetch_thin(height))?
                    }
                }
            } else {
                cache
                    .lock()
                    .unwrap()
                    .fetch(&rpc, archive, height, fetch_thin(height))?
            };
            // Keep a receipt's block in full. Its thin copy was fetched anyway: a
            // gap in the requests would point the OSS at the note.
            let block = match located.remove(&height) {
                Some(full) if full.hash == block.hash => full,
                _ => block,
            };
            control.stage(format!("Validating block {height}…"))?;
            cache.lock().unwrap().validate(
                &block,
                previous.as_ref(),
                config.activation,
                thin(height),
            )?;
            control.check()?;
            store.put_block(&block)?;
            previous = Some(block);
        }
        Ok(previous)
    })?;
    let last = previous.expect("sync has a checkpoint");
    if last.height == tip {
        control.stage("Validating transparent funding snapshot…")?;
        store.put_funding_snapshot(&funding.into_snapshot(&rpc, &funding_address, store)?)?;
    }
    ensure!(
        rpc.hash(last.height)? == last.hash,
        "chain reorganized during sync; retry"
    );
    find_mined_sends(store, &rpc, archive, start.saturating_add(1), &last)?;
    let lookup = |values: &[String]| thin_spends(store, &rpc, archive, config.activation, values);
    super::refresh_note_nullifiers(store, config, last.epoch, Some(&lookup))?;
    let unresolved = store.unresolved_notes()?.len();
    Ok(
        json!({"height":last.height,"hash":last.hash,"epoch":last.epoch,"caught_up":last.height == tip,
        "reorg":reorg,
        "birthday_height":config.birthday_height.unwrap_or(config.activation),
        "sync_start_height":if backfill { needed_start } else { first },
        "unresolved_receipts":unresolved,
        "transparent_synced_height":store.funding_snapshot()?.map(|snapshot| snapshot.height)}),
    )
}

/// Where `nullifiers` are published, for epochs synced thin, from the OSS.
/// Each claimed spend is checked in its block, which is then kept in full: a
/// false claim would hide the note.
fn thin_spends(
    store: &Store,
    rpc: &Rpc,
    archive: Archive,
    activation: u32,
    nullifiers: &[String],
) -> Result<Vec<Option<u32>>> {
    let (oss, _) = archive
        .context("this wallet synced epochs thin through an OSS; pass --oss-url to check them")?;
    rpc.control.privacy(&format!(
        "asked the OSS whether a note is spent, with its nullifiers for {} epoch(s) synced thin. \
         The OSS can link them to each other, and a published one to the transaction that spent the note.",
        nullifiers.len()
    ));
    let heights = oss.tachygrams(nullifiers)?;
    for (nullifier, height) in nullifiers.iter().zip(&heights) {
        if let Some(height) = *height {
            let block = fetch_block(rpc, archive, height, false)?;
            ensure!(
                block
                    .stamps
                    .iter()
                    .any(|s| s.tachygrams.contains(nullifier)),
                "the OSS says block {height} publishes a nullifier that it does not"
            );
            fill(store, &block, activation)?;
        }
    }
    Ok(heights)
}

/// Replaces the synced block at `full.height` with `full`, once it is the
/// same block with every tachygram.
fn fill(store: &Store, full: &Block, activation: u32) -> Result<()> {
    let stored = store
        .block(full.height)?
        .with_context(|| format!("block {} is not synced", full.height))?;
    ensure!(
        stored.hash == full.hash && stored.anchor_after == full.anchor_after,
        "block {} changed since it was synced; sync again",
        full.height
    );
    let previous = store.block(full.height - 1)?;
    chain::validate(full, previous.as_ref(), activation)?;
    store.put_block(full)
}
