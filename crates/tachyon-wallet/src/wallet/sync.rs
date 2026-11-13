//! Birthday checkpoints and bounded backfills of contiguous public evidence.

use super::*;
use crate::{
    chain::{self, Block},
    note::Locator,
    rpc::{self, RpcError},
};
use oss_core::MAX_BLOCKS;
use std::collections::BTreeMap;

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
        Some((oss, from)) if height >= from => oss
            .block(height, thin)
            .and_then(|block| rpc.with_transactions(block, true)),
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

    /// Blocks `from..=to` from the OSS, each checked against the node's block
    /// at its height. One `getblock` batch gives the node's hashes and
    /// transaction lists; `oss_blocks` pages fetch the blocks not cached.
    fn fetch_range(
        &mut self,
        rpc: &Rpc,
        oss: &Oss,
        from: u32,
        to: u32,
        thin: bool,
    ) -> Result<BTreeMap<u32, Block>> {
        let ordinary = rpc.batch(
            "getblock",
            (from..=to).map(|h| json!([h.to_string(), 1])).collect(),
        )?;
        let mut page = BTreeMap::new();
        let mut blocks = BTreeMap::new();
        for (height, ordinary) in (from..=to).zip(ordinary) {
            let hash = match &ordinary {
                Ok(header) => header["hash"]
                    .as_str()
                    .context("getblock without a hash")?
                    .to_owned(),
                // A pruned body has no `getblock`: ask for the hash alone.
                Err(_) => rpc.hash(height)?,
            };
            if let Some(block) = self
                .blocks
                .get(&height)
                .filter(|block| block.hash == hash && (thin || !block.is_thin()))
            {
                blocks.insert(height, block.clone());
                continue;
            }
            if !page.contains_key(&height) {
                page = oss
                    .blocks(height, to - height + 1, thin)?
                    .into_iter()
                    .map(|block| (block.height, block))
                    .collect();
            }
            let block = page
                .remove(&height)
                .expect("an OSS page starts at its first height");
            ensure!(block.hash == hash, "Tachyon block changed during fetch");
            let block = rpc::attach_transactions(block, ordinary, true)?;
            self.blocks.insert(height, block.clone());
            self.fetches += 1;
            blocks.insert(height, block);
        }
        Ok(blocks)
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

/// Hints only narrow the search. Aggregation can put a leaf transaction's
/// commitment in another transaction's stamp in the same block.
fn contains_receipt(block: &Block, receipt: &Receipt, locator: &Locator) -> Result<bool> {
    let cm = receipt.id()?;
    Ok(block.transactions.contains(&locator.txid)
        && block
            .stamps
            .iter()
            .any(|stamp| stamp.tachygrams.contains(&cm)))
}

fn located_block(
    rpc: &Rpc,
    height: u32,
    receipt: &Receipt,
    locator: &Locator,
    config: &Config,
    tip: u32,
) -> Result<Option<Block>> {
    if height < config.activation || height > tip {
        return Ok(None);
    }
    // Check the cheap, retained block metadata first. A stale height hint must
    // not require the payload of an unrelated, potentially pruned block.
    // privacy: tells the node which block paid this wallet.
    let hash = rpc.hash(height)?;
    let header: Value = rpc.call("getblock", json!([hash, 1]))?;
    ensure!(
        header["hash"] == hash && header["height"] == height,
        "receipt block identity mismatch"
    );
    let transactions = header["tx"]
        .as_array()
        .context("receipt block has no transaction list")?;
    if !transactions
        .iter()
        .any(|id| id.as_str() == Some(locator.txid.as_str()))
    {
        return Ok(None);
    }
    let block = fetch_block(rpc, None, height, false)?;
    // The subsequent contiguous sync validates the transitions from our
    // checkpoint. This lookup alone never makes a note spendable.
    ensure!(
        hash == block.hash && rpc.hash(height)? == block.hash,
        "receipt block changed during lookup; retry sync"
    );
    Ok(contains_receipt(&block, receipt, locator)?.then_some(block))
}

pub(super) fn locate(
    rpc: &Rpc,
    receipt: &Receipt,
    config: &Config,
    tip: u32,
) -> Result<Option<Block>> {
    let Some(locator) = &receipt.locator else {
        return Ok(None);
    };
    if let Some(height) = locator.height
        && let Some(block) = located_block(rpc, height, receipt, locator, config, tip)?
    {
        return Ok(Some(block));
    }
    // A reorg can move the same transaction to another height. Ignore the
    // stale hint and resolve the txid against the node's current chain.
    // privacy: tells the node which transaction paid this wallet.
    let result: Value = match rpc.call("getrawtransaction", json!([locator.txid, 1])) {
        Ok(result) => result,
        Err(error) if error.downcast_ref::<RpcError>().is_some_and(|error| error.code == Some(-5)) => return Ok(None),
        Err(error) => return Err(error.context("cannot locate receipt transaction; supply --txid/--height if the node lacks historical transaction lookup")),
    };
    let Some(hash) = result["blockhash"].as_str() else {
        return Ok(None);
    };
    bytes32(hash)?;
    let header: Value = rpc.call("getblock", json!([hash, 1]))?;
    let height = u32::try_from(
        header["height"]
            .as_u64()
            .context("receipt block has no height")?,
    )?;
    if height > tip || height < config.activation || rpc.hash(height)? != hash {
        return Ok(None); // Mempool, side-chain, or newer than this sync snapshot.
    }
    ensure!(header["hash"] == hash, "receipt block identity mismatch");
    let block = located_block(rpc, height, receipt, locator, config, tip)?;
    ensure!(
        block.is_some(),
        "receipt transaction does not contain the note commitment in its block; correct its locator"
    );
    Ok(block)
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
        if let Some(block) = locate(&rpc, &receipt, config, tip)? {
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
    let mut previous = if backfill {
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
    // Blocks fetched a page ahead from the OSS.
    let mut ahead = BTreeMap::new();
    control.stage(format!(
        "Syncing heights {}–{stop} (node tip {tip})…",
        start.saturating_add(1).min(stop)
    ))?;
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
        } else if let Some((oss, _)) = archive.filter(|(_, from)| height >= *from) {
            if !ahead.contains_key(&height) {
                // A page never mixes thin and full blocks.
                let thin = fetch_thin(height);
                let to = (height..=stop)
                    .take(MAX_BLOCKS as usize)
                    .take_while(|h| fetch_thin(*h) == thin)
                    .last()
                    .unwrap_or(height);
                ahead = cache
                    .lock()
                    .unwrap()
                    .fetch_range(&rpc, oss, height, to, thin)?;
            }
            ahead
                .remove(&height)
                .expect("fetch_range returns every height")
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
    let last = previous.expect("sync has a checkpoint");
    if last.height == tip {
        control.stage("Validating transparent funding snapshot…")?;
        store.put_funding_snapshot(&funding.into_snapshot(&rpc, &funding_address, store)?)?;
    }
    ensure!(
        rpc.hash(last.height)? == last.hash,
        "chain reorganized during sync; retry"
    );
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
