use anyhow::Result;
use primitives::transaction::Transaction;
use protocol::{consensus::BranchId, value::Zatoshis};
use sha2::{Digest, Sha256};
use transparent::bundle::{OutPoint, TxOut};
use udon::field::Field;
use zcash_tachyon::pasta::Fp;
use zcash_tachyon::{
    Anchor, EpochIndex, QrClassRoot, Tachygram, TachygramSetPoly, TachyonBundle,
    constants::EPOCH_SIZE, keys::private::SpendingKey,
};

use oss::testing::{FakeNode, OssHandle, TempDb, spawn_oss_with};
use oss_core::TachyonStamp as Stamp;

use crate::{
    chain::{self, Block},
    control::Control,
    note::{self, Receipt},
    proofs::Prover,
    rpc::Oss,
    store::ChainData,
    transaction::{self, FEE, Funding, Payment},
};

pub(crate) const SEED: [u8; 32] = [7; 32];
pub(crate) const NETWORK: &str = "test-network";

fn build(payment: Payment<'_>) -> Result<Transaction> {
    let ChainData::Blocks(blocks) = payment.blocks else {
        unreachable!("test payments carry their blocks")
    };
    transaction::build(payment, &Prover::Local(&blocks.into()), &Control::new(true))
}

/// An OSS following a fake node, for the remote twins of closed-epoch tests.
struct Remote {
    // Fields drop in order: stop the OSS before its node.
    oss: OssHandle,
    node: FakeNode,
    client: Oss,
    _db: TempDb,
}

impl Remote {
    fn start(blocks: &[Block]) -> Result<Self> {
        Self::start_with(blocks, &[])
    }

    /// [`Remote::start`] with extra `tachyon-oss` flags.
    fn start_with(blocks: &[Block], flags: &[&str]) -> Result<Self> {
        let db = TempDb::new();
        let node = FakeNode::start(blocks.to_vec())?;
        let (url, oss) = spawn_oss_with(&node.url, &db.0, flags)?;
        Ok(Self {
            oss,
            node,
            client: Oss::new(&url, None, &Control::new(true))?,
            _db: db,
        })
    }

    /// Serves `blocks` from their first height up, and waits until the OSS
    /// has built their tip and sealed every closed epoch.
    fn follow(&self, blocks: &[Block]) -> Result<()> {
        {
            let mut data = self.node.data();
            data.blocks.retain(|b| b.height < blocks[0].height);
            data.blocks.extend_from_slice(blocks);
        }
        let tip = blocks.last().unwrap();
        if let Some(closed) = tip.epoch.checked_sub(1) {
            self.oss.wait_ready(closed)?;
        }
        self.oss.wait_built(tip.height)
    }
}

/// A prover for `chain`: local, or `oss` once it has followed `blocks`.
fn prover_for<'a>(
    chain: &'a ChainData<'a>,
    oss: Option<&'a Remote>,
    blocks: &[Block],
) -> Result<Prover<'a>> {
    let Some(oss) = oss else {
        return Ok(Prover::Local(chain));
    };
    oss.follow(blocks)?;
    Ok(Prover::Remote(&oss.client, chain))
}

/// Spends `receipt` at the tip of `blocks`, proving closed epochs locally or
/// through `oss`.
fn spend(blocks: &[Block], receipt: &Receipt, oss: Option<&Remote>) -> Result<()> {
    let chain = ChainData::Blocks(blocks);
    spend_with(blocks, receipt, &prover_for(&chain, oss, blocks)?)
}

fn spend_with(blocks: &[Block], receipt: &Receipt, prover: &Prover<'_>) -> Result<()> {
    let sent = transaction::build(
        Payment {
            seed: SEED,
            blocks: blocks.into(),
            spends: vec![receipt],
            funding: None,
            outputs: &[own(950_000)],
            transparent_output: None,
            expiry: blocks.last().unwrap().height + 20,
        },
        prover,
        &Control::new(true),
    )?;
    transaction::verify_for_test(&sent, None)
}

#[test]
fn same_epoch_spend_proves_its_spans_without_the_oss() -> Result<()> {
    let mut blocks = vec![genesis()];
    let receipt = own(1_000_000);
    let tx = shield(&blocks, &receipt)?;
    mine(&mut blocks, Some(&tx))?;
    populate_epoch(&mut blocks, 3)?; // A later stamp, so the spend needs a span.
    // Nothing listens here, so any OSS request fails the spend.
    let port = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    let dead = Oss::new(
        &format!("http://127.0.0.1:{port}"),
        None,
        &Control::new(true),
    )?;
    spend_with(
        &blocks,
        &receipt,
        &Prover::Remote(&dead, &ChainData::Blocks(&blocks)),
    )
}

#[test]
fn a_proxy_html_error_reports_its_http_status() -> Result<()> {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let url = format!("http://{}", listener.local_addr()?);
    let proxy = std::thread::spawn(move || -> std::io::Result<()> {
        let (mut stream, _) = listener.accept()?;
        let mut request = Vec::new();
        let mut chunk = [0; 4096];
        while !request.ends_with(b"}") {
            let n = stream.read(&mut chunk)?;
            assert!(n > 0, "the client closed before sending its body");
            request.extend_from_slice(&chunk[..n]);
        }
        let body = "<html>401 Authorization Required</html>";
        write!(
            stream,
            "HTTP/1.1 401 Unauthorized\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    });
    let error = Oss::new(&url, None, &Control::new(true))?
        .call::<serde_json::Value>("oss_info", serde_json::json!({}))
        .unwrap_err();
    proxy.join().unwrap()?;
    assert!(
        format!("{error:#}").contains("oss_info: invalid RPC JSON (HTTP 401 Unauthorized)"),
        "{error:#}"
    );
    Ok(())
}

#[test]
fn remote_proves_epochs_below_the_oss_archive_locally() -> Result<()> {
    let mut blocks = vec![genesis()];
    let receipt = own(1_000_000);
    let tx = shield(&blocks, &receipt)?;
    mine(&mut blocks, Some(&tx))?;
    while blocks.last().unwrap().epoch < 2 {
        mine(&mut blocks, None)?;
    }
    // The OSS archives from epoch 1: the note's epoch 0 is `Unavailable` there
    // and proven locally, then epoch 1 and the spans come from the OSS.
    let start = blocks.iter().find(|b| b.epoch == 1).unwrap().height;
    let oss = Remote::start_with(&blocks, &["--start-height", &start.to_string()])?;
    spend(&blocks, &receipt, Some(&oss))
}

#[test]
fn oss_not_ready_is_retried_then_reported() -> Result<()> {
    let mut oss = Remote::start(&[genesis()])?;
    oss.client.patience = std::time::Duration::from_millis(2500);
    let started = std::time::Instant::now();
    // Epoch 0 is open, so the OSS answers NotReady with retryAfterMs = 1000.
    let error = oss
        .client
        .call::<oss_core::UnspentResult>(
            "oss_unspent",
            oss_core::UnspentParams {
                epoch_start: 0,
                nullifiers: vec![hex::encode(Fp::ONE.to_bytes())],
            },
        )
        .unwrap_err();
    assert!(error.to_string().contains("OSS not ready"), "{error}");
    assert!(started.elapsed() >= std::time::Duration::from_secs(1));
    Ok(())
}

#[test]
fn malformed_oss_spans_are_errors() {
    let from = Anchor::default();
    let answer = |target: Anchor, start: Vec<Option<u32>>| oss_core::AnchorSpansResult {
        epoch: 0,
        target: chain::anchor_hex(target),
        chunks: vec![],
        start,
    };
    let checked = |target, start| crate::proofs::checked_spans(&[from], answer(target, start));
    assert!(checked(from, vec![None]).is_ok());
    assert!(checked(from, vec![]).is_err()); // One start per anchor.
    assert!(checked(from, vec![Some(0)]).is_err()); // No such chunk.
    assert!(checked(Anchor(Fp::ONE), vec![None]).is_err()); // Not at the target.
}

/// Each `fn(remote: bool)` body as a local test and its remote twin.
macro_rules! twins {
    ($($local:ident, $remote:ident => $body:ident;)*) => {$(
        #[test]
        fn $local() -> Result<()> {
            $body(false)
        }
        #[test]
        fn $remote() -> Result<()> {
            $body(true)
        }
    )*};
}

twins! {
    old_note_spends_after_populated_and_empty_closed_epochs,
    old_note_spends_after_populated_and_empty_closed_epochs_remote => old_note_spends;
    checkpoint_history_supports_spends_before_and_after_creation_epoch_closes,
    checkpoint_history_supports_spends_before_and_after_creation_epoch_closes_remote
        => checkpoint_history_spends;
    spends_after_epoch_with_more_tachygrams_than_polynomial_capacity,
    spends_after_epoch_with_more_tachygrams_than_polynomial_capacity_remote
        => spends_after_large_epoch;
    cached_spendability_advances_only_across_new_epochs,
    cached_spendability_advances_only_across_new_epochs_remote => cached_spendability;
    spent_note_cannot_produce_closed_epoch_absence_evidence,
    spent_note_cannot_produce_closed_epoch_absence_evidence_remote => spent_note_has_no_evidence;
    spent_note_cannot_hide_in_another_routed_bucket,
    spent_note_cannot_hide_in_another_routed_bucket_remote => spent_note_cannot_hide;
}

pub(crate) fn genesis() -> Block {
    let anchor = chain::anchor_hex(Anchor::default());
    Block {
        hash: hex::encode([1; 32]),
        previous_block_hash: hex::encode([0; 32]),
        height: 8,
        activation_height: 8,
        pool_height: 0,
        epoch: 0,
        epoch_length: EPOCH_SIZE,
        anchor_before: anchor.clone(),
        epoch_start_anchor: Some(anchor.clone()),
        anchor_after: anchor,
        stamps: vec![],
        transactions: vec![],
    }
}

pub(crate) fn mine(blocks: &mut Vec<Block>, tx: Option<&Transaction>) -> Result<()> {
    let parent = blocks.last().unwrap();
    let height = parent.height + 1;
    let pool_height = height - 8;
    let epoch = pool_height / EPOCH_SIZE;
    let before = chain::anchor(&parent.anchor_after)?;
    let entry = if epoch != parent.epoch {
        before.next_epoch(EpochIndex::new(epoch))?
    } else {
        before
    };
    let mut after = entry;
    let mut stamps = Vec::new();
    if let Some(tx) = tx.filter(|tx| !matches!(tx.tachyon_bundle(), TachyonBundle::NoBundle)) {
        let TachyonBundle::Proven(bundle) = tx.tachyon_bundle() else {
            panic!("expected proven bundle")
        };
        after = entry.next_stamp(EpochIndex::new(epoch), &bundle.stamp.tachygram_set)?;
        let mut commitment = Vec::new();
        bundle.stamp.tachygram_set.write(&mut commitment)?;
        stamps.push(Stamp {
            transaction_index: 0,
            txid: tx.txid().to_string(),
            tachygram_set: hex::encode(commitment),
            tachygrams: bundle
                .stamp
                .tachygrams
                .iter()
                .map(|t| hex::encode(Fp::from(*t).to_bytes()))
                .collect(),
        });
    }
    let block = Block {
        hash: hex::encode(Sha256::digest(height.to_le_bytes())),
        previous_block_hash: parent.hash.clone(),
        height,
        activation_height: 8,
        pool_height,
        epoch,
        epoch_length: EPOCH_SIZE,
        anchor_before: parent.anchor_after.clone(),
        epoch_start_anchor: (epoch != parent.epoch).then(|| chain::anchor_hex(entry)),
        anchor_after: chain::anchor_hex(after),
        stamps,
        transactions: tx.map(|t| vec![t.txid().to_string()]).unwrap_or_default(),
    };
    chain::validate(&block, Some(parent), 8)?;
    blocks.push(block);
    Ok(())
}

pub(crate) fn own(value: u64) -> Receipt {
    Receipt::new(NETWORK, &note::address(&SpendingKey::from(SEED)), value).unwrap()
}

pub(crate) fn shield(blocks: &[Block], receipt: &Receipt) -> Result<Transaction> {
    build(Payment {
        seed: SEED,
        blocks: blocks.into(),
        spends: vec![],
        funding: Some(Funding {
            outpoint: OutPoint::new([2; 32], 0),
            output: TxOut::new(
                Zatoshis::from_u64(receipt.value_zat + FEE)?,
                transaction::transparent_script(&transaction::funding_address(SEED)?)?,
            ),
        }),
        outputs: std::slice::from_ref(receipt),
        transparent_output: None,
        expiry: blocks.last().unwrap().height + 20,
    })
}

#[test]
fn transparent_payment_absorbs_dust_change_into_fee() -> Result<()> {
    let output = TxOut::new(
        Zatoshis::from_u64(150_005)?,
        transaction::transparent_script(&transaction::funding_address(SEED)?)?,
    );
    let recipient = bs58::encode([&[0x1c, 0xba][..], &[9; 20]].concat())
        .with_check()
        .into_string();
    let tx = transaction::build_transparent(
        SEED,
        Funding {
            outpoint: OutPoint::new([2; 32], 0),
            output: output.clone(),
        },
        &recipient,
        100_000,
        28,
    )?;
    assert_eq!(tx.transparent_bundle().unwrap().vout.len(), 1);
    transaction::verify_for_test(&tx, Some(output))?;
    Ok(())
}

#[test]
fn transparent_payment_signatures_cover_recipient_and_change_and_reject_foreign_funding()
-> Result<()> {
    let output = TxOut::new(
        Zatoshis::from_u64(250_000)?,
        transaction::transparent_script(&transaction::funding_address(SEED)?)?,
    );
    let recipient = bs58::encode([&[0x1c, 0xba][..], &[9; 20]].concat())
        .with_check()
        .into_string();
    let tx = transaction::build_transparent(
        SEED,
        Funding {
            outpoint: OutPoint::new([2; 32], 0),
            output: output.clone(),
        },
        &recipient,
        100_000,
        28,
    )?;
    assert!(matches!(tx.tachyon_bundle(), TachyonBundle::NoBundle));
    let bundle = tx.transparent_bundle().unwrap();
    assert_eq!(bundle.vout.len(), 2);
    assert_eq!(
        bundle.vout[0].script_pubkey(),
        &transaction::transparent_script(&recipient)?
    );
    assert_eq!(bundle.vout[1].value().into_u64(), 100_000);
    let mut bytes = Vec::new();
    tx.write(&mut bytes)?;
    let decoded = Transaction::read(&bytes[..], BranchId::NuTachyon)?;
    assert_eq!(decoded.txid(), tx.txid());
    transaction::verify_for_test(&decoded, Some(output.clone()))?;
    for index in [0, 1] {
        let mut changed = bundle.clone();
        changed.vout[index] = TxOut::new(
            Zatoshis::from_u64(99_999)?,
            changed.vout[index].script_pubkey().clone(),
        );
        let tampered = primitives::transaction::TransactionData::<
            primitives::transaction::Authorized,
        >::from_parts_v7(
            BranchId::NuTachyon,
            0,
            tx.expiry_height(),
            Zatoshis::ZERO,
            Some(changed),
            None,
            None,
            None,
            TachyonBundle::NoBundle,
        )
        .freeze()?;
        assert!(transaction::verify_for_test(&tampered, Some(output.clone())).is_err());
    }
    assert!(
        transaction::build_transparent(
            [8; 32],
            Funding {
                outpoint: OutPoint::new([2; 32], 0),
                output
            },
            &recipient,
            100_000,
            28
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn receipts_are_canonical_and_bound_to_owner_and_network() -> Result<()> {
    let receipt = own(100_000);
    receipt.check_owner(&SpendingKey::from(SEED), NETWORK)?;
    assert!(
        receipt
            .check_owner(&SpendingKey::from([8; 32]), NETWORK)
            .is_err()
    );
    assert!(
        receipt
            .check_owner(&SpendingKey::from(SEED), "other-chain")
            .is_err()
    );
    let mut broken = receipt.clone();
    broken.rcm = hex::encode([0; 32]);
    assert!(broken.note().is_err());
    broken.rcm = hex::encode([255; 32]);
    assert!(broken.note().is_err());
    assert!(Receipt::new(NETWORK, "tachyon-test:deadbeef", 1).is_err());
    assert!(Receipt::new(NETWORK, &note::address(&SpendingKey::from(SEED)), 0).is_err());
    Ok(())
}

#[test]
fn chain_rejects_corrupt_inputs_and_discontinuities() -> Result<()> {
    let mut blocks = vec![genesis()];
    chain::validate(&blocks[0], None, 8)?;
    let tx = shield(&blocks, &own(1_000_000))?;
    mine(&mut blocks, Some(&tx))?;
    let mut bad = blocks[1].clone();
    bad.stamps[0].tachygrams.pop();
    assert!(chain::validate(&bad, Some(&blocks[0]), 8).is_err());
    let mut bad = blocks[1].clone();
    bad.previous_block_hash = hex::encode([9; 32]);
    assert!(chain::validate(&bad, Some(&blocks[0]), 8).is_err());
    let mut bad = blocks[1].clone();
    bad.epoch_start_anchor = Some(bad.anchor_before.clone());
    assert!(chain::validate(&bad, Some(&blocks[0]), 8).is_err());
    let mut bad = blocks[1].clone();
    bad.epoch_length /= 2;
    assert!(chain::validate(&bad, Some(&blocks[0]), 8).is_err());
    let mut bad = blocks[1].clone();
    // Reject before constructing a polynomial, including under mock Ragu.
    bad.stamps[0].tachygrams = vec![hex::encode([0; 32]); chain::max_polynomial_members() + 1];
    assert!(
        chain::validate(&bad, Some(&blocks[0]), 8)
            .unwrap_err()
            .to_string()
            .contains("polynomial capacity")
    );
    Ok(())
}

#[test]
fn shield_transfer_change_and_unshield_roundtrip_with_valid_authorization() -> Result<()> {
    let mut blocks = vec![genesis()];
    let funded = own(1_000_000);
    let tx = shield(&blocks, &funded)?;
    transaction::verify_for_test(
        &tx,
        Some(TxOut::new(
            Zatoshis::from_u64(1_000_000 + FEE)?,
            transaction::transparent_script(&transaction::funding_address(SEED)?)?,
        )),
    )?;
    mine(&mut blocks, Some(&tx))?;
    // A later unrelated stamp forces the spending stamp to lift within the active epoch.
    let unrelated = shield(&blocks, &own(200_000))?;
    mine(&mut blocks, Some(&unrelated))?;
    let recipient = Receipt::new(
        NETWORK,
        &note::address(&SpendingKey::from([8; 32])),
        300_000,
    )?;
    let change = own(650_000);
    let sent = build(Payment {
        seed: SEED,
        blocks: (&blocks).into(),
        spends: vec![&funded],
        funding: None,
        outputs: &[recipient, change.clone()],
        transparent_output: None,
        expiry: 30,
    })?;
    transaction::verify_for_test(&sent, None)?;
    let TachyonBundle::Proven(bundle) = sent.tachyon_bundle() else {
        panic!()
    };
    assert_eq!(bundle.descriptors().len(), 3); // Spend + recipient + change, not output-only.
    assert_eq!(
        bundle.stamp.anchor,
        chain::anchor(&blocks.last().unwrap().anchor_after)?
    );
    mine(&mut blocks, Some(&sent))?;
    let unshield = build(Payment {
        seed: SEED,
        blocks: (&blocks).into(),
        spends: vec![&change],
        funding: None,
        outputs: &[],
        transparent_output: Some((transaction::funding_address(SEED)?, 600_000)),
        expiry: 30,
    })?;
    transaction::verify_for_test(&unshield, None)?;
    assert_eq!(
        unshield.transparent_bundle().unwrap().vout[0]
            .value()
            .into_u64(),
        600_000
    );
    let mut bytes = Vec::new();
    unshield.write(&mut bytes)?;
    let decoded = Transaction::read(&bytes[..], BranchId::NuTachyon)?;
    assert_eq!(decoded.txid(), unshield.txid());
    transaction::verify_for_test(&decoded, None)?;
    Ok(())
}

fn old_note_spends(remote: bool) -> Result<()> {
    let mut blocks = vec![genesis()];
    let receipt = own(1_000_000);
    let tx = shield(&blocks, &receipt)?;
    mine(&mut blocks, Some(&tx))?;
    // Epoch zero contains the minted note; epoch one has no stamps at all.
    while blocks.last().unwrap().epoch < 2 {
        mine(&mut blocks, None)?;
    }
    let oss = remote.then(|| Remote::start(&blocks)).transpose()?;
    spend(&blocks, &receipt, oss.as_ref())
}

fn checkpoint_history_spends(remote: bool) -> Result<()> {
    let mut blocks = vec![genesis()];
    while blocks.last().unwrap().epoch < 1 {
        mine(&mut blocks, None)?;
    }
    // The OSS archives from activation; the wallet does not need to.
    let oss = remote.then(|| Remote::start(&blocks)).transpose()?;
    let checkpoint = blocks.last().unwrap().clone();
    chain::validate_checkpoint(&checkpoint, 8)?;
    assert!(chain::validate(&checkpoint, None, 8).is_err());
    blocks = vec![checkpoint]; // No public data from epoch zero is needed.
    let receipt = own(1_000_000);
    let tx = shield(&blocks, &receipt)?;
    mine(&mut blocks, Some(&tx))?;
    for target_epoch in [1, 2] {
        while blocks.last().unwrap().epoch < target_epoch {
            mine(&mut blocks, None)?;
        }
        spend(&blocks, &receipt, oss.as_ref())?;
    }
    Ok(())
}

/// Add distinct public stamp inputs without generating thousands of payments.
/// Each stamp fits individually; their union deliberately exceeds one polynomial.
pub(crate) fn populate_epoch(blocks: &mut Vec<Block>, count: usize) -> Result<()> {
    mine(blocks, None)?;
    let parent_index = blocks.len() - 2;
    let mut block = blocks.last().unwrap().clone();
    let epoch = EpochIndex::new(block.epoch);
    let mut anchor = block.entry()?;
    let existing: std::collections::BTreeSet<_> = blocks
        .iter()
        .filter(|b| b.epoch == block.epoch)
        .flat_map(|b| &b.stamps)
        .map(Stamp::members)
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect();
    let members: Vec<_> = (1u64..)
        .map(|i| Tachygram::from(Fp::from(i)))
        .filter(|member| !existing.contains(member))
        .take(count)
        .collect();
    for (index, members) in members.chunks(64).enumerate() {
        let commitment = members
            .iter()
            .copied()
            .collect::<TachygramSetPoly>()
            .commit();
        anchor = anchor.next_stamp(epoch, &commitment)?;
        let mut bytes = Vec::new();
        commitment.write(&mut bytes)?;
        block.stamps.push(Stamp {
            transaction_index: index,
            txid: hex::encode(Sha256::digest(index.to_le_bytes())),
            tachygram_set: hex::encode(bytes),
            tachygrams: members
                .iter()
                .map(|m| hex::encode(Fp::from(*m).to_bytes()))
                .collect(),
        });
    }
    block.anchor_after = chain::anchor_hex(anchor);
    chain::validate(&block, Some(&blocks[parent_index]), 8)?;
    *blocks.last_mut().unwrap() = block;
    Ok(())
}

fn spends_after_large_epoch(remote: bool) -> Result<()> {
    let mut blocks = vec![genesis()];
    let key = SpendingKey::from(SEED);
    let older = own(1_000_000);
    let funded = shield(&blocks, &older)?;
    mine(&mut blocks, Some(&funded))?;
    while blocks.last().unwrap().epoch < 1 {
        mine(&mut blocks, None)?;
    }
    // Force creation membership and nullifier absence into different QR buckets.
    let receipt = (0..64)
        .map(|_| own(1_000_000))
        .find(|r| {
            let note = r.note().unwrap();
            let nf = key
                .derive_nullifier_private()
                .derive_note_private(note.psi)
                .derive_nullifier(EpochIndex::new(1));
            QrClassRoot::of(note.commitment().into(), Fp::from(1)).0
                != QrClassRoot::of(nf.into(), Fp::from(1)).0
        })
        .expect("one of 64 random notes routes differently from its nullifier");
    let funded = shield(&blocks, &receipt)?;
    mine(&mut blocks, Some(&funded))?;
    populate_epoch(&mut blocks, chain::max_polynomial_members() + 19)?;
    while blocks.last().unwrap().epoch < 2 {
        mine(&mut blocks, None)?;
    }
    assert_eq!(blocks.last().unwrap().height, 8200);
    let oss = remote.then(|| Remote::start(&blocks)).transpose()?;
    // Exercise both routed creation and lifting an older note through a large epoch.
    for receipt in [&receipt, &older] {
        spend(&blocks, receipt, oss.as_ref())?;
    }
    Ok(())
}

#[test]
fn store_indexes_new_blocks_and_rewinds_without_rescanning() -> Result<()> {
    let directory = tempfile::tempdir()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    let store = crate::store::Store::open(directory.path(), true)?;
    let mut blocks = vec![genesis()];
    let receipt = own(1_000_000);
    let funded = shield(&blocks, &receipt)?;
    mine(&mut blocks, Some(&funded))?;
    for block in &blocks {
        store.put_block(block)?;
    }
    assert_eq!(store.tip()?.map(|block| block.height), Some(9));
    assert_eq!(store.tachygram_height(&receipt.id()?)?, Some(9));
    assert!(store.has_transaction(&funded.txid().to_string())?);
    assert_eq!(store.blocks_range(8, 8)?.len(), 1);
    store.put_note(&receipt)?;
    assert!(store.unresolved_notes()?.is_empty());
    let unconfirmed = own(2_000_000);
    store.put_note(&unconfirmed)?;
    assert_eq!(store.unresolved_notes()?.len(), 1);
    assert_eq!(store.unresolved_notes()?[0].id()?, unconfirmed.id()?);
    store.rewind(8)?;
    assert_eq!(store.tachygram_height(&receipt.id()?)?, None);
    assert!(!store.has_transaction(&funded.txid().to_string())?);
    Ok(())
}

#[test]
fn note_spend_tracking_updates_from_new_blocks_and_rewinds() -> Result<()> {
    let directory = tempfile::tempdir()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    let store = crate::store::Store::open(directory.path(), true)?;
    let config = crate::store::Config {
        version: 1,
        rpc_url: String::new(),
        cookie_file: None,
        activation: 8,
        activation_hash: String::new(),
        genesis: String::new(),
        network_id: NETWORK.into(),
        seed: SEED,
        birthday_height: Some(8),
    };
    let mut blocks = vec![genesis()];
    let receipt = own(1_000_000);
    let funded = shield(&blocks, &receipt)?;
    mine(&mut blocks, Some(&funded))?;
    for block in &blocks {
        store.put_block(block)?;
    }
    store.put_note(&receipt)?;
    let unconfirmed = own(2_000_000);
    store.put_note(&unconfirmed)?;
    let available = store.confirmed_unspent_note_rows()?;
    assert_eq!(available.len(), 1);
    assert_eq!(available[0].0, receipt.id()?);
    crate::wallet::refresh_note_nullifiers(&store, &config, 0, None)?;
    assert!(store.confirmed_notes_without_nullifier(0)?.is_empty());
    assert!(store.spent_note_ids()?.is_empty());

    let sent = build(Payment {
        seed: SEED,
        blocks: (&blocks).into(),
        spends: vec![&receipt],
        funding: None,
        outputs: &[own(950_000)],
        transparent_output: None,
        expiry: 30,
    })?;
    mine(&mut blocks, Some(&sent))?;
    let spend_height = blocks.last().unwrap().height;
    store.put_block(blocks.last().unwrap())?;
    assert!(store.spent_note_ids()?.contains(&receipt.id()?));
    assert!(store.confirmed_unspent_note_rows()?.is_empty());

    store.rewind(spend_height - 1)?;
    assert!(store.spent_note_ids()?.is_empty());
    store.put_block(blocks.last().unwrap())?;
    assert!(store.spent_note_ids()?.contains(&receipt.id()?));
    store.commit()?;
    let readonly = crate::store::Store::open_readonly(directory.path())?;
    assert!(readonly.put_note(&own(3_000_000)).is_err());
    Ok(())
}

fn cached_spendability(remote: bool) -> Result<()> {
    let directory = tempfile::tempdir()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    let store = crate::store::Store::open(directory.path(), true)?;
    store.set_config(&crate::store::Config {
        version: 1,
        rpc_url: String::new(),
        cookie_file: None,
        activation: 8,
        activation_hash: genesis().hash,
        genesis: String::new(),
        network_id: NETWORK.into(),
        seed: SEED,
        birthday_height: Some(8),
    })?;
    let mut blocks = vec![genesis()];
    let receipt = own(1_000_000);
    let funded = shield(&blocks, &receipt)?;
    mine(&mut blocks, Some(&funded))?;
    while blocks.last().unwrap().epoch < 2 {
        mine(&mut blocks, None)?;
    }
    for block in &blocks {
        store.put_block(block)?;
    }
    let oss = remote.then(|| Remote::start(&blocks)).transpose()?;
    let chain = ChainData::Store(&store);
    let prover = prover_for(&chain, oss.as_ref(), &blocks)?;
    let control = Control::new(true);
    let key = SpendingKey::from(SEED);
    let first = crate::proofs::spendable(&chain, &prover, &key, receipt.note()?, &control)?;
    let cached = store
        .spendable_proof(&receipt.id()?)?
        .expect("spendability proof is cached");
    assert!(!cached.is_empty());
    let second = crate::proofs::spendable(&chain, &prover, &key, receipt.note()?, &control)?;
    assert_eq!(second.data(), first.data());
    // A local payment cached every bucket of both closed epochs.
    assert_eq!(
        store.bucket_profiles(0)?.len() + store.bucket_profiles(1)?.len(),
        if remote { 0 } else { 2 }
    );
    store.put_spendable_proof(&receipt.id()?, &[0u8; 32])?;
    let recovered = crate::proofs::spendable(&chain, &prover, &key, receipt.note()?, &control)?;
    assert_eq!(recovered.data(), first.data());
    assert_ne!(store.spendable_proof(&receipt.id()?)?, Some(vec![0u8; 32]));
    while blocks.last().unwrap().epoch < 3 {
        mine(&mut blocks, None)?;
    }
    for block in &blocks {
        if store.block(block.height)?.is_none() {
            store.put_block(block)?;
        }
    }
    if let Some(oss) = &oss {
        oss.follow(&blocks)?;
    }
    let third = crate::proofs::spendable(&chain, &prover, &key, receipt.note()?, &control)?;
    assert!(third.data().1 > second.data().1);
    assert_eq!(
        third.data().2,
        chain.epoch_sentinel(third.data().1.into())?,
        "closed-epoch spendability must land on the active epoch sentinel"
    );
    Ok(())
}

fn spent_note_has_no_evidence(remote: bool) -> Result<()> {
    let mut blocks = vec![genesis()];
    let receipt = own(1_000_000);
    let funded = shield(&blocks, &receipt)?;
    mine(&mut blocks, Some(&funded))?;
    let sent = build(Payment {
        seed: SEED,
        blocks: (&blocks).into(),
        spends: vec![&receipt],
        funding: None,
        outputs: &[own(950_000)],
        transparent_output: None,
        expiry: 30,
    })?;
    mine(&mut blocks, Some(&sent))?;
    while blocks.last().unwrap().epoch < 1 {
        mine(&mut blocks, None)?;
    }
    let oss = remote.then(|| Remote::start(&blocks)).transpose()?;
    let chain = ChainData::Blocks(&blocks);
    let error = crate::proofs::spendable(
        &chain,
        &prover_for(&chain, oss.as_ref(), &blocks)?,
        &SpendingKey::from(SEED),
        receipt.note()?,
        &Control::new(true),
    )
    .err()
    .expect("a spent note has no absence evidence");
    assert!(error.to_string().contains("note is spent"), "{error}");
    Ok(())
}

fn spent_note_cannot_hide(remote: bool) -> Result<()> {
    let mut blocks = vec![genesis()];
    let receipt = own(1_000_000);
    let funded = shield(&blocks, &receipt)?;
    mine(&mut blocks, Some(&funded))?;
    let sent = build(Payment {
        seed: SEED,
        blocks: (&blocks).into(),
        spends: vec![&receipt],
        funding: None,
        outputs: &[own(950_000)],
        transparent_output: None,
        expiry: 30,
    })?;
    mine(&mut blocks, Some(&sent))?;
    populate_epoch(&mut blocks, chain::max_polynomial_members() + 19)?;
    while blocks.last().unwrap().epoch < 1 {
        mine(&mut blocks, None)?;
    }
    let oss = remote.then(|| Remote::start(&blocks)).transpose()?;
    let chain = ChainData::Blocks(&blocks);
    let prover = prover_for(&chain, oss.as_ref(), &blocks)?;
    let (key, note, control) = (SpendingKey::from(SEED), receipt.note()?, Control::new(true));
    // The wallet's own tachygram index marks the note spent, in remote mode
    // too, before any OSS request (that text is not the OSS's `Spent`).
    let error = crate::proofs::spendable(&chain, &prover, &key, note, &control)
        .err()
        .expect("a spent note is not spendable");
    assert!(
        error
            .to_string()
            .contains("note is spent: its epoch 0 nullifier is published"),
        "{error}"
    );
    let nf = key
        .derive_nullifier_private()
        .derive_note_private(note.psi)
        .derive_nullifier(EpochIndex::new(0));
    // Asked directly, the OSS's own index answers `Spent`.
    if let Some(oss) = &oss {
        let error = oss
            .client
            .call::<oss_core::UnspentResult>(
                "oss_unspent",
                oss_core::UnspentParams {
                    epoch_start: 0,
                    nullifiers: vec![hex::encode(Fp::from(nf).to_bytes())],
                },
            )
            .unwrap_err();
        assert!(
            error.to_string().contains("note is spent: the OSS has"),
            "{error}"
        );
    }
    // Below both index checks, the proof still refuses: the nullifier is
    // tested against its own routed bucket, which holds it.
    let error = oss_core::prove_unspent(0, &[nf], |epoch, value| {
        prover.bucket_for(epoch, value, &control)
    })
    .err()
    .expect("a spent note must fail absence verification");
    assert!(
        error.to_string().contains("found nullifier in the bucket"),
        "{error}"
    );
    Ok(())
}

#[test]
fn cached_local_bucket_is_rebuilt_after_its_closing_block_reorgs() -> Result<()> {
    let directory = tempfile::tempdir()?;
    #[cfg(unix)]
    std::fs::set_permissions(
        directory.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )?;
    let store = crate::store::Store::open(directory.path(), true)?;
    let mut blocks = vec![genesis()];
    let receipt = own(1_000_000);
    let funded = shield(&blocks, &receipt)?;
    mine(&mut blocks, Some(&funded))?;
    while blocks.last().unwrap().epoch < 1 {
        mine(&mut blocks, None)?;
    }
    for block in &blocks {
        store.put_block(block)?;
    }
    let chain = crate::store::ChainData::Store(&store);
    let prover = Prover::Local(&chain);
    let cm = Fp::from(Tachygram::from(receipt.note()?.commitment()));
    let control = Control::with_timing(true, true);
    let built = prover.bucket_for(0, cm, &control)?;
    assert_eq!(prover.bucket_for(0, cm, &control)?.data(), built.data());
    assert_eq!(control.cache_counts("bucket"), (1, 1));

    // Replace epoch 0's closing block with one that carries a stamp, which
    // moves epoch 1's entry anchor. The verified cached row no longer matches.
    let closing = blocks.len() - 2;
    blocks.truncate(closing);
    store.rewind(blocks.last().unwrap().height)?;
    let other = shield(&blocks, &own(2_000_000))?;
    mine(&mut blocks, Some(&other))?;
    mine(&mut blocks, None)?;
    for block in &blocks[closing..] {
        store.put_block(block)?;
    }
    let rebuilt = prover.bucket_for(0, cm, &control)?;
    assert_eq!(control.cache_counts("bucket"), (1, 2));
    assert_ne!(rebuilt.data().2, built.data().2);
    assert_eq!(rebuilt.data().2, chain.epoch_sentinel(1)?);
    // The rebuilt row replaced the stale one.
    assert_eq!(prover.bucket_for(0, cm, &control)?.data(), rebuilt.data());
    assert_eq!(control.cache_counts("bucket"), (2, 2));
    Ok(())
}
