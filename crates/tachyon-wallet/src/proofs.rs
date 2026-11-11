//! Spendability over closed epochs (design §4.3), written once against a
//! [`Prover`] that supplies buckets, unspent segments and anchor spans.

use std::ops::Range;

use anyhow::{Context, Result, ensure};
use oss_core::{
    MAX_UNSPENT_NULLIFIERS, Pcd, SpanBuilder, Spans, build_epoch, pcd_from_bytes, pcd_to_bytes,
    profile_of, prove_unspent, trivial, verify_pcd,
};
use udon::field::Field;
use zcash_tachyon::{
    Anchor, EpochIndex, Note, QrDiscriminant, Tachygram,
    keys::private::SpendingKey,
    nullifier::{NF_DERIVATION_WIDTH, Nullifier},
    pasta::Fp,
    stamp::proof::{PROOF_SYSTEM, delegation, pool, qr, spendable},
    witness,
};

use crate::{
    chain::{self, anchor, anchor_hex},
    control::Control,
    store::ChainData,
};

/// Where buckets, unspent segments and spans come from (design §4.6).
pub enum Prover<'a> {
    /// Self-prove from the wallet's synced chain, with fixed `R0 = 1`.
    Local(&'a ChainData<'a>),
}

impl Prover<'_> {
    /// One segment proving `nfs[i]` absent from epoch `epoch_start + i`.
    /// Fails if any of them is published: the note is spent.
    pub fn unspent(
        &self,
        epoch_start: u32,
        nfs: &[Nullifier],
        control: &Control,
    ) -> Result<Pcd<pool::ArbitraryUnspent>> {
        let Self::Local(chain) = self;
        for (epoch, nf) in (epoch_start..).zip(nfs) {
            ensure!(
                !chain.published(Tachygram::from(*nf))?,
                "note is spent: its epoch {epoch} nullifier is published"
            );
        }
        control.stage(format!(
            "Proving unspent evidence for {} epochs from {epoch_start}…",
            nfs.len()
        ))?;
        prove_unspent(epoch_start, nfs, |epoch, value| {
            self.bucket_for(epoch, value, control)
        })
    }

    /// The sealed bucket of closed `epoch` whose profile holds `value`.
    pub fn bucket_for(
        &self,
        epoch: u32,
        value: Fp,
        control: &Control,
    ) -> Result<Pcd<qr::QrBucket>> {
        let Self::Local(chain) = self;
        let r0 = QrDiscriminant(Fp::ONE);
        // A row counts only if it verifies and sits on this chain's entry anchors.
        if let Some(profile) = profile_of(value, r0, &chain.bucket_profiles(epoch)?)
            && let Some(bytes) = chain.bucket_proof(epoch, profile)?
            && let Ok(bucket) = pcd_from_bytes::<qr::QrBucket>(&bytes)
            && {
                let (e, start, next, disc, p, _) = *bucket.data();
                (e, start, next, disc, p)
                    == (
                        EpochIndex::new(epoch),
                        chain.epoch_sentinel(epoch)?,
                        chain.epoch_sentinel(epoch + 1)?,
                        r0,
                        profile,
                    )
            }
            && verify_pcd(&bucket).unwrap_or(false)
        {
            control.record_cache("bucket", true, u64::try_from(bytes.len())?);
            return Ok(bucket);
        }
        control.record_cache("bucket", false, 0);
        control.stage(format!("Proving closed epoch {epoch} buckets…"))?;
        let blocks = chain.epoch_blocks(epoch)?;
        let first = blocks.first().context("missing epoch inputs")?;
        // Seal only a complete, valid epoch, including its closing sentinel.
        chain::validate_checkpoint(first, first.activation_height)?;
        for pair in blocks.windows(2) {
            chain::validate(&pair[1], Some(&pair[0]), first.activation_height)?;
        }
        let predecessor = if epoch == 0 {
            Anchor(Fp::ZERO)
        } else {
            anchor(&first.anchor_before)?
        };
        let buckets = build_epoch(&blocks, predecessor, r0)?;
        chain.put_buckets(
            epoch,
            &buckets
                .iter()
                .map(|(profile, bucket, _)| Ok((*profile, pcd_to_bytes(bucket)?)))
                .collect::<Result<Vec<_>>>()?,
        )?;
        let leaves: Vec<_> = buckets.iter().map(|b| b.0).collect();
        let profile = profile_of(value, r0, &leaves).context("no bucket on the routing path")?;
        Ok(buckets
            .into_iter()
            .find(|b| b.0 == profile)
            .expect("profile_of picks one of the leaves")
            .1)
    }

    /// Spans lifting every anchor of `from` to one target, the synced tip.
    pub fn spans(&self, from: &[Anchor], control: &Control) -> Result<Spans> {
        let Self::Local(chain) = self;
        let tip = chain.tip()?;
        let epoch = tip.epoch;
        let blocks: Vec<_> = chain
            .epoch_blocks(epoch)?
            .into_iter()
            .filter(|b| b.epoch == epoch)
            .collect();
        // Start at the earliest spend anchor in chain order, not the epoch entry.
        let mut cursor = blocks.first().context("missing epoch start")?.entry()?;
        let mut stamps = blocks.iter().flat_map(|b| &b.stamps);
        while !from.contains(&cursor) {
            let stamp = stamps.next().with_context(|| {
                format!(
                    "cannot reach the requested anchors from epoch {epoch}: {:?}",
                    from.iter().map(|a| anchor_hex(*a)).collect::<Vec<_>>()
                )
            })?;
            cursor = cursor.next_stamp(EpochIndex::new(epoch), &stamp.commitment()?)?;
        }
        let mut builder = SpanBuilder::new(epoch, cursor, chain::max_polynomial_members());
        control.stage("Proving anchor spans…")?;
        for block in &blocks {
            control.check()?;
            builder.push_block(block)?;
        }
        // `push_block` skips stamps it cannot extend, so check where it ended.
        ensure!(
            builder.target() == anchor(&tip.anchor_after)?,
            "anchor spans stop at {}, not the synced tip {}",
            anchor_hex(builder.target()),
            tip.anchor_after
        );
        builder
            .spans_from(from)
            .context("a spend anchor is not in the current epoch")
    }
}

pub fn secret(
    key: &SpendingKey,
    note: Note,
    control: &Control,
) -> Result<Pcd<delegation::NoteSecret>> {
    control.stage("Proving note secret…")?;
    Ok(PROOF_SYSTEM
        .seed(
            &mut rand::rng(),
            delegation::NoteSeed,
            witness::note_seed(((), ()), note, key.derive_proof_private()),
        )?
        .0)
}

fn nullifiers(key: &SpendingKey, note: Note, epochs: Range<u32>) -> Vec<Nullifier> {
    let mk = key.derive_nullifier_private().derive_note_private(note.psi);
    epochs
        .map(|e| mk.derive_nullifier(EpochIndex::new(e)))
        .collect()
}

/// `NullifierDerive` per 16-epoch window that `epochs` touches, joined by
/// `NullifierFuse`.
fn derivation(
    secret: &Pcd<delegation::NoteSecret>,
    key: &SpendingKey,
    note: Note,
    epochs: Range<u32>,
    control: &Control,
) -> Result<Pcd<delegation::NoteNullifiers>> {
    let width = u32::try_from(NF_DERIVATION_WIDTH)?;
    let first = epochs.start - epochs.start % width;
    let mut derived: Option<Pcd<delegation::NoteNullifiers>> = None;
    for start in (first..epochs.end).step_by(NF_DERIVATION_WIDTH) {
        control.stage(format!("Proving nullifier derivation for epoch {start}…"))?;
        let (window, ()) = PROOF_SYSTEM.fuse(
            &mut rand::rng(),
            delegation::NullifierDerive,
            witness::nullifier_derive((*secret.data(), ()), EpochIndex::new(start)),
            secret.clone(),
            trivial(),
        )?;
        derived = Some(match derived {
            None => window,
            Some(left) => {
                PROOF_SYSTEM
                    .fuse(
                        &mut rand::rng(),
                        delegation::NullifierFuse,
                        witness::nullifier_fuse(
                            (*left.data(), *window.data()),
                            &nullifiers(key, note, first..start),
                            &nullifiers(key, note, start..start + width),
                        ),
                        left,
                        window,
                    )?
                    .0
            }
        });
    }
    derived.context("empty epoch range")
}

/// `UnspentBind`: ties the segment's tested values to this note's derivation.
fn bind(
    secret: &Pcd<delegation::NoteSecret>,
    key: &SpendingKey,
    note: Note,
    segment: Pcd<pool::ArbitraryUnspent>,
    control: &Control,
) -> Result<Pcd<pool::NoteUnspent>> {
    let (_, start, next, _) = *segment.data();
    let epochs = u32::from(start)..u32::from(next);
    let derived = derivation(secret, key, note, epochs.clone(), control)?;
    let (_, first, last) = *derived.data();
    control.stage("Binding unspent evidence…")?;
    Ok(PROOF_SYSTEM
        .fuse(
            &mut rand::rng(),
            pool::UnspentBind,
            witness::unspent_bind(
                (*segment.data(), *derived.data()),
                &nullifiers(key, note, u32::from(first)..u32::from(last) + 1),
                &nullifiers(key, note, epochs),
            ),
            segment,
            derived,
        )?
        .0)
}

pub fn spendable(
    chain: &ChainData<'_>,
    prover: &Prover<'_>,
    key: &SpendingKey,
    note: Note,
    control: &Control,
) -> Result<Pcd<spendable::NoteSpendable>> {
    let cm = Tachygram::from(note.commitment());
    let note_id = hex::encode(Fp::from(cm).to_bytes());
    let current = chain.tip()?.epoch;
    let (created, before, members) = chain
        .creation(cm)?
        .context("note commitment has not been mined")?;
    ensure!(created <= current, "note creation epoch is above the tip");

    // A closed-epoch lineage must sit exactly on its epoch's sentinel: lifts
    // start there, and StampLift must never cross one. A same-epoch
    // SpendableInit may sit on an ordinary creation anchor.
    let mut cached = None;
    if let Some(bytes) = chain.spendable_proof_bytes(&note_id)?
        && let Ok(proof) = Pcd::<spendable::NoteSpendable>::from_bytes(&bytes)
        && Tachygram::from(proof.data().0) == cm
        && u32::from(proof.data().1) <= current
        && verify_pcd(&proof)?
    {
        let at = u32::from(proof.data().1);
        let on_sentinel = proof.data().2 == chain.epoch_sentinel(at)?;
        if at == current && (created == current || on_sentinel) {
            control.stage("Reusing cached spendability proof…")?;
            return Ok(proof);
        }
        if at < current && on_sentinel {
            cached = Some(proof);
        }
    }

    let secret = secret(key, note, control)?;
    let landed = |lineage: &Pcd<spendable::NoteSpendable>, epoch: u32| -> Result<()> {
        ensure!(
            u32::from(lineage.data().1) == epoch
                && lineage.data().2 == chain.epoch_sentinel(epoch)?,
            "closed-epoch spendability did not land on the epoch {epoch} sentinel"
        );
        cache_spendable(chain, &note_id, lineage)
    };
    let mut lineage = match cached {
        Some(lineage) => lineage,
        None if created == current => {
            let derived = derivation(&secret, key, note, current..current + 1, control)?;
            control.stage("Proving spendability in the current epoch…")?;
            let lineage = PROOF_SYSTEM
                .fuse(
                    &mut rand::rng(),
                    spendable::SpendableInit,
                    witness::spendable_init(
                        (*derived.data(), ()),
                        before,
                        &members,
                        EpochIndex::new(current),
                    ),
                    derived,
                    trivial(),
                )?
                .0;
            cache_spendable(chain, &note_id, &lineage)?;
            return Ok(lineage);
        }
        None => {
            let c = created;
            let segment = prover.unspent(c, &nullifiers(key, note, c..c + 1), control)?;
            let unspent = bind(&secret, key, note, segment, control)?;
            // The commitment need not route to its nullifier's bucket.
            let creation = prover.bucket_for(c, cm.into(), control)?;
            control.stage("Proving initial closed-epoch spendability…")?;
            let (lineage, ()) = PROOF_SYSTEM.fuse(
                &mut rand::rng(),
                spendable::QrSpendableInit,
                (),
                unspent,
                creation,
            )?;
            landed(&lineage, c + 1)?;
            lineage
        }
    };
    let page = u32::try_from(MAX_UNSPENT_NULLIFIERS)?;
    while u32::from(lineage.data().1) < current {
        let k = u32::from(lineage.data().1);
        let next = current.min(k.saturating_add(page));
        let segment = prover.unspent(k, &nullifiers(key, note, k..next), control)?;
        let unspent = bind(&secret, key, note, segment, control)?;
        control.stage("Lifting spendability across epochs…")?;
        lineage = PROOF_SYSTEM
            .fuse(
                &mut rand::rng(),
                spendable::SpendableLift,
                (),
                lineage,
                unspent,
            )?
            .0;
        landed(&lineage, next)?;
    }
    Ok(lineage)
}

fn cache_spendable(
    chain: &ChainData<'_>,
    note_id: &str,
    proof: &Pcd<spendable::NoteSpendable>,
) -> Result<()> {
    let bytes = proof
        .to_bytes()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    chain.put_spendable_proof_bytes(note_id, &bytes)
}
