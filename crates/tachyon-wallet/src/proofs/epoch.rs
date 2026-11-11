//! Complete closed-epoch evidence, routed before merging to bound polynomial size.

use std::collections::BTreeSet;

use crate::evidence::{Cache, Key, Payload};
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use zcash_tachyon::pasta::Fp;
use zcash_tachyon::{
    Anchor, EpochIndex, QrClassRoot, QrDiscriminant, QrProfile, Tachygram,
    stamp::proof::{PROOF_SYSTEM, qr},
    witness,
};
use zcash_tachyon::{TachygramSetCommit, TachygramSetPoly};

use super::{Pcd, trivial, verify_proof};
use crate::chain::{anchor, max_polynomial_members};
use crate::control::Control;
use crate::store::ChainData;
use udon::field::Field;

#[derive(Clone)]
struct Intake {
    proof: Pcd<qr::QrIntake>,
    members: Vec<Tachygram>,
}

/// Choose one common QR path for the query across all stamps, without first
/// constructing the (potentially oversized) whole-epoch polynomial.
fn routing_path(
    mut members: Vec<Tachygram>,
    query: Tachygram,
    discriminant: QrDiscriminant,
    control: &Control,
) -> Result<Vec<bool>> {
    let mut path = Vec::new();
    while members.len() > max_polynomial_members() {
        control.check()?;
        ensure!(
            path.len() < QrProfile::MAX_DEPTH,
            "epoch cannot be routed within Tachyon's polynomial capacity"
        );
        let shift = discriminant.at(u32::try_from(path.len())?);
        let side = QrClassRoot::of(query.into(), shift).0;
        members.retain(|member| QrClassRoot::of((*member).into(), shift).0 == side);
        path.push(side);
    }
    Ok(path)
}

impl Intake {
    fn route(
        mut self,
        path: &[bool],
        discriminant: QrDiscriminant,
        control: &Control,
    ) -> Result<Self> {
        for &side in path {
            control.check()?;
            let depth = self.proof.data().4.depth;
            let (sides, ()) = PROOF_SYSTEM.fuse(
                &mut rand::rng(),
                qr::QrIntakeSplit,
                witness::qr_intake_split((*self.proof.data(), ()), &self.members),
                self.proof,
                trivial(),
            )?;
            control.check()?;
            let (selection, ()) = PROOF_SYSTEM.fuse(
                &mut rand::rng(),
                qr::QrSideSelect,
                witness::qr_side_select((*sides.data(), ()), &self.members, side),
                sides.clone(),
                trivial(),
            )?;
            self.proof = PROOF_SYSTEM
                .fuse(
                    &mut rand::rng(),
                    qr::QrSideDescend,
                    witness::qr_side_descend((*sides.data(), *selection.data()), side),
                    sides,
                    selection,
                )?
                .0;
            let shift = discriminant.at(depth);
            self.members
                .retain(|member| QrClassRoot::of((*member).into(), shift).0 == side);
        }
        Ok(self)
    }

    fn merge(mut self, right: Self, control: &Control) -> Result<Self> {
        control.check()?;
        ensure!(
            self.members.len() + right.members.len() <= max_polynomial_members(),
            "routed epoch bucket exceeds Tachyon's polynomial capacity"
        );
        self.proof = PROOF_SYSTEM
            .fuse(
                &mut rand::rng(),
                qr::QrIntakeMerge,
                witness::qr_intake_merge(
                    (*self.proof.data(), *right.proof.data()),
                    &self.members,
                    &right.members,
                ),
                self.proof,
                right.proof,
            )?
            .0;
        self.members.extend(right.members);
        Ok(self)
    }
}

fn load_intake(
    chain: &ChainData<'_>,
    epoch: u32,
    kind: u8,
    first: u32,
    last: u32,
    profile: QrProfile,
    control: &Control,
) -> Result<Option<Intake>> {
    control.check()?;
    let cache_kind = if kind == 1 {
        "intake-merge"
    } else if profile.depth == 0 {
        "intake-root"
    } else {
        "intake-route"
    };
    let Some((bytes, members)) = chain.epoch_node(epoch, kind, first, last, profile)? else {
        control.record_cache(cache_kind, false, 0);
        return Ok(None);
    };
    let read = u64::try_from(bytes.len() + members.len()).unwrap_or(u64::MAX);
    let Some(members) = decode_members(&members) else {
        control.record_cache(cache_kind, false, read);
        return Ok(None);
    };
    let Ok(proof) = Pcd::<qr::QrIntake>::from_bytes(&bytes) else {
        control.record_cache(cache_kind, false, read);
        return Ok(None);
    };
    if proof.data().0 != EpochIndex::new(epoch)
        || proof.data().4 != profile
        || members.len() > max_polynomial_members()
        || TachygramSetCommit::from(zcash_tachyon::pasta::Eq::from(proof.commitments()[0]))
            != members
                .iter()
                .copied()
                .collect::<TachygramSetPoly>()
                .commit()
        || !verify_proof(&proof).unwrap_or(false)
    {
        control.record_cache(cache_kind, false, read);
        return Ok(None);
    }
    control.record_cache(cache_kind, true, read);
    Ok(Some(Intake { proof, members }))
}

fn put_intake(
    chain: &ChainData<'_>,
    epoch: u32,
    kind: u8,
    first: u32,
    last: u32,
    intake: &Intake,
) -> Result<()> {
    let profile = intake.proof.data().4;
    let pcd = intake
        .proof
        .to_bytes()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    chain.put_epoch_node(
        epoch,
        kind,
        first,
        last,
        profile,
        &pcd,
        &encode_members(&intake.members),
    )
}

fn merge_cached(
    chain: &ChainData<'_>,
    epoch: u32,
    first: u32,
    left: Intake,
    last: u32,
    right: Intake,
    control: &Control,
) -> Result<Intake> {
    let profile = left.proof.data().4;
    if let Some(cached) = load_intake(chain, epoch, 1, first, last, profile, control)?
        && cached.proof.data().1 == left.proof.data().1
        && cached.proof.data().2 == right.proof.data().2
        && cached.proof.data().3 == left.proof.data().3
        && cached
            .members
            .iter()
            .copied()
            .eq(left.members.iter().chain(&right.members).copied())
    {
        return Ok(cached);
    }
    let merged = left.merge(right, control)?;
    put_intake(chain, epoch, 1, first, last, &merged)?;
    Ok(merged)
}

impl Intake {
    #[expect(
        clippy::too_many_arguments,
        reason = "persistent cache identity and proof payload"
    )]
    fn cached_route(
        mut self,
        chain: &ChainData<'_>,
        epoch: u32,
        first: u32,
        last: u32,
        path: &[bool],
        discriminant: QrDiscriminant,
        control: &Control,
    ) -> Result<Self> {
        for &side in path {
            let profile = self.proof.data().4.descend(side);
            control.stage(format!(
                "Routing epoch {epoch} stamps {first}..={last} to depth {}…",
                profile.depth
            ))?;
            if let Some(cached) = load_intake(chain, epoch, 0, first, last, profile, control)? {
                let expected: Vec<_> = self
                    .members
                    .iter()
                    .copied()
                    .filter(|member| {
                        QrClassRoot::of(
                            (*member).into(),
                            discriminant.at(self.proof.data().4.depth),
                        )
                        .0 == side
                    })
                    .collect();
                if cached.members == expected
                    && cached.proof.data().1 == self.proof.data().1
                    && cached.proof.data().2 == self.proof.data().2
                    && cached.proof.data().3 == discriminant
                {
                    self = cached;
                    continue;
                }
            }
            self = self.route(&[side], discriminant, control)?;
            put_intake(chain, epoch, 0, first, last, &self)?;
        }
        Ok(self)
    }
}

/// Every leaf of the capacity-bounded routing tree, including empty siblings.
/// Queries absent from the epoch can still select those empty profiles.
fn profiles(
    members: Vec<Tachygram>,
    discriminant: QrDiscriminant,
    control: &Control,
) -> Result<Vec<Vec<bool>>> {
    let mut pending = vec![(Vec::new(), members)];
    let mut leaves = Vec::new();
    while let Some((path, members)) = pending.pop() {
        control.check()?;
        if members.len() <= max_polynomial_members() {
            leaves.push(path);
            continue;
        }
        ensure!(
            path.len() < QrProfile::MAX_DEPTH,
            "epoch cannot be routed within Tachyon's polynomial capacity"
        );
        let shift = discriminant.at(u32::try_from(path.len())?);
        let (yes, no): (Vec<_>, Vec<_>) = members
            .into_iter()
            .partition(|m| QrClassRoot::of((*m).into(), shift).0);
        for (side, members) in [(false, no), (true, yes)] {
            let mut child = path.clone();
            child.push(side);
            pending.push((child, members));
        }
    }
    Ok(leaves)
}

struct Epoch {
    epoch: u32,
    stamps: Vec<(Anchor, Vec<Tachygram>)>,
    members: Vec<Tachygram>,
    start: Anchor,
    predecessor: Anchor,
    next: Anchor,
    context: String,
}
impl Epoch {
    fn read(chain: &ChainData<'_>, epoch: u32, control: &Control) -> Result<Self> {
        let blocks = chain.epoch_blocks(epoch)?;
        let first = blocks.first().context("missing epoch inputs")?;
        let next_epoch = epoch.checked_add(1).context("epoch overflow")?;
        let next = blocks
            .iter()
            .find(|b| b.epoch == next_epoch)
            .context("epoch has not closed")?;
        ensure!(
            first.epoch == epoch
                && first
                    .pool_height
                    .is_multiple_of(zcash_tachyon::constants::EPOCH_SIZE),
            "missing epoch start"
        );
        ensure!(
            next.pool_height
                .is_multiple_of(zcash_tachyon::constants::EPOCH_SIZE),
            "missing next epoch entry"
        );
        let mut hash = Sha256::new();
        let mut stamps = Vec::new();
        let mut members = BTreeSet::new();
        let mut previous = None;
        for block in blocks.iter().take_while(|b| b.height <= next.height) {
            control.check()?;
            // Validate complete contiguous coverage, including the closing
            // sentinel. A partial epoch must never be sealed as complete.
            if previous.is_none() {
                block.validate_checkpoint(first.activation_height)?;
            } else {
                block.validate(previous, first.activation_height)?;
            }
            previous = Some(block);
            hash.update(serde_json::to_vec(block)?);
            if block.epoch != epoch {
                break;
            }
            let mut cursor = block.entry()?;
            for stamp in &block.stamps {
                let values = stamp.members()?;
                for value in &values {
                    ensure!(members.insert(*value), "duplicate tachygrams in an epoch");
                }
                stamps.push((cursor, values));
                cursor = cursor.next_stamp(EpochIndex::new(epoch), &stamp.commitment()?)?;
            }
        }
        Ok(Self {
            epoch,
            stamps,
            members: members.into_iter().collect(),
            start: first.entry()?,
            predecessor: if epoch == 0 {
                Anchor(Fp::ZERO)
            } else {
                anchor(&first.anchor_before)?
            },
            next: next.entry()?,
            context: hex::encode(hash.finalize()),
        })
    }
    fn selected(&self, path: &[bool]) -> Vec<Tachygram> {
        let discriminant = QrDiscriminant(Fp::ONE);
        self.members
            .iter()
            .copied()
            .filter(|member| {
                path.iter().enumerate().all(|(depth, side)| {
                    QrClassRoot::of(
                        (*member).into(),
                        discriminant.at(u32::try_from(depth).expect("bounded depth")),
                    )
                    .0 == *side
                })
            })
            .collect()
    }
    fn verify(
        &self,
        payload: &Payload,
        path: &[bool],
    ) -> Result<Option<(Pcd<qr::QrBucket>, Vec<Tachygram>)>> {
        let Some(members) = decode_members(&payload.1) else {
            return Ok(None);
        };
        let expected = self.selected(path);
        if members.len() != expected.len()
            || members.iter().copied().collect::<BTreeSet<_>>()
                != expected.iter().copied().collect()
        {
            return Ok(None);
        }
        let Ok(proof) = Pcd::<qr::QrBucket>::from_bytes(&payload.0) else {
            return Ok(None);
        };
        let profile = path.iter().fold(QrProfile::ROOT, |p, &b| p.descend(b));
        let commitment = expected.into_iter().collect::<TachygramSetPoly>().commit();
        let data = proof.data();
        if data.0 != EpochIndex::new(self.epoch)
            || data.1 != self.start
            || data.2 != self.next
            || data.3 != QrDiscriminant(Fp::ONE)
            || data.4 != profile
            || data.5 != commitment.bridge()?
            || TachygramSetCommit::from(zcash_tachyon::pasta::Eq::from(proof.commitments()[0]))
                != commitment
            || !verify_proof(&proof).unwrap_or(false)
        {
            return Ok(None);
        }
        Ok(Some((proof, members)))
    }
    fn chunks(&self, chain: &ChainData<'_>, control: &Control) -> Result<Vec<(u32, u32, Intake)>> {
        let epoch = self.epoch;
        let epoch_index = EpochIndex::new(epoch);
        let discriminant = QrDiscriminant(Fp::ONE);
        let mut chunks = Vec::new();
        let mut current: Option<(u32, u32, Intake)> = None;
        let total = self.stamps.len();
        for (index, (before, members)) in self.stamps.iter().cloned().enumerate() {
            let index = u32::try_from(index)?;
            let intake = if let Some(cached) =
                load_intake(chain, epoch, 0, index, index, QrProfile::ROOT, control)?
            {
                let expected_end = before.next_stamp(
                    epoch_index,
                    &members
                        .iter()
                        .copied()
                        .collect::<TachygramSetPoly>()
                        .commit(),
                )?;
                if cached.members == members
                    && cached.proof.data().1 == before
                    && cached.proof.data().2 == expected_end
                    && cached.proof.data().3 == discriminant
                {
                    Some(cached)
                } else {
                    None
                }
            } else {
                None
            };
            let intake = if let Some(cached) = intake {
                cached
            } else {
                control.stage(format!(
                    "Proving epoch {epoch} stamp intake {}/{total}…",
                    index + 1
                ))?;
                let (proof, ()) = PROOF_SYSTEM.seed(
                    &mut rand::rng(),
                    qr::QrStampIntakeSeed,
                    witness::qr_stamp_intake_seed(
                        ((), ()),
                        before,
                        epoch_index,
                        discriminant,
                        &members,
                    ),
                )?;
                let intake = Intake { proof, members };
                put_intake(chain, epoch, 0, index, index, &intake)?;
                intake
            };
            current = match current.take() {
                Some((first, _, left))
                    if left.members.len() + intake.members.len() <= max_polynomial_members() =>
                {
                    Some((
                        first,
                        index,
                        merge_cached(chain, epoch, first, left, index, intake, control)?,
                    ))
                }
                Some(chunk) => {
                    chunks.push(chunk);
                    Some((index, index, intake))
                }
                None => Some((index, index, intake)),
            };
        }
        if let Some(chunk) = current {
            chunks.push(chunk);
        }
        if chunks.is_empty() {
            control.stage(format!("Proving empty epoch {epoch}…"))?;
            let (proof, ()) = PROOF_SYSTEM.seed(
                &mut rand::rng(),
                qr::QrEmptyIntakeSeed,
                witness::qr_empty_intake_seed(((), ()), self.start, epoch_index, discriminant),
            )?;
            chunks.push((
                0,
                0,
                Intake {
                    proof,
                    members: Vec::new(),
                },
            ));
        }
        Ok(chunks)
    }

    fn build(
        &self,
        chain: &ChainData<'_>,
        path: &[bool],
        chunks: &[(u32, u32, Intake)],
        control: &Control,
    ) -> Result<Payload> {
        let epoch = self.epoch;
        let discriminant = QrDiscriminant(Fp::ONE);
        let mut intakes = chunks.to_vec();
        for &side in path {
            // QrIntakeSplit rejects empty intakes. Absorb empty spans into an
            // adjacent nonempty intake before descending, preserving coverage
            // without inventing a proof or dropping an anchor transition.
            let mut joined: Vec<(u32, u32, Intake)> = Vec::new();
            for (first, last, right) in intakes {
                if let Some((left_first, left_last, left)) = joined.pop() {
                    if left.members.is_empty() || right.members.is_empty() {
                        joined.push((
                            left_first,
                            last,
                            merge_cached(chain, epoch, left_first, left, last, right, control)?,
                        ));
                    } else {
                        joined.push((left_first, left_last, left));
                        joined.push((first, last, right));
                    }
                } else {
                    joined.push((first, last, right));
                }
            }
            intakes = Vec::with_capacity(joined.len());
            for (first, last, intake) in joined {
                intakes.push((
                    first,
                    last,
                    intake.cached_route(
                        chain,
                        epoch,
                        first,
                        last,
                        &[side],
                        discriminant,
                        control,
                    )?,
                ));
            }
        }
        // Balanced, adjacent merges avoid rebuilding an ever-growing prefix for
        // every stamp, while preserving the original anchor order.
        while intakes.len() > 1 {
            control.stage(format!("Merging {} epoch {epoch} intakes…", intakes.len()))?;
            let mut merged = Vec::new();
            let mut pairs = intakes.into_iter();
            while let Some((first, left_last, left)) = pairs.next() {
                merged.push(match pairs.next() {
                    Some((_, last, right)) => {
                        let intake = merge_cached(chain, epoch, first, left, last, right, control)?;
                        (first, last, intake)
                    }
                    None => (first, left_last, left),
                });
            }
            intakes = merged;
        }
        let (_, _, Intake { proof, members }) = intakes.pop().context("missing epoch intake")?;

        control.stage(format!("Sealing epoch {epoch} bucket…"))?;
        let (bucket, ()) = PROOF_SYSTEM.fuse(
            &mut rand::rng(),
            qr::QrBucketSeal,
            witness::qr_bucket_seal((*proof.data(), ()), self.predecessor),
            proof,
            trivial(),
        )?;
        ensure!(
            bucket.data().2 == self.next,
            "epoch evidence does not meet the next entry anchor"
        );
        Ok((
            bucket
                .to_bytes()
                .map_err(|e| anyhow::anyhow!(e.to_string()))?,
            encode_members(&members),
        ))
    }
    fn get(
        &self,
        chain: &ChainData<'_>,
        path: &[bool],
        chunks: &mut Option<Vec<(u32, u32, Intake)>>,
        cache: Option<(&Cache, &str, i64)>,
        control: &Control,
    ) -> Result<(Pcd<qr::QrBucket>, Vec<Tachygram>)> {
        let profile = path.iter().fold(QrProfile::ROOT, |p, &b| p.descend(b));
        let build = || -> Result<Payload> {
            // Old wire caches are retained and promoted only after full
            // verification against this chain and the current proof system.
            if let Some(payload) = chain.bucket_proof(self.epoch, profile)?
                && self.verify(&payload, path)?.is_some()
            {
                return Ok(payload);
            }
            if chunks.is_none() {
                *chunks = Some(self.chunks(chain, control)?);
            }
            self.build(chain, path, chunks.as_ref().unwrap(), control)
        };
        if let Some((cache, namespace, generation)) = cache {
            let key = Key {
                namespace: namespace.into(),
                epoch: self.epoch,
                depth: profile.depth,
                bits: profile.bits,
                context: self.context.clone(),
                generation,
            };
            cache.get_or_build(&key, control, |p| self.verify(p, path), build)
        } else {
            let mut build = build;
            let payload = build()?;
            self.verify(&payload, path)?
                .context("invalid epoch evidence")
        }
    }
}

pub(super) fn bucket(
    chain: &ChainData<'_>,
    epoch: u32,
    query: Tachygram,
    control: &Control,
) -> Result<(Pcd<qr::QrBucket>, Vec<Tachygram>)> {
    let cached = match chain {
        ChainData::Store(store) => {
            store.check_evidence_identity(&store.config()?)?;
            Some((
                store.evidence_cache()?,
                crate::evidence::namespace(&store.config()?.network_id),
            ))
        }
        _ => None,
    };
    let generation = cached.as_ref().map(|(c, _)| c.generation()).transpose()?;
    let epoch = Epoch::read(chain, epoch, control)?;
    let path = routing_path(
        epoch.members.clone(),
        query,
        QrDiscriminant(Fp::ONE),
        control,
    )?;
    epoch.get(
        chain,
        &path,
        &mut None,
        cached
            .as_ref()
            .map(|(c, n)| (c, n.as_str(), generation.unwrap())),
        control,
    )
}

/// Prewarm all closed epochs available in this wallet's public history. This
/// deliberately uses a read-only wallet connection and a separate evidence DB.
pub(crate) fn prewarm(store: &crate::store::Store, control: &Control) -> Result<serde_json::Value> {
    let config = store.config()?;
    store.check_evidence_identity(&config)?;
    let cache = store.evidence_cache()?;
    let generation = cache.generation()?;
    let namespace = crate::evidence::namespace(&config.network_id);
    let chain = ChainData::Store(store);
    let tip = chain.tip()?;
    let first = store.first_height()?.context("wallet has not synced")?;
    let first_epoch = first
        .checked_sub(config.activation)
        .context("public history precedes activation")?
        / zcash_tachyon::constants::EPOCH_SIZE;
    let mut completed = 0u64;
    for index in first_epoch..tip.epoch {
        control.check()?;
        let height = config
            .activation
            .checked_add(
                index
                    .checked_mul(zcash_tachyon::constants::EPOCH_SIZE)
                    .context("epoch overflow")?,
            )
            .context("epoch height overflow")?;
        let first = store.block(height)?.context("missing epoch start")?;
        let next = store
            .block(
                height
                    .checked_add(zcash_tachyon::constants::EPOCH_SIZE)
                    .context("epoch height overflow")?,
            )?
            .context("missing next epoch entry")?;
        if let Some(count) = cache.completed_epoch(&namespace, index, &first.hash, &next.hash)? {
            completed += u64::from(count);
            continue;
        }
        let epoch = Epoch::read(&chain, index, control)?;
        let mut chunks = None;
        let paths = profiles(epoch.members.clone(), QrDiscriminant(Fp::ONE), control)?;
        let count = u32::try_from(paths.len())?;
        for path in paths {
            epoch.get(
                &chain,
                &path,
                &mut chunks,
                Some((&cache, &namespace, generation)),
                control,
            )?;
        }
        let key = Key {
            namespace: namespace.clone(),
            epoch: index,
            depth: 0,
            bits: 0,
            context: epoch.context,
            generation,
        };
        cache.complete_epoch(&key, &first.hash, &next.hash, count)?;
        completed += u64::from(count);
    }
    ensure!(
        cache.generation()? == generation,
        "epoch evidence invalidated by reorg"
    );
    Ok(
        serde_json::json!({"profiles":completed,"through_epoch":tip.epoch.checked_sub(1),"height":tip.height,"hash":tip.hash,"generation":generation,"namespace":namespace}),
    )
}

fn encode_members(members: &[Tachygram]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(members.len() * 32);
    for member in members {
        bytes.extend_from_slice(Fp::from(*member).to_bytes().as_ref());
    }
    bytes
}

fn decode_members(bytes: &[u8]) -> Option<Vec<Tachygram>> {
    if !bytes.len().is_multiple_of(32) {
        return None;
    }
    bytes
        .as_chunks::<32>()
        .0
        .iter()
        .map(|chunk| {
            let mut repr = Fp::ZERO.to_bytes();
            repr.as_mut_slice().copy_from_slice(chunk);
            Fp::from_bytes(repr).map(Tachygram::from)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use zcash_tachyon::TachygramSetPoly;

    use super::*;

    #[test]
    fn empty_chunk_spans_survive_multiple_routing_levels() -> Result<()> {
        let disc = QrDiscriminant(Fp::ONE);
        let query = Tachygram::from(Fp::from(7));
        let side = QrClassRoot::of(query.into(), disc.at(0)).0;
        let excluded = (1u64..)
            .map(Fp::from)
            .map(Tachygram::from)
            .find(|m| QrClassRoot::of((*m).into(), disc.at(0)).0 != side)
            .unwrap();
        let mut cursor = Anchor::default();
        let mut chunks = Vec::new();
        for (index, member) in [excluded, query].into_iter().enumerate() {
            let members = vec![member];
            let (proof, ()) = PROOF_SYSTEM.seed(
                &mut rand::rng(),
                qr::QrStampIntakeSeed,
                witness::qr_stamp_intake_seed(((), ()), cursor, EpochIndex::new(0), disc, &members),
            )?;
            cursor = cursor.next_stamp(
                EpochIndex::new(0),
                &members
                    .iter()
                    .copied()
                    .collect::<TachygramSetPoly>()
                    .commit(),
            )?;
            chunks.push((
                u32::try_from(index)?,
                u32::try_from(index)?,
                Intake { proof, members },
            ));
        }
        let epoch = Epoch {
            epoch: 0,
            stamps: Vec::new(),
            members: vec![excluded, query],
            start: Anchor::default(),
            predecessor: Anchor(Fp::ZERO),
            next: cursor.next_epoch(EpochIndex::new(1))?,
            context: String::new(),
        };
        let path = [side, QrClassRoot::of(query.into(), disc.at(1)).0];
        let payload = epoch.build(&ChainData::Blocks(&[]), &path, &chunks, &Control::new(true))?;
        assert!(epoch.verify(&payload, &path)?.is_some());
        Ok(())
    }

    #[test]
    fn profiles_include_empty_siblings_and_follow_query_rules() -> Result<()> {
        let disc = QrDiscriminant(Fp::ONE);
        let control = Control::new(true);
        assert_eq!(
            profiles(Vec::new(), disc, &control)?,
            vec![Vec::<bool>::new()]
        );
        let members: Vec<_> = (1u64..)
            .map(Fp::from)
            .map(Tachygram::from)
            .filter(|m| QrClassRoot::of((*m).into(), disc.at(0)).0)
            .take(max_polynomial_members() + 1)
            .collect();
        let paths = profiles(members.clone(), disc, &control)?;
        assert!(paths.contains(&vec![false]));
        assert!(paths.iter().any(|p| p.len() > 1));
        for query in (0u64..4).map(Fp::from).map(Tachygram::from) {
            assert!(paths.contains(&routing_path(members.clone(), query, disc, &control)?));
        }
        Ok(())
    }

    #[test]
    #[ignore = "manual benchmark; requires a disposable database COPY and public blocks"]
    fn benchmark_evidence_copy() -> Result<()> {
        use crate::store::{Config, Store};
        use std::{path::PathBuf, time::Instant};
        let path = PathBuf::from(
            std::env::var_os("EVIDENCE_BENCH_DB").context("EVIDENCE_BENCH_DB missing")?,
        );
        ensure!(
            path.file_name().is_some_and(|n| n == "benchmark.sqlite"),
            "benchmark only accepts a file named benchmark.sqlite, never live evidence.sqlite"
        );
        let blocks: Vec<crate::chain::Block> = serde_json::from_slice(&std::fs::read(
            std::env::var_os("EVIDENCE_BENCH_BLOCKS").context("EVIDENCE_BENCH_BLOCKS missing")?,
        )?)?;
        let conn = rusqlite::Connection::open(&path)?;
        let network: String = conn.query_row(
            "SELECT value FROM metadata WHERE key='network_id'",
            [],
            |r| r.get(0),
        )?;
        let dir = tempfile::tempdir()?;
        #[cfg(unix)]
        std::fs::set_permissions(
            dir.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )?;
        let store = Store::open(dir.path(), true)?;
        store.set_config(&Config {
            version: 1,
            rpc_url: String::new(),
            cookie_file: None,
            activation: blocks[0].activation_height,
            activation_hash: blocks[0].hash.clone(),
            genesis: String::new(),
            network_id: network,
            seed: [0; 32],
            birthday_height: None,
        })?;
        for block in &blocks {
            store.put_block(block)?;
        }
        store.commit()?;
        drop(store);
        let mut store = Store::open_for_prewarm(dir.path())?;
        store.use_evidence_copy(&path)?;
        let cache = store.evidence_cache()?;
        // Only the disposable COPY is mutated. Preserve all intake/merge nodes
        // to reproduce the reported warm-base/cold-final boundary condition.
        if std::env::var_os("EVIDENCE_BENCH_COLD").is_some() {
            cache.invalidate()?;
            conn.execute("DELETE FROM epoch_proofs", [])?;
        }
        let control = Control::with_timing(true, true);
        let start = Instant::now();
        let result = prewarm(&store, &control)?;
        println!(
            "PREWARM result={result} seconds={:.3} cache={:?}",
            start.elapsed().as_secs_f64(),
            control.cache_counts("bucket")
        );
        let repeated = Control::with_timing(true, true);
        let start = Instant::now();
        prewarm(&store, &repeated)?;
        println!(
            "INCREMENTAL_RECHECK seconds={:.3} cache={:?}",
            start.elapsed().as_secs_f64(),
            repeated.cache_counts("bucket")
        );
        assert_eq!(repeated.cache_counts("bucket"), (0, 0));
        let epoch = blocks[0].epoch;
        let warm = Control::with_timing(true, true);
        let start = Instant::now();
        let (proof, members) = bucket(
            &ChainData::Store(&store),
            epoch,
            Tachygram::from(Fp::from(7)),
            &warm,
        )?;
        ensure!(verify_proof(&proof)?, "invalid warm proof");
        println!(
            "FIRST_PAYMENT_BUCKET seconds={:.3} members={} cache={:?}",
            start.elapsed().as_secs_f64(),
            members.len(),
            warm.cache_counts("bucket")
        );
        assert_eq!(warm.cache_counts("bucket"), (1, 0));
        Ok(())
    }

    #[test]
    fn empty_routed_stamps_still_cover_their_anchor_transitions() -> Result<()> {
        let epoch = EpochIndex::new(0);
        let discriminant = QrDiscriminant(Fp::from(1));
        let query = Tachygram::from(Fp::from(7));
        let side = QrClassRoot::of(query.into(), discriminant.at(0)).0;
        let excluded: Vec<_> = (1u64..)
            .map(|i| Tachygram::from(Fp::from(i)))
            .filter(|value| QrClassRoot::of((*value).into(), discriminant.at(0)).0 != side)
            .take(2)
            .collect();
        let mut anchor = Anchor::default();
        let mut intakes = Vec::new();
        for members in [vec![excluded[0]], vec![excluded[1]], vec![query]] {
            let (proof, ()) = PROOF_SYSTEM.seed(
                &mut rand::rng(),
                qr::QrStampIntakeSeed,
                witness::qr_stamp_intake_seed(((), ()), anchor, epoch, discriminant, &members),
            )?;
            anchor = anchor.next_stamp(
                epoch,
                &members
                    .iter()
                    .copied()
                    .collect::<TachygramSetPoly>()
                    .commit(),
            )?;
            intakes.push(Intake { proof, members }.route(
                &[side],
                discriminant,
                &Control::new(true),
            )?);
        }
        assert!(intakes[0].members.is_empty());
        assert!(intakes[1].members.is_empty());
        assert_eq!(intakes[2].members, vec![query]);
        let mut intakes = intakes.into_iter();
        let intake = intakes
            .next()
            .unwrap()
            .merge(intakes.next().unwrap(), &Control::new(true))?
            .merge(intakes.next().unwrap(), &Control::new(true))?;
        assert_eq!(intake.proof.data().1, Anchor::default());
        assert_eq!(intake.proof.data().2, anchor);
        let (bucket, ()) = PROOF_SYSTEM.fuse(
            &mut rand::rng(),
            qr::QrBucketSeal,
            witness::qr_bucket_seal((*intake.proof.data(), ()), Anchor(Fp::from(0))),
            intake.proof,
            trivial(),
        )?;
        assert_eq!(bucket.data().2, anchor.next_epoch(EpochIndex::new(1))?);
        // Absence from a different bucket does not prove absence from the epoch:
        // QrUnspentInit must bind the tested value to the selected path.
        let result = PROOF_SYSTEM.fuse(
            &mut rand::rng(),
            qr::QrUnspentInit,
            witness::qr_unspent_init((*bucket.data(), ()), excluded[0]),
            bucket,
            trivial(),
        );
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn persistent_intake_round_trip_and_corruption_fallback() -> Result<()> {
        let temp = tempfile::tempdir()?;
        #[cfg(unix)]
        std::fs::set_permissions(
            temp.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )?;
        let store = crate::store::Store::open(temp.path(), true)?;
        let chain = ChainData::from(&store);
        let epoch = EpochIndex::new(0);
        let discriminant = QrDiscriminant(Fp::from(1));
        let query = Tachygram::from(Fp::from(7));
        let side = QrClassRoot::of(query.into(), discriminant.at(0)).0;
        let excluded = (1u64..)
            .map(Fp::from)
            .map(Tachygram::from)
            .find(|value| QrClassRoot::of((*value).into(), discriminant.at(0)).0 != side)
            .unwrap();
        let second = QrClassRoot::of(query.into(), discriminant.at(1)).0;
        let other = (8u64..)
            .map(Fp::from)
            .map(Tachygram::from)
            .find(|value| {
                QrClassRoot::of((*value).into(), discriminant.at(0)).0 == side
                    && QrClassRoot::of((*value).into(), discriminant.at(1)).0 != second
            })
            .unwrap();
        let members = vec![query, other, excluded];
        let (proof, ()) = PROOF_SYSTEM.seed(
            &mut rand::rng(),
            qr::QrStampIntakeSeed,
            witness::qr_stamp_intake_seed(
                ((), ()),
                Anchor::default(),
                epoch,
                discriminant,
                &members,
            ),
        )?;
        let intake = Intake { proof, members };
        put_intake(&chain, 0, 0, 0, 0, &intake)?;
        let cached =
            load_intake(&chain, 0, 0, 0, 0, QrProfile::ROOT, &Control::new(true))?.unwrap();
        assert_eq!(cached.proof.data(), intake.proof.data());
        assert_eq!(cached.members, intake.members);
        cached.cached_route(
            &chain,
            0,
            0,
            0,
            &[side, second],
            discriminant,
            &Control::new(true),
        )?;
        store.put_epoch_node(0, 0, 0, 0, QrProfile::ROOT, b"corrupt", b"members")?;
        assert!(load_intake(&chain, 0, 0, 0, 0, QrProfile::ROOT, &Control::new(true))?.is_none());
        Ok(())
    }

    #[test]
    fn routing_stops_at_capacity_and_descends_further_for_skewed_members() -> Result<()> {
        let discriminant = QrDiscriminant(Fp::from(1));
        let query = Tachygram::from(Fp::from(7));
        let side = QrClassRoot::of(query.into(), discriminant.at(0)).0;
        let members: Vec<_> = (1u64..)
            .map(|i| Tachygram::from(Fp::from(i)))
            .filter(|v| QrClassRoot::of((*v).into(), discriminant.at(0)).0 == side)
            .take(max_polynomial_members() + 1)
            .collect();
        assert!(
            routing_path(
                members[..max_polynomial_members()].to_vec(),
                query,
                discriminant,
                &Control::new(true)
            )?
            .is_empty()
        );
        let path = routing_path(members, query, discriminant, &Control::new(true))?;
        assert_eq!(path.len(), 2);
        assert_eq!(path[0], side);
        assert_eq!(path[1], QrClassRoot::of(query.into(), discriminant.at(1)).0);
        Ok(())
    }
}
