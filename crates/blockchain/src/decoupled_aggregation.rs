//! Staggered signing and two-level aggregation of lean decoupled attestations.
//!
//! At a round's action time `a_r` every validator's attestation is decided at
//! once (one [`AttestationInput`](ethlambda_decoupled::AttestationInput)
//! snapshot), but signed in subgroups spread over the rest of the slot, so
//! aggregators can prove while votes are still arriving:
//!
//! ```text
//! a_r                 subgroup 0 signs, on its subnet
//! a_r + spacing       subgroup 1 signs     subnet aggregators fold each
//! a_r + 2·spacing     subgroup 2 signs     quarter of their subnet into a
//! a_r + 3·spacing     subgroup 3 signs     running proof, the last one as a child
//! final deadline      last batch; each subnet aggregator publishes its proof
//! all subnets in      every aggregator merges the subnet proofs, one per data,
//!   (or deadline)     and publishes the result for proposers to pack
//! ```
//!
//! A validator's subgroup is [`attestation_subgroup`]: subgroups split each
//! subnet evenly. An aggregator folds a batch once a subgroup's worth of its
//! subnets' votes is pending, which is a count, not a clock: a slow prover
//! simply folds bigger batches. Only the last batch is published, and the
//! merge across subnets starts once every subnet with validators has a
//! published proof for the slot, or at the merge deadline.
//!
//! Everything here is store-free. The actor in `decoupled_lean` owns the
//! pools and the schedule, and hands [`Job`]s to a worker thread.

use std::collections::{BTreeMap, HashMap, HashSet};

use ethlambda_crypto::signature::{ValidatorPublicKey, ValidatorSignature};
use ethlambda_crypto::{
    AggregationError, MAX_CHILD_PROOFS, aggregate_mixed, aggregate_proofs,
    verify_aggregated_signature,
};
use ethlambda_types::aggregator::AggregatorController;
use ethlambda_types::attestation::{AggregationBits, XmssSignature};
use ethlambda_types::block::ByteList512KiB;
use ethlambda_types::decoupled::{Attestation, AttestationData};
use ethlambda_types::lean_decoupled::{
    AggregatedDecoupledAttestation, attestation_epoch, attestation_subnet,
};
use ethlambda_types::primitives::{H256, HashTreeRoot as _};
use libssz::SszEncode as _;

/// Default number of signing subgroups per subnet.
pub const DEFAULT_ATTESTATION_SUBGROUPS: u64 = 4;

/// Default fan-in of a merge: leanVM's limit, so a merge across up to that
/// many subnets is one proof.
pub const DEFAULT_MAX_AGGREGATION_CHILDREN: usize = MAX_CHILD_PROOFS;

/// The operator's knobs. Every node of a network should run the same
/// `subgroups` and `subgroup_spacing_ms`: validators sign by them, and
/// aggregators size their batches and deadlines by them.
#[derive(Clone, Debug)]
pub struct AggregationConfig {
    /// The aggregator role, toggleable at runtime.
    pub aggregator: AggregatorController,
    /// Number of attestation subnets.
    pub committee_count: u64,
    /// The subnets this node aggregates: `--aggregate-subnet-ids`, else every
    /// subnet it subscribes to.
    pub duty_subnets: HashSet<u64>,
    /// Signing subgroups per subnet.
    pub subgroups: u64,
    /// Time between two subgroups' signing. `None`: half a `Δ`.
    pub subgroup_spacing_ms: Option<u64>,
    /// Most child proofs one merge folds in.
    pub max_children: usize,
    /// How long after `a_r` an aggregator waits for every subnet's proof
    /// before merging what it has. `None`: two `Δ` after the final deadline.
    pub merge_deadline_ms: Option<u64>,
}

impl AggregationConfig {
    /// A node without the aggregator role, on `committee_count` subnets.
    pub fn without_aggregator(committee_count: u64) -> Self {
        Self {
            aggregator: AggregatorController::new(false),
            committee_count,
            duty_subnets: HashSet::new(),
            subgroups: DEFAULT_ATTESTATION_SUBGROUPS,
            subgroup_spacing_ms: None,
            max_children: DEFAULT_MAX_AGGREGATION_CHILDREN,
            merge_deadline_ms: None,
        }
    }
}

/// The schedule of one round, as offsets from its action time `a_r`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Schedule {
    pub subgroups: u64,
    pub spacing_ms: u64,
    /// When an aggregator folds its last batch, whatever is still missing:
    /// the last subgroup's signing time plus half a `Δ` for its votes to
    /// arrive.
    pub final_deadline_ms: u64,
    /// When an aggregator merges whatever subnet proofs it has.
    pub merge_deadline_ms: u64,
}

impl Schedule {
    pub fn new(config: &AggregationConfig, delta_ms: u64) -> Self {
        let subgroups = config.subgroups.max(1);
        let spacing_ms = config.subgroup_spacing_ms.unwrap_or(delta_ms / 2);
        let final_deadline_ms = spacing_ms * (subgroups - 1) + delta_ms / 2;
        let merge_deadline_ms = config
            .merge_deadline_ms
            .unwrap_or(final_deadline_ms + 2 * delta_ms)
            .max(final_deadline_ms);
        Self {
            subgroups,
            spacing_ms,
            final_deadline_ms,
            merge_deadline_ms,
        }
    }

    /// When `subgroup` signs, after `a_r`.
    pub fn sign_offset_ms(&self, subgroup: u64) -> u64 {
        subgroup * self.spacing_ms
    }
}

/// Validators with an index below `validator_count` on `subnets`.
pub fn validators_on(subnets: &HashSet<u64>, validator_count: u64, committee_count: u64) -> u64 {
    let committee_count = committee_count.max(1);
    subnets
        .iter()
        .filter(|&&subnet| subnet < committee_count)
        .map(|&subnet| {
            validator_count / committee_count
                + u64::from(subnet < validator_count % committee_count)
        })
        .sum()
}

/// Every subnet some validator is on.
pub fn populated_subnets(validator_count: u64, committee_count: u64) -> HashSet<u64> {
    (0..committee_count.max(1).min(validator_count)).collect()
}

// ── Pools ──────────────────────────────────────────────────────────────────

/// One data's signatures from one slot, not yet folded into a proof.
#[derive(Debug, Clone)]
pub struct RawGroup {
    pub data: AttestationData,
    pub signatures: BTreeMap<u64, XmssSignature>,
}

/// One data's signatures a batch folds in.
#[derive(Debug, Clone)]
pub struct Pending {
    pub data_root: H256,
    pub data: AttestationData,
    pub signatures: Vec<(u64, XmssSignature)>,
}

/// Individual signatures an aggregator holds, by `(data root, slot)`.
#[derive(Debug, Default)]
pub struct RawPool {
    groups: HashMap<(H256, u64), RawGroup>,
}

impl RawPool {
    pub fn insert(
        &mut self,
        data: &AttestationData,
        slot: u64,
        validator: u64,
        signature: XmssSignature,
    ) {
        self.groups
            .entry((data.hash_tree_root(), slot))
            .or_insert_with(|| RawGroup {
                data: data.clone(),
                signatures: BTreeMap::new(),
            })
            .signatures
            .insert(validator, signature);
    }

    /// Signatures of `slot` whose signer is not in `folded`.
    pub fn pending(&self, slot: u64, folded: &HashSet<u64>) -> usize {
        self.groups
            .iter()
            .filter(|((_, group_slot), _)| *group_slot == slot)
            .map(|(_, group)| {
                group
                    .signatures
                    .keys()
                    .filter(|validator| !folded.contains(validator))
                    .count()
            })
            .sum()
    }

    /// The pending signatures of `slot`, one entry per data.
    pub fn batch(&self, slot: u64, folded: &HashSet<u64>) -> Vec<Pending> {
        let mut batch: Vec<Pending> = self
            .groups
            .iter()
            .filter(|((_, group_slot), _)| *group_slot == slot)
            .filter_map(|((root, _), group)| {
                let signatures: Vec<(u64, XmssSignature)> = group
                    .signatures
                    .iter()
                    .filter(|(validator, _)| !folded.contains(validator))
                    .map(|(validator, signature)| (*validator, signature.clone()))
                    .collect();
                (!signatures.is_empty()).then(|| Pending {
                    data_root: *root,
                    data: group.data.clone(),
                    signatures,
                })
            })
            .collect();
        batch.sort_by_key(|pending| pending.data_root);
        batch
    }

    /// Forget signatures now inside a proof.
    pub fn remove(&mut self, data_root: H256, slot: u64, validators: &[u64]) {
        if let Some(group) = self.groups.get_mut(&(data_root, slot)) {
            for validator in validators {
                group.signatures.remove(validator);
            }
            if group.signatures.is_empty() {
                self.groups.remove(&(data_root, slot));
            }
        }
    }

    /// Drop every slot below `oldest`.
    pub fn prune(&mut self, oldest: u64) {
        self.groups.retain(|(_, slot), _| *slot >= oldest);
    }

    pub fn len(&self) -> usize {
        self.groups
            .values()
            .map(|group| group.signatures.len())
            .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }
}

/// An aggregate held for merging and packing, with its participants decoded.
#[derive(Debug, Clone)]
pub struct Pooled {
    pub aggregate: AggregatedDecoupledAttestation,
    pub participants: Vec<u64>,
}

/// Verified aggregates, by `(data root, slot)`.
#[derive(Debug, Default)]
pub struct AggregatePool {
    entries: HashMap<(H256, u64), Vec<Pooled>>,
}

impl AggregatePool {
    /// Add `aggregate` unless an entry with the same participants is already
    /// held for its data and slot. Returns whether it was added.
    pub fn insert(&mut self, aggregate: AggregatedDecoupledAttestation) -> bool {
        let participants: Vec<u64> = aggregate.participant_indices().collect();
        let key = (aggregate.data.hash_tree_root(), aggregate.slot);
        let entries = self.entries.entry(key).or_default();
        if entries.iter().any(|held| held.participants == participants) {
            return false;
        }
        entries.push(Pooled {
            aggregate,
            participants,
        });
        true
    }

    /// The subnets some held aggregate of `slot` has a participant on.
    pub fn covered_subnets(&self, slot: u64, committee_count: u64) -> HashSet<u64> {
        self.entries
            .iter()
            .filter(|((_, entry_slot), _)| *entry_slot == slot)
            .flat_map(|(_, entries)| entries.iter())
            .flat_map(|held| held.participants.iter())
            .map(|&validator| attestation_subnet(validator, committee_count))
            .collect()
    }

    /// For every data of `slot` worth merging, the proofs to merge: pairwise
    /// disjoint, largest first. A data is skipped when one held proof already
    /// covers every participant held for it, or when fewer than two disjoint
    /// proofs are left.
    pub fn merge_inputs(&self, slot: u64) -> Vec<(H256, &AttestationData, Vec<&Pooled>)> {
        let mut inputs = Vec::new();
        for ((root, entry_slot), entries) in &self.entries {
            if *entry_slot != slot || entries.len() < 2 {
                continue;
            }
            let union: HashSet<u64> = entries
                .iter()
                .flat_map(|held| held.participants.iter().copied())
                .collect();
            if entries
                .iter()
                .any(|held| held.participants.len() == union.len())
            {
                continue;
            }
            let mut by_size: Vec<&Pooled> = entries.iter().collect();
            by_size.sort_by_key(|held| std::cmp::Reverse(held.participants.len()));
            let mut covered = HashSet::new();
            let mut chosen = Vec::new();
            for held in by_size {
                if held.participants.iter().any(|v| covered.contains(v)) {
                    continue;
                }
                covered.extend(held.participants.iter().copied());
                chosen.push(held);
            }
            if chosen.len() >= 2 {
                inputs.push((*root, &entries[0].aggregate.data, chosen));
            }
        }
        inputs.sort_by_key(|(root, _, _)| *root);
        inputs
    }

    /// The fewest held aggregates, signed before `block_slot`, that cover the
    /// attestations `selected` names, greedily, at most `cap` of them. Data
    /// keep the order of their first attestation in `selected`.
    pub fn pack(
        &self,
        selected: &[Attestation],
        block_slot: u64,
        cap: usize,
    ) -> Vec<AggregatedDecoupledAttestation> {
        let mut order: Vec<H256> = Vec::new();
        let mut wanted: HashMap<H256, HashSet<u64>> = HashMap::new();
        for attestation in selected {
            let root = attestation.data.hash_tree_root();
            wanted
                .entry(root)
                .or_insert_with(|| {
                    order.push(root);
                    HashSet::new()
                })
                .insert(attestation.validator);
        }
        let mut packed = Vec::new();
        for root in order {
            let mut uncovered = wanted.remove(&root).unwrap_or_default();
            let candidates: Vec<&Pooled> = self
                .entries
                .iter()
                .filter(|((entry_root, slot), _)| *entry_root == root && *slot < block_slot)
                .flat_map(|(_, entries)| entries.iter())
                .collect();
            while !uncovered.is_empty() && packed.len() < cap {
                let best = candidates
                    .iter()
                    .map(|held| {
                        let gain = held
                            .participants
                            .iter()
                            .filter(|v| uncovered.contains(v))
                            .count();
                        (gain, *held)
                    })
                    .filter(|(gain, _)| *gain > 0)
                    .max_by_key(|(gain, held)| (*gain, std::cmp::Reverse(held.aggregate.slot)));
                let Some((_, held)) = best else {
                    break;
                };
                for validator in &held.participants {
                    uncovered.remove(validator);
                }
                packed.push(held.aggregate.clone());
            }
        }
        packed
    }

    /// Keep the data `keep` accepts.
    pub fn retain(&mut self, mut keep: impl FnMut(&AttestationData) -> bool) {
        self.entries.retain(|_, entries| {
            entries
                .first()
                .is_some_and(|held| keep(&held.aggregate.data))
        });
    }

    pub fn len(&self) -> usize {
        self.entries.values().map(Vec::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ── Proving ────────────────────────────────────────────────────────────────

/// A proof to fold in, with what a verifier needs to decode it.
#[derive(Clone)]
pub struct Child {
    pub pubkeys: Vec<ValidatorPublicKey>,
    pub proof: ByteList512KiB,
    pub participants: Vec<u64>,
}

/// One proof to produce: `children` and `raw` signatures, all over one data
/// signed in one slot.
pub struct Job {
    pub data: AttestationData,
    pub data_root: H256,
    pub slot: u64,
    pub children: Vec<Child>,
    pub raw: Vec<(u64, ValidatorPublicKey, ValidatorSignature)>,
}

/// What a [`Job`] produced.
#[derive(Debug, Clone)]
pub struct Produced {
    pub data_root: H256,
    pub aggregate: AggregatedDecoupledAttestation,
    /// The validators that came in as raw signatures.
    pub folded: Vec<u64>,
}

/// Run `job`, merging its children `max_children` at a time first when it has
/// more than one proof can take.
pub fn run_job(job: Job, max_children: usize) -> Result<Produced, AggregationError> {
    let Job {
        data,
        data_root,
        slot,
        mut children,
        raw,
    } = job;
    let epoch = u32::try_from(attestation_epoch(slot)).expect("epoch fits u32");
    let max_children = max_children.clamp(2, MAX_CHILD_PROOFS);

    while children.len() > max_children {
        let mut next = Vec::with_capacity(children.len().div_ceil(max_children));
        let mut rest = children.into_iter().peekable();
        while rest.peek().is_some() {
            let chunk: Vec<Child> = rest.by_ref().take(max_children).collect();
            next.push(merge_children(chunk, &data_root, epoch)?);
        }
        children = next;
    }

    let folded: Vec<u64> = raw.iter().map(|(validator, _, _)| *validator).collect();
    let mut participants: Vec<u64> = children
        .iter()
        .flat_map(|child| child.participants.iter().copied())
        .chain(folded.iter().copied())
        .collect();
    participants.sort_unstable();
    participants.dedup();

    let proof = if raw.is_empty() {
        match children.len() {
            0 => return Err(AggregationError::EmptyInput),
            1 => children.remove(0).proof,
            _ => aggregate_proofs(
                children
                    .into_iter()
                    .map(|child| (child.pubkeys, child.proof))
                    .collect(),
                &data_root,
                epoch,
            )?,
        }
    } else {
        let (raw_pubkeys, raw_signatures) = raw
            .into_iter()
            .map(|(_, pubkey, signature)| (pubkey, signature))
            .unzip();
        aggregate_mixed(
            children
                .into_iter()
                .map(|child| (child.pubkeys, child.proof))
                .collect(),
            raw_pubkeys,
            raw_signatures,
            &data_root,
            epoch,
        )?
    };

    Ok(Produced {
        data_root,
        aggregate: AggregatedDecoupledAttestation {
            data,
            slot,
            participants: bits(&participants),
            proof,
        },
        folded,
    })
}

/// One level of a wide merge: a lone child passes through.
fn merge_children(
    mut chunk: Vec<Child>,
    data_root: &H256,
    epoch: u32,
) -> Result<Child, AggregationError> {
    if chunk.len() == 1 {
        return Ok(chunk.remove(0));
    }
    let mut pubkeys = Vec::new();
    let mut participants = Vec::new();
    let mut inputs = Vec::with_capacity(chunk.len());
    for child in chunk {
        pubkeys.extend(child.pubkeys.iter().cloned());
        participants.extend(child.participants.iter().copied());
        inputs.push((child.pubkeys, child.proof));
    }
    let proof = aggregate_proofs(inputs, data_root, epoch)?;
    Ok(Child {
        pubkeys,
        proof,
        participants,
    })
}

/// A participant bitfield with exactly `participants` set.
pub fn bits(participants: &[u64]) -> AggregationBits {
    let len = participants.iter().max().map_or(0, |max| *max as usize + 1);
    let mut bits = AggregationBits::with_length(len).expect("participants within the registry");
    for &validator in participants {
        bits.set(validator as usize, true)
            .expect("bitfield sized to the highest participant");
    }
    bits
}

/// The attestation keys of `participants`, or `None` when one is out of the
/// registry.
pub fn participant_keys(
    participants: &[u64],
    attestation_keys: &[ValidatorPublicKey],
) -> Option<Vec<ValidatorPublicKey>> {
    participants
        .iter()
        .map(|&validator| attestation_keys.get(validator as usize).cloned())
        .collect()
}

/// Whether `aggregate`'s proof binds its participants to its data at its
/// slot's attestation epoch.
pub fn verify_aggregate(
    aggregate: &AggregatedDecoupledAttestation,
    attestation_keys: &[ValidatorPublicKey],
) -> bool {
    let participants: Vec<u64> = aggregate.participant_indices().collect();
    if participants.is_empty() || !aggregate.data.is_well_formed() {
        return false;
    }
    let Ok(epoch) = u32::try_from(attestation_epoch(aggregate.slot)) else {
        return false;
    };
    let Some(keys) = participant_keys(&participants, attestation_keys) else {
        return false;
    };
    verify_aggregated_signature(
        &aggregate.proof,
        keys,
        &aggregate.data.hash_tree_root(),
        epoch,
    )
    .is_ok()
}

/// An XMSS signature in the crypto crate's type.
pub fn decode_signature(signature: &XmssSignature) -> Option<ValidatorSignature> {
    ValidatorSignature::from_bytes(&signature.to_ssz()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_types::decoupled::HeightVote;

    fn data(height: u64) -> AttestationData {
        AttestationData::new(
            HeightVote {
                height,
                entry: H256::from_slice(&[height as u8; 32]),
                timeout: false,
            },
            None,
        )
    }

    fn aggregate(height: u64, slot: u64, participants: &[u64]) -> AggregatedDecoupledAttestation {
        AggregatedDecoupledAttestation {
            data: data(height),
            slot,
            participants: bits(participants),
            proof: ByteList512KiB::try_from(vec![participants.len() as u8]).unwrap(),
        }
    }

    fn config(subgroups: u64, spacing: Option<u64>, merge: Option<u64>) -> AggregationConfig {
        AggregationConfig {
            subgroups,
            subgroup_spacing_ms: spacing,
            merge_deadline_ms: merge,
            ..AggregationConfig::without_aggregator(4)
        }
    }

    #[test]
    fn the_default_schedule_signs_over_two_deltas_and_merges_a_slot_after_a_r() {
        // Δ = 2000 ms, an 8 s slot.
        let schedule = Schedule::new(&config(4, None, None), 2000);
        let offsets: Vec<u64> = (0..4).map(|g| schedule.sign_offset_ms(g)).collect();
        assert_eq!(offsets, [0, 1000, 2000, 3000]);
        assert_eq!(schedule.final_deadline_ms, 4000);
        assert_eq!(schedule.merge_deadline_ms, 8000);
    }

    #[test]
    fn a_merge_deadline_never_precedes_the_final_one() {
        let schedule = Schedule::new(&config(4, Some(500), Some(100)), 2000);
        assert_eq!(schedule.final_deadline_ms, 2500);
        assert_eq!(schedule.merge_deadline_ms, 2500);
    }

    #[test]
    fn validators_on_counts_the_uneven_subnets() {
        // 10 validators on 4 subnets: 3, 3, 2, 2.
        let subnets = HashSet::from([0, 3]);
        assert_eq!(validators_on(&subnets, 10, 4), 5);
        assert_eq!(populated_subnets(3, 4), HashSet::from([0, 1, 2]));
    }

    #[test]
    fn the_raw_pool_counts_and_batches_only_unfolded_signers() {
        let mut pool = RawPool::default();
        let signature =
            XmssSignature::try_from(vec![0u8; ethlambda_types::attestation::SIGNATURE_SIZE])
                .unwrap();
        for validator in 0..4 {
            pool.insert(&data(1), 7, validator, signature.clone());
        }
        pool.insert(&data(2), 7, 9, signature.clone());
        pool.insert(&data(1), 6, 5, signature.clone());
        let folded = HashSet::from([0, 1]);
        assert_eq!(pool.pending(7, &folded), 3);
        let batch = pool.batch(7, &folded);
        let sizes: HashSet<usize> = batch.iter().map(|p| p.signatures.len()).collect();
        assert_eq!(sizes, HashSet::from([2, 1]));
        pool.remove(data(1).hash_tree_root(), 7, &[2, 3]);
        assert_eq!(pool.pending(7, &folded), 1);
        pool.prune(7);
        assert_eq!(pool.len(), 3);
    }

    #[test]
    fn merging_takes_disjoint_proofs_and_skips_a_data_already_merged() {
        let mut pool = AggregatePool::default();
        // Two aggregators on subnet {0, 4}, one on {1, 5}, at four subnets.
        assert!(pool.insert(aggregate(1, 3, &[0, 4])));
        assert!(pool.insert(aggregate(1, 3, &[0])));
        assert!(pool.insert(aggregate(1, 3, &[1, 5])));
        assert!(!pool.insert(aggregate(1, 3, &[1, 5])), "same participants");
        assert_eq!(pool.covered_subnets(3, 4), HashSet::from([0, 1]));

        let inputs = pool.merge_inputs(3);
        assert_eq!(inputs.len(), 1);
        let chosen: Vec<&Vec<u64>> = inputs[0].2.iter().map(|held| &held.participants).collect();
        assert_eq!(chosen, [&vec![0, 4], &vec![1, 5]]);

        // Once someone's merge covers them all, there is nothing left to do.
        pool.insert(aggregate(1, 3, &[0, 1, 4, 5]));
        assert!(pool.merge_inputs(3).is_empty());
    }

    #[test]
    fn packing_prefers_the_widest_proof_and_skips_this_slots() {
        let mut pool = AggregatePool::default();
        pool.insert(aggregate(1, 3, &[0, 4]));
        pool.insert(aggregate(1, 3, &[0, 1, 4, 5]));
        pool.insert(aggregate(1, 5, &[2, 6]));
        let selected: Vec<Attestation> = [0, 1, 2, 4, 5, 6]
            .into_iter()
            .map(|validator| Attestation {
                validator,
                data: data(1),
            })
            .collect();
        let packed = pool.pack(&selected, 5, 16);
        assert_eq!(
            packed.len(),
            1,
            "slot 5's proof is not includable at slot 5"
        );
        assert_eq!(
            packed[0].participant_indices().collect::<Vec<_>>(),
            [0, 1, 4, 5]
        );
        assert_eq!(pool.pack(&selected, 6, 16).len(), 2);
        assert_eq!(pool.pack(&selected, 6, 1).len(), 1, "capped");
    }

    /// Two subnets of four validators: one aggregator folds its subnet in two
    /// batches (the second taking the first as a child), the other subnet
    /// comes as two halves, and a merge two children at a time joins all
    /// three into one proof that verifies as the node checks it.
    #[test]
    #[ignore = "slow: real leanVM proofs"]
    fn batches_chain_and_merge_into_one_verifiable_proof() {
        use ethlambda_crypto::signature::ValidatorSecretKey;

        ethlambda_crypto::init_leanvm(false);
        let slot = 5;
        let epoch = attestation_epoch(slot) as u32;
        let data = data(1);
        let data_root = data.hash_tree_root();
        let secret_keys: Vec<ValidatorSecretKey> = (0..8u8)
            .map(|seed| ValidatorSecretKey::generate_from_seed([seed + 1; 32], 0..=31).unwrap())
            .collect();
        let keys: Vec<ValidatorPublicKey> = secret_keys
            .iter()
            .map(ValidatorSecretKey::public_key)
            .collect();
        let raw = |validators: &[u64]| {
            validators
                .iter()
                .map(|&v| {
                    let signature = secret_keys[v as usize].sign(epoch, &data_root).unwrap();
                    (v, keys[v as usize].clone(), signature)
                })
                .collect()
        };
        let child = |aggregate: &AggregatedDecoupledAttestation| {
            let participants: Vec<u64> = aggregate.participant_indices().collect();
            Child {
                pubkeys: participant_keys(&participants, &keys).unwrap(),
                proof: aggregate.proof.clone(),
                participants,
            }
        };
        let job = |children: Vec<Child>, raw| Job {
            data: data.clone(),
            data_root,
            slot,
            children,
            raw,
        };

        let first = run_job(job(vec![], raw(&[0, 2])), 16).unwrap();
        let subnet_0 = run_job(job(vec![child(&first.aggregate)], raw(&[4, 6])), 16).unwrap();
        assert_eq!(subnet_0.folded, [4, 6]);
        assert!(verify_aggregate(&subnet_0.aggregate, &keys));

        let half_a = run_job(job(vec![], raw(&[1, 3])), 16).unwrap();
        let half_b = run_job(job(vec![], raw(&[5, 7])), 16).unwrap();
        let children = vec![
            child(&subnet_0.aggregate),
            child(&half_a.aggregate),
            child(&half_b.aggregate),
        ];
        let merged = run_job(job(children, vec![]), 2).unwrap();
        assert_eq!(
            merged.aggregate.participant_indices().collect::<Vec<_>>(),
            (0..8).collect::<Vec<_>>()
        );
        assert!(verify_aggregate(&merged.aggregate, &keys));

        let mut moved = merged.aggregate.clone();
        moved.slot += 1;
        assert!(
            !verify_aggregate(&moved, &keys),
            "the proof binds its epoch"
        );
    }
}
