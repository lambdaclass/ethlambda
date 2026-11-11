//! Assembling an EIP-8453 block from the fork choice's proposal.
//!
//! The pieces a proposer needs beyond the engine's `get_ac_proposal`
//! ([`crate::beacon::eip8453_node::Eip8453Proposal`]): the pooled single
//! attestations aggregated into the body's `Attestation`s, keeping only those
//! `process_attestation` accepts on the block's pre-state
//! ([`pack_attestations`]), and the unsigned block with its post-state root
//! ([`assemble_block`]). The Beacon API's block production endpoint and the
//! in-process network test build on these; signing is the caller's.

use std::collections::BTreeMap;
use std::ops::Range;

use crate::beacon::config::Config;
use crate::beacon::containers::{BeaconState, SignedBeaconBlock, eip8453, gloas};
use crate::beacon::error::Result;
use crate::beacon::helpers::accessors::{
    ActiveBalanceCache, CommitteeCache, get_beacon_proposer_index,
};
use crate::beacon::helpers::eip8453::get_attestation_committee;
use crate::beacon::preset;
use crate::beacon::primitives::{BlsSignature, Epoch, Root, Slot, ValidatorIndex};
use crate::beacon::stf::{self, ExecutionEngine, block::BlockProcessingOptions};

/// Aggregate single attestations into the body's `Attestation`s: per
/// `(data, epoch)`, over the committees its attesters sit in, split into as
/// few aggregates as `MAX_VALIDATORS_PER_AGGREGATE` allows, and keep the ones
/// `process_attestation` accepts on `state` (the block's pre-state, advanced
/// to its slot), in that order, up to `MAX_ATTESTATIONS_ELECTRA`.
///
/// The bound counts every member of the committees an aggregate names, not
/// only its signers (`is_valid_aggregation_bits`), and one round's committees
/// already hold the whole active set, so the most common data would otherwise
/// span more than one aggregate may.
pub fn pack_attestations<'a>(
    state: &BeaconState,
    pool: impl IntoIterator<Item = &'a eip8453::SingleAttestation>,
) -> Vec<eip8453::Attestation> {
    // (epoch, data) -> committee -> attester -> signature
    type Signers = BTreeMap<u64, BTreeMap<u64, BlsSignature>>;
    let mut groups: BTreeMap<(Epoch, [u8; 81]), (eip8453::AttestationData, Signers)> =
        BTreeMap::new();
    for attestation in pool {
        let key = (attestation.epoch, attestation_key(&attestation.data));
        let (_, signers) = groups
            .entry(key)
            .or_insert_with(|| (attestation.data, BTreeMap::new()));
        signers
            .entry(attestation.committee_index)
            .or_default()
            .insert(attestation.attester_index, attestation.signature);
    }
    let mut scratch = state.clone();
    let mut packed = Vec::new();
    for ((epoch, _), (data, signers)) in groups {
        let committees: Option<Vec<(u64, Vec<ValidatorIndex>)>> = signers
            .keys()
            .map(|&index| {
                let committee = get_attestation_committee(state, epoch, index).ok()?;
                Some((index, committee.to_vec()))
            })
            .collect();
        let Some(committees) = committees else {
            continue;
        };
        let sizes: Vec<u64> = committees
            .iter()
            .map(|(_, members)| members.len() as u64)
            .collect();
        for run in aggregate_runs(&sizes, preset::MAX_VALIDATORS_PER_AGGREGATE) {
            let Some(attestation) = aggregate(epoch, data, &committees[run], &signers) else {
                continue;
            };
            if stf::eip8453::process_attestation(&mut scratch, &attestation).is_ok() {
                packed.push(attestation);
                if packed.len() == preset::MAX_ATTESTATIONS_ELECTRA {
                    return packed;
                }
            }
        }
    }
    packed
}

/// Consecutive runs of committees, given their sizes in committee index
/// order, each holding at most `limit` members in all: the aggregates one
/// `(data, epoch)` is split into (validator.md's "Split messages into
/// separate aggregates when the bound would be exceeded"). A committee larger
/// than `limit` fits no aggregate and is in no run.
fn aggregate_runs(sizes: &[u64], limit: u64) -> Vec<Range<usize>> {
    let mut runs = Vec::new();
    let mut start = 0;
    let mut total: u64 = 0;
    for (position, &size) in sizes.iter().enumerate() {
        if size > limit {
            if start < position {
                runs.push(start..position);
            }
            start = position + 1;
            total = 0;
            continue;
        }
        // `total <= limit` and `size <= limit`, so the sum cannot overflow.
        if total + size > limit {
            runs.push(start..position);
            start = position;
            total = 0;
        }
        total += size;
    }
    if start < sizes.len() {
        runs.push(start..sizes.len());
    }
    runs
}

/// The SSZ bytes of `data`, a total order to group by.
fn attestation_key(data: &eip8453::AttestationData) -> [u8; 81] {
    let bytes = libssz::SszEncode::to_ssz(data);
    let mut key = [0u8; 81];
    key.copy_from_slice(&bytes[..81]);
    key
}

/// One `Attestation` of `data` for `epoch` over `committees` (index and
/// members, ascending), from their attesters in `signers`: `committee_bits`
/// names the committees, `aggregation_bits` marks the attesters in the
/// committees' concatenation.
fn aggregate(
    epoch: Epoch,
    data: eip8453::AttestationData,
    committees: &[(u64, Vec<ValidatorIndex>)],
    signers: &BTreeMap<u64, BTreeMap<u64, BlsSignature>>,
) -> Option<eip8453::Attestation> {
    let mut committee_bits = eip8453::AttestationCommitteeBits::new();
    let mut bits = Vec::new();
    let mut signatures = Vec::new();
    for (committee_index, committee) in committees {
        let attesters = signers.get(committee_index)?;
        committee_bits.set(*committee_index as usize, true).ok()?;
        for member in committee {
            match attesters.get(member) {
                Some(signature) => {
                    bits.push(true);
                    signatures.push(*signature);
                }
                None => bits.push(false),
            }
        }
    }
    if signatures.is_empty() {
        return None;
    }
    let mut aggregation_bits = eip8453::AggregationBits::with_length(bits.len());
    for (position, bit) in bits.into_iter().enumerate() {
        if bit {
            aggregation_bits.set(position, true).ok()?;
        }
    }
    Some(eip8453::Attestation {
        aggregation_bits,
        data,
        signature: crate::beacon::bls::aggregate(&signatures).ok()?,
        committee_bits,
        epoch,
    })
}

/// The unsigned EIP-8453 block at `slot` on `parent_root`, whose post-state
/// is `pre_state` (the parent's post-state) advanced to `slot` and run through
/// the block, and the post-state's root in `state_root`. Errors with the state
/// transition's own error when the body does not apply.
#[allow(clippy::too_many_arguments)]
pub fn assemble_block(
    pre_state: &BeaconState,
    parent_root: Root,
    slot: Slot,
    randao_reveal: BlsSignature,
    signed_execution_payload_bid: gloas::SignedExecutionPayloadBid,
    head_votes: Vec<eip8453::HeadVote>,
    head_vote_support: Vec<eip8453::HeadVoteSupportBits>,
    attestations: Vec<eip8453::Attestation>,
    config: &Config,
) -> Result<(eip8453::BeaconBlock, BeaconState)> {
    let mut state = pre_state.clone();
    if state.slot() < slot {
        stf::process_slots(&mut state, slot, config)?;
    }
    let mut body = eip8453::BeaconBlockBody::empty();
    body.randao_reveal = randao_reveal;
    body.signed_execution_payload_bid = signed_execution_payload_bid;
    body.head_votes = head_votes.into();
    body.head_vote_support = head_vote_support.into();
    body.attestations = attestations.into();
    body.sync_aggregate.sync_committee_signature =
        BlsSignature(crate::beacon::bls::G2_POINT_AT_INFINITY);
    let mut block = eip8453::BeaconBlock {
        slot,
        proposer_index: get_beacon_proposer_index(&state)?,
        parent_root,
        state_root: Root::ZERO,
        body,
    };
    let unsigned = SignedBeaconBlock::Eip8453(eip8453::SignedBeaconBlock {
        message: block.clone(),
        signature: BlsSignature::default(),
    });
    stf::block::process_block(
        &mut state,
        &unsigned,
        config,
        &ExecutionEngine::valid(),
        &CommitteeCache::default(),
        &ActiveBalanceCache::default(),
        BlockProcessingOptions::default(),
    )?;
    state.apply_pending_mutations();
    block.state_root = state.hash_tree_root();
    Ok((block, state))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::beacon::constants::DOMAIN_FINALITY_ATTESTER;
    use crate::beacon::fork::ForkName;
    use crate::beacon::helpers::accessors::{get_current_epoch, get_domain};
    use crate::beacon::helpers::eip8453::{
        eip8453_state, get_attesting_indices, is_valid_aggregation_bits,
    };
    use crate::beacon::helpers::misc::compute_signing_root;
    use crate::beacon::helpers::test_state;
    use crate::beacon::primitives::HashTreeRoot as _;

    /// More validators than one aggregate may cover, every one voting for the
    /// current target in the same epoch: the votes are split over several
    /// aggregates that `process_attestation` accepts, together covering every
    /// voter, rather than one aggregate it refuses (`is_valid_aggregation_bits`
    /// counts every member of the named committees). Needs
    /// `MAX_VALIDATORS_PER_AGGREGATE` signing validators, which only the
    /// minimal preset (512) keeps small; mainnet's is 131,072.
    #[test]
    #[cfg_attr(
        not(feature = "preset-minimal"),
        ignore = "needs more validators than MAX_VALIDATORS_PER_AGGREGATE, 131,072 on mainnet"
    )]
    fn pack_attestations_splits_a_vote_larger_than_one_aggregate() {
        let committees = preset::ATTESTATION_COMMITTEES_PER_ROUND as u64;
        let count = (preset::MAX_VALIDATORS_PER_AGGREGATE + committees) as usize;
        let config = Config::active().with_fork_epoch(ForkName::Eip8453, 1);
        let mut state = test_state::with_signing_validators_at(ForkName::Eip8453, count);
        let slot = state.slot() + 1;
        stf::process_slots(&mut state, slot, &config).unwrap();

        let epoch = get_current_epoch(&state);
        let data = eip8453::AttestationData {
            target: eip8453_state(&state, "test").unwrap().target_checkpoint,
            timeout: false,
            finality: eip8453::HeightCheckpoint::empty(),
        };
        let domain = get_domain(&state, DOMAIN_FINALITY_ATTESTER, Some(epoch));
        let signing_root = compute_signing_root(data.hash_tree_root(), domain);
        let mut pool = Vec::new();
        for committee_index in 0..committees {
            let committee = get_attestation_committee(&state, epoch, committee_index).unwrap();
            for &attester_index in committee.iter() {
                pool.push(eip8453::SingleAttestation {
                    committee_index,
                    attester_index,
                    data,
                    signature: test_state::sign_for(attester_index as usize, signing_root),
                    epoch,
                });
            }
        }
        assert_eq!(pool.len(), count);

        let packed = pack_attestations(&state, &pool);
        assert!(!packed.is_empty(), "the vote is packed");
        let mut covered = BTreeSet::new();
        for attestation in &packed {
            assert!(is_valid_aggregation_bits(&state, epoch, attestation).unwrap());
            covered.extend(get_attesting_indices(&state, attestation).unwrap());
        }
        assert_eq!(covered.len(), count, "every voter is in some aggregate");

        // The block carrying them records every target vote.
        for attestation in &packed {
            stf::eip8453::process_attestation(&mut state, attestation).unwrap();
        }
        let inner = eip8453_state(&state, "test").unwrap();
        assert!(inner.target_participation.iter().all(|&voted| voted));
    }

    #[test]
    fn aggregate_runs_fill_each_aggregate_up_to_the_limit() {
        let none: Vec<Range<usize>> = Vec::new();
        assert_eq!(aggregate_runs(&[], 10), none);
        assert_eq!(aggregate_runs(&[4, 4, 4], 10), vec![0..2, 2..3]);
        assert_eq!(aggregate_runs(&[5, 5, 5, 5], 10), vec![0..2, 2..4]);
        assert_eq!(aggregate_runs(&[0, 10, 0], 10), vec![0..3]);
        // A committee larger than the limit is in no run; its neighbours are.
        assert_eq!(aggregate_runs(&[3, 11, 3, 3], 10), vec![0..1, 2..4]);
        assert_eq!(aggregate_runs(&[11], 10), none);

        // A whole round's committees at this preset, holding twice the limit:
        // every committee lands in exactly one run, none over the limit.
        let committees = preset::ATTESTATION_COMMITTEES_PER_ROUND;
        let limit = preset::MAX_VALIDATORS_PER_AGGREGATE;
        let size = 2 * limit / committees as u64 + 1;
        let sizes = vec![size; committees];
        let runs = aggregate_runs(&sizes, limit);
        assert!(runs.len() > 1);
        assert_eq!(runs.first().unwrap().start, 0);
        assert_eq!(runs.last().unwrap().end, committees);
        for pair in runs.windows(2) {
            assert_eq!(pair[0].end, pair[1].start);
        }
        for run in runs {
            assert!(sizes[run].iter().sum::<u64>() <= limit);
        }
    }
}
