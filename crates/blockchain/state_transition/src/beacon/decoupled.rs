//! The `decoupled` fork's state transition: fulu's, with the protocol's votes
//! carried in the block body and checked here, and none of the Casper FFG
//! machinery run.
//!
//! The protocol's chain state σ is *not* part of the beacon state (see
//! [`crate::beacon::containers::decoupled`]): every node derives it from block
//! contents with `ethlambda-decoupled`. What this module owns is everything
//! the beacon chain has to settle before the engine may look at a block:
//!
//! * the block shape ([`process_decoupled_body`]): no LMD attestations or
//!   attester slashings, and every vote aggregate well formed and correctly
//!   signed;
//! * expanding aggregates into the engine's per-validator objects
//!   ([`goldfish_votes_of`], [`attestations_of`], [`block_input`]);
//! * the committee a Goldfish vote refers to ([`slot_committee`]);
//! * the fork boundary ([`upgrade_to_decoupled`]) and the epoch step list
//!   ([`process_epoch`]).
//!
//! The FFG fields of the state (`current_justified_checkpoint`,
//! `finalized_checkpoint`, `justification_bits`, participation flags) stay at
//! their fork-boundary values: nothing in this fork updates them. Registry
//! updates still key activation off the frozen `finalized_checkpoint`, which
//! is accepted.

use ethlambda_decoupled::{BlockInput, Params};
use ethlambda_types::decoupled::{Attestation, GoldfishVote};
use libssz_types::{SszBitlist, SszList};

use crate::beacon::bls;
use crate::beacon::config::Config;
use crate::beacon::constants;
use crate::beacon::containers::decoupled::{
    BeaconBlock, CombinedAttestationAggregate, GoldfishVoteAggregate,
    MAX_COMBINED_ATTESTATION_AGGREGATES, MAX_GOLDFISH_VOTE_AGGREGATES, SignedBeaconBlock,
};
use crate::beacon::containers::shared::Fork;
use crate::beacon::containers::{BeaconState, fulu};
use crate::beacon::error::{Error, Result, verify};
use crate::beacon::helpers::accessors::{
    ActiveBalanceCache, CommitteeCache, CommitteeCacheExt, get_domain_from_schedule,
};
use crate::beacon::helpers::misc::{compute_epoch_at_slot, compute_signing_root};
use crate::beacon::primitives::{HashTreeRoot as _, Slot, ValidatorIndex};
use crate::beacon::stf::ExecutionEngine;

/// The protocol's parameters, read from the five `DECOUPLED_*` config keys.
pub fn params(config: &Config) -> Params {
    Params {
        slots_per_round: config.decoupled_slots_per_round,
        eta_sg: config.decoupled_sg_window,
        k: config.decoupled_nonjustifiable_period,
        d: config.decoupled_finality_debt,
        timeout_delay: config.decoupled_timeout_delay,
    }
}

/// The protocol fields a proposer supplies for a decoupled block body: what
/// [`BeaconBlockBody::from_electra`](crate::beacon::containers::decoupled::BeaconBlockBody::from_electra)
/// leaves empty.
#[derive(Debug, Clone, Default)]
pub struct DecoupledBodyFields {
    pub goldfish_votes: SszList<GoldfishVoteAggregate, MAX_GOLDFISH_VOTE_AGGREGATES>,
    pub goldfish_support: SszBitlist<MAX_GOLDFISH_VOTE_AGGREGATES>,
    pub combined_attestations:
        SszList<CombinedAttestationAggregate, MAX_COMBINED_ATTESTATION_AGGREGATES>,
}

/// `𝒦_s`: the members of slot `slot`'s committee, as the beacon committees of
/// that slot concatenated in committee-index order (electra's whole-slot
/// attestation layout, which a Goldfish aggregate's bits index).
///
/// `state` must be able to derive the shuffling of `slot`'s epoch: any state
/// within the epoch of `slot` or the epoch after it does, which covers the
/// pre-state of a block at `slot + 1` advanced to its slot.
pub fn slot_committee(
    state: &BeaconState,
    slot: Slot,
    committees: &CommitteeCache,
) -> Result<Vec<ValidatorIndex>> {
    let epoch = compute_epoch_at_slot(slot);
    let epoch_committees = committees.committees(state, epoch);
    let mut members = Vec::new();
    for index in 0..epoch_committees.committees_per_slot() {
        members.extend_from_slice(epoch_committees.committee(slot, index)?);
    }
    Ok(members)
}

/// Fulu's state with its `fork` moved to the decoupled version.
///
/// Nothing else changes: the state container is shared, and σ lives outside
/// it. `epoch` is the epoch of the state's slot, which at a fork boundary is
/// `decoupled_fork_epoch`.
pub fn upgrade_to_decoupled(mut state: fulu::BeaconState, config: &Config) -> fulu::BeaconState {
    state.fork = Fork {
        previous_version: state.fork.current_version,
        current_version: config.decoupled_fork_version,
        epoch: compute_epoch_at_slot(state.slot),
    };
    state
}

/// Decoupled's block processing: fulu's, on the body's electra fields, then
/// [`process_decoupled_body`].
///
/// The header's `body_root` is the decoupled body's own tree root, not the
/// electra view's; the electra view is a clone, which costs one payload copy
/// per block.
pub fn process_block(
    state: &mut BeaconState,
    block: &BeaconBlock,
    config: &Config,
    engine: &ExecutionEngine,
    committees: &CommitteeCache,
    active_balances: &ActiveBalanceCache,
    verify_signatures: bool,
) -> Result<()> {
    // Cheapest checks first: a block carrying LMD operations is refused
    // before any state is touched.
    check_no_legacy_operations(block)?;
    let electra_body = block.body.to_electra();
    crate::beacon::stf::fulu::process_block_with_body_root(
        state,
        block.slot,
        block.proposer_index,
        block.parent_root,
        block.body.hash_tree_root(),
        &electra_body,
        config,
        engine,
        committees,
        active_balances,
    )?;
    process_decoupled_body(state, block, config, committees, verify_signatures)
}

fn check_no_legacy_operations(block: &BeaconBlock) -> Result<()> {
    if !block.body.attestations.is_empty() {
        return Err(Error::DecoupledLegacyOperations("attestations"));
    }
    if !block.body.attester_slashings.is_empty() {
        return Err(Error::DecoupledLegacyOperations("attester_slashings"));
    }
    Ok(())
}

/// The checks on the protocol fields of a decoupled block body. Changes no
/// state.
///
/// `state` is the block's state at the block's slot (after `process_slots`,
/// before or after the block's own operations: nothing here reads what a block
/// changes). With `verify_signatures` false the BLS checks are skipped, as the
/// proposer signature is for blocks verified elsewhere; every structural check
/// still runs.
pub fn process_decoupled_body(
    state: &BeaconState,
    block: &BeaconBlock,
    config: &Config,
    committees: &CommitteeCache,
    verify_signatures: bool,
) -> Result<()> {
    let body = &block.body;
    check_no_legacy_operations(block)?;
    verify(
        body.goldfish_support.len() == body.goldfish_votes.len(),
        "len(body.goldfish_support) == len(body.goldfish_votes)",
    )?;

    let params = params(config);
    verify(
        params.validate().is_ok(),
        "the decoupled protocol parameters are valid",
    )?;

    for aggregate in body.goldfish_votes.iter() {
        let data = &aggregate.data;
        verify(
            data.slot.checked_add(1) == Some(block.slot),
            "goldfish vote slot + 1 == block.slot",
        )?;
        let committee = slot_committee(state, data.slot, committees)?;
        if aggregate.aggregation_bits.len() != committee.len() {
            return Err(Error::InvalidDecoupledVote(
                "goldfish aggregation_bits length != slot committee size",
            ));
        }
        let signers = set_members(&aggregate.aggregation_bits, |bit| committee[bit]);
        if signers.is_empty() {
            return Err(Error::InvalidDecoupledVote(
                "goldfish aggregate has no bit set",
            ));
        }
        if verify_signatures {
            let domain = get_domain_from_schedule(
                config,
                state,
                constants::DOMAIN_GOLDFISH_VOTE,
                compute_epoch_at_slot(data.slot),
            );
            verify_aggregate(
                state,
                &signers,
                compute_signing_root(data.hash_tree_root(), domain),
                &aggregate.signature,
                "goldfish vote aggregate",
            )?;
        }
    }

    let current_round = params.round_of(block.slot);
    let validator_count = state.validator_count();
    for aggregate in body.combined_attestations.iter() {
        let data = &aggregate.data;
        verify(
            data.round <= current_round,
            "combined attestation round <= round(block.slot)",
        )?;
        if aggregate.aggregation_bits.len() != validator_count {
            return Err(Error::InvalidDecoupledVote(
                "combined aggregation_bits length != validator count",
            ));
        }
        let signers = set_members(&aggregate.aggregation_bits, |bit| bit as ValidatorIndex);
        if signers.is_empty() {
            return Err(Error::InvalidDecoupledVote(
                "combined attestation aggregate has no bit set",
            ));
        }
        if verify_signatures {
            let domain = get_domain_from_schedule(
                config,
                state,
                constants::DOMAIN_COMBINED_ATTESTATION,
                compute_epoch_at_slot(params.opening_slot(data.round)),
            );
            verify_aggregate(
                state,
                &signers,
                compute_signing_root(data.hash_tree_root(), domain),
                &aggregate.signature,
                "combined attestation aggregate",
            )?;
        }
    }
    Ok(())
}

/// The validators named by the set bits of `bits`, mapping a bit position to
/// its validator with `member`.
fn set_members<const N: usize>(
    bits: &SszBitlist<N>,
    member: impl Fn(usize) -> ValidatorIndex,
) -> Vec<ValidatorIndex> {
    (0..bits.len())
        .filter(|&bit| bits.get(bit).unwrap_or(false))
        .map(member)
        .collect()
}

fn verify_aggregate(
    state: &BeaconState,
    signers: &[ValidatorIndex],
    signing_root: crate::beacon::primitives::Root,
    signature: &crate::beacon::primitives::BlsSignature,
    what: &'static str,
) -> Result<()> {
    let pubkeys = signers
        .iter()
        .map(|&index| state.validator(index).map(|validator| validator.pubkey))
        .collect::<Result<Vec<_>>>()?;
    if bls::fast_aggregate_verify(&pubkeys, signing_root, signature) {
        Ok(())
    } else {
        Err(Error::InvalidSignature(what))
    }
}

/// The per-validator Goldfish votes an aggregate stands for, in committee
/// order. `state` must satisfy [`slot_committee`]'s requirement for the
/// aggregate's slot.
pub fn goldfish_votes_of(
    state: &BeaconState,
    aggregate: &GoldfishVoteAggregate,
    committees: &CommitteeCache,
) -> Result<Vec<GoldfishVote>> {
    let data = &aggregate.data;
    let committee = slot_committee(state, data.slot, committees)?;
    if aggregate.aggregation_bits.len() != committee.len() {
        return Err(Error::InvalidDecoupledVote(
            "goldfish aggregation_bits length != slot committee size",
        ));
    }
    Ok(
        set_members(&aggregate.aggregation_bits, |bit| committee[bit])
            .into_iter()
            .map(|validator| GoldfishVote {
                validator,
                slot: data.slot,
                head: data.head,
            })
            .collect(),
    )
}

/// The per-validator combined attestations an aggregate stands for, in
/// validator order.
pub fn attestations_of(aggregate: &CombinedAttestationAggregate) -> Vec<Attestation> {
    set_members(&aggregate.aggregation_bits, |bit| bit as ValidatorIndex)
        .into_iter()
        .map(|validator| Attestation {
            validator,
            data: aggregate.data.clone(),
        })
        .collect()
}

/// The engine's view of a decoupled block.
///
/// `state` supplies the committee of slot `block.slot - 1`. The block's
/// pre-state advanced to its slot works, and so does its post-state: neither
/// can differ in the shuffling of that slot's epoch, since activations and
/// exits land at least `MAX_SEED_LOOKAHEAD` epochs out. The goldfish votes
/// are `goldfish_votes` expanded; `support_votes` are those of the aggregates
/// whose `goldfish_support` bit is set; attestations are every combined
/// aggregate expanded. `_config` is accepted for symmetry with the other
/// entry points: nothing here depends on the protocol parameters.
pub fn block_input(
    state: &BeaconState,
    signed_block: &SignedBeaconBlock,
    committees: &CommitteeCache,
    _config: &Config,
) -> Result<BlockInput> {
    let block = &signed_block.message;
    let body = &block.body;
    verify(
        body.goldfish_support.len() == body.goldfish_votes.len(),
        "len(body.goldfish_support) == len(body.goldfish_votes)",
    )?;

    let mut votes = Vec::new();
    let mut support_votes = Vec::new();
    for (index, aggregate) in body.goldfish_votes.iter().enumerate() {
        let expanded = goldfish_votes_of(state, aggregate, committees)?;
        if body.goldfish_support.get(index).unwrap_or(false) {
            support_votes.extend(expanded.iter().cloned());
        }
        votes.extend(expanded);
    }
    let attestations = body
        .combined_attestations
        .iter()
        .flat_map(attestations_of)
        .collect();

    Ok(BlockInput {
        root: block.hash_tree_root(),
        parent_root: block.parent_root,
        slot: block.slot,
        proposer: block.proposer_index,
        votes,
        support_votes,
        attestations,
    })
}

/// Decoupled's epoch-boundary driver: fulu's steps except justification and
/// finalization, inactivity updates and rewards and penalties.
///
/// A step list of its own rather than a flag on fulu's fused registry pass:
/// the pass fuses the three steps this fork drops with the ones it keeps, and
/// no participation exists here to account for. The kept steps are the
/// specification's, in its order: registry updates, slashings, eth1 reset,
/// pending deposits (fulu's), pending consolidations, effective balances,
/// slashings reset, randao reset, historical summaries, participation flag
/// rotation, sync committee updates and the proposer lookahead.
pub fn process_epoch(state: &mut BeaconState, config: &Config) -> Result<()> {
    use crate::beacon::stf::epoch;

    epoch::electra::process_registry_updates(state, config)?;
    epoch::electra::process_slashings(state, config)?;
    epoch::process_eth1_data_reset(state)?;
    epoch::fulu::process_pending_deposits(state, config)?;
    epoch::electra::process_pending_consolidations(state, config)?;
    epoch::electra::process_effective_balance_updates(state)?;
    epoch::process_slashings_reset(state)?;
    epoch::process_randao_mixes_reset(state)?;
    epoch::capella::process_historical_summaries_update(state)?;
    epoch::altair::process_participation_flag_updates(state)?;
    epoch::altair::process_sync_committee_updates(state)?;
    epoch::fulu::process_proposer_lookahead(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::containers::bellatrix::LogsBloom;
    use crate::beacon::containers::decoupled::{BeaconBlockBody, GoldfishVoteData};
    use crate::beacon::containers::{deneb, electra};
    use crate::beacon::fork::ForkName;
    use crate::beacon::helpers::accessors::{
        get_beacon_proposer_index, get_current_epoch, get_domain, get_randao_mix,
    };
    use crate::beacon::helpers::test_state::{sign_for, with_signing_validators_at};
    use crate::beacon::preset;
    use crate::beacon::primitives::{
        BlsSignature, Bytes32, ExecutionAddress, ExecutionBlockHash, Root, Uint256,
    };
    use ethlambda_types::decoupled::AttestationData;

    const VALIDATORS: usize = 64;

    fn config() -> Config {
        Config::mainnet().with_fork_epoch(ForkName::Decoupled, 0)
    }

    /// A decoupled state at the first slot of epoch 1 with real, distinct keys,
    /// its proposer lookahead and sync committees filled from the registry.
    fn decoupled_state() -> BeaconState {
        let mut state = with_signing_validators_at(ForkName::Fulu, VALIDATORS);
        let lookahead =
            crate::beacon::helpers::fulu::initialize_proposer_lookahead(&state).unwrap();
        let committee = crate::beacon::helpers::altair::get_next_sync_committee(&state).unwrap();
        let BeaconState::Fulu(inner) = &mut state else {
            unreachable!("built as fulu")
        };
        inner.proposer_lookahead = lookahead.try_into().unwrap();
        inner.current_sync_committee = committee.clone();
        inner.next_sync_committee = committee;
        let BeaconState::Fulu(inner) = state else {
            unreachable!("built as fulu")
        };
        BeaconState::Decoupled(upgrade_to_decoupled(inner, &config()))
    }

    /// The G2 point at infinity, the only signature an empty sync aggregate
    /// verifies under.
    fn infinity_signature() -> BlsSignature {
        let mut bytes = [0u8; 96];
        bytes[0] = 0b1100_0000;
        BlsSignature(bytes)
    }

    /// An empty decoupled block on `state`'s slot, with a valid randao reveal
    /// and payload, ready to be amended.
    fn empty_block(state: &BeaconState, config: &Config) -> BeaconBlock {
        let proposer = get_beacon_proposer_index(state).unwrap();
        let epoch = get_current_epoch(state);
        let domain = get_domain(state, constants::DOMAIN_RANDAO, None);
        let randao_root = compute_signing_root(epoch.hash_tree_root(), domain);
        // `with_validators_at` leaves the payload header all-zero.
        let parent_hash = ExecutionBlockHash::ZERO;

        let payload = deneb::ExecutionPayload {
            parent_hash,
            fee_recipient: ExecutionAddress::ZERO,
            state_root: Bytes32::ZERO,
            receipts_root: Bytes32::ZERO,
            logs_bloom: LogsBloom::try_from(vec![0u8; preset::BYTES_PER_LOGS_BLOOM]).unwrap(),
            prev_randao: get_randao_mix(state, epoch),
            block_number: 0,
            gas_limit: 0,
            gas_used: 0,
            timestamp: crate::beacon::stf::bellatrix::compute_timestamp_at_slot(
                state,
                state.slot(),
                config,
            ),
            extra_data: Default::default(),
            base_fee_per_gas: Uint256::ZERO,
            block_hash: ExecutionBlockHash::repeat_byte(0xcd),
            transactions: Default::default(),
            withdrawals: Default::default(),
            blob_gas_used: 0,
            excess_blob_gas: 0,
        };
        let mut electra_body = electra::BeaconBlockBody::empty();
        electra_body.randao_reveal = sign_for(proposer as usize, randao_root);
        electra_body.execution_payload = payload;
        electra_body.sync_aggregate.sync_committee_signature = infinity_signature();

        BeaconBlock {
            slot: state.slot(),
            proposer_index: proposer,
            parent_root: state.latest_block_header().hash_tree_root(),
            state_root: Root::ZERO,
            body: BeaconBlockBody::from_electra(electra_body),
        }
    }

    fn engine() -> ExecutionEngine {
        ExecutionEngine::valid()
    }

    fn apply(state: &mut BeaconState, block: &BeaconBlock, verify_signatures: bool) -> Result<()> {
        process_block(
            state,
            block,
            &config(),
            &engine(),
            &CommitteeCache::default(),
            &ActiveBalanceCache::default(),
            verify_signatures,
        )
    }

    fn bits<const N: usize>(len: usize, set: &[usize]) -> SszBitlist<N> {
        let mut bits = SszBitlist::<N>::with_length(len).unwrap();
        for &bit in set {
            bits.set(bit, true).unwrap();
        }
        bits
    }

    /// A goldfish aggregate of `slot` signed by the first `signers` members
    /// of its committee.
    fn goldfish_aggregate(
        state: &BeaconState,
        slot: Slot,
        signers: usize,
    ) -> GoldfishVoteAggregate {
        let committee = slot_committee(state, slot, &CommitteeCache::default()).unwrap();
        let data = GoldfishVoteData {
            slot,
            head: Root::repeat_byte(0x11),
        };
        let domain = get_domain_from_schedule(
            &config(),
            state,
            constants::DOMAIN_GOLDFISH_VOTE,
            compute_epoch_at_slot(slot),
        );
        let root = compute_signing_root(data.hash_tree_root(), domain);
        let signatures: Vec<_> = committee[..signers]
            .iter()
            .map(|&member| sign_for(member as usize, root))
            .collect();
        GoldfishVoteAggregate {
            aggregation_bits: bits(committee.len(), &(0..signers).collect::<Vec<_>>()),
            data,
            signature: bls::aggregate(&signatures).unwrap(),
        }
    }

    fn combined_aggregate(
        state: &BeaconState,
        round: u64,
        signers: &[usize],
    ) -> CombinedAttestationAggregate {
        let data = AttestationData::new(round, Some(Root::repeat_byte(0x22)), None, None);
        let params = params(&config());
        let domain = get_domain_from_schedule(
            &config(),
            state,
            constants::DOMAIN_COMBINED_ATTESTATION,
            compute_epoch_at_slot(params.opening_slot(round)),
        );
        let root = compute_signing_root(data.hash_tree_root(), domain);
        let signatures: Vec<_> = signers.iter().map(|&i| sign_for(i, root)).collect();
        CombinedAttestationAggregate {
            aggregation_bits: bits(state.validator_count(), signers),
            data,
            signature: bls::aggregate(&signatures).unwrap(),
        }
    }

    #[test]
    fn the_upgrade_changes_only_the_fork() {
        let BeaconState::Fulu(before) = with_signing_validators_at(ForkName::Fulu, VALIDATORS)
        else {
            unreachable!()
        };
        let after = upgrade_to_decoupled(before.clone(), &config());
        assert_eq!(after.fork.current_version, config().decoupled_fork_version);
        assert_eq!(after.fork.previous_version, before.fork.current_version);
        assert_eq!(after.fork.epoch, compute_epoch_at_slot(before.slot));
        let mut restored = after;
        restored.fork = before.fork.clone();
        assert_eq!(restored, before);
    }

    #[test]
    fn an_empty_block_applies() {
        let mut state = decoupled_state();
        let block = empty_block(&state, &config());
        apply(&mut state, &block, true).expect("an empty decoupled block is valid");
        assert_eq!(state.latest_block_header().slot, block.slot);
    }

    #[test]
    fn a_block_with_attestations_is_rejected() {
        let mut state = decoupled_state();
        let mut block = empty_block(&state, &config());
        let attestation = electra::Attestation {
            aggregation_bits: electra::AggregationBits::with_length(1).unwrap(),
            data: Default::default(),
            signature: Default::default(),
            committee_bits: Default::default(),
        };
        block.body.attestations = vec![attestation].try_into().unwrap();
        let before = state.clone();
        assert!(matches!(
            apply(&mut state, &block, true),
            Err(Error::DecoupledLegacyOperations("attestations"))
        ));
        assert_eq!(state, before, "refused before any state is touched");
    }

    #[test]
    fn a_goldfish_aggregate_of_the_wrong_slot_is_rejected() {
        let mut state = decoupled_state();
        let mut block = empty_block(&state, &config());
        // Two slots back, not the previous one.
        let aggregate = goldfish_aggregate(&state, state.slot() - 2, 2);
        block.body.goldfish_votes = vec![aggregate].try_into().unwrap();
        block.body.goldfish_support = bits(1, &[0]);
        assert!(apply(&mut state, &block, true).is_err());
    }

    #[test]
    fn correctly_signed_aggregates_are_accepted_and_expand() {
        let mut state = decoupled_state();
        let mut block = empty_block(&state, &config());
        let goldfish = goldfish_aggregate(&state, state.slot() - 1, 2);
        let combined = combined_aggregate(&state, 0, &[1, 4, 9]);
        block.body.goldfish_votes = vec![goldfish.clone()].try_into().unwrap();
        block.body.goldfish_support = bits(1, &[0]);
        block.body.combined_attestations = vec![combined.clone()].try_into().unwrap();

        apply(&mut state, &block, true).expect("both aggregates verify");

        let committees = CommitteeCache::default();
        let committee = slot_committee(&state, state.slot() - 1, &committees).unwrap();
        let votes = goldfish_votes_of(&state, &goldfish, &committees).unwrap();
        assert_eq!(votes.len(), 2);
        assert_eq!(
            votes.iter().map(|v| v.validator).collect::<Vec<_>>(),
            committee[..2]
        );
        let attestations = attestations_of(&combined);
        assert_eq!(
            attestations.iter().map(|a| a.validator).collect::<Vec<_>>(),
            vec![1, 4, 9]
        );

        let signed = SignedBeaconBlock {
            message: block,
            signature: BlsSignature::default(),
        };
        let input = block_input(&state, &signed, &committees, &config()).unwrap();
        assert_eq!(input.slot, signed.message.slot);
        assert_eq!(input.votes.len(), 2);
        assert_eq!(input.support_votes, input.votes);
        assert_eq!(input.attestations.len(), 3);
        assert_eq!(input.root, signed.message.hash_tree_root());
    }

    #[test]
    fn a_bad_signature_is_rejected_only_when_verifying() {
        let mut state = decoupled_state();
        let mut block = empty_block(&state, &config());
        let mut aggregate = combined_aggregate(&state, 0, &[2, 3]);
        aggregate.signature = sign_for(7, Root::repeat_byte(0x99));
        block.body.combined_attestations = vec![aggregate].try_into().unwrap();

        let mut unverified = state.clone();
        apply(&mut unverified, &block, false).expect("signatures are skipped");
        assert!(matches!(
            apply(&mut state, &block, true),
            Err(Error::InvalidSignature(_))
        ));
    }

    #[test]
    fn malformed_aggregates_are_rejected() {
        let state = decoupled_state();
        let block = empty_block(&state, &config());

        let mut short = block.clone();
        let mut aggregate = combined_aggregate(&state, 0, &[1]);
        aggregate.aggregation_bits = bits(VALIDATORS - 1, &[1]);
        short.body.combined_attestations = vec![aggregate].try_into().unwrap();
        assert!(apply(&mut state.clone(), &short, false).is_err());

        let mut empty = block.clone();
        let mut aggregate = combined_aggregate(&state, 0, &[1]);
        aggregate.aggregation_bits = bits(VALIDATORS, &[]);
        empty.body.combined_attestations = vec![aggregate].try_into().unwrap();
        assert!(apply(&mut state.clone(), &empty, false).is_err());

        let mut future = block.clone();
        let aggregate = combined_aggregate(&state, 1_000, &[1]);
        future.body.combined_attestations = vec![aggregate].try_into().unwrap();
        assert!(apply(&mut state.clone(), &future, false).is_err());

        let mut unmatched = block;
        unmatched.body.goldfish_votes = vec![goldfish_aggregate(&state, state.slot() - 1, 2)]
            .try_into()
            .unwrap();
        // `goldfish_support` left empty: lengths disagree.
        assert!(apply(&mut state.clone(), &unmatched, false).is_err());
    }

    #[test]
    fn epoch_processing_leaves_balances_alone_when_nobody_participated() {
        let mut decoupled = decoupled_state();
        let mut fulu = with_signing_validators_at(ForkName::Fulu, VALIDATORS);
        // An epoch past genesis with no participation: fulu's rewards step
        // penalizes every eligible validator for missing its duties.
        let start = decoupled.slot() + preset::SLOTS_PER_EPOCH * 3 - 1;
        *decoupled.slot_mut() = start;
        *fulu.slot_mut() = start;
        let balances: Vec<_> = decoupled.iter_balances().collect();

        crate::beacon::stf::epoch::process_epoch(&mut decoupled, &config()).unwrap();
        crate::beacon::stf::epoch::process_epoch(&mut fulu, &config()).unwrap();

        assert_eq!(decoupled.iter_balances().collect::<Vec<_>>(), balances);
        assert_ne!(
            fulu.iter_balances().collect::<Vec<_>>(),
            balances,
            "fulu penalizes the same state"
        );
    }
}
