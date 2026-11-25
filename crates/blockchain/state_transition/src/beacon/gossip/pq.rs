//! Gossip validation for the PQ fork's topics
//! (`specs/_features/pq/p2p-interface.md`, consensus-specs' `pq` branch at
//! `b5d422b255db80c9bbc48f515370655ecc8bf6e5`).
//!
//! Every topic whose message carries a validator's or builder's signature
//! carries an XMSS one instead, at the leaf the fork assigns that message, and
//! an aggregate proves its attesters' signatures with a STARK proof rather
//! than an aggregate BLS signature. Aggregators come from the state's
//! aggregation committee rather than a selection proof, and attestations
//! travel on `ATTESTATION_SUBNET_COUNT_PQ` subnets. `voluntary_exit`,
//! `bls_to_execution_change` and the sync committee topics are gone.
//!
//! # What is ported
//!
//! The branch restates every rule it touches on a consensus-specs `master`
//! newer than this repository's pin, with head-state reads and checks in a
//! different order. This module applies only the lines marked `[Modified in
//! PQ]` or `[New in PQ]` to the gloas rules the neighbouring modules already
//! implement, keeping their deliberate departures (the vote block's own
//! post-state rather than the head's, the pubkey-only signature before any
//! committee derivation, "post-state is cached" for "passes validation"); see
//! `docs/spec_deviations.md`. The topics with a gloas counterpart that differs
//! only in the signature (bids, preferences, payload attestation messages)
//! reuse that module's rules through its fork trait or `*_with` function.
//!
//! # States
//!
//! A PQ rule reads XMSS keys, which only a PQ state holds. A rule whose state
//! is of another fork answers [`IgnoreReason::StateUnavailable`], never a
//! REJECT: the node does not follow PQ (`ForkName::is_followed`), so on a live
//! node no PQ block is imported and every stateful rule here ends in an
//! IGNORE or a queue, while the cheap rules judge what arrives on a PQ digest
//! that a network schedules.

use std::sync::Arc;

use ethlambda_storage::CacheKey;

use super::aggregate::AggregateKey;
use super::column::judgeable_block_gloas;
use super::execution_payload_bid::cached_checkpoint_state;
use super::operations::SeenOperations;
use super::{
    IgnoreReason, Outcome, QueueReason, RejectReason, SeenAggregates, SeenAttestations, SeenBlocks,
    SeenEnvelopes, SeenPayloadAttestations, ancestor_at, finalized_start_slot,
    is_current_or_previous_epoch, is_future_slot, verify_attestation_payload_status,
};
use crate::beacon::config::Config;
use crate::beacon::constants::{
    DOMAIN_AGGREGATE_AND_PROOF, DOMAIN_BEACON_ATTESTER, DOMAIN_PTC_ATTESTER,
    LEAF_OFFSET_AGGREGATE_AND_PROOF, LEAF_OFFSET_PTC_ATTESTER,
};
use crate::beacon::containers::{BeaconState, SignedBeaconBlock, pq};
use crate::beacon::fork_choice::Store;
use crate::beacon::helpers::accessors::{
    CommitteeCacheExt, get_current_epoch, get_domain, get_domain_from_schedule,
};
use crate::beacon::helpers::misc::{
    compute_epoch_at_slot, compute_signing_root, compute_start_slot_at_epoch,
};
use crate::beacon::helpers::pq::{
    compute_xmss_attestation_leaf_index, compute_xmss_leaf_index, get_aggregation_committee,
    get_attestation_statements, get_attesting_indices, get_committee_indices,
    is_valid_indexed_attestation, verify_aggregates, xmss_verify,
};
use crate::beacon::helpers::predicates::{is_slashable_attestation_data, is_slashable_validator};
use crate::beacon::lean_boundary::lean_block_unreachable;
use crate::beacon::preset;
use crate::beacon::primitives::{
    CommitteeIndex, Epoch, HashTreeRoot as _, Root, Slot, ValidatorIndex,
};
use crate::beacon::stf;

/// How many epochs past the vote block's own a PQ rule advances its state to
/// reach the attestation's epoch. Advancing runs every slot between, so an
/// unbounded advance is work any peer could ask for: on a node that does not
/// follow PQ, every head is far behind a PQ slot. The aggregation committee
/// window already reaches `MIN_SEED_LOOKAHEAD` epochs ahead, so a vote block
/// that recent needs no advance at all.
pub const MAX_VOTE_STATE_ADVANCE_EPOCHS: u64 = preset::MIN_SEED_LOOKAHEAD + 1;

/// The most aggregation bits a PQ aggregate may carry: every committee of a
/// slot at full size, under the PQ committee cap. The progressive bitlist has
/// no bound of its own, so the rules enforce this one before reading the bits.
pub fn max_aggregation_bits() -> usize {
    preset::MAX_VALIDATORS_PER_COMMITTEE * preset::max_committees_per_slot_pq()
}

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

/// `compute_subnet_for_attestation` (modified in PQ, `pq/validator.md`): the
/// subnet an attestation travels on, among `ATTESTATION_SUBNET_COUNT_PQ`.
pub fn compute_subnet_for_attestation(
    committees_per_slot: u64,
    slot: Slot,
    committee_index: CommitteeIndex,
    config: &Config,
) -> u64 {
    let slots_since_epoch_start = slot % preset::slots_per_epoch();
    let committees_since_epoch_start = committees_per_slot.saturating_mul(slots_since_epoch_start);
    committees_since_epoch_start.saturating_add(committee_index)
        % config.attestation_subnet_count_pq.max(1)
}

/// The vote block's post-state, as a PQ state that can name `attestation_epoch`'s
/// committees and aggregation committees.
///
/// The vote block's own cached post-state when it is a PQ state whose
/// aggregation-committee window reaches the epoch, else that state advanced to
/// the epoch's start, the specification's `[New in PQ]` `process_slots` for an
/// epoch past `MIN_SEED_LOOKAHEAD` (here also for a vote block of an earlier
/// fork, whose state holds no XMSS keys), at most
/// [`MAX_VOTE_STATE_ADVANCE_EPOCHS`] ahead. Cached-only, as every gossip rule
/// reads states: a miss is an IGNORE, and so is a state that is not PQ.
fn pq_vote_state(
    store: &Store,
    block_root: Root,
    attestation_epoch: Epoch,
) -> Result<Arc<BeaconState>, Outcome> {
    // [IGNORE] The block being voted for has been seen.
    if !store.has_block(&block_root) {
        return Err(Outcome::Ignore(IgnoreReason::UnknownBlock));
    }
    // "Passes validation" is "post-state is cached"; see `super::aggregate`.
    let Some(state) = store.cached_state(CacheKey::BlockState(block_root)) else {
        return Err(Outcome::Ignore(IgnoreReason::StateUnavailable));
    };
    let state_epoch = get_current_epoch(&state);
    let window_reaches = attestation_epoch + 1 >= state_epoch
        && attestation_epoch <= state_epoch + preset::MIN_SEED_LOOKAHEAD;
    let state = if matches!(*state, BeaconState::Pq(_)) && window_reaches {
        state
    } else {
        // Bounded before anything is advanced: see
        // `MAX_VOTE_STATE_ADVANCE_EPOCHS`.
        if attestation_epoch < state_epoch
            || attestation_epoch - state_epoch > MAX_VOTE_STATE_ADVANCE_EPOCHS
        {
            return Err(Outcome::Ignore(IgnoreReason::StateUnavailable));
        }
        cached_checkpoint_state(store, attestation_epoch, block_root)
            .ok_or(Outcome::Ignore(IgnoreReason::StateUnavailable))?
    };
    if !matches!(*state, BeaconState::Pq(_)) {
        return Err(Outcome::Ignore(IgnoreReason::StateUnavailable));
    }
    Ok(state)
}

/// The two ancestry rules every attestation topic ends with, against the vote
/// state's own history ([`ancestor_at`]).
fn check_ancestry(
    store: &Store,
    state: &BeaconState,
    block_root: Root,
    target_epoch: Epoch,
    target_root: Root,
) -> Result<(), Outcome> {
    // [REJECT] The target is the vote block's ancestor at the target epoch.
    let target_start_slot = compute_start_slot_at_epoch(target_epoch);
    let Some(checkpoint_block) = ancestor_at(state, block_root, target_start_slot) else {
        return Err(Outcome::Ignore(IgnoreReason::AncestryUnknown));
    };
    if checkpoint_block != target_root {
        return Err(Outcome::Reject(RejectReason::TargetNotAncestor));
    }
    // [IGNORE] The finalized checkpoint is an ancestor of the vote block.
    let finalized = store.beacon_finalized_checkpoint();
    let finalized_start_slot = compute_start_slot_at_epoch(finalized.epoch);
    let Some(finalized_block) = ancestor_at(state, block_root, finalized_start_slot) else {
        return Err(Outcome::Ignore(IgnoreReason::AncestryUnknown));
    };
    if finalized_block != finalized.root {
        return Err(Outcome::Ignore(IgnoreReason::FinalizedNotAncestor));
    }
    Ok(())
}

/// The fork-choice head's post-state when it is a PQ state: what the operation
/// topics check against, as the specification and `super::operations` do.
fn pq_head_state(store: &Store) -> Result<Arc<BeaconState>, Outcome> {
    let Some((_slot, head_root)) = store.beacon_head() else {
        return Err(Outcome::Ignore(IgnoreReason::StateUnavailable));
    };
    let Ok(Some(state)) = store.get_state(&head_root) else {
        return Err(Outcome::Ignore(IgnoreReason::StateUnavailable));
    };
    if !matches!(*state, BeaconState::Pq(_)) {
        return Err(Outcome::Ignore(IgnoreReason::StateUnavailable));
    }
    Ok(state)
}

// ---------------------------------------------------------------------------
// beacon_aggregate_and_proof
// ---------------------------------------------------------------------------

/// The keys [`SeenAggregates`] records a PQ aggregate under, or `None` when its
/// committee bits do not name exactly one committee.
pub fn aggregate_key(signed: &pq::SignedAggregateAndProof) -> Option<AggregateKey> {
    let aggregate = &signed.message.aggregate;
    let [committee_index] = get_committee_indices(&aggregate.committee_bits)[..] else {
        return None;
    };
    Some(AggregateKey {
        data_root: aggregate.data.hash_tree_root(),
        committee_index,
        target_epoch: aggregate.data.target.epoch,
        aggregator_index: signed.message.aggregator_index,
    })
}

/// The aggregate's bits, expanded. Only after [`aggregate_cheap_checks`] has
/// bounded their length.
pub fn aggregation_bits(signed: &pq::SignedAggregateAndProof) -> Vec<bool> {
    let bits = &signed.message.aggregate.aggregation_bits;
    (0..bits.len())
        .map(|index| bits.get(index).unwrap_or(false))
        .collect()
}

/// The rules that read only the message, the clock and the seen cache: the
/// gloas aggregate's, with no selection proof to read.
pub fn aggregate_cheap_checks(
    seen: &SeenAggregates,
    store: &Store,
    signed: &pq::SignedAggregateAndProof,
    now_ms: u64,
) -> Result<(), Outcome> {
    let config = store.config();
    let aggregate = &signed.message.aggregate;
    let data = &aggregate.data;
    // [REJECT] The bitfield fits every committee of a slot, read without
    // expanding it: everything below expands it.
    if aggregate.aggregation_bits.len() > max_aggregation_bits() {
        return Err(Outcome::Reject(RejectReason::BitsLength));
    }
    // [REJECT] The aggregate attestation's data index is 0 or 1.
    if data.index > 1 {
        return Err(Outcome::Reject(RejectReason::DataIndexOutOfRange));
    }
    // [REJECT] Exactly one committee is specified by the committee bits.
    let Some(key) = aggregate_key(signed) else {
        return Err(Outcome::Reject(RejectReason::CommitteeBits));
    };
    let bits = aggregation_bits(signed);
    // [IGNORE] Not a covered superset, and [IGNORE] the first for this epoch
    // and aggregator.
    seen.verdict_parts(&key, &bits)?;
    // [IGNORE] Not from a future slot.
    if is_future_slot(&config, data.slot, now_ms) {
        return Err(Outcome::Ignore(IgnoreReason::FutureSlot));
    }
    // [IGNORE] The current or the previous epoch.
    let attestation_epoch = compute_epoch_at_slot(data.slot);
    if !is_current_or_previous_epoch(&config, attestation_epoch, now_ms) {
        return Err(Outcome::Ignore(IgnoreReason::OutsideEpochWindow));
    }
    // [REJECT] The epoch matches its target.
    if data.target.epoch != attestation_epoch {
        return Err(Outcome::Reject(RejectReason::EpochMismatch));
    }
    // [REJECT] The aggregate has participants. One named committee, so a set
    // bit is a real attester whichever committee it is.
    if !bits.iter().any(|&bit| bit) {
        return Err(Outcome::Reject(RejectReason::NoParticipants));
    }
    Ok(())
}

/// The rules that need the vote block's state. `Ok` is `Accept`, carrying the
/// attesting indices the proof covers.
pub fn aggregate_stateful_checks(
    store: &Store,
    signed: &pq::SignedAggregateAndProof,
) -> Result<Vec<ValidatorIndex>, Outcome> {
    let aggregate_and_proof = &signed.message;
    let aggregate = &aggregate_and_proof.aggregate;
    let data = &aggregate.data;
    let target_epoch = data.target.epoch;
    let config = store.config();
    let state = pq_vote_state(
        store,
        data.beacon_block_root,
        compute_epoch_at_slot(data.slot),
    )?;

    // The pubkey-only signature first, before any committee derivation.
    let aggregator_index = aggregate_and_proof.aggregator_index;
    let Ok(aggregator) = state.pq_validator(aggregator_index) else {
        return Err(Outcome::Reject(RejectReason::UnknownValidator));
    };
    // [Modified in PQ] [REJECT] The aggregator's XMSS signature at the slot's
    // aggregate leaf.
    let domain =
        get_domain_from_schedule(&config, &state, DOMAIN_AGGREGATE_AND_PROOF, target_epoch);
    let signing_root = compute_signing_root(aggregate_and_proof.hash_tree_root(), domain);
    let leaf_index = compute_xmss_leaf_index(data.slot, LEAF_OFFSET_AGGREGATE_AND_PROOF)
        .map_err(|_| Outcome::Reject(RejectReason::AggregatorSignature))?;
    if !xmss_verify(
        &aggregator.pubkey(),
        leaf_index,
        signing_root,
        &signed.signature,
    ) {
        return Err(Outcome::Reject(RejectReason::AggregatorSignature));
    }

    let committees = store.committee_cache();
    let epoch_committees = committees.committees(&state, target_epoch);
    let committee_index = aggregate_key(signed)
        .expect("aggregate_cheap_checks rejects an aggregate with no single committee")
        .committee_index;
    // [REJECT] The committee index is within the expected range.
    if committee_index >= epoch_committees.committees_per_slot() {
        return Err(Outcome::Reject(RejectReason::CommitteeIndex));
    }
    let Ok(committee) = epoch_committees.committee(data.slot, committee_index) else {
        return Err(Outcome::Ignore(IgnoreReason::Internal));
    };
    // [REJECT] The number of aggregation bits matches the committee size.
    if aggregate.aggregation_bits.len() != committee.len() {
        return Err(Outcome::Reject(RejectReason::BitsLength));
    }
    // [Modified in PQ] [REJECT] The validator is one of the committee's
    // aggregators: a member of its aggregation committee.
    let aggregators = get_aggregation_committee(&state, data.slot, committee_index)
        .map_err(|_| Outcome::Ignore(IgnoreReason::StateUnavailable))?;
    if !aggregators.contains(&aggregator_index) {
        return Err(Outcome::Reject(RejectReason::NotAggregator));
    }
    // [Modified in PQ] [REJECT] The aggregate stark is valid.
    let statements = get_attestation_statements(&state, aggregate, &committees)
        .map_err(|_| Outcome::Reject(RejectReason::AggregateProof))?;
    if !verify_aggregates(&statements, &aggregate_and_proof.proof) {
        return Err(Outcome::Reject(RejectReason::AggregateProof));
    }
    let attesting_indices = get_attesting_indices(&state, aggregate, &committees)
        .map_err(|_| Outcome::Ignore(IgnoreReason::Internal))?;

    check_ancestry(
        store,
        &state,
        data.beacon_block_root,
        target_epoch,
        data.target.root,
    )?;
    // The attested payload status is consistent with the block's payload.
    verify_attestation_payload_status(store, data)?;
    Ok(attesting_indices)
}

// ---------------------------------------------------------------------------
// beacon_attestation_{subnet_id}
// ---------------------------------------------------------------------------

/// The rules that read only the message, the clock and the seen cache: the
/// gloas attestation's.
pub fn attestation_cheap_checks(
    seen: &SeenAttestations,
    store: &Store,
    attestation: &pq::SingleAttestation,
    now_ms: u64,
) -> Result<(), Outcome> {
    let config = store.config();
    let data = &attestation.data;
    // [IGNORE] No other valid attestation seen for this target epoch and
    // validator.
    if seen.contains(data.target.epoch, attestation.attester_index) {
        return Err(Outcome::Ignore(IgnoreReason::AlreadySeen));
    }
    // [REJECT] The attestation's data index is 0 or 1.
    if data.index > 1 {
        return Err(Outcome::Reject(RejectReason::DataIndexOutOfRange));
    }
    // [IGNORE] Not from a future slot.
    if is_future_slot(&config, data.slot, now_ms) {
        return Err(Outcome::Ignore(IgnoreReason::FutureSlot));
    }
    // [IGNORE] The current or the previous epoch.
    let attestation_epoch = compute_epoch_at_slot(data.slot);
    if !is_current_or_previous_epoch(&config, attestation_epoch, now_ms) {
        return Err(Outcome::Ignore(IgnoreReason::OutsideEpochWindow));
    }
    // [REJECT] The epoch matches its target.
    if data.target.epoch != attestation_epoch {
        return Err(Outcome::Reject(RejectReason::EpochMismatch));
    }
    Ok(())
}

/// The rules that need the vote block's state.
pub fn attestation_stateful_checks(
    store: &Store,
    attestation: &pq::SingleAttestation,
    subnet_id: u64,
) -> Outcome {
    match attestation_stateful_rules(store, attestation, subnet_id) {
        Ok(()) => Outcome::Accept,
        Err(outcome) => outcome,
    }
}

fn attestation_stateful_rules(
    store: &Store,
    attestation: &pq::SingleAttestation,
    subnet_id: u64,
) -> Result<(), Outcome> {
    let data = &attestation.data;
    let target_epoch = data.target.epoch;
    let config = store.config();
    let state = pq_vote_state(
        store,
        data.beacon_block_root,
        compute_epoch_at_slot(data.slot),
    )?;

    // The pubkey-only signature first, before any committee derivation.
    let Ok(attester) = state.pq_validator(attestation.attester_index) else {
        return Err(Outcome::Reject(RejectReason::UnknownValidator));
    };
    // [Modified in PQ] [REJECT] The attester's XMSS signature at the target
    // epoch's attestation leaf.
    let domain = get_domain_from_schedule(&config, &state, DOMAIN_BEACON_ATTESTER, target_epoch);
    let signing_root = compute_signing_root(data.hash_tree_root(), domain);
    let leaf_index = compute_xmss_attestation_leaf_index(target_epoch)
        .map_err(|_| Outcome::Reject(RejectReason::BadSignature))?;
    if !xmss_verify(
        &attester.pubkey(),
        leaf_index,
        signing_root,
        &attestation.signature,
    ) {
        return Err(Outcome::Reject(RejectReason::BadSignature));
    }

    let committees = store.committee_cache();
    let epoch_committees = committees.committees(&state, target_epoch);
    // [REJECT] The committee index is within the expected range.
    if attestation.committee_index >= epoch_committees.committees_per_slot() {
        return Err(Outcome::Reject(RejectReason::CommitteeIndex));
    }
    // [Modified in PQ] [REJECT] The attestation is for the correct subnet, one
    // of `ATTESTATION_SUBNET_COUNT_PQ`.
    let expected_subnet = compute_subnet_for_attestation(
        epoch_committees.committees_per_slot(),
        data.slot,
        attestation.committee_index,
        &config,
    );
    if expected_subnet != subnet_id {
        return Err(Outcome::Reject(RejectReason::WrongSubnet));
    }
    let Ok(committee) = epoch_committees.committee(data.slot, attestation.committee_index) else {
        return Err(Outcome::Ignore(IgnoreReason::Internal));
    };
    // [REJECT] The attester is a member of the committee.
    if !committee.contains(&attestation.attester_index) {
        return Err(Outcome::Reject(RejectReason::NotInCommittee));
    }

    check_ancestry(
        store,
        &state,
        data.beacon_block_root,
        target_epoch,
        data.target.root,
    )?;
    // The attested payload status is consistent with the block's payload.
    verify_attestation_payload_status(store, data)
}

// ---------------------------------------------------------------------------
// proposer_slashing, attester_slashing
// ---------------------------------------------------------------------------

/// The rules that read only the message and the seen record.
pub fn proposer_slashing_cheap_checks(
    seen: &SeenOperations,
    slashing: &pq::ProposerSlashing,
) -> Result<(), Outcome> {
    let header_1 = &slashing.signed_header_1.message;
    let header_2 = &slashing.signed_header_2.message;
    // [IGNORE] The first valid proposer slashing for this proposer.
    if !seen.proposer_slashing_is_new(header_1.proposer_index) {
        return Err(Outcome::Ignore(IgnoreReason::AlreadySeen));
    }
    // [REJECT] The header slots and proposer indices match, and the headers
    // differ.
    if header_1.slot != header_2.slot
        || header_1.proposer_index != header_2.proposer_index
        || header_1 == header_2
    {
        return Err(Outcome::Reject(RejectReason::InvalidOperation));
    }
    Ok(())
}

/// The rules that read the head state.
pub fn proposer_slashing_stateful_checks(
    store: &Store,
    slashing: &pq::ProposerSlashing,
) -> Outcome {
    let state = match pq_head_state(store) {
        Ok(state) => state,
        Err(outcome) => return outcome,
    };
    let proposer_index = slashing.signed_header_1.message.proposer_index;
    // [REJECT] The proposer index is a valid validator index.
    let Ok(proposer) = state.pq_validator(proposer_index) else {
        return Outcome::Reject(RejectReason::UnknownValidator);
    };
    // [REJECT] The proposer is slashable.
    if !is_slashable_validator(&proposer.record, get_current_epoch(&state)) {
        return Outcome::Reject(RejectReason::InvalidOperation);
    }
    // [Modified in PQ] [REJECT] Both XMSS signatures, each at its header slot's
    // proposer leaf.
    let pubkey = proposer.pubkey();
    for signed_header in [&slashing.signed_header_1, &slashing.signed_header_2] {
        let valid = stf::pq::header_signature_valid(
            &state,
            &pubkey,
            &signed_header.message,
            &signed_header.signature,
        );
        if !matches!(valid, Ok(true)) {
            return Outcome::Reject(RejectReason::BadSignature);
        }
    }
    Outcome::Accept
}

/// The indices both of a PQ attester slashing's attestations name: the
/// validators it slashes.
pub fn slashed_indices(slashing: &pq::AttesterSlashing) -> Vec<ValidatorIndex> {
    let first: std::collections::HashSet<ValidatorIndex> = slashing
        .attestation_1
        .attesting_indices
        .iter()
        .copied()
        .collect();
    slashing
        .attestation_2
        .attesting_indices
        .iter()
        .copied()
        .filter(|index| first.contains(index))
        .collect()
}

/// The rules that read only the message and the seen record.
pub fn attester_slashing_cheap_checks(
    seen: &SeenOperations,
    slashing: &pq::AttesterSlashing,
) -> Result<(), Outcome> {
    // [IGNORE] At least one overlapping index is unseen.
    if !seen.attester_slashing_is_new(&slashed_indices(slashing)) {
        return Err(Outcome::Ignore(IgnoreReason::AlreadySeen));
    }
    // [REJECT] The data is a double or surround vote.
    if !is_slashable_attestation_data(&slashing.attestation_1.data, &slashing.attestation_2.data) {
        return Err(Outcome::Reject(RejectReason::InvalidOperation));
    }
    Ok(())
}

/// The rules that read the head state. In `super::operations`'s order: the
/// cheap REJECTs before any proof is verified.
pub fn attester_slashing_stateful_checks(
    store: &Store,
    slashing: &pq::AttesterSlashing,
) -> Outcome {
    let state = match pq_head_state(store) {
        Ok(state) => state,
        Err(outcome) => return outcome,
    };
    let attestations = [&slashing.attestation_1, &slashing.attestation_2];
    let validator_count = state.validator_count() as u64;
    // [REJECT] Every index is a validator.
    if attestations.iter().any(|attestation| {
        attestation
            .attesting_indices
            .iter()
            .any(|index| *index >= validator_count)
    }) {
        return Outcome::Reject(RejectReason::UnknownValidator);
    }
    // [REJECT] At least one overlapping validator is slashable.
    let current_epoch = get_current_epoch(&state);
    let any_slashable = slashed_indices(slashing).into_iter().any(|index| {
        state
            .validator(index)
            .is_ok_and(|validator| is_slashable_validator(validator, current_epoch))
    });
    if !any_slashable {
        return Outcome::Reject(RejectReason::InvalidOperation);
    }
    // [Modified in PQ] [REJECT] Each indexed attestation is non-empty, sorted
    // and unique, and its proof proves its attesters' signatures.
    if !attestations
        .iter()
        .all(|attestation| matches!(is_valid_indexed_attestation(&state, attestation), Ok(true)))
    {
        return Outcome::Reject(RejectReason::InvalidOperation);
    }
    Outcome::Accept
}

// ---------------------------------------------------------------------------
// payload_attestation_message
// ---------------------------------------------------------------------------

/// The gloas rules that read only the message, the clock and the seen cache.
pub fn payload_attestation_cheap_checks(
    seen: &SeenPayloadAttestations,
    store: &Store,
    message: &pq::PayloadAttestationMessage,
    now_ms: u64,
) -> Result<(), Outcome> {
    super::payload_attestation::cheap_checks_parts(
        seen,
        store,
        message.data.slot,
        message.validator_index,
        now_ms,
    )
}

/// The gloas rules that need the head state, with `[Modified in PQ]` the
/// validator's XMSS signature at the slot's PTC leaf.
pub fn payload_attestation_stateful_checks(
    store: &Store,
    message: &pq::PayloadAttestationMessage,
) -> Outcome {
    let data = &message.data;
    super::payload_attestation::stateful_checks_with(
        store,
        message.validator_index,
        data,
        |state| matches!(state, BeaconState::Pq(_)),
        |state, validator_index| {
            let Ok(validator) = state.pq_validator(validator_index) else {
                return false;
            };
            let domain = get_domain(
                state,
                DOMAIN_PTC_ATTESTER,
                Some(compute_epoch_at_slot(data.slot)),
            );
            let signing_root = compute_signing_root(data.hash_tree_root(), domain);
            let Ok(leaf_index) = compute_xmss_leaf_index(data.slot, LEAF_OFFSET_PTC_ATTESTER)
            else {
                return false;
            };
            xmss_verify(
                &validator.pubkey(),
                leaf_index,
                signing_root,
                &message.signature,
            )
        },
    )
}

// ---------------------------------------------------------------------------
// execution_payload
// ---------------------------------------------------------------------------

/// `verify_execution_requests_limits` (modified in PQ): gloas's four lists,
/// then the three PQ adds. EIP-8483's registration lists are gone.
pub fn execution_requests_within_limits(requests: &pq::ExecutionRequests) -> bool {
    requests.withdrawals.len() <= preset::MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD
        && requests.consolidations.len() <= preset::MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD
        && requests.builder_deposits.len() as u64
            <= preset::MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD
        && requests.builder_exits.len() as u64 <= preset::MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD
        && requests.validator_preregistrations.len() as u64
            <= preset::MAX_VALIDATOR_PREREGISTRATION_REQUESTS_PER_PAYLOAD
        && requests.builder_preregistrations.len() as u64
            <= preset::MAX_BUILDER_PREREGISTRATION_REQUESTS_PER_PAYLOAD
        && requests.voluntary_exits.len() as u64 <= preset::MAX_VOLUNTARY_EXIT_REQUESTS_PER_PAYLOAD
}

/// The gloas envelope rules that read only the message and the seen cache,
/// with PQ's execution request limits.
pub fn envelope_cheap_checks(
    seen: &SeenEnvelopes,
    store: &Store,
    envelope: &pq::SignedExecutionPayloadEnvelope,
) -> Result<(), Outcome> {
    let message = &envelope.message;
    // [IGNORE] The first envelope for this block and builder.
    if seen.contains(message.beacon_block_root, message.builder_index) {
        return Err(Outcome::Ignore(IgnoreReason::AlreadySeen));
    }
    // [IGNORE] Not from before the finalized epoch.
    if message.payload.slot_number < finalized_start_slot(store) {
        return Err(Outcome::Ignore(IgnoreReason::Finalized));
    }
    // [REJECT] The withdrawals and execution requests are within their limits.
    if message.payload.withdrawals.len() > preset::max_withdrawals_per_payload() {
        return Err(Outcome::Reject(RejectReason::TooManyWithdrawals));
    }
    if !execution_requests_within_limits(&message.execution_requests) {
        return Err(Outcome::Reject(RejectReason::OperationLimit));
    }
    Ok(())
}

/// The gloas envelope rules that need the block, with `[Modified in PQ]` the
/// builder's (or self-building proposer's) XMSS signature.
pub fn envelope_stateful_checks(
    store: &Store,
    envelope: &pq::SignedExecutionPayloadEnvelope,
) -> Outcome {
    let message = &envelope.message;
    let payload = &message.payload;
    let block = match judgeable_block_gloas(store, &message.beacon_block_root) {
        Ok(block) => block,
        Err(outcome) => return outcome,
    };
    let block = match &block {
        SignedBeaconBlock::Pq(block) => &block.message,
        SignedBeaconBlock::Phase0(_)
        | SignedBeaconBlock::Altair(_)
        | SignedBeaconBlock::Bellatrix(_)
        | SignedBeaconBlock::Capella(_)
        | SignedBeaconBlock::Deneb(_)
        | SignedBeaconBlock::Electra(_)
        | SignedBeaconBlock::Fulu(_) => return Outcome::Reject(RejectReason::BlockNotGloas),
        // A PQ-shaped envelope for a gloas or EIP-8483 block: around the
        // boundary, the one digest's topic may carry the other's. Not
        // something this envelope's rules can judge.
        SignedBeaconBlock::Gloas(_) | SignedBeaconBlock::Eip8483(_) => {
            return Outcome::Ignore(IgnoreReason::UnsupportedFork);
        }
        SignedBeaconBlock::Lean(_) => lean_block_unreachable("pq::envelope_stateful_checks"),
    };
    let bid = &block.body.signed_execution_payload_bid.message;
    // [REJECT] The envelope matches its block's slot and bid.
    if block.slot != payload.slot_number {
        return Outcome::Reject(RejectReason::SlotMismatch);
    }
    if message.builder_index != bid.builder_index {
        return Outcome::Reject(RejectReason::BuilderIndexMismatch);
    }
    if payload.block_hash != bid.block_hash {
        return Outcome::Reject(RejectReason::BlockHashMismatch);
    }
    if message.execution_requests.hash_tree_root() != bid.execution_requests_root {
        return Outcome::Reject(RejectReason::ExecutionRequestsRootMismatch);
    }
    let Some(state) = store.cached_state(CacheKey::BlockState(message.beacon_block_root)) else {
        return Outcome::Queue(QueueReason::StateNotCached);
    };
    // [Modified in PQ] [REJECT] The signature is valid.
    if !matches!(
        stf::pq::verify_execution_payload_envelope_signature(&state, envelope),
        Ok(true)
    ) {
        return Outcome::Reject(RejectReason::BadSignature);
    }
    Outcome::Accept
}

// ---------------------------------------------------------------------------
// beacon_block
// ---------------------------------------------------------------------------

/// `verify_block_body_operation_limits` (modified in PQ): the attestation
/// count is `MAX_ATTESTATIONS_PQ`, and exits, BLS changes and payload
/// attestations are no longer in the body.
pub fn body_operations_within_limits(body: &pq::BeaconBlockBody) -> bool {
    body.proposer_slashings.len() <= preset::MAX_PROPOSER_SLASHINGS
        && body.attester_slashings.len() <= preset::MAX_ATTESTER_SLASHINGS_ELECTRA
        && body.attestations.len() as u64 <= preset::MAX_ATTESTATIONS_PQ
        && body.deposits.is_empty()
}

/// The gloas block rules that read only the block, the clock and the store's
/// metadata, with PQ's operation and execution request limits. The proposer's
/// XMSS signature is the precheck's (`crate::beacon::precheck`).
pub fn block_cheap_checks(
    seen: &SeenBlocks,
    store: &Store,
    signed_block: &pq::SignedBeaconBlock,
    now_ms: u64,
) -> Result<(), Outcome> {
    let config = store.config();
    let block = &signed_block.message;
    // [IGNORE] The first block with a valid signature for its slot and
    // proposer.
    if seen.contains(block.slot, block.proposer_index) {
        return Err(Outcome::Ignore(IgnoreReason::AlreadySeen));
    }
    // [IGNORE] Not from a future slot.
    if is_future_slot(&config, block.slot, now_ms) {
        return Err(Outcome::Ignore(IgnoreReason::FutureSlot));
    }
    // [IGNORE] From a slot greater than the latest finalized slot.
    if block.slot <= finalized_start_slot(store) {
        return Err(Outcome::Ignore(IgnoreReason::Finalized));
    }
    // [Modified in PQ] [REJECT] The body's operation counts, and the parent
    // execution requests' counts, are within their limits.
    if !body_operations_within_limits(&block.body)
        || !execution_requests_within_limits(&block.body.parent_execution_requests)
    {
        return Err(Outcome::Reject(RejectReason::OperationLimit));
    }
    // [REJECT] The bid's blob KZG commitment count is within the epoch's limit.
    let bid = &block.body.signed_execution_payload_bid.message;
    let max_blobs = config.max_blobs_per_block(compute_epoch_at_slot(block.slot));
    if bid.blob_kzg_commitments.len() as u64 > max_blobs {
        return Err(Outcome::Reject(RejectReason::TooManyBlobs));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ethlambda_crypto::{lean_xmss, stark};

    use super::*;
    use crate::beacon::builder_market::SignedBid;
    use crate::beacon::constants::{
        DOMAIN_BEACON_PROPOSER, DOMAIN_PROPOSER_PREFERENCES, LEAF_OFFSET_BEACON_PROPOSER,
        LEAF_OFFSET_PROPOSER_PREFERENCES,
    };
    use crate::beacon::containers::gloas;
    use crate::beacon::containers::shared::{AttestationData, BeaconBlockHeader, Checkpoint, Fork};
    use crate::beacon::fork::ForkName;
    use crate::beacon::gossip::execution_payload_bid::BidRules;
    use crate::beacon::gossip::proposer_preferences::PreferencesRules;
    use crate::beacon::gossip::test_support::{
        seen_aggregates, seen_attestations, slot_start_ms, store_with_config,
    };
    use crate::beacon::helpers::accessors::get_beacon_committee;
    use crate::beacon::helpers::gloas::get_ptc;
    use crate::beacon::helpers::misc::compute_domain;
    use crate::beacon::helpers::pq::initialize_aggregation_committee_window;
    use crate::beacon::helpers::test_state::with_validators_at;
    use crate::beacon::primitives::{BlsPubkey, XmssPubkey, XmssSignature};

    /// The vote block, which is also the head: the anchor root, so the store's
    /// head is it without a fork-choice run.
    const BLOCK: Root = Root::ZERO;

    fn config() -> Config {
        Config::mainnet()
            .with_fork_epoch(ForkName::Gloas, 0)
            .with_fork_epoch(ForkName::Eip8483, 0)
            .with_fork_epoch(ForkName::Pq, 0)
    }

    /// A key real over `first..=last` alone: a range key, a few hashes to
    /// build. Its public key depends on the range, so a validator signs at the
    /// leaves of one range only.
    fn key(seed: u64, first: u64, last: u64) -> lean_xmss::SecretKey {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&(seed + 1).to_le_bytes());
        lean_xmss::range_key(&bytes, first as u32, last as u32)
    }

    fn sign(secret: &lean_xmss::SecretKey, root: Root, leaf: u64) -> XmssSignature {
        let signature = secret
            .sign(&root.0, leaf as u32)
            .expect("a leaf of the range");
        XmssSignature(
            signature
                .to_bytes()
                .try_into()
                .expect("a leanXMSS signature is XMSS_SIGNATURE_SIZE bytes"),
        )
    }

    fn set_key(state: &mut BeaconState, index: ValidatorIndex, secret: &lean_xmss::SecretKey) {
        let BeaconState::Pq(inner) = state else {
            panic!("a PQ test state")
        };
        inner
            .validators
            .get_mut(index as usize)
            .expect("index is in the registry")
            .record
            .pubkey = XmssPubkey(secret.public_key().to_bytes()).to_request_key();
    }

    /// A PQ state at slot 32 (epoch 1) with 64 validators, every slot's
    /// committee two strong, under the schedule's own versions, its
    /// aggregation committee window filled.
    fn pq_state(config: &Config) -> BeaconState {
        let mut state = with_validators_at(ForkName::Pq, 64);
        *state.fork_mut() = Fork {
            previous_version: config.eip8483_fork_version,
            current_version: config.pq_fork_version,
            epoch: 0,
        };
        let window = initialize_aggregation_committee_window(&state).expect("a full window");
        let BeaconState::Pq(inner) = &mut state else {
            unreachable!("built as a PQ state")
        };
        inner.aggregation_committee_window = window;
        state.apply_pending_mutations();
        state
    }

    fn pq_block(slot: Slot) -> SignedBeaconBlock {
        SignedBeaconBlock::Pq(Box::new(pq::SignedBeaconBlock {
            message: pq::BeaconBlock {
                slot,
                proposer_index: 0,
                parent_root: Root::repeat_byte(9),
                state_root: Root::ZERO,
                body: pq::BeaconBlockBody::empty(),
            },
            signature: Default::default(),
        }))
    }

    /// A store whose vote block and head is [`BLOCK`], with `state` as its
    /// post-state.
    fn store_with(config: &Config, state: &BeaconState) -> Store {
        let mut store = store_with_config(0, config.clone());
        store
            .insert_pending_block(BLOCK, pq_block(state.slot()))
            .expect("insert the vote block");
        // Cached only: every rule reads states through the cache, and
        // `has_state` asks it first.
        let mut cached = state.clone();
        cached.apply_pending_mutations();
        store.cache_state(CacheKey::BlockState(BLOCK), Arc::new(cached));
        store
    }

    /// A vote at the state's slot for [`BLOCK`], its own target.
    fn data(state: &BeaconState) -> AttestationData {
        AttestationData {
            slot: state.slot(),
            index: 0,
            beacon_block_root: BLOCK,
            source: Checkpoint::default(),
            target: Checkpoint {
                epoch: compute_epoch_at_slot(state.slot()),
                root: BLOCK,
            },
        }
    }

    fn attestation_root(config: &Config, state: &BeaconState, data: &AttestationData) -> Root {
        let domain =
            get_domain_from_schedule(config, state, DOMAIN_BEACON_ATTESTER, data.target.epoch);
        compute_signing_root(data.hash_tree_root(), domain)
    }

    #[test]
    fn a_pq_attestation_takes_one_of_sixteen_subnets() {
        let config = config();
        assert_eq!(config.attestation_subnet_count_pq, 16);
        // Slots within the epoch under either preset.
        assert_eq!(compute_subnet_for_attestation(5, 3, 0, &config), 15);
        assert_eq!(compute_subnet_for_attestation(4, 4, 0, &config), 0);
        assert_eq!(compute_subnet_for_attestation(4, 3, 5, &config), 1);
    }

    /// A vote block far behind the attestation's epoch is not advanced: that
    /// would replay every slot between on any peer's say-so.
    #[test]
    fn a_pq_vote_for_a_block_far_behind_is_ignored_unadvanced() {
        let config = config();
        let state = pq_state(&config);
        let store = store_with(&config, &state);
        let far = compute_epoch_at_slot(state.slot()) + MAX_VOTE_STATE_ADVANCE_EPOCHS + 1;
        let mut data = data(&state);
        data.slot = compute_start_slot_at_epoch(far);
        data.target.epoch = far;
        let attestation = pq::SingleAttestation {
            committee_index: 0,
            attester_index: 0,
            data,
            signature: XmssSignature::default(),
        };
        assert_eq!(
            attestation_stateful_checks(&store, &attestation, 0),
            Outcome::Ignore(IgnoreReason::StateUnavailable)
        );
        assert!(
            store
                .cached_state(CacheKey::CheckpointState {
                    epoch: far,
                    root: BLOCK
                })
                .is_none(),
            "nothing was advanced"
        );
    }

    #[test]
    fn a_pq_attestation_is_checked_at_its_target_epochs_leaf() {
        let config = config();
        let mut state = pq_state(&config);
        let data = data(&state);
        let attester = get_beacon_committee(&state, data.slot, 0).unwrap()[0];
        let leaf = compute_xmss_attestation_leaf_index(data.target.epoch).unwrap();
        let secret = key(attester, leaf, leaf + 1);
        set_key(&mut state, attester, &secret);
        let store = store_with(&config, &state);
        let committees_per_slot = store
            .committee_cache()
            .committees(&state, data.target.epoch)
            .committees_per_slot();
        let subnet = compute_subnet_for_attestation(committees_per_slot, data.slot, 0, &config);
        let root = attestation_root(&config, &state, &data);
        let attestation = |leaf| pq::SingleAttestation {
            committee_index: 0,
            attester_index: attester,
            data,
            signature: sign(&secret, root, leaf),
        };

        assert_eq!(
            attestation_stateful_checks(&store, &attestation(leaf), subnet),
            Outcome::Accept
        );
        assert_eq!(
            attestation_stateful_checks(&store, &attestation(leaf + 1), subnet),
            Outcome::Reject(RejectReason::BadSignature),
            "signed at the next leaf"
        );
        assert_eq!(
            attestation_stateful_checks(&store, &attestation(leaf), (subnet + 1) % 16),
            Outcome::Reject(RejectReason::WrongSubnet)
        );
    }

    /// The node does not follow PQ, so on a live node the vote block's state
    /// is never a PQ one: the message is ignored, not rejected.
    #[test]
    fn a_pq_vote_for_a_block_without_a_pq_state_is_ignored() {
        let config = Config::mainnet().with_fork_epoch(ForkName::Gloas, 0);
        let state = with_validators_at(ForkName::Gloas, 64);
        let mut store = store_with_config(0, config);
        store
            .insert_pending_block(BLOCK, pq_block(state.slot()))
            .unwrap();
        store.cache_state(CacheKey::BlockState(BLOCK), Arc::new(state.clone()));
        let attestation = pq::SingleAttestation {
            committee_index: 0,
            attester_index: 0,
            data: data(&state),
            signature: XmssSignature::default(),
        };
        assert_eq!(
            attestation_stateful_checks(&store, &attestation, 0),
            Outcome::Ignore(IgnoreReason::StateUnavailable)
        );
    }

    /// An aggregate of the slot's first committee member's vote, by
    /// `aggregator`, whose proof is `proof` and whose own signature is at
    /// `aggregator_leaf`.
    fn aggregate(
        state: &BeaconState,
        config: &Config,
        aggregator: (ValidatorIndex, &lean_xmss::SecretKey),
        aggregator_leaf: u64,
        proof: Vec<u8>,
    ) -> pq::SignedAggregateAndProof {
        let data = data(state);
        let committee_len = get_beacon_committee(state, data.slot, 0).unwrap().len();
        let mut aggregation_bits = pq::AggregationBits::with_length(committee_len);
        aggregation_bits.set(0, true).unwrap();
        let mut committee_bits = pq::CommitteeBits::new();
        committee_bits.set(0, true).unwrap();
        let message = pq::AggregateAndProof {
            aggregator_index: aggregator.0,
            aggregate: pq::Attestation {
                aggregation_bits,
                data,
                committee_bits,
            },
            proof: proof.try_into().expect("far below MAX_STARK_PROOF_SIZE"),
        };
        let domain =
            get_domain_from_schedule(config, state, DOMAIN_AGGREGATE_AND_PROOF, data.target.epoch);
        let root = compute_signing_root(message.hash_tree_root(), domain);
        pq::SignedAggregateAndProof {
            signature: sign(aggregator.1, root, aggregator_leaf),
            message,
        }
    }

    #[test]
    fn a_pq_aggregate_needs_an_aggregator_its_signature_and_its_proof() {
        let config = config();
        let mut state = pq_state(&config);
        let data = data(&state);
        let committee = get_beacon_committee(&state, data.slot, 0).unwrap();
        let aggregators = get_aggregation_committee(&state, data.slot, 0).unwrap();
        let (attester, aggregator) = (committee[0], committee[1]);
        assert!(aggregators.contains(&aggregator));
        let outsider = (0..64)
            .find(|index| !aggregators.contains(index))
            .expect("a validator outside the aggregation committee");

        let vote_leaf = compute_xmss_attestation_leaf_index(data.target.epoch).unwrap();
        let attester_key = key(attester, vote_leaf, vote_leaf);
        let aggregate_leaf =
            compute_xmss_leaf_index(data.slot, LEAF_OFFSET_AGGREGATE_AND_PROOF).unwrap();
        let aggregator_key = key(aggregator, aggregate_leaf, aggregate_leaf + 1);
        let outsider_key = key(outsider, aggregate_leaf, aggregate_leaf);
        set_key(&mut state, attester, &attester_key);
        set_key(&mut state, aggregator, &aggregator_key);
        set_key(&mut state, outsider, &outsider_key);
        let store = store_with(&config, &state);

        let vote_root = attestation_root(&config, &state, &data);
        let vote = sign(&attester_key, vote_root, vote_leaf);
        let statement = stark::AggregateStatement {
            pubkeys: vec![attester_key.public_key().to_bytes()],
            leaf_index: vote_leaf,
            message: vote_root.0,
        };
        let proof = stark::prove_aggregates(&[statement], &[vec![vote.0.to_vec()]]).unwrap();

        let valid = aggregate(
            &state,
            &config,
            (aggregator, &aggregator_key),
            aggregate_leaf,
            proof.clone(),
        );
        assert_eq!(
            aggregate_stateful_checks(&store, &valid),
            Ok(vec![attester])
        );

        let wrong_leaf = aggregate(
            &state,
            &config,
            (aggregator, &aggregator_key),
            aggregate_leaf + 1,
            proof.clone(),
        );
        assert_eq!(
            aggregate_stateful_checks(&store, &wrong_leaf),
            Err(Outcome::Reject(RejectReason::AggregatorSignature))
        );

        let not_aggregator = aggregate(
            &state,
            &config,
            (outsider, &outsider_key),
            aggregate_leaf,
            proof,
        );
        assert_eq!(
            aggregate_stateful_checks(&store, &not_aggregator),
            Err(Outcome::Reject(RejectReason::NotAggregator))
        );

        let unproven = aggregate(
            &state,
            &config,
            (aggregator, &aggregator_key),
            aggregate_leaf,
            Vec::new(),
        );
        assert_eq!(
            aggregate_stateful_checks(&store, &unproven),
            Err(Outcome::Reject(RejectReason::AggregateProof))
        );
    }

    #[test]
    fn a_pq_aggregate_names_one_committee_and_carries_a_payload_flag() {
        let config = config();
        let state = pq_state(&config);
        let store = store_with(&config, &state);
        let now = slot_start_ms(&store, state.slot());
        let secret = key(1, 0, 0);
        let valid = aggregate(&state, &config, (1, &secret), 0, Vec::new());
        assert_eq!(
            aggregate_cheap_checks(&seen_aggregates(), &store, &valid, now),
            Ok(())
        );

        let mut two_committees = valid.clone();
        two_committees
            .message
            .aggregate
            .committee_bits
            .set(1, true)
            .unwrap();
        assert_eq!(
            aggregate_cheap_checks(&seen_aggregates(), &store, &two_committees, now),
            Err(Outcome::Reject(RejectReason::CommitteeBits))
        );

        let mut flag_two = valid.clone();
        flag_two.message.aggregate.data.index = 2;
        assert_eq!(
            aggregate_cheap_checks(&seen_aggregates(), &store, &flag_two, now),
            Err(Outcome::Reject(RejectReason::DataIndexOutOfRange))
        );

        // Recorded, a second aggregate with the same bits is covered.
        let mut seen = seen_aggregates();
        let key = aggregate_key(&valid).unwrap();
        assert!(seen.record_parts(&key, &aggregation_bits(&valid)));
        assert_eq!(
            aggregate_cheap_checks(&seen, &store, &valid, now),
            Err(Outcome::Ignore(IgnoreReason::CoveredBits))
        );
    }

    #[test]
    fn a_pq_attestation_with_a_payload_flag_past_one_is_rejected() {
        let config = config();
        let state = pq_state(&config);
        let store = store_with(&config, &state);
        let mut data = data(&state);
        data.index = 2;
        let attestation = pq::SingleAttestation {
            committee_index: 0,
            attester_index: 0,
            data,
            signature: XmssSignature::default(),
        };
        let now = slot_start_ms(&store, state.slot());
        assert_eq!(
            attestation_cheap_checks(&seen_attestations(), &store, &attestation, now),
            Err(Outcome::Reject(RejectReason::DataIndexOutOfRange))
        );
    }

    #[test]
    fn a_pq_proposer_slashing_is_signed_at_the_slots_proposer_leaf() {
        let config = config();
        let mut state = pq_state(&config);
        let proposer = 3;
        let slot = state.slot() - 1;
        let leaf = compute_xmss_leaf_index(slot, LEAF_OFFSET_BEACON_PROPOSER).unwrap();
        let secret = key(proposer, leaf, leaf + 1);
        set_key(&mut state, proposer, &secret);
        let store = store_with(&config, &state);
        let header = |state_root: Root| BeaconBlockHeader {
            slot,
            proposer_index: proposer,
            parent_root: Root::ZERO,
            state_root,
            body_root: Root::ZERO,
        };
        let domain = get_domain(
            &state,
            DOMAIN_BEACON_PROPOSER,
            Some(compute_epoch_at_slot(slot)),
        );
        let signed = |header: BeaconBlockHeader, leaf| pq::SignedBeaconBlockHeader {
            signature: sign(
                &secret,
                compute_signing_root(header.hash_tree_root(), domain),
                leaf,
            ),
            message: header,
        };
        let slashing = |second_leaf| pq::ProposerSlashing {
            signed_header_1: signed(header(Root::repeat_byte(1)), leaf),
            signed_header_2: signed(header(Root::repeat_byte(2)), second_leaf),
        };

        let seen = SeenOperations::default();
        assert_eq!(
            proposer_slashing_cheap_checks(&seen, &slashing(leaf)),
            Ok(())
        );
        assert_eq!(
            proposer_slashing_stateful_checks(&store, &slashing(leaf)),
            Outcome::Accept
        );
        assert_eq!(
            proposer_slashing_stateful_checks(&store, &slashing(leaf + 1)),
            Outcome::Reject(RejectReason::BadSignature)
        );
    }

    #[test]
    fn a_pq_attester_slashing_proves_both_votes() {
        let config = config();
        let mut state = pq_state(&config);
        let slashed = 5;
        let epoch = compute_epoch_at_slot(state.slot());
        let leaf = compute_xmss_attestation_leaf_index(epoch).unwrap();
        let secret = key(slashed, leaf, leaf);
        set_key(&mut state, slashed, &secret);
        let store = store_with(&config, &state);
        let vote = |root_byte: u8| {
            let mut data = data(&state);
            data.beacon_block_root = Root::repeat_byte(root_byte);
            data
        };
        let indexed = |data: AttestationData, proven: bool| {
            let domain = get_domain(&state, DOMAIN_BEACON_ATTESTER, Some(epoch));
            let root = compute_signing_root(data.hash_tree_root(), domain);
            let proof = if proven {
                sign(&secret, root, leaf).0.to_vec()
            } else {
                Vec::new()
            };
            pq::IndexedAttestation {
                attesting_indices: vec![slashed].into(),
                data,
                proof: proof.try_into().unwrap(),
            }
        };
        let slashing = |proven| pq::AttesterSlashing {
            attestation_1: indexed(vote(1), true),
            attestation_2: indexed(vote(2), proven),
        };

        let seen = SeenOperations::default();
        assert_eq!(
            attester_slashing_cheap_checks(&seen, &slashing(true)),
            Ok(())
        );
        assert_eq!(
            attester_slashing_stateful_checks(&store, &slashing(true)),
            Outcome::Accept
        );
        assert_eq!(
            attester_slashing_stateful_checks(&store, &slashing(false)),
            Outcome::Reject(RejectReason::InvalidOperation)
        );
    }

    #[test]
    fn a_pq_payload_attestation_is_signed_at_the_slots_ptc_leaf() {
        let config = config();
        let mut state = pq_state(&config);
        let slot = state.slot();
        let member = get_ptc(&state, slot, &config).unwrap()[0];
        let leaf = compute_xmss_leaf_index(slot, LEAF_OFFSET_PTC_ATTESTER).unwrap();
        let secret = key(member, leaf, leaf + 1);
        set_key(&mut state, member, &secret);
        let store = store_with(&config, &state);
        let data = gloas::PayloadAttestationData {
            beacon_block_root: BLOCK,
            slot,
            payload_present: true,
            blob_data_available: true,
        };
        let domain = get_domain(
            &state,
            DOMAIN_PTC_ATTESTER,
            Some(compute_epoch_at_slot(slot)),
        );
        let root = compute_signing_root(data.hash_tree_root(), domain);
        let message = |leaf| pq::PayloadAttestationMessage {
            validator_index: member,
            data,
            signature: sign(&secret, root, leaf),
        };
        assert_eq!(
            payload_attestation_stateful_checks(&store, &message(leaf)),
            Outcome::Accept
        );
        assert_eq!(
            payload_attestation_stateful_checks(&store, &message(leaf + 1)),
            Outcome::Reject(RejectReason::BadSignature)
        );
    }

    #[test]
    fn pq_preferences_are_signed_at_the_proposal_slots_preferences_leaf() {
        let config = config();
        let mut state = pq_state(&config);
        let proposer = 7;
        let proposal_slot = state.slot() + 1;
        let leaf =
            compute_xmss_leaf_index(proposal_slot, LEAF_OFFSET_PROPOSER_PREFERENCES).unwrap();
        let secret = key(proposer, leaf, leaf + 1);
        set_key(&mut state, proposer, &secret);
        let message = gloas::ProposerPreferences {
            proposal_slot,
            validator_index: proposer,
            ..Default::default()
        };
        let proposal_epoch = compute_epoch_at_slot(proposal_slot);
        let domain = compute_domain(
            DOMAIN_PROPOSER_PREFERENCES,
            config.fork_version(config.fork_at_epoch(proposal_epoch)),
            state.genesis_validators_root(),
        );
        let root = compute_signing_root(message.hash_tree_root(), domain);
        let signed = |leaf| pq::SignedProposerPreferences {
            message: message.clone(),
            signature: sign(&secret, root, leaf),
        };
        assert!(signed(leaf).signature_valid(&state, &config, proposal_epoch));
        assert!(!signed(leaf + 1).signature_valid(&state, &config, proposal_epoch));
        assert!(<pq::SignedProposerPreferences as PreferencesRules>::judged_by(&state));
        assert!(!<gloas::SignedProposerPreferences as PreferencesRules>::judged_by(&state));
    }

    /// `XMSSPubkey(request.pubkey[16:]) == builder.pubkey`: a request naming
    /// the key with anything in its first 16 bytes still names it.
    #[test]
    fn a_pq_builder_exit_names_its_builder_by_the_last_32_bytes() {
        let builder = XmssPubkey([7; 32]).to_request_key();
        let mut request = builder;
        request.0[0] = 1;
        assert!(<pq::SignedExecutionPayloadBid as BidRules>::exit_names(
            &request, &builder
        ));
        assert!(!<gloas::SignedExecutionPayloadBid as BidRules>::exit_names(
            &request, &builder
        ));
        let other = BlsPubkey([9; 48]);
        assert!(!<pq::SignedExecutionPayloadBid as BidRules>::exit_names(
            &other, &builder
        ));
        assert_eq!(pq::SignedExecutionPayloadBid::default().message().slot, 0);
    }

    /// A PQ bid on a PQ head runs gloas's whole rule over the PQ market: the
    /// head view, the preferences and known payload, the builder, and its
    /// XMSS signature, which only a bid leaf may carry.
    #[test]
    fn a_pq_bid_on_a_pq_head_is_accepted_at_a_bid_leaf() {
        use crate::beacon::builder_market::PqBuilderMarket;
        use crate::beacon::builder_market::test_support::envelope_with_gas_limit;
        use crate::beacon::constants::{
            DOMAIN_BEACON_BUILDER, FAR_FUTURE_EPOCH, PAYLOAD_BUILDER_VERSION,
            XMSS_ATTESTATION_LEAVES, XMSS_RESERVED_LEAVES,
        };
        use crate::beacon::fork_choice::PayloadStatus;
        use crate::beacon::gossip::execution_payload_bid as bid_rules;
        use crate::beacon::gossip::proposer_preferences::dependent_root_at;
        use crate::beacon::helpers::accessors::get_randao_mix;
        use crate::beacon::precheck::fixed_proposer;
        use crate::beacon::primitives::{ExecutionAddress, ExecutionBlockHash};

        let config = config();
        let mut state = pq_state(&config);
        let parent_hash = ExecutionBlockHash::repeat_byte(0x44);
        let gas_limit = 30_000_000;
        // The first bid leaf, and the last attestation leaf just before it.
        let bid_leaf = XMSS_RESERVED_LEAVES + XMSS_ATTESTATION_LEAVES;
        let secret = key(1_000, bid_leaf - 1, bid_leaf);
        {
            let BeaconState::Pq(inner) = &mut state else {
                unreachable!("a PQ test state")
            };
            inner.builders.0.push(gloas::Builder {
                pubkey: XmssPubkey(secret.public_key().to_bytes()).to_request_key(),
                version: PAYLOAD_BUILDER_VERSION,
                execution_address: ExecutionAddress::repeat_byte(1),
                balance: 100_000_000_000,
                deposit_epoch: 0,
                withdrawable_epoch: FAR_FUTURE_EPOCH,
            });
            // Active once the finalized epoch passes its deposit epoch.
            inner.finalized_checkpoint.epoch = 1;
            inner.latest_execution_payload_bid.block_hash = parent_hash;
        }
        state.apply_pending_mutations();
        let store = store_with(&config, &state);
        store.set_head_payload_status(BLOCK, PayloadStatus::Full);

        let bid_slot = state.slot() + 2;
        let dependent_root = dependent_root_at(&state, BLOCK, bid_slot).expect("in the window");
        let proposer = fixed_proposer(&state, bid_slot).expect("in the lookahead");
        let fee_recipient = ExecutionAddress::repeat_byte(0x11);
        let market = PqBuilderMarket::default();
        assert!(market.record_preferences(
            pq::SignedProposerPreferences {
                message: gloas::ProposerPreferences {
                    dependent_root,
                    proposal_slot: bid_slot,
                    validator_index: proposer,
                    fee_recipient,
                    target_gas_limit: gas_limit,
                },
                signature: Default::default(),
            },
            bid_slot - 1,
        ));
        market.record_execution_payload(&envelope_with_gas_limit(
            parent_hash,
            gas_limit,
            BLOCK,
            vec![],
        ));

        let message = gloas::ExecutionPayloadBid {
            parent_block_hash: parent_hash,
            parent_block_root: BLOCK,
            block_hash: ExecutionBlockHash::repeat_byte(0x33),
            prev_randao: get_randao_mix(&state, compute_epoch_at_slot(state.slot())),
            fee_recipient,
            gas_limit,
            builder_index: 0,
            slot: bid_slot,
            value: 1,
            ..Default::default()
        };
        let domain = get_domain(&state, DOMAIN_BEACON_BUILDER, None);
        let root = compute_signing_root(message.hash_tree_root(), domain);
        let signed = |leaf| pq::SignedExecutionPayloadBid {
            message: message.clone(),
            signature: sign(&secret, root, leaf),
        };

        let now = slot_start_ms(&store, bid_slot) + 100;
        assert_eq!(
            bid_rules::cheap_checks(&market, &store, &signed(bid_leaf), now),
            Ok(())
        );
        assert_eq!(
            bid_rules::stateful_checks(&store, &market, &signed(bid_leaf)),
            Outcome::Accept
        );
        assert_eq!(
            bid_rules::stateful_checks(&store, &market, &signed(bid_leaf - 1)),
            Outcome::Reject(RejectReason::BadSignature),
            "an attestation leaf"
        );
    }

    /// The gloas envelope rules against a PQ block, with PQ's request
    /// container: a block never seen is queued, and one whose slot or
    /// request root differs is refused before any signature.
    #[test]
    fn a_pq_envelope_is_matched_against_its_pq_block() {
        use crate::beacon::builder_market::test_support::envelope_with_gas_limit;
        use crate::beacon::primitives::ExecutionBlockHash;

        let config = config();
        let state = pq_state(&config);
        let store = store_with(&config, &state);
        let envelope = |block_root: Root, slot: Slot| {
            let gloas = envelope_with_gas_limit(ExecutionBlockHash::ZERO, 0, block_root, vec![]);
            let mut payload = gloas.payload;
            payload.slot_number = slot;
            pq::SignedExecutionPayloadEnvelope {
                message: pq::ExecutionPayloadEnvelope {
                    payload,
                    execution_requests: Default::default(),
                    builder_index: 0,
                    beacon_block_root: block_root,
                    parent_beacon_block_root: Root::ZERO,
                },
                signature: Default::default(),
            }
        };
        assert_eq!(
            envelope_stateful_checks(&store, &envelope(Root::repeat_byte(3), state.slot())),
            Outcome::Queue(QueueReason::BlockUnknown)
        );
        assert_eq!(
            envelope_stateful_checks(&store, &envelope(BLOCK, state.slot() + 1)),
            Outcome::Reject(RejectReason::SlotMismatch)
        );
        assert_eq!(
            envelope_stateful_checks(&store, &envelope(BLOCK, state.slot())),
            Outcome::Reject(RejectReason::ExecutionRequestsRootMismatch),
            "the block's bid commits to no requests root"
        );
    }

    #[test]
    fn pq_operation_and_request_limits_are_enforced() {
        let mut requests = pq::ExecutionRequests::default();
        assert!(execution_requests_within_limits(&requests));
        requests.voluntary_exits =
            vec![Default::default(); preset::MAX_VOLUNTARY_EXIT_REQUESTS_PER_PAYLOAD as usize + 1]
                .into();
        assert!(!execution_requests_within_limits(&requests));

        let mut body = pq::BeaconBlockBody::empty();
        assert!(body_operations_within_limits(&body));
        let config = config();
        let state = pq_state(&config);
        let attestation = aggregate(&state, &config, (0, &key(0, 0, 0)), 0, Vec::new())
            .message
            .aggregate;
        body.attestations = vec![attestation; preset::MAX_ATTESTATIONS_PQ as usize + 1].into();
        assert!(!body_operations_within_limits(&body));
    }
}
