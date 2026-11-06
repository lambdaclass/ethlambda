//! EIP-8453's ("Decoupled Consensus") new and modified helpers: the
//! specification's "Helpers" section (predicates, misc, beacon state
//! accessors, mutators) and `fork.md`'s `initialize_head_vote_committee_window`.
//!
//! Transcribed from `specs/_features/eip8453/beacon-chain.md` at
//! ethereum/consensus-specs `0f4fa3ffdd26ec083ff4dba65645d81433178413`. Each
//! function's doc names the specification function it implements; where the
//! code departs from the text for speed, the doc says why the result is the
//! same.
//!
//! # Weights
//!
//! The specification computes finality-gadget weights in `Uint256`. This
//! module uses [`Weight`] (`u128`), which cannot overflow for any state: a
//! validator's weight is at most `(u64::MAX / EFFECTIVE_BALANCE_INCREMENT) *
//! EJECTION_INACTIVITY_SCORE**2 < 2**35 * 2**32 = 2**67`, the registry holds at
//! most `VALIDATOR_REGISTRY_LIMIT = 2**40` validators, so a total is below
//! `2**107` and three times it below `2**109`. Every comparison and product
//! the specification makes therefore has the same value in `u128`; the
//! arithmetic is still checked, so the bound is enforced rather than assumed.
//!
//! # Shuffled selections
//!
//! `compute_balance_weighted_selection(..., shuffle_indices=True)` and
//! `compute_uniform_selection` draw `indices[compute_shuffled_index(i % total,
//! total, seed)]` for every draw. With one seed per call, that is the
//! whole-list shuffle [`shuffle_list`] computes once (`shuffle_list(indices,
//! seed)[i] == indices[compute_shuffled_index(i, n, seed)]`), so the draws
//! here index a pre-shuffled list instead of reshuffling per draw. The head
//! vote committee draws `HEAD_VOTE_COMMITTEE_SIZE` members per slot from the
//! whole active set, which per draw would be `SHUFFLE_ROUND_COUNT` hash pairs
//! each; `tests::shuffled_selections_match_the_per_draw_definition` pins the
//! equivalence.

use std::collections::BTreeSet;

use crate::beacon::bls;
use crate::beacon::config::Config;
use crate::beacon::constants;
use crate::beacon::containers::shared::{AttestationData as LegacyAttestationData, Validator};
use crate::beacon::containers::{BeaconState, eip8453, gloas, heze};
use crate::beacon::error::{Error, Result, verify};
use crate::beacon::hash::hash;
use crate::beacon::preset;
use crate::beacon::primitives::{
    Bytes32, Epoch, Gwei, HashTreeRoot as _, ParticipationFlags, Root, Slot, ValidatorIndex,
};

use super::accessors::{
    get_active_validator_indices, get_block_root_at_slot, get_current_epoch, get_domain, get_seed,
    get_total_active_balance, get_total_balance,
};
use super::altair::{add_flag, has_flag};
use super::math::{bytes_to_uint64, integer_squareroot};
use super::misc::{compute_epoch_at_slot, compute_signing_root, compute_start_slot_at_epoch};
use super::predicates::{are_indices_sorted_and_unique, is_active_validator};
use super::shuffling::shuffle_list;

/// A finality-gadget weight, `Uint256` in the specification. See the module
/// doc for why `u128` holds every value one can take.
pub type Weight = u128;

// ---------------------------------------------------------------------------
// State projection
// ---------------------------------------------------------------------------

/// The EIP-8453 state inside `state`, or [`Error::UnsupportedForFork`] naming
/// `function`.
pub fn eip8453_state<'a>(
    state: &'a BeaconState,
    function: &'static str,
) -> Result<&'a eip8453::BeaconState> {
    match state {
        BeaconState::Eip8453(inner) => Ok(inner),
        other => Err(Error::UnsupportedForFork {
            function,
            fork: other.fork_name(),
        }),
    }
}

/// [`eip8453_state`], mutably.
pub fn eip8453_state_mut<'a>(
    state: &'a mut BeaconState,
    function: &'static str,
) -> Result<&'a mut eip8453::BeaconState> {
    match state {
        BeaconState::Eip8453(inner) => Ok(inner),
        other => Err(Error::UnsupportedForFork {
            function,
            fork: other.fork_name(),
        }),
    }
}

// ---------------------------------------------------------------------------
// Predicates
// ---------------------------------------------------------------------------

/// `is_well_formed_attestation_data`: whether the height pair and the
/// finality pair of `data` have valid forms.
pub fn is_well_formed_attestation_data(data: &eip8453::AttestationData) -> bool {
    if data.target.height == 0 || data.target.root == Root::ZERO {
        return false;
    }
    if data.finality == eip8453::HeightCheckpoint::empty() {
        return true;
    }
    data.finality.root != Root::ZERO && data.finality.height < data.target.height
}

/// `is_valid_attestation_data`: whether `data` names the target checkpoint of
/// `state`, or is a vote below the current height whose finality pair is
/// pending.
pub fn is_valid_attestation_data(
    state: &eip8453::BeaconState,
    data: &eip8453::AttestationData,
) -> bool {
    if data.target == state.target_checkpoint {
        return true;
    }
    state
        .pending_finality
        .iter()
        .any(|pending| pending.checkpoint == data.finality)
        && data.finality.height < data.target.height
        && data.target.height < state.target_checkpoint.height
}

/// `is_valid_indexed_attestation` (modified): non-empty, at most
/// `MAX_VALIDATORS_PER_AGGREGATE` sorted and unique indices, and a valid
/// aggregate signature under `DOMAIN_FINALITY_ATTESTER` at the attestation's
/// own `epoch`.
pub fn is_valid_indexed_attestation(
    state: &BeaconState,
    indexed_attestation: &eip8453::IndexedAttestation,
) -> bool {
    let indices: &[ValidatorIndex] = &indexed_attestation.attesting_indices;
    if indices.is_empty()
        || indices.len() as u64 > preset::MAX_VALIDATORS_PER_AGGREGATE
        || !are_indices_sorted_and_unique(indices)
    {
        return false;
    }
    let mut pubkeys = Vec::with_capacity(indices.len());
    for index in indices {
        match state.validator(*index) {
            Ok(validator) => pubkeys.push(validator.pubkey),
            Err(_) => return false,
        }
    }
    let domain = get_domain(
        state,
        constants::DOMAIN_FINALITY_ATTESTER,
        Some(indexed_attestation.epoch),
    );
    let signing_root = compute_signing_root(indexed_attestation.data.hash_tree_root(), domain);
    bls::fast_aggregate_verify(&pubkeys, signing_root, &indexed_attestation.signature)
}

/// `is_double_target_vote`: whether `data_1` and `data_2` are target votes
/// for different roots at the same height.
pub fn is_double_target_vote(
    data_1: &eip8453::AttestationData,
    data_2: &eip8453::AttestationData,
) -> bool {
    if data_1.timeout {
        return false;
    }
    if data_2.timeout {
        return false;
    }
    if data_1.target.height != data_2.target.height {
        return false;
    }
    if data_1.target.root == data_2.target.root {
        return false;
    }
    true
}

/// `is_conflicting_with_finality_pair`: whether `data` votes at the height of
/// the non-empty `finality` pair without a target vote for its root.
pub fn is_conflicting_with_finality_pair(
    data: &eip8453::AttestationData,
    finality: &eip8453::HeightCheckpoint,
) -> bool {
    if *finality == eip8453::HeightCheckpoint::empty() {
        return false;
    }
    if data.target.height != finality.height {
        return false;
    }
    if data.timeout {
        return true;
    }
    if data.target.root != finality.root {
        return true;
    }
    false
}

/// `is_slashable_attestation_data` (rewritten for the finality gadget).
pub fn is_slashable_attestation_data(
    data_1: &eip8453::AttestationData,
    data_2: &eip8453::AttestationData,
) -> bool {
    if is_double_target_vote(data_1, data_2) {
        return true;
    }
    if is_conflicting_with_finality_pair(data_1, &data_2.finality) {
        return true;
    }
    if is_conflicting_with_finality_pair(data_2, &data_1.finality) {
        return true;
    }
    false
}

/// `is_slashable_legacy_attestation_data`: Casper FFG's double and surround
/// vote rules over heze's `AttestationData`, phase0's
/// `is_slashable_attestation_data` under a new name.
pub fn is_slashable_legacy_attestation_data(
    data_1: &LegacyAttestationData,
    data_2: &LegacyAttestationData,
) -> bool {
    super::predicates::is_slashable_attestation_data(data_1, data_2)
}

/// `is_valid_legacy_indexed_attestation`: heze's `is_valid_indexed_attestation`
/// under a new name. Heze's (gloas's) own check is the same rule:
/// non-empty, at most `MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT`
/// (`MAX_VALIDATORS_PER_SLOT`) sorted unique indices, and an aggregate
/// signature under `DOMAIN_BEACON_ATTESTER` at `data.target.epoch`.
pub fn is_valid_legacy_indexed_attestation(
    state: &BeaconState,
    indexed_attestation: &gloas::IndexedAttestation,
) -> bool {
    super::gloas::is_valid_indexed_attestation(state, indexed_attestation)
}

/// `is_eligible_for_activation` (modified): the validator's place in the
/// activation queue is finalized by the finality gadget's `finalized_slot`
/// rather than Casper FFG's `finalized_checkpoint.epoch`.
pub fn is_eligible_for_activation(state: &eip8453::BeaconState, validator: &Validator) -> bool {
    validator.activation_eligibility_epoch <= compute_epoch_at_slot(state.finalized_slot)
        && validator.activation_epoch == constants::FAR_FUTURE_EPOCH
}

/// `is_active_builder` (modified): the builder's place in the builder list is
/// finalized by `finalized_slot`.
pub fn is_active_builder(
    state: &eip8453::BeaconState,
    builder_index: gloas::BuilderIndex,
) -> Result<bool> {
    let builder = state
        .builders
        .get(builder_index as usize)
        .ok_or(Error::IndexOutOfBounds {
            index: builder_index as usize,
            len: state.builders.len(),
        })?;
    Ok(
        builder.deposit_epoch < compute_epoch_at_slot(state.finalized_slot)
            && builder.withdrawable_epoch == constants::FAR_FUTURE_EPOCH,
    )
}

/// `is_head_vote_same_slot`: whether `data` votes for the block proposed at
/// its slot. Fails where `get_block_root_at_slot` asserts.
pub fn is_head_vote_same_slot(state: &BeaconState, data: &eip8453::HeadVoteData) -> Result<bool> {
    if data.slot == constants::GENESIS_SLOT {
        return Ok(true);
    }
    if data.beacon_block_root != get_block_root_at_slot(state, data.slot)? {
        return Ok(false);
    }
    if data.beacon_block_root == get_block_root_at_slot(state, data.slot - 1)? {
        return Ok(false);
    }
    Ok(true)
}

/// `has_builder_payment_quorum`: whether the seats set in `participation`
/// reach the payment quorum, `BUILDER_PAYMENT_THRESHOLD_NUMERATOR /
/// BUILDER_PAYMENT_THRESHOLD_DENOMINATOR` of the committee.
pub fn has_builder_payment_quorum(participation: &eip8453::HeadVoteCommitteeBits) -> bool {
    let seats = participation.count_ones() as u64;
    let quorum =
        preset::HEAD_VOTE_COMMITTEE_SIZE as u64 * constants::BUILDER_PAYMENT_THRESHOLD_NUMERATOR;
    seats * constants::BUILDER_PAYMENT_THRESHOLD_DENOMINATOR >= quorum
}

/// `has_quorum`: whether the validators marked in `participation` hold at
/// least two thirds of the total weight of the active validators.
///
/// One pass over the registry computes both `get_participating_weight` and
/// `get_total_weight` of the active set; the values are the ones the two
/// spec functions give.
pub fn has_quorum(state: &BeaconState, participation: &[bool]) -> Result<bool> {
    let (participating_weight, total_weight) =
        participating_and_total_weight(state, participation)?;
    let lhs = participating_weight
        .checked_mul(3)
        .ok_or(Error::ArithmeticOverflow(
            "has_quorum: participating_weight * 3",
        ))?;
    let rhs = total_weight
        .checked_mul(2)
        .ok_or(Error::ArithmeticOverflow("has_quorum: total_weight * 2"))?;
    Ok(participating_weight > 0 && lhs >= rhs)
}

/// `is_in_inactivity_leak` (modified): finality has lagged more than
/// `MIN_ROUNDS_TO_INACTIVITY_LEAK` rounds.
pub fn is_in_inactivity_leak(state: &BeaconState) -> Result<bool> {
    Ok(get_finality_delay(state)? > preset::MIN_ROUNDS_TO_INACTIVITY_LEAK)
}

/// `is_valid_aggregation_bits`: whether `aggregate.aggregation_bits` has one
/// bit per member of the attestation committees its `committee_bits` names,
/// within `MAX_VALIDATORS_PER_AGGREGATE`.
pub fn is_valid_aggregation_bits(
    state: &BeaconState,
    epoch: Epoch,
    aggregate: &eip8453::Attestation,
) -> Result<bool> {
    let active = get_active_validator_indices(state, epoch);
    let mut committees_size: u64 = 0;
    for committee_index in get_committee_indices(&aggregate.committee_bits) {
        let size = attestation_committee_from(&active, epoch, committee_index)?.len() as u64;
        committees_size = committees_size
            .checked_add(size)
            .ok_or(Error::ArithmeticOverflow(
                "is_valid_aggregation_bits: committees_size",
            ))?;
    }
    if committees_size > preset::MAX_VALIDATORS_PER_AGGREGATE {
        return Ok(false);
    }
    Ok(aggregate.aggregation_bits.len() as u64 == committees_size)
}

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

/// `compute_round_at_slot`.
pub fn compute_round_at_slot(slot: Slot) -> eip8453::Round {
    slot / preset::SLOTS_PER_ROUND
}

/// `compute_start_slot_at_round`. A `uint64` product in the specification, so
/// an overflow is an error.
pub fn compute_start_slot_at_round(round: eip8453::Round) -> Result<Slot> {
    round
        .checked_mul(preset::SLOTS_PER_ROUND)
        .ok_or(Error::ArithmeticOverflow(
            "compute_start_slot_at_round: round * SLOTS_PER_ROUND",
        ))
}

/// `compute_attestation_committee_slot`: the slot of `round` the committee at
/// `index` attests in, `ATTESTATION_COMMITTEES_PER_ROUND // SLOTS_PER_ROUND`
/// committees per slot, in order.
pub fn compute_attestation_committee_slot(
    round: eip8453::Round,
    index: crate::beacon::primitives::CommitteeIndex,
) -> Result<Slot> {
    let committees_per_slot =
        preset::ATTESTATION_COMMITTEES_PER_ROUND as u64 / preset::SLOTS_PER_ROUND;
    compute_start_slot_at_round(round)?
        .checked_add(index / committees_per_slot)
        .ok_or(Error::ArithmeticOverflow(
            "compute_attestation_committee_slot: start + index // committees_per_slot",
        ))
}

/// `compute_uniform_selection`: `size` indices sampled uniformly from
/// `indices` by shuffling, with duplicates only when `size` exceeds
/// `len(indices)`. See the module doc for why this indexes one whole-list
/// shuffle.
pub fn compute_uniform_selection(
    indices: &[ValidatorIndex],
    seed: Bytes32,
    size: u64,
) -> Result<Vec<ValidatorIndex>> {
    let total = indices.len() as u64;
    verify(total > 0, "compute_uniform_selection: total > 0")?;
    let shuffled = shuffle_list(indices.to_vec(), seed);
    Ok((0..size).map(|i| shuffled[(i % total) as usize]).collect())
}

/// `compute_balance_weighted_selection(state, indices, seed, size,
/// shuffle_indices=True)`, gloas's selection, through one whole-list shuffle
/// (see the module doc). [`super::gloas::compute_balance_weighted_selection`]
/// is the spec-literal version this is tested against.
pub fn compute_shuffled_balance_weighted_selection(
    state: &BeaconState,
    indices: &[ValidatorIndex],
    seed: Bytes32,
    size: u64,
) -> Result<Vec<ValidatorIndex>> {
    // `2**16 - 1`, the largest value a two-byte little-endian draw can take.
    const MAX_RANDOM_VALUE: u64 = u16::MAX as u64;

    let total = indices.len() as u64;
    verify(total > 0, "compute_balance_weighted_selection: total > 0")?;

    let shuffled = shuffle_list(indices.to_vec(), seed);
    let mut effective_balances = Vec::with_capacity(shuffled.len());
    for index in &shuffled {
        effective_balances.push(state.validator(*index)?.effective_balance);
    }

    let mut selected = Vec::with_capacity(size as usize);
    let mut random_bytes = Bytes32::ZERO;
    let mut i: u64 = 0;
    while (selected.len() as u64) < size {
        let offset = (i % 16) * 2;
        if offset == 0 {
            let mut input = Vec::with_capacity(32 + 8);
            input.extend_from_slice(&seed.0);
            input.extend_from_slice(&(i / 16).to_le_bytes());
            random_bytes = hash(&input);
        }
        let next = (i % total) as usize;
        let weight = effective_balances[next]
            .checked_mul(MAX_RANDOM_VALUE)
            .ok_or(Error::ArithmeticOverflow(
                "compute_balance_weighted_selection: effective_balance * MAX_RANDOM_VALUE",
            ))?;
        let random_value = bytes_to_uint64(&random_bytes.0[offset as usize..offset as usize + 2]);
        if weight >= preset::MAX_EFFECTIVE_BALANCE_ELECTRA * random_value {
            selected.push(shuffled[next]);
        }
        i = i.checked_add(1).ok_or(Error::ArithmeticOverflow(
            "compute_balance_weighted_selection: i",
        ))?;
    }
    Ok(selected)
}

/// `sha256(get_seed(state, epoch, domain) + uint_to_bytes(slot))`, the
/// per-slot seed `compute_ptc` and `compute_head_vote_committee` both draw
/// under.
fn slot_seed(
    state: &BeaconState,
    slot: Slot,
    domain: crate::beacon::primitives::DomainType,
) -> Bytes32 {
    let epoch = compute_epoch_at_slot(slot);
    let mut input = Vec::with_capacity(32 + 8);
    input.extend_from_slice(&get_seed(state, epoch, domain).0);
    input.extend_from_slice(&slot.to_le_bytes());
    hash(&input)
}

/// `compute_ptc` (modified): the payload timeliness committee for `slot`,
/// drawn by effective balance from the whole active set of its epoch with
/// shuffling, rather than from the slot's beacon committees in order.
pub fn compute_ptc(state: &BeaconState, slot: Slot) -> Result<gloas::PayloadTimelinessCommittee> {
    let seed = slot_seed(state, slot, constants::DOMAIN_PTC_ATTESTER);
    let indices = get_active_validator_indices(state, compute_epoch_at_slot(slot));
    let selected = compute_shuffled_balance_weighted_selection(
        state,
        &indices,
        seed,
        preset::PTC_SIZE as u64,
    )?;
    Ok(selected.try_into()?)
}

/// `compute_head_vote_committee`: the head vote committee for `slot`, with
/// possible duplicates.
pub fn compute_head_vote_committee(
    state: &BeaconState,
    slot: Slot,
) -> Result<eip8453::HeadVoteCommittee> {
    let seed = slot_seed(state, slot, constants::DOMAIN_HEAD_VOTE_COMMITTEE);
    let indices = get_active_validator_indices(state, compute_epoch_at_slot(slot));
    let selected = compute_shuffled_balance_weighted_selection(
        state,
        &indices,
        seed,
        preset::HEAD_VOTE_COMMITTEE_SIZE as u64,
    )?;
    Ok(selected.try_into()?)
}

/// `initialize_head_vote_committee_window` (`fork.md`): empty committees for
/// the previous epoch, then the computed ones for the current epoch and
/// `MIN_SEED_LOOKAHEAD` epochs after it.
pub fn initialize_head_vote_committee_window(
    state: &BeaconState,
) -> Result<eip8453::HeadVoteCommitteeWindow> {
    let mut committees =
        vec![eip8453::empty_head_vote_committee(); preset::SLOTS_PER_EPOCH as usize];
    let current_epoch = get_current_epoch(state);
    let start_slot = compute_start_slot_at_epoch(current_epoch);
    let end_slot = compute_start_slot_at_epoch(current_epoch + preset::MIN_SEED_LOOKAHEAD + 1);
    for slot in start_slot..end_slot {
        committees.push(compute_head_vote_committee(state, slot)?);
    }
    Ok(committees.try_into()?)
}

// ---------------------------------------------------------------------------
// Beacon state accessors
// ---------------------------------------------------------------------------

/// `get_current_round`.
pub fn get_current_round(state: &BeaconState) -> eip8453::Round {
    compute_round_at_slot(state.slot())
}

/// `get_previous_round`: the previous round, or `GENESIS_ROUND` if that is the
/// current round.
pub fn get_previous_round(state: &BeaconState) -> eip8453::Round {
    let current_round = get_current_round(state);
    if current_round == constants::GENESIS_ROUND {
        return constants::GENESIS_ROUND;
    }
    current_round - 1
}

/// The set bits of `committee_bits`, ascending: electra's
/// `get_committee_indices`, over this fork's wider bitvector.
pub fn get_committee_indices(
    committee_bits: &eip8453::AttestationCommitteeBits,
) -> Vec<crate::beacon::primitives::CommitteeIndex> {
    (0..committee_bits.len())
        .filter(|&index| committee_bits.get(index).unwrap_or(false))
        .map(|index| index as u64)
        .collect()
}

/// `get_attestation_committee`'s body over an already computed active set,
/// so a caller asking for several committees of one epoch scans the registry
/// once.
fn attestation_committee_from(
    active: &[ValidatorIndex],
    epoch: Epoch,
    index: crate::beacon::primitives::CommitteeIndex,
) -> Result<Vec<ValidatorIndex>> {
    let count = active.len() as u64;
    let committees = preset::ATTESTATION_COMMITTEES_PER_ROUND as u64;
    let overflow = Error::ArithmeticOverflow("get_attestation_committee: committee bounds");
    let start = count.checked_mul(index).ok_or(Error::ArithmeticOverflow(
        "get_attestation_committee: committee bounds",
    ))? / committees;
    let end = index
        .checked_add(1)
        .and_then(|next| count.checked_mul(next))
        .ok_or(overflow)?
        / committees;
    let mut committee = Vec::with_capacity(end.saturating_sub(start) as usize);
    for position in start..end {
        let rotated = position
            .checked_add(epoch)
            .ok_or(Error::ArithmeticOverflow(
                "get_attestation_committee: position + epoch",
            ))?;
        committee.push(active[(rotated % count) as usize]);
    }
    Ok(committee)
}

/// `get_attestation_committee`: the attestation committee at `index` for
/// `epoch`. The active validators are not shuffled: they are split evenly into
/// `ATTESTATION_COMMITTEES_PER_ROUND` committees in index order, rotated by
/// `epoch`.
pub fn get_attestation_committee(
    state: &BeaconState,
    epoch: Epoch,
    index: crate::beacon::primitives::CommitteeIndex,
) -> Result<eip8453::AttestationCommittee> {
    let active = get_active_validator_indices(state, epoch);
    Ok(attestation_committee_from(&active, epoch, index)?.into())
}

/// `get_aggregate_participants`: the validators marked in
/// `aggregate.aggregation_bits`, which concatenates the attestation committees
/// its `committee_bits` names for `epoch`. A bit past the end of
/// `aggregation_bits` is an error, as the specification's indexing is.
pub fn get_aggregate_participants(
    state: &BeaconState,
    epoch: Epoch,
    aggregate: &eip8453::Attestation,
) -> Result<BTreeSet<ValidatorIndex>> {
    let active = get_active_validator_indices(state, epoch);
    let mut participants = BTreeSet::new();
    let mut committee_offset = 0usize;
    for committee_index in get_committee_indices(&aggregate.committee_bits) {
        let committee = attestation_committee_from(&active, epoch, committee_index)?;
        for (i, validator_index) in committee.iter().enumerate() {
            let position = committee_offset + i;
            let bit = aggregate
                .aggregation_bits
                .get(position)
                .ok_or(Error::IndexOutOfBounds {
                    index: position,
                    len: aggregate.aggregation_bits.len(),
                })?;
            if bit {
                participants.insert(*validator_index);
            }
        }
        committee_offset += committee.len();
    }
    Ok(participants)
}

/// `get_attesting_indices` (modified): the participants of `attestation` for
/// its own `epoch`.
pub fn get_attesting_indices(
    state: &BeaconState,
    attestation: &eip8453::Attestation,
) -> Result<BTreeSet<ValidatorIndex>> {
    get_aggregate_participants(state, attestation.epoch, attestation)
}

/// `get_indexed_attestation` (modified): carries the attestation's `epoch`.
pub fn get_indexed_attestation(
    state: &BeaconState,
    attestation: &eip8453::Attestation,
) -> Result<eip8453::IndexedAttestation> {
    let attesting_indices: Vec<ValidatorIndex> = get_attesting_indices(state, attestation)?
        .into_iter()
        .collect();
    Ok(eip8453::IndexedAttestation {
        attesting_indices: attesting_indices.into(),
        data: attestation.data,
        signature: attestation.signature,
        epoch: attestation.epoch,
    })
}

/// `get_head_vote_committee`: the cached head vote committee for `slot`,
/// whose epoch must be the state's own, the previous one, or within
/// `MIN_SEED_LOOKAHEAD` epochs ahead, and not before the fork.
pub fn get_head_vote_committee(
    state: &BeaconState,
    slot: Slot,
    config: &Config,
) -> Result<eip8453::HeadVoteCommittee> {
    let inner = eip8453_state(state, "get_head_vote_committee")?;
    let epoch = compute_epoch_at_slot(slot);
    verify(
        epoch >= config.eip8453_fork_epoch,
        "get_head_vote_committee: epoch >= EIP8453_FORK_EPOCH",
    )?;
    let state_epoch = get_current_epoch(state);
    let slot_in_epoch = (slot % preset::SLOTS_PER_EPOCH) as usize;
    let index = if epoch < state_epoch {
        verify(
            epoch + 1 == state_epoch,
            "get_head_vote_committee: epoch + 1 == state_epoch",
        )?;
        slot_in_epoch
    } else {
        let bound = state_epoch.checked_add(preset::MIN_SEED_LOOKAHEAD).ok_or(
            Error::ArithmeticOverflow("get_head_vote_committee: state_epoch + MIN_SEED_LOOKAHEAD"),
        )?;
        verify(
            epoch <= bound,
            "get_head_vote_committee: epoch <= state_epoch + MIN_SEED_LOOKAHEAD",
        )?;
        // `epoch - state_epoch + 1` is at most `MIN_SEED_LOOKAHEAD + 1` here.
        ((epoch - state_epoch + 1) * preset::SLOTS_PER_EPOCH) as usize + slot_in_epoch
    };
    inner
        .head_vote_committee_window
        .get(index)
        .cloned()
        .ok_or(Error::IndexOutOfBounds {
            index,
            len: inner.head_vote_committee_window.len(),
        })
}

/// `get_inclusion_list_committee` (modified): `INCLUSION_LIST_COMMITTEE_SIZE`
/// members drawn uniformly from the epoch's whole active set, rather than the
/// slot's beacon committees concatenated and cycled.
pub fn get_inclusion_list_committee(
    state: &BeaconState,
    slot: Slot,
) -> Result<heze::InclusionListCommittee> {
    let seed = slot_seed(state, slot, constants::DOMAIN_INCLUSION_LIST_COMMITTEE);
    let indices = get_active_validator_indices(state, compute_epoch_at_slot(slot));
    let selected =
        compute_uniform_selection(&indices, seed, preset::INCLUSION_LIST_COMMITTEE_SIZE as u64)?;
    Ok(selected.try_into()?)
}

/// `get_unslashed_participating_indices` (rewritten): the active, unslashed
/// validators whose current round participation has `flag_index`, ascending.
pub fn get_unslashed_participating_indices(
    state: &BeaconState,
    flag_index: usize,
) -> Result<Vec<ValidatorIndex>> {
    let inner = eip8453_state(state, "get_unslashed_participating_indices")?;
    let epoch = get_current_epoch(state);
    let mut indices = Vec::new();
    for (index, validator) in state.iter_validators().enumerate() {
        if !is_active_validator(validator, epoch) {
            continue;
        }
        let flags = *inner
            .round_participation
            .get(index)
            .ok_or(Error::IndexOutOfBounds {
                index,
                len: inner.round_participation.len(),
            })?;
        if has_flag(flags, flag_index) && !validator.slashed {
            indices.push(index as ValidatorIndex);
        }
    }
    Ok(indices)
}

/// A validator's weight from its effective balance and inactivity score, the
/// body of `get_validator_weight`.
fn validator_weight(validator: &Validator, inactivity_score: u64) -> Weight {
    let increments =
        Weight::from(validator.effective_balance / preset::EFFECTIVE_BALANCE_INCREMENT);
    let score = Weight::from(inactivity_score.min(preset::EJECTION_INACTIVITY_SCORE));
    let ejection = Weight::from(preset::EJECTION_INACTIVITY_SCORE);
    // `score <= ejection`, so neither factor underflows, and the product is
    // below `2**35 * 2**32` (see the module doc).
    increments * ((ejection - score) * (ejection + score))
}

/// `get_validator_weight`: the validator's current effective balance in
/// increments, times `EJECTION_INACTIVITY_SCORE**2 - inactivity_score**2`.
pub fn get_validator_weight(state: &BeaconState, index: ValidatorIndex) -> Result<Weight> {
    let inner = eip8453_state(state, "get_validator_weight")?;
    let validator = state.validator(index)?;
    let score = *inner
        .inactivity_scores
        .get(index as usize)
        .ok_or(Error::IndexOutOfBounds {
            index: index as usize,
            len: inner.inactivity_scores.len(),
        })?;
    Ok(validator_weight(validator, score))
}

/// `get_total_weight`: the combined weight of `indices`, each counted once
/// (the specification's argument is a set).
pub fn get_total_weight(state: &BeaconState, indices: &BTreeSet<ValidatorIndex>) -> Result<Weight> {
    let mut total: Weight = 0;
    for index in indices {
        total = total
            .checked_add(get_validator_weight(state, *index)?)
            .ok_or(Error::ArithmeticOverflow("get_total_weight"))?;
    }
    Ok(total)
}

/// One pass over the registry: the weight of the active, unslashed
/// validators `participation` marks (`get_participating_weight`), and the
/// weight of every active validator (`get_total_weight` of the current
/// epoch's active set), as `has_quorum` reads them.
fn participating_and_total_weight(
    state: &BeaconState,
    participation: &[bool],
) -> Result<(Weight, Weight)> {
    let inner = eip8453_state(state, "has_quorum")?;
    let epoch = get_current_epoch(state);
    let mut participating: Weight = 0;
    let mut total: Weight = 0;
    for (index, validator) in state.iter_validators().enumerate() {
        if !is_active_validator(validator, epoch) {
            continue;
        }
        let score = *inner
            .inactivity_scores
            .get(index)
            .ok_or(Error::IndexOutOfBounds {
                index,
                len: inner.inactivity_scores.len(),
            })?;
        let weight = validator_weight(validator, score);
        total = total
            .checked_add(weight)
            .ok_or(Error::ArithmeticOverflow("get_total_weight"))?;
        let participates = *participation.get(index).ok_or(Error::IndexOutOfBounds {
            index,
            len: participation.len(),
        })?;
        if participates && !validator.slashed {
            participating = participating
                .checked_add(weight)
                .ok_or(Error::ArithmeticOverflow("get_participating_weight"))?;
        }
    }
    Ok((participating, total))
}

/// `get_participating_weight`: the combined weight of the active, unslashed
/// validators marked in `participation`.
pub fn get_participating_weight(state: &BeaconState, participation: &[bool]) -> Result<Weight> {
    Ok(participating_and_total_weight(state, participation)?.0)
}

/// `get_finality_delay` (rewritten): the delay in rounds between the previous
/// round and the finalized slot's round, stopping at zero.
pub fn get_finality_delay(state: &BeaconState) -> Result<eip8453::Round> {
    let inner = eip8453_state(state, "get_finality_delay")?;
    let previous_round = get_previous_round(state);
    let finalized_round = compute_round_at_slot(inner.finalized_slot);
    if finalized_round > previous_round {
        return Ok(0);
    }
    Ok(previous_round - finalized_round)
}

/// `get_round_base_reward`'s body, given `get_total_active_balance(state)`,
/// which is the same for every validator of one call.
pub(crate) fn round_base_reward(effective_balance: Gwei, total_active_balance: Gwei) -> Gwei {
    let increments = effective_balance / preset::EFFECTIVE_BALANCE_INCREMENT;
    // `get_total_active_balance` is floored at one increment, so the root is
    // never zero.
    let total_balance_root = integer_squareroot(total_active_balance);
    let reward_per_increment =
        preset::EFFECTIVE_BALANCE_INCREMENT * preset::ROUND_REWARD_FACTOR / total_balance_root;
    increments * reward_per_increment
}

/// `get_round_base_reward`: the base reward for one round of the validator at
/// `index`.
pub fn get_round_base_reward(state: &BeaconState, index: ValidatorIndex) -> Result<Gwei> {
    let effective_balance = state.validator(index)?.effective_balance;
    Ok(round_base_reward(
        effective_balance,
        get_total_active_balance(state)?,
    ))
}

/// `get_flag_index_rewards`: each validator's reward for `flag_index` this
/// round, indexed by validator. No rewards during an inactivity leak, and
/// none (no penalty either) for a validator without the flag.
pub fn get_flag_index_rewards(state: &BeaconState, flag_index: usize) -> Result<Vec<Gwei>> {
    let mut rewards = vec![0; state.validator_count()];
    if is_in_inactivity_leak(state)? {
        return Ok(rewards);
    }

    let unslashed_participating_indices = get_unslashed_participating_indices(state, flag_index)?;
    let weight = *constants::PARTICIPATION_FLAG_WEIGHTS_EIP8453
        .get(flag_index)
        .ok_or(Error::IndexOutOfBounds {
            index: flag_index,
            len: constants::PARTICIPATION_FLAG_WEIGHTS_EIP8453.len(),
        })?;
    let unslashed_participating_balance =
        get_total_balance(state, &unslashed_participating_indices)?;
    let unslashed_participating_increments =
        unslashed_participating_balance / preset::EFFECTIVE_BALANCE_INCREMENT;
    let total_active_balance = get_total_active_balance(state)?;
    let active_increments = total_active_balance / preset::EFFECTIVE_BALANCE_INCREMENT;
    let reward_denominator = active_increments
        .checked_mul(constants::WEIGHT_DENOMINATOR)
        .ok_or(Error::ArithmeticOverflow(
            "get_flag_index_rewards: active_increments * WEIGHT_DENOMINATOR",
        ))?;
    for index in unslashed_participating_indices {
        let base_reward = round_base_reward(
            state.validator(index)?.effective_balance,
            total_active_balance,
        );
        let reward_numerator = base_reward
            .checked_mul(weight)
            .and_then(|product| product.checked_mul(unslashed_participating_increments))
            .ok_or(Error::ArithmeticOverflow(
                "get_flag_index_rewards: base_reward * weight * unslashed_participating_increments",
            ))?;
        let reward = &mut rewards[index as usize];
        *reward = reward
            .checked_add(reward_numerator / reward_denominator)
            .ok_or(Error::ArithmeticOverflow(
                "get_flag_index_rewards: rewards[index]",
            ))?;
    }
    Ok(rewards)
}

// ---------------------------------------------------------------------------
// Beacon state mutators
// ---------------------------------------------------------------------------

/// `add_participation_flag`: sets `flag_index` in the current round
/// participation of the validator at `index`.
pub fn add_participation_flag(
    state: &mut eip8453::BeaconState,
    index: ValidatorIndex,
    flag_index: usize,
) -> Result<()> {
    let len = state.round_participation.len();
    let flags: &mut ParticipationFlags =
        state
            .round_participation
            .get_mut(index as usize)
            .ok_or(Error::IndexOutOfBounds {
                index: index as usize,
                len,
            })?;
    *flags = add_flag(*flags, flag_index);
    Ok(())
}

