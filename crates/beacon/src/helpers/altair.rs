//! Altair's helper functions.
//!
//! Altair's two headline changes are sync committees and a rewrite of how
//! attestations earn a reward. [`get_next_sync_committee_indices`] and
//! [`get_next_sync_committee`] draw the rotating committee that lets a light
//! client follow the chain's head from a single aggregate signature rather
//! than replaying the whole state transition. Everything else here replaces
//! phase0's accumulate-then-replay `PendingAttestation`s with three
//! per-validator, per-epoch bits (a [`ParticipationFlags`]): [`add_flag`] and
//! [`has_flag`] are the bit operations, [`get_attestation_participation_flag_indices`]
//! is where an attestation earns its flags at processing time instead of
//! waiting for the epoch boundary the way phase0 does, and
//! [`get_unslashed_participating_indices`], [`get_flag_index_deltas`], and
//! [`get_inactivity_penalty_deltas`] are the epoch-boundary reward and penalty
//! accounting that reads those flags back.
//!
//! [`get_eligible_validator_indices`](crate::stf::epoch::rewards::get_eligible_validator_indices)
//! and [`is_in_inactivity_leak`](crate::stf::epoch::rewards::is_in_inactivity_leak)
//! are reused from phase0's rewards module rather than redefined here: the
//! specification does not modify either of them in altair, and both are
//! already written against `BeaconState`'s fork-invariant accessors rather
//! than phase0's concrete struct, so nothing about them is phase0-specific.
//!
//! # Why some functions take `config` and others do not
//!
//! Every quantity these functions read is either a specification constant, a
//! preset value, or (for [`get_inactivity_penalty_deltas`]'s
//! `INACTIVITY_SCORE_BIAS`) a configuration value: the altair specification's
//! own tables list it under "Configuration" rather than "Preset", since a
//! network is free to retune how fast an inactive validator's score rises
//! without changing the shape of any SSZ container. That is the only function
//! below that takes a [`Config`]; the rest need nothing a network could vary.

use crate::bls;
use crate::config::Config;
use crate::constants;
use crate::containers::shared::AttestationData;
use crate::containers::{BeaconState, altair};
use crate::error::{Error, Result};
use crate::hash::hash;
use crate::preset;
use crate::primitives::{Epoch, Gwei, ParticipationFlags, ValidatorIndex};
use crate::stf::epoch::rewards::{get_eligible_validator_indices, is_in_inactivity_leak};

use super::accessors::{
    get_active_validator_indices, get_block_root, get_block_root_at_slot, get_current_epoch,
    get_previous_epoch, get_seed, get_total_active_balance, get_total_balance,
};
use super::math::integer_squareroot;
use super::shuffling::compute_shuffled_index;

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

/// Sets `flag_index`'s bit in `flags`, leaving every other bit as it was.
pub fn add_flag(flags: ParticipationFlags, flag_index: usize) -> ParticipationFlags {
    let flag = 1u8 << flag_index;
    flags | flag
}

/// Whether `flag_index`'s bit is set in `flags`.
pub fn has_flag(flags: ParticipationFlags, flag_index: usize) -> bool {
    let flag = 1u8 << flag_index;
    flags & flag == flag
}

// ---------------------------------------------------------------------------
// Beacon state accessors
// ---------------------------------------------------------------------------

/// The sync committee indices, with possible duplicates, for the sync
/// committee period starting next epoch.
///
/// Rejection sampling weighted by effective balance, the same shape as
/// [`super::shuffling::compute_proposer_index`]: a candidate is drawn
/// uniformly from the shuffled active set and accepted with probability
/// proportional to its effective balance. The difference is that this keeps
/// drawing until it has accepted `SYNC_COMMITTEE_SIZE` candidates rather than
/// stopping at the first one, and it never deduplicates, so the same
/// validator can end up holding more than one of the committee's seats. Both
/// of those are load-bearing: a committee member's voting weight is meant to
/// scale with effective balance, and giving a heavy validator more than one
/// seat (in expectation) is how that happens without the committee itself
/// tracking per-seat weights.
pub fn get_next_sync_committee_indices(state: &BeaconState) -> Result<Vec<ValidatorIndex>> {
    let epoch = get_current_epoch(state) + 1;

    // `2**8 - 1`, the largest value a single random byte can take. Named
    // rather than left as a literal, matching `compute_proposer_index`'s
    // identical rejection-sampling shape.
    const MAX_RANDOM_BYTE: u64 = u8::MAX as u64;

    let active_validator_indices = get_active_validator_indices(state, epoch);
    let active_validator_count = active_validator_indices.len() as u64;
    crate::verify(
        active_validator_count > 0,
        "len(active_validator_indices) > 0",
    )?;
    let seed = get_seed(state, epoch, constants::DOMAIN_SYNC_COMMITTEE);

    let mut i: u64 = 0;
    let mut sync_committee_indices = Vec::with_capacity(preset::SYNC_COMMITTEE_SIZE);
    while sync_committee_indices.len() < preset::SYNC_COMMITTEE_SIZE {
        let shuffled_index =
            compute_shuffled_index(i % active_validator_count, active_validator_count, seed)?;
        // `shuffled_index` is mathematically guaranteed to be within
        // `active_validator_indices`, since `compute_shuffled_index` returns a
        // permutation of `0..active_validator_count`; indexed directly here
        // rather than defensively, the same way `compute_proposer_index` reads
        // its own shuffled candidate.
        let candidate_index = active_validator_indices[shuffled_index as usize];

        let mut random_input = Vec::with_capacity(32 + 8);
        random_input.extend_from_slice(&seed.0);
        random_input.extend_from_slice(&(i / 32).to_le_bytes());
        let random_byte = hash(&random_input).0[(i % 32) as usize] as u64;

        let effective_balance = state.validator(candidate_index)?.effective_balance;
        if effective_balance * MAX_RANDOM_BYTE >= preset::MAX_EFFECTIVE_BALANCE * random_byte {
            sync_committee_indices.push(candidate_index);
        }
        i += 1;
    }
    Ok(sync_committee_indices)
}

/// The sync committee for the period starting next epoch, with possible
/// pubkey duplicates.
///
/// Only meant to be called at a sync committee period boundary (or when
/// upgrading a state to altair): calling it at any other slot still returns
/// an answer, but not one anything reads, since `current_sync_committee` and
/// `next_sync_committee` only change at that boundary.
pub fn get_next_sync_committee(state: &BeaconState) -> Result<altair::SyncCommittee> {
    let indices = get_next_sync_committee_indices(state)?;
    let mut pubkeys = Vec::with_capacity(indices.len());
    for index in &indices {
        pubkeys.push(state.validator(*index)?.pubkey);
    }
    let aggregate_pubkey = bls::eth_aggregate_pubkeys(&pubkeys)?;
    Ok(altair::SyncCommittee {
        pubkeys: pubkeys.try_into()?,
        aggregate_pubkey,
    })
}

/// The reward every one-increment slice of a validator's effective balance
/// earns for a single timely, correct component of its attestation.
///
/// Phase0 computes a reward proportional to the validator's whole effective
/// balance and divides the result by `BASE_REWARDS_PER_EPOCH` to split it
/// across the source, target, and head components. Altair instead scales
/// from this smaller, per-increment unit and multiplies back up by the
/// validator's own increment count in [`get_base_reward`], which is what lets
/// [`get_flag_index_deltas`] weight a flag's reward by how many increments of
/// stake actually earned it rather than assuming every attestation splits the
/// same fixed fraction.
pub fn get_base_reward_per_increment(state: &BeaconState) -> Result<Gwei> {
    let total_active_balance = get_total_active_balance(state)?;
    Ok(
        preset::EFFECTIVE_BALANCE_INCREMENT * preset::BASE_REWARD_FACTOR
            / integer_squareroot(total_active_balance),
    )
}

/// The base reward for the validator at `index`.
///
/// Altair's version of this function: it drops phase0's division by
/// `BASE_REWARDS_PER_EPOCH` (there is no fixed four-way split of a fixed
/// reward any more, since [`get_flag_index_deltas`] weighs each flag by
/// [`crate::constants::PARTICIPATION_FLAG_WEIGHTS`] instead) and reads
/// [`get_base_reward_per_increment`] rather than the total active balance
/// directly. See [`crate::stf::epoch::rewards::get_base_reward`] for phase0's
/// version; the two coexist in different modules rather than one replacing
/// the other, since fork dispatch happens at the call site, not here.
pub fn get_base_reward(state: &BeaconState, index: ValidatorIndex) -> Result<Gwei> {
    let effective_balance = state.validator(index)?.effective_balance;
    let increments = effective_balance / preset::EFFECTIVE_BALANCE_INCREMENT;
    Ok(increments * get_base_reward_per_increment(state)?)
}

/// The active, unslashed validators that had `flag_index` set for `epoch`.
///
/// `epoch` must be the current or previous epoch, since those are the only
/// two altair keeps a participation record for (`current_epoch_participation`
/// and `previous_epoch_participation`, mirroring the two-epoch window phase0
/// keeps for `PendingAttestation`s).
///
/// Ascending and duplicate-free: it is built by filtering
/// [`get_active_validator_indices`], which already returns indices in that
/// order, so callers may binary-search it the way
/// [`get_flag_index_deltas`] does.
pub fn get_unslashed_participating_indices(
    state: &BeaconState,
    flag_index: usize,
    epoch: Epoch,
) -> Result<Vec<ValidatorIndex>> {
    crate::verify(
        epoch == get_previous_epoch(state) || epoch == get_current_epoch(state),
        "epoch in (get_previous_epoch(state), get_current_epoch(state))",
    )?;

    let altair_state = altair_state_ref(state, "get_unslashed_participating_indices")?;
    let epoch_participation = if epoch == get_current_epoch(state) {
        &altair_state.current_epoch_participation
    } else {
        &altair_state.previous_epoch_participation
    };

    let mut participating_indices = Vec::new();
    for index in get_active_validator_indices(state, epoch) {
        let flags =
            epoch_participation
                .get(index as usize)
                .copied()
                .ok_or(Error::IndexOutOfBounds {
                    index: index as usize,
                    len: epoch_participation.len(),
                })?;
        if has_flag(flags, flag_index) && !state.validator(index)?.slashed {
            participating_indices.push(index);
        }
    }
    Ok(participating_indices)
}

/// Which of the three participation flags an attestation with `data`,
/// included after `inclusion_delay` slots, satisfies.
///
/// The three checks nest: a target vote can only be timely-and-correct if the
/// source vote already was, and a head vote can only be timely-and-correct if
/// the target vote already was. That nesting is what `is_matching_target`
/// and `is_matching_head` encode by including the previous check in their own
/// condition, rather than the three being independent.
///
/// Fails if the source does not match the justified checkpoint the target's
/// epoch should have voted from: the specification asserts this
/// unconditionally, so a caller (`process_attestation`, not implemented in
/// this file) is expected to have already rejected such an attestation before
/// this runs.
pub fn get_attestation_participation_flag_indices(
    state: &BeaconState,
    data: &AttestationData,
    inclusion_delay: u64,
) -> Result<Vec<usize>> {
    // Matching source.
    let justified_checkpoint = if data.target.epoch == get_current_epoch(state) {
        state.current_justified_checkpoint()
    } else {
        state.previous_justified_checkpoint()
    };
    let is_matching_source = data.source == justified_checkpoint;

    // Matching target.
    let target_root = get_block_root(state, data.target.epoch)?;
    let target_root_matches = data.target.root == target_root;
    let is_matching_target = is_matching_source && target_root_matches;

    // Matching head.
    let head_root = get_block_root_at_slot(state, data.slot)?;
    let head_root_matches = data.beacon_block_root == head_root;
    let is_matching_head = is_matching_target && head_root_matches;

    crate::verify(is_matching_source, "is_matching_source")?;

    let mut participation_flag_indices = Vec::new();
    if is_matching_source && inclusion_delay <= integer_squareroot(preset::SLOTS_PER_EPOCH) {
        participation_flag_indices.push(constants::TIMELY_SOURCE_FLAG_INDEX);
    }
    if is_matching_target && inclusion_delay <= preset::SLOTS_PER_EPOCH {
        participation_flag_indices.push(constants::TIMELY_TARGET_FLAG_INDEX);
    }
    if is_matching_head && inclusion_delay == preset::MIN_ATTESTATION_INCLUSION_DELAY {
        participation_flag_indices.push(constants::TIMELY_HEAD_FLAG_INDEX);
    }

    Ok(participation_flag_indices)
}

/// The reward and penalty for one participation flag, for every validator.
///
/// Reuses [`get_eligible_validator_indices`] and [`is_in_inactivity_leak`]
/// from phase0's rewards module unchanged, since the specification does not
/// touch either of them in altair.
///
/// During an inactivity leak, a matching validator earns nothing here for
/// this flag rather than the balance-weighted share the non-leaking branch
/// computes: unlike phase0 (which pays the full base reward during a leak
/// and lets [`get_inactivity_penalty_deltas`] claw an equivalent amount back),
/// altair simply withholds the reward outright, so there is nothing to claw
/// back and [`get_inactivity_penalty_deltas`] only ever penalizes.
pub fn get_flag_index_deltas(
    state: &BeaconState,
    flag_index: usize,
) -> Result<(Vec<Gwei>, Vec<Gwei>)> {
    let validator_count = state.validators().len();
    let mut rewards = vec![0; validator_count];
    let mut penalties = vec![0; validator_count];

    let previous_epoch = get_previous_epoch(state);
    let unslashed_participating_indices =
        get_unslashed_participating_indices(state, flag_index, previous_epoch)?;
    let weight = constants::PARTICIPATION_FLAG_WEIGHTS[flag_index];
    let unslashed_participating_balance =
        get_total_balance(state, &unslashed_participating_indices)?;
    let unslashed_participating_increments =
        unslashed_participating_balance / preset::EFFECTIVE_BALANCE_INCREMENT;
    let active_increments = get_total_active_balance(state)? / preset::EFFECTIVE_BALANCE_INCREMENT;

    for index in get_eligible_validator_indices(state) {
        let base_reward = get_base_reward(state, index)?;
        if unslashed_participating_indices
            .binary_search(&index)
            .is_ok()
        {
            if !is_in_inactivity_leak(state) {
                let reward_numerator = base_reward * weight * unslashed_participating_increments;
                rewards[index as usize] +=
                    reward_numerator / (active_increments * constants::WEIGHT_DENOMINATOR);
            }
        } else if flag_index != constants::TIMELY_HEAD_FLAG_INDEX {
            penalties[index as usize] += base_reward * weight / constants::WEIGHT_DENOMINATOR;
        }
    }
    Ok((rewards, penalties))
}

/// The inactivity penalty for every validator; altair pays no reward for
/// this, only a penalty, so the reward side of the pair is always zero.
///
/// Unlike phase0's version, this does not gate on [`is_in_inactivity_leak`]
/// at all: every eligible validator missing a timely target vote pays a
/// penalty regardless of whether the chain is currently leaking. That is
/// consistent with [`get_flag_index_deltas`] no longer paying (and needing to
/// claw back) a reward during a leak; there is no cancellation left to
/// arrange here.
///
/// Scales with `inactivity_scores`, which only the epoch-processing side of
/// altair (not implemented in this file) updates. A validator's score rises
/// without bound the longer it stays offline through a leak, so the balance
/// scaling below is checked rather than left to wrap.
pub fn get_inactivity_penalty_deltas(
    state: &BeaconState,
    config: &Config,
) -> Result<(Vec<Gwei>, Vec<Gwei>)> {
    let validator_count = state.validators().len();
    let rewards = vec![0; validator_count];
    let mut penalties = vec![0; validator_count];

    let previous_epoch = get_previous_epoch(state);
    let matching_target_indices = get_unslashed_participating_indices(
        state,
        constants::TIMELY_TARGET_FLAG_INDEX,
        previous_epoch,
    )?;

    let altair_state = altair_state_ref(state, "get_inactivity_penalty_deltas")?;

    for index in get_eligible_validator_indices(state) {
        if matching_target_indices.binary_search(&index).is_err() {
            let effective_balance = state.validator(index)?.effective_balance;
            let inactivity_score = altair_state
                .inactivity_scores
                .get(index as usize)
                .copied()
                .ok_or(Error::IndexOutOfBounds {
                    index: index as usize,
                    len: altair_state.inactivity_scores.len(),
                })?;

            let penalty_numerator = effective_balance.checked_mul(inactivity_score).ok_or(
                Error::ArithmeticOverflow("effective_balance * inactivity_scores[index]"),
            )?;
            let penalty_denominator =
                config.inactivity_score_bias * preset::INACTIVITY_PENALTY_QUOTIENT_ALTAIR;
            penalties[index as usize] += penalty_numerator / penalty_denominator;
        }
    }

    Ok((rewards, penalties))
}

// ---------------------------------------------------------------------------
// Fork projection
// ---------------------------------------------------------------------------

/// The altair state, mutably, or an error naming the function that needs one.
///
/// This module is the first to need a field
/// (`previous_epoch_participation`/`current_epoch_participation`) that exists
/// only from altair on and has no fork-invariant accessor on [`BeaconState`],
/// so the projection lives here rather than alongside `crate::stf::phase0_state`,
/// which it is otherwise modeled exactly on.
///
/// Every accessor in this file only reads those fields, so nothing here calls
/// this particular projection; it is kept alongside [`altair_state_ref`] for
/// altair's rewrite of `process_attestation` and
/// `process_participation_flag_updates` (in `crate::stf`, not this file),
/// both of which assign through `previous_epoch_participation` and
/// `current_epoch_participation` directly.
#[allow(dead_code)]
pub(crate) fn altair_state<'a>(
    state: &'a mut BeaconState,
    function: &'static str,
) -> Result<&'a mut altair::BeaconState> {
    match state {
        BeaconState::Altair(state) => Ok(state),
        other => Err(Error::UnsupportedForFork {
            function,
            fork: other.fork_name(),
        }),
    }
}

/// The altair state, immutably. See [`altair_state`].
pub(crate) fn altair_state_ref<'a>(
    state: &'a BeaconState,
    function: &'static str,
) -> Result<&'a altair::BeaconState> {
    match state {
        BeaconState::Altair(state) => Ok(state),
        other => Err(Error::UnsupportedForFork {
            function,
            fork: other.fork_name(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::containers::altair::SyncCommittee;
    use crate::containers::shared::Validator;
    use crate::primitives::{BlsPubkey, Bytes32, Root};

    /// An altair state with `count` fully active, full-balance validators,
    /// positioned the same way `crate::helpers::test_state::with_validators`
    /// positions its phase0 state: one epoch in, so the previous epoch and the
    /// block-root history window both have entries.
    ///
    /// Not added to `test_state`, which only ever builds phase0 states: this
    /// module is the first to need an altair state in a test, so the builder
    /// lives here rather than growing that module into a fork-dispatching
    /// helper for a single caller.
    fn altair_state_with_validators(count: usize) -> BeaconState {
        let validators: Vec<Validator> = (0..count)
            .map(|_| Validator {
                effective_balance: preset::MAX_EFFECTIVE_BALANCE,
                activation_eligibility_epoch: 0,
                activation_epoch: 0,
                exit_epoch: constants::FAR_FUTURE_EPOCH,
                withdrawable_epoch: constants::FAR_FUTURE_EPOCH,
                ..Default::default()
            })
            .collect();

        let empty_sync_committee = || SyncCommittee {
            pubkeys: vec![BlsPubkey::default(); preset::SYNC_COMMITTEE_SIZE]
                .try_into()
                .expect("built at exactly SYNC_COMMITTEE_SIZE"),
            aggregate_pubkey: BlsPubkey::default(),
        };

        BeaconState::Altair(altair::BeaconState {
            genesis_time: 0,
            genesis_validators_root: Root::zero(),
            slot: preset::SLOTS_PER_EPOCH,
            fork: Default::default(),
            latest_block_header: Default::default(),
            block_roots: vec![Root::zero(); preset::SLOTS_PER_HISTORICAL_ROOT]
                .try_into()
                .expect("the vector is built at its exact length"),
            state_roots: vec![Root::zero(); preset::SLOTS_PER_HISTORICAL_ROOT]
                .try_into()
                .expect("the vector is built at its exact length"),
            historical_roots: Default::default(),
            eth1_data: Default::default(),
            eth1_data_votes: Default::default(),
            eth1_deposit_index: 0,
            validators: validators
                .try_into()
                .expect("count is far below VALIDATOR_REGISTRY_LIMIT"),
            balances: vec![preset::MAX_EFFECTIVE_BALANCE; count]
                .try_into()
                .expect("count is far below VALIDATOR_REGISTRY_LIMIT"),
            randao_mixes: vec![Bytes32::zero(); preset::EPOCHS_PER_HISTORICAL_VECTOR]
                .try_into()
                .expect("the vector is built at its exact length"),
            slashings: vec![0; preset::EPOCHS_PER_SLASHINGS_VECTOR]
                .try_into()
                .expect("the vector is built at its exact length"),
            previous_epoch_participation: vec![0; count]
                .try_into()
                .expect("count is far below VALIDATOR_REGISTRY_LIMIT"),
            current_epoch_participation: vec![0; count]
                .try_into()
                .expect("count is far below VALIDATOR_REGISTRY_LIMIT"),
            justification_bits: Default::default(),
            previous_justified_checkpoint: Default::default(),
            current_justified_checkpoint: Default::default(),
            finalized_checkpoint: Default::default(),
            inactivity_scores: vec![0; count]
                .try_into()
                .expect("count is far below VALIDATOR_REGISTRY_LIMIT"),
            current_sync_committee: empty_sync_committee(),
            next_sync_committee: empty_sync_committee(),
        })
    }

    #[test]
    fn has_flag_and_add_flag_round_trip_every_flag_index() {
        for flag_index in [
            constants::TIMELY_SOURCE_FLAG_INDEX,
            constants::TIMELY_TARGET_FLAG_INDEX,
            constants::TIMELY_HEAD_FLAG_INDEX,
        ] {
            let flags: ParticipationFlags = 0;
            assert!(!has_flag(flags, flag_index));
            let flags = add_flag(flags, flag_index);
            assert!(has_flag(flags, flag_index));
        }
    }

    #[test]
    fn add_flag_is_idempotent() {
        let once = add_flag(0, constants::TIMELY_SOURCE_FLAG_INDEX);
        let twice = add_flag(once, constants::TIMELY_SOURCE_FLAG_INDEX);
        assert_eq!(once, twice);
    }

    #[test]
    fn add_flag_leaves_other_bits_alone() {
        let flags = add_flag(0, constants::TIMELY_SOURCE_FLAG_INDEX);
        let flags = add_flag(flags, constants::TIMELY_TARGET_FLAG_INDEX);
        assert!(has_flag(flags, constants::TIMELY_SOURCE_FLAG_INDEX));
        assert!(has_flag(flags, constants::TIMELY_TARGET_FLAG_INDEX));
        assert!(!has_flag(flags, constants::TIMELY_HEAD_FLAG_INDEX));
    }

    #[test]
    fn next_sync_committee_indices_are_exactly_sync_committee_size_and_may_repeat() {
        // Far fewer active validators than the sync committee has seats, so by
        // the pigeonhole principle every draw with replacement must repeat
        // someone, regardless of which preset the crate was built against.
        let state = altair_state_with_validators(4);
        let indices = get_next_sync_committee_indices(&state).unwrap();

        assert_eq!(indices.len(), preset::SYNC_COMMITTEE_SIZE);
        assert!(indices.iter().all(|index| *index < 4));

        let mut seen = std::collections::HashSet::new();
        assert!(
            indices.iter().any(|index| !seen.insert(*index)),
            "drawing SYNC_COMMITTEE_SIZE seats from 4 validators must repeat someone",
        );
    }
}
