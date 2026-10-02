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
//! [`get_eligible_validator_indices`](super::finality::get_eligible_validator_indices)
//! and [`is_in_inactivity_leak`](super::finality::is_in_inactivity_leak)
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

use super::finality::is_in_inactivity_leak;
use super::predicates::is_active_validator;
use crate::beacon::bls;
use crate::beacon::config::Config;
use crate::beacon::constants;
use crate::beacon::containers::shared::{AttestationData, EpochParticipation, Validator};
use crate::beacon::containers::{BeaconState, altair};
use crate::beacon::error::{Error, Result};
use crate::beacon::fork::ForkName;
use crate::beacon::hash::hash;
use crate::beacon::preset;
use crate::beacon::primitives::{Epoch, Gwei, ParticipationFlags, ValidatorIndex};

use super::accessors::{
    get_active_validator_indices, get_block_root, get_block_root_at_slot, get_current_epoch,
    get_previous_epoch, get_seed, get_total_active_balance,
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
///
/// Altair's own version of the draw, unmodified through deneb.
/// [`get_next_sync_committee`] is what chooses between this and electra's
/// widened draw, so nothing here needs to know that a later fork changes it.
pub fn get_next_sync_committee_indices(state: &BeaconState) -> Result<Vec<ValidatorIndex>> {
    let epoch = get_current_epoch(state) + 1;

    // `2**8 - 1`, the largest value a single random byte can take. Named
    // rather than left as a literal, matching `compute_proposer_index`'s
    // identical rejection-sampling shape.
    const MAX_RANDOM_BYTE: u64 = u8::MAX as u64;

    let active_validator_indices = get_active_validator_indices(state, epoch);
    let active_validator_count = active_validator_indices.len() as u64;
    crate::beacon::verify(
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
///
/// Electra's specification modifies the indices draw itself (widening the
/// acceptance test's random value from one byte to two, and swapping in
/// [`preset::MAX_EFFECTIVE_BALANCE_ELECTRA`]) rather than anything in this
/// function, so [`crate::beacon::helpers::electra::get_next_sync_committee_indices`]
/// coexists with this file's own version instead of replacing it, the same
/// way `crate::beacon::helpers::accessors::get_beacon_proposer_index` is where
/// [`crate::beacon::helpers::shuffling::compute_proposer_index`] and
/// [`crate::beacon::helpers::electra::compute_proposer_index`] are chosen between.
/// This function is that dispatch point for the sync committee draw: it is
/// the one caller every fork reaches unconditionally at the period boundary
/// (see [`crate::beacon::stf::epoch::altair::process_sync_committee_updates`]), so
/// picking the fork-appropriate indices function here, rather than in that
/// caller, is what lets fulu (which reuses this whole function) draw a
/// correctly weighted committee too.
pub fn get_next_sync_committee(state: &BeaconState) -> Result<altair::SyncCommittee> {
    let indices = match state.fork_name() {
        ForkName::Electra | ForkName::Fulu => {
            crate::beacon::helpers::electra::get_next_sync_committee_indices(state)?
        }
        _ => get_next_sync_committee_indices(state)?,
    };
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
/// [`crate::beacon::constants::PARTICIPATION_FLAG_WEIGHTS`] instead) and reads
/// [`get_base_reward_per_increment`] rather than the total active balance
/// directly. See [`crate::beacon::stf::epoch::rewards::get_base_reward`] for phase0's
/// version; the two coexist in different modules rather than one replacing
/// the other, since fork dispatch happens at the call site, not here.
pub fn get_base_reward(state: &BeaconState, index: ValidatorIndex) -> Result<Gwei> {
    let effective_balance = state.validator(index)?.effective_balance;
    let increments = effective_balance / preset::EFFECTIVE_BALANCE_INCREMENT;
    Ok(increments * get_base_reward_per_increment(state)?)
}

/// The participation list `epoch` reads from, and the check that `epoch` is
/// one of the two the state keeps a record for.
///
/// At the genesis epoch the previous and current epoch coincide, and the
/// current list is the one read, exactly as the specification's
/// `epoch == get_current_epoch(state)` branch does.
fn epoch_participation(state: &BeaconState, epoch: Epoch) -> Result<&EpochParticipation> {
    crate::beacon::verify(
        epoch == get_previous_epoch(state) || epoch == get_current_epoch(state),
        "epoch in (get_previous_epoch(state), get_current_epoch(state))",
    )?;

    let (previous_epoch_participation, current_epoch_participation, _) =
        state.altair_validator_lists()?;
    Ok(if epoch == get_current_epoch(state) {
        current_epoch_participation
    } else {
        previous_epoch_participation
    })
}

/// Calls `each` with the index and record of every active, unslashed validator
/// that had `flag_index` set for `epoch`, in ascending index order.
///
/// One walk over the registry's leaves, reading the flat participation list by
/// position: no index `Vec` and no per-index registry descent, which is what
/// the callers below used to pay per participant. An active validator past the
/// end of the participation list is an error, as before, and is reported for
/// the lowest such index whether or not it holds the flag.
fn for_each_unslashed_participant(
    state: &BeaconState,
    flag_index: usize,
    epoch: Epoch,
    mut each: impl FnMut(usize, &Validator),
) -> Result<()> {
    let epoch_participation = epoch_participation(state, epoch)?;

    for (index, validator) in state.validators().iter().enumerate() {
        if !is_active_validator(validator, epoch) {
            continue;
        }
        let flags = epoch_participation
            .get(index)
            .copied()
            .ok_or(Error::IndexOutOfBounds {
                index,
                len: epoch_participation.len(),
            })?;
        if has_flag(flags, flag_index) && !validator.slashed {
            each(index, validator);
        }
    }
    Ok(())
}

/// The active, unslashed validators that had `flag_index` set for `epoch`.
///
/// `epoch` must be the current or previous epoch, since those are the only
/// two altair keeps a participation record for (`current_epoch_participation`
/// and `previous_epoch_participation`, mirroring the two-epoch window phase0
/// keeps for `PendingAttestation`s).
///
/// Ascending and duplicate-free, since it walks the registry in index order.
/// Callers that only need the combined balance should use
/// [`get_unslashed_participating_balance`], which skips building this list.
pub fn get_unslashed_participating_indices(
    state: &BeaconState,
    flag_index: usize,
    epoch: Epoch,
) -> Result<Vec<ValidatorIndex>> {
    let mut participating_indices = Vec::new();
    for_each_unslashed_participant(state, flag_index, epoch, |index, _| {
        participating_indices.push(index as ValidatorIndex);
    })?;
    Ok(participating_indices)
}

/// The combined effective balance of [`get_unslashed_participating_indices`]'s
/// result, floored at one increment like
/// [`get_total_balance`](super::accessors::get_total_balance).
///
/// Exactly `get_total_balance(state, &get_unslashed_participating_indices(..)?)`
/// (same saturating sum, same floor, same errors), computed in the one pass
/// that finds the participants.
pub fn get_unslashed_participating_balance(
    state: &BeaconState,
    flag_index: usize,
    epoch: Epoch,
) -> Result<Gwei> {
    let mut total: Gwei = 0;
    for_each_unslashed_participant(state, flag_index, epoch, |_, validator| {
        total = total.saturating_add(validator.effective_balance);
    })?;
    Ok(total.max(preset::EFFECTIVE_BALANCE_INCREMENT))
}

/// The value [`get_total_active_balance`] returns, in one walk over the
/// registry's leaves.
///
/// Sums every validator active at the current epoch (slashed ones included),
/// saturating, floored at one increment. It exists so the epoch steps do not
/// pay [`get_total_active_balance`]'s index `Vec` plus one registry descent
/// per active validator.
pub(crate) fn compute_total_active_balance(state: &BeaconState) -> Gwei {
    let current_epoch = get_current_epoch(state);
    let total = state
        .validators()
        .iter()
        .filter(|validator| is_active_validator(validator, current_epoch))
        .fold(0, |total: Gwei, validator| {
            total.saturating_add(validator.effective_balance)
        });
    total.max(preset::EFFECTIVE_BALANCE_INCREMENT)
}

/// [`get_base_reward_per_increment`] for an already-computed
/// `total_active_balance`, with the same formula and operation order.
pub(crate) fn base_reward_per_increment_from_total(total_active_balance: Gwei) -> Gwei {
    preset::EFFECTIVE_BALANCE_INCREMENT * preset::BASE_REWARD_FACTOR
        / integer_squareroot(total_active_balance)
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

    crate::beacon::verify(is_matching_source, "is_matching_source")?;

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
/// Applies [`get_eligible_validator_indices`](super::finality::get_eligible_validator_indices)'s
/// predicate inline (one walk instead of an index list) and reuses
/// [`is_in_inactivity_leak`] from phase0's rewards module unchanged, since the
/// specification does not touch either of them in altair.
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
    // Also the bounds check for the loop below: an active validator past the
    // end of the participation list fails here, so the loop only indexes the
    // list for validators this call has already proven are in range.
    let unslashed_participating_balance =
        get_unslashed_participating_balance(state, flag_index, previous_epoch)?;
    let epoch_participation = epoch_participation(state, previous_epoch)?;

    let weight = constants::PARTICIPATION_FLAG_WEIGHTS[flag_index];
    let unslashed_participating_increments =
        unslashed_participating_balance / preset::EFFECTIVE_BALANCE_INCREMENT;
    let total_active_balance = compute_total_active_balance(state);
    let active_increments = total_active_balance / preset::EFFECTIVE_BALANCE_INCREMENT;

    // `get_base_reward(state, index)` is `increments *
    // get_base_reward_per_increment(state)`, and the second factor depends on
    // the total active balance, a registry-wide sum. It is the same for every
    // validator, so it is computed once here rather than per eligible
    // validator (which made this function quadratic in the registry size).
    let base_reward_per_increment = base_reward_per_increment_from_total(total_active_balance);
    let leaking = is_in_inactivity_leak(state);

    // One walk over the registry: eligibility (same predicate as
    // `get_eligible_validator_indices`) and participation are decided from the
    // iterated validator, so no index list, binary search or descent is needed.
    for (index, validator) in state.validators().iter().enumerate() {
        let active = is_active_validator(validator, previous_epoch);
        if !(active || (validator.slashed && previous_epoch + 1 < validator.withdrawable_epoch)) {
            continue;
        }
        // `get_base_reward(state, index)` inlined against the hoisted
        // per-increment value, in the helper's own order of operations so
        // the result is bit-identical.
        let increments = validator.effective_balance / preset::EFFECTIVE_BALANCE_INCREMENT;
        let base_reward = increments * base_reward_per_increment;
        // Only an active validator has a participation record that counts;
        // an eligible but inactive (slashed, exited) one never participates,
        // and its index may lie past the end of the list.
        let participated =
            active && !validator.slashed && has_flag(epoch_participation[index], flag_index);
        if participated {
            if !leaking {
                let reward_numerator = base_reward * weight * unslashed_participating_increments;
                rewards[index] +=
                    reward_numerator / (active_increments * constants::WEIGHT_DENOMINATOR);
            }
        } else if flag_index != constants::TIMELY_HEAD_FLAG_INDEX {
            penalties[index] += base_reward * weight / constants::WEIGHT_DENOMINATOR;
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
///
/// The quotient in the penalty's denominator is retuned once more after
/// altair: bellatrix's own specification modifies this exact function to
/// swap in `INACTIVITY_PENALTY_QUOTIENT_BELLATRIX`, and no fork after
/// bellatrix retunes it again, so [`preset::retuned::inactivity_penalty_quotient`]
/// is what tells altair's own value apart from every later fork's.
pub fn get_inactivity_penalty_deltas(
    state: &BeaconState,
    config: &Config,
) -> Result<(Vec<Gwei>, Vec<Gwei>)> {
    let validator_count = state.validators().len();
    let rewards = vec![0; validator_count];
    let mut penalties = vec![0; validator_count];

    let previous_epoch = get_previous_epoch(state);
    let target_participation = epoch_participation(state, previous_epoch)?;
    let (_, _, inactivity_scores) = state.altair_validator_lists()?;
    let inactivity_penalty_quotient =
        preset::retuned::inactivity_penalty_quotient(state.fork_name());

    // A participation-list bounds error outranks a score error from an
    // earlier validator (the participants are resolved before any score is
    // read), so a score error is held back while the walk keeps looking for
    // one. Both only occur on malformed states.
    let mut deferred_error = None;
    for (index, validator) in state.validators().iter().enumerate() {
        let active = is_active_validator(validator, previous_epoch);
        let flags = if active {
            Some(
                target_participation
                    .get(index)
                    .copied()
                    .ok_or(Error::IndexOutOfBounds {
                        index,
                        len: target_participation.len(),
                    })?,
            )
        } else {
            None
        };
        if deferred_error.is_some() {
            continue;
        }
        if !(active || (validator.slashed && previous_epoch + 1 < validator.withdrawable_epoch)) {
            continue;
        }
        let participated = flags.is_some_and(|flags| {
            !validator.slashed && has_flag(flags, constants::TIMELY_TARGET_FLAG_INDEX)
        });
        if participated {
            continue;
        }

        let Some(&inactivity_score) = inactivity_scores.get(index) else {
            deferred_error = Some(Error::IndexOutOfBounds {
                index,
                len: inactivity_scores.len(),
            });
            continue;
        };
        let Some(penalty_numerator) = validator.effective_balance.checked_mul(inactivity_score)
        else {
            deferred_error = Some(Error::ArithmeticOverflow(
                "effective_balance * inactivity_scores[index]",
            ));
            continue;
        };
        let penalty_denominator = config.inactivity_score_bias * inactivity_penalty_quotient;
        penalties[index] += penalty_numerator / penalty_denominator;
    }

    match deferred_error {
        Some(error) => Err(error),
        None => Ok((rewards, penalties)),
    }
}

// ---------------------------------------------------------------------------
// Fork projection
// ---------------------------------------------------------------------------

/// The altair state, immutably, or an error naming the function that needs one.
///
/// There is no mutable sibling, and the reason is worth recording, because it
/// was a real bug and a tempting one. The fields altair introduces
/// (`previous_epoch_participation`, `current_epoch_participation`,
/// `inactivity_scores`, and the two sync committees) exist unchanged through
/// fulu, so a projection to a concrete `altair::BeaconState` rejects every one
/// of bellatrix through fulu with [`Error::UnsupportedForFork`]: precisely the
/// states that matter. Every reader of those fields goes through
/// [`BeaconState::altair_validator_lists`] or [`BeaconState::sync_committees`]
/// instead, which answer for every fork that carries them.
///
/// This immutable one survives for a genuinely different reason:
/// [`crate::beacon::upgrade::upgrade_to_bellatrix`] reads an actual, concrete altair
/// state to build the bellatrix state that succeeds it. That is a real need for
/// `altair::BeaconState` specifically, and a fork-upgrade function is exactly
/// the case a per-fork projection is right for, since it only ever runs on the
/// one fork it upgrades from.
///
/// The distinction generalises: project to a concrete per-fork state when the
/// *return type* has to be that fork's, and reach through a `BeaconState`
/// accessor when the *fields* are shared. Confusing the two produced three
/// separate bugs in this module.
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
mod reference_tests;

#[cfg(test)]
mod tests {
    use super::*;

    /// An altair state with `count` fully active, full-balance validators,
    /// positioned the same way `crate::beacon::helpers::test_state::with_validators`
    /// positions its phase0 state: one epoch in, so the previous epoch and the
    /// block-root history window both have entries.
    ///
    /// A thin wrapper around the shared fork-parameterised builder: see
    /// [`crate::beacon::helpers::test_state::with_validators_at`] for the construction
    /// this and every other fork's test module used to duplicate.
    fn altair_state_with_validators(count: usize) -> BeaconState {
        crate::beacon::helpers::test_state::with_validators_at(ForkName::Altair, count)
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

    /// Measures [`get_flag_index_deltas`]'s cost at a validator count large
    /// enough to show the shape of the fix, without actually running the
    /// unhoisted form at mainnet scale: see the doc comment inside
    /// [`get_flag_index_deltas`] for why that call was, before this change,
    /// one `get_total_active_balance` scan (`O(registry size)`) per
    /// *eligible validator*, i.e. `O(registry size squared)` overall.
    ///
    /// Run at `VALIDATOR_COUNT` (2^15) rather than mainnet's ~2^20: the fixed
    /// form is `O(n)`, so its mainnet-scale cost extrapolates from this
    /// number by the `32x` size ratio; the bug's form is `O(n^2)`, so its
    /// mainnet-scale cost would have extrapolated by `32^2 = 1024x` instead.
    /// Comparing the two at 2^15 already shows which regime each is in
    /// without spending the hours the unhoisted form would need to finish
    /// one call at mainnet scale.
    ///
    /// Only prints the raw per-call time, deliberately not a baked-in
    /// mainnet extrapolation: which multiplier (`32x` or `1024x`) applies
    /// depends on which form of the function this binary was built against,
    /// which this test has no way to know from the outside.
    ///
    /// Not part of `make test-beacon`'s pass/fail contract, for the same
    /// reason as `fork_choice`'s own benchmarks: it always succeeds as long
    /// as the deltas compute, and exists to print a number (`--nocapture`).
    #[test]
    fn measures_the_cost_of_get_flag_index_deltas() {
        use std::time::Instant;

        const VALIDATOR_COUNT: usize = 32_768;
        const ITERATIONS: u32 = 5;

        let state = altair_state_with_validators(VALIDATOR_COUNT);

        let start = Instant::now();
        for _ in 0..ITERATIONS {
            get_flag_index_deltas(&state, constants::TIMELY_SOURCE_FLAG_INDEX)
                .expect("deltas compute over a well-formed state");
        }
        let elapsed = start.elapsed() / ITERATIONS;
        println!("get_flag_index_deltas, {VALIDATOR_COUNT} validators -> {elapsed:?}/call");
    }
}
