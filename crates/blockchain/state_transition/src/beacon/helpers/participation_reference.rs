//! The specification-shaped implementations of altair's participation
//! helpers, kept as an oracle for [`super::participation`].
//!
//! These are the functions as they were before the one-pass summary replaced
//! them: each rebuilds index lists and reads the registry by index. They are
//! compiled for tests and debug builds only, where the epoch driver runs them
//! on a clone and asserts the fast path agrees.

use super::accessors::{
    get_active_validator_indices, get_current_epoch, get_previous_epoch, get_total_active_balance,
    get_total_balance,
};
use super::altair::{get_base_reward_per_increment, has_flag};
use super::finality::{get_eligible_validator_indices, is_in_inactivity_leak};
use crate::beacon::config::Config;
use crate::beacon::constants;
use crate::beacon::containers::BeaconState;
use crate::beacon::error::{Error, Result};
use crate::beacon::preset;
use crate::beacon::primitives::{Epoch, Gwei, ValidatorIndex};

/// Reference for [`super::altair::get_unslashed_participating_indices`].
pub fn get_unslashed_participating_indices(
    state: &BeaconState,
    flag_index: usize,
    epoch: Epoch,
) -> Result<Vec<ValidatorIndex>> {
    crate::beacon::verify(
        epoch == get_previous_epoch(state) || epoch == get_current_epoch(state),
        "epoch in (get_previous_epoch(state), get_current_epoch(state))",
    )?;

    let (previous_epoch_participation, current_epoch_participation, _) =
        state.altair_validator_lists()?;
    let epoch_participation = if epoch == get_current_epoch(state) {
        current_epoch_participation
    } else {
        previous_epoch_participation
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

/// Reference for [`super::altair::get_flag_index_deltas`].
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

    // Hoisted out of the loop below, where the specification writes
    // `get_base_reward(state, index)` per eligible validator. That helper is
    // `increments * get_base_reward_per_increment(state)`, and the second
    // factor is `get_total_active_balance`, an unconditional `O(registry
    // size)` scan with no cache of its own. That is the same quantity
    // `active_increments` above already paid for, just run through a
    // different formula (`get_base_reward_per_increment` divides by
    // `integer_squareroot`, `active_increments` does not), so it is not
    // reusable as-is and has to be hoisted on its own.
    //
    // [`process_epoch::electra::process_epoch`] calls this (via
    // `process_epoch::altair::process_rewards_and_penalties`) once per
    // [`crate::beacon::constants::PARTICIPATION_FLAG_WEIGHTS`] entry, three times per
    // epoch boundary. At mainnet's ~1M validators, the unhoisted form is
    // three separate million-element scans per *eligible validator*, effectively
    // unbounded, for what this function already computes once above. This is
    // the same bug already fixed in `process_attestation`'s per-attester loop
    // (see that function's own comment), left unfixed here because it runs
    // once per epoch rather than once per block and so never showed up in a
    // profile that did not cross an epoch boundary.
    //
    // Measured directly: `tests::measures_the_cost_of_get_flag_index_deltas`
    // times this call at 2^15 validators. Unhoisted, that call took ~11.9s;
    // hoisted, ~384us: roughly 31,000x at that scale, and the gap widens
    // further at mainnet's ~2^20 validators, since the unhoisted form is
    // O(n^2) (`1024x` slower again at that size) while this is O(n) (`32x`
    // slower again, same as every other size-dependent cost in this crate).
    let base_reward_per_increment = get_base_reward_per_increment(state)?;

    for index in get_eligible_validator_indices(state) {
        // `get_base_reward(state, index)` inlined against the hoisted
        // per-increment value, in the helper's own order of operations so
        // the result is bit-identical.
        let increments =
            state.validator(index)?.effective_balance / preset::EFFECTIVE_BALANCE_INCREMENT;
        let base_reward = increments * base_reward_per_increment;
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

/// Reference for [`super::altair::get_inactivity_penalty_deltas`].
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

    let (_, _, inactivity_scores) = state.altair_validator_lists()?;

    for index in get_eligible_validator_indices(state) {
        if matching_target_indices.binary_search(&index).is_err() {
            let effective_balance = state.validator(index)?.effective_balance;
            let inactivity_score =
                inactivity_scores
                    .get(index as usize)
                    .copied()
                    .ok_or(Error::IndexOutOfBounds {
                        index: index as usize,
                        len: inactivity_scores.len(),
                    })?;

            let penalty_numerator = effective_balance.checked_mul(inactivity_score).ok_or(
                Error::ArithmeticOverflow("effective_balance * inactivity_scores[index]"),
            )?;
            let inactivity_penalty_quotient =
                preset::retuned::inactivity_penalty_quotient(state.fork_name());
            let penalty_denominator = config.inactivity_score_bias * inactivity_penalty_quotient;
            penalties[index as usize] += penalty_numerator / penalty_denominator;
        }
    }

    Ok((rewards, penalties))
}
