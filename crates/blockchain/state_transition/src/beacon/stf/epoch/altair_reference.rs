//! The specification-shaped altair steps 1-3, kept as an oracle for the
//! one-pass implementation in [`super::altair`].
//!
//! These are the step functions as they were before
//! [`crate::beacon::helpers::participation`] replaced them: each reads the
//! registry through index lists and per-index descents. Compiled for tests
//! and debug builds only. [`super::altair::process_participation_steps`] runs
//! [`process_participation_steps`] on a clone and asserts the outcomes agree.

use crate::beacon::config::Config;
use crate::beacon::constants;
use crate::beacon::containers::BeaconState;
use crate::beacon::error::{Error, Result};
use crate::beacon::helpers::accessors::{
    get_current_epoch, get_previous_epoch, get_total_active_balance, get_total_balance,
};
use crate::beacon::helpers::finality::{get_eligible_validator_indices, is_in_inactivity_leak};
use crate::beacon::helpers::math::saturating_sub;
use crate::beacon::helpers::mutators::{decrease_balance, increase_balance};
use crate::beacon::helpers::participation_reference::{
    get_flag_index_deltas, get_inactivity_penalty_deltas, get_unslashed_participating_indices,
};
use crate::beacon::primitives::ValidatorIndex;

use super::justification::weigh_justification_and_finalization;

/// Steps 1-3 back to back, the way each fork's driver called them.
pub fn process_participation_steps(state: &mut BeaconState, config: &Config) -> Result<()> {
    process_justification_and_finalization(state)?;
    process_inactivity_updates(state, config)?;
    process_rewards_and_penalties(state, config)
}

/// Step 1, as the specification writes it.
pub fn process_justification_and_finalization(state: &mut BeaconState) -> Result<()> {
    // Initial FFG checkpoint values have a `0x00` stub for `root`. Skip FFG
    // updates in the first two epochs to avoid corner cases that might result
    // in modifying this stub.
    if get_current_epoch(state) <= constants::GENESIS_EPOCH + 1 {
        return Ok(());
    }

    let previous_indices = get_unslashed_participating_indices(
        state,
        constants::TIMELY_TARGET_FLAG_INDEX,
        get_previous_epoch(state),
    )?;
    let current_indices = get_unslashed_participating_indices(
        state,
        constants::TIMELY_TARGET_FLAG_INDEX,
        get_current_epoch(state),
    )?;
    let total_active_balance = get_total_active_balance(state)?;
    let previous_target_balance = get_total_balance(state, &previous_indices)?;
    let current_target_balance = get_total_balance(state, &current_indices)?;
    weigh_justification_and_finalization(
        state,
        total_active_balance,
        previous_target_balance,
        current_target_balance,
    )
}

/// Step 2, as the specification writes it.
pub fn process_inactivity_updates(state: &mut BeaconState, config: &Config) -> Result<()> {
    if get_current_epoch(state) == constants::GENESIS_EPOCH {
        return Ok(());
    }

    // Every read below needs `&BeaconState`, so they all run before this takes
    // the mutable borrow `inactivity_scores` requires: `altair_validator_lists_mut`
    // borrows the whole state, and there is no way to hold that mutably while
    // also calling `get_eligible_validator_indices`, `get_unslashed_participating_indices`,
    // or `is_in_inactivity_leak`, each of which needs its own `&BeaconState`.
    // `process_effective_balance_updates` in the parent module resolves the
    // identical conflict the same way: decide everything in one pass over
    // immutable state, then apply it in a second pass over a mutable borrow.
    let eligible_indices = get_eligible_validator_indices(state);
    let previous_epoch = get_previous_epoch(state);
    let participating_indices = get_unslashed_participating_indices(
        state,
        constants::TIMELY_TARGET_FLAG_INDEX,
        previous_epoch,
    )?;
    let leaking = is_in_inactivity_leak(state)?;

    let (_, _, inactivity_scores) = state.altair_validator_lists_mut()?;
    let score_count = inactivity_scores.len();
    for index in eligible_indices {
        let score = inactivity_scores
            .get_mut(index as usize)
            .ok_or(Error::IndexOutOfBounds {
                index: index as usize,
                len: score_count,
            })?;

        // `participating_indices` is ascending and duplicate-free (see
        // `get_unslashed_participating_indices`), so membership is a binary
        // search rather than a linear scan.
        if participating_indices.binary_search(&index).is_ok() {
            // `x -= min(1, x)`, written with `saturating_sub` so a
            // already-zero score cannot underflow.
            *score = saturating_sub(*score, 1);
        } else {
            // The specification treats a `uint64` overflow here as an invalid
            // state rather than a wrapped one, so this is checked rather than
            // left to release-mode wrapping.
            *score = score.checked_add(config.inactivity_score_bias).ok_or(
                Error::ArithmeticOverflow("inactivity_scores[index] + INACTIVITY_SCORE_BIAS"),
            )?;
        }

        if !leaking {
            *score = saturating_sub(*score, config.inactivity_score_recovery_rate);
        }
    }

    Ok(())
}

/// Step 3, as the specification writes it.
pub fn process_rewards_and_penalties(state: &mut BeaconState, config: &Config) -> Result<()> {
    if get_current_epoch(state) == constants::GENESIS_EPOCH {
        return Ok(());
    }

    let mut deltas = Vec::with_capacity(constants::PARTICIPATION_FLAG_WEIGHTS.len() + 1);
    for flag_index in 0..constants::PARTICIPATION_FLAG_WEIGHTS.len() {
        deltas.push(get_flag_index_deltas(state, flag_index)?);
    }
    deltas.push(get_inactivity_penalty_deltas(state, config)?);

    let validator_count = state.validator_count() as ValidatorIndex;
    for (rewards, penalties) in deltas {
        for index in 0..validator_count {
            increase_balance(state, index, rewards[index as usize])?;
            decrease_balance(state, index, penalties[index as usize])?;
        }
    }
    Ok(())
}
