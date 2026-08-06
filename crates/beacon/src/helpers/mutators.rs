//! Beacon state mutators.
//!
//! These are the specification's four functions that change a state in place:
//! the two balance adjustments, and the two ways a validator leaves.

use crate::config::Config;
use crate::constants::FAR_FUTURE_EPOCH;
use crate::containers::BeaconState;
use crate::error::Result;
use crate::preset;
use crate::primitives::{Epoch, Gwei, ValidatorIndex};

use super::accessors::{get_beacon_proposer_index, get_current_epoch, get_validator_churn_limit};
use super::misc::compute_activation_exit_epoch;

/// Adds `delta` to a validator's balance.
pub fn increase_balance(state: &mut BeaconState, index: ValidatorIndex, delta: Gwei) -> Result<()> {
    let balance = state
        .balances_mut()
        .get_mut(index as usize)
        .ok_or(crate::Error::UnknownValidator(index))?;
    *balance = balance.saturating_add(delta);
    Ok(())
}

/// Subtracts `delta` from a validator's balance, flooring at zero.
///
/// Saturating rather than checked: the specification defines a balance as
/// unsigned and explicitly floors this at zero, since a penalty larger than the
/// remaining balance is normal rather than an error.
pub fn decrease_balance(state: &mut BeaconState, index: ValidatorIndex, delta: Gwei) -> Result<()> {
    let balance = state
        .balances_mut()
        .get_mut(index as usize)
        .ok_or(crate::Error::UnknownValidator(index))?;
    *balance = balance.saturating_sub(delta);
    Ok(())
}

/// Puts a validator into the exit queue.
///
/// Does nothing if it is already exiting, so this is safe to call more than once
/// for the same validator, which is what lets `slash_validator` call it
/// unconditionally.
///
/// The queue epoch is the later of the earliest permissible exit and the last
/// epoch already in use, pushed out by one more if that epoch is already at the
/// churn limit. Rate limiting exits is what stops a large fraction of the
/// validator set from leaving fast enough to strand finality.
pub fn initiate_validator_exit(
    state: &mut BeaconState,
    index: ValidatorIndex,
    config: &Config,
) -> Result<()> {
    if state.validator(index)?.exit_epoch != FAR_FUTURE_EPOCH {
        return Ok(());
    }

    let earliest = compute_activation_exit_epoch(get_current_epoch(state));
    let mut exit_queue_epoch = state
        .validators()
        .iter()
        .map(|validator| validator.exit_epoch)
        .filter(|epoch| *epoch != FAR_FUTURE_EPOCH)
        .chain(core::iter::once(earliest))
        .max()
        .unwrap_or(earliest);

    let churn_at_that_epoch = state
        .validators()
        .iter()
        .filter(|validator| validator.exit_epoch == exit_queue_epoch)
        .count() as u64;
    if churn_at_that_epoch >= get_validator_churn_limit(state, config) {
        exit_queue_epoch += 1;
    }

    let withdrawable = exit_queue_epoch + config.min_validator_withdrawability_delay;
    let validator = state.validator_mut(index)?;
    validator.exit_epoch = exit_queue_epoch;
    validator.withdrawable_epoch = withdrawable;
    Ok(())
}

/// Slashes a validator: exits it, penalizes it, and pays the reporter.
///
/// The immediate penalty is only a fraction of the effective balance. The rest of
/// the punishment is applied at the epoch boundary and scales with how much of
/// the validator set was slashed around the same time, which is what makes a
/// coordinated attack far more expensive than an isolated mistake. Recording the
/// balance in `slashings` here is what lets that later computation see it.
///
/// `whistleblower_index` defaults to the current proposer when not given.
pub fn slash_validator(
    state: &mut BeaconState,
    slashed_index: ValidatorIndex,
    whistleblower_index: Option<ValidatorIndex>,
    config: &Config,
) -> Result<()> {
    let epoch = get_current_epoch(state);
    initiate_validator_exit(state, slashed_index, config)?;

    let effective_balance = state.validator(slashed_index)?.effective_balance;

    let validator = state.validator_mut(slashed_index)?;
    validator.slashed = true;
    validator.withdrawable_epoch = validator
        .withdrawable_epoch
        .max(epoch + preset::EPOCHS_PER_SLASHINGS_VECTOR as Epoch);

    let slot = epoch as usize % preset::EPOCHS_PER_SLASHINGS_VECTOR;
    let slashings = state.slashings_mut();
    slashings[slot] = slashings[slot].saturating_add(effective_balance);

    decrease_balance(
        state,
        slashed_index,
        effective_balance / preset::MIN_SLASHING_PENALTY_QUOTIENT,
    )?;

    let proposer_index = get_beacon_proposer_index(state)?;
    let whistleblower_index = whistleblower_index.unwrap_or(proposer_index);
    let whistleblower_reward = effective_balance / preset::WHISTLEBLOWER_REWARD_QUOTIENT;
    let proposer_reward = whistleblower_reward / preset::PROPOSER_REWARD_QUOTIENT;

    increase_balance(state, proposer_index, proposer_reward)?;
    increase_balance(
        state,
        whistleblower_index,
        whistleblower_reward - proposer_reward,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decreasing_below_zero_floors_at_zero() {
        let mut state = crate::helpers::test_state::with_validators(4);
        decrease_balance(&mut state, 0, Gwei::MAX).unwrap();
        assert_eq!(state.balance(0).unwrap(), 0);
    }

    #[test]
    fn increasing_and_decreasing_are_inverses() {
        let mut state = crate::helpers::test_state::with_validators(4);
        let before = state.balance(1).unwrap();
        increase_balance(&mut state, 1, 500).unwrap();
        assert_eq!(state.balance(1).unwrap(), before + 500);
        decrease_balance(&mut state, 1, 500).unwrap();
        assert_eq!(state.balance(1).unwrap(), before);
    }

    #[test]
    fn an_unknown_validator_is_an_error() {
        let mut state = crate::helpers::test_state::with_validators(4);
        assert!(increase_balance(&mut state, 99, 1).is_err());
        assert!(decrease_balance(&mut state, 99, 1).is_err());
    }

    #[test]
    fn initiating_an_exit_twice_leaves_the_first_one_alone() {
        let config = Config::mainnet();
        let mut state = crate::helpers::test_state::with_validators(8);

        initiate_validator_exit(&mut state, 0, &config).unwrap();
        let first = state.validator(0).unwrap().exit_epoch;
        assert_ne!(first, FAR_FUTURE_EPOCH);

        // A second call must not push the validator further out.
        initiate_validator_exit(&mut state, 0, &config).unwrap();
        assert_eq!(state.validator(0).unwrap().exit_epoch, first);
    }

    #[test]
    fn exit_sets_a_withdrawable_epoch_after_the_exit() {
        let config = Config::mainnet();
        let mut state = crate::helpers::test_state::with_validators(8);
        initiate_validator_exit(&mut state, 0, &config).unwrap();

        let validator = state.validator(0).unwrap();
        assert_eq!(
            validator.withdrawable_epoch,
            validator.exit_epoch + config.min_validator_withdrawability_delay
        );
    }

    #[test]
    fn slashing_marks_exits_penalizes_and_records() {
        let config = Config::mainnet();
        let mut state = crate::helpers::test_state::with_validators(32);
        let effective_balance = state.validator(3).unwrap().effective_balance;
        let balance_before = state.balance(3).unwrap();

        slash_validator(&mut state, 3, None, &config).unwrap();

        let validator = state.validator(3).unwrap();
        assert!(validator.slashed);
        assert_ne!(validator.exit_epoch, FAR_FUTURE_EPOCH);

        // The effective balance is recorded for the epoch boundary's
        // proportional penalty.
        let epoch = get_current_epoch(&state);
        assert_eq!(
            state.slashings()[epoch as usize % preset::EPOCHS_PER_SLASHINGS_VECTOR],
            effective_balance
        );

        // The immediate penalty is only a fraction of the effective balance, so
        // the validator keeps most of its balance for now.
        assert!(state.balance(3).unwrap() < balance_before);
        assert!(state.balance(3).unwrap() > balance_before / 2);
    }
}
