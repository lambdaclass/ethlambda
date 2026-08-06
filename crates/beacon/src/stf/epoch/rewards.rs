//! Rewards and penalties.
//!
//! Every accounting pass here reads the attestations the previous epoch's
//! validators cast (buffered as `PendingAttestation`s and matched by slot,
//! target, and head in `super`) and turns them into one delta per validator: a
//! reward for a vote component that matched the canonical chain, a penalty for
//! one that did not, and, while the chain is failing to finalize, an
//! inactivity penalty that grows the longer finality stays stuck. Every reward
//! and penalty is proportional to [`get_base_reward`], itself inversely
//! proportional to the square root of the total active balance, so the
//! aggregate reward rate shrinks as the validator set grows rather than paying
//! a fixed amount per validator regardless of how many there are.
//!
//! [`process_rewards_and_penalties`] applies the results as two separate
//! passes, rewards then penalties, each through [`increase_balance`] and
//! [`decrease_balance`] rather than a single netted delta. That distinction is
//! load-bearing: [`decrease_balance`] floors at zero, and netting the two
//! before applying them would let a reward mask a penalty that should have
//! driven a low balance all the way down.
//!
//! # Why every component-delta function takes `config`
//!
//! None of phase0's own formulas below read a configuration value: every
//! divisor and threshold they use (`BASE_REWARD_FACTOR`,
//! `PROPOSER_REWARD_QUOTIENT`, `INACTIVITY_PENALTY_QUOTIENT`,
//! `MIN_EPOCHS_TO_INACTIVITY_PENALTY`) is a preset, resolved through
//! `crate::preset` at compile time with no argument needed. [`get_source_deltas`],
//! [`get_target_deltas`], [`get_head_deltas`], [`get_inclusion_delay_deltas`],
//! and [`get_inactivity_penalty_deltas`] still take `config: &Config` (unused
//! here, each parameter named `_config`), for two reasons: the `rewards`
//! fixture runner calls all five through one array and so needs them to share
//! exactly one signature, and altair's rewrite of this module (participation
//! flags instead of matched attestations, and configuration-scoped inactivity
//! score parameters) does need `Config` for the equivalent functions there.
//! Accepting the parameter now, unused, is what keeps this module's call shape
//! stable across that later rewrite.

use crate::config::Config;
use crate::constants;
use crate::containers::BeaconState;
use crate::containers::phase0::PendingAttestation;
use crate::error::{Error, Result};
use crate::helpers::accessors::{
    get_current_epoch, get_previous_epoch, get_total_active_balance, get_total_balance,
};
use crate::helpers::math::integer_squareroot;
use crate::helpers::mutators::{decrease_balance, increase_balance};
use crate::helpers::predicates::is_active_validator;
use crate::preset;
use crate::primitives::{Epoch, Gwei, ValidatorIndex};

use super::{
    get_matching_head_attestations, get_matching_source_attestations,
    get_matching_target_attestations, get_unslashed_attesting_indices,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// The base unit every attestation-component reward and inactivity penalty
/// scales from.
///
/// Scales with the validator's own effective balance, but divides by the
/// square root of the total active balance rather than the total itself: the
/// aggregate reward budget is meant to grow with the square root of stake, not
/// linearly with it, so adding validators dilutes each one's reward rate.
pub fn get_base_reward(state: &BeaconState, index: ValidatorIndex) -> Result<Gwei> {
    let total_balance = get_total_active_balance(state)?;
    let effective_balance = state.validator(index)?.effective_balance;
    Ok(effective_balance * preset::BASE_REWARD_FACTOR
        / integer_squareroot(total_balance)
        / constants::BASE_REWARDS_PER_EPOCH)
}

/// The proposer's cut of an attester's base reward for including its
/// attestation.
pub fn get_proposer_reward(state: &BeaconState, attesting_index: ValidatorIndex) -> Result<Gwei> {
    Ok(get_base_reward(state, attesting_index)? / preset::PROPOSER_REWARD_QUOTIENT)
}

/// How many epochs finality has lagged behind the previous epoch.
///
/// Zero whenever finality is keeping pace with attestation processing; grows
/// by one every further epoch the chain fails to finalize, which is what lets
/// [`is_in_inactivity_leak`] and the inactivity penalty scale with how long the
/// stall has lasted rather than firing at a fixed severity.
pub fn get_finality_delay(state: &BeaconState) -> Epoch {
    get_previous_epoch(state) - state.finalized_checkpoint().epoch
}

/// Whether the chain has gone long enough without finalizing that inactive
/// validators' balances should start leaking away.
///
/// The leak exists so a large inactive or adversarial minority cannot stall
/// finality forever while keeping its stake intact: the longer finality
/// stalls, the faster an inactive validator's share of the active set shrinks,
/// until the honest, active minority eventually clears the two-thirds
/// threshold on its own.
pub fn is_in_inactivity_leak(state: &BeaconState) -> bool {
    get_finality_delay(state) > preset::MIN_EPOCHS_TO_INACTIVITY_PENALTY
}

/// Validators whose participation this epoch's rewards and penalties account
/// for: every currently active validator, plus one already exited but not yet
/// past its withdrawable epoch, so a validator that leaves the active set
/// still pays (or earns) whatever this epoch's accounting owes it up to that
/// point.
pub fn get_eligible_validator_indices(state: &BeaconState) -> Vec<ValidatorIndex> {
    let previous_epoch = get_previous_epoch(state);
    state
        .validators()
        .iter()
        .enumerate()
        .filter(|(_, validator)| {
            is_active_validator(validator, previous_epoch)
                || (validator.slashed && previous_epoch + 1 < validator.withdrawable_epoch)
        })
        .map(|(index, _)| index as ValidatorIndex)
        .collect()
}

/// Shared accounting for the source, target, and head components of the
/// attestation reward: every eligible validator that cast whichever vote
/// `attestations` names is rewarded, and every eligible validator that did not
/// is penalized one base reward.
///
/// Takes no `config`, unlike its five callers below, because nothing in the
/// shared formula reads one; see the module documentation for why the callers
/// carry it anyway.
///
/// During an inactivity leak, a matching validator is paid its full base
/// reward here rather than the balance-weighted share the non-leaking branch
/// computes, because [`get_inactivity_penalty_deltas`] is about to cancel
/// exactly that much back out; paying it in full first is what makes an
/// optimally participating validator's net reward during a leak come out
/// neutral rather than negative.
pub fn get_attestation_component_deltas(
    state: &BeaconState,
    attestations: &[PendingAttestation],
) -> Result<(Vec<Gwei>, Vec<Gwei>)> {
    let mut rewards = vec![0; state.validators().len()];
    let mut penalties = vec![0; state.validators().len()];

    let total_balance = get_total_active_balance(state)?;
    let unslashed_attesting_indices = get_unslashed_attesting_indices(state, attestations)?;
    let attesting_balance = get_total_balance(state, &unslashed_attesting_indices)?;

    for index in get_eligible_validator_indices(state) {
        if unslashed_attesting_indices.binary_search(&index).is_ok() {
            // Factored out of both totals below before the division, to keep
            // the numerator and denominator well clear of `u64::MAX` on a
            // large validator set.
            let increment = preset::EFFECTIVE_BALANCE_INCREMENT;
            if is_in_inactivity_leak(state) {
                rewards[index as usize] += get_base_reward(state, index)?;
            } else {
                let reward_numerator =
                    get_base_reward(state, index)? * (attesting_balance / increment);
                rewards[index as usize] += reward_numerator / (total_balance / increment);
            }
        } else {
            penalties[index as usize] += get_base_reward(state, index)?;
        }
    }
    Ok((rewards, penalties))
}

// ---------------------------------------------------------------------------
// Components of attestation deltas
// ---------------------------------------------------------------------------

/// Attester micro-rewards/penalties for the source-vote component.
pub fn get_source_deltas(state: &BeaconState, _config: &Config) -> Result<(Vec<Gwei>, Vec<Gwei>)> {
    let matching_source_attestations =
        get_matching_source_attestations(state, get_previous_epoch(state))?;
    get_attestation_component_deltas(state, &matching_source_attestations)
}

/// Attester micro-rewards/penalties for the target-vote component.
pub fn get_target_deltas(state: &BeaconState, _config: &Config) -> Result<(Vec<Gwei>, Vec<Gwei>)> {
    let matching_target_attestations =
        get_matching_target_attestations(state, get_previous_epoch(state))?;
    get_attestation_component_deltas(state, &matching_target_attestations)
}

/// Attester micro-rewards/penalties for the head-vote component.
pub fn get_head_deltas(state: &BeaconState, _config: &Config) -> Result<(Vec<Gwei>, Vec<Gwei>)> {
    let matching_head_attestations =
        get_matching_head_attestations(state, get_previous_epoch(state))?;
    get_attestation_component_deltas(state, &matching_head_attestations)
}

/// Proposer and inclusion-delay micro-rewards for each validator.
///
/// Unlike the three components above, there is no penalty side: attesting
/// late only shrinks the reward the attester and its including proposer
/// split, it never costs either of them a balance they would otherwise have
/// kept.
///
/// An attester that matches more than one retained source attestation (by
/// appearing in more than one of them) is paid only once, through whichever
/// reached the chain with the smallest `inclusion_delay`: the proposer who
/// included that one earns the proposer reward, and the attester's own reward
/// divides by that same delay, so being included again later cannot be used to
/// collect a second reward.
pub fn get_inclusion_delay_deltas(
    state: &BeaconState,
    _config: &Config,
) -> Result<(Vec<Gwei>, Vec<Gwei>)> {
    let mut rewards = vec![0; state.validators().len()];

    let matching_source_attestations =
        get_matching_source_attestations(state, get_previous_epoch(state))?;

    for index in get_unslashed_attesting_indices(state, &matching_source_attestations)? {
        // `PendingAttestation` shares `Attestation`'s `data`/`aggregation_bits`
        // shape but is a distinct container type, so membership is checked by
        // asking for the unslashed attesters of a single-attestation slice
        // rather than by re-deriving the committee lookup directly. `index` is
        // already known unslashed (it came from the call above), so this
        // agrees with the specification's plain "index in
        // get_attesting_indices(state, a)" check.
        let mut candidates = Vec::new();
        for attestation in &matching_source_attestations {
            let attesters =
                get_unslashed_attesting_indices(state, std::slice::from_ref(attestation))?;
            if attesters.binary_search(&index).is_ok() {
                candidates.push(attestation);
            }
        }
        let attestation = candidates
            .into_iter()
            .min_by_key(|attestation| attestation.inclusion_delay)
            .ok_or(Error::SpecAssert(
                "an unslashed source attester attests in at least one matching source attestation",
            ))?;

        let proposer_reward = get_proposer_reward(state, index)?;
        rewards[attestation.proposer_index as usize] += proposer_reward;
        let max_attester_reward = get_base_reward(state, index)? - proposer_reward;
        rewards[index as usize] += max_attester_reward / attestation.inclusion_delay;
    }

    // No penalties are associated with inclusion delay.
    let penalties = vec![0; state.validators().len()];
    Ok((rewards, penalties))
}

/// Inactivity penalties for each validator; phase0 pays no separate inactivity
/// reward, only a penalty, so the reward side of the pair is always zero.
///
/// Outside a leak this is a no-op: the whole penalty exists to drain balance
/// from validators that are not helping the chain finalize while it is stuck,
/// and there is nothing to drain if it is not stuck. Inside a leak, every
/// eligible validator pays back the base reward
/// [`get_attestation_component_deltas`] already credited it, for a canceling
/// effect on an optimally participating validator, and a validator that also
/// missed the target vote pays an additional penalty that grows with
/// [`get_finality_delay`]: the longer finality stalls, the faster an inactive
/// validator's share of the stake shrinks.
pub fn get_inactivity_penalty_deltas(
    state: &BeaconState,
    _config: &Config,
) -> Result<(Vec<Gwei>, Vec<Gwei>)> {
    let mut penalties = vec![0; state.validators().len()];

    if is_in_inactivity_leak(state) {
        let matching_target_attestations =
            get_matching_target_attestations(state, get_previous_epoch(state))?;
        let matching_target_attesting_indices =
            get_unslashed_attesting_indices(state, &matching_target_attestations)?;

        for index in get_eligible_validator_indices(state) {
            let base_reward = get_base_reward(state, index)?;
            let proposer_reward = get_proposer_reward(state, index)?;
            penalties[index as usize] +=
                constants::BASE_REWARDS_PER_EPOCH * base_reward - proposer_reward;

            if matching_target_attesting_indices
                .binary_search(&index)
                .is_err()
            {
                let effective_balance = state.validator(index)?.effective_balance;
                // `get_finality_delay` grows without bound the longer a leak
                // lasts, so this product is checked rather than left to wrap:
                // the specification treats a `uint64` overflow here as an
                // invalid state, not as a penalty that silently wraps small.
                let penalty_numerator = effective_balance
                    .checked_mul(get_finality_delay(state))
                    .ok_or(Error::ArithmeticOverflow(
                        "scaling effective balance by the finality delay for the inactivity penalty",
                    ))?;
                penalties[index as usize] +=
                    penalty_numerator / preset::INACTIVITY_PENALTY_QUOTIENT;
            }
        }
    }

    // No rewards are associated with inactivity penalties.
    let rewards = vec![0; state.validators().len()];
    Ok((rewards, penalties))
}

// ---------------------------------------------------------------------------
// `get_attestation_deltas`
// ---------------------------------------------------------------------------

/// The combined attestation reward and penalty for each validator: the sum of
/// the source, target, head, and inclusion-delay rewards, and the sum of the
/// source, target, head, and inactivity penalties.
pub fn get_attestation_deltas(
    state: &BeaconState,
    config: &Config,
) -> Result<(Vec<Gwei>, Vec<Gwei>)> {
    let (source_rewards, source_penalties) = get_source_deltas(state, config)?;
    let (target_rewards, target_penalties) = get_target_deltas(state, config)?;
    let (head_rewards, head_penalties) = get_head_deltas(state, config)?;
    let (inclusion_delay_rewards, _) = get_inclusion_delay_deltas(state, config)?;
    let (_, inactivity_penalties) = get_inactivity_penalty_deltas(state, config)?;

    let validator_count = state.validators().len();
    let mut rewards = vec![0; validator_count];
    let mut penalties = vec![0; validator_count];
    for i in 0..validator_count {
        rewards[i] =
            source_rewards[i] + target_rewards[i] + head_rewards[i] + inclusion_delay_rewards[i];
        penalties[i] =
            source_penalties[i] + target_penalties[i] + head_penalties[i] + inactivity_penalties[i];
    }

    Ok((rewards, penalties))
}

/// Applies the epoch's attestation rewards and penalties to every validator's
/// balance.
///
/// Skipped entirely at the genesis epoch: rewards pay for attestations cast in
/// the previous epoch, and genesis has none. Rewards and penalties are two
/// separate passes over [`increase_balance`] and [`decrease_balance`], not one
/// netted delta, because [`decrease_balance`] floors at zero: netting first
/// would let a reward mask a penalty that should have driven a low balance all
/// the way down.
pub fn process_rewards_and_penalties(state: &mut BeaconState, config: &Config) -> Result<()> {
    if get_current_epoch(state) == constants::GENESIS_EPOCH {
        return Ok(());
    }

    let (rewards, penalties) = get_attestation_deltas(state, config)?;
    for index in 0..state.validators().len() as ValidatorIndex {
        increase_balance(state, index, rewards[index as usize])?;
        decrease_balance(state, index, penalties[index as usize])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finality_delay_is_zero_on_a_fresh_state() {
        // `with_validators` positions the state at current epoch 1, previous
        // epoch 0, with the finalized checkpoint left at its default (epoch
        // 0): finality has not fallen behind at all.
        let state = crate::helpers::test_state::with_validators(4);
        assert_eq!(get_finality_delay(&state), 0);
    }

    #[test]
    fn current_finality_is_not_a_leak() {
        let state = crate::helpers::test_state::with_validators(4);
        assert!(!is_in_inactivity_leak(&state));
    }

    #[test]
    fn finality_stalled_past_the_threshold_is_a_leak() {
        let mut state = crate::helpers::test_state::with_validators(4);
        // The finalized checkpoint stays at its default (epoch 0); pushing the
        // slot far enough ahead pulls the previous epoch more than
        // `MIN_EPOCHS_TO_INACTIVITY_PENALTY` epochs ahead of it.
        *state.slot_mut() =
            preset::SLOTS_PER_EPOCH * (preset::MIN_EPOCHS_TO_INACTIVITY_PENALTY + 10);
        assert!(is_in_inactivity_leak(&state));
    }

    #[test]
    fn every_active_validator_is_eligible() {
        let state = crate::helpers::test_state::with_validators(6);
        assert_eq!(
            get_eligible_validator_indices(&state),
            (0..6).collect::<Vec<_>>()
        );
    }

    #[test]
    fn process_rewards_and_penalties_is_a_no_op_at_genesis() {
        let config = Config::mainnet();
        let mut state = crate::helpers::test_state::with_validators(4);
        *state.slot_mut() = 0;
        let balances_before = state.balances().clone();

        process_rewards_and_penalties(&mut state, &config).unwrap();

        assert_eq!(
            state.balances(),
            &balances_before,
            "the genesis epoch has no previous epoch to reward"
        );
    }
}
