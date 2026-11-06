//! EIP-8453's round and epoch processing.
//!
//! Rounds are new: every `SLOTS_PER_ROUND` slots, [`process_round`] settles
//! the finality gadget's inactivity ([`process_inactivity_updates`]) and
//! rewards ([`process_rewards`]) and resets the round's participation flags
//! ([`process_participation_flag_updates`]). `process_slots` runs it before
//! [`process_epoch`] when the two boundaries coincide.
//!
//! [`process_epoch`] is heze's step list without Casper FFG's justification
//! and finalization and without the three steps rounds now own, with
//! [`process_builder_pending_payments`] and [`process_pending_deposits`]
//! rewritten and [`process_head_vote_committee_window`] appended. Every
//! other step is heze's own function, called unchanged: the ones that read a
//! finality fact (`process_registry_updates` through
//! `is_eligible_for_activation`, `process_ptc_window` through `compute_ptc`)
//! dispatch on the state's fork inside them, so the EIP-8453 rule applies
//! without a copy of the step.
//!
//! Transcribed from `specs/_features/eip8453/beacon-chain.md` at
//! ethereum/consensus-specs `0f4fa3ffdd26ec083ff4dba65645d81433178413`.

use crate::beacon::config::Config;
use crate::beacon::constants;
use crate::beacon::containers::{BeaconState, eip8453, gloas};
use crate::beacon::error::{Error, Result};
use crate::beacon::helpers::accessors::{get_active_validator_indices, get_current_epoch};
use crate::beacon::helpers::eip8453::{
    add_participation_flag, compute_head_vote_committee, eip8453_state, eip8453_state_mut,
    get_flag_index_rewards, get_unslashed_participating_indices, has_builder_payment_quorum,
};
use crate::beacon::helpers::gloas::get_activation_churn_limit;
use crate::beacon::helpers::math::saturating_sub;
use crate::beacon::helpers::misc::compute_start_slot_at_epoch;
use crate::beacon::helpers::mutators::increase_balance;
use crate::beacon::preset;
use crate::beacon::primitives::{Gwei, ValidatorIndex};

// ---------------------------------------------------------------------------
// Round processing
// ---------------------------------------------------------------------------

/// `process_round`: inactivity, rewards, then the participation flag reset,
/// on the last slot of every round.
pub fn process_round(state: &mut BeaconState, config: &Config) -> Result<()> {
    process_inactivity_updates(state, config)?;
    process_rewards(state)?;
    process_participation_flag_updates(state)?;
    Ok(())
}

/// `process_inactivity_updates` (rewritten): in every round, an active
/// validator with the progress flag recovers `INACTIVITY_SCORE_RECOVERY_RATE`
/// points and one without it gains `INACTIVITY_SCORE_BIAS`, and is exited
/// once its score reaches `EJECTION_INACTIVITY_SCORE`. Scores cost weight,
/// not balance.
///
/// Walked in validator index order, as the specification's loop is, so the
/// exit churn each ejection draws is consumed in the same order.
pub fn process_inactivity_updates(state: &mut BeaconState, config: &Config) -> Result<()> {
    let participating = get_unslashed_participating_indices(state, constants::PROGRESS_FLAG_INDEX)?;
    let active = get_active_validator_indices(state, get_current_epoch(state));
    // Both lists are ascending, so membership is a merge walk.
    let mut participating = participating.into_iter().peekable();
    for index in active {
        while participating.next_if(|&p| p < index).is_some() {}
        let is_participating = participating.next_if_eq(&index).is_some();
        let score = state.inactivity_score_mut(index as usize)?;
        if is_participating {
            *score = saturating_sub(*score, config.inactivity_score_recovery_rate);
        } else {
            *score = score.checked_add(config.inactivity_score_bias).ok_or(
                Error::ArithmeticOverflow(
                    "process_inactivity_updates: inactivity_scores[index] + INACTIVITY_SCORE_BIAS",
                ),
            )?;
            if *score >= preset::EJECTION_INACTIVITY_SCORE {
                crate::beacon::helpers::electra::initiate_validator_exit(state, index, config)?;
            }
        }
    }
    Ok(())
}

/// `process_rewards`: pays each flag's rewards from `get_flag_index_rewards`.
/// Replaces `process_rewards_and_penalties`: there are no penalties. A zero
/// reward is skipped, which `increase_balance` would leave unchanged anyway,
/// so an unrewarded balance keeps its tree node.
pub fn process_rewards(state: &mut BeaconState) -> Result<()> {
    for flag_index in 0..constants::PARTICIPATION_FLAG_WEIGHTS_EIP8453.len() {
        let rewards = get_flag_index_rewards(state, flag_index)?;
        for (index, reward) in rewards.into_iter().enumerate() {
            if reward != 0 {
                increase_balance(state, index as ValidatorIndex, reward)?;
            }
        }
    }
    Ok(())
}

/// `process_participation_flag_updates` (modified): a fresh round
/// participation list, with the progress flag carried over for every
/// validator whose progress at the current height is already recorded (a
/// validator votes once per height, however many rounds it lasts).
pub fn process_participation_flag_updates(state: &mut BeaconState) -> Result<()> {
    let validator_count = state.validator_count();
    let inner = eip8453_state_mut(state, "process_participation_flag_updates")?;
    inner.round_participation = vec![0; validator_count].into();
    for index in 0..validator_count {
        let progressed =
            *inner
                .progress_participation
                .get(index)
                .ok_or(Error::IndexOutOfBounds {
                    index,
                    len: inner.progress_participation.len(),
                })?;
        if progressed {
            add_participation_flag(
                inner,
                index as ValidatorIndex,
                constants::PROGRESS_FLAG_INDEX,
            )?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Epoch processing
// ---------------------------------------------------------------------------

/// `process_epoch` (modified): heze's steps without
/// `process_justification_and_finalization`, `process_inactivity_updates`,
/// `process_rewards_and_penalties` and `process_participation_flag_updates`
/// (the last three run in [`process_round`]), plus
/// [`process_head_vote_committee_window`].
pub fn process_epoch(state: &mut BeaconState, config: &Config) -> Result<()> {
    // [Modified in EIP8453] `is_eligible_for_activation` reads `finalized_slot`.
    super::electra::process_registry_updates(state, config)?;
    super::electra::process_slashings(state, config)?;
    // [Modified in EIP8453]
    process_pending_deposits(state, config)?;
    super::electra::process_pending_consolidations(state, config)?;
    // [Modified in EIP8453]
    process_builder_pending_payments(state)?;
    super::electra::process_effective_balance_updates(state)?;
    super::process_slashings_reset(state)?;
    super::process_randao_mixes_reset(state)?;
    super::capella::process_historical_summaries_update(state)?;
    super::altair::process_sync_committee_updates(state)?;
    super::fulu::process_proposer_lookahead(state)?;
    // [Modified in EIP8453] through `compute_ptc`.
    super::gloas::process_ptc_window(state)?;
    // [New in EIP8453]
    process_head_vote_committee_window(state)?;
    Ok(())
}

/// `process_builder_pending_payments` (rewritten): a previous-epoch payment
/// is paid when the head votes recorded for its slot in
/// `head_vote_participation` reach the payment quorum, rather than when its
/// attestation weight does; then both two-epoch windows shift by one epoch.
pub fn process_builder_pending_payments(state: &mut BeaconState) -> Result<()> {
    let inner = eip8453_state_mut(state, "process_builder_pending_payments")?;
    let epoch_len = preset::SLOTS_PER_EPOCH as usize;

    for index in 0..epoch_len {
        let payment = &inner.builder_pending_payments[index];
        if payment.withdrawal.amount == 0 {
            continue;
        }
        if has_builder_payment_quorum(&inner.head_vote_participation[index]) {
            inner
                .builder_pending_withdrawals
                .push(payment.withdrawal.clone());
        }
    }

    for index in 0..epoch_len {
        inner.builder_pending_payments[index] =
            inner.builder_pending_payments[epoch_len + index].clone();
        inner.builder_pending_payments[epoch_len + index] = gloas::BuilderPendingPayment::default();
    }

    for index in 0..epoch_len {
        inner.head_vote_participation[index] =
            inner.head_vote_participation[epoch_len + index].clone();
        inner.head_vote_participation[epoch_len + index] = eip8453::HeadVoteCommitteeBits::new();
    }
    Ok(())
}

/// `process_pending_deposits` (modified): gloas's, with the finality gate
/// reading `finalized_slot` (`deposit.slot > state.finalized_slot` stops the
/// drain). The drain is `super::electra::drain_pending_deposits`, which reads
/// the gate off the state's fork; the budget is gloas's activation churn.
pub fn process_pending_deposits(state: &mut BeaconState, config: &Config) -> Result<()> {
    eip8453_state(state, "process_pending_deposits")?;
    let churn_limit: Gwei = get_activation_churn_limit(state, config)?;
    super::electra::drain_pending_deposits(state, config, churn_limit)
}

/// `process_head_vote_committee_window`: shifts the cached head vote
/// committees down one epoch and computes the newly visible epoch's, one
/// per slot.
pub fn process_head_vote_committee_window(state: &mut BeaconState) -> Result<()> {
    let current_epoch = get_current_epoch(state);
    let slots_per_epoch = preset::SLOTS_PER_EPOCH as usize;
    let start_slot = compute_start_slot_at_epoch(current_epoch + preset::MIN_SEED_LOOKAHEAD + 1);
    let mut new_committees = Vec::with_capacity(slots_per_epoch);
    for slot in start_slot..start_slot + preset::SLOTS_PER_EPOCH {
        new_committees.push(compute_head_vote_committee(state, slot)?);
    }

    let inner = eip8453_state_mut(state, "process_head_vote_committee_window")?;
    let mut committees = Vec::with_capacity(preset::HEAD_VOTE_COMMITTEE_WINDOW_LENGTH);
    committees.extend_from_slice(&inner.head_vote_committee_window[slots_per_epoch..]);
    committees.extend(new_committees);
    inner.head_vote_committee_window = committees.try_into()?;
    Ok(())
}

#[cfg(test)]
mod tests;
