//! The PQ fork's epoch processing (consensus-specs
//! `specs/_features/pq/beacon-chain.md`, on the `pq` branch at
//! `b5d422b255db80c9bbc48f515370655ecc8bf6e5`).
//!
//! Gloas's driver without `process_sync_committee_updates` (sync committees are
//! gone), with [`process_aggregation_committee_window`] and
//! [`process_preregistration_expiry`] appended, and its own
//! [`process_pending_deposits`]: a deposit names an XMSS key after 16 zero
//! bytes or a legacy BLS key, carries a VRF root where its signature was, and
//! is never signature-checked.

use crate::beacon::config::Config;
use crate::beacon::constants::FAR_FUTURE_EPOCH;
use crate::beacon::containers::{BeaconState, electra, pq, shared::Validator};
use crate::beacon::error::{Error, Result};
use crate::beacon::helpers::accessors::{CommitteeCache, get_current_epoch};
use crate::beacon::helpers::electra::{get_max_effective_balance, pending_queue_fields};
use crate::beacon::helpers::gloas::get_activation_churn_limit;
use crate::beacon::helpers::misc::compute_start_slot_at_epoch;
use crate::beacon::helpers::mutators::increase_balance;
use crate::beacon::helpers::pq::{
    compute_aggregation_committees, compute_deposit_pubkey, compute_deposit_vrf_root,
    is_active_builder_preregistration, is_active_validator_preregistration, is_legacy_pubkey,
    pq_state,
};
use crate::beacon::preset;
use crate::beacon::primitives::{Gwei, ValidatorIndex};

/// `process_epoch` (modified in PQ).
pub fn process_epoch(state: &mut BeaconState, config: &Config) -> Result<()> {
    super::altair::process_justification_and_finalization(state)?;
    super::altair::process_inactivity_updates(state, config)?;
    super::altair::process_rewards_and_penalties(state, config)?;
    super::electra::process_registry_updates(state, config)?;
    super::electra::process_slashings(state, config)?;
    super::process_eth1_data_reset(state)?;
    // [Modified in PQ]
    process_pending_deposits(state, config)?;
    super::electra::process_pending_consolidations(state, config)?;
    super::gloas::process_builder_pending_payments(state)?;
    super::electra::process_effective_balance_updates(state)?;
    super::process_slashings_reset(state)?;
    super::process_randao_mixes_reset(state)?;
    super::capella::process_historical_summaries_update(state)?;
    super::gloas::process_participation_flag_updates(state)?;
    // [Modified in PQ] Removed `process_sync_committee_updates`.
    super::fulu::process_proposer_lookahead(state)?;
    super::gloas::process_ptc_window(state)?;
    // [New in PQ]
    process_aggregation_committee_window(state)?;
    // [New in PQ:EIP8205]
    process_preregistration_expiry(state)?;
    Ok(())
}

/// `process_aggregation_committee_window`: shifts the window down one epoch
/// and fills the newly visible epoch's aggregation committees.
pub fn process_aggregation_committee_window(state: &mut BeaconState) -> Result<()> {
    let next_epoch = get_current_epoch(state) + preset::MIN_SEED_LOOKAHEAD + 1;
    let start_slot = compute_start_slot_at_epoch(next_epoch);
    let committees = CommitteeCache::default();
    let mut new_slice = Vec::with_capacity(preset::SLOTS_PER_EPOCH as usize);
    for slot in start_slot..start_slot + preset::SLOTS_PER_EPOCH {
        new_slice.push(compute_aggregation_committees(state, slot, &committees)?);
    }

    let inner = pq_state(state, "process_aggregation_committee_window")?;
    let slots_per_epoch = preset::SLOTS_PER_EPOCH as usize;
    let mut window = Vec::with_capacity(preset::AGGREGATION_COMMITTEE_WINDOW_LENGTH);
    window.extend_from_slice(&inner.aggregation_committee_window[slots_per_epoch..]);
    window.extend(new_slice);
    inner.aggregation_committee_window = window.try_into().expect(
        "dropping SLOTS_PER_EPOCH entries and appending SLOTS_PER_EPOCH more preserves the length",
    );
    Ok(())
}

/// `process_preregistration_expiry`: garbage collection only. Bindings are
/// enforced through `is_active_*_preregistration`, so when the sweep runs has
/// no effect on whether a binding is enforced or a request admitted.
pub fn process_preregistration_expiry(state: &mut BeaconState) -> Result<()> {
    let inner = pq_state(state, "process_preregistration_expiry")?;
    let validators: Vec<pq::ValidatorPreregistration> = inner
        .validator_preregistrations
        .iter()
        .filter(|record| is_active_validator_preregistration(inner, record))
        .cloned()
        .collect();
    let builders: Vec<pq::BuilderPreregistration> = inner
        .builder_preregistrations
        .iter()
        .filter(|record| is_active_builder_preregistration(inner, record))
        .cloned()
        .collect();
    inner.validator_preregistrations = validators.into();
    inner.builder_preregistrations = builders.into();
    Ok(())
}

/// `process_pending_deposits` (modified in PQ): gloas's activation-only churn
/// budget, each deposit's validator found by [`compute_deposit_pubkey`], and a
/// legacy deposit applied without consuming churn, since its validator never
/// becomes active.
pub fn process_pending_deposits(state: &mut BeaconState, config: &Config) -> Result<()> {
    let next_epoch = get_current_epoch(state) + 1;
    let churn_limit = get_activation_churn_limit(state, config)?;
    let finalized_slot = compute_start_slot_at_epoch(state.finalized_checkpoint().epoch);

    let (available_for_processing, deposits) = {
        let mut fields = pending_queue_fields(state, "process_pending_deposits")?;
        let available = fields
            .deposit_balance_to_consume()
            .checked_add(churn_limit)
            .ok_or(Error::ArithmeticOverflow(
                "deposit_balance_to_consume + get_activation_churn_limit(state)",
            ))?;
        (available, fields.take_pending_deposits())
    };

    let mut processed_amount: Gwei = 0;
    let mut next_deposit_index = 0usize;
    let mut deposits_to_postpone: Vec<electra::PendingDeposit> = Vec::new();
    let mut is_churn_limit_reached = false;

    for deposit in &deposits {
        if deposit.slot > finalized_slot {
            break;
        }
        if next_deposit_index >= preset::MAX_PENDING_DEPOSITS_PER_EPOCH as usize {
            break;
        }

        let record_key = compute_deposit_pubkey(&deposit.pubkey).to_request_key();
        let (is_validator_exited, is_validator_withdrawn) = state
            .iter_validators()
            .find(|validator| validator.pubkey == record_key)
            .map(|validator| {
                (
                    validator.exit_epoch < FAR_FUTURE_EPOCH,
                    validator.withdrawable_epoch < next_epoch,
                )
            })
            .unwrap_or((false, false));

        if is_validator_withdrawn || is_legacy_pubkey(&deposit.pubkey) {
            // Deposited balance will never become active: credited without
            // consuming churn.
            apply_pending_deposit(state, deposit, config)?;
        } else if is_validator_exited {
            deposits_to_postpone.push(deposit.clone());
        } else {
            match processed_amount.checked_add(deposit.amount) {
                Some(sum) if sum <= available_for_processing => {
                    processed_amount = sum;
                    apply_pending_deposit(state, deposit, config)?;
                }
                _ => {
                    is_churn_limit_reached = true;
                    break;
                }
            }
        }
        next_deposit_index += 1;
    }

    let remaining: Vec<electra::PendingDeposit> = deposits
        .into_iter()
        .skip(next_deposit_index)
        .chain(deposits_to_postpone)
        .collect();
    let deposit_balance_to_consume = if is_churn_limit_reached {
        available_for_processing
            .checked_sub(processed_amount)
            .ok_or(Error::ArithmeticOverflow(
                "available_for_processing - processed_amount",
            ))?
    } else {
        0
    };

    let mut fields = pending_queue_fields(state, "process_pending_deposits")?;
    fields.set_pending_deposits(remaining)?;
    *fields.deposit_balance_to_consume_mut() = deposit_balance_to_consume;
    Ok(())
}

/// `apply_pending_deposit` (modified in PQ): a deposit for a new validator is
/// not verified, its validator takes the deposit's VRF root, and a legacy
/// deposit's validator is exited at once, without consuming exit churn, since
/// it was never active.
pub fn apply_pending_deposit(
    state: &mut BeaconState,
    deposit: &electra::PendingDeposit,
    config: &Config,
) -> Result<()> {
    let record_key = compute_deposit_pubkey(&deposit.pubkey).to_request_key();
    let existing = state
        .iter_validators()
        .position(|validator| validator.pubkey == record_key);
    if let Some(index) = existing {
        return increase_balance(state, index as ValidatorIndex, deposit.amount);
    }

    let index = state.validator_count() as ValidatorIndex;
    let mut validator = Validator {
        pubkey: record_key,
        withdrawal_credentials: deposit.withdrawal_credentials,
        activation_eligibility_epoch: FAR_FUTURE_EPOCH,
        activation_epoch: FAR_FUTURE_EPOCH,
        exit_epoch: FAR_FUTURE_EPOCH,
        withdrawable_epoch: FAR_FUTURE_EPOCH,
        ..Default::default()
    };
    let max_effective_balance = get_max_effective_balance(&validator);
    validator.effective_balance = (deposit.amount
        - deposit.amount % preset::EFFECTIVE_BALANCE_INCREMENT)
        .min(max_effective_balance);
    let validator = pq::Validator {
        record: validator,
        vrf_root: compute_deposit_vrf_root(deposit),
    };
    state.push_pq_validator(validator, deposit.amount)?;
    pending_queue_fields(state, "apply_pending_deposit")?
        .push_empty_participation_and_inactivity()?;

    if is_legacy_pubkey(&deposit.pubkey) {
        let epoch = get_current_epoch(state);
        let validator = state.validator_mut(index)?;
        validator.exit_epoch = epoch;
        validator.withdrawable_epoch = epoch
            .checked_add(config.min_validator_withdrawability_delay)
            .ok_or(Error::ArithmeticOverflow(
                "epoch + MIN_VALIDATOR_WITHDRAWABILITY_DELAY",
            ))?;
    }
    Ok(())
}
