//! Gloas-specific epoch processing.
//!
//! [`process_epoch`] is transcribed from `beacon-chain.md`'s own list, in the
//! order it gives them. Gloas inserts one new step,
//! [`process_builder_pending_payments`] (EIP-7732), between fulu's own
//! `process_pending_consolidations` and `process_effective_balance_updates`,
//! and appends another, [`process_ptc_window`] (EIP-7732), after
//! `process_proposer_lookahead`. [`process_pending_deposits`] is also modified
//! in place (EIP-8061: gloas's own activation-only churn budget, see its own
//! doc below); every other step is fulu's own step list, unmodified by
//! gloas's `beacon-chain.md`.
//!
//! Being unmodified in the specification text is not the same as being
//! callable unchanged, though. EIP-7688 makes `previous_epoch_participation`,
//! `current_epoch_participation`, `inactivity_scores`, `pending_deposits`,
//! and `pending_consolidations` progressive lists
//! (`libssz_types::ProgressiveList`) on a gloas state, a different Rust type
//! from every earlier fork's bounded `SszList`. Each step was checked against
//! the real code rather than assumed, and falls into one of three groups:
//!
//! - **Registry and balance steps** ([`super::electra::process_registry_updates`],
//!   [`super::electra::process_slashings`],
//!   [`super::electra::process_effective_balance_updates`]) touch only
//!   `validators` and `balances`, which [`crate::beacon::containers::BeaconState`]
//!   already reaches through element accessors generic over the bounded/tree-backed
//!   split (`iter_validators`, `validator_mut`, `push_validator`, ...). These
//!   call straight through, unchanged, on a gloas state.
//! - **Participation and inactivity steps**
//!   ([`super::altair::process_justification_and_finalization`],
//!   [`super::altair::process_inactivity_updates`],
//!   [`super::altair::process_rewards_and_penalties`]) reach
//!   `previous_epoch_participation`/`current_epoch_participation`/`inactivity_scores`
//!   as plain slices, through [`crate::beacon::containers::BeaconState::altair_validator_lists`]
//!   and [`crate::beacon::containers::BeaconState::inactivity_scores_mut`]: both
//!   `SszList` and `ProgressiveList` `Deref` to a plain `[T]`.
//! - **[`super::electra::process_pending_consolidations`]** takes the queue
//!   as a `Vec` and writes it back, through
//!   [`crate::beacon::helpers::electra::PendingQueueFields::take_pending_consolidations`] and
//!   [`crate::beacon::helpers::electra::PendingQueueFields::set_pending_consolidations`], which
//!   accept a gloas state.
//! - **[`super::fulu::process_proposer_lookahead`]** shifts the window
//!   through an accessor both forks share, and chooses the proposer draw by
//!   fork: gloas's `get_beacon_proposer_indices` excludes slashed validators
//!   (EIP-8045).
//! - Resets and other
//!   fixed-shape fields ([`super::process_eth1_data_reset`],
//!   [`super::process_slashings_reset`], [`super::process_randao_mixes_reset`],
//!   [`super::capella::process_historical_summaries_update`],
//!   [`super::altair::process_sync_committee_updates`]) call straight through,
//!   through accessors that already list gloas among the forks they serve.
//! - **[`process_pending_deposits`] and [`process_participation_flag_updates`]
//!   are gloas's own copy**, over [`gloas::BeaconState`] directly (through
//!   `helpers::gloas::gloas_state`). `process_pending_deposits` is
//!   spec-modified (EIP-8061: gloas's own activation-only churn budget) and
//!   still calls the shared [`super::electra::apply_pending_deposit`] for the
//!   "credit one dequeued deposit" sub-step.
//!   `process_participation_flag_updates` is unmodified in the specification,
//!   but replaces the whole list (a new length, not an element write), which
//!   only the fork's own concrete container type can do: electra's and
//!   fulu's `EpochParticipation::try_from` is fallible where gloas's
//!   `ProgressiveList::from` is not, so there is no shared return type a
//!   `dispatch_state_from!` body could give both.

use crate::beacon::config::Config;
use crate::beacon::constants::FAR_FUTURE_EPOCH;
use crate::beacon::containers::{BeaconState, electra, gloas};
use crate::beacon::error::{Error, Result};
use crate::beacon::helpers::accessors::{CommitteeCache, get_current_epoch};
use crate::beacon::helpers::gloas::{
    compute_ptc, get_activation_churn_limit, get_builder_payment_quorum_threshold, gloas_state,
};
use crate::beacon::helpers::misc::compute_start_slot_at_epoch;
use crate::beacon::preset;
use crate::beacon::primitives::Gwei;

/// Gloas's epoch-boundary driver, in the specification's own order
/// (`beacon-chain.md`'s "Modified `process_epoch`"): fulu's own step list,
/// with [`process_builder_pending_payments`] inserted right after
/// [`process_pending_consolidations`](super::electra::process_pending_consolidations)
/// and [`process_ptc_window`] appended after `process_proposer_lookahead`. See
/// this module's own doc for which steps below are shared and which are
/// gloas's own copy.
pub fn process_epoch(state: &mut BeaconState, config: &Config) -> Result<()> {
    super::altair::process_justification_and_finalization(state)?;
    super::altair::process_inactivity_updates(state, config)?;
    super::altair::process_rewards_and_penalties(state, config)?;
    super::electra::process_registry_updates(state, config)?;
    super::electra::process_slashings(state, config)?;
    super::process_eth1_data_reset(state)?;
    // [Modified in Gloas:EIP8061]
    process_pending_deposits(state, config)?;
    super::electra::process_pending_consolidations(state, config)?;
    // [New in Gloas:EIP7732]
    process_builder_pending_payments(state)?;
    super::electra::process_effective_balance_updates(state)?;
    super::process_slashings_reset(state)?;
    super::process_randao_mixes_reset(state)?;
    super::capella::process_historical_summaries_update(state)?;
    process_participation_flag_updates(state)?;
    super::altair::process_sync_committee_updates(state)?;
    super::fulu::process_proposer_lookahead(state)?;
    // [New in Gloas:EIP7732]
    process_ptc_window(state)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Participation flag updates
// ---------------------------------------------------------------------------

/// Rotates the current epoch's participation flags into the previous slot and
/// installs a fresh, all-zero current list, gloas's own copy of
/// [`crate::beacon::stf::epoch::altair::process_participation_flag_updates`]:
/// identical logic, writing gloas's own progressive lists through
/// [`gloas_state`] (an infallible `From<Vec<_>>` conversion, unlike the
/// bounded `EpochParticipation`'s fallible `TryFrom` altair's version needs).
/// See this module's own doc for why that difference is what keeps this a
/// separate copy rather than a shared, `Vec`-level function the way
/// [`super::electra::process_pending_consolidations`] is.
pub fn process_participation_flag_updates(state: &mut BeaconState) -> Result<()> {
    let validator_count = state.validator_count();
    let inner = gloas_state(state, "process_participation_flag_updates")?;

    inner.previous_epoch_participation = core::mem::take(&mut inner.current_epoch_participation);
    inner.current_epoch_participation = vec![0; validator_count].into();

    Ok(())
}

// ---------------------------------------------------------------------------
// Pending deposits
// ---------------------------------------------------------------------------

/// `process_pending_deposits` (gloas `beacon-chain.md`).
///
/// Modified from electra's and fulu's (EIP-8061): the churn budget is
/// [`get_activation_churn_limit`]'s own, independent activation-only budget,
/// not electra's combined activation/exit one
/// (`crate::beacon::helpers::electra::get_activation_exit_churn_limit`); like fulu's
/// own copy, the eth1-bridge-ahead-of-requests gate is gone outright (see
/// `crate::beacon::stf::epoch::fulu::process_pending_deposits`'s own doc for why
/// dropping it changes nothing observable once a chain has reached this far).
/// The queue is gloas's own progressive one (EIP-7688), read and written
/// directly through [`gloas_state`] rather than through
/// [`crate::beacon::helpers::electra::pending_queue_fields`]'s [`PendingQueueFields`](crate::beacon::helpers::electra::PendingQueueFields),
/// which refuses that field for a gloas state (see its own doc). Once a
/// deposit is dequeued and cleared to apply, though,
/// [`super::electra::apply_pending_deposit`] is the identical function electra
/// and fulu use: nothing about crediting one already-dequeued deposit differs
/// for gloas.
pub fn process_pending_deposits(state: &mut BeaconState, config: &Config) -> Result<()> {
    let next_epoch = get_current_epoch(state) + 1;
    let churn_limit = get_activation_churn_limit(state, config)?;
    let finalized_slot = compute_start_slot_at_epoch(state.finalized_checkpoint().epoch);

    // See `crate::beacon::stf::epoch::electra::process_pending_deposits`'s own doc
    // for why the queue is taken by value here rather than iterated in place.
    let (available_for_processing, deposits) = {
        let inner = gloas_state(state, "process_pending_deposits")?;
        let available_for_processing = inner
            .deposit_balance_to_consume
            .checked_add(churn_limit)
            .ok_or(Error::ArithmeticOverflow(
                "deposit_balance_to_consume + get_activation_churn_limit",
            ))?;
        let deposits: Vec<electra::PendingDeposit> =
            core::mem::take(&mut inner.pending_deposits).into_inner();
        (available_for_processing, deposits)
    };

    let mut processed_amount: Gwei = 0;
    let mut next_deposit_index = 0usize;
    let mut deposits_to_postpone: Vec<electra::PendingDeposit> = Vec::new();
    let mut is_churn_limit_reached = false;

    for deposit in &deposits {
        // A deposit whose queue position could still be reorged out must
        // wait: crediting it now and reverting later is not an option, since
        // nothing else in the state transition undoes a balance change.
        if deposit.slot > finalized_slot {
            break;
        }

        if next_deposit_index >= preset::MAX_PENDING_DEPOSITS_PER_EPOCH as usize {
            break;
        }

        let (is_validator_exited, is_validator_withdrawn) = state
            .iter_validators()
            .find(|validator| validator.pubkey == deposit.pubkey)
            .map(|validator| {
                (
                    validator.exit_epoch < FAR_FUTURE_EPOCH,
                    validator.withdrawable_epoch < next_epoch,
                )
            })
            .unwrap_or((false, false));

        if is_validator_withdrawn {
            super::electra::apply_pending_deposit(state, deposit, config)?;
        } else if is_validator_exited {
            deposits_to_postpone.push(deposit.clone());
        } else {
            match processed_amount.checked_add(deposit.amount) {
                Some(sum) if sum <= available_for_processing => {
                    processed_amount = sum;
                    super::electra::apply_pending_deposit(state, deposit, config)?;
                }
                // Either the sum overflowed (certainly too much) or it fit in
                // a `u64` but still exceeded the budget: both mean this
                // epoch's processing stops here.
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

    let inner = gloas_state(state, "process_pending_deposits")?;
    inner.pending_deposits = gloas::PendingDeposits::from(remaining);
    inner.deposit_balance_to_consume = deposit_balance_to_consume;

    Ok(())
}

// ---------------------------------------------------------------------------
// Builder pending payments (EIP-7732)
// ---------------------------------------------------------------------------

/// `process_builder_pending_payments` (gloas `beacon-chain.md`).
///
/// New in gloas (EIP-7732). Settles or drops each of the previous epoch's
/// [`gloas::BuilderPendingPayment`]s, weighed against
/// [`get_builder_payment_quorum_threshold`], then shifts the fixed two-epoch
/// window (`builder_pending_payments`, `preset::BUILDER_PENDING_PAYMENTS_LENGTH`
/// long) down by one epoch, the builder-payment counterpart of
/// [`process_pending_deposits`]'s deposit queue.
///
/// The loop over `builder_pending_payments` borrows it immutably while
/// pushing to `builder_pending_withdrawals`; those are different fields of
/// the same `&mut gloas::BeaconState`, so this compiles with direct field
/// access rather than through methods that would each take `&mut *inner`
/// whole.
pub fn process_builder_pending_payments(state: &mut BeaconState) -> Result<()> {
    let quorum = get_builder_payment_quorum_threshold(state)?;
    let inner = gloas_state(state, "process_builder_pending_payments")?;
    let epoch_len = preset::SLOTS_PER_EPOCH as usize;

    for payment in &inner.builder_pending_payments[..epoch_len] {
        if payment.weight >= quorum {
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

    Ok(())
}

// ---------------------------------------------------------------------------
// PTC window (EIP-7732)
// ---------------------------------------------------------------------------

/// `process_ptc_window` (gloas `beacon-chain.md`).
///
/// New in gloas (EIP-7732). Shifts the cached `ptc_window`
/// (`preset::PTC_WINDOW_LENGTH` slots long: the previous, current, and
/// `MIN_SEED_LOOKAHEAD`-epochs-ahead committees) down by one epoch, the same
/// fixed-window shift `super::fulu::process_proposer_lookahead` performs, and
/// fills the newly-visible epoch's slice with [`compute_ptc`], one committee
/// per slot. Draws every one of that epoch's committees through one shared
/// [`CommitteeCache`], the same reason [`compute_ptc`]'s own doc gives for why
/// its caller should hold one across a whole epoch's worth of calls rather
/// than letting each shuffle the active set on its own.
pub fn process_ptc_window(state: &mut BeaconState) -> Result<()> {
    let next_epoch = get_current_epoch(state) + preset::MIN_SEED_LOOKAHEAD + 1;
    let start_slot = compute_start_slot_at_epoch(next_epoch);
    let slots_per_epoch = preset::SLOTS_PER_EPOCH as usize;

    let committees = CommitteeCache::default();
    let mut new_slice = Vec::with_capacity(slots_per_epoch);
    for offset in 0..preset::SLOTS_PER_EPOCH {
        let slot = start_slot
            .checked_add(offset)
            .ok_or(Error::ArithmeticOverflow(
                "process_ptc_window: start_slot + offset",
            ))?;
        new_slice.push(compute_ptc(state, slot, &committees)?);
    }

    let inner = gloas_state(state, "process_ptc_window")?;
    let mut window = Vec::with_capacity(preset::PTC_WINDOW_LENGTH);
    window.extend_from_slice(&inner.ptc_window[slots_per_epoch..]);
    window.extend(new_slice);
    inner.ptc_window = window.try_into().expect(
        "dropping SLOTS_PER_EPOCH entries and appending SLOTS_PER_EPOCH more preserves \
         PTC_WINDOW_LENGTH",
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::constants;
    use crate::beacon::fork::ForkName;
    use crate::beacon::helpers::accessors::get_total_active_balance;
    use crate::beacon::helpers::gloas::{get_ptc, gloas_state_ref};
    use crate::beacon::primitives::ValidatorIndex;

    /// A gloas state with `count` fully active, full-balance validators,
    /// positioned one epoch in, the same way
    /// `crate::beacon::helpers::test_state::with_validators` positions its phase0
    /// state.
    fn gloas_state_with_validators(count: usize) -> BeaconState {
        crate::beacon::helpers::test_state::with_validators_at(ForkName::Gloas, count)
    }

    fn gloas_inner(state: &BeaconState) -> &gloas::BeaconState {
        gloas_state_ref(state, "test").unwrap()
    }

    fn gloas_inner_mut(state: &mut BeaconState) -> &mut gloas::BeaconState {
        gloas_state(state, "test").unwrap()
    }

    // -----------------------------------------------------------------------
    // process_epoch
    // -----------------------------------------------------------------------

    #[test]
    fn process_epoch_runs_every_step_without_error_on_a_fresh_state() {
        // 64, not fewer: `process_ptc_window` (a step of `process_epoch`)
        // needs enough validators that every slot's committee is non-empty;
        // see `compute_ptc_returns_ptc_size_active_indices_deterministically`
        // in `helpers::gloas`'s own tests for the same floor and why.
        let config = Config::mainnet();
        let mut state = gloas_state_with_validators(64);
        process_epoch(&mut state, &config).unwrap();
    }

    // -----------------------------------------------------------------------
    // process_participation_flag_updates
    // -----------------------------------------------------------------------

    #[test]
    fn participation_flag_updates_rotate_current_into_previous_and_reset_current() {
        let mut state = gloas_state_with_validators(4);
        gloas_inner_mut(&mut state).current_epoch_participation[0] = 5;
        gloas_inner_mut(&mut state).current_epoch_participation[1] = 7;
        let current_before = gloas_inner(&state).current_epoch_participation.to_vec();

        process_participation_flag_updates(&mut state).unwrap();

        let inner = gloas_inner(&state);
        assert_eq!(inner.previous_epoch_participation.to_vec(), current_before);
        assert_eq!(inner.current_epoch_participation.len(), 4);
        assert!(
            inner
                .current_epoch_participation
                .iter()
                .all(|&flags| flags == 0),
            "the fresh current list must start all-zero"
        );
    }

    // -----------------------------------------------------------------------
    // process_pending_deposits
    // -----------------------------------------------------------------------

    #[test]
    fn a_pending_deposit_for_an_already_withdrawn_validator_bypasses_churn() {
        let config = Config::mainnet();
        let mut state = gloas_state_with_validators(2);
        let next_epoch = get_current_epoch(&state) + 1;

        let (pubkey, withdrawal_credentials) = {
            let validator = state.validator_mut(0).unwrap();
            validator.exit_epoch = 0;
            validator.withdrawable_epoch = 0;
            (validator.pubkey, validator.withdrawal_credentials)
        };
        assert!(state.validator(0).unwrap().withdrawable_epoch < next_epoch);

        let churn_limit = get_activation_churn_limit(&state, &config).unwrap();
        // Deliberately larger than the whole churn budget: a withdrawn
        // validator's deposit must go through regardless of budget.
        let deposit_amount = churn_limit + preset::EFFECTIVE_BALANCE_INCREMENT;
        let deposit = electra::PendingDeposit {
            pubkey,
            withdrawal_credentials,
            amount: deposit_amount,
            signature: Default::default(),
            slot: constants::GENESIS_SLOT,
        };
        gloas_inner_mut(&mut state).pending_deposits.push(deposit);

        let balance_before = state.balance(0).unwrap();
        process_pending_deposits(&mut state, &config).unwrap();

        assert_eq!(state.balance(0).unwrap(), balance_before + deposit_amount);
        let inner = gloas_inner(&state);
        assert_eq!(inner.deposit_balance_to_consume, 0);
        assert!(inner.pending_deposits.is_empty());
    }

    #[test]
    fn a_pending_deposit_for_an_exited_but_not_yet_withdrawn_validator_is_postponed_not_dropped() {
        let config = Config::mainnet();
        let mut state = gloas_state_with_validators(2);
        let next_epoch = get_current_epoch(&state) + 1;

        let (pubkey, withdrawal_credentials) = {
            let validator = state.validator_mut(0).unwrap();
            validator.exit_epoch = 0;
            validator.withdrawable_epoch = FAR_FUTURE_EPOCH;
            (validator.pubkey, validator.withdrawal_credentials)
        };
        assert!(state.validator(0).unwrap().withdrawable_epoch >= next_epoch);

        let deposit = electra::PendingDeposit {
            pubkey,
            withdrawal_credentials,
            amount: preset::EFFECTIVE_BALANCE_INCREMENT,
            signature: Default::default(),
            slot: constants::GENESIS_SLOT,
        };
        gloas_inner_mut(&mut state)
            .pending_deposits
            .push(deposit.clone());

        let balance_before = state.balance(0).unwrap();
        process_pending_deposits(&mut state, &config).unwrap();

        assert_eq!(state.balance(0).unwrap(), balance_before);
        let inner = gloas_inner(&state);
        assert_eq!(inner.pending_deposits.len(), 1);
        assert_eq!(inner.pending_deposits[0], deposit);
    }

    #[test]
    fn pending_deposits_stop_at_the_activation_only_churn_limit() {
        // A config whose gloas activation-churn quotient is deliberately
        // different from electra's combined one, with the floor zeroed so a
        // small registry does not flatten both to the same constant the way
        // `Config::mainnet()`'s much larger floor would: see the `assert_ne!`
        // below, which is what makes this test actually gloas-specific
        // rather than exercising whatever churn `process_pending_deposits`
        // happens to be handed.
        let config = Config {
            min_per_epoch_churn_limit_electra: 0,
            churn_limit_quotient: 4,
            churn_limit_quotient_gloas: 2,
            max_per_epoch_activation_exit_churn_limit: u64::MAX,
            max_per_epoch_activation_churn_limit_gloas: u64::MAX,
            ..Config::mainnet()
        };
        let mut state = gloas_state_with_validators(4);

        let total_active_balance = get_total_active_balance(&state).unwrap();
        let electra_combined_churn =
            crate::beacon::helpers::electra::get_balance_churn_limit(&state, &config).unwrap();
        let churn_limit = get_activation_churn_limit(&state, &config).unwrap();
        assert_ne!(
            churn_limit, electra_combined_churn,
            "the two quotients must actually diverge, or excluding electra's \
             combined churn below proves nothing gloas-specific"
        );
        // Computed independently of `get_activation_churn_limit`, straight
        // from its own formula (`beacon-chain.md`'s New `get_activation_churn_limit`):
        // floor at `min_per_epoch_churn_limit_electra`, round down to an
        // increment, cap at `max_per_epoch_activation_churn_limit_gloas`.
        let expected_churn_limit = {
            let churn = config
                .min_per_epoch_churn_limit_electra
                .max(total_active_balance / config.churn_limit_quotient_gloas);
            let churn = churn - churn % preset::EFFECTIVE_BALANCE_INCREMENT;
            config.max_per_epoch_activation_churn_limit_gloas.min(churn)
        };
        assert_eq!(churn_limit, expected_churn_limit);

        let (pubkey_0, credentials_0) = {
            let v = state.validator(0).unwrap();
            (v.pubkey, v.withdrawal_credentials)
        };
        let (pubkey_1, credentials_1) = {
            let v = state.validator(1).unwrap();
            (v.pubkey, v.withdrawal_credentials)
        };

        let first_amount = churn_limit / 2;
        let second_amount = churn_limit;
        let first = electra::PendingDeposit {
            pubkey: pubkey_0,
            withdrawal_credentials: credentials_0,
            amount: first_amount,
            signature: Default::default(),
            slot: constants::GENESIS_SLOT,
        };
        let second = electra::PendingDeposit {
            pubkey: pubkey_1,
            withdrawal_credentials: credentials_1,
            amount: second_amount,
            signature: Default::default(),
            slot: constants::GENESIS_SLOT,
        };
        {
            let inner = gloas_inner_mut(&mut state);
            inner.pending_deposits.push(first);
            inner.pending_deposits.push(second.clone());
        }

        let balance_0_before = state.balance(0).unwrap();
        let balance_1_before = state.balance(1).unwrap();
        process_pending_deposits(&mut state, &config).unwrap();

        assert_eq!(state.balance(0).unwrap(), balance_0_before + first_amount);
        assert_eq!(
            state.balance(1).unwrap(),
            balance_1_before,
            "over budget: must not apply"
        );

        let inner = gloas_inner(&state);
        assert_eq!(inner.deposit_balance_to_consume, churn_limit - first_amount);
        assert_eq!(inner.pending_deposits.len(), 1);
        assert_eq!(inner.pending_deposits[0], second);
    }

    // -----------------------------------------------------------------------
    // process_pending_consolidations (shared: super::electra's own copy,
    // exercised here against a gloas state)
    // -----------------------------------------------------------------------

    #[test]
    fn an_eligible_pending_consolidation_moves_the_source_balance_to_the_target() {
        let config = Config::mainnet();
        let mut state = gloas_state_with_validators(2);
        state.validator_mut(0).unwrap().withdrawable_epoch = 0;

        let consolidation = electra::PendingConsolidation {
            source_index: 0,
            target_index: 1,
        };
        gloas_inner_mut(&mut state)
            .pending_consolidations
            .push(consolidation);

        let source_effective_balance = state.validator(0).unwrap().effective_balance;
        let source_balance_before = state.balance(0).unwrap();
        let target_balance_before = state.balance(1).unwrap();

        super::super::electra::process_pending_consolidations(&mut state, &config).unwrap();

        let moved = source_balance_before.min(source_effective_balance);
        assert_eq!(state.balance(0).unwrap(), source_balance_before - moved);
        assert_eq!(state.balance(1).unwrap(), target_balance_before + moved);
        assert!(gloas_inner(&state).pending_consolidations.is_empty());
    }

    #[test]
    fn a_pending_consolidation_from_a_slashed_source_is_dropped_from_the_queue() {
        let config = Config::mainnet();
        let mut state = gloas_state_with_validators(2);
        state.validator_mut(0).unwrap().slashed = true;

        let consolidation = electra::PendingConsolidation {
            source_index: 0,
            target_index: 1,
        };
        gloas_inner_mut(&mut state)
            .pending_consolidations
            .push(consolidation);

        let source_balance_before = state.balance(0).unwrap();
        let target_balance_before = state.balance(1).unwrap();
        super::super::electra::process_pending_consolidations(&mut state, &config).unwrap();

        assert_eq!(state.balance(0).unwrap(), source_balance_before);
        assert_eq!(state.balance(1).unwrap(), target_balance_before);
        assert!(gloas_inner(&state).pending_consolidations.is_empty());
    }

    // -----------------------------------------------------------------------
    // process_builder_pending_payments
    // -----------------------------------------------------------------------

    #[test]
    fn a_payment_at_or_above_quorum_settles_into_a_withdrawal_and_below_quorum_is_dropped() {
        let mut state = gloas_state_with_validators(64);
        let quorum = get_builder_payment_quorum_threshold(&state).unwrap();

        {
            let inner = gloas_inner_mut(&mut state);
            inner.builder_pending_payments[0] = gloas::BuilderPendingPayment {
                weight: quorum,
                withdrawal: gloas::BuilderPendingWithdrawal {
                    builder_index: 7,
                    amount: 100,
                    ..Default::default()
                },
                proposer_index: 0,
            };
            inner.builder_pending_payments[1] = gloas::BuilderPendingPayment {
                weight: quorum - 1,
                withdrawal: gloas::BuilderPendingWithdrawal {
                    builder_index: 9,
                    amount: 200,
                    ..Default::default()
                },
                proposer_index: 0,
            };
        }

        process_builder_pending_payments(&mut state).unwrap();

        let inner = gloas_inner(&state);
        assert_eq!(inner.builder_pending_withdrawals.len(), 1);
        assert_eq!(inner.builder_pending_withdrawals[0].builder_index, 7);
    }

    /// Unlike `settle_builder_payment`, which only pushes a withdrawal when
    /// `payment.withdrawal.amount > 0`, `process_builder_pending_payments`'s
    /// own gate is `payment.weight >= quorum` alone (`beacon-chain.md`'s own
    /// `if payment.weight >= quorum: ... append(payment.withdrawal)`, no
    /// amount check at all): a zero-amount payment that still cleared quorum
    /// is appended anyway.
    #[test]
    fn a_zero_amount_payment_at_quorum_is_still_appended() {
        use crate::beacon::helpers::gloas::settle_builder_payment;

        let mut state = gloas_state_with_validators(64);
        let quorum = get_builder_payment_quorum_threshold(&state).unwrap();

        let payment = gloas::BuilderPendingPayment {
            weight: quorum,
            withdrawal: gloas::BuilderPendingWithdrawal {
                builder_index: 7,
                amount: 0,
                ..Default::default()
            },
            proposer_index: 0,
        };
        gloas_inner_mut(&mut state).builder_pending_payments[0] = payment.clone();

        process_builder_pending_payments(&mut state).unwrap();

        let inner = gloas_inner(&state);
        assert_eq!(
            inner.builder_pending_withdrawals.len(),
            1,
            "process_builder_pending_payments must append even a zero-amount \
             payment once it clears quorum"
        );
        assert_eq!(inner.builder_pending_withdrawals[0].builder_index, 7);

        // The contrast: `settle_builder_payment` itself would have dropped
        // this same payment silently, since its own amount check gates on
        // `> 0` regardless of weight.
        let mut settle_state = gloas_state_with_validators(64);
        gloas_inner_mut(&mut settle_state).builder_pending_payments[0] = payment;
        settle_builder_payment(gloas_inner_mut(&mut settle_state), 0).unwrap();
        assert!(
            gloas_inner(&settle_state)
                .builder_pending_withdrawals
                .is_empty(),
            "settle_builder_payment drops a zero-amount withdrawal instead"
        );
    }

    #[test]
    fn process_builder_pending_payments_shifts_the_second_epoch_into_the_first_and_zeroes_the_rest()
    {
        let mut state = gloas_state_with_validators(4);
        let epoch_len = preset::SLOTS_PER_EPOCH as usize;

        {
            let inner = gloas_inner_mut(&mut state);
            inner.builder_pending_payments[epoch_len] = gloas::BuilderPendingPayment {
                weight: 0,
                withdrawal: gloas::BuilderPendingWithdrawal {
                    builder_index: 3,
                    amount: 55,
                    ..Default::default()
                },
                proposer_index: 0,
            };
        }

        process_builder_pending_payments(&mut state).unwrap();

        let inner = gloas_inner(&state);
        assert_eq!(
            inner.builder_pending_payments[0].withdrawal.builder_index,
            3
        );
        assert_eq!(inner.builder_pending_payments[0].withdrawal.amount, 55);
        for payment in &inner.builder_pending_payments[epoch_len..] {
            assert_eq!(*payment, gloas::BuilderPendingPayment::default());
        }
    }

    // -----------------------------------------------------------------------
    // process_proposer_lookahead (shared: super::fulu's own copy, exercised
    // here against a gloas state)
    // -----------------------------------------------------------------------

    #[test]
    fn process_proposer_lookahead_shifts_the_window_and_excludes_a_slashed_validator() {
        let mut state = gloas_state_with_validators(64);
        let slots_per_epoch = preset::SLOTS_PER_EPOCH as usize;

        // Distinct values in the existing window, so a shift that dropped or
        // reordered the carried-over slice (rather than moving it down by
        // exactly one epoch) would be caught: every slot in the default,
        // all-zero test state otherwise looks the same before and after.
        {
            let inner = gloas_inner_mut(&mut state);
            for (index, value) in inner.proposer_lookahead.iter_mut().enumerate() {
                *value = index as ValidatorIndex;
            }
        }
        let before = gloas_inner(&state).proposer_lookahead.to_vec();

        // Control: fulu's own, unfiltered draw (no EIP-8045 exclusion) on
        // this exact state, computed before anyone is slashed. Picking the
        // validator it actually names, rather than an arbitrary index,
        // guarantees the exclusion check below is not vacuous: an unfiltered
        // draw that happened to skip whichever index the test slashed would
        // let a broken filter (or none at all) pass just as easily.
        let new_epoch = get_current_epoch(&state) + preset::MIN_SEED_LOOKAHEAD + 1;
        let unfiltered =
            crate::beacon::helpers::fulu::get_beacon_proposer_indices(&state, new_epoch).unwrap();
        let slashed_index = *unfiltered
            .first()
            .expect("SLOTS_PER_EPOCH draws always name at least one proposer");
        state.validator_mut(slashed_index).unwrap().slashed = true;

        super::super::fulu::process_proposer_lookahead(&mut state).unwrap();

        let inner = gloas_inner(&state);
        assert_eq!(
            inner.proposer_lookahead.len(),
            preset::PROPOSER_LOOKAHEAD_LENGTH
        );
        assert_eq!(
            inner.proposer_lookahead[..inner.proposer_lookahead.len() - slots_per_epoch],
            before[slots_per_epoch..],
            "the carried-over slice must shift down by exactly one epoch"
        );
        let new_slice =
            &inner.proposer_lookahead[inner.proposer_lookahead.len() - slots_per_epoch..];
        assert!(
            !new_slice.contains(&slashed_index),
            "the slashed validator must never be drawn into the new slice, even though \
             the unfiltered (fulu) draw above proves it would otherwise be"
        );
    }

    // -----------------------------------------------------------------------
    // process_ptc_window
    // -----------------------------------------------------------------------

    #[test]
    fn process_ptc_window_shifts_and_fills_a_fresh_lookahead_slice() {
        let mut state = gloas_state_with_validators(64);
        let window_len = preset::PTC_WINDOW_LENGTH;
        let slots_per_epoch = preset::SLOTS_PER_EPOCH as usize;

        // Distinct values per window index, so a shift that scrambled order
        // (rather than moving each slice down by exactly one epoch) would be
        // caught: every slice in the default, all-zero test state is
        // otherwise identical and could not tell a correct shift from a
        // wrong one. Mirrors `helpers::gloas::tests::mark_ptc_window`.
        {
            let inner = gloas_inner_mut(&mut state);
            for window_index in 0..window_len {
                inner.ptc_window[window_index] = vec![window_index as u64; preset::PTC_SIZE]
                    .try_into()
                    .expect("built at exactly PTC_SIZE");
            }
        }
        let before = gloas_inner(&state).ptc_window.to_vec();

        let epoch_before = get_current_epoch(&state);
        process_ptc_window(&mut state).unwrap();

        let inner = gloas_inner(&state);
        assert_eq!(inner.ptc_window.len(), window_len);
        assert_eq!(
            inner.ptc_window[..window_len - slots_per_epoch],
            before[slots_per_epoch..],
            "the carried-over slices must shift down by exactly one epoch"
        );

        // The freshly-filled tail: one `compute_ptc` per slot of the
        // newly-visible epoch, matching `process_ptc_window`'s own fill loop.
        let next_epoch = epoch_before + preset::MIN_SEED_LOOKAHEAD + 1;
        let start_slot = compute_start_slot_at_epoch(next_epoch);
        let committees = CommitteeCache::default();
        for offset in 0..preset::SLOTS_PER_EPOCH {
            let slot = start_slot + offset;
            let expected = compute_ptc(&state, slot, &committees).unwrap();
            let actual = &inner.ptc_window[window_len - slots_per_epoch + offset as usize];
            assert_eq!(&actual[..], &expected[..], "slot {slot}");
        }
    }

    #[test]
    fn get_ptc_reads_back_what_process_ptc_window_just_filled() {
        let mut state = gloas_state_with_validators(64);
        let config = Config::mainnet().with_fork_epoch(ForkName::Gloas, 0);

        let epoch_before = get_current_epoch(&state);
        process_ptc_window(&mut state).unwrap();

        // `get_ptc`'s future-epoch branch only accepts up to
        // `state_epoch + MIN_SEED_LOOKAHEAD`, so read the freshly-filled
        // slice back the way `process_epoch` actually leaves it for: after
        // the state's own slot has advanced into the next epoch, which is
        // what `process_slots` does once epoch processing finishes and is
        // what turns the slice this call just filled
        // (`epoch_before + MIN_SEED_LOOKAHEAD + 1`) into the new
        // `state_epoch + MIN_SEED_LOOKAHEAD` boundary.
        *state.slot_mut() += preset::SLOTS_PER_EPOCH;

        let next_epoch = epoch_before + preset::MIN_SEED_LOOKAHEAD + 1;
        let slot = compute_start_slot_at_epoch(next_epoch);
        let expected = {
            let committees = CommitteeCache::default();
            compute_ptc(&state, slot, &committees).unwrap()
        };
        let read_back = get_ptc(&state, slot, &config).unwrap();
        assert_eq!(&read_back[..], &expected[..]);
    }
}
