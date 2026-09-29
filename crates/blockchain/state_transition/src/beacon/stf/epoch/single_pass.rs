//! Electra's epoch steps 1-9 over one walk of the validator registry.
//!
//! Run step by step, the specification reads the registry once per step:
//! inactivity updates, rewards, registry updates, slashings, pending deposits
//! and effective-balance updates each walk it, and several of them touch every
//! active validator through a tree descent. At mainnet scale (millions of
//! entries) that is the bulk of an epoch-start block. Here one loop visits
//! each validator once, in index order, on a local copy of it and of its
//! balance:
//!
//! ```text
//! inactivity score -> rewards and penalties -> registry update
//!   -> slashing penalty -> this validator's planned deposits
//!   -> effective-balance update (unless deferred)
//! ```
//!
//! then the changes are written back. That is the specification's order for
//! every validator, and steps only ever read the validator being processed
//! plus values fixed before the loop, which is what makes the fusion exact:
//!
//! - Justification runs first, unchanged, on the totals of
//!   [`EpochSummary`]; the reward constants are built after it.
//! - The total active balance is the summary's. It equals
//!   `get_total_active_balance` from step 1 through step 8: exits and
//!   activations scheduled by registry updates take effect no earlier than
//!   `compute_activation_exit_epoch`, and effective balances only move in
//!   step 9. Slashings and every churn limit reuse it.
//! - Ejections advance the exit-churn cursor in index order, so the loop
//!   carries a local [`ExitChurnCursor`] and writes it back once.
//! - Pending deposits are decided before the loop ([`DepositPlan`]), since
//!   the walk down the queue depends on the registry only through each
//!   deposit's validator: existing validators are topped up inside the loop,
//!   deposits for pubkeys the registry has never seen are applied after it
//!   (they append validators), in queue order.
//! - Pending consolidations move balance between two validators and read the
//!   source's effective balance, so they run after the loop through the
//!   ordinary step, and the effective-balance update of every validator a
//!   consolidation names is deferred until they are done.
//!
//! What cannot be fused falls back to the step-by-step path
//! ([`super::electra::process_unfused_steps`]): the genesis epoch (no
//! participation to account for), and any state whose registry-sized lists
//! disagree in length, where the specification's per-step errors depend on
//! which step reads which list.
//!
//! In debug builds (`release-fast` keeps debug assertions) a registry small
//! enough to afford it is also run through the specification-shaped steps on
//! a clone, and the two full states must hash equal.

use std::borrow::Cow;
use std::collections::BTreeMap;

use crate::beacon::config::Config;
use crate::beacon::constants::{self, FAR_FUTURE_EPOCH};
use crate::beacon::containers::shared::Validator;
use crate::beacon::containers::{BeaconState, electra};
use crate::beacon::error::{Error, Result};
use crate::beacon::helpers::accessors::get_current_epoch;
use crate::beacon::helpers::electra::{ExitChurnCursor, activation_exit_churn_limit_for};
use crate::beacon::helpers::misc::{compute_activation_exit_epoch, compute_start_slot_at_epoch};
use crate::beacon::helpers::participation::{EpochSummary, RewardContext};
use crate::beacon::preset;
use crate::beacon::primitives::{BlsPubkey, Epoch, Gwei, ValidatorIndex};

use super::altair::{next_inactivity_score, weigh_with_totals};
use super::electra::{
    RegistryAction, SlashingsContext, apply_pending_deposit, pending_queue_fields,
    process_pending_consolidations, process_unfused_steps, registry_action,
    updated_effective_balance,
};

/// Registries above this size skip the debug oracle: it is the slow path this
/// module replaces.
#[cfg(debug_assertions)]
const ORACLE_LIMIT: usize = 4096;

/// Electra and fulu steps 1-9: justification, inactivity updates, rewards and
/// penalties, registry updates, slashings, eth1 data reset, pending deposits,
/// pending consolidations and effective-balance updates.
pub(super) fn process_steps_through_effective_balances(
    state: &mut BeaconState,
    config: &Config,
) -> Result<()> {
    #[cfg(debug_assertions)]
    {
        if state.validators().len() <= ORACLE_LIMIT {
            let mut expected = state.clone();
            let expected_result = process_unfused_steps(&mut expected, config, true);
            let result = dispatch(state, config);
            assert_eq!(
                result.is_ok(),
                expected_result.is_ok(),
                "single pass disagrees with the unfused steps: {result:?} vs {expected_result:?}"
            );
            if result.is_ok() {
                assert_same_state(state, &mut expected);
            }
            return result;
        }
    }
    dispatch(state, config)
}

pub(super) fn dispatch(state: &mut BeaconState, config: &Config) -> Result<()> {
    if can_fuse(state) {
        fused(state, config)
    } else {
        process_unfused_steps(state, config, false)
    }
}

/// Whether the single pass reproduces the unfused steps on `state`.
///
/// It does when every registry-sized list is exactly as long as the registry,
/// so no step can fail on a missing entry, and there is participation to
/// account for.
pub(super) fn can_fuse(state: &BeaconState) -> bool {
    if !matches!(state, BeaconState::Electra(_) | BeaconState::Fulu(_)) {
        return false;
    }
    if get_current_epoch(state) == constants::GENESIS_EPOCH {
        return false;
    }
    let count = state.validators().len();
    let Ok((previous, current, scores)) = state.altair_validator_lists() else {
        return false;
    };
    state.balances().len() == count
        && previous.len() == count
        && current.len() == count
        && scores.len() == count
}

fn fused(state: &mut BeaconState, config: &Config) -> Result<()> {
    let current_epoch = get_current_epoch(state);

    // Step 1, on the summary's totals; the reward constants read the
    // finalized checkpoint it may move, so they come after.
    let justifies = current_epoch > constants::GENESIS_EPOCH + 1;
    let summary = EpochSummary::build(state, justifies)?;
    if justifies {
        weigh_with_totals(state, summary.totals())?;
    }
    let total_active_balance = summary.totals().total_active_balance;
    let rewards = RewardContext::new(state, summary.totals())?;

    let finalized_epoch = state.finalized_checkpoint().epoch;
    let activation_epoch = compute_activation_exit_epoch(current_epoch);
    let per_epoch_churn = activation_exit_churn_limit_for(total_active_balance, config);
    let slashings = SlashingsContext::new(state, total_active_balance)?;
    let mut exit_cursor = ExitChurnCursor::read(state)?;
    let exit_cursor_before = exit_cursor;
    let mut plan = DepositPlan::new(
        state,
        config,
        per_epoch_churn,
        current_epoch,
        finalized_epoch,
    )?;
    let deferred = consolidation_participants(state)?;

    // The loop only reads the state; every change is collected and written
    // after it.
    let mut score_changes: Vec<(usize, u64)> = Vec::new();
    let mut validator_changes: Vec<(usize, Validator)> = Vec::new();
    let mut balance_changes: Vec<(usize, Gwei)> = Vec::new();
    {
        let validators = state.validators();
        let balances = state.balances();
        let (_, _, scores) = state.altair_validator_lists()?;
        let mut top_ups = plan.top_ups.iter().peekable();
        let mut deferred_cursor = deferred.iter().peekable();

        for (index, (((validator, &balance), &score), (flags, _))) in validators
            .iter()
            .zip(balances.iter())
            .zip(scores.iter())
            .zip(summary.iter())
            .enumerate()
        {
            let mut new_balance = balance;
            let mut new_score = score;

            // Steps 2 and 3.
            if flags.is_eligible() {
                new_score = next_inactivity_score(score, flags, rewards.is_leaking(), config)?;
                let deltas =
                    rewards.deltas(flags, validator.effective_balance, || Ok(new_score), config)?;
                new_balance = deltas.apply(new_balance);
            }

            // Step 4.
            let mut current: Cow<'_, Validator> = Cow::Borrowed(validator);
            match registry_action(
                validator,
                current_epoch,
                finalized_epoch,
                config.ejection_balance,
            ) {
                Some(RegistryAction::QueueForActivation) => {
                    current.to_mut().activation_eligibility_epoch = current_epoch + 1;
                }
                Some(RegistryAction::Eject) if validator.exit_epoch == FAR_FUTURE_EPOCH => {
                    let exit_epoch = exit_cursor.advance(
                        validator.effective_balance,
                        per_epoch_churn,
                        current_epoch,
                    )?;
                    // Checked for the reason `initiate_validator_exit` gives.
                    let withdrawable = exit_epoch
                        .checked_add(config.min_validator_withdrawability_delay)
                        .ok_or(Error::ArithmeticOverflow(
                            "exit_queue_epoch + MIN_VALIDATOR_WITHDRAWABILITY_DELAY",
                        ))?;
                    let ejected = current.to_mut();
                    ejected.exit_epoch = exit_epoch;
                    ejected.withdrawable_epoch = withdrawable;
                }
                Some(RegistryAction::Activate) => {
                    current.to_mut().activation_epoch = activation_epoch;
                }
                // Already exiting: `initiate_validator_exit` does nothing.
                Some(RegistryAction::Eject) | None => {}
            }

            // Step 5, on the validator as step 4 left it.
            if let Some(penalty) = slashings.penalty(&current)? {
                new_balance = new_balance.saturating_sub(penalty);
            }

            // Step 7, for deposits naming this validator.
            if let Some(&&(_, amount)) = top_ups.peek().filter(|&&&(at, _)| at == index) {
                new_balance = new_balance.saturating_add(amount);
                top_ups.next();
            }

            // Step 9, unless a pending consolidation may still move this
            // validator's balance or read its effective balance.
            while deferred_cursor.next_if(|&&at| at < index).is_some() {}
            let is_deferred = deferred_cursor.next_if(|&&at| at == index).is_some();
            if !is_deferred
                && let Some(effective) = updated_effective_balance(&current, new_balance)?
                && effective != current.effective_balance
            {
                current.to_mut().effective_balance = effective;
            }

            if let Cow::Owned(validator) = current {
                validator_changes.push((index, validator));
            }
            if new_balance != balance {
                balance_changes.push((index, new_balance));
            }
            if new_score != score {
                score_changes.push((index, new_score));
            }
        }
    }
    drop(summary);

    write_back(
        state,
        validator_changes,
        balance_changes,
        score_changes,
        exit_cursor,
        exit_cursor_before,
    )?;

    // Step 6 (eth1 votes are untouched by everything above and below).
    super::process_eth1_data_reset(state)?;

    // Step 7: the queue itself, then the deposits that create validators.
    let registry_len = state.validators().len();
    plan.finish(state, config)?;

    // Step 8, then step 9 for what was deferred, and for the validators the
    // deposits just created.
    process_pending_consolidations(state, config)?;
    let new_registry_len = state.validators().len();
    let mut effective_updates = Vec::new();
    let patched = deferred
        .iter()
        .copied()
        .filter(|&index| index < registry_len)
        .chain(registry_len..new_registry_len);
    for index in patched {
        let validator = state.validator(index as ValidatorIndex)?;
        let balance = state.balance(index as ValidatorIndex)?;
        if let Some(effective) = updated_effective_balance(validator, balance)? {
            effective_updates.push((index, effective));
        }
    }
    for (index, effective) in effective_updates {
        state
            .validator_mut(index as ValidatorIndex)?
            .effective_balance = effective;
    }
    Ok(())
}

/// Stores what the loop decided.
fn write_back(
    state: &mut BeaconState,
    validator_changes: Vec<(usize, Validator)>,
    balance_changes: Vec<(usize, Gwei)>,
    score_changes: Vec<(usize, u64)>,
    exit_cursor: ExitChurnCursor,
    exit_cursor_before: ExitChurnCursor,
) -> Result<()> {
    let validators = state.validators_mut();
    for (index, validator) in validator_changes {
        *validators
            .get_mut(index)
            .ok_or(Error::UnknownValidator(index as ValidatorIndex))? = validator;
    }
    let balances = state.balances_mut();
    for (index, balance) in balance_changes {
        *balances
            .get_mut(index)
            .ok_or(Error::UnknownValidator(index as ValidatorIndex))? = balance;
    }
    let (_, _, scores) = state.altair_validator_lists_mut()?;
    let score_count = scores.len();
    for (index, score) in score_changes {
        *scores.get_mut(index).ok_or(Error::IndexOutOfBounds {
            index,
            len: score_count,
        })? = score;
    }
    if exit_cursor != exit_cursor_before {
        exit_cursor.write(state)?;
    }
    Ok(())
}

/// The validators named by any pending consolidation, sorted and deduplicated.
///
/// A superset of the ones the consolidation step will actually touch (it
/// stops at the first source that is not withdrawable yet), which is safe:
/// deferring a validator's effective-balance update to after that step and
/// then doing it on its final balance is the same as doing it in the loop for
/// a validator nothing touched.
fn consolidation_participants(state: &mut BeaconState) -> Result<Vec<usize>> {
    let mut fields = pending_queue_fields(state, "single-pass epoch processing")?;
    let mut participants: Vec<usize> = fields
        .pending_consolidations_mut()
        .iter()
        .flat_map(|consolidation| {
            [
                consolidation.source_index as usize,
                consolidation.target_index as usize,
            ]
        })
        .collect();
    participants.sort_unstable();
    participants.dedup();
    Ok(participants)
}

/// What [`super::electra::process_pending_deposits`] would do, decided before
/// the registry loop.
struct DepositPlan {
    /// Total top-up per existing validator, ascending by index. Applied in the
    /// loop, at the point of the specification's deposit step.
    top_ups: Vec<(usize, Gwei)>,
    /// Deposits whose pubkey the registry has not got, in queue order. They
    /// are applied after the loop through [`apply_pending_deposit`], which
    /// creates the validator (if the signature holds) and tops it up on later
    /// deposits for the same pubkey.
    new_pubkey_deposits: Vec<electra::PendingDeposit>,
    /// The queue as it stands after this epoch: what was not reached, then
    /// what was postponed.
    remaining: Vec<electra::PendingDeposit>,
    deposit_balance_to_consume: Gwei,
}

/// How a reached deposit was resolved.
enum DepositKind {
    /// Credited to a validator already in the registry.
    TopUp,
    /// Named a pubkey the registry lacks.
    NewPubkey,
    /// Named an exiting validator: moved to the back of the queue.
    Postpone,
}

impl DepositPlan {
    /// Walks the queue exactly as `process_pending_deposits` does, without
    /// applying anything: same stopping rules, same churn accounting, same
    /// errors.
    ///
    /// A validator counts as exited when it already has an exit epoch or when
    /// registry updates are about to eject it (the ejection sets one), and as
    /// withdrawn by its withdrawable epoch before registry updates: an
    /// ejection that changes anything moves that epoch to
    /// `compute_activation_exit_epoch` or later, which is never before the
    /// next epoch.
    fn new(
        state: &mut BeaconState,
        config: &Config,
        per_epoch_churn: Gwei,
        current_epoch: Epoch,
        finalized_epoch: Epoch,
    ) -> Result<Self> {
        let next_epoch = current_epoch + 1;
        let finalized_slot = compute_start_slot_at_epoch(finalized_epoch);
        let eth1_deposit_index = state.eth1_deposit_index();

        let (deposit_requests_start_index, available_for_processing, mut deposits) = {
            let mut fields = pending_queue_fields(state, "single-pass epoch processing")?;
            let available_for_processing = fields
                .deposit_balance_to_consume()
                .checked_add(per_epoch_churn)
                .ok_or(Error::ArithmeticOverflow(
                    "deposit_balance_to_consume + get_activation_exit_churn_limit",
                ))?;
            let deposits: Vec<electra::PendingDeposit> =
                core::mem::take(fields.pending_deposits_mut()).into_inner();
            (
                fields.deposit_requests_start_index(),
                available_for_processing,
                deposits,
            )
        };

        // The ordering gates and the per-epoch cap read nothing from the
        // registry, so the deposits the walk can reach are known up front.
        let reachable = deposits
            .iter()
            .take(preset::MAX_PENDING_DEPOSITS_PER_EPOCH as usize)
            .take_while(|deposit| {
                !(deposit.slot > constants::GENESIS_SLOT
                    && eth1_deposit_index < deposit_requests_start_index)
                    && deposit.slot <= finalized_slot
            })
            .count();
        let found = first_indices_of(
            state,
            deposits[..reachable].iter().map(|deposit| deposit.pubkey),
        );

        let mut processed_amount: Gwei = 0;
        let mut is_churn_limit_reached = false;
        let mut kinds: Vec<DepositKind> = Vec::with_capacity(reachable);
        let mut top_ups: BTreeMap<usize, Gwei> = BTreeMap::new();
        let mut credit = |index: usize, amount: Gwei| {
            let total = top_ups.entry(index).or_default();
            *total = total.saturating_add(amount);
        };

        for (deposit, existing) in deposits[..reachable].iter().zip(found) {
            let (is_validator_exited, is_validator_withdrawn) = match existing {
                Some(index) => {
                    let validator = state.validator(index as ValidatorIndex)?;
                    let ejected_now = validator.exit_epoch == FAR_FUTURE_EPOCH
                        && matches!(
                            registry_action(
                                validator,
                                current_epoch,
                                finalized_epoch,
                                config.ejection_balance,
                            ),
                            Some(RegistryAction::Eject)
                        );
                    (
                        validator.exit_epoch < FAR_FUTURE_EPOCH || ejected_now,
                        !ejected_now && validator.withdrawable_epoch < next_epoch,
                    )
                }
                None => (false, false),
            };

            if is_validator_withdrawn {
                let index = existing.expect("a withdrawn validator is in the registry");
                credit(index, deposit.amount);
                kinds.push(DepositKind::TopUp);
            } else if is_validator_exited {
                kinds.push(DepositKind::Postpone);
            } else {
                match processed_amount.checked_add(deposit.amount) {
                    Some(sum) if sum <= available_for_processing => {
                        processed_amount = sum;
                        match existing {
                            Some(index) => {
                                credit(index, deposit.amount);
                                kinds.push(DepositKind::TopUp);
                            }
                            None => kinds.push(DepositKind::NewPubkey),
                        }
                    }
                    _ => {
                        is_churn_limit_reached = true;
                        break;
                    }
                }
            }
        }

        let next_deposit_index = kinds.len();
        let tail = deposits.split_off(next_deposit_index);
        let mut new_pubkey_deposits = Vec::new();
        let mut remaining = tail;
        for (deposit, kind) in deposits.into_iter().zip(kinds) {
            match kind {
                DepositKind::TopUp => {}
                DepositKind::NewPubkey => new_pubkey_deposits.push(deposit),
                DepositKind::Postpone => remaining.push(deposit),
            }
        }

        let deposit_balance_to_consume = if is_churn_limit_reached {
            available_for_processing
                .checked_sub(processed_amount)
                .ok_or(Error::ArithmeticOverflow(
                    "available_for_processing - processed_amount",
                ))?
        } else {
            0
        };

        Ok(Self {
            top_ups: top_ups.into_iter().collect(),
            new_pubkey_deposits,
            remaining,
            deposit_balance_to_consume,
        })
    }

    /// Writes the queue and the leftover churn back, then applies the
    /// deposits that create validators, in queue order.
    fn finish(&mut self, state: &mut BeaconState, config: &Config) -> Result<()> {
        let remaining = core::mem::take(&mut self.remaining);
        let mut fields = pending_queue_fields(state, "single-pass epoch processing")?;
        *fields.pending_deposits_mut() = electra::PendingDeposits::try_from(remaining)?;
        *fields.deposit_balance_to_consume_mut() = self.deposit_balance_to_consume;

        for deposit in core::mem::take(&mut self.new_pubkey_deposits) {
            apply_pending_deposit(state, &deposit, config)?;
        }
        Ok(())
    }
}

/// For each pubkey, in order, the first registry index holding it.
///
/// One walk of the registry for all of them, instead of one per deposit. The
/// first-match rule is `process_pending_deposits`'s, and matters when a
/// crafted registry repeats a key.
fn first_indices_of(
    state: &BeaconState,
    pubkeys: impl Iterator<Item = BlsPubkey>,
) -> Vec<Option<usize>> {
    let wanted: Vec<BlsPubkey> = pubkeys.collect();
    let mut found: Vec<Option<usize>> = vec![None; wanted.len()];
    if wanted.is_empty() {
        return found;
    }
    // The first eight bytes of a key are as good as random, so most
    // validators are rejected by one integer comparison per wanted key.
    let prefix =
        |pubkey: &BlsPubkey| u64::from_le_bytes(pubkey.0[..8].try_into().expect("8 <= 48"));
    let prefixes: Vec<u64> = wanted.iter().map(prefix).collect();
    let mut missing = wanted.len();
    for (index, validator) in state.validators().iter().enumerate() {
        let validator_prefix = prefix(&validator.pubkey);
        for (slot, wanted_prefix) in prefixes.iter().enumerate() {
            if found[slot].is_none()
                && *wanted_prefix == validator_prefix
                && wanted[slot] == validator.pubkey
            {
                found[slot] = Some(index);
                missing -= 1;
            }
        }
        if missing == 0 {
            break;
        }
    }
    found
}

/// Panics, naming what differs, unless the single pass and the unfused steps
/// left identical states.
#[cfg(any(test, debug_assertions))]
fn assert_same_state(state: &mut BeaconState, expected: &mut BeaconState) {
    state.apply_pending_mutations();
    expected.apply_pending_mutations();
    if state.hash_tree_root() == expected.hash_tree_root() {
        return;
    }
    panic!(
        "single pass diverged from the unfused steps in: {}",
        differing_fields(state, expected).join(", ")
    );
}

/// The touched fields that differ, for a failing oracle to report.
#[cfg(any(test, debug_assertions))]
pub(super) fn differing_fields(state: &mut BeaconState, expected: &mut BeaconState) -> Vec<String> {
    let mut differences = Vec::new();
    let mut note = |field: &str, differs: bool| {
        if differs {
            differences.push(field.to_string());
        }
    };

    let describe_at = |what: &str, left: Vec<String>, right: Vec<String>| {
        if left.len() != right.len() {
            return Some(format!("{what} length {} vs {}", left.len(), right.len()));
        }
        left.iter()
            .zip(&right)
            .position(|(a, b)| a != b)
            .map(|index| format!("{what}[{index}]: {} vs {}", left[index], right[index]))
    };
    let debug_all = |items: &mut dyn Iterator<Item = String>| items.collect::<Vec<_>>();

    let left = debug_all(&mut state.validators().iter().map(|v| format!("{v:?}")));
    let right = debug_all(&mut expected.validators().iter().map(|v| format!("{v:?}")));
    if let Some(text) = describe_at("validators", left, right) {
        note(&text, true);
    }

    let left = debug_all(&mut state.balances().iter().map(|v| v.to_string()));
    let right = debug_all(&mut expected.balances().iter().map(|v| v.to_string()));
    if let Some(text) = describe_at("balances", left, right) {
        note(&text, true);
    }

    if let (Ok((_, _, left)), Ok((_, _, right))) = (
        state.altair_validator_lists(),
        expected.altair_validator_lists(),
    ) {
        note("inactivity_scores", left != right);
    }
    note(
        "finalized_checkpoint",
        state.finalized_checkpoint() != expected.finalized_checkpoint(),
    );
    note(
        "current_justified_checkpoint",
        state.current_justified_checkpoint() != expected.current_justified_checkpoint(),
    );
    note(
        "previous_justified_checkpoint",
        state.previous_justified_checkpoint() != expected.previous_justified_checkpoint(),
    );
    note(
        "justification_bits",
        state.justification_bits() != expected.justification_bits(),
    );
    note(
        "exit_churn_cursor",
        ExitChurnCursor::read(state).ok() != ExitChurnCursor::read(expected).ok(),
    );
    if let (Ok(mut left), Ok(mut right)) = (
        pending_queue_fields(state, "oracle"),
        pending_queue_fields(expected, "oracle"),
    ) {
        note(
            "pending_deposits",
            left.pending_deposits_mut() != right.pending_deposits_mut(),
        );
        note(
            "deposit_balance_to_consume",
            left.deposit_balance_to_consume() != right.deposit_balance_to_consume(),
        );
        note(
            "pending_consolidations",
            left.pending_consolidations_mut() != right.pending_consolidations_mut(),
        );
    }
    if differences.is_empty() {
        differences.push("a field outside the ones compared (eth1 votes, resets)".to_string());
    }
    differences
}
