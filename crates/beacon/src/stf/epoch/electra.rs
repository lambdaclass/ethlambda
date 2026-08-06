//! Electra-specific epoch processing.
//!
//! Every earlier fork credits a deposit's balance the moment block processing
//! sees it, because every validator's effective balance was capped at the
//! same fixed value, so the only thing worth rate-limiting was how many
//! validators could activate in one epoch. EIP-7251 breaks that: a validator
//! with a compounding withdrawal credential can hold up to
//! [`preset::MAX_EFFECTIVE_BALANCE_ELECTRA`], dozens of times the old ceiling
//! ([`crate::helpers::electra::get_max_effective_balance`]), so a single
//! deposit or consolidation can now move as much voting weight as the old
//! count-based churn limit needed a whole epoch's worth of validators to
//! admit. Crediting it immediately would let that happen in one slot instead.
//! So electra queues both kinds of balance movement and drains each a
//! bounded amount per epoch instead of applying either at block-processing
//! time: [`process_pending_deposits`] rate-limits new stake by
//! [`crate::helpers::electra::get_activation_exit_churn_limit`]'s Gwei
//! budget, and [`process_pending_consolidations`] moves balance between
//! already-active validators, which is why the second one needs no churn
//! budget of its own (see its own doc for why).
//!
//! [`process_epoch`] is transcribed from the specification's own list, in the
//! order it gives them. Registry updates, slashings, and effective-balance
//! updates are electra's own rewrites ([`process_registry_updates`],
//! [`process_slashings`], and [`process_effective_balance_updates`]); the two
//! pending-queue steps are new outright; everything else is unmodified and
//! reused through `super::altair`, `super::registry`, `super::capella`, and
//! `super`. `process_slashings` looks, at a glance, like the same
//! "swap-the-constant" shape altair and bellatrix each use for this same
//! function (see `super::registry::process_slashings`'s own doc), but EIP-7251
//! restructures the division itself rather than only raising a multiplier, so
//! that shared copy stops being correct here; see [`process_slashings`]'s own
//! doc for the arithmetic and a worked example of the two diverging.

use crate::bls;
use crate::config::Config;
use crate::constants::{self, FAR_FUTURE_EPOCH};
use crate::containers::shared::{DepositMessage, Validator};
use crate::containers::{BeaconState, electra, fulu};
use crate::error::{Error, Result};
use crate::helpers::accessors::{get_current_epoch, get_total_active_balance};
use crate::helpers::electra::{
    get_activation_exit_churn_limit, get_max_effective_balance, initiate_validator_exit,
    is_eligible_for_activation_queue,
};
use crate::helpers::misc::{
    compute_activation_exit_epoch, compute_deposit_domain, compute_signing_root,
    compute_start_slot_at_epoch,
};
use crate::helpers::mutators::{decrease_balance, increase_balance};
use crate::helpers::predicates::{is_active_validator, is_eligible_for_activation};
use crate::preset;
use crate::primitives::{
    BlsPubkey, BlsSignature, Bytes32, Epoch, Gwei, HashTreeRoot as _, ValidatorIndex,
};

/// Electra's epoch-boundary driver, in the specification's order.
///
/// Every step but five is reused unchanged, called through `super::altair`,
/// `super::registry`, `super::capella`, and `super` exactly as
/// [`super::capella::process_epoch`] itself calls them. The five exceptions:
/// [`process_registry_updates`], [`process_slashings`], and
/// [`process_effective_balance_updates`] replace the shared versions in
/// place, and [`process_pending_deposits`] and [`process_pending_consolidations`]
/// are inserted right after `process_eth1_data_reset`, exactly where the
/// specification's own listing puts them (before the effective-balance
/// update, so a deposit credited this epoch is already reflected when
/// effective balances round toward it).
pub fn process_epoch(state: &mut BeaconState, config: &Config) -> Result<()> {
    super::altair::process_justification_and_finalization(state)?;
    super::altair::process_inactivity_updates(state, config)?;
    super::altair::process_rewards_and_penalties(state, config)?;
    // [Modified in Electra:EIP7251]
    process_registry_updates(state, config)?;
    // [Modified in Electra:EIP7251]: electra's own copy; see this module's
    // own doc and `process_slashings`'s own doc for why `super::registry`'s
    // copy is no longer correct from here on.
    process_slashings(state, config)?;
    super::process_eth1_data_reset(state)?;
    // [New in Electra:EIP7251]
    process_pending_deposits(state, config)?;
    // [New in Electra:EIP7251]
    process_pending_consolidations(state, config)?;
    // [Modified in Electra:EIP7251]
    process_effective_balance_updates(state)?;
    super::process_slashings_reset(state)?;
    super::process_randao_mixes_reset(state)?;
    super::capella::process_historical_summaries_update(state)?;
    super::altair::process_participation_flag_updates(state)?;
    super::altair::process_sync_committee_updates(state)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Registry updates
// ---------------------------------------------------------------------------

/// A validator's outcome for one run of [`process_registry_updates`]: at most
/// one of the specification's `if`/`elif`/`elif` branches applies.
enum RegistryAction {
    QueueForActivation,
    Eject,
    Activate,
}

/// Moves validators between activation-queue eligibility, ejection, and
/// activation, replacing `super::registry::process_registry_updates` for this
/// fork.
///
/// Rewritten as a single pass over the registry rather than phase0's two
/// passes (eligibility-and-ejection, then a sorted, churn-limited activation
/// queue): EIP-7251 moves the very thing that used to bound activation, a
/// per-epoch validator headcount, onto [`process_pending_deposits`]'s Gwei
/// budget instead, so nothing here needs to rate-limit how many validators
/// activate in one epoch. Every validator whose eligibility is already
/// finalized simply activates, in registry order, at the same
/// `compute_activation_exit_epoch(current_epoch)` the specification computes
/// once up front, which is the detail that most differs from phase0 and is
/// worth transcribing precisely rather than assuming.
///
/// Decided in one immutable pass and applied in a second, the same shape
/// `crate::stf::epoch::process_effective_balance_updates` uses: `state` is an
/// enum over per-fork structs, so nothing can hold `validators` mutably while
/// also reading it to decide the next validator's action. None of the three
/// checks reads anything a *different* validator's mutation could have
/// changed, so the two passes are safe to split. The one exception is
/// [`initiate_validator_exit`]'s own churn cursor, which must still advance in
/// ascending validator-index order for the ejected balance total to match the
/// specification's single loop exactly; applying every decided action in
/// registry order (rather than, say, ejections first) is what preserves that.
pub fn process_registry_updates(state: &mut BeaconState, config: &Config) -> Result<()> {
    let current_epoch = get_current_epoch(state);
    let activation_epoch = compute_activation_exit_epoch(current_epoch);
    let finalized_epoch = state.finalized_checkpoint().epoch;

    let actions: Vec<Option<RegistryAction>> = state
        .validators()
        .iter()
        .map(|validator| {
            if is_eligible_for_activation_queue(validator) {
                Some(RegistryAction::QueueForActivation)
            } else if is_active_validator(validator, current_epoch)
                && validator.effective_balance <= config.ejection_balance
            {
                Some(RegistryAction::Eject)
            } else if is_eligible_for_activation(validator, finalized_epoch) {
                Some(RegistryAction::Activate)
            } else {
                None
            }
        })
        .collect();

    for (index, action) in actions.into_iter().enumerate() {
        let index = index as ValidatorIndex;
        match action {
            Some(RegistryAction::QueueForActivation) => {
                state.validator_mut(index)?.activation_eligibility_epoch = current_epoch + 1;
            }
            Some(RegistryAction::Eject) => initiate_validator_exit(state, index, config)?,
            Some(RegistryAction::Activate) => {
                state.validator_mut(index)?.activation_epoch = activation_epoch;
            }
            None => {}
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Slashings
// ---------------------------------------------------------------------------

/// Applies the deferred part of every slashing whose penalty falls due this
/// epoch, replacing `super::registry::process_slashings` for this fork.
///
/// The same three passes as that version: sum `state.slashings`, scale and cap
/// the sum against the total active balance, then apply a per-validator
/// penalty to whoever's withdrawable epoch arrives this epoch. What EIP-7251
/// changes is which side of a division the rounding happens on. That version
/// computes, per validator, `effective_balance_increments *
/// adjusted_total_slashing_balance`, divides by the raw `total_balance`, and
/// only then multiplies back up by `increment`. This version instead divides
/// `adjusted_total_slashing_balance` by `total_balance / increment` once, up
/// front, and multiplies that one shared quotient by each validator's own
/// `effective_balance_increments`.
///
/// The two orders are not algebraically equivalent under integer division.
/// Multiplying by a validator's own increment count before dividing, the way
/// the pre-electra version does, needs the *product* to reach `total_balance`
/// before any penalty shows up at all; dividing first only needs the slashed
/// amount itself to reach `total_balance / increment`, a number smaller by a
/// factor of `EFFECTIVE_BALANCE_INCREMENT`. A validator whose slashed balance
/// is not the dominant contributor to the epoch's total can therefore round
/// all the way down to no penalty under the old order while still receiving a
/// real one under this one; see this function's own tests for a worked
/// example. The specification also frames the restructuring as an overflow
/// guard: the pre-electra product, `effective_balance_increments *
/// adjusted_total_slashing_balance`, risks overflowing a `uint64` once a
/// compounding validator's ceiling
/// ([`preset::MAX_EFFECTIVE_BALANCE_ELECTRA`]) is dozens of times larger than
/// the old, fixed one, so dividing the shared quotient down to size before
/// that multiplication, rather than after, is not merely a rounding
/// preference.
///
/// The proportional multiplier itself is unchanged from bellatrix: electra
/// never redefines it, so reading it by fork through
/// [`preset::retuned::proportional_slashing_multiplier`] reaches the same
/// constant that function already selects for this fork; only the arithmetic
/// downstream of it moves.
///
/// Takes `config` only to match [`process_epoch`]'s pipeline, the same reason
/// `super::registry::process_slashings` does; the specification's own version
/// takes no configuration either.
pub fn process_slashings(state: &mut BeaconState, _config: &Config) -> Result<()> {
    let epoch = get_current_epoch(state);
    let total_balance = get_total_active_balance(state)?;

    let mut slashed_sum: Gwei = 0;
    for &slashing in state.slashings().iter() {
        slashed_sum = slashed_sum
            .checked_add(slashing)
            .ok_or(Error::ArithmeticOverflow("summing the slashings vector"))?;
    }
    let multiplier = preset::retuned::proportional_slashing_multiplier(state.fork_name());
    let scaled_slashings = slashed_sum
        .checked_mul(multiplier)
        .ok_or(Error::ArithmeticOverflow(
            "scaling the summed slashings by the proportional multiplier",
        ))?;
    let adjusted_total_slashing_balance = scaled_slashings.min(total_balance);

    let increment = preset::EFFECTIVE_BALANCE_INCREMENT;
    // `total_balance` (`get_total_active_balance`) sums every active
    // validator's own increment-quantized effective balance and is floored at
    // one whole increment, so it is always an exact multiple of `increment`:
    // this can never divide by zero, and no remainder is lost to carry
    // forward.
    let total_increments = total_balance / increment;
    let penalty_per_effective_balance_increment =
        adjusted_total_slashing_balance / total_increments;

    let withdrawable_offset = (preset::EPOCHS_PER_SLASHINGS_VECTOR / 2) as Epoch;

    // Collecting the penalties before applying any of them keeps this pass
    // reading a stable registry, the same reason
    // `super::registry::process_slashings` does.
    let mut penalties = Vec::new();
    for (index, validator) in state.validators().iter().enumerate() {
        if validator.slashed && epoch + withdrawable_offset == validator.withdrawable_epoch {
            let effective_balance_increments = validator.effective_balance / increment;
            let penalty = penalty_per_effective_balance_increment
                .checked_mul(effective_balance_increments)
                .ok_or(Error::ArithmeticOverflow(
                    "penalty_per_effective_balance_increment * effective_balance_increments",
                ))?;
            penalties.push((index as ValidatorIndex, penalty));
        }
    }

    for (index, penalty) in penalties {
        decrease_balance(state, index, penalty)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Pending deposits
// ---------------------------------------------------------------------------

/// Drains a balance-churn-limited amount of [`electra::PendingDeposit`]s into
/// the validator registry.
///
/// New in electra; see this module's own doc for why crediting a deposit
/// immediately, the way every earlier fork's `process_deposit` does, is no
/// longer safe once a validator's ceiling can be far above
/// [`preset::MIN_ACTIVATION_BALANCE`]. `crate::stf::operations::process_deposit`
/// and `apply_deposit` (block processing's own deposit path, EIP-6110, a file
/// this task does not own) queue a deposit's amount rather than crediting it
/// directly; this is what actually applies it, once there is room in this
/// epoch's [`get_activation_exit_churn_limit`] budget.
///
/// The queue is drained strictly from the front. Every entry reached advances
/// `next_deposit_index`, meaning it leaves its place at the front of the
/// queue, except one case: a deposit that would push this epoch's processed
/// total over budget stops the whole pass rather than being skipped over, so
/// a small deposit further back in the queue can never jump ahead of a large
/// one still waiting for room. Three outcomes decide what happens to an entry
/// that clears the ordering gates (the eth1-bridge-ahead-of-requests check,
/// the finality check, and the per-epoch processing cap):
///
/// - A deposit naming a validator that is already past its withdrawable
///   epoch can never usefully activate that balance, so it is credited
///   immediately without touching the churn budget at all.
/// - A deposit naming a validator that has started exiting, but is not yet
///   withdrawable, is **postponed**: moved out of its place in the queue and
///   appended to `deposits_to_postpone`, to be retried once the validator's
///   status resolves one way or the other. This is the branch worth reading
///   twice: dropping it here instead, the way an ordinary rejected operation
///   would be dropped, is silent stake loss, since nothing else in the state
///   transition ever revisits a discarded deposit.
/// - Anything else (an unknown pubkey, or a validator that is neither exited
///   nor withdrawn) consumes churn and is credited, unless doing so would
///   exceed the budget, in which case processing stops for this epoch as
///   described above.
pub fn process_pending_deposits(state: &mut BeaconState, config: &Config) -> Result<()> {
    let next_epoch = get_current_epoch(state) + 1;
    let churn_limit = get_activation_exit_churn_limit(state, config)?;
    let finalized_slot = compute_start_slot_at_epoch(state.finalized_checkpoint().epoch);
    let eth1_deposit_index = state.eth1_deposit_index();

    // `pending_queue_fields` borrows the whole state, so everything read
    // through it below has to finish before the loop's own, ordinary
    // mutable borrows of `state` begin. Taking `pending_deposits` by value
    // here, rather than iterating it in place, is what frees `state` for
    // those: once the queue is a plain `Vec` of its own, reading
    // `state.validators()` and crediting balances through `state` cannot
    // conflict with walking the deposits that drive those reads and writes.
    let (deposit_requests_start_index, available_for_processing, deposits) = {
        let mut fields = pending_queue_fields(state, "process_pending_deposits")?;
        let deposit_requests_start_index = fields.deposit_requests_start_index();
        let available_for_processing = fields
            .deposit_balance_to_consume()
            .checked_add(churn_limit)
            .ok_or(Error::ArithmeticOverflow(
                "deposit_balance_to_consume + get_activation_exit_churn_limit",
            ))?;
        let deposits: Vec<electra::PendingDeposit> =
            core::mem::take(fields.pending_deposits_mut()).into_inner();
        (
            deposit_requests_start_index,
            available_for_processing,
            deposits,
        )
    };

    let mut processed_amount: Gwei = 0;
    let mut next_deposit_index = 0usize;
    let mut deposits_to_postpone: Vec<electra::PendingDeposit> = Vec::new();
    let mut is_churn_limit_reached = false;

    for deposit in &deposits {
        // Eth1 bridge deposits (`slot == GENESIS_SLOT`) must all be applied
        // before the first deposit *request* is: the two sources are ordered
        // relative to each other only by this check, since a request's own
        // slot says nothing about where it falls in the bridge's queue.
        if deposit.slot > constants::GENESIS_SLOT
            && eth1_deposit_index < deposit_requests_start_index
        {
            break;
        }

        // A deposit whose queue position could still be reorged out must
        // wait: crediting it now and reverting later is not an option, since
        // nothing else in the state transition undoes a balance change.
        if deposit.slot > finalized_slot {
            break;
        }

        if next_deposit_index >= preset::MAX_PENDING_DEPOSITS_PER_EPOCH as usize {
            break;
        }

        let (is_validator_exited, is_validator_withdrawn) = match state
            .validators()
            .iter()
            .position(|validator| validator.pubkey == deposit.pubkey)
        {
            Some(index) => {
                let validator = &state.validators()[index];
                (
                    validator.exit_epoch < FAR_FUTURE_EPOCH,
                    validator.withdrawable_epoch < next_epoch,
                )
            }
            None => (false, false),
        };

        if is_validator_withdrawn {
            apply_pending_deposit(state, deposit, config)?;
        } else if is_validator_exited {
            deposits_to_postpone.push(deposit.clone());
        } else {
            match processed_amount.checked_add(deposit.amount) {
                Some(sum) if sum <= available_for_processing => {
                    processed_amount = sum;
                    apply_pending_deposit(state, deposit, config)?;
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

    // Leftover churn is only worth remembering when it was actually the
    // reason processing stopped: if the queue simply ran out, or one of the
    // ordering gates stopped it first, next epoch's budget starts fresh
    // rather than inheriting room this epoch never even tried to spend.
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
    *fields.pending_deposits_mut() = electra::PendingDeposits::try_from(remaining)?;
    *fields.deposit_balance_to_consume_mut() = deposit_balance_to_consume;

    Ok(())
}

/// Credits one dequeued [`electra::PendingDeposit`]: as a balance top-up if
/// its pubkey already has a registry entry, or as a brand-new validator
/// (subject to [`is_valid_deposit_signature`]) if it does not.
///
/// The specification's own `apply_pending_deposit`. Not a call into
/// `crate::stf::operations::apply_deposit`: that function answers the
/// equivalent question for block processing's own, differently-shaped
/// deposit path (a file this task does not own), and, as read while writing
/// this, still builds a new validator phase0's way; see
/// [`add_validator_from_pending_deposit`]'s doc for exactly how reusing it
/// would go wrong here.
fn apply_pending_deposit(
    state: &mut BeaconState,
    deposit: &electra::PendingDeposit,
    config: &Config,
) -> Result<()> {
    let existing_index = state
        .validators()
        .iter()
        .position(|validator| validator.pubkey == deposit.pubkey);

    match existing_index {
        Some(index) => increase_balance(state, index as ValidatorIndex, deposit.amount),
        None if is_valid_deposit_signature(
            deposit.pubkey,
            deposit.withdrawal_credentials,
            deposit.amount,
            deposit.signature,
            config,
        ) =>
        {
            add_validator_from_pending_deposit(
                state,
                deposit.pubkey,
                deposit.withdrawal_credentials,
                deposit.amount,
            )
        }
        // An invalid signature is not an error: the deposit is simply never
        // credited to a new validator, the same tolerance
        // `crate::stf::operations::apply_deposit` documents for its own,
        // block-processing deposit path.
        None => Ok(()),
    }
}

/// Whether `signature` is a valid proof of possession over (`pubkey`,
/// `withdrawal_credentials`, `amount`).
///
/// The specification's own domain, `compute_domain(DOMAIN_DEPOSIT)` with no
/// fork version or validators root supplied, defaults to the genesis fork
/// version and an all-zero validators root: exactly what
/// [`compute_deposit_domain`] already computes for phase0's own deposit path,
/// so this reuses it rather than re-deriving the same default by hand. A
/// deposit is signed by a depositor with no way to know which fork, or even
/// which chain, will eventually accept it, which is why this is the one
/// signature check in the whole state transition that does not commit to a
/// specific fork version or genesis validators root the way every other one
/// does.
fn is_valid_deposit_signature(
    pubkey: BlsPubkey,
    withdrawal_credentials: Bytes32,
    amount: Gwei,
    signature: BlsSignature,
    config: &Config,
) -> bool {
    let deposit_message = DepositMessage {
        pubkey,
        withdrawal_credentials,
        amount,
    };
    let domain = compute_deposit_domain(config.genesis_fork_version);
    let signing_root = compute_signing_root(deposit_message.hash_tree_root(), domain);
    bls::verify(&pubkey, signing_root, &signature)
}

/// Builds and appends a brand-new validator for a pending deposit whose
/// pubkey has no existing registry entry.
///
/// A second copy of the specification's electra-modified
/// `add_validator_to_registry`, not a call into
/// `crate::stf::operations::add_validator_to_registry`: that copy belongs to
/// block processing's own deposit path (a file this task does not own) and,
/// as read while writing this, still caps a new validator's effective
/// balance at the phase0 `MAX_EFFECTIVE_BALANCE` rather than
/// [`get_max_effective_balance`]'s per-validator ceiling, and never extends
/// `previous_epoch_participation`, `current_epoch_participation`, or
/// `inactivity_scores` (fields phase0 does not have). Reusing it here would
/// activate a compounding validator at the wrong ceiling and desync those
/// three lists from the registry the moment a pending deposit creates a
/// validator, since nothing would ever grow them back into with the
/// registry's own length again.
fn add_validator_from_pending_deposit(
    state: &mut BeaconState,
    pubkey: BlsPubkey,
    withdrawal_credentials: Bytes32,
    amount: Gwei,
) -> Result<()> {
    let mut validator = Validator {
        pubkey,
        withdrawal_credentials,
        activation_eligibility_epoch: FAR_FUTURE_EPOCH,
        activation_epoch: FAR_FUTURE_EPOCH,
        exit_epoch: FAR_FUTURE_EPOCH,
        withdrawable_epoch: FAR_FUTURE_EPOCH,
        ..Default::default()
    };
    // `get_max_effective_balance` only reads `withdrawal_credentials`, which
    // is already set above, so the ceiling is correct even though
    // `effective_balance` itself is still the zero `Default` placeholder.
    // Subtracting the remainder can never underflow, since a modulus is
    // always at most the value it divides.
    let max_effective_balance = get_max_effective_balance(&validator);
    validator.effective_balance =
        (amount - amount % preset::EFFECTIVE_BALANCE_INCREMENT).min(max_effective_balance);

    state.validators_mut().push(validator)?;
    state.balances_mut().push(amount)?;
    pending_queue_fields(state, "add_validator_from_pending_deposit")?
        .push_empty_participation_and_inactivity()
}

// ---------------------------------------------------------------------------
// Pending consolidations
// ---------------------------------------------------------------------------

/// Applies queued validator consolidations (EIP-7251), moving each eligible
/// source's balance to its target.
///
/// New in electra. Unlike [`process_pending_deposits`], nothing here is
/// balance-churn-limited: a consolidation moves stake between two validators
/// already counted in the active balance rather than admitting new stake, so
/// it cannot grow the total the way a deposit can, and there is nothing left
/// for a churn budget to protect against. `config` is threaded through only
/// so this matches the signature every other step of [`process_epoch`]'s
/// pipeline is called with, the same reason
/// `super::registry::process_slashings` takes one it never reads.
///
/// The queue is drained strictly from the front, but its two stopping
/// conditions behave differently. A slashed source is dropped from the queue
/// outright: its balance is already earmarked for the slashing penalty
/// instead of its intended target, and no later epoch changes that, so
/// nothing is gained by keeping the entry around. A source that is not yet
/// withdrawable simply stops the pass: that entry, and everything queued
/// behind it, is left in place (not postponed to the back, unlike
/// [`process_pending_deposits`]'s exited-validator case) to be retried once
/// it clears.
pub fn process_pending_consolidations(state: &mut BeaconState, _config: &Config) -> Result<()> {
    let next_epoch = get_current_epoch(state) + 1;

    let consolidations: Vec<electra::PendingConsolidation> = {
        let mut fields = pending_queue_fields(state, "process_pending_consolidations")?;
        core::mem::take(fields.pending_consolidations_mut()).into_inner()
    };

    let mut next_pending_consolidation = 0usize;
    for consolidation in &consolidations {
        let (slashed, withdrawable_epoch, effective_balance) = {
            let source = state.validator(consolidation.source_index)?;
            (
                source.slashed,
                source.withdrawable_epoch,
                source.effective_balance,
            )
        };

        if slashed {
            next_pending_consolidation += 1;
            continue;
        }
        if withdrawable_epoch > next_epoch {
            break;
        }

        let source_effective_balance = state
            .balance(consolidation.source_index)?
            .min(effective_balance);
        decrease_balance(state, consolidation.source_index, source_effective_balance)?;
        increase_balance(state, consolidation.target_index, source_effective_balance)?;
        next_pending_consolidation += 1;
    }

    let remaining: Vec<electra::PendingConsolidation> = consolidations
        .into_iter()
        .skip(next_pending_consolidation)
        .collect();
    let mut fields = pending_queue_fields(state, "process_pending_consolidations")?;
    *fields.pending_consolidations_mut() = electra::PendingConsolidations::try_from(remaining)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Effective balance updates
// ---------------------------------------------------------------------------

/// Moves each validator's effective balance toward its actual balance,
/// replacing `super::process_effective_balance_updates` for this fork.
///
/// The only change from that version: the ceiling each validator rounds
/// toward is [`get_max_effective_balance`], read per validator, rather than
/// the single `MAX_EFFECTIVE_BALANCE` every validator shared before
/// EIP-7251, since a compounding validator's ceiling can be far higher. The
/// hysteresis arithmetic itself is copied unchanged from that version, down
/// to computing `HYSTERESIS_INCREMENT` by dividing first and only then
/// multiplying it up to each threshold: multiplying before dividing is
/// algebraically equivalent but rounds differently, and only the
/// specification's own order reproduces its integer rounding.
pub fn process_effective_balance_updates(state: &mut BeaconState) -> Result<()> {
    const HYSTERESIS_INCREMENT: Gwei =
        preset::EFFECTIVE_BALANCE_INCREMENT / preset::HYSTERESIS_QUOTIENT;
    const DOWNWARD_THRESHOLD: Gwei = HYSTERESIS_INCREMENT * preset::HYSTERESIS_DOWNWARD_MULTIPLIER;
    const UPWARD_THRESHOLD: Gwei = HYSTERESIS_INCREMENT * preset::HYSTERESIS_UPWARD_MULTIPLIER;

    // Two passes for the same reason `super::process_effective_balance_updates`
    // needs them: `state` is an enum over per-fork structs, so there is no
    // way to hold `validators` mutably while also reading `balances`, or
    // (here) while calling `get_max_effective_balance` on the validator
    // being decided on.
    let mut updates = Vec::new();
    for (index, validator) in state.validators().iter().enumerate() {
        let balance = state.balances()[index];
        if balance + DOWNWARD_THRESHOLD < validator.effective_balance
            || validator.effective_balance + UPWARD_THRESHOLD < balance
        {
            let max_effective_balance = get_max_effective_balance(validator);
            let effective = (balance - balance % preset::EFFECTIVE_BALANCE_INCREMENT)
                .min(max_effective_balance);
            updates.push((index, effective));
        }
    }

    let validators = state.validators_mut();
    for (index, effective) in updates {
        validators[index].effective_balance = effective;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Fork projection
// ---------------------------------------------------------------------------

/// Fields [`process_pending_deposits`] and [`process_pending_consolidations`]
/// need that [`crate::helpers::electra::electra_state`] does not expose: that
/// projection only covers what its own module's functions need (the exit and
/// consolidation churn cursors, and `pending_deposits_mut` for
/// `queue_excess_active_balance` and its neighbors). This crate keeps one
/// file per fork's own state-transition concerns, so a second, file-local
/// projection lives here rather than as an addition to that module, even
/// though its shape, an electra-or-fulu match, is identical: fulu keeps every
/// field this covers unchanged (see `crate::helpers::electra`'s own module
/// doc for why that module's projection accepts fulu too).
enum PendingQueueFields<'a> {
    Electra(&'a mut electra::BeaconState),
    Fulu(&'a mut fulu::BeaconState),
}

impl<'a> PendingQueueFields<'a> {
    /// The execution-layer deposit request index at which the state switched
    /// from crediting deposits off `Eth1Data` votes to crediting them off
    /// `DepositRequest`s directly, read by [`process_pending_deposits`] to
    /// know whether any eth1-bridge deposit is still outstanding.
    fn deposit_requests_start_index(&self) -> u64 {
        match self {
            PendingQueueFields::Electra(state) => state.deposit_requests_start_index,
            PendingQueueFields::Fulu(state) => state.deposit_requests_start_index,
        }
    }

    /// How much of this epoch's deposit balance churn limit remains unused.
    fn deposit_balance_to_consume(&self) -> Gwei {
        match self {
            PendingQueueFields::Electra(state) => state.deposit_balance_to_consume,
            PendingQueueFields::Fulu(state) => state.deposit_balance_to_consume,
        }
    }

    fn deposit_balance_to_consume_mut(&mut self) -> &mut Gwei {
        match self {
            PendingQueueFields::Electra(state) => &mut state.deposit_balance_to_consume,
            PendingQueueFields::Fulu(state) => &mut state.deposit_balance_to_consume,
        }
    }

    /// Deposits known but not yet credited to the validator registry.
    fn pending_deposits_mut(&mut self) -> &mut electra::PendingDeposits {
        match self {
            PendingQueueFields::Electra(state) => &mut state.pending_deposits,
            PendingQueueFields::Fulu(state) => &mut state.pending_deposits,
        }
    }

    /// Consolidations known but not yet applied.
    fn pending_consolidations_mut(&mut self) -> &mut electra::PendingConsolidations {
        match self {
            PendingQueueFields::Electra(state) => &mut state.pending_consolidations,
            PendingQueueFields::Fulu(state) => &mut state.pending_consolidations,
        }
    }

    /// Extends `previous_epoch_participation`, `current_epoch_participation`,
    /// and `inactivity_scores` by one all-zero entry each, keeping them
    /// exactly as long as the registry after
    /// [`add_validator_from_pending_deposit`] appends a validator.
    fn push_empty_participation_and_inactivity(&mut self) -> Result<()> {
        match self {
            PendingQueueFields::Electra(state) => {
                state.previous_epoch_participation.push(0)?;
                state.current_epoch_participation.push(0)?;
                state.inactivity_scores.push(0)?;
            }
            PendingQueueFields::Fulu(state) => {
                state.previous_epoch_participation.push(0)?;
                state.current_epoch_participation.push(0)?;
                state.inactivity_scores.push(0)?;
            }
        }
        Ok(())
    }
}

/// The electra-or-fulu state, mutably, through [`PendingQueueFields`]. See
/// its own doc for why this is a second projection rather than a call into
/// [`crate::helpers::electra::electra_state`].
fn pending_queue_fields<'a>(
    state: &'a mut BeaconState,
    function: &'static str,
) -> Result<PendingQueueFields<'a>> {
    match state {
        BeaconState::Electra(state) => Ok(PendingQueueFields::Electra(state)),
        BeaconState::Fulu(state) => Ok(PendingQueueFields::Fulu(state)),
        other => Err(Error::UnsupportedForFork {
            function,
            fork: other.fork_name(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blst::min_pk::SecretKey;

    use crate::fork::ForkName;

    /// An electra state with `count` fully active, full-balance validators,
    /// positioned one epoch in, the same way
    /// `crate::helpers::test_state::with_validators` positions its phase0
    /// state.
    ///
    /// A thin wrapper around the shared fork-parameterised builder: see
    /// [`crate::helpers::test_state::with_validators_at`] for the construction
    /// this and every other fork's test module used to duplicate.
    fn electra_state_with_validators(count: usize) -> BeaconState {
        crate::helpers::test_state::with_validators_at(ForkName::Electra, count)
    }

    // -----------------------------------------------------------------------
    // process_pending_deposits
    // -----------------------------------------------------------------------

    #[test]
    fn a_pending_deposit_for_an_already_withdrawn_validator_bypasses_churn() {
        let config = Config::mainnet();
        let mut state = electra_state_with_validators(2);
        let next_epoch = get_current_epoch(&state) + 1;

        let (pubkey, withdrawal_credentials) = {
            let validator = state.validator_mut(0).unwrap();
            validator.exit_epoch = 0;
            validator.withdrawable_epoch = 0;
            (validator.pubkey, validator.withdrawal_credentials)
        };
        assert!(state.validator(0).unwrap().withdrawable_epoch < next_epoch);

        let churn_limit = get_activation_exit_churn_limit(&state, &config).unwrap();
        // Deliberately larger than the whole churn budget: a withdrawn
        // validator's deposit must go through regardless of budget.
        let deposit_amount = churn_limit + preset::EFFECTIVE_BALANCE_INCREMENT;
        let deposit = electra::PendingDeposit {
            pubkey,
            withdrawal_credentials,
            amount: deposit_amount,
            signature: BlsSignature::default(),
            slot: constants::GENESIS_SLOT,
        };
        pending_queue_fields(&mut state, "test setup")
            .unwrap()
            .pending_deposits_mut()
            .push(deposit)
            .unwrap();

        let balance_before = state.balance(0).unwrap();
        process_pending_deposits(&mut state, &config).unwrap();

        assert_eq!(state.balance(0).unwrap(), balance_before + deposit_amount);
        let mut fields = pending_queue_fields(&mut state, "test assertion").unwrap();
        assert_eq!(fields.deposit_balance_to_consume(), 0);
        assert!(fields.pending_deposits_mut().is_empty());
    }

    #[test]
    fn a_pending_deposit_for_an_exited_but_not_yet_withdrawn_validator_is_postponed_not_dropped() {
        let config = Config::mainnet();
        let mut state = electra_state_with_validators(2);
        let next_epoch = get_current_epoch(&state) + 1;

        let (pubkey, withdrawal_credentials) = {
            let validator = state.validator_mut(0).unwrap();
            validator.exit_epoch = 0;
            // Still far from withdrawable: `next_epoch` must not exceed this.
            validator.withdrawable_epoch = FAR_FUTURE_EPOCH;
            (validator.pubkey, validator.withdrawal_credentials)
        };
        assert!(state.validator(0).unwrap().withdrawable_epoch >= next_epoch);

        let deposit = electra::PendingDeposit {
            pubkey,
            withdrawal_credentials,
            amount: preset::EFFECTIVE_BALANCE_INCREMENT,
            signature: BlsSignature::default(),
            slot: constants::GENESIS_SLOT,
        };
        pending_queue_fields(&mut state, "test setup")
            .unwrap()
            .pending_deposits_mut()
            .push(deposit.clone())
            .unwrap();

        let balance_before = state.balance(0).unwrap();
        process_pending_deposits(&mut state, &config).unwrap();

        // Not applied...
        assert_eq!(state.balance(0).unwrap(), balance_before);
        // ...and not lost: it comes back out the other end of the queue.
        let mut fields = pending_queue_fields(&mut state, "test assertion").unwrap();
        let remaining = fields.pending_deposits_mut();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0], deposit);
    }

    #[test]
    fn pending_deposits_stop_at_the_churn_limit_and_the_rest_stay_queued_in_place() {
        let config = Config::mainnet();
        let mut state = electra_state_with_validators(2);
        let churn_limit = get_activation_exit_churn_limit(&state, &config).unwrap();

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
            signature: BlsSignature::default(),
            slot: constants::GENESIS_SLOT,
        };
        let second = electra::PendingDeposit {
            pubkey: pubkey_1,
            withdrawal_credentials: credentials_1,
            amount: second_amount,
            signature: BlsSignature::default(),
            slot: constants::GENESIS_SLOT,
        };
        {
            let mut fields = pending_queue_fields(&mut state, "test setup").unwrap();
            fields.pending_deposits_mut().push(first).unwrap();
            fields.pending_deposits_mut().push(second.clone()).unwrap();
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

        let mut fields = pending_queue_fields(&mut state, "test assertion").unwrap();
        assert_eq!(
            fields.deposit_balance_to_consume(),
            churn_limit - first_amount
        );
        let remaining = fields.pending_deposits_mut();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0], second);
    }

    #[test]
    fn a_pending_deposit_for_an_unseen_pubkey_activates_a_new_validator_at_its_own_ceiling() {
        let config = Config::mainnet();
        let mut state = electra_state_with_validators(1);

        let secret_key = SecretKey::key_gen(&[9u8; 32], &[]).expect("32 bytes of key material");
        let pubkey = BlsPubkey(secret_key.sk_to_pk().to_bytes());
        let mut withdrawal_credentials = Bytes32::zero();
        withdrawal_credentials.0[0] = constants::COMPOUNDING_WITHDRAWAL_PREFIX;
        let amount = preset::MIN_ACTIVATION_BALANCE + preset::EFFECTIVE_BALANCE_INCREMENT;

        let deposit_message = DepositMessage {
            pubkey,
            withdrawal_credentials,
            amount,
        };
        let domain = compute_deposit_domain(config.genesis_fork_version);
        let signing_root = compute_signing_root(deposit_message.hash_tree_root(), domain);
        // The same domain separation tag `crate::bls` signs and verifies
        // under, redefined here because that module keeps it private; see
        // `crate::stf::operations::tests`'s own attester-slashing test for
        // the same pattern applied to a different domain.
        const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
        let signature = BlsSignature(
            secret_key
                .sign(signing_root.as_bytes(), DST, &[])
                .to_bytes(),
        );

        let deposit = electra::PendingDeposit {
            pubkey,
            withdrawal_credentials,
            amount,
            signature,
            slot: constants::GENESIS_SLOT,
        };
        pending_queue_fields(&mut state, "test setup")
            .unwrap()
            .pending_deposits_mut()
            .push(deposit)
            .unwrap();

        let validators_before = state.validators().len();
        process_pending_deposits(&mut state, &config).unwrap();

        assert_eq!(state.validators().len(), validators_before + 1);
        let new_index = validators_before as ValidatorIndex;
        let new_validator = state.validator(new_index).unwrap();
        assert_eq!(new_validator.pubkey, pubkey);
        // A compounding credential from birth, so the deposit's whole amount
        // (comfortably under `MAX_EFFECTIVE_BALANCE_ELECTRA`) becomes
        // effective balance rather than being capped at the non-compounding
        // `MIN_ACTIVATION_BALANCE` ceiling.
        assert_eq!(new_validator.effective_balance, amount);
        assert_eq!(state.balance(new_index).unwrap(), amount);

        // The participation and inactivity lists must stay exactly as long
        // as the registry, or a later epoch's indexing into them for this
        // validator panics or errors.
        match &state {
            BeaconState::Electra(inner) => {
                assert_eq!(
                    inner.previous_epoch_participation.len(),
                    state.validators().len()
                );
                assert_eq!(
                    inner.current_epoch_participation.len(),
                    state.validators().len()
                );
                assert_eq!(inner.inactivity_scores.len(), state.validators().len());
            }
            _ => unreachable!("electra_state_with_validators always builds an Electra state"),
        }
    }

    #[test]
    fn a_pending_deposit_with_an_invalid_signature_is_dropped_not_added() {
        let config = Config::mainnet();
        let mut state = electra_state_with_validators(1);

        let deposit = electra::PendingDeposit {
            pubkey: BlsPubkey::default(),
            withdrawal_credentials: Bytes32::zero(),
            amount: preset::MIN_ACTIVATION_BALANCE,
            signature: BlsSignature::default(),
            slot: constants::GENESIS_SLOT,
        };
        pending_queue_fields(&mut state, "test setup")
            .unwrap()
            .pending_deposits_mut()
            .push(deposit)
            .unwrap();

        let validators_before = state.validators().len();
        process_pending_deposits(&mut state, &config).unwrap();

        assert_eq!(
            state.validators().len(),
            validators_before,
            "an invalid signature must not create a validator"
        );
        let mut fields = pending_queue_fields(&mut state, "test assertion").unwrap();
        assert!(
            fields.pending_deposits_mut().is_empty(),
            "the entry is still consumed from the queue, just never credited"
        );
    }

    // -----------------------------------------------------------------------
    // process_pending_consolidations
    // -----------------------------------------------------------------------

    #[test]
    fn a_pending_consolidation_from_a_slashed_source_is_dropped_from_the_queue() {
        let config = Config::mainnet();
        let mut state = electra_state_with_validators(2);
        state.validator_mut(0).unwrap().slashed = true;

        let consolidation = electra::PendingConsolidation {
            source_index: 0,
            target_index: 1,
        };
        pending_queue_fields(&mut state, "test setup")
            .unwrap()
            .pending_consolidations_mut()
            .push(consolidation)
            .unwrap();

        let source_balance_before = state.balance(0).unwrap();
        let target_balance_before = state.balance(1).unwrap();
        process_pending_consolidations(&mut state, &config).unwrap();

        assert_eq!(state.balance(0).unwrap(), source_balance_before);
        assert_eq!(state.balance(1).unwrap(), target_balance_before);
        let mut fields = pending_queue_fields(&mut state, "test assertion").unwrap();
        assert!(fields.pending_consolidations_mut().is_empty());
    }

    #[test]
    fn a_pending_consolidation_not_yet_withdrawable_stays_queued_in_place() {
        let config = Config::mainnet();
        let mut state = electra_state_with_validators(2);
        let next_epoch = get_current_epoch(&state) + 1;
        state.validator_mut(0).unwrap().withdrawable_epoch = next_epoch + 1;

        let consolidation = electra::PendingConsolidation {
            source_index: 0,
            target_index: 1,
        };
        pending_queue_fields(&mut state, "test setup")
            .unwrap()
            .pending_consolidations_mut()
            .push(consolidation.clone())
            .unwrap();

        process_pending_consolidations(&mut state, &config).unwrap();

        let mut fields = pending_queue_fields(&mut state, "test assertion").unwrap();
        let remaining = fields.pending_consolidations_mut();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0], consolidation);
    }

    #[test]
    fn an_eligible_pending_consolidation_moves_the_source_balance_to_the_target() {
        let config = Config::mainnet();
        let mut state = electra_state_with_validators(2);
        state.validator_mut(0).unwrap().withdrawable_epoch = 0;

        let consolidation = electra::PendingConsolidation {
            source_index: 0,
            target_index: 1,
        };
        pending_queue_fields(&mut state, "test setup")
            .unwrap()
            .pending_consolidations_mut()
            .push(consolidation)
            .unwrap();

        let source_effective_balance = state.validator(0).unwrap().effective_balance;
        let source_balance_before = state.balance(0).unwrap();
        let target_balance_before = state.balance(1).unwrap();

        process_pending_consolidations(&mut state, &config).unwrap();

        let moved = source_balance_before.min(source_effective_balance);
        assert_eq!(state.balance(0).unwrap(), source_balance_before - moved);
        assert_eq!(state.balance(1).unwrap(), target_balance_before + moved);
        let mut fields = pending_queue_fields(&mut state, "test assertion").unwrap();
        assert!(fields.pending_consolidations_mut().is_empty());
    }

    // -----------------------------------------------------------------------
    // process_registry_updates
    // -----------------------------------------------------------------------

    #[test]
    fn every_finalized_eligible_validator_activates_the_same_epoch_uncapped_by_headcount() {
        let config = Config::mainnet();
        // More candidates than phase0's old count-based churn limit would
        // ever admit in one epoch, to make the absence of that cap here
        // unmistakable.
        let count = config.min_per_epoch_churn_limit as usize + 4;
        let mut state = electra_state_with_validators(count);

        for index in 0..count as ValidatorIndex {
            let validator = state.validator_mut(index).unwrap();
            validator.activation_eligibility_epoch = 0; // already finalized
            validator.activation_epoch = FAR_FUTURE_EPOCH; // not yet activated
        }

        process_registry_updates(&mut state, &config).unwrap();

        for index in 0..count as ValidatorIndex {
            assert_ne!(
                state.validator(index).unwrap().activation_epoch,
                FAR_FUTURE_EPOCH,
                "validator {index} should have activated: electra rate-limits admission by \
                 balance, not by a per-epoch headcount",
            );
        }
    }

    // -----------------------------------------------------------------------
    // process_effective_balance_updates
    // -----------------------------------------------------------------------

    #[test]
    fn effective_balance_updates_cap_a_compounding_validator_higher_than_a_regular_one() {
        let mut state = electra_state_with_validators(2);
        state.validator_mut(1).unwrap().withdrawal_credentials.0[0] =
            constants::COMPOUNDING_WITHDRAWAL_PREFIX;

        // Push both balances far above either ceiling, so the update fires
        // and both validators are actually capped, not merely nudged.
        let huge = preset::MAX_EFFECTIVE_BALANCE_ELECTRA + preset::EFFECTIVE_BALANCE_INCREMENT;
        state.balances_mut()[0] = huge;
        state.balances_mut()[1] = huge;

        process_effective_balance_updates(&mut state).unwrap();

        assert_eq!(
            state.validator(0).unwrap().effective_balance,
            preset::MIN_ACTIVATION_BALANCE,
            "a non-compounding validator is still capped at MIN_ACTIVATION_BALANCE"
        );
        assert_eq!(
            state.validator(1).unwrap().effective_balance,
            preset::MAX_EFFECTIVE_BALANCE_ELECTRA,
            "a compounding validator's ceiling is MAX_EFFECTIVE_BALANCE_ELECTRA instead"
        );
    }

    // -----------------------------------------------------------------------
    // process_slashings
    // -----------------------------------------------------------------------

    /// A slashing outside the withdrawable window must leave the balance
    /// untouched, the same guard `super::registry::process_slashings` has.
    #[test]
    fn a_slashing_outside_the_withdrawable_window_is_untouched() {
        let config = Config::mainnet();
        let mut state = electra_state_with_validators(4);
        let balance_before = state.balance(1).unwrap();

        state.validator_mut(1).unwrap().slashed = true;
        state.slashings_mut()[0] = preset::MAX_EFFECTIVE_BALANCE_ELECTRA;

        process_slashings(&mut state, &config).unwrap();

        assert_eq!(state.balance(1).unwrap(), balance_before);
    }

    /// A worked example of the divergence [`process_slashings`]'s own doc
    /// describes. A slashed sum equal to `total_increments` (the total active
    /// balance's own increment count) is dwarfed by `total_balance` itself,
    /// which is `total_increments` whole copies of `EFFECTIVE_BALANCE_INCREMENT`,
    /// but it is exactly enough for electra's own division,
    /// `adjusted_total_slashing_balance / total_increments`, to clear its
    /// floor: the two cancel to precisely `multiplier`, with nothing left
    /// over. `super::registry::process_slashings` divides by the raw
    /// `total_balance` instead of `total_increments`, a divisor larger by a
    /// factor of `EFFECTIVE_BALANCE_INCREMENT`, so the identical input never
    /// clears *that* floor and rounds down to no penalty at all.
    ///
    /// This is not a contrived corner case: it is the ordinary shape of a
    /// single validator's slashing measured against a whole active set's
    /// balance, which is exactly why reusing the shared, pre-electra copy for
    /// this fork would silently drop real penalties rather than merely
    /// rounding them differently.
    #[test]
    fn electras_division_order_still_penalizes_where_the_shared_copy_rounds_to_zero() {
        let config = Config::mainnet();
        let mut state = electra_state_with_validators(4);
        let epoch = get_current_epoch(&state);

        let total_balance = get_total_active_balance(&state).unwrap();
        let total_increments = total_balance / preset::EFFECTIVE_BALANCE_INCREMENT;
        let multiplier = preset::retuned::proportional_slashing_multiplier(state.fork_name());

        let validator = state.validator_mut(1).unwrap();
        validator.slashed = true;
        validator.withdrawable_epoch = epoch + (preset::EPOCHS_PER_SLASHINGS_VECTOR / 2) as Epoch;
        let effective_balance_increments =
            validator.effective_balance / preset::EFFECTIVE_BALANCE_INCREMENT;

        state.slashings_mut()[0] = total_increments;

        let mut shared_copy_state = state.clone();
        process_slashings(&mut state, &config).unwrap();
        super::super::registry::process_slashings(&mut shared_copy_state, &config).unwrap();

        let expected_penalty = multiplier * effective_balance_increments;
        assert_eq!(
            preset::MIN_ACTIVATION_BALANCE - state.balance(1).unwrap(),
            expected_penalty,
            "electra's own division order lands exactly multiplier * effective_balance_increments"
        );
        assert_eq!(
            shared_copy_state.balance(1).unwrap(),
            preset::MIN_ACTIVATION_BALANCE,
            "the shared, pre-electra copy rounds the exact same inputs down to no penalty at all"
        );
    }
}
