//! Fulu-specific epoch processing.
//!
//! Fulu's "Epoch processing" section (`beacon-chain.md`) redefines
//! `process_epoch` in two ways: it appends one new step,
//! [`process_proposer_lookahead`] (EIP-7917), after electra's last one, and it
//! retires the eth1-bridge deposit mechanism's last trace in
//! [`process_pending_deposits`] (this module's own, not electra's shared one;
//! see that function's own doc for why sharing it would be wrong here, not
//! merely redundant). Every other step carries over unchanged: the state
//! simply grows one more piece of bookkeeping for
//! [`process_proposer_lookahead`] to maintain.
//!
//! [`process_proposer_lookahead`] keeps `BeaconState::proposer_lookahead`
//! (`crate::beacon::containers::fulu::BeaconState`) a fixed-length rolling window: it
//! drops the epoch that just ended (the window's oldest slice) and appends the
//! one epoch further out than the window already reached, so the window keeps
//! covering exactly the current epoch through `MIN_SEED_LOOKAHEAD` epochs
//! beyond it, the same span
//! [`crate::beacon::helpers::fulu::initialize_proposer_lookahead`] fills from scratch
//! at genesis and at the fulu upgrade. See that function's module docs for why
//! a seed, and therefore a proposer, is only ever knowable that far ahead and
//! no further.
//!
//! Gloas shares this exact function: `proposer_lookahead` keeps the identical
//! field and type from fulu on (`containers::gloas`'s own module doc), and
//! gloas's `beacon-chain.md` does not redefine this step either. Only the
//! callee that draws the newly-visible epoch's proposers differs by fork
//! (EIP-8045 excludes slashed validators for gloas), so
//! [`process_proposer_lookahead`] picks it by fork rather than being copied.
//!
//! # Why this step runs last
//!
//! The newly-visible epoch's proposers come from
//! [`crate::beacon::helpers::fulu::get_beacon_proposer_indices`], which weighs
//! [`crate::beacon::helpers::accessors::get_active_validator_indices`] and each
//! validator's `effective_balance`, both of which earlier steps in this same
//! epoch's processing change: [`super::registry::process_registry_updates`]
//! moves validators into or out of the active set, and
//! [`super::process_effective_balance_updates`] moves balances toward their
//! post-epoch values. Running [`process_proposer_lookahead`] after every such
//! step, rather than before, is what lets the newly-appended epoch's proposers
//! reflect this epoch's final registry state rather than a stale one; the
//! specification gets that simply by placing the step last, and this driver
//! does the same.
//!
//! The randao mix the new epoch's seed reads is not why the step sits where it
//! does. [`crate::beacon::helpers::accessors::get_seed`]'s lookback means the
//! newly-visible epoch's seed is drawn from the *current*, outgoing epoch's
//! mix, and that mix was already fixed by the last block processed in this
//! epoch, well before epoch processing starts. [`super::process_randao_mixes_reset`]
//! only ever writes the *next* epoch's slot, so running this step before or
//! after that reset would not change which mix the new epoch's seed reads;
//! only the registry and balance state matters for the ordering here.

use crate::beacon::config::Config;
use crate::beacon::constants::FAR_FUTURE_EPOCH;
use crate::beacon::containers::BeaconState;
use crate::beacon::containers::electra as electra_containers;
use crate::beacon::error::{Error, Result};
use crate::beacon::fork::ForkName;
use crate::beacon::helpers::accessors::get_current_epoch;
use crate::beacon::helpers::electra::{get_activation_exit_churn_limit, pending_queue_fields};
use crate::beacon::helpers::fulu::{get_beacon_proposer_indices, proposer_lookahead_mut};
use crate::beacon::helpers::misc::compute_start_slot_at_epoch;
use crate::beacon::lean_state_unreachable;
use crate::beacon::preset;
use crate::beacon::primitives::Gwei;

use super::electra;

/// Fulu's epoch-boundary driver, in the specification's own order
/// (`beacon-chain.md`'s "Modified `process_epoch`"): electra's own steps,
/// with this module's own [`process_pending_deposits`] standing in for
/// [`electra::process_pending_deposits`], and [`process_proposer_lookahead`]
/// appended at the end.
pub fn process_epoch(state: &mut BeaconState, config: &Config) -> Result<()> {
    super::altair::process_justification_and_finalization(state)?;
    super::altair::process_inactivity_updates(state, config)?;
    super::altair::process_rewards_and_penalties(state, config)?;
    electra::process_registry_updates(state, config)?;
    electra::process_slashings(state, config)?;
    super::process_eth1_data_reset(state)?;
    process_pending_deposits(state, config)?;
    electra::process_pending_consolidations(state, config)?;
    electra::process_effective_balance_updates(state)?;
    super::process_slashings_reset(state)?;
    super::process_randao_mixes_reset(state)?;
    super::capella::process_historical_summaries_update(state)?;
    super::altair::process_participation_flag_updates(state)?;
    super::altair::process_sync_committee_updates(state)?;
    // [New in Fulu:EIP7917]
    process_proposer_lookahead(state)
}

// ---------------------------------------------------------------------------
// Pending deposits
// ---------------------------------------------------------------------------

/// Drains a balance-churn-limited amount of [`electra_containers::PendingDeposit`]s
/// into the validator registry.
///
/// [`electra::process_pending_deposits`]'s own doc covers the shape this
/// shares with it in full: strict front-to-back draining, the three outcomes
/// a dequeued entry can have, and why a deposit that would blow this epoch's
/// budget stops the whole pass rather than being skipped over.
///
/// The one thing this drops is that function's first gate, the one holding
/// every deposit *request* back until every eth1-bridge deposit ahead of it
/// (tracked by `deposit_requests_start_index`) has drained, which is exactly
/// what `beacon-chain.md`'s "Modified `process_pending_deposits`" for this
/// fork says to remove. That gate stalls the queue whenever
/// `eth1_deposit_index < deposit_requests_start_index`: either
/// `deposit_requests_start_index` is still
/// [`crate::beacon::constants::UNSET_DEPOSIT_REQUESTS_START_INDEX`] (no
/// deposit request has ever been seen), or it is set but `eth1_deposit_index`
/// has not yet drained up to it. Once `eth1_deposit_index` *has* caught up,
/// which every real network is expected to have well before it reaches fulu
/// (the eth1-bridge drain itself takes on the order of a day; electra ran
/// about seven months ahead of fulu on mainnet, sepolia, and hoodi), the gate
/// is already a no-op, which is why dropping it here changes nothing
/// observable on mainnet. The case this function actually exists for is a
/// chain that reaches a deposit request under fulu with the field either
/// still unset or set but not yet caught up: see
/// [`super::super::fulu::process_deposit_request`]'s own doc for why fulu
/// never writes it, and why pairing that with electra's gate here would stall
/// the queue for good rather than merely once. This function reads neither
/// field.
// [Modified in Fulu]
pub fn process_pending_deposits(state: &mut BeaconState, config: &Config) -> Result<()> {
    let next_epoch = get_current_epoch(state) + 1;
    let churn_limit = get_activation_exit_churn_limit(state, config)?;
    let finalized_slot = compute_start_slot_at_epoch(state.finalized_checkpoint().epoch);

    // See `electra::process_pending_deposits`'s own doc for why the queue is
    // taken by value here rather than iterated in place.
    let (available_for_processing, deposits) = {
        let mut fields = pending_queue_fields(state, "process_pending_deposits")?;
        let available_for_processing = fields
            .deposit_balance_to_consume()
            .checked_add(churn_limit)
            .ok_or(Error::ArithmeticOverflow(
                "deposit_balance_to_consume + get_activation_exit_churn_limit",
            ))?;
        let deposits: Vec<electra_containers::PendingDeposit> = fields.take_pending_deposits()?;
        (available_for_processing, deposits)
    };

    let mut processed_amount: Gwei = 0;
    let mut next_deposit_index = 0usize;
    let mut deposits_to_postpone: Vec<electra_containers::PendingDeposit> = Vec::new();
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
            electra::apply_pending_deposit(state, deposit, config)?;
        } else if is_validator_exited {
            deposits_to_postpone.push(deposit.clone());
        } else {
            match processed_amount.checked_add(deposit.amount) {
                Some(sum) if sum <= available_for_processing => {
                    processed_amount = sum;
                    electra::apply_pending_deposit(state, deposit, config)?;
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

    let remaining: Vec<electra_containers::PendingDeposit> = deposits
        .into_iter()
        .skip(next_deposit_index)
        .chain(deposits_to_postpone)
        .collect();

    // Leftover churn is only worth remembering when it was actually the
    // reason processing stopped: if the queue simply ran out, or the
    // finality or per-epoch-cap gate stopped it first, next epoch's budget
    // starts fresh rather than inheriting room this epoch never even tried
    // to spend.
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

/// Shifts `proposer_lookahead` forward by one epoch.
///
/// Drops the window's first `SLOTS_PER_EPOCH` entries (the epoch that just
/// ended) and appends `SLOTS_PER_EPOCH` more for the epoch that becomes
/// computable now that this epoch's registry and balance updates have run: see
/// the module docs for why appending happens last rather than first.
///
/// The specification writes this as two in-place slice assignments on
/// `state.proposer_lookahead`. This instead builds the whole new window as a
/// plain `Vec` and assigns it back in one piece, since `SszVector` has no
/// `Default` to grow into and its `IndexMut` only ever addresses a window that
/// already exists at its full length; building the replacement value
/// explicitly, at exactly [`preset::PROPOSER_LOOKAHEAD_LENGTH`], sidesteps
/// needing one.
pub fn process_proposer_lookahead(state: &mut BeaconState) -> Result<()> {
    // The seed for this epoch is only just now fixed, per the module docs, so
    // this is the earliest moment its proposers could have been computed.
    let new_epoch = get_current_epoch(state) + preset::MIN_SEED_LOOKAHEAD + 1;
    let new_epoch_proposers = match state.fork_name() {
        ForkName::Fulu => get_beacon_proposer_indices(state, new_epoch)?,
        // EIP-8045: gloas's own draw excludes slashed validators before
        // sampling; see `crate::beacon::helpers::gloas::get_beacon_proposer_indices`'s
        // own doc. This is the one part of the step gloas cannot share
        // unchanged; see this module's own module doc.
        ForkName::Gloas => {
            crate::beacon::helpers::gloas::get_beacon_proposer_indices(state, new_epoch)?
        }
        fork @ (ForkName::Phase0
        | ForkName::Altair
        | ForkName::Bellatrix
        | ForkName::Capella
        | ForkName::Deneb
        | ForkName::Electra) => {
            return Err(Error::UnsupportedForFork {
                function: "process_proposer_lookahead",
                fork,
            });
        }
        ForkName::Lean => lean_state_unreachable("process_proposer_lookahead"),
    };

    let slots_per_epoch = preset::SLOTS_PER_EPOCH as usize;
    let lookahead = proposer_lookahead_mut(state, "process_proposer_lookahead")?;

    let mut window = Vec::with_capacity(preset::PROPOSER_LOOKAHEAD_LENGTH);
    window.extend_from_slice(&lookahead[slots_per_epoch..]);
    window.extend(new_epoch_proposers);

    *lookahead = window.try_into().expect(
        "dropping SLOTS_PER_EPOCH entries and appending SLOTS_PER_EPOCH more preserves \
         PROPOSER_LOOKAHEAD_LENGTH",
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::constants;
    use crate::beacon::fork::ForkName;
    use crate::beacon::helpers::fulu::initialize_proposer_lookahead;
    use crate::beacon::primitives::BlsSignature;

    /// A fulu state with `count` fully active, full-balance validators and a
    /// `proposer_lookahead` filled by
    /// [`crate::beacon::helpers::fulu::initialize_proposer_lookahead`], one epoch past
    /// genesis.
    ///
    /// The shared builder leaves `proposer_lookahead` zeroed, since that
    /// field is fulu-specific and most of this module's per-fork test states
    /// never touch it; this module's own tests are exactly the ones that do,
    /// so this runs the real computation on top before handing the state
    /// back, the same override
    /// `crate::beacon::helpers::fulu::tests::fulu_state_with_validators` applies.
    fn fulu_state_with_validators(count: usize) -> BeaconState {
        let mut state =
            crate::beacon::helpers::test_state::with_validators_at(ForkName::Fulu, count);
        let lookahead = initialize_proposer_lookahead(&state).unwrap();
        if let BeaconState::Fulu(fulu_state) = &mut state {
            fulu_state.proposer_lookahead = lookahead.try_into().expect(
                "initialize_proposer_lookahead returns exactly PROPOSER_LOOKAHEAD_LENGTH indices",
            );
        }
        state
    }

    /// Reads out `proposer_lookahead` for assertions, without exposing the
    /// fork-specific projection to every test.
    fn lookahead_of(state: &BeaconState) -> Vec<crate::beacon::primitives::ValidatorIndex> {
        match state {
            BeaconState::Fulu(state) => state.proposer_lookahead.to_vec(),
            _ => unreachable!("test states here are always fulu"),
        }
    }

    #[test]
    fn process_proposer_lookahead_preserves_the_carried_over_slice() {
        let mut state = fulu_state_with_validators(32);
        let before = lookahead_of(&state);

        process_proposer_lookahead(&mut state).unwrap();

        let after = lookahead_of(&state);
        let slots_per_epoch = preset::SLOTS_PER_EPOCH as usize;
        // Everything but the oldest and newest epoch's worth of entries must
        // carry over unchanged, just shifted down by one epoch's length.
        assert_eq!(
            after[..after.len() - slots_per_epoch],
            before[slots_per_epoch..]
        );
    }

    #[test]
    fn process_proposer_lookahead_appends_the_newly_computable_epoch() {
        let state = fulu_state_with_validators(32);
        let current_epoch = get_current_epoch(&state);
        let new_epoch = current_epoch + preset::MIN_SEED_LOOKAHEAD + 1;
        let expected = get_beacon_proposer_indices(&state, new_epoch).unwrap();

        let mut state = state;
        process_proposer_lookahead(&mut state).unwrap();

        let after = lookahead_of(&state);
        let slots_per_epoch = preset::SLOTS_PER_EPOCH as usize;
        assert_eq!(after[after.len() - slots_per_epoch..], expected[..]);
    }

    #[test]
    fn process_proposer_lookahead_keeps_the_window_at_its_fixed_length() {
        let mut state = fulu_state_with_validators(32);
        process_proposer_lookahead(&mut state).unwrap();
        assert_eq!(
            lookahead_of(&state).len(),
            preset::PROPOSER_LOOKAHEAD_LENGTH
        );
    }

    #[test]
    fn process_proposer_lookahead_rejects_a_state_older_than_fulu() {
        let mut phase0_state = crate::beacon::helpers::test_state::with_validators(4);
        assert!(process_proposer_lookahead(&mut phase0_state).is_err());
    }

    // -----------------------------------------------------------------------
    // process_pending_deposits
    // -----------------------------------------------------------------------

    /// A pending deposit shaped like one a deposit *request* would queue
    /// (`slot > GENESIS_SLOT`), topping up `index`'s own existing balance so
    /// [`electra::apply_pending_deposit`] takes the
    /// signature-free top-up branch rather than needing a real one.
    fn request_sourced_pending_deposit(
        state: &BeaconState,
        index: usize,
    ) -> electra_containers::PendingDeposit {
        let validator = state.validator(index as u64).unwrap();
        electra_containers::PendingDeposit {
            pubkey: validator.pubkey,
            withdrawal_credentials: validator.withdrawal_credentials,
            amount: preset::EFFECTIVE_BALANCE_INCREMENT,
            signature: BlsSignature::default(),
            slot: constants::GENESIS_SLOT + 1,
        }
    }

    #[test]
    fn a_test_state_starts_with_deposit_requests_start_index_unset() {
        let mut state = fulu_state_with_validators(2);
        assert_eq!(
            pending_queue_fields(&mut state, "test assertion")
                .unwrap()
                .deposit_requests_start_index(),
            constants::UNSET_DEPOSIT_REQUESTS_START_INDEX
        );
    }

    #[test]
    fn an_unset_start_index_does_not_stall_fulus_own_pending_deposits() {
        let config = Config::mainnet();
        let mut state = fulu_state_with_validators(2);
        // Past the deposit's own slot, so the unrelated finality gate
        // (`deposit.slot > finalized_slot`) cannot be what lets, or blocks,
        // this deposit through; only the eth1-bridge gate is under test.
        state.finalized_checkpoint_mut().epoch = 1;
        let deposit = request_sourced_pending_deposit(&state, 0);
        pending_queue_fields(&mut state, "test setup")
            .unwrap()
            .push_pending_deposit(deposit)
            .unwrap();

        let balance_before = state.balance(0).unwrap();
        process_pending_deposits(&mut state, &config).unwrap();

        // Applied: the queue's only entry was a top-up for an active,
        // non-exited validator, so nothing here should postpone or block it.
        assert_eq!(
            state.balance(0).unwrap(),
            balance_before + preset::EFFECTIVE_BALANCE_INCREMENT
        );
        let BeaconState::Fulu(inner) = &state else {
            unreachable!("built as Fulu");
        };
        assert!(inner.pending_deposits.is_empty());
    }

    #[test]
    fn the_same_queue_stalls_forever_under_electras_own_gate() {
        let config = Config::mainnet();
        let mut state = fulu_state_with_validators(2);
        // See the previous test: past the deposit's own slot, so only the
        // eth1-bridge gate, not the unrelated finality gate, is under test.
        state.finalized_checkpoint_mut().epoch = 1;
        let deposit = request_sourced_pending_deposit(&state, 0);
        pending_queue_fields(&mut state, "test setup")
            .unwrap()
            .push_pending_deposit(deposit.clone())
            .unwrap();

        let balance_before = state.balance(0).unwrap();
        // `electra::process_pending_deposits` accepts a fulu state too (its
        // `PendingQueueFields` projection covers both), which is exactly what
        // let the pre-fix code call it here unnoticed.
        electra::process_pending_deposits(&mut state, &config).unwrap();

        // Blocked: `deposit_requests_start_index` is still
        // `UNSET_DEPOSIT_REQUESTS_START_INDEX`, so electra's
        // `eth1_deposit_index < deposit_requests_start_index` gate holds for
        // this request-sourced entry and the whole pass breaks before ever
        // reaching it.
        assert_eq!(state.balance(0).unwrap(), balance_before);
        let BeaconState::Fulu(inner) = &state else {
            unreachable!("built as Fulu");
        };
        assert_eq!(inner.pending_deposits.len(), 1);
        assert_eq!(inner.pending_deposits[0], deposit);
    }
}
