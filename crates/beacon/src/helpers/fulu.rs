//! Fulu's proposer lookahead.
//!
//! Every fork through electra computes a slot's proposer on demand: it
//! shuffles that slot's epoch's active set under a seed drawn from the
//! randao mix, and that seed only exists once the mix it reads is
//! `MIN_SEED_LOOKAHEAD` epochs old (see [`super::accessors::get_seed`]). A
//! validator therefore cannot know its own proposer duty for next epoch,
//! only for the current one, because next epoch's seed is not fixed yet.
//!
//! Fulu breaks that coupling by moving the computation off the read path.
//! `BeaconState::proposer_lookahead` (`crate::containers::fulu::BeaconState`)
//! precomputes a rolling window of upcoming proposers, one epoch at a time,
//! as far ahead as a seed is ever knowable: [`initialize_proposer_lookahead`]
//! fills the window from scratch at genesis and when upgrading to fulu, and
//! the specification's `process_proposer_lookahead` (`beacon-chain.md`'s
//! "Epoch processing", not implemented in this file, see below) shifts it
//! forward by one epoch at every later epoch boundary. Reading a duty is then
//! a lookup into whatever the window last computed, rather than a shuffle run
//! at the moment something asks: [`get_beacon_proposer_index`] becomes
//! `state.proposer_lookahead[state.slot % SLOTS_PER_EPOCH]`, an index into
//! already-settled answers instead of a computation over the current
//! shuffling seed.
//!
//! [`get_beacon_proposer_index`] here does not replace
//! [`super::accessors::get_beacon_proposer_index`] in place: the two coexist,
//! fulu's reading the precomputed window and every earlier fork's computing
//! on demand, and that accessor dispatches between them by fork itself,
//! rather than each of *its* own callers doing so, the same split
//! [`super::altair::altair_state_ref`] documents for altair's
//! participation-flag fields. A state older than fulu has no
//! `proposer_lookahead` to read, so [`get_beacon_proposer_index`] fails
//! through [`fulu_state_ref`] rather than falling back to the on-demand
//! computation.
//!
//! [`compute_proposer_indices`] and [`get_beacon_proposer_indices`] are the
//! building blocks the window is filled from. Both take a [`BeaconState`] of
//! any fork, not only fulu's, because both read the state only through
//! fork-invariant accessors (`get_active_validator_indices`, `get_seed`,
//! `state.validator`) and never touch `proposer_lookahead` themselves; the
//! specification's own `upgrade_to_fulu` (`fork.md`) relies on exactly that,
//! calling [`initialize_proposer_lookahead`] on the electra state being
//! upgraded, one slot before a `proposer_lookahead` field exists anywhere to
//! read back out of.
//!
//! This file does not implement `process_proposer_lookahead` itself: that
//! function mutates state at an epoch boundary, and every other fork's
//! equivalent epoch-processing step lives in `crate::stf`, not in a
//! `helpers::<fork>` module (see [`super::altair`]'s module docs, which make
//! the same point about `process_attestation`). [`fulu_state`] is kept
//! alongside [`fulu_state_ref`] for whenever that step is written, the same
//! way altair keeps a mutable state projection ready for its own
//! not-yet-written processing steps.

use crate::constants;
use crate::containers::{BeaconState, fulu};
use crate::error::{Error, Result};
use crate::hash::hash;
use crate::preset;
use crate::primitives::{Bytes32, Epoch, ValidatorIndex};

use super::accessors::{get_active_validator_indices, get_current_epoch, get_seed};
use super::electra::compute_proposer_index;
use super::misc::compute_start_slot_at_epoch;

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

/// The proposer for every slot of `epoch`, drawn from `indices` under `seed`.
///
/// One shuffling seed per epoch is not enough on its own: every slot of that
/// epoch would otherwise draw the same proposer. The specification mixes
/// `seed` with each slot number first (shadowing its own `seed` parameter
/// with the result, one hash per slot, inside a single list comprehension);
/// this keeps that per-slot hash in its own binding, `slot_seed`, instead.
///
/// Calls [`super::electra::compute_proposer_index`], not
/// [`super::shuffling::compute_proposer_index`]: fulu's specification builds
/// on electra's (`beacon-chain.md`'s own introduction says as much), so the
/// `compute_proposer_index` this function's own spec text calls is already
/// electra's widened-draw, `MAX_EFFECTIVE_BALANCE_ELECTRA`-weighted version,
/// not phase0's. A fulu validator can hold exactly the same balances an
/// electra one can, so nothing here would justify falling back to the
/// narrower, pre-electra acceptance test.
pub fn compute_proposer_indices(
    state: &BeaconState,
    epoch: Epoch,
    seed: Bytes32,
    indices: &[ValidatorIndex],
) -> Result<Vec<ValidatorIndex>> {
    let start_slot = compute_start_slot_at_epoch(epoch);

    let mut proposer_indices = Vec::with_capacity(preset::SLOTS_PER_EPOCH as usize);
    for offset in 0..preset::SLOTS_PER_EPOCH {
        let mut input = Vec::with_capacity(32 + 8);
        input.extend_from_slice(&seed.0);
        input.extend_from_slice(&(start_slot + offset).to_le_bytes());
        let slot_seed = hash(&input);

        let proposer_index = compute_proposer_index(indices, slot_seed, |index| {
            Ok(state.validator(index)?.effective_balance)
        })?;
        proposer_indices.push(proposer_index);
    }
    Ok(proposer_indices)
}

// ---------------------------------------------------------------------------
// Beacon state accessors
// ---------------------------------------------------------------------------

/// The proposer for every slot of `epoch`, computed fresh from that epoch's
/// active set and shuffling seed.
///
/// What [`initialize_proposer_lookahead`] calls once per epoch of the window,
/// and what the specification's `process_proposer_lookahead` (not implemented
/// in this file, see the module docs) calls once more each epoch boundary to
/// extend the window by one epoch.
pub fn get_beacon_proposer_indices(
    state: &BeaconState,
    epoch: Epoch,
) -> Result<Vec<ValidatorIndex>> {
    let indices = get_active_validator_indices(state, epoch);
    let seed = get_seed(state, epoch, constants::DOMAIN_BEACON_PROPOSER);
    compute_proposer_indices(state, epoch, seed, &indices)
}

/// The proposer for the state's current slot.
///
/// Fulu's replacement for [`super::accessors::get_beacon_proposer_index`]: a
/// lookup into the current epoch's slice of `proposer_lookahead` rather than
/// a shuffle computed on demand. See the module docs for why that lookup is
/// possible at all and why the on-demand version is not simply reused here.
pub fn get_beacon_proposer_index(state: &BeaconState) -> Result<ValidatorIndex> {
    let fulu_state = fulu_state_ref(state, "get_beacon_proposer_index")?;
    let index = (state.slot() % preset::SLOTS_PER_EPOCH) as usize;
    fulu_state
        .proposer_lookahead
        .get(index)
        .copied()
        .ok_or(Error::IndexOutOfBounds {
            index,
            len: fulu_state.proposer_lookahead.len(),
        })
}

// ---------------------------------------------------------------------------
// Fork upgrade
// ---------------------------------------------------------------------------

/// The full lookahead window for `state`'s current epoch: every proposer from
/// the start of the current epoch through `MIN_SEED_LOOKAHEAD` full epochs
/// beyond it.
///
/// Used to seed `BeaconState::proposer_lookahead` from nothing, at genesis and
/// when upgrading to fulu, which is the only time the whole window has to be
/// computed at once; every later epoch only needs one more epoch appended; see
/// the module docs for why that step is not implemented here. The loop runs
/// `MIN_SEED_LOOKAHEAD + 1` times (the current epoch, plus that many ahead of
/// it) because that many epochs of `SLOTS_PER_EPOCH` proposers each is exactly
/// [`preset::PROPOSER_LOOKAHEAD_LENGTH`] slots, the window's fixed length.
pub fn initialize_proposer_lookahead(state: &BeaconState) -> Result<Vec<ValidatorIndex>> {
    let current_epoch = get_current_epoch(state);

    let mut lookahead = Vec::with_capacity(preset::PROPOSER_LOOKAHEAD_LENGTH);
    for offset in 0..=preset::MIN_SEED_LOOKAHEAD {
        lookahead.extend(get_beacon_proposer_indices(state, current_epoch + offset)?);
    }
    Ok(lookahead)
}

// ---------------------------------------------------------------------------
// Fork projection
// ---------------------------------------------------------------------------

/// The fulu state, mutably, or an error naming the function that needs one.
///
/// Only [`get_beacon_proposer_index`] needs this: it is the one function in
/// this module that reads `proposer_lookahead` itself rather than working
/// through fork-invariant accessors. Kept alongside [`fulu_state_ref`] for
/// `process_proposer_lookahead`, which will need to write through this same
/// projection once it is written (see the module docs); nothing in this file
/// calls it yet.
#[allow(dead_code)]
pub(crate) fn fulu_state<'a>(
    state: &'a mut BeaconState,
    function: &'static str,
) -> Result<&'a mut fulu::BeaconState> {
    match state {
        BeaconState::Fulu(state) => Ok(state),
        other => Err(Error::UnsupportedForFork {
            function,
            fork: other.fork_name(),
        }),
    }
}

/// The fulu state, immutably. See [`fulu_state`].
pub(crate) fn fulu_state_ref<'a>(
    state: &'a BeaconState,
    function: &'static str,
) -> Result<&'a fulu::BeaconState> {
    match state {
        BeaconState::Fulu(state) => Ok(state),
        other => Err(Error::UnsupportedForFork {
            function,
            fork: other.fork_name(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::containers::altair::SyncCommittee;
    use crate::containers::bellatrix::LogsBloom;
    use crate::containers::deneb::ExecutionPayloadHeader;
    use crate::containers::electra::{
        PendingConsolidations, PendingDeposits, PendingPartialWithdrawals,
    };
    use crate::containers::shared::Validator;
    use crate::primitives::{
        BlsPubkey, Bytes32, ExecutionAddress, ExecutionBlockHash, Root, Uint256,
    };

    /// An all-zero execution payload header, standing in for the genesis
    /// payload: nothing in this module inspects it, so only its presence (not
    /// its contents) matters for building a fulu state.
    fn empty_execution_payload_header() -> ExecutionPayloadHeader {
        ExecutionPayloadHeader {
            parent_hash: ExecutionBlockHash::zero(),
            fee_recipient: ExecutionAddress::zero(),
            state_root: Bytes32::zero(),
            receipts_root: Bytes32::zero(),
            logs_bloom: LogsBloom::try_from(vec![0u8; preset::BYTES_PER_LOGS_BLOOM]).unwrap(),
            prev_randao: Bytes32::zero(),
            block_number: 0,
            gas_limit: 0,
            gas_used: 0,
            timestamp: 0,
            extra_data: Default::default(),
            base_fee_per_gas: Uint256::zero(),
            block_hash: ExecutionBlockHash::zero(),
            transactions_root: Root::zero(),
            withdrawals_root: Root::zero(),
            blob_gas_used: 0,
            excess_blob_gas: 0,
        }
    }

    /// A fulu state with `count` fully active, full-balance validators and a
    /// `proposer_lookahead` filled by [`initialize_proposer_lookahead`],
    /// positioned the same way `crate::helpers::test_state::with_validators`
    /// positions its phase0 state: one epoch in, so the previous epoch and
    /// the block-root history window both have entries.
    ///
    /// Not added to `test_state`, which only ever builds phase0 states, and
    /// modeled on `crate::helpers::altair::tests::altair_state_with_validators`,
    /// which is the first of these per-fork test builders and has the same
    /// justification for staying local to its own module rather than growing
    /// `test_state` into a fork-dispatching helper for a single caller each.
    /// These builders are accumulating one per fork now; sharing the
    /// fork-invariant field setup between them would be worth doing once a
    /// third or fourth one shows up.
    fn fulu_state_with_validators(count: usize) -> BeaconState {
        let validators: Vec<Validator> = (0..count)
            .map(|_| Validator {
                effective_balance: preset::MAX_EFFECTIVE_BALANCE,
                activation_eligibility_epoch: 0,
                activation_epoch: 0,
                exit_epoch: constants::FAR_FUTURE_EPOCH,
                withdrawable_epoch: constants::FAR_FUTURE_EPOCH,
                ..Default::default()
            })
            .collect();

        let empty_sync_committee = || SyncCommittee {
            pubkeys: vec![BlsPubkey::default(); preset::SYNC_COMMITTEE_SIZE]
                .try_into()
                .expect("built at exactly SYNC_COMMITTEE_SIZE"),
            aggregate_pubkey: BlsPubkey::default(),
        };

        let mut state = BeaconState::Fulu(fulu::BeaconState {
            genesis_time: 0,
            genesis_validators_root: Root::zero(),
            slot: preset::SLOTS_PER_EPOCH,
            fork: Default::default(),
            latest_block_header: Default::default(),
            block_roots: vec![Root::zero(); preset::SLOTS_PER_HISTORICAL_ROOT]
                .try_into()
                .expect("the vector is built at its exact length"),
            state_roots: vec![Root::zero(); preset::SLOTS_PER_HISTORICAL_ROOT]
                .try_into()
                .expect("the vector is built at its exact length"),
            historical_roots: Default::default(),
            eth1_data: Default::default(),
            eth1_data_votes: Default::default(),
            eth1_deposit_index: 0,
            validators: validators
                .try_into()
                .expect("count is far below VALIDATOR_REGISTRY_LIMIT"),
            balances: vec![preset::MAX_EFFECTIVE_BALANCE; count]
                .try_into()
                .expect("count is far below VALIDATOR_REGISTRY_LIMIT"),
            randao_mixes: vec![Bytes32::zero(); preset::EPOCHS_PER_HISTORICAL_VECTOR]
                .try_into()
                .expect("the vector is built at its exact length"),
            slashings: vec![0; preset::EPOCHS_PER_SLASHINGS_VECTOR]
                .try_into()
                .expect("the vector is built at its exact length"),
            previous_epoch_participation: vec![0; count]
                .try_into()
                .expect("count is far below VALIDATOR_REGISTRY_LIMIT"),
            current_epoch_participation: vec![0; count]
                .try_into()
                .expect("count is far below VALIDATOR_REGISTRY_LIMIT"),
            justification_bits: Default::default(),
            previous_justified_checkpoint: Default::default(),
            current_justified_checkpoint: Default::default(),
            finalized_checkpoint: Default::default(),
            inactivity_scores: vec![0; count]
                .try_into()
                .expect("count is far below VALIDATOR_REGISTRY_LIMIT"),
            current_sync_committee: empty_sync_committee(),
            next_sync_committee: empty_sync_committee(),
            latest_execution_payload_header: empty_execution_payload_header(),
            next_withdrawal_index: 0,
            next_withdrawal_validator_index: 0,
            historical_summaries: Default::default(),
            deposit_requests_start_index: constants::UNSET_DEPOSIT_REQUESTS_START_INDEX,
            deposit_balance_to_consume: 0,
            exit_balance_to_consume: 0,
            earliest_exit_epoch: 0,
            consolidation_balance_to_consume: 0,
            earliest_consolidation_epoch: 0,
            pending_deposits: PendingDeposits::default(),
            pending_partial_withdrawals: PendingPartialWithdrawals::default(),
            pending_consolidations: PendingConsolidations::default(),
            // Overwritten below by `initialize_proposer_lookahead`; built here
            // only to give the struct literal a value of the right length.
            proposer_lookahead: vec![0; preset::PROPOSER_LOOKAHEAD_LENGTH]
                .try_into()
                .expect("the vector is built at its exact length"),
        });

        let lookahead = initialize_proposer_lookahead(&state).unwrap();
        if let BeaconState::Fulu(fulu_state) = &mut state {
            fulu_state.proposer_lookahead = lookahead.try_into().expect(
                "initialize_proposer_lookahead returns exactly PROPOSER_LOOKAHEAD_LENGTH indices",
            );
        }
        state
    }

    #[test]
    fn initialize_proposer_lookahead_fills_the_whole_window() {
        let state = fulu_state_with_validators(32);
        let lookahead = initialize_proposer_lookahead(&state).unwrap();
        assert_eq!(lookahead.len(), preset::PROPOSER_LOOKAHEAD_LENGTH);
        assert!(lookahead.iter().all(|index| *index < 32));
    }

    #[test]
    fn initialize_proposer_lookahead_matches_get_beacon_proposer_indices_epoch_by_epoch() {
        // The window is just those two (or more, at MIN_SEED_LOOKAHEAD greater
        // than one) epochs' worth of proposers concatenated, so recomputing
        // each epoch independently must reproduce the same slice.
        let state = fulu_state_with_validators(32);
        let current_epoch = get_current_epoch(&state);
        let lookahead = initialize_proposer_lookahead(&state).unwrap();

        let mut expected = Vec::new();
        for offset in 0..=preset::MIN_SEED_LOOKAHEAD {
            expected.extend(get_beacon_proposer_indices(&state, current_epoch + offset).unwrap());
        }
        assert_eq!(lookahead, expected);
    }

    #[test]
    fn get_beacon_proposer_index_reads_the_current_slot_out_of_the_lookahead() {
        let state = fulu_state_with_validators(32);
        let expected = if let BeaconState::Fulu(fulu_state) = &state {
            fulu_state.proposer_lookahead[(state.slot() % preset::SLOTS_PER_EPOCH) as usize]
        } else {
            unreachable!()
        };
        assert_eq!(get_beacon_proposer_index(&state).unwrap(), expected);
    }

    #[test]
    fn get_beacon_proposer_index_rejects_a_state_older_than_fulu() {
        let phase0_state = crate::helpers::test_state::with_validators(4);
        assert!(get_beacon_proposer_index(&phase0_state).is_err());
    }
}
