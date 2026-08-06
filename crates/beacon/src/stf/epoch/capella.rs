//! Capella-specific epoch processing.
//!
//! Capella's own `process_epoch` is otherwise altair's step list with one
//! swap: `process_historical_roots_update` is replaced by
//! [`process_historical_summaries_update`], since `historical_roots` is
//! frozen as of this fork (`state.historical_roots` keeps whatever bellatrix
//! left it at and is never appended to again) and `historical_summaries`
//! accumulates new history in its place. [`process_epoch`] below is
//! transcribed from the specification's own list, in the order it gives
//! them, which is the same order [`super::altair::process_epoch`] uses apart
//! from that one substitution; see [`super`]'s and `super::altair`'s own
//! documentation for why that order matters everywhere it is not just this
//! one swap.
//!
//! Deneb reuses this driver unchanged: its own "Epoch processing" section in
//! the specification says nothing at all, meaning deneb's `process_epoch` is
//! whatever the previous fork (capella) already defined. [`super::process_epoch`]'s
//! dispatcher already routes `ForkName::Deneb` here for exactly that reason,
//! so [`process_epoch`] and [`process_historical_summaries_update`] both
//! accept a deneb state as readily as a capella one rather than gating on
//! `ForkName::Capella` specifically; see [`historical_summaries_mut`] for
//! where that acceptance actually lives.

use crate::config::Config;
use crate::containers::{BeaconState, HistoricalSummaries, HistoricalSummary};
use crate::error::{Error, Result};
use crate::helpers::accessors::get_current_epoch;
use crate::preset;
use crate::primitives::{Epoch, HashTreeRoot as _};

/// Capella's epoch-boundary driver, in the specification's order.
///
/// Every step but one is altair's own, called through `super::altair` and
/// `super::registry` exactly as [`super::altair::process_epoch`] itself calls
/// them; the one exception is [`process_historical_summaries_update`] in
/// place of `super::process_historical_roots_update`.
pub fn process_epoch(state: &mut BeaconState, config: &Config) -> Result<()> {
    super::altair::process_justification_and_finalization(state)?;
    super::altair::process_inactivity_updates(state, config)?;
    super::altair::process_rewards_and_penalties(state, config)?;
    super::registry::process_registry_updates(state, config)?;
    super::registry::process_slashings(state, config)?;
    super::process_eth1_data_reset(state)?;
    super::process_effective_balance_updates(state)?;
    super::process_slashings_reset(state)?;
    super::process_randao_mixes_reset(state)?;
    // [Modified in Capella]
    process_historical_summaries_update(state)?;
    super::altair::process_participation_flag_updates(state)?;
    super::altair::process_sync_committee_updates(state)?;
    Ok(())
}

/// Folds the block and state root vectors into one [`HistoricalSummary`] when
/// they are about to wrap, capella's replacement for
/// `super::process_historical_roots_update`.
///
/// [`HistoricalSummary`]'s two fields are `hash_tree_root(state.block_roots)`
/// and `hash_tree_root(state.state_roots)` taken directly, not the root of a
/// combined [`crate::containers::HistoricalBatch`] wrapping both: the
/// specification's own note that the two containers are hash-tree-root
/// compatible is what makes those the same two child roots either way, so a
/// verifier holding only one of the two forms can still check a historical
/// proof against either.
pub fn process_historical_summaries_update(state: &mut BeaconState) -> Result<()> {
    let next_epoch = get_current_epoch(state) + 1;
    let epochs_per_historical_root =
        (preset::SLOTS_PER_HISTORICAL_ROOT / preset::SLOTS_PER_EPOCH as usize) as Epoch;
    if next_epoch.is_multiple_of(epochs_per_historical_root) {
        let summary = HistoricalSummary {
            block_summary_root: state.block_roots().hash_tree_root(),
            state_summary_root: state.state_roots().hash_tree_root(),
        };
        historical_summaries_mut(state, "process_historical_summaries_update")?.push(summary)?;
    }
    Ok(())
}

/// The `historical_summaries` list, mutably, for any fork that carries it, or
/// an error naming the function that needs one.
///
/// `historical_summaries` enters the state at capella and every later fork
/// keeps the identical field: deneb reuses this whole driver unchanged (see
/// this module's own documentation), and electra and fulu each fold this same
/// step into their own, larger driver rather than redefining it, since
/// neither fork's specification says anything about historical summaries at
/// all. Matching every variant that actually has the field, rather than only
/// [`BeaconState::Capella`], is what lets each of those reuse this function
/// instead of a copy of it.
fn historical_summaries_mut<'a>(
    state: &'a mut BeaconState,
    function: &'static str,
) -> Result<&'a mut HistoricalSummaries> {
    match state {
        BeaconState::Capella(state) => Ok(&mut state.historical_summaries),
        BeaconState::Deneb(state) => Ok(&mut state.historical_summaries),
        BeaconState::Electra(state) => Ok(&mut state.historical_summaries),
        BeaconState::Fulu(state) => Ok(&mut state.historical_summaries),
        other => Err(Error::UnsupportedForFork {
            function,
            fork: other.fork_name(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fork::ForkName;

    /// A capella state with `count` fully active, full-balance validators,
    /// positioned one epoch in the same way
    /// `crate::helpers::test_state::with_validators` positions its phase0
    /// state.
    ///
    /// A thin wrapper around the shared fork-parameterised builder: see
    /// [`crate::helpers::test_state::with_validators_at`] for the construction
    /// this and every other fork's test module used to duplicate.
    fn capella_state_with_validators(count: usize) -> BeaconState {
        crate::helpers::test_state::with_validators_at(ForkName::Capella, count)
    }

    #[test]
    fn historical_summaries_update_is_a_no_op_off_the_boundary() {
        // Current epoch 1: `next_epoch` (2) is not a multiple of
        // `SLOTS_PER_HISTORICAL_ROOT / SLOTS_PER_EPOCH` on either preset.
        let mut state = capella_state_with_validators(4);
        process_historical_summaries_update(&mut state).unwrap();

        let inner = historical_summaries_mut(&mut state, "test assertion").unwrap();
        assert!(inner.is_empty());
    }

    #[test]
    fn historical_summaries_update_appends_at_the_boundary_instead_of_historical_roots() {
        let epochs_per_historical_root =
            preset::SLOTS_PER_HISTORICAL_ROOT as u64 / preset::SLOTS_PER_EPOCH;
        let mut state = capella_state_with_validators(4);
        // One epoch before the boundary, so `next_epoch` lands exactly on it.
        *state.slot_mut() = preset::SLOTS_PER_EPOCH * (epochs_per_historical_root - 1);

        let expected_block_summary_root = state.block_roots().hash_tree_root();
        let expected_state_summary_root = state.state_roots().hash_tree_root();

        process_historical_summaries_update(&mut state).unwrap();

        assert!(
            state.historical_roots().is_empty(),
            "capella must never append to historical_roots: it is frozen as of this fork"
        );
        let summaries = historical_summaries_mut(&mut state, "test assertion").unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].block_summary_root, expected_block_summary_root);
        assert_eq!(summaries[0].state_summary_root, expected_state_summary_root);
    }

    #[test]
    fn historical_summaries_update_accepts_a_deneb_state_too() {
        // `process_epoch` is dispatched for deneb states through this exact
        // driver (`ForkName::Deneb => capella::process_epoch`), so the
        // historical-summaries step it calls must not reject one.
        let capella_state = capella_state_with_validators(2);
        let deneb_state = if let BeaconState::Capella(inner) = capella_state {
            crate::containers::deneb::BeaconState {
                genesis_time: inner.genesis_time,
                genesis_validators_root: inner.genesis_validators_root,
                slot: preset::SLOTS_PER_HISTORICAL_ROOT as u64 - preset::SLOTS_PER_EPOCH,
                fork: inner.fork,
                latest_block_header: inner.latest_block_header,
                block_roots: inner.block_roots,
                state_roots: inner.state_roots,
                historical_roots: inner.historical_roots,
                eth1_data: inner.eth1_data,
                eth1_data_votes: inner.eth1_data_votes,
                eth1_deposit_index: inner.eth1_deposit_index,
                validators: inner.validators,
                balances: inner.balances,
                randao_mixes: inner.randao_mixes,
                slashings: inner.slashings,
                previous_epoch_participation: inner.previous_epoch_participation,
                current_epoch_participation: inner.current_epoch_participation,
                justification_bits: inner.justification_bits,
                previous_justified_checkpoint: inner.previous_justified_checkpoint,
                current_justified_checkpoint: inner.current_justified_checkpoint,
                finalized_checkpoint: inner.finalized_checkpoint,
                inactivity_scores: inner.inactivity_scores,
                current_sync_committee: inner.current_sync_committee,
                next_sync_committee: inner.next_sync_committee,
                latest_execution_payload_header: crate::containers::deneb::ExecutionPayloadHeader {
                    parent_hash: inner.latest_execution_payload_header.parent_hash,
                    fee_recipient: inner.latest_execution_payload_header.fee_recipient,
                    state_root: inner.latest_execution_payload_header.state_root,
                    receipts_root: inner.latest_execution_payload_header.receipts_root,
                    logs_bloom: inner.latest_execution_payload_header.logs_bloom,
                    prev_randao: inner.latest_execution_payload_header.prev_randao,
                    block_number: inner.latest_execution_payload_header.block_number,
                    gas_limit: inner.latest_execution_payload_header.gas_limit,
                    gas_used: inner.latest_execution_payload_header.gas_used,
                    timestamp: inner.latest_execution_payload_header.timestamp,
                    extra_data: inner.latest_execution_payload_header.extra_data,
                    base_fee_per_gas: inner.latest_execution_payload_header.base_fee_per_gas,
                    block_hash: inner.latest_execution_payload_header.block_hash,
                    transactions_root: inner.latest_execution_payload_header.transactions_root,
                    withdrawals_root: inner.latest_execution_payload_header.withdrawals_root,
                    blob_gas_used: 0,
                    excess_blob_gas: 0,
                },
                next_withdrawal_index: inner.next_withdrawal_index,
                next_withdrawal_validator_index: inner.next_withdrawal_validator_index,
                historical_summaries: inner.historical_summaries,
            }
        } else {
            unreachable!()
        };
        let mut state = BeaconState::Deneb(deneb_state);

        process_historical_summaries_update(&mut state).unwrap();

        let summaries = historical_summaries_mut(&mut state, "test assertion").unwrap();
        assert_eq!(summaries.len(), 1);
    }
}
