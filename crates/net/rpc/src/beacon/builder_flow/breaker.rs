//! The circuit breaker: when the chain looks unhealthy, propose a local
//! block rather than a builder's.
//!
//! builder-specs leaves the conditions to the client; these follow
//! Lighthouse's. They read the proposal state alone, so two nodes holding
//! the same state agree: a slot `i` before the proposal slot was empty iff
//! `block_roots[i] == block_roots[i - 1]`, since `process_slots` carries the
//! previous root forward over an empty slot.

use ethlambda_state_transition::beacon::helpers::accessors::get_block_root_at_slot;
use ethlambda_types::beacon::containers::BeaconState;
use ethlambda_types::beacon::preset::SLOTS_PER_EPOCH;
use ethlambda_types::beacon::primitives::Slot;
use ethlambda_types::beacon::signing::compute_epoch_at_slot;

/// How unhealthy the chain may look before block production skips the
/// builder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FallbackThresholds {
    /// The most consecutive empty slots allowed right before the proposal.
    pub skips: u64,
    /// The most empty slots allowed in the epoch's worth of slots before the
    /// proposal.
    pub skips_per_epoch: u64,
    /// The most epochs the proposal may be past the finalized checkpoint.
    pub epochs_since_finalization: u64,
}

impl FallbackThresholds {
    /// Lighthouse's defaults.
    pub const DEFAULT: Self = Self {
        skips: 3,
        skips_per_epoch: 8,
        epochs_since_finalization: 3,
    };
}

impl Default for FallbackThresholds {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Why the breaker kept the builder out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Trip {
    Syncing,
    OptimisticHead,
    /// Reads the state's realized `finalized_checkpoint`, not fork choice's.
    NoFinality,
    ConsecutiveSkips,
    SkipsPerEpoch,
}

impl Trip {
    /// The metric label.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Syncing => "syncing",
            Self::OptimisticHead => "optimistic_head",
            Self::NoFinality => "no_finality",
            Self::ConsecutiveSkips => "consecutive_skips",
            Self::SkipsPerEpoch => "skips_per_epoch",
        }
    }
}

/// Whether the builder may be used for a block at `state`'s slot.
///
/// `state` is the head state advanced to the proposal slot. `optimistic` and
/// `syncing` are the node's own view, which the state cannot know.
pub(crate) fn check(
    state: &BeaconState,
    thresholds: &FallbackThresholds,
    optimistic: bool,
    syncing: bool,
) -> Result<(), Trip> {
    if syncing {
        return Err(Trip::Syncing);
    }
    if optimistic {
        return Err(Trip::OptimisticHead);
    }
    let slot = state.slot();
    let since_finalization =
        compute_epoch_at_slot(slot).saturating_sub(state.finalized_checkpoint().epoch);
    if since_finalization > thresholds.epochs_since_finalization {
        return Err(Trip::NoFinality);
    }
    let consecutive = (1..slot).rev().take_while(|&i| is_empty(state, i)).count() as u64;
    if consecutive > thresholds.skips {
        return Err(Trip::ConsecutiveSkips);
    }
    let window_start = slot.saturating_sub(SLOTS_PER_EPOCH).max(1);
    let in_window = (window_start..slot).filter(|&i| is_empty(state, i)).count() as u64;
    if in_window > thresholds.skips_per_epoch {
        return Err(Trip::SkipsPerEpoch);
    }
    Ok(())
}

/// Whether slot `i` (with `0 < i < state.slot()`) had no block.
fn is_empty(state: &BeaconState, i: Slot) -> bool {
    match (
        get_block_root_at_slot(state, i),
        get_block_root_at_slot(state, i - 1),
    ) {
        (Ok(root), Ok(previous)) => root == previous,
        // Older than the state remembers: count it as filled, so a short
        // history never trips the breaker on its own.
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use ethlambda_state_transition::beacon::helpers::test_state::with_signing_validators_at;
    use ethlambda_types::beacon::fork::ForkName;
    use ethlambda_types::beacon::primitives::{Epoch, H256};

    use super::*;

    /// A fulu state at `slot` whose every earlier slot had a block except
    /// those in `empty`, finalized at `finalized_epoch`.
    fn state_at(slot: Slot, empty: &[Slot], finalized_epoch: Epoch) -> BeaconState {
        let mut state = with_signing_validators_at(ForkName::Fulu, 8);
        let BeaconState::Fulu(fulu) = &mut state else {
            unreachable!("built as fulu")
        };
        fulu.slot = slot;
        fulu.finalized_checkpoint.epoch = finalized_epoch;
        let history = fulu.block_roots.len() as u64;
        let mut root = H256([0; 32]);
        for i in 0..slot {
            if !empty.contains(&i) {
                let mut bytes = [0u8; 32];
                bytes[..8].copy_from_slice(&(i + 1).to_le_bytes());
                root = H256(bytes);
            }
            fulu.block_roots[(i % history) as usize] = root;
        }
        state
    }

    const LENIENT_SYNC: (bool, bool) = (false, false);

    fn check_at(state: &BeaconState) -> Result<(), Trip> {
        let (optimistic, syncing) = LENIENT_SYNC;
        check(state, &FallbackThresholds::DEFAULT, optimistic, syncing)
    }

    #[test]
    fn a_healthy_chain_uses_the_builder() {
        assert_eq!(check_at(&state_at(100, &[], 2)), Ok(()));
    }

    #[test]
    fn three_empty_slots_in_a_row_are_tolerated_and_four_are_not() {
        assert_eq!(check_at(&state_at(100, &[97, 98, 99], 2)), Ok(()));
        assert_eq!(
            check_at(&state_at(100, &[96, 97, 98, 99], 2)),
            Err(Trip::ConsecutiveSkips)
        );
    }

    #[test]
    fn eight_scattered_empty_slots_in_an_epoch_are_tolerated_and_nine_are_not() {
        let eight = [70, 72, 74, 76, 78, 80, 82, 84];
        assert_eq!(check_at(&state_at(100, &eight, 2)), Ok(()));
        let nine = [70, 72, 74, 76, 78, 80, 82, 84, 86];
        assert_eq!(check_at(&state_at(100, &nine, 2)), Err(Trip::SkipsPerEpoch));
    }

    #[test]
    fn empty_slots_outside_the_epoch_window_do_not_count() {
        let old = [10, 12, 14, 16, 18, 20, 22, 24, 26, 28];
        assert_eq!(check_at(&state_at(100, &old, 2)), Ok(()));
    }

    #[test]
    fn three_epochs_without_finality_are_tolerated_and_four_are_not() {
        // Slot 200 is in epoch 6.
        assert_eq!(check_at(&state_at(200, &[], 3)), Ok(()));
        assert_eq!(check_at(&state_at(200, &[], 2)), Err(Trip::NoFinality));
    }

    #[test]
    fn a_proposal_near_genesis_counts_no_slot_before_slot_one() {
        assert_eq!(check_at(&state_at(1, &[], 0)), Ok(()));
        assert_eq!(check_at(&state_at(5, &[], 0)), Ok(()));
        // Slots 1 to 4 are all empty: four in a row, and slot 0 is never judged.
        assert_eq!(
            check_at(&state_at(5, &[1, 2, 3, 4], 0)),
            Err(Trip::ConsecutiveSkips)
        );
        assert_eq!(check_at(&state_at(4, &[1, 2, 3], 0)), Ok(()));
    }

    #[test]
    fn a_history_that_wraps_is_read_at_its_wrapped_index() {
        let wrapped = 8192 + 100;
        assert_eq!(check_at(&state_at(wrapped, &[], 300)), Ok(()));
        let run = [wrapped - 4, wrapped - 3, wrapped - 2, wrapped - 1];
        assert_eq!(
            check_at(&state_at(wrapped, &run, 300)),
            Err(Trip::ConsecutiveSkips)
        );
    }

    #[test]
    fn a_slot_older_than_the_history_counts_as_filled() {
        let slot = 8192 + 100;
        let all_empty: Vec<Slot> = (1..slot).collect();
        let state = state_at(slot, &all_empty, 300);
        // Slot 1 is out of the state's reach, so its roots are not compared.
        assert!(!is_empty(&state, 1));
        assert!(is_empty(&state, slot - 1));
    }

    #[test]
    fn an_empty_run_that_does_not_end_right_before_the_proposal_is_not_consecutive() {
        // Five empty slots, but slot 99 had a block.
        assert_eq!(check_at(&state_at(100, &[90, 91, 92, 93, 94], 2)), Ok(()));
    }

    #[test]
    fn an_optimistic_head_or_a_syncing_node_keeps_the_builder_out() {
        let state = state_at(100, &[], 2);
        let thresholds = FallbackThresholds::DEFAULT;
        assert_eq!(
            check(&state, &thresholds, true, false),
            Err(Trip::OptimisticHead)
        );
        assert_eq!(check(&state, &thresholds, false, true), Err(Trip::Syncing));
    }
}
