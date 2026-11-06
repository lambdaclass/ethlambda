//! EIP-8453's parameters and the public time grid.
//!
//! The engine keeps time in ticks of `Δ = SLOT_DURATION_MS / 4`. The spec's
//! three due times within a slot (`HEAD_VOTE_DUE_BPS`, `SUPPORT_CUTOFF_BPS`,
//! `VIEW_FREEZE_BPS`, at 25%, 50% and 75% of the slot) all land on that grid,
//! and every comparison the spec makes against them is a strict `<` on a
//! receipt time or a strict `>` on a lock deadline, both of which give the same
//! answer on a time floored to the grid. So the engine stamps an object
//! received between two grid instants with the earlier one, and the host
//! converts wall-clock time with `floor((now_ms - genesis_ms) / Δ_ms)`.

use crate::types::{Round, Slot, Tick};

/// `GENESIS_SLOT`.
pub const GENESIS_SLOT: Slot = 0;

/// The basis-point denominator of the slot-component durations.
pub const BASIS_POINTS: u64 = 10_000;

/// `HEAD_VOTE_DUE_BPS` (fork-choice.md, time parameters).
pub const HEAD_VOTE_DUE_BPS: u64 = 2500;
/// `SUPPORT_CUTOFF_BPS`.
pub const SUPPORT_CUTOFF_BPS: u64 = 5000;
/// `VIEW_FREEZE_BPS`.
pub const VIEW_FREEZE_BPS: u64 = 7500;

/// Ticks per slot: a slot is `4Δ`.
pub const TICKS_PER_SLOT: Tick = 4;

/// `get_head_vote_due_ms()`, in ticks into the slot.
pub const HEAD_VOTE_DUE: Tick = bps_to_ticks(HEAD_VOTE_DUE_BPS);
/// `get_support_cutoff_ms()`, in ticks into the slot.
pub const SUPPORT_CUTOFF: Tick = bps_to_ticks(SUPPORT_CUTOFF_BPS);
/// `get_view_freeze_ms()`, in ticks into the slot.
pub const VIEW_FREEZE: Tick = bps_to_ticks(VIEW_FREEZE_BPS);

/// A basis-point offset that lands exactly on the `Δ` grid, in ticks. Fails to
/// compile for one that does not.
const fn bps_to_ticks(bps: u64) -> Tick {
    assert!(
        (bps * TICKS_PER_SLOT as u64).is_multiple_of(BASIS_POINTS),
        "a due time must land on the Δ grid"
    );
    (bps * TICKS_PER_SLOT as u64 / BASIS_POINTS) as Tick
}

/// `SLOTS_PER_ROUND` in the minimal preset.
pub const MINIMAL_SLOTS_PER_ROUND: u64 = 4;
/// `SLOTS_PER_ROUND` in the mainnet preset.
pub const MAINNET_SLOTS_PER_ROUND: u64 = 8;
/// `PENDING_FINALITY_WINDOW` (both presets).
pub const PENDING_FINALITY_WINDOW: u64 = 4;
/// `SLOW_LOCK_WINDOW` (fork-choice.md, misc config).
pub const SLOW_LOCK_WINDOW: u64 = 4;

/// The protocol's parameters that the spec does not fix as constants above.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    /// `SLOTS_PER_ROUND`. `TIMEOUT_DELAY_SLOTS` equals it.
    pub slots_per_round: u64,
    /// `PENDING_FINALITY_WINDOW`: pending justifications a chain state keeps.
    pub pending_finality_window: u64,
    /// `SLOW_LOCK_WINDOW`: slots of saved confirmations a slow lock needs.
    pub slow_lock_window: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParamsError {
    #[error("slots per round must be at least 1")]
    EmptyRound,
    #[error("the pending finality window {0} must be at least 2")]
    PendingWindowTooSmall(u64),
    #[error("the slow lock window must be at least 1")]
    EmptySlowLockWindow,
}

impl Default for Params {
    fn default() -> Self {
        Self::minimal()
    }
}

impl Params {
    /// The minimal preset: `SLOTS_PER_ROUND = 4`.
    pub fn minimal() -> Self {
        Self::with_slots_per_round(MINIMAL_SLOTS_PER_ROUND)
    }

    /// The mainnet preset: `SLOTS_PER_ROUND = 8`.
    pub fn mainnet() -> Self {
        Self::with_slots_per_round(MAINNET_SLOTS_PER_ROUND)
    }

    /// The spec's values with a chosen round length.
    pub fn with_slots_per_round(slots_per_round: u64) -> Self {
        Self {
            slots_per_round,
            pending_finality_window: PENDING_FINALITY_WINDOW,
            slow_lock_window: SLOW_LOCK_WINDOW,
        }
    }

    pub fn validate(&self) -> Result<(), ParamsError> {
        if self.slots_per_round == 0 {
            return Err(ParamsError::EmptyRound);
        }
        if self.pending_finality_window < 2 {
            return Err(ParamsError::PendingWindowTooSmall(
                self.pending_finality_window,
            ));
        }
        if self.slow_lock_window == 0 {
            return Err(ParamsError::EmptySlowLockWindow);
        }
        Ok(())
    }

    /// `TIMEOUT_DELAY_SLOTS = SLOTS_PER_ROUND`.
    pub fn timeout_delay_slots(&self) -> u64 {
        self.slots_per_round
    }

    /// `compute_round_at_slot`.
    pub fn round_of(&self, slot: Slot) -> Round {
        slot / self.slots_per_round
    }

    /// `compute_start_slot_at_round`.
    pub fn round_start_slot(&self, round: Round) -> Slot {
        round * self.slots_per_round
    }

    /// The deadline of a lock created by the confirmation of `slot`:
    /// `compute_time_at_slot_ms(slot + SLOW_LOCK_WINDOW + 1) +
    /// get_head_vote_due_ms()` (`update_locks_and_confirmation`).
    pub fn lock_deadline(&self, slot: Slot) -> Tick {
        head_vote_due(slot + self.slow_lock_window + 1)
    }
}

/// `compute_time_at_slot`, in ticks.
pub fn slot_start(slot: Slot) -> Tick {
    TICKS_PER_SLOT * slot as Tick
}

/// `compute_slot_at_time`; times before genesis clamp to slot 0.
pub fn slot_of(t: Tick) -> Slot {
    if t < 0 {
        0
    } else {
        (t / TICKS_PER_SLOT) as Slot
    }
}

/// `get_time_into_slot`, in ticks.
pub fn time_into_slot(t: Tick) -> Tick {
    t.rem_euclid(TICKS_PER_SLOT)
}

/// The head vote deadline of `slot`: `t_s + Δ`.
pub fn head_vote_due(slot: Slot) -> Tick {
    slot_start(slot) + HEAD_VOTE_DUE
}

/// The support cutoff of `slot`: `t_s + 2Δ`.
pub fn support_cutoff(slot: Slot) -> Tick {
    slot_start(slot) + SUPPORT_CUTOFF
}

/// The view freeze of `slot`: `t_s + 3Δ`.
pub fn view_freeze(slot: Slot) -> Tick {
    slot_start(slot) + VIEW_FREEZE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_due_times_are_the_quarter_points_of_a_slot() {
        assert_eq!((HEAD_VOTE_DUE, SUPPORT_CUTOFF, VIEW_FREEZE), (1, 2, 3));
        assert_eq!(head_vote_due(3), 13);
        assert_eq!(support_cutoff(3), 14);
        assert_eq!(view_freeze(3), 15);
        assert_eq!(slot_of(15), 3);
        assert_eq!(time_into_slot(15), 3);
    }

    #[test]
    fn a_lock_lives_until_the_head_vote_of_the_slot_after_the_window() {
        let params = Params::minimal();
        // Confirmed at slot 10: expires at slot 15's head vote deadline.
        assert_eq!(params.lock_deadline(10), head_vote_due(15));
    }

    #[test]
    fn validation_enforces_the_spec_floors() {
        assert!(Params::minimal().validate().is_ok());
        assert!(Params::mainnet().validate().is_ok());
        assert!(Params::with_slots_per_round(0).validate().is_err());
        let mut params = Params::minimal();
        params.pending_finality_window = 1;
        assert!(params.validate().is_err());
    }
}
