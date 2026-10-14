//! Protocol constants and the public time grid.

use crate::types::{Slot, Tick};

/// The protocol's fixed parameters.
///
/// `Δ` itself is not here: the engine counts time in units of `Δ` (see
/// [`Tick`]), and the host converts wall-clock milliseconds with its own slot
/// duration (`4Δ` per slot).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    /// `k ≥ 2`: the slow window. A lock that the confirmation update of slot
    /// `s` writes has the deadline `t_{s+k} + 5Δ`, and the slow test reads
    /// the saved confirmations of the previous `k − 1` slots.
    pub lock_period: u64,
    /// `R ≥ 1`: slots per round. The FG action (the attestation duty) runs
    /// once per round, at `a_r = T_r + 6Δ`.
    ///
    /// The specification asks `R ≥ max{2, ⌈(6Δ + Δ_F)/(4Δ)⌉}`, which keeps
    /// `a_r` inside its own round. `R = 1` is allowed anyway: `a_r` then
    /// falls in the next slot, so every slot from 1 on carries the previous
    /// round's action, at its confirmation update.
    pub slots_per_round: u64,
    /// `K_W ≥ 2`: how many justifications `σ.pending_finality` keeps.
    pub pending_window: u64,
    /// `δ_t`: slots a timeout waits after a height's entry before it can
    /// move the height.
    pub timeout_delay: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParamsError {
    #[error("lock period k = {0} must be at least 2")]
    LockPeriodTooShort(u64),
    #[error("round length R = {0} must be at least 1")]
    RoundTooShort(u64),
    #[error("pending finality window K_W = {0} must be at least 2")]
    WindowTooSmall(u64),
}

impl Default for Params {
    fn default() -> Self {
        Self::with_lock_period(DEFAULT_LOCK_PERIOD)
    }
}

/// The lock period of the Goldilocks examples.
pub const DEFAULT_LOCK_PERIOD: u64 = 4;

/// The smallest round the specification allows when attestations travel as
/// fast as blocks (`Δ_F = Δ`): `R ≥ max{2, ⌈(6Δ + Δ_F)/(4Δ)⌉} = 2`.
pub const DEFAULT_SLOTS_PER_ROUND: u64 = 2;

/// The smallest pending finality window the specification allows.
pub const DEFAULT_PENDING_WINDOW: u64 = 2;

impl Params {
    /// The defaults for a given lock period: the smallest `R` and `K_W` the
    /// specification allows, and `δ_t = 2k`, the time conflicting locks need
    /// to drain away after the network turns synchronous.
    pub fn with_lock_period(lock_period: u64) -> Self {
        Self {
            lock_period,
            slots_per_round: DEFAULT_SLOTS_PER_ROUND,
            pending_window: DEFAULT_PENDING_WINDOW,
            timeout_delay: 2 * lock_period,
        }
    }

    /// Check the structural floors.
    pub fn validate(&self) -> Result<(), ParamsError> {
        if self.lock_period < 2 {
            return Err(ParamsError::LockPeriodTooShort(self.lock_period));
        }
        if self.slots_per_round < 1 {
            return Err(ParamsError::RoundTooShort(self.slots_per_round));
        }
        if self.pending_window < 2 {
            return Err(ParamsError::WindowTooSmall(self.pending_window));
        }
        Ok(())
    }

    /// `a_r = T_r + 6Δ`: the action time of round `r`, which is the
    /// confirmation update of its first slot `rR` (`t_{rR+1} + 2Δ`).
    pub fn action_time(&self, round: u64) -> Tick {
        confirmation_time(round * self.slots_per_round)
    }

    /// Whether `t` is an action time.
    ///
    /// `a_r` falls in slot `rR + 1`: still round `r` when `R ≥ 2`, the next
    /// round when `R = 1`. So the round is read off the slot as
    /// `(slot − 1) / R`, which is both.
    pub fn is_action_time(&self, t: Tick) -> bool {
        if t < 0 {
            return false;
        }
        let slot = slot_of(t);
        let rounds = self.slots_per_round.max(1);
        slot >= 1 && (slot - 1).is_multiple_of(rounds) && t == self.action_time((slot - 1) / rounds)
    }

    /// The deadline of a lock that the confirmation update of `slot` writes:
    /// `t_{s+k} + 5Δ`, which is the vote time of slot `s + k + 1`.
    pub fn lock_deadline(&self, slot: Slot) -> Tick {
        slot_start(slot + self.lock_period) + 5
    }
}

/// `t_s = 4Δs`.
pub fn slot_start(slot: Slot) -> Tick {
    4 * slot as Tick
}

/// `s = ⌊t / 4Δ⌋`; times before genesis clamp to slot 0.
pub fn slot_of(t: Tick) -> Slot {
    if t < 0 { 0 } else { (t / 4) as Slot }
}

/// `t_s + Δ`: the Goldfish vote of slot `s`, and the revocation of the locks
/// against slot-`(s − 1)` votes just before it.
pub fn vote_time(slot: Slot) -> Tick {
    slot_start(slot) + 1
}

/// `t_s + 2Δ`: the support cutoff of slot `s`, which is also the
/// confirmation update of slot `s − 1`.
pub fn support_cutoff(slot: Slot) -> Tick {
    slot_start(slot) + 2
}

/// `t_s + 3Δ`: the view freeze of slot `s`.
pub fn view_freeze(slot: Slot) -> Tick {
    slot_start(slot) + 3
}

/// `t_s + 6Δ`: the confirmation update of slot `s`.
pub fn confirmation_time(slot: Slot) -> Tick {
    slot_start(slot) + 6
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_confirmation_update_of_a_slot_is_the_next_slots_support_cutoff() {
        for slot in 0..10 {
            assert_eq!(confirmation_time(slot), support_cutoff(slot + 1));
            assert_eq!(slot_of(confirmation_time(slot)), slot + 1);
        }
    }

    #[test]
    fn the_action_time_is_once_per_round_after_its_first_update() {
        let params = Params {
            slots_per_round: 3,
            ..Params::default()
        };
        let actions: Vec<Tick> = (0..40).filter(|&t| params.is_action_time(t)).collect();
        // Rounds start at slots 0, 3, 6: a_r = t_{3r+1} + 2Δ.
        assert_eq!(actions, vec![6, 18, 30]);
    }

    #[test]
    fn a_one_slot_round_acts_in_every_slot_from_the_first() {
        let params = Params {
            slots_per_round: 1,
            ..Params::default()
        };
        let actions: Vec<Tick> = (0..24).filter(|&t| params.is_action_time(t)).collect();
        // a_r = t_{r+1} + 2Δ: the confirmation update of every slot.
        assert_eq!(actions, vec![6, 10, 14, 18, 22]);
        assert!(params.validate().is_ok());
    }

    #[test]
    fn a_lock_expires_at_the_vote_time_k_plus_one_slots_later() {
        let params = Params::default();
        assert_eq!(
            params.lock_deadline(10),
            vote_time(10 + params.lock_period + 1)
        );
    }

    #[test]
    fn validation_enforces_the_structural_floors() {
        assert!(Params::default().validate().is_ok());
        assert!(Params::with_lock_period(1).validate().is_err());
        let empty_round = Params {
            slots_per_round: 0,
            ..Params::default()
        };
        assert!(empty_round.validate().is_err());
        let small_window = Params {
            pending_window: 1,
            ..Params::default()
        };
        assert!(small_window.validate().is_err());
    }
}
