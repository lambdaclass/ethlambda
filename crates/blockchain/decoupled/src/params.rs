//! Protocol constants and the public time grid.

use crate::types::{Slot, Tick};

/// The protocol's fixed parameters.
///
/// `Δ` itself is not here: the engine counts time in units of `Δ` (see
/// [`Tick`]), and the host converts wall-clock milliseconds with its own slot
/// duration (`4Δ` per slot).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    /// `k ≥ 2`: how many slots a lock lives, and how many consecutive
    /// confirmations form a slow lock.
    ///
    /// A lock formed by the confirmation update of slot `s` anchors every
    /// fork-choice run over votes of slots `s ..= s + k − 1`: the votes of
    /// slots `s + 2 ..= s + k` and the updates of slots `s + 1 ..= s + k − 1`.
    pub lock_period: u64,
    /// `K ≥ 4`: every `K`-th height is nonjustifiable under finality debt.
    pub nonjustifiable_period: u64,
    /// `D ≥ 2`: the finality-debt bound.
    pub finality_debt: u64,
    /// `δ_t`: slots a timeout waits before it can move a height.
    pub timeout_delay: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParamsError {
    #[error("lock period k = {0} must be at least 2")]
    LockPeriodTooShort(u64),
    #[error("nonjustifiable period K = {0} must be at least 4")]
    PeriodTooShort(u64),
    #[error("finality-debt bound D = {0} must be at least 2")]
    DebtTooSmall(u64),
}

impl Default for Params {
    fn default() -> Self {
        Self::with_lock_period(DEFAULT_LOCK_PERIOD)
    }
}

/// The lock period of the Goldilocks examples.
pub const DEFAULT_LOCK_PERIOD: u64 = 4;

impl Params {
    /// The defaults for a given lock period: `K = 5` (the smallest value at
    /// which the formal finality claims are non-vacuous), `D = 2` (the
    /// structural floor) and `δ_t = 2k`, the time conflicting locks need to
    /// drain away after the network turns synchronous.
    pub fn with_lock_period(lock_period: u64) -> Self {
        Self {
            lock_period,
            nonjustifiable_period: 5,
            finality_debt: 2,
            timeout_delay: 2 * lock_period,
        }
    }

    /// Check the structural floors.
    pub fn validate(&self) -> Result<(), ParamsError> {
        if self.lock_period < 2 {
            return Err(ParamsError::LockPeriodTooShort(self.lock_period));
        }
        if self.nonjustifiable_period < 4 {
            return Err(ParamsError::PeriodTooShort(self.nonjustifiable_period));
        }
        if self.finality_debt < 2 {
            return Err(ParamsError::DebtTooSmall(self.finality_debt));
        }
        Ok(())
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

/// `t_s + Δ`: the Goldfish vote of slot `s`.
pub fn vote_time(slot: Slot) -> Tick {
    slot_start(slot) + 1
}

/// `t_s + 2Δ`: the support cutoff of slot `s`, which is also the slot-`(s−1)`
/// confirmation update and the attestation instant of slot `s`.
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
    fn validation_enforces_the_structural_floors() {
        assert!(Params::default().validate().is_ok());
        assert!(Params::with_lock_period(1).validate().is_err());
        let short_period = Params {
            nonjustifiable_period: 3,
            ..Params::default()
        };
        assert!(short_period.validate().is_err());
        let small_debt = Params {
            finality_debt: 1,
            ..Params::default()
        };
        assert!(small_debt.validate().is_err());
    }
}
