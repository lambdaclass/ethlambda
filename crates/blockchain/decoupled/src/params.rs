//! Protocol constants and the public time grid (appendix A.2, A.6, A.9, A.11).

use crate::types::{Round, Slot, Tick};

/// The protocol's fixed parameters.
///
/// `Δ` itself is not here: the engine counts time in units of `Δ` (see
/// [`Tick`]), and the host converts wall-clock milliseconds with its own slot
/// duration (`4Δ` per slot).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    /// `R ≥ 3`: slots per round (§6.1).
    pub slots_per_round: u64,
    /// `η_SG ≥ 1`: the SG expiry window, in rounds (§3.3).
    pub eta_sg: u64,
    /// `K ≥ 4`: every `K`-th height is nonjustifiable under finality debt (§4).
    pub k: u64,
    /// `D ≥ 2`: the finality-debt bound (§4).
    pub d: u64,
    /// `δ_t`: slots a timeout waits before it can move a height (§4). The
    /// protocol's value is `2R`.
    pub timeout_delay: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParamsError {
    #[error("slots per round R = {0} must be at least 3")]
    RoundTooShort(u64),
    #[error("SG expiry window eta_SG = {0} must be at least 1")]
    WindowTooShort(u64),
    #[error("nonjustifiable period K = {0} must be at least 4")]
    PeriodTooShort(u64),
    #[error("finality-debt bound D = {0} must be at least 2")]
    DebtTooSmall(u64),
}

impl Params {
    /// The protocol's defaults for a given round length: `η_SG = 2`, `K = 5`
    /// (the smallest value at which the formal finality claims are non-vacuous,
    /// MODELING_CHOICES §7), `D = 2` (the structural floor) and `δ_t = 2R`.
    pub fn with_round_length(slots_per_round: u64) -> Self {
        Self {
            slots_per_round,
            eta_sg: 2,
            k: 5,
            d: 2,
            timeout_delay: 2 * slots_per_round,
        }
    }

    /// Check the structural conditions of MODELING_CHOICES §8.
    pub fn validate(&self) -> Result<(), ParamsError> {
        if self.slots_per_round < 3 {
            return Err(ParamsError::RoundTooShort(self.slots_per_round));
        }
        if self.eta_sg < 1 {
            return Err(ParamsError::WindowTooShort(self.eta_sg));
        }
        if self.k < 4 {
            return Err(ParamsError::PeriodTooShort(self.k));
        }
        if self.d < 2 {
            return Err(ParamsError::DebtTooSmall(self.d));
        }
        Ok(())
    }

    /// `round(s) = ⌊s / R⌋`.
    pub fn round_of(&self, slot: Slot) -> Round {
        slot / self.slots_per_round
    }

    /// The opening slot `rR` of round `r`.
    pub fn opening_slot(&self, round: Round) -> Slot {
        round * self.slots_per_round
    }

    /// `T_r = t_{rR}`: the opening slot's proposal time.
    pub fn round_start(&self, round: Round) -> Tick {
        slot_start(self.opening_slot(round))
    }

    /// `a_r = T_r + 6Δ`: the round's attestation time, which is the opening
    /// slot's confirmation evaluation (§6.1). With `R ≥ 3` it falls in slot
    /// `rR + 1`, inside round `r`.
    pub fn attestation_time(&self, round: Round) -> Tick {
        self.round_start(round) + 6
    }

    /// The inclusive SG admission window `[max(0, r − η_SG), r]` (§1.4).
    pub fn admits_round(&self, current: Round, round: Round) -> bool {
        current.saturating_sub(self.eta_sg) <= round && round <= current
    }

    /// The rounds `I_r = [max(0, r − η_SG), r)` the grades of round `r` read
    /// (§3.3). Round 0 reads nothing.
    pub fn grade_window(&self, round: Round) -> std::ops::Range<Round> {
        round.saturating_sub(self.eta_sg)..round
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
/// confirmation evaluation.
pub fn support_cutoff(slot: Slot) -> Tick {
    slot_start(slot) + 2
}

/// `t_s + 3Δ`: the view freeze of slot `s`.
pub fn view_freeze(slot: Slot) -> Tick {
    slot_start(slot) + 3
}

/// `t_s + 6Δ`: the confirmation evaluation of slot `s`.
pub fn confirmation_time(slot: Slot) -> Tick {
    slot_start(slot) + 6
}

/// The three grades and their cutoffs relative to `T_r` (§6.1):
///
/// ```text
/// grade   early   late    completes
/// G2      T−5Δ    T−Δ     T−Δ   (in the previous round)
/// G1      T−4Δ    T−2Δ    T
/// G0      T−3Δ    T−3Δ    T+Δ
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grade {
    G0,
    G1,
    G2,
}

impl Grade {
    pub const ALL: [Grade; 3] = [Grade::G2, Grade::G1, Grade::G0];

    pub fn early_offset(self) -> Tick {
        match self {
            Grade::G0 => -3,
            Grade::G1 => -4,
            Grade::G2 => -5,
        }
    }

    pub fn late_offset(self) -> Tick {
        match self {
            Grade::G0 => -3,
            Grade::G1 => -2,
            Grade::G2 => -1,
        }
    }

    pub fn completion_offset(self) -> Tick {
        match self {
            Grade::G0 => 1,
            Grade::G1 => 0,
            Grade::G2 => -1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_attestation_time_falls_in_the_rounds_second_slot() {
        for r in 3..8 {
            let params = Params::with_round_length(r);
            for round in 0..5 {
                let a = params.attestation_time(round);
                assert_eq!(slot_of(a), params.opening_slot(round) + 1);
                assert_eq!(params.round_of(slot_of(a)), round);
                assert_eq!(a, support_cutoff(params.opening_slot(round) + 1));
            }
        }
    }

    #[test]
    fn the_previous_rounds_attestation_lands_before_the_grade_2_early_cutoff() {
        // R ≥ 3 is what makes a_{r−1} + Δ ≤ T_r − 5Δ (A.11).
        let params = Params::with_round_length(3);
        for round in 1..5 {
            let delivered = params.attestation_time(round - 1) + 1;
            let early = params.round_start(round) + Grade::G2.early_offset();
            assert!(delivered <= early);
        }
    }

    #[test]
    fn validation_enforces_the_structural_floors() {
        assert!(Params::with_round_length(3).validate().is_ok());
        assert!(Params::with_round_length(2).validate().is_err());
        let mut params = Params::with_round_length(4);
        params.k = 3;
        assert!(params.validate().is_err());
    }
}
