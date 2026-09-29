//! One registry pass for the epoch's participation accounting.
//!
//! Justification, inactivity updates and rewards each need to know, per
//! validator, whether it earned each timeliness flag last epoch and whether it
//! is eligible for rewards, plus a few balance totals over those sets. Asking
//! the specification's helpers for that one question at a time reads the
//! tree-backed registry many times over and, per active validator, once more
//! by index (a tree descent each). Here the registry is walked once, with
//! `validators().iter()` zipped against the participation slices, and every
//! later step runs over flat data.
//!
//! The pieces, from cheapest to most complete:
//!
//! - [`ParticipationTotals::compute`]: only the balance totals justification
//!   divides by. One scan, no allocation. This is what the per-block
//!   pulled-up tip pays.
//! - [`EpochSummary::build`]: the same scan, additionally keeping each
//!   validator's [`EpochFlags`] and effective balance.
//! - [`RewardContext`]: the epoch-wide constants of the reward formulas.
//!   Built after justification, since the inactivity-leak flag reads the
//!   finalized checkpoint which justification may move.
//!   [`RewardContext::deltas`] maps one validator's flags, effective balance
//!   and inactivity score to its [`ValidatorDeltas`].
//!
//! A summary is only valid while nothing it read changes: steps 1-3 write the
//! justification fields, `inactivity_scores` and `balances`, and none of those
//! feed a flag or an effective balance. It must be dropped before registry
//! updates run, and is never stored in the state.
//!
//! The specification-shaped implementation these replace is kept, compiled for
//! tests and debug builds only, in [`super::participation_reference`].

use crate::beacon::config::Config;
use crate::beacon::constants;
use crate::beacon::containers::BeaconState;
use crate::beacon::error::{Error, Result};
use crate::beacon::fork::ForkName;
use crate::beacon::preset;
use crate::beacon::primitives::Gwei;

use super::accessors::{get_current_epoch, get_previous_epoch};
use super::altair::has_flag;
use super::math::integer_squareroot;
use super::predicates::is_active_validator;

/// Number of timeliness flags a validator can earn.
const FLAG_COUNT: usize = constants::PARTICIPATION_FLAG_WEIGHTS.len();

/// A validator's standing for the previous epoch's accounting.
///
/// Bits 0..3 (one per timeliness flag): the validator is in
/// `get_unslashed_participating_indices(state, flag, previous_epoch)`, i.e.
/// active in the previous epoch, unslashed, and has the flag set.
/// Bit 3: the validator is in `get_eligible_validator_indices(state)`.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct EpochFlags(u8);

impl EpochFlags {
    const ELIGIBLE_BIT: u8 = 1 << FLAG_COUNT;

    /// Whether the validator is an unslashed participant for `flag_index`
    /// (one of the `TIMELY_*_FLAG_INDEX` constants) in the previous epoch.
    pub fn participated(self, flag_index: usize) -> bool {
        debug_assert!(flag_index < FLAG_COUNT);
        self.0 & (1 << flag_index) != 0
    }

    /// Whether the validator is eligible for this epoch's rewards and
    /// penalties.
    pub fn is_eligible(self) -> bool {
        self.0 & Self::ELIGIBLE_BIT != 0
    }
}

/// The balance totals justification and the reward formulas divide by.
///
/// Each is `get_total_balance` of its set: a saturating sum of effective
/// balances, floored at one increment so a caller can divide by it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ParticipationTotals {
    /// `get_total_active_balance`: the current epoch's active validators,
    /// slashed ones included.
    pub total_active_balance: Gwei,
    /// Per flag, the unslashed participating balance of the previous epoch.
    pub previous_epoch_flags: [Gwei; FLAG_COUNT],
    /// The unslashed balance that cast a timely target vote in the current
    /// epoch. Only meaningful when built with the current target requested
    /// (see [`EpochSummary::build`]); otherwise just the floor.
    pub current_epoch_target: Gwei,
}

impl ParticipationTotals {
    /// The totals justification needs, in one scan with no allocation.
    ///
    /// Fails exactly where `get_unslashed_participating_indices` does for
    /// either epoch: [`Error::IndexOutOfBounds`] when a participation list is
    /// shorter than an active validator's index (the previous epoch's list is
    /// reported first).
    pub fn compute(state: &BeaconState) -> Result<Self> {
        scan(state, true, |_, _, _| {})
    }
}

/// Walks the registry once, calling `each(index, flags, effective_balance)` per
/// validator, and returns the totals.
///
/// The only place the membership predicates live. `current_target` says
/// whether the current epoch's list is read at all: the specification's
/// steps 2 and 3 never touch it, so a caller that only runs them must not be
/// failed by a short current list.
///
/// At the genesis epoch "previous" and "current" coincide and the
/// specification reads the CURRENT list for both, so the previous epoch's
/// list aliases it there.
fn scan(
    state: &BeaconState,
    current_target: bool,
    mut each: impl FnMut(usize, EpochFlags, Gwei),
) -> Result<ParticipationTotals> {
    let (previous_list, current_list, _) = state.altair_validator_lists()?;
    let current_epoch = get_current_epoch(state);
    let previous_epoch = get_previous_epoch(state);
    let previous_list = if current_epoch == previous_epoch {
        current_list
    } else {
        previous_list
    };

    let mut total_active: Gwei = 0;
    let mut previous_flags = [0 as Gwei; FLAG_COUNT];
    let mut current_target_balance: Gwei = 0;
    // The two lists are checked independently and the previous epoch's error
    // wins, matching the order the specification's step 1 asks for them in.
    let mut previous_error = None;
    let mut current_error = None;

    for (index, validator) in state.validators().iter().enumerate() {
        let effective_balance = validator.effective_balance;
        let active_now = is_active_validator(validator, current_epoch);
        let active_before = is_active_validator(validator, previous_epoch);

        if active_now {
            total_active = total_active.saturating_add(effective_balance);
        }

        let mut bits = 0u8;
        if active_before {
            match previous_list.get(index) {
                Some(&participation) => {
                    if !validator.slashed {
                        for (flag_index, total) in previous_flags.iter_mut().enumerate() {
                            if has_flag(participation, flag_index) {
                                bits |= 1 << flag_index;
                                *total = total.saturating_add(effective_balance);
                            }
                        }
                    }
                }
                None => {
                    previous_error.get_or_insert(Error::IndexOutOfBounds {
                        index,
                        len: previous_list.len(),
                    });
                }
            }
        }
        // Slashed but not yet withdrawable validators stay eligible so they
        // keep paying penalties after leaving the active set.
        if active_before || (validator.slashed && previous_epoch + 1 < validator.withdrawable_epoch)
        {
            bits |= EpochFlags::ELIGIBLE_BIT;
        }

        if current_target && active_now {
            match current_list.get(index) {
                Some(&participation) => {
                    if has_flag(participation, constants::TIMELY_TARGET_FLAG_INDEX)
                        && !validator.slashed
                    {
                        current_target_balance =
                            current_target_balance.saturating_add(effective_balance);
                    }
                }
                None => {
                    current_error.get_or_insert(Error::IndexOutOfBounds {
                        index,
                        len: current_list.len(),
                    });
                }
            }
        }

        each(index, EpochFlags(bits), effective_balance);
    }

    if let Some(error) = previous_error.or(current_error) {
        return Err(error);
    }

    let floor = |total: Gwei| total.max(preset::EFFECTIVE_BALANCE_INCREMENT);
    Ok(ParticipationTotals {
        total_active_balance: floor(total_active),
        previous_epoch_flags: previous_flags.map(floor),
        current_epoch_target: floor(current_target_balance),
    })
}

/// Per-validator flags and effective balances for one epoch boundary, plus the
/// totals from the same scan.
///
/// Built once before step 1 and dropped after step 3; see the module docs for
/// why it must not outlive them. Costs one byte and eight bytes per registry
/// entry.
pub struct EpochSummary {
    flags: Vec<EpochFlags>,
    effective_balances: Vec<Gwei>,
    totals: ParticipationTotals,
}

impl EpochSummary {
    /// Scans the registry once.
    ///
    /// `need_current_target` is whether the caller will run justification:
    /// only then is the current epoch's participation list read, and only
    /// then is [`ParticipationTotals::current_epoch_target`] meaningful. Fails
    /// like [`ParticipationTotals::compute`].
    pub fn build(state: &BeaconState, need_current_target: bool) -> Result<Self> {
        let count = state.validators().len();
        let mut flags = Vec::with_capacity(count);
        let mut effective_balances = Vec::with_capacity(count);
        let totals = scan(state, need_current_target, |_, validator_flags, balance| {
            flags.push(validator_flags);
            effective_balances.push(balance);
        })?;
        Ok(Self {
            flags,
            effective_balances,
            totals,
        })
    }

    /// The totals from the scan.
    pub fn totals(&self) -> &ParticipationTotals {
        &self.totals
    }

    /// The number of validators the summary covers (the registry length at
    /// build time).
    pub fn len(&self) -> usize {
        self.flags.len()
    }

    /// Whether the summary covers no validators.
    pub fn is_empty(&self) -> bool {
        self.flags.is_empty()
    }

    /// Validator `index`'s flags and effective balance, or `None` past the
    /// end.
    pub fn get(&self, index: usize) -> Option<(EpochFlags, Gwei)> {
        Some((*self.flags.get(index)?, self.effective_balances[index]))
    }

    /// Every validator's flags and effective balance, in registry order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (EpochFlags, Gwei)> + '_ {
        self.flags
            .iter()
            .copied()
            .zip(self.effective_balances.iter().copied())
    }
}

/// One validator's rewards and penalties for the epoch, as `(reward, penalty)`
/// pairs in the specification's order: source, target, head, inactivity.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct ValidatorDeltas(pub [(Gwei, Gwei); FLAG_COUNT + 1]);

impl ValidatorDeltas {
    /// Position of the inactivity component in the array.
    pub const INACTIVITY: usize = FLAG_COUNT;

    /// `balance` after applying each component in the specification's order,
    /// reward first and then penalty.
    ///
    /// Deliberately not the net of all rewards and penalties: the balance
    /// floors at zero after each penalty, so a reward arriving after a
    /// penalty that emptied the balance still counts.
    pub fn apply(self, balance: Gwei) -> Gwei {
        self.0.iter().fold(balance, |balance, &(reward, penalty)| {
            balance.saturating_add(reward).saturating_sub(penalty)
        })
    }
}

/// The epoch-wide constants of the altair reward formulas.
///
/// Build it after justification: the leak flag reads `finalized_checkpoint`,
/// which justification may advance.
#[derive(Clone, Copy, Debug)]
pub struct RewardContext {
    leaking: bool,
    fork: ForkName,
    base_reward_per_increment: Gwei,
    active_increments: Gwei,
    participating_increments: [Gwei; FLAG_COUNT],
}

impl RewardContext {
    /// Derives the constants from `totals` (taken before or after
    /// justification alike) and the state's finality, which must be the
    /// post-justification one.
    ///
    /// Fails when that finality is past the previous epoch (see
    /// [`get_finality_delay`](super::finality::get_finality_delay)).
    pub fn new(state: &BeaconState, totals: &ParticipationTotals) -> Result<Self> {
        Ok(Self {
            leaking: super::finality::is_in_inactivity_leak(state)?,
            fork: state.fork_name(),
            base_reward_per_increment: preset::EFFECTIVE_BALANCE_INCREMENT
                * preset::BASE_REWARD_FACTOR
                / integer_squareroot(totals.total_active_balance),
            active_increments: totals.total_active_balance / preset::EFFECTIVE_BALANCE_INCREMENT,
            participating_increments: totals
                .previous_epoch_flags
                .map(|total| total / preset::EFFECTIVE_BALANCE_INCREMENT),
        })
    }

    /// Whether the chain is in an inactivity leak.
    pub fn is_leaking(&self) -> bool {
        self.leaking
    }

    /// The `(reward, penalty)` of each timeliness flag, in flag order.
    ///
    /// All zero for an ineligible validator. Arithmetic and operation order
    /// are `get_flag_index_deltas`'s, so the result is bit-identical.
    pub fn flag_deltas(
        &self,
        flags: EpochFlags,
        effective_balance: Gwei,
    ) -> [(Gwei, Gwei); FLAG_COUNT] {
        let mut deltas = [(0, 0); FLAG_COUNT];
        if !flags.is_eligible() {
            return deltas;
        }
        let increments = effective_balance / preset::EFFECTIVE_BALANCE_INCREMENT;
        let base_reward = increments * self.base_reward_per_increment;
        for (flag_index, delta) in deltas.iter_mut().enumerate() {
            let weight = constants::PARTICIPATION_FLAG_WEIGHTS[flag_index];
            if flags.participated(flag_index) {
                if !self.leaking {
                    let reward_numerator =
                        base_reward * weight * self.participating_increments[flag_index];
                    delta.0 +=
                        reward_numerator / (self.active_increments * constants::WEIGHT_DENOMINATOR);
                }
            } else if flag_index != constants::TIMELY_HEAD_FLAG_INDEX {
                delta.1 += base_reward * weight / constants::WEIGHT_DENOMINATOR;
            }
        }
        deltas
    }

    /// The inactivity penalty, as `get_inactivity_penalty_deltas` computes it.
    ///
    /// `score` is only called (and so the score only looked up) for an
    /// eligible validator that did not participate in the target, the one
    /// case that reads it; its error is passed through. Fails with
    /// [`Error::ArithmeticOverflow`] when `effective_balance * score`
    /// overflows.
    pub fn inactivity_penalty(
        &self,
        flags: EpochFlags,
        effective_balance: Gwei,
        score: impl FnOnce() -> Result<u64>,
        config: &Config,
    ) -> Result<Gwei> {
        if !flags.is_eligible() || flags.participated(constants::TIMELY_TARGET_FLAG_INDEX) {
            return Ok(0);
        }
        let penalty_numerator =
            effective_balance
                .checked_mul(score()?)
                .ok_or(Error::ArithmeticOverflow(
                    "effective_balance * inactivity_scores[index]",
                ))?;
        let inactivity_penalty_quotient = preset::retuned::inactivity_penalty_quotient(self.fork);
        let penalty_denominator = config.inactivity_score_bias * inactivity_penalty_quotient;
        Ok(penalty_numerator / penalty_denominator)
    }

    /// All four components for one validator.
    ///
    /// `score` is the validator's post-step-2 inactivity score, looked up
    /// lazily (see [`Self::inactivity_penalty`]).
    pub fn deltas(
        &self,
        flags: EpochFlags,
        effective_balance: Gwei,
        score: impl FnOnce() -> Result<u64>,
        config: &Config,
    ) -> Result<ValidatorDeltas> {
        let mut deltas = ValidatorDeltas::default();
        let flag_deltas = self.flag_deltas(flags, effective_balance);
        deltas.0[..FLAG_COUNT].copy_from_slice(&flag_deltas);
        deltas.0[ValidatorDeltas::INACTIVITY].1 =
            self.inactivity_penalty(flags, effective_balance, score, config)?;
        Ok(deltas)
    }
}
