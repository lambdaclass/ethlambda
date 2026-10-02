//! Randomized equivalence tests for the single-pass altair epoch helpers.
//!
//! The functions below are the implementations these helpers had before they
//! were rewritten to walk the registry once: they build index lists, descend
//! the registry per index and binary-search. They are kept verbatim as the
//! reference the current code must match exactly, errors included, on states
//! only a fixture would reach (short participation lists, zero and off-grid
//! effective balances, scores near the top of the range).

use super::*;
use crate::beacon::containers::shared::InactivityScores;
use crate::beacon::helpers::accessors::{get_active_validator_indices, get_total_balance};
use crate::beacon::helpers::finality::get_eligible_validator_indices;
use crate::beacon::helpers::math::saturating_sub;
use crate::beacon::helpers::mutators::{decrease_balance, increase_balance};
use crate::beacon::helpers::test_state::with_validators_at;
use crate::beacon::stf::epoch::altair as steps;
use crate::beacon::stf::epoch::justification::weigh_justification_and_finalization;

// ---------------------------------------------------------------------------
// Reference implementations (the code as it was before the single pass)
// ---------------------------------------------------------------------------

fn ref_unslashed_participating_indices(
    state: &BeaconState,
    flag_index: usize,
    epoch: Epoch,
) -> Result<Vec<ValidatorIndex>> {
    crate::beacon::verify(
        epoch == get_previous_epoch(state) || epoch == get_current_epoch(state),
        "epoch in (get_previous_epoch(state), get_current_epoch(state))",
    )?;

    let (previous_epoch_participation, current_epoch_participation, _) =
        state.altair_validator_lists()?;
    let epoch_participation = if epoch == get_current_epoch(state) {
        current_epoch_participation
    } else {
        previous_epoch_participation
    };

    let mut participating_indices = Vec::new();
    for index in get_active_validator_indices(state, epoch) {
        let flags =
            epoch_participation
                .get(index as usize)
                .copied()
                .ok_or(Error::IndexOutOfBounds {
                    index: index as usize,
                    len: epoch_participation.len(),
                })?;
        if has_flag(flags, flag_index) && !state.validator(index)?.slashed {
            participating_indices.push(index);
        }
    }
    Ok(participating_indices)
}

fn ref_flag_index_deltas(state: &BeaconState, flag_index: usize) -> Result<(Vec<Gwei>, Vec<Gwei>)> {
    let validator_count = state.validators().len();
    let mut rewards = vec![0; validator_count];
    let mut penalties = vec![0; validator_count];

    let previous_epoch = get_previous_epoch(state);
    let unslashed_participating_indices =
        ref_unslashed_participating_indices(state, flag_index, previous_epoch)?;
    let weight = constants::PARTICIPATION_FLAG_WEIGHTS[flag_index];
    let unslashed_participating_balance =
        get_total_balance(state, &unslashed_participating_indices)?;
    let unslashed_participating_increments =
        unslashed_participating_balance / preset::EFFECTIVE_BALANCE_INCREMENT;
    let active_increments = get_total_active_balance(state)? / preset::EFFECTIVE_BALANCE_INCREMENT;
    let base_reward_per_increment = get_base_reward_per_increment(state)?;

    for index in get_eligible_validator_indices(state) {
        let increments =
            state.validator(index)?.effective_balance / preset::EFFECTIVE_BALANCE_INCREMENT;
        let base_reward = increments * base_reward_per_increment;
        if unslashed_participating_indices
            .binary_search(&index)
            .is_ok()
        {
            if !is_in_inactivity_leak(state) {
                let reward_numerator = base_reward * weight * unslashed_participating_increments;
                rewards[index as usize] +=
                    reward_numerator / (active_increments * constants::WEIGHT_DENOMINATOR);
            }
        } else if flag_index != constants::TIMELY_HEAD_FLAG_INDEX {
            penalties[index as usize] += base_reward * weight / constants::WEIGHT_DENOMINATOR;
        }
    }
    Ok((rewards, penalties))
}

fn ref_inactivity_penalty_deltas(
    state: &BeaconState,
    config: &Config,
) -> Result<(Vec<Gwei>, Vec<Gwei>)> {
    let validator_count = state.validators().len();
    let rewards = vec![0; validator_count];
    let mut penalties = vec![0; validator_count];

    let previous_epoch = get_previous_epoch(state);
    let matching_target_indices = ref_unslashed_participating_indices(
        state,
        constants::TIMELY_TARGET_FLAG_INDEX,
        previous_epoch,
    )?;

    let (_, _, inactivity_scores) = state.altair_validator_lists()?;

    for index in get_eligible_validator_indices(state) {
        if matching_target_indices.binary_search(&index).is_err() {
            let effective_balance = state.validator(index)?.effective_balance;
            let inactivity_score =
                inactivity_scores
                    .get(index as usize)
                    .copied()
                    .ok_or(Error::IndexOutOfBounds {
                        index: index as usize,
                        len: inactivity_scores.len(),
                    })?;

            let penalty_numerator = effective_balance.checked_mul(inactivity_score).ok_or(
                Error::ArithmeticOverflow("effective_balance * inactivity_scores[index]"),
            )?;
            let inactivity_penalty_quotient =
                preset::retuned::inactivity_penalty_quotient(state.fork_name());
            let penalty_denominator = config.inactivity_score_bias * inactivity_penalty_quotient;
            penalties[index as usize] += penalty_numerator / penalty_denominator;
        }
    }

    Ok((rewards, penalties))
}

fn ref_process_justification_and_finalization(state: &mut BeaconState) -> Result<()> {
    if get_current_epoch(state) <= constants::GENESIS_EPOCH + 1 {
        return Ok(());
    }

    let previous_indices = ref_unslashed_participating_indices(
        state,
        constants::TIMELY_TARGET_FLAG_INDEX,
        get_previous_epoch(state),
    )?;
    let current_indices = ref_unslashed_participating_indices(
        state,
        constants::TIMELY_TARGET_FLAG_INDEX,
        get_current_epoch(state),
    )?;
    let total_active_balance = get_total_active_balance(state)?;
    let previous_target_balance = get_total_balance(state, &previous_indices)?;
    let current_target_balance = get_total_balance(state, &current_indices)?;
    weigh_justification_and_finalization(
        state,
        total_active_balance,
        previous_target_balance,
        current_target_balance,
    )
}

fn ref_process_inactivity_updates(state: &mut BeaconState, config: &Config) -> Result<()> {
    if get_current_epoch(state) == constants::GENESIS_EPOCH {
        return Ok(());
    }

    let eligible_indices = get_eligible_validator_indices(state);
    let previous_epoch = get_previous_epoch(state);
    let participating_indices = ref_unslashed_participating_indices(
        state,
        constants::TIMELY_TARGET_FLAG_INDEX,
        previous_epoch,
    )?;
    let leaking = is_in_inactivity_leak(state);

    let (_, _, inactivity_scores) = state.altair_validator_lists_mut()?;
    let score_count = inactivity_scores.len();
    for index in eligible_indices {
        let score = inactivity_scores
            .get_mut(index as usize)
            .ok_or(Error::IndexOutOfBounds {
                index: index as usize,
                len: score_count,
            })?;

        if participating_indices.binary_search(&index).is_ok() {
            *score = saturating_sub(*score, 1);
        } else {
            *score = score.checked_add(config.inactivity_score_bias).ok_or(
                Error::ArithmeticOverflow("inactivity_scores[index] + INACTIVITY_SCORE_BIAS"),
            )?;
        }

        if !leaking {
            *score = saturating_sub(*score, config.inactivity_score_recovery_rate);
        }
    }

    Ok(())
}

fn ref_process_rewards_and_penalties(state: &mut BeaconState, config: &Config) -> Result<()> {
    if get_current_epoch(state) == constants::GENESIS_EPOCH {
        return Ok(());
    }

    let mut deltas = Vec::with_capacity(constants::PARTICIPATION_FLAG_WEIGHTS.len() + 1);
    for flag_index in 0..constants::PARTICIPATION_FLAG_WEIGHTS.len() {
        deltas.push(ref_flag_index_deltas(state, flag_index)?);
    }
    deltas.push(ref_inactivity_penalty_deltas(state, config)?);

    let validator_count = state.validators().len() as ValidatorIndex;
    for (rewards, penalties) in deltas {
        for index in 0..validator_count {
            increase_balance(state, index, rewards[index as usize])?;
            decrease_balance(state, index, penalties[index as usize])?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Randomized states
// ---------------------------------------------------------------------------

/// SplitMix64: a small deterministic generator, enough for test inputs.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }

    fn pick<T: Copy>(&mut self, options: &[T]) -> T {
        options[self.below(options.len() as u64) as usize]
    }
}

/// The most an electra-era effective balance can hold.
const MAX_BALANCE: Gwei = 2_048_000_000_000;

/// The current epochs the tests visit: the first three, an ordinary one, and
/// one far enough past the genesis-default finalized checkpoint to leak.
fn epoch_choices() -> [Epoch; 5] {
    [0, 1, 2, 5, preset::MIN_EPOCHS_TO_INACTIVITY_PENALTY + 6]
}

fn random_state(rng: &mut Rng, fork: ForkName, current_epoch: Epoch) -> BeaconState {
    let count = 100 + rng.below(201) as usize;
    let mut state = with_validators_at(fork, count);
    *state.slot_mut() = current_epoch * preset::SLOTS_PER_EPOCH;
    let previous_epoch = current_epoch.saturating_sub(1);

    // Finality anywhere at or before the previous epoch (a leak when it is
    // far behind), which keeps the finality delay from underflowing.
    let leaking_state = current_epoch > preset::MIN_EPOCHS_TO_INACTIVITY_PENALTY;
    let finalized_epoch = if leaking_state && rng.chance(70) {
        0
    } else {
        rng.below(previous_epoch + 1)
    };
    state.finalized_checkpoint_mut().epoch = finalized_epoch;
    state.current_justified_checkpoint_mut().epoch = rng.below(current_epoch + 1);
    state.previous_justified_checkpoint_mut().epoch = rng.below(previous_epoch + 1);
    let bits = rng.below(16);
    for bit in 0..4 {
        let _ = state
            .justification_bits_mut()
            .set(bit, bits >> bit & 1 == 1);
    }

    let epochs_around = [
        0,
        previous_epoch.saturating_sub(1),
        previous_epoch,
        current_epoch,
        current_epoch + 1,
        current_epoch + 2,
    ];
    let large_scores = rng.chance(15);
    for index in 0..count {
        let activation_epoch = if rng.chance(70) {
            0
        } else {
            rng.pick(&epochs_around)
        };
        let exit_epoch = if rng.chance(70) {
            constants::FAR_FUTURE_EPOCH
        } else {
            rng.pick(&epochs_around)
        };
        let withdrawable_epoch = if rng.chance(50) {
            constants::FAR_FUTURE_EPOCH
        } else {
            rng.pick(&epochs_around)
        };
        let effective_balance = match rng.below(6) {
            0 => 0,
            1 => preset::MAX_EFFECTIVE_BALANCE,
            2 => rng.below(MAX_BALANCE + 1),
            _ => {
                rng.below(MAX_BALANCE / preset::EFFECTIVE_BALANCE_INCREMENT + 1)
                    * preset::EFFECTIVE_BALANCE_INCREMENT
            }
        };
        let validator = state.validator_mut(index as u64).unwrap();
        validator.activation_epoch = activation_epoch;
        validator.exit_epoch = exit_epoch;
        validator.withdrawable_epoch = withdrawable_epoch;
        validator.slashed = rng.chance(25);
        validator.effective_balance = effective_balance;

        let balance = match rng.below(4) {
            0 => 0,
            1 => rng.below(1_000_000_000),
            2 => effective_balance,
            _ => effective_balance.saturating_add(rng.below(2_000_000_000)),
        };
        *state.balances_mut().get_mut(index).unwrap() = balance;
    }

    let (previous, current, scores) = state.altair_validator_lists_mut().unwrap();
    for index in 0..count {
        previous[index] = rng.below(8) as u8;
        current[index] = rng.below(8) as u8;
        scores[index] = if large_scores && rng.chance(4) {
            u64::MAX - rng.below(10)
        } else if rng.chance(10) {
            rng.below(1 << 20)
        } else {
            rng.below(200)
        };
    }

    // Some states have a list shorter than the registry, which only a fixture
    // can build; both implementations must report the same error.
    if rng.chance(8) {
        let keep = rng.below(count as u64) as usize;
        match rng.below(3) {
            0 => *previous = truncated_participation(previous, keep),
            1 => *current = truncated_participation(current, keep),
            _ => *scores = truncated_scores(scores, keep),
        }
    }

    state
}

fn truncated_participation(list: &EpochParticipation, keep: usize) -> EpochParticipation {
    list.iter()
        .copied()
        .take(keep)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

fn truncated_scores(list: &InactivityScores, keep: usize) -> InactivityScores {
    list.iter()
        .copied()
        .take(keep)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

fn for_random_states(seed: u64, mut check: impl FnMut(&mut Rng, &BeaconState)) {
    let mut rng = Rng(seed);
    for fork in [ForkName::Altair, ForkName::Electra] {
        for current_epoch in epoch_choices() {
            for _ in 0..12 {
                let state = random_state(&mut rng, fork, current_epoch);
                check(&mut rng, &state);
            }
        }
    }
}

fn debug<T: core::fmt::Debug>(value: &T) -> String {
    format!("{value:?}")
}

/// Everything the three epoch steps can write.
fn snapshot(state: &BeaconState) -> String {
    let (_, _, scores) = state.altair_validator_lists().unwrap();
    debug(&(
        state.justification_bits().clone(),
        state.previous_justified_checkpoint(),
        state.current_justified_checkpoint(),
        state.finalized_checkpoint(),
        scores.iter().copied().collect::<Vec<_>>(),
        state.balances().iter().copied().collect::<Vec<_>>(),
    ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn participation_helpers_match_reference() {
    for_random_states(1, |_, state| {
        let current_epoch = get_current_epoch(state);
        let epochs = [
            get_previous_epoch(state),
            current_epoch,
            // Neither current nor previous: both must refuse.
            current_epoch + 3,
        ];
        for flag_index in 0..constants::PARTICIPATION_FLAG_WEIGHTS.len() {
            for epoch in epochs {
                let expected = ref_unslashed_participating_indices(state, flag_index, epoch);
                let actual = get_unslashed_participating_indices(state, flag_index, epoch);
                assert_eq!(debug(&actual), debug(&expected));

                let expected_balance =
                    expected.and_then(|indices| get_total_balance(state, &indices));
                let actual_balance = get_unslashed_participating_balance(state, flag_index, epoch);
                assert_eq!(debug(&actual_balance), debug(&expected_balance));
            }
        }

        let total = get_total_active_balance(state).unwrap();
        assert_eq!(compute_total_active_balance(state), total);
        assert_eq!(
            base_reward_per_increment_from_total(total),
            get_base_reward_per_increment(state).unwrap(),
        );
    });
}

#[test]
fn reward_deltas_match_reference() {
    let config = Config::mainnet();
    for_random_states(2, |_, state| {
        for flag_index in 0..constants::PARTICIPATION_FLAG_WEIGHTS.len() {
            let expected = ref_flag_index_deltas(state, flag_index);
            let actual = get_flag_index_deltas(state, flag_index);
            assert_eq!(debug(&actual), debug(&expected), "flag {flag_index}");
        }
        let expected = ref_inactivity_penalty_deltas(state, &config);
        let actual = get_inactivity_penalty_deltas(state, &config);
        assert_eq!(debug(&actual), debug(&expected));
    });
}

#[test]
fn epoch_steps_match_reference() {
    let config = Config::mainnet();
    for_random_states(3, |_, state| {
        let mut expected_state = state.clone();
        let mut actual_state = state.clone();
        let expected = ref_process_justification_and_finalization(&mut expected_state);
        let actual = steps::process_justification_and_finalization(&mut actual_state);
        assert_eq!(debug(&actual), debug(&expected));
        assert_eq!(snapshot(&actual_state), snapshot(&expected_state));

        let mut expected_state = state.clone();
        let mut actual_state = state.clone();
        let expected = ref_process_inactivity_updates(&mut expected_state, &config);
        let actual = steps::process_inactivity_updates(&mut actual_state, &config);
        assert_eq!(debug(&actual), debug(&expected));
        assert_eq!(snapshot(&actual_state), snapshot(&expected_state));

        let mut expected_state = state.clone();
        let mut actual_state = state.clone();
        let expected = ref_process_rewards_and_penalties(&mut expected_state, &config);
        let actual = steps::process_rewards_and_penalties(&mut actual_state, &config);
        assert_eq!(debug(&actual), debug(&expected));
        assert_eq!(snapshot(&actual_state), snapshot(&expected_state));

        // The steps in driver order, so step 3 reads the scores step 2 wrote
        // and the leak flag step 1's finality may have moved.
        let mut expected_state = state.clone();
        let mut actual_state = state.clone();
        let expected = ref_process_justification_and_finalization(&mut expected_state)
            .and_then(|()| ref_process_inactivity_updates(&mut expected_state, &config))
            .and_then(|()| ref_process_rewards_and_penalties(&mut expected_state, &config));
        let actual = steps::process_justification_and_finalization(&mut actual_state)
            .and_then(|()| steps::process_inactivity_updates(&mut actual_state, &config))
            .and_then(|()| steps::process_rewards_and_penalties(&mut actual_state, &config));
        assert_eq!(debug(&actual), debug(&expected));
        assert_eq!(snapshot(&actual_state), snapshot(&expected_state));
    });
}
