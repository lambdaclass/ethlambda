//! Randomized equivalence of the one-pass participation accounting with the
//! specification-shaped reference it replaced.
//!
//! Every value the one-pass path is meant to reproduce is compared: the four
//! totals, each validator's flags, each component's `(reward, penalty)`, the
//! post-step scores and balances, the justification bits and checkpoints, and
//! the errors. States are crafted to reach what live chains do not: slashed and
//! exiting validators, effective balances off the increment or zero, scores
//! near `u64::MAX`, balances below one penalty, short lists, and the genesis
//! aliasing of the previous epoch's participation.

use super::{altair, altair_reference};
use crate::beacon::config::Config;
use crate::beacon::constants;
use crate::beacon::containers::BeaconState;
use crate::beacon::containers::shared::Checkpoint;
use crate::beacon::fork::ForkName;
use crate::beacon::helpers::accessors::{
    get_current_epoch, get_previous_epoch, get_total_active_balance, get_total_balance,
};
use crate::beacon::helpers::altair as helpers;
use crate::beacon::helpers::participation::{
    EpochSummary, ParticipationTotals, RewardContext, ValidatorDeltas,
};
use crate::beacon::helpers::participation_reference as reference;
use crate::beacon::helpers::test_state::with_validators_at;
use crate::beacon::preset;
use crate::beacon::primitives::{Gwei, Root, ValidatorIndex};

/// Small deterministic generator, so a failing case reproduces from its seed
/// without a new dependency.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `0..bound`.
    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }

    /// True with probability `percent` in a hundred.
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len() as u64) as usize]
    }
}

const FORKS: [ForkName; 5] = [
    ForkName::Altair,
    ForkName::Bellatrix,
    ForkName::Capella,
    ForkName::Electra,
    ForkName::Fulu,
];

/// A random state at a random position, with `extreme` allowing the values
/// that overflow or empty balances.
fn random_state(rng: &mut SplitMix64, fork: ForkName) -> BeaconState {
    let count = 1 + rng.below(300) as usize;
    let mut state = with_validators_at(fork, count);

    let epoch = match rng.below(6) {
        0 => 0,
        1 => 1,
        2 => 2,
        // Far enough past the genesis-finalized checkpoint to leak.
        3 => preset::MIN_EPOCHS_TO_INACTIVITY_PENALTY + 3 + rng.below(4),
        _ => 3 + rng.below(40),
    };
    // A non-zero offset lets the block root lookups for the current epoch
    // succeed; zero exercises their error.
    let offset = if rng.chance(90) {
        1 + rng.below(preset::SLOTS_PER_EPOCH - 1)
    } else {
        0
    };
    *state.slot_mut() = epoch * preset::SLOTS_PER_EPOCH + offset;

    let extreme = rng.chance(15);
    let participation_density = rng.pick(&[0, 30, 70, 95, 100]);
    let slashed_density = rng.pick(&[0, 5, 20]);
    let max_effective_balance = if matches!(fork, ForkName::Electra | ForkName::Fulu) {
        preset::MAX_EFFECTIVE_BALANCE_ELECTRA
    } else {
        preset::MAX_EFFECTIVE_BALANCE
    };

    for index in 0..count {
        let validator = state.validator_mut(index as ValidatorIndex).unwrap();
        // Epochs clustered around the previous and current ones so both
        // boundaries of `is_active_validator` and the slashed-eligibility
        // window are hit.
        let near = |rng: &mut SplitMix64| (epoch + rng.below(5)).saturating_sub(2);
        validator.activation_epoch = match rng.below(10) {
            0 => near(rng),
            1 => epoch + 1,
            _ => 0,
        };
        validator.exit_epoch = match rng.below(10) {
            0 => near(rng),
            1 => near(rng) + 1,
            _ => constants::FAR_FUTURE_EPOCH,
        };
        validator.slashed = rng.chance(slashed_density);
        validator.withdrawable_epoch = match rng.below(4) {
            0 => near(rng),
            1 => near(rng) + 1,
            _ => constants::FAR_FUTURE_EPOCH,
        };
        validator.effective_balance = match rng.below(10) {
            0 => 0,
            1 => rng.below(max_effective_balance),
            2 => {
                (1 + rng.below(max_effective_balance / preset::EFFECTIVE_BALANCE_INCREMENT))
                    * preset::EFFECTIVE_BALANCE_INCREMENT
            }
            _ => preset::MAX_EFFECTIVE_BALANCE,
        };
    }

    let balances: Vec<Gwei> = (0..count)
        .map(|index| {
            let effective = state
                .validator(index as ValidatorIndex)
                .unwrap()
                .effective_balance;
            match rng.below(10) {
                0 => 0,
                // Below one penalty, so a penalty empties it.
                1 => rng.below(5_000),
                2 if extreme => u64::MAX - rng.below(3),
                2 => rng.below(2 * effective + 1),
                _ => effective,
            }
        })
        .collect();
    *state.balances_mut() = balances.try_into().unwrap();

    let mut lists: Vec<Vec<u8>> = (0..2)
        .map(|_| {
            (0..count)
                .map(|_| {
                    if rng.chance(participation_density) {
                        // All eight bit patterns, upper bits included: only
                        // the three flag bits may matter.
                        // Half of them full votes, so the two-thirds
                        // threshold is reachable.
                        if rng.chance(50) {
                            0b111 | (rng.below(32) as u8) << 3
                        } else {
                            rng.below(256) as u8
                        }
                    } else {
                        0
                    }
                })
                .collect()
        })
        .collect();
    let mut scores: Vec<u64> = (0..count)
        .map(|_| match rng.below(10) {
            0 if extreme => u64::MAX - rng.below(6),
            1 if extreme => u64::MAX / 2 + rng.below(1 << 20),
            0..=2 => 0,
            3..=6 => rng.below(64),
            // Small enough that `effective_balance * score` does not
            // overflow outside the `extreme` cases.
            _ => rng.below(1 << 20),
        })
        .collect();

    // Short lists, which a live chain never has and the reference fails on.
    if rng.chance(3) {
        let keep = rng.below(count as u64) as usize;
        match rng.below(3) {
            0 => lists[0].truncate(keep),
            1 => lists[1].truncate(keep),
            _ => scores.truncate(keep),
        }
    }
    if rng.chance(1) {
        let keep = rng.below(count as u64) as usize;
        let mut balances = state.balances().to_vec();
        balances.truncate(keep);
        *state.balances_mut() = balances.try_into().unwrap();
    }
    let (previous, current, inactivity) = state.altair_validator_lists_mut().unwrap();
    *current = lists.pop().unwrap().try_into().unwrap();
    *previous = lists.pop().unwrap().try_into().unwrap();
    *inactivity = scores.try_into().unwrap();

    // Finality positioned so the four finalization rules can fire and the leak
    // can start or not.
    let checkpoint = |epoch: u64| Checkpoint {
        epoch,
        root: Root::ZERO,
    };
    *state.previous_justified_checkpoint_mut() = checkpoint(epoch.saturating_sub(rng.below(4)));
    *state.current_justified_checkpoint_mut() = checkpoint(epoch.saturating_sub(rng.below(3)));
    *state.finalized_checkpoint_mut() = if rng.chance(50) {
        checkpoint(0)
    } else {
        checkpoint(epoch.saturating_sub(rng.below(3)))
    };
    for bit in 0..constants::JUSTIFICATION_BITS_LENGTH {
        let value = rng.chance(50);
        state.justification_bits_mut().set(bit, value).unwrap();
    }
    state
}

/// Two results agree when both succeed or both fail with the same error.
fn assert_same_outcome<T, U>(
    seed: u64,
    what: &str,
    fast: &crate::beacon::error::Result<T>,
    slow: &crate::beacon::error::Result<U>,
) {
    match (fast, slow) {
        (Ok(_), Ok(_)) => {}
        (Err(fast), Err(slow)) => {
            assert_eq!(
                fast.to_string(),
                slow.to_string(),
                "{what} error, seed {seed}"
            );
        }
        _ => panic!(
            "{what} outcome differs, seed {seed}: fast ok={} slow ok={}",
            fast.is_ok(),
            slow.is_ok()
        ),
    }
}

fn assert_same_state(seed: u64, what: &str, fast: &BeaconState, slow: &BeaconState) {
    assert_eq!(
        fast.balances(),
        slow.balances(),
        "{what} balances, seed {seed}"
    );
    let (_, _, fast_scores) = fast.altair_validator_lists().unwrap();
    let (_, _, slow_scores) = slow.altair_validator_lists().unwrap();
    assert_eq!(fast_scores, slow_scores, "{what} scores, seed {seed}");
    assert_eq!(
        fast.justification_bits(),
        slow.justification_bits(),
        "{what} bits, seed {seed}"
    );
    assert_eq!(
        fast.previous_justified_checkpoint(),
        slow.previous_justified_checkpoint(),
        "{what} previous justified, seed {seed}"
    );
    assert_eq!(
        fast.current_justified_checkpoint(),
        slow.current_justified_checkpoint(),
        "{what} current justified, seed {seed}"
    );
    assert_eq!(
        fast.finalized_checkpoint(),
        slow.finalized_checkpoint(),
        "{what} finalized, seed {seed}"
    );
}

const CASES_PER_FORK: u64 = 300;

fn for_each_state(mut check: impl FnMut(u64, &BeaconState)) {
    for (fork_number, fork) in FORKS.into_iter().enumerate() {
        for case in 0..CASES_PER_FORK {
            let seed = (fork_number as u64) << 32 | case;
            let mut rng = SplitMix64(seed);
            let state = random_state(&mut rng, fork);
            check(seed, &state);
        }
    }
}

#[test]
fn drivers_match_the_reference_steps() {
    let config = Config::mainnet();
    let (mut total, mut succeeded, mut balances_moved, mut justified, mut finalized) =
        (0, 0, 0, 0, 0);
    for_each_state(|seed, state| {
        let mut fast = state.clone();
        let mut slow = state.clone();
        // The driver also asserts against the reference itself; the explicit
        // comparison here adds the error text.
        let fast_result = altair::process_participation_steps(&mut fast, &config);
        let slow_result = altair_reference::process_participation_steps(&mut slow, &config);
        assert_same_outcome(seed, "driver", &fast_result, &slow_result);
        total += 1;
        if fast_result.is_ok() {
            assert_same_state(seed, "driver", &fast, &slow);
            succeeded += 1;
            balances_moved += (fast.balances() != state.balances()) as u32;
            justified += (fast.current_justified_checkpoint()
                != state.current_justified_checkpoint()) as u32;
            finalized += (fast.finalized_checkpoint() != state.finalized_checkpoint()) as u32;
        }
    });
    // The generator has to reach the interesting outcomes, not only errors.
    assert!(
        succeeded * 2 > total,
        "too many errors: {succeeded}/{total}"
    );
    assert!(balances_moved > 100, "balances moved in {balances_moved}");
    assert!(justified > 20, "justification moved in {justified}");
    assert!(finalized > 5, "finalization moved in {finalized}");
}

#[test]
fn public_steps_match_the_reference_in_isolation() {
    let config = Config::mainnet();
    for_each_state(|seed, state| {
        let mut fast = state.clone();
        let mut slow = state.clone();
        let fast_result = altair::process_justification_and_finalization(&mut fast);
        let slow_result = altair_reference::process_justification_and_finalization(&mut slow);
        assert_same_outcome(seed, "justification", &fast_result, &slow_result);
        if fast_result.is_ok() {
            assert_same_state(seed, "justification", &fast, &slow);
        }

        let mut fast = state.clone();
        let mut slow = state.clone();
        let fast_result = altair::process_inactivity_updates(&mut fast, &config);
        let slow_result = altair_reference::process_inactivity_updates(&mut slow, &config);
        assert_same_outcome(seed, "inactivity", &fast_result, &slow_result);
        if fast_result.is_ok() {
            assert_same_state(seed, "inactivity", &fast, &slow);
        }

        let mut fast = state.clone();
        let mut slow = state.clone();
        let fast_result = altair::process_rewards_and_penalties(&mut fast, &config);
        let slow_result = altair_reference::process_rewards_and_penalties(&mut slow, &config);
        assert_same_outcome(seed, "rewards", &fast_result, &slow_result);
        if fast_result.is_ok() {
            assert_same_state(seed, "rewards", &fast, &slow);
        }
    });
}

#[test]
fn helpers_match_the_reference() {
    let config = Config::mainnet();
    for_each_state(|seed, state| {
        let previous = get_previous_epoch(state);
        let current = get_current_epoch(state);

        for flag in 0..constants::PARTICIPATION_FLAG_WEIGHTS.len() {
            for epoch in [previous, current] {
                let fast = helpers::get_unslashed_participating_indices(state, flag, epoch);
                let slow = reference::get_unslashed_participating_indices(state, flag, epoch);
                assert_same_outcome(seed, "participating indices", &fast, &slow);
                if let (Ok(fast), Ok(slow)) = (fast, slow) {
                    assert_eq!(fast, slow, "participating indices, seed {seed}");
                }
            }

            let fast = helpers::get_flag_index_deltas(state, flag);
            let slow = reference::get_flag_index_deltas(state, flag);
            assert_same_outcome(seed, "flag deltas", &fast, &slow);
            if let (Ok(fast), Ok(slow)) = (fast, slow) {
                assert_eq!(fast, slow, "flag deltas {flag}, seed {seed}");
            }
        }

        let fast = helpers::get_inactivity_penalty_deltas(state, &config);
        let slow = reference::get_inactivity_penalty_deltas(state, &config);
        assert_same_outcome(seed, "inactivity deltas", &fast, &slow);
        if let (Ok(fast), Ok(slow)) = (fast, slow) {
            assert_eq!(fast, slow, "inactivity deltas, seed {seed}");
        }
    });
}

#[test]
fn summary_matches_the_reference() {
    let config = Config::mainnet();
    for_each_state(|seed, state| {
        let previous = get_previous_epoch(state);
        let current = get_current_epoch(state);
        let flag_count = constants::PARTICIPATION_FLAG_WEIGHTS.len();

        // The reference's answer for each set, or its first error, previous
        // epoch's list first as step 1 asks for them.
        let previous_sets: Vec<_> = (0..flag_count)
            .map(|flag| reference::get_unslashed_participating_indices(state, flag, previous))
            .collect();
        let current_target = reference::get_unslashed_participating_indices(
            state,
            constants::TIMELY_TARGET_FLAG_INDEX,
            current,
        );

        let compute = ParticipationTotals::compute(state);
        let previous_error = previous_sets.iter().find(|set| set.is_err());
        match (previous_error, &current_target, &compute) {
            (Some(Err(expected)), _, Err(actual)) | (None, Err(expected), Err(actual)) => {
                assert_eq!(
                    actual.to_string(),
                    expected.to_string(),
                    "totals error, seed {seed}"
                );
                return;
            }
            (None, Ok(_), Ok(_)) => {}
            _ => panic!("totals outcome differs, seed {seed}"),
        }
        let totals = compute.unwrap();

        assert_eq!(
            totals.total_active_balance,
            get_total_active_balance(state).unwrap(),
            "total active, seed {seed}"
        );
        for (flag, set) in previous_sets.iter().enumerate() {
            assert_eq!(
                totals.previous_epoch_flags[flag],
                get_total_balance(state, set.as_ref().unwrap()).unwrap(),
                "previous flag {flag} total, seed {seed}"
            );
        }
        assert_eq!(
            totals.current_epoch_target,
            get_total_balance(state, current_target.as_ref().unwrap()).unwrap(),
            "current target total, seed {seed}"
        );

        // Steps 2 and 3 never read the current epoch's list, so a summary
        // built without it must not be failed by it, and its shared totals
        // must agree.
        let summary = EpochSummary::build(state, false).unwrap();
        assert_eq!(
            summary.totals().total_active_balance,
            totals.total_active_balance
        );
        assert_eq!(
            summary.totals().previous_epoch_flags,
            totals.previous_epoch_flags
        );
        let summary = EpochSummary::build(state, true).unwrap();
        assert_eq!(summary.totals(), &totals, "summary totals, seed {seed}");
        assert_eq!(summary.len(), state.validators().len());

        let eligible = crate::beacon::helpers::finality::get_eligible_validator_indices(state);
        for (index, (flags, effective_balance)) in summary.iter().enumerate() {
            assert_eq!(
                effective_balance,
                state
                    .validator(index as ValidatorIndex)
                    .unwrap()
                    .effective_balance
            );
            assert_eq!(
                flags.is_eligible(),
                eligible.binary_search(&(index as ValidatorIndex)).is_ok(),
                "eligible {index}, seed {seed}"
            );
            for (flag, set) in previous_sets.iter().enumerate() {
                assert_eq!(
                    flags.participated(flag),
                    set.as_ref()
                        .unwrap()
                        .binary_search(&(index as ValidatorIndex))
                        .is_ok(),
                    "flag {flag} of {index}, seed {seed}"
                );
            }
        }

        // Each component of `RewardContext::deltas` against the reference's
        // vectors, and the balance it applies to against the spec's order.
        let context = RewardContext::new(state, summary.totals());
        let (_, _, scores) = state.altair_validator_lists().unwrap();
        let flag_deltas: Vec<_> = (0..flag_count)
            .map(|flag| reference::get_flag_index_deltas(state, flag).unwrap())
            .collect();
        let inactivity = reference::get_inactivity_penalty_deltas(state, &config);
        let mut first_expected_error = None;
        for (index, (flags, effective_balance)) in summary.iter().enumerate() {
            let deltas = context.deltas(
                flags,
                effective_balance,
                || {
                    scores.get(index).copied().ok_or(
                        crate::beacon::error::Error::IndexOutOfBounds {
                            index,
                            len: scores.len(),
                        },
                    )
                },
                &config,
            );
            let deltas = match deltas {
                Ok(deltas) => deltas,
                Err(error) => {
                    first_expected_error.get_or_insert(error.to_string());
                    continue;
                }
            };
            for (flag, (rewards, penalties)) in flag_deltas.iter().enumerate() {
                assert_eq!(
                    deltas.0[flag],
                    (rewards[index], penalties[index]),
                    "flag {flag} deltas of {index}, seed {seed}"
                );
            }
            if let Ok((_, penalties)) = &inactivity {
                assert_eq!(
                    deltas.0[ValidatorDeltas::INACTIVITY],
                    (0, penalties[index]),
                    "inactivity delta of {index}, seed {seed}"
                );
            }
        }
        match (&inactivity, first_expected_error) {
            (Ok(_), None) => {}
            (Err(expected), Some(actual)) => {
                assert_eq!(actual, expected.to_string(), "delta error, seed {seed}");
            }
            _ => panic!("inactivity delta outcome differs, seed {seed}"),
        }
    });
}

#[test]
fn applying_deltas_floors_after_each_component() {
    // A reward arriving after a penalty that emptied the balance still counts;
    // netting first would lose it.
    let deltas = ValidatorDeltas([(0, 10), (5, 0), (0, 0), (0, 0)]);
    assert_eq!(deltas.apply(3), 5);
    let netted = 3u64.saturating_add(5).saturating_sub(10);
    assert_ne!(deltas.apply(3), netted);
}
