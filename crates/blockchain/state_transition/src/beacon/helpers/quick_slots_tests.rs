//! EIP-8198 (quick slots): the reward and churn accessors against values
//! worked out by hand from the specification's formulas.
//!
//! The pinned spec fixtures predate EIP-8198 and run with one slot duration
//! throughout, so these are the coverage for a duration that changes at
//! Heze. The schedule is 12 s slots, 9 s from epoch 2.

use super::accessors::get_current_epoch;
use super::altair::{base_reward_per_increment_at, get_base_reward_per_increment};
use super::gloas::{
    get_activation_churn_limit, get_consolidation_churn_limit, get_exit_churn_limit,
};
use super::participation::{EpochSummary, RewardContext};
use super::test_state::with_validators_at;
use crate::beacon::config::Config;
use crate::beacon::constants;
use crate::beacon::containers::BeaconState;
use crate::beacon::fork::ForkName;
use crate::beacon::preset;

const HEZE_EPOCH: u64 = 2;

fn quick_slots() -> Config {
    Config {
        slot_duration_ms: 12_000,
        slot_duration_ms_heze: 9_000,
        heze_fork_epoch: HEZE_EPOCH,
        ..Config::mainnet()
    }
}

fn state_at_epoch(fork: ForkName, epoch: u64, count: usize) -> BeaconState {
    let mut state = with_validators_at(fork, count);
    *state.slot_mut() = epoch * preset::SLOTS_PER_EPOCH;
    state
}

#[test]
fn base_reward_per_increment_follows_the_slot_duration_of_the_epoch() {
    let config = quick_slots();
    // 1e15 Gwei active: integer_squareroot is 31_622_776.
    let total = 1_000_000_000_000_000;
    // 1e9 * 64 = 6.4e10 per sqrt unit at 12 s; the 9 s price is 3/4 of it,
    // floored before the square root division: 4.8e10.
    assert_eq!(base_reward_per_increment_at(total, 0, &config), 2_023);
    assert_eq!(base_reward_per_increment_at(total, 1, &config), 2_023);
    assert_eq!(base_reward_per_increment_at(total, 2, &config), 1_517);
    assert_eq!(base_reward_per_increment_at(total, 50, &config), 1_517);
}

#[test]
fn base_reward_per_increment_matches_the_old_price_without_a_fork() {
    let config = Config {
        heze_fork_epoch: constants::FAR_FUTURE_EPOCH,
        ..quick_slots()
    };
    for total in [32_000_000_000, 1_000_000_000_000_000] {
        assert_eq!(
            base_reward_per_increment_at(total, 7, &config),
            super::altair::base_reward_per_increment(total)
        );
    }
}

#[test]
fn get_base_reward_per_increment_reads_the_state_and_the_requested_epoch() {
    let config = quick_slots();
    let state = state_at_epoch(ForkName::Heze, 3, 4);
    // 4 validators of 32 ETH: integer_squareroot(128e9) is 357_770.
    let at = |epoch| get_base_reward_per_increment(&state, epoch, &config).unwrap();
    assert_eq!(at(1), 64_000_000_000 / 357_770);
    assert_eq!(at(2), 48_000_000_000 / 357_770);
}

/// Priced at the previous epoch: the first epoch after the fork still pays
/// for the last pre-fork epoch at the old price.
#[test]
fn flag_deltas_are_priced_at_the_previous_epoch() {
    let config = quick_slots();
    let penalty_of = |epoch: u64| {
        let state = state_at_epoch(ForkName::Heze, epoch, 4);
        let summary = EpochSummary::build(&state, false).unwrap();
        let context = RewardContext::new(&state, summary.totals(), &config).unwrap();
        let (flags, effective_balance) = summary.iter().next().unwrap();
        // Nobody participated, so the source flag is a pure penalty.
        context.flag_deltas(flags, effective_balance)[constants::TIMELY_SOURCE_FLAG_INDEX].1
    };
    let expected = |duration_ms: u128| {
        let per_increment = 64_000_000_000u128 * duration_ms / 12_000 / 357_770;
        let base_reward = 32 * per_increment;
        (base_reward * u128::from(constants::PARTICIPATION_FLAG_WEIGHTS[0])
            / u128::from(constants::WEIGHT_DENOMINATOR)) as u64
    };
    // Epoch 2 is the fork epoch: it pays for epoch 1, a 12 s epoch.
    assert_eq!(penalty_of(2), expected(12_000));
    // Epoch 3 pays for epoch 2, a 9 s epoch.
    assert_eq!(penalty_of(3), expected(9_000));
    assert_ne!(expected(12_000), expected(9_000));
}

/// The penalty grows with the square of the epoch duration, so the
/// denominator scales with the squared ratio of the previous epoch's.
#[test]
fn inactivity_penalty_scales_with_the_squared_duration_ratio() {
    let config = quick_slots();
    let penalty_of = |epoch: u64| {
        let state = state_at_epoch(ForkName::Heze, epoch, 4);
        let summary = EpochSummary::build(&state, false).unwrap();
        let context = RewardContext::new(&state, summary.totals(), &config).unwrap();
        let (flags, effective_balance) = summary.iter().next().unwrap();
        context
            .inactivity_penalty(flags, effective_balance, || Ok(1_000), &config)
            .unwrap()
    };
    let quotient = u128::from(preset::retuned::inactivity_penalty_quotient(ForkName::Heze));
    let bias = u128::from(config.inactivity_score_bias);
    let expected = |previous_duration: u128| {
        let denominator =
            bias * quotient * 12_000 * 12_000 / (previous_duration * previous_duration);
        (32_000_000_000u128 * 1_000 / denominator) as u64
    };
    assert_eq!(penalty_of(2), expected(12_000));
    assert_eq!(penalty_of(3), expected(9_000));
    assert!(
        penalty_of(3) < penalty_of(2),
        "shorter epochs pay a smaller penalty"
    );
}

#[test]
fn exit_and_consolidation_churn_scale_and_round_once() {
    // A floor that is not a whole number of increments, so rounding before
    // scaling and rounding after it give different answers.
    let config = Config {
        min_per_epoch_churn_limit_electra: 133_000_000_001,
        ..quick_slots()
    };
    let before = state_at_epoch(ForkName::Heze, 1, 4);
    let after = state_at_epoch(ForkName::Heze, 2, 4);
    // Unscaled: 133_000_000_001 rounds to 133e9.
    assert_eq!(
        get_exit_churn_limit(&before, &config).unwrap(),
        133_000_000_000
    );
    // Scaled: 133_000_000_001 * 9000 / 12000 floors to 99_750_000_000, which
    // then rounds down to 99e9. Rounding first would have given 99.75e9.
    assert_eq!(
        get_exit_churn_limit(&after, &config).unwrap(),
        99_000_000_000
    );

    let config = Config {
        consolidation_churn_limit_quotient: 1,
        ..quick_slots()
    };
    // 128e9 total active: 128e9 at 12 s, 96e9 at 9 s.
    assert_eq!(
        get_consolidation_churn_limit(&before, &config).unwrap(),
        128_000_000_000
    );
    assert_eq!(
        get_consolidation_churn_limit(&after, &config).unwrap(),
        96_000_000_000
    );
}

#[test]
fn activation_churn_caps_before_scaling_from_heze_on() {
    let config = Config {
        min_per_epoch_churn_limit_electra: 400_000_000_000,
        max_per_epoch_activation_churn_limit_gloas: 200_000_000_000,
        ..quick_slots()
    };
    // Before the fork (and on a gloas state): the cap alone.
    let gloas = state_at_epoch(ForkName::Gloas, 1, 4);
    assert_eq!(
        get_activation_churn_limit(&gloas, &config).unwrap(),
        200_000_000_000
    );
    // From Heze: cap to 200e9, then scale by 9000/12000. Scaling first would
    // leave 300e9 and the cap would then give 200e9.
    let heze = state_at_epoch(ForkName::Heze, 2, 4);
    assert_eq!(get_current_epoch(&heze), 2);
    assert_eq!(
        get_activation_churn_limit(&heze, &config).unwrap(),
        150_000_000_000
    );
}

#[test]
fn churn_is_unchanged_when_the_slot_duration_does_not_change() {
    let config = Config {
        slot_duration_ms_heze: 12_000,
        ..quick_slots()
    };
    let heze = state_at_epoch(ForkName::Heze, 5, 4);
    assert_eq!(
        get_exit_churn_limit(&heze, &config).unwrap(),
        config.min_per_epoch_churn_limit_electra
    );
}
