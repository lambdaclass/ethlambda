#[path = "chain_properties/generators.rs"]
mod generators;

use ephyra::{Config, check, check_generator, check_shrinker};
use ephyra_validator::chain_model::{
    check_chain_boundary, check_different_offsets, check_follow, check_order, check_response_order,
    check_unordered_repair,
};

fn config(name: &str, tests: u64) -> Config {
    Config::default().name(name).tests(tests)
}

#[test]
fn generator_and_shrinker_are_valid() {
    let cfg = config("schedule_generator", 500);
    check_generator(&cfg, generators::cases(), generators::valid_case).assert_passed();
    check_shrinker(&cfg, generators::cases(), generators::valid_case, |case| {
        case.nodes.len() as u64
    })
    .assert_passed();
    check_generator(
        &cfg,
        generators::offset_cases(),
        generators::valid_offset_case,
    )
    .assert_passed();
    check_shrinker(
        &cfg,
        generators::offset_cases(),
        generators::valid_offset_case,
        |case| case.offsets.len() as u64,
    )
    .assert_passed();
    check_generator(
        &cfg,
        generators::unordered_cases(),
        generators::valid_unordered_case,
    )
    .assert_passed();
    check_shrinker(
        &cfg,
        generators::unordered_cases(),
        generators::valid_unordered_case,
        |case| u64::from(case.current_fulu + case.served_gloas),
    )
    .assert_passed();
}

#[test]
fn ordered_merge() {
    let report = check(&config("ordered_merge", 500), generators::cases(), |case| {
        check_order(&case)
    });
    println!("{report}");
    report.assert_passed();
}

#[test]
fn response_order() {
    let report = check(
        &config("response_order", 500),
        generators::cases(),
        |case| check_response_order(&case),
    );
    println!("{report}");
    report.assert_passed();
}

#[test]
fn future_and_active_chain_boundary() {
    let report = check(
        &config("chain_boundary", 500),
        generators::cases(),
        |case| check_chain_boundary(&case),
    );
    println!("{report}");
    report.assert_passed();
}

#[test]
fn follow_equals_merge() {
    let report = check(
        &config("follow_equals_merge", 500),
        generators::cases(),
        |case| check_follow(&case),
    );
    println!("{report}");
    report.assert_passed();
}

#[test]
fn differing_duty_offsets() {
    let report = check(
        &config("differing_duty_offsets", 500),
        generators::offset_cases(),
        |case| check_different_offsets(&case),
    );
    println!("{report}");
    report.assert_passed();
}

#[test]
fn initially_unordered_schedule_is_repaired() {
    let report = check(
        &config("initially_unordered_repair", 500),
        generators::unordered_cases(),
        |case| check_unordered_repair(&case),
    );
    println!("{report}");
    report.assert_passed();
}
