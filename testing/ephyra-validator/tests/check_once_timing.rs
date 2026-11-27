#[path = "check_once_timing/generators.rs"]
mod generators;

use ephyra::{Config, check, check_generator, check_shrinker};
use ephyra_validator::timing_model::{check_fast_answer_beats_slow_timeout, check_timing};

fn config(name: &str, cases: u64) -> Config {
    Config::default().name(name).tests(cases)
}

#[test]
fn generator_and_shrinker_are_valid() {
    let cfg = config("timing_generator", 300);
    check_generator(
        &cfg,
        generators::timing_cases(),
        generators::valid_timing_case,
    )
    .assert_passed();
    check_shrinker(
        &cfg,
        generators::timing_cases(),
        generators::valid_timing_case,
        |case| {
            u64::from(case.fork_delta + case.delay_ms + case.version)
                + u64::from(case.answer_after_fork)
        },
    )
    .assert_passed();
    check_generator(&cfg, generators::race_cases(), generators::valid_race_case).assert_passed();
    check_shrinker(
        &cfg,
        generators::race_cases(),
        generators::valid_race_case,
        |case| u64::from(case.fast_delay_ms + case.slow_delay_ms + case.version),
    )
    .assert_passed();
}

#[test]
fn response_epoch_controls_adoption() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Tokio runtime");
    let report = check(
        &config("response_epoch_controls_adoption", 100),
        generators::timing_cases(),
        |case| {
            runtime.block_on(check_timing(&case));
        },
    );
    println!("{report}");
    report.assert_passed();
}

#[test]
fn prompt_answer_precedes_slow_node() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Tokio runtime");
    let report = check(
        &config("prompt_answer_precedes_slow_node", 100),
        generators::race_cases(),
        |case| runtime.block_on(check_fast_answer_beats_slow_timeout(&case)),
    );
    println!("{report}");
    report.assert_passed();
}
