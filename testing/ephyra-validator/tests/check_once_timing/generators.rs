//! Ephyra adapter for the portable timing cases.

use std::ops::ControlFlow;

use ephyra::{Gen, GenExt, Source};
use ephyra_validator::timing_model::{
    RaceCase, TimingCase, valid_race_case as race_case_is_valid,
    valid_timing_case as timing_case_is_valid,
};

#[ephyra::generator]
pub fn valid_timing_case(case: &TimingCase) -> bool {
    timing_case_is_valid(case)
}

fn draw_case(g: &mut Source) -> TimingCase {
    TimingCase {
        fork_delta: g.int(1u8..=5),
        answer_after_fork: g.bool(),
        delay_ms: g.int(1u8..=20),
        version: g.int(1u8..=3),
    }
}

pub fn shrink_case(
    case: &TimingCase,
    visit: &mut dyn FnMut(TimingCase) -> ControlFlow<()>,
) -> ControlFlow<()> {
    for smaller in [
        TimingCase {
            fork_delta: 1,
            ..case.clone()
        },
        TimingCase {
            delay_ms: 1,
            ..case.clone()
        },
        TimingCase {
            version: 1,
            ..case.clone()
        },
        TimingCase {
            answer_after_fork: false,
            ..case.clone()
        },
    ] {
        if smaller != *case {
            visit(smaller)?;
        }
    }
    ControlFlow::Continue(())
}

#[ephyra::generator(valid_timing_case)]
pub fn timing_cases() -> impl Gen<Value = TimingCase> {
    draw_case.with_shrink(shrink_case)
}

#[ephyra::generator]
pub fn valid_race_case(case: &RaceCase) -> bool {
    race_case_is_valid(case)
}

fn draw_race_case(g: &mut Source) -> RaceCase {
    RaceCase {
        fast_delay_ms: g.int(1u8..=5),
        slow_delay_ms: g.int(20u8..=100),
        version: g.int(1u8..=3),
    }
}

pub fn shrink_race_case(
    case: &RaceCase,
    visit: &mut dyn FnMut(RaceCase) -> ControlFlow<()>,
) -> ControlFlow<()> {
    for smaller in [
        RaceCase {
            fast_delay_ms: 1,
            ..case.clone()
        },
        RaceCase {
            slow_delay_ms: 20,
            ..case.clone()
        },
        RaceCase {
            version: 1,
            ..case.clone()
        },
    ] {
        if smaller != *case {
            visit(smaller)?;
        }
    }
    ControlFlow::Continue(())
}

#[ephyra::generator(valid_race_case)]
pub fn race_cases() -> impl Gen<Value = RaceCase> {
    draw_race_case.with_shrink(shrink_race_case)
}
