//! Thin ephyra adapter for the portable `chain_model` cases.

use std::ops::ControlFlow;

use ephyra::{Gen, GenExt, Source};
use ephyra_validator::chain_model::{
    ForkReport, NodeReport, OffsetCase, ScheduleCase, UnorderedCase, valid_case as case_is_valid,
    valid_offset_case as offset_case_is_valid, valid_unordered_case as unordered_case_is_valid,
};

#[ephyra::generator]
pub fn valid_case(case: &ScheduleCase) -> bool {
    case_is_valid(case)
}

fn report(g: &mut Source) -> ForkReport {
    let fulu = if g.int(0u8..=9) == 0 {
        None
    } else {
        Some(g.int(1u16..=100))
    };
    let gloas = fulu.and_then(|fulu| {
        if g.bool_with(0.35) {
            None
        } else {
            Some(g.int(fulu..=200u16))
        }
    });
    ForkReport {
        fulu,
        gloas,
        fulu_version: g.int(0u8..=3),
        gloas_version: g.int(0u8..=3),
    }
}

fn draw_case(g: &mut Source) -> ScheduleCase {
    let current = report(g);
    let count = g.int(1usize..=4);
    let nodes = (0..count)
        .map(|_| NodeReport {
            forks: report(g),
            say: g.bool_with(0.75),
        })
        .collect();
    ScheduleCase {
        current,
        nodes,
        node_offset: g.int(1u64..=9_000),
        difference_kind: g.int(0u8..=6),
    }
}

pub fn shrink_case(
    case: &ScheduleCase,
    visit: &mut dyn FnMut(ScheduleCase) -> ControlFlow<()>,
) -> ControlFlow<()> {
    for i in 0..case.nodes.len() {
        let mut smaller = case.clone();
        smaller.nodes.remove(i);
        visit(smaller)?;
    }
    ControlFlow::Continue(())
}

#[ephyra::generator(valid_case)]
pub fn cases() -> impl Gen<Value = ScheduleCase> {
    draw_case.with_shrink(shrink_case)
}

#[ephyra::generator]
pub fn valid_offset_case(case: &OffsetCase) -> bool {
    offset_case_is_valid(case)
}

fn draw_offset_case(g: &mut Source) -> OffsetCase {
    let mut schedule = draw_case(g);
    while schedule.nodes.len() < 2 {
        schedule.nodes.push(NodeReport {
            forks: report(g),
            say: g.bool_with(0.75),
        });
    }
    let first = g.int(1u64..=9_000);
    let second = if first == 9_000 { first - 1 } else { first + 1 };
    let mut offsets = vec![first, second];
    offsets.extend((2..schedule.nodes.len()).map(|_| g.int(1u64..=9_000)));
    OffsetCase { schedule, offsets }
}

pub fn shrink_offset_case(
    case: &OffsetCase,
    visit: &mut dyn FnMut(OffsetCase) -> ControlFlow<()>,
) -> ControlFlow<()> {
    for i in 2..case.offsets.len() {
        let mut smaller = case.clone();
        smaller.offsets.remove(i);
        smaller.schedule.nodes.remove(i);
        visit(smaller)?;
    }
    ControlFlow::Continue(())
}

#[ephyra::generator(valid_offset_case)]
pub fn offset_cases() -> impl Gen<Value = OffsetCase> {
    draw_offset_case.with_shrink(shrink_offset_case)
}

#[ephyra::generator]
pub fn valid_unordered_case(case: &UnorderedCase) -> bool {
    unordered_case_is_valid(case)
}

fn draw_unordered_case(g: &mut Source) -> UnorderedCase {
    let current_fulu = g.int(2u16..=200);
    let current_gloas = g.int(1u16..=current_fulu - 1);
    let served_fulu = g.int(1u16..=200);
    UnorderedCase {
        current_fulu,
        current_gloas,
        served_fulu,
        served_gloas: g.int(served_fulu..=200),
        version: g.int(0u8..=3),
    }
}

pub fn shrink_unordered_case(
    case: &UnorderedCase,
    visit: &mut dyn FnMut(UnorderedCase) -> ControlFlow<()>,
) -> ControlFlow<()> {
    if case.current_fulu > case.current_gloas + 1 {
        let mut smaller = case.clone();
        smaller.current_fulu = case.current_gloas + 1;
        visit(smaller)?;
    }
    if case.served_gloas > case.served_fulu {
        let mut smaller = case.clone();
        smaller.served_gloas = case.served_fulu;
        visit(smaller)?;
    }
    ControlFlow::Continue(())
}

#[ephyra::generator(valid_unordered_case)]
pub fn unordered_cases() -> impl Gen<Value = UnorderedCase> {
    draw_unordered_case.with_shrink(shrink_unordered_case)
}
