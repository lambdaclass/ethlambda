//! Ephyra adapter: only generation, support, and shrinking live here.

use std::ops::ControlFlow;

use ephyra::{Gen, GenExt, Source};
use ephyra_validator::model::{
    DurableCase, DurableCorruption, ImportEntry, MAX_EPOCH, MAX_KEY, MAX_SLOT, Op, Trace,
    interchange, valid_durable_case as durable_case_is_valid, valid_vote,
};

#[ephyra::generator]
pub fn valid_trace(trace: &Trace) -> bool {
    if trace.ops.len() > 25 {
        return false;
    }
    trace.ops.iter().all(|op| match op {
        Op::Register(keys) | Op::Export(keys) => {
            keys.len() <= 4 && keys.iter().all(|key| *key <= MAX_KEY)
        }
        Op::Block { key, slot, root } => *key <= MAX_KEY && *slot <= MAX_SLOT && *root <= 1,
        Op::Attest {
            keys,
            source,
            target,
            slot,
            root,
        } => {
            keys.len() <= 4
                && keys.iter().all(|key| *key <= MAX_KEY)
                && *target <= MAX_EPOCH
                && *source <= MAX_EPOCH + 1
                && *slot <= MAX_EPOCH * 32 + 1
                && *root <= 1
        }
        Op::Reopen { mode } => *mode <= 12,
        Op::Import { entries, .. } => valid_entries(entries),
        Op::Absorb {
            entries, register, ..
        } => {
            valid_entries(entries)
                && register.len() <= 4
                && register.iter().all(|key| *key <= MAX_KEY)
        }
    })
}

fn valid_entries(entries: &[ImportEntry]) -> bool {
    entries.len() <= 3
        && entries.iter().all(|entry| {
            entry.key <= MAX_KEY
                && entry.blocks.len() <= 3
                && entry.blocks.iter().all(|s| *s <= MAX_SLOT)
                && entry.attestations.len() <= 3
                && entry
                    .attestations
                    .iter()
                    .all(|(s, t)| *t <= MAX_EPOCH && valid_vote(*s, *t))
        })
}

fn vote_epochs(g: &mut Source) -> (u64, u64) {
    let target = g.int(0u64..=MAX_EPOCH);
    let source = if target == 0 {
        0
    } else {
        g.int(0u64..=target - 1)
    };
    (source, target)
}

fn key_list(g: &mut Source, max: usize) -> Vec<u8> {
    let count = g.int(0usize..=max);
    (0..count).map(|_| g.int(0u8..=MAX_KEY)).collect()
}

fn import_entry(g: &mut Source) -> ImportEntry {
    let blocks = (0..g.int(0usize..=3))
        .map(|_| g.int(0u64..=MAX_SLOT))
        .collect();
    let attestations = (0..g.int(0usize..=3)).map(|_| vote_epochs(g)).collect();
    ImportEntry {
        key: g.int(0u8..=MAX_KEY),
        blocks,
        attestations,
    }
}

fn draw_trace(g: &mut Source) -> Trace {
    let mut ops = vec![Op::Register(vec![0, 1])];
    let count = g.int(0usize..=22);
    for _ in 0..count {
        let choice = g.int(0u8..=99);
        let op = match choice {
            0..=12 => Op::Register(key_list(g, 4)),
            13..=37 => Op::Block {
                key: g.int(0u8..=MAX_KEY),
                slot: g.int(0u64..=MAX_SLOT),
                root: g.int(0u8..=1),
            },
            38..=63 => {
                let (source, target) = if g.int(0u8..=5) == 0 {
                    let target = g.int(1u64..=MAX_EPOCH);
                    (target + g.int(0u64..=1), target)
                } else {
                    vote_epochs(g)
                };
                let mut keys = key_list(g, 3);
                if keys.is_empty() {
                    keys.push(g.int(0u8..=MAX_KEY));
                }
                Op::Attest {
                    keys,
                    source,
                    target,
                    slot: target * 32 + g.int(0u64..=1),
                    root: g.int(0u8..=1),
                }
            }
            64..=75 => Op::Reopen {
                mode: g.int(0u8..=12),
            },
            76..=85 => Op::Import {
                entries: (0..g.int(0usize..=3)).map(|_| import_entry(g)).collect(),
                wrong_chain: g.int(0u8..=9) == 0,
            },
            86..=92 => Op::Absorb {
                entries: (0..g.int(0usize..=3)).map(|_| import_entry(g)).collect(),
                register: key_list(g, 4),
                wrong_chain: g.int(0u8..=9) == 0,
            },
            _ => Op::Export(key_list(g, 4)),
        };
        ops.push(op);
    }
    Trace { ops }
}

pub fn shrink_trace(
    trace: &Trace,
    visit: &mut dyn FnMut(Trace) -> ControlFlow<()>,
) -> ControlFlow<()> {
    // Deleting one operation preserves support and strictly reduces the size.
    for i in 0..trace.ops.len() {
        let mut smaller = trace.clone();
        smaller.ops.remove(i);
        visit(smaller)?;
    }
    ControlFlow::Continue(())
}

#[ephyra::generator(valid_trace)]
pub fn traces() -> impl Gen<Value = Trace> {
    draw_trace.with_shrink(shrink_trace)
}

#[ephyra::generator]
pub fn valid_text(_text: &String) -> bool {
    true
}

fn draw_text(g: &mut Source) -> String {
    let seed = interchange(
        &[ImportEntry {
            key: 1,
            blocks: vec![3],
            attestations: vec![(2, 3)],
        }],
        false,
    );
    match g.int(0u8..=15) {
        0 => String::new(),
        1 => "{}".to_string(),
        2 => "[]".to_string(),
        3 => seed,
        4 => seed.replace("\"5\"", "\"4\""),
        5 => seed.replace("\"source_epoch\":\"2\"", "\"source_epoch\":\"9\""),
        6..=10 => {
            let mut bytes = seed.into_bytes();
            let index = g.index(bytes.len());
            match g.int(0u8..=3) {
                0 => bytes[index] = *g.pick(b"{}[]:,\"0123456789xaz \n\0"),
                1 => {
                    bytes.remove(index);
                }
                2 => bytes.insert(index, *g.pick(b"{}[]:,\"0123456789xaz \n\0")),
                _ => {
                    let count = g.int(1usize..=8);
                    bytes.splice(
                        index..(index + count).min(bytes.len()),
                        b"18446744073709551616".iter().copied(),
                    );
                }
            }
            String::from_utf8(bytes).expect("ASCII mutations")
        }
        _ => {
            let count = g.int(0usize..=128);
            (0..count)
                .map(|_| {
                    if g.bool_with(0.2) {
                        char::from_u32(g.int(0u32..=0x10ffff)).unwrap_or('\u{fffd}')
                    } else {
                        *g.pick(b"{}[]:,\"0123456789xaz \n\0") as char
                    }
                })
                .collect()
        }
    }
}

pub fn shrink_text(
    text: &String,
    visit: &mut dyn FnMut(String) -> ControlFlow<()>,
) -> ControlFlow<()> {
    let chars: Vec<char> = text.chars().collect();
    for i in 0..chars.len() {
        let mut smaller = chars.clone();
        smaller.remove(i);
        visit(smaller.into_iter().collect())?;
    }
    ControlFlow::Continue(())
}

#[ephyra::generator(valid_text)]
pub fn texts() -> impl Gen<Value = String> {
    draw_text.with_shrink(shrink_text)
}

#[ephyra::generator]
pub fn valid_durable_case(case: &DurableCase) -> bool {
    durable_case_is_valid(case)
}

fn draw_durable_case(g: &mut Source) -> DurableCase {
    let corruption = match g.int(0u8..=9) {
        0 => DurableCorruption::InvalidUtf8,
        1 => DurableCorruption::Empty,
        2 => DurableCorruption::Truncated,
        3 => DurableCorruption::WrongVersion,
        4 => DurableCorruption::DuplicateKey,
        5 => DurableCorruption::UnknownField,
        6 => DurableCorruption::MissingField,
        7 => DurableCorruption::ImpossibleVote,
        8 => DurableCorruption::InvalidPubkey,
        _ => DurableCorruption::OverflowingSlot,
    };
    DurableCase {
        slot: g.int(1u8..=12),
        corruption,
        opener: g.int(0u8..=2),
    }
}

pub fn shrink_durable_case(
    case: &DurableCase,
    visit: &mut dyn FnMut(DurableCase) -> ControlFlow<()>,
) -> ControlFlow<()> {
    if case.slot > 1 {
        let mut smaller = case.clone();
        smaller.slot = 1;
        visit(smaller)?;
    }
    if case.opener > 0 {
        let mut smaller = case.clone();
        smaller.opener = 0;
        visit(smaller)?;
    }
    ControlFlow::Continue(())
}

#[ephyra::generator(valid_durable_case)]
pub fn durable_cases() -> impl Gen<Value = DurableCase> {
    draw_durable_case.with_shrink(shrink_durable_case)
}
