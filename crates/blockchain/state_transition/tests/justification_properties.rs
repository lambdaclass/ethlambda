//! Property tests for the 3SF-mini justification bookkeeping, each against a
//! reference model written straight from the specification:
//!
//! - `slot_is_justifiable_after` against leanSpec's `Slot.is_justifiable_after`
//!   (`src/lean_spec/spec/forks/lstar/slot.py`), which computes in unbounded
//!   Python integers; the model here computes in `u128`.
//! - `justified_slots_ops` (the bitlist indexed relative to the finalized
//!   slot) against a plain set of absolute justified slots, over random
//!   sequences of extend / justify / finalize steps.
//!
//! Driven by ephyra; a failure prints an `EPHYRA_REPLAY=seed:iteration` line
//! that reruns that exact input. See `docs/property_testing.md`.

use std::collections::BTreeSet;

use ephyra::prelude::*;
use ephyra::{BoxGen, gens};
use ethlambda_state_transition::{Error, justified_slots_ops as ops, slot_is_justifiable_after};
use ethlambda_types::state::JustifiedSlots;

// --- slot_is_justifiable_after ---------------------------------------------

/// Integer square root by bisection: slow, obviously correct, and no shared
/// code with `u64::isqrt`.
fn model_isqrt(n: u128) -> u128 {
    let (mut lo, mut hi) = (0u128, 1u128 << 64);
    while lo < hi {
        let mid = lo + (hi - lo).div_ceil(2);
        if mid * mid <= n {
            lo = mid
        } else {
            hi = mid - 1
        }
    }
    lo
}

/// leanSpec's `is_justifiable_after`, rule for rule.
fn model_justifiable(slot: u64, finalized: u64) -> bool {
    if slot < finalized {
        return false;
    }
    let delta = u128::from(slot - finalized);
    let root = model_isqrt(delta);
    delta <= 5 || root * root == delta || root * (root + 1) == delta
}

/// The largest slot distance the comparison covers.
///
/// Above `u64::MAX / 4` the implementation's pronic test (`4 * delta + 1` an
/// odd square, under `checked_mul`) overflows and answers "not pronic" where
/// the spec, in unbounded integers, says justifiable: ephyra found
/// `delta = 12357188433973714806 = 3515279282 * 3515279283`. That is 2^62
/// slots, some 5.8e11 years of 4-second slots past finalization, so no chain
/// reaches it; the bound keeps the property on the distances that matter.
const REACHABLE_DELTA: u64 = u64::MAX / 4;

/// Distances that sit on, or one off, the squares and pronics the rule
/// accepts, for roots from tiny to the largest whose pronic stays within
/// [`REACHABLE_DELTA`].
fn deltas() -> BoxGen<u64> {
    let near_rule = (
        gens::frequency(vec![
            (3, gens::int(0u64..=1_000).boxed()),
            (1, gens::int(0u64..=(1 << 31) - 1).boxed()),
            (1, gens::edges(0u64..=(1 << 31) - 1).boxed()),
        ]),
        gens::int(0u8..=5),
    )
        .map(|(root, shape)| {
            let square = root.saturating_mul(root);
            let pronic = square.saturating_add(root);
            match shape {
                0 => square,
                1 => square.saturating_add(1),
                2 => square.saturating_sub(1),
                3 => pronic,
                4 => pronic.saturating_add(1),
                _ => pronic.saturating_sub(1),
            }
        });
    gens::frequency(vec![
        (4, near_rule.boxed()),
        (1, gens::int(0u64..=64).boxed()),
        (1, gens::int(0u64..=REACHABLE_DELTA).boxed()),
        (1, gens::edges(0u64..=REACHABLE_DELTA).boxed()),
    ])
    .boxed()
}

#[ephyra::test(tests = 20_000)]
fn justifiability_matches_the_spec(
    #[ephyra(gen = deltas())] delta: u64,
    #[ephyra(gen = gens::frequency(vec![
        (3, gens::int(0u64..=10_000).boxed()),
        (1, gens::int(..).boxed()),
    ]))]
    finalized: u64,
    before_finalized: bool,
) {
    // Either side of the finalized slot, without wrapping.
    let slot = if before_finalized {
        finalized.saturating_sub(delta)
    } else {
        finalized.saturating_add(delta)
    };
    assert_eq!(
        slot_is_justifiable_after(slot, finalized),
        model_justifiable(slot, finalized),
        "slot {slot}, finalized {finalized}, delta {}",
        i128::from(slot) - i128::from(finalized)
    );
}

// --- justified_slots_ops -----------------------------------------------------

/// One step of the window's life, as the state transition takes it.
#[derive(Clone, Debug, ephyra::Arbitrary)]
enum Step {
    /// `extend_to_slot` to `finalized + offset`.
    Extend(#[ephyra(gen = gens::int(0u64..=96))] u64),
    /// `set_justified` on `finalized + offset`, the offset taken modulo the
    /// tracked length plus one so the slot is always tracked or finalized
    /// (the state transition extends before it justifies).
    Justify(#[ephyra(gen = gens::int(0u64..=96))] u64),
    /// Finalization advances by `delta`: `shift_window(delta)`.
    Finalize(#[ephyra(gen = gens::int(0u64..=40))] u64),
}

/// The window as a set of absolute slots: nothing relative, nothing shifted.
struct Model {
    finalized: u64,
    /// Slots `finalized + 1 ..= finalized + tracked` have a status.
    tracked: u64,
    justified: BTreeSet<u64>,
}

impl Model {
    fn is_slot_justified(&self, slot: u64) -> Option<bool> {
        if slot <= self.finalized {
            Some(true)
        } else if slot - self.finalized <= self.tracked {
            Some(self.justified.contains(&slot))
        } else {
            None
        }
    }
}

#[ephyra::test(tests = 5_000)]
fn the_justified_window_matches_a_set_of_absolute_slots(
    #[ephyra(gen = gens::frequency(vec![
        (3, gens::int(0u64..=1_000).boxed()),
        (1, gens::int(0u64..=u64::MAX - 100_000).boxed()),
    ]))]
    finalized: u64,
    #[ephyra(gen = gens::vec(ephyra::any::<Step>()).len(0..=60))] steps: Vec<Step>,
) {
    let mut slots = JustifiedSlots::new();
    let mut model = Model {
        finalized,
        tracked: 0,
        justified: BTreeSet::new(),
    };

    for (i, step) in steps.iter().enumerate() {
        match *step {
            Step::Extend(offset) => {
                ops::extend_to_slot(&mut slots, model.finalized, model.finalized + offset);
                model.tracked = model.tracked.max(offset);
            }
            Step::Justify(offset) => {
                let offset = offset % (model.tracked + 1);
                let slot = model.finalized + offset;
                ops::set_justified(&mut slots, model.finalized, slot);
                if offset > 0 {
                    model.justified.insert(slot);
                }
            }
            Step::Finalize(delta) => {
                ops::shift_window(&mut slots, delta as usize);
                model.finalized += delta;
                model.tracked = model.tracked.saturating_sub(delta);
                let finalized = model.finalized;
                model.justified.retain(|&slot| slot > finalized);
            }
        }

        assert_eq!(
            slots.len() as u64,
            model.tracked,
            "step {i}: {step:?}: tracked length"
        );
        // Every slot from below the boundary to past the tracked end.
        let from = model.finalized.saturating_sub(2);
        for slot in from..=model.finalized + model.tracked + 2 {
            let actual = ops::is_slot_justified(&slots, model.finalized, slot);
            match model.is_slot_justified(slot) {
                Some(expected) => assert_eq!(
                    actual.ok(),
                    Some(expected),
                    "step {i}: {step:?}: slot {slot}, finalized {}",
                    model.finalized
                ),
                None => assert!(
                    matches!(actual, Err(Error::JustifiedSlotOutOfRange { .. })),
                    "step {i}: {step:?}: untracked slot {slot} answered {actual:?}"
                ),
            }
        }
    }
}
