//! The `shuffling` runner.
//!
//! Each case gives a seed, a set size, and the full permutation the
//! specification's shuffle produces. `mapping[i]` is where index `i` ends up, so
//! checking every entry pins down `compute_shuffled_index` exactly, for every
//! index rather than for a sampled few. The same fixture also pins down
//! `compute_shuffled_indices`, the whole-list form
//! `helpers::accessors::EpochCommittees` derives its cached shuffling from: it
//! is a from-scratch reimplementation sharing hashing across positions rather
//! than a wrapper around `compute_shuffled_index`, so it gets its own pass
//! over every case rather than riding along on the per-index one.
//!
//! This is the only fixture suite that tests the shuffle directly. Everything
//! else depends on it only through committee assignment, where a subtle error
//! would show up as a confusing signature failure much later, so it is worth
//! getting green on its own before any of that is built.

use ethlambda_beacon::helpers::shuffling::{compute_shuffled_index, compute_shuffled_indices};
use ethlambda_beacon::primitives::Root;
use libtest_mimic::Trial;

use super::{PRESET, collect};

#[derive(serde::Deserialize)]
struct Mapping {
    seed: String,
    count: u64,
    mapping: Vec<u64>,
}

/// This suite is not gated here: [`super::case_trial`] applies
/// [`super::Case::in_scope`]'s gate itself, so every case collected below is
/// simply handed to it.
pub fn trials() -> Vec<Trial> {
    let cases = collect(PRESET, "shuffling", "core");
    let mut trials = vec![super::discovery_trial("shuffling", cases.len())];

    for case in cases {
        trials.push(super::case_trial("shuffling", case, move |case| {
            let mapping: Mapping = case.yaml("mapping");

            let stripped = mapping.seed.strip_prefix("0x").unwrap_or(&mapping.seed);
            let seed_bytes = hex::decode(stripped).expect("the seed is a hex string");
            let seed = Root::from_slice(&seed_bytes);

            if mapping.mapping.len() as u64 != mapping.count {
                return Err(format!(
                    "fixture claims count {} but lists {} entries",
                    mapping.count,
                    mapping.mapping.len()
                ));
            }

            for (index, expected) in mapping.mapping.iter().enumerate() {
                let actual = compute_shuffled_index(index as u64, mapping.count, seed)
                    .map_err(|err| format!("index {index}: {err}"))?;
                if actual != *expected {
                    return Err(format!(
                        "index {index} shuffled to {actual}, expected {expected}"
                    ));
                }
            }

            // An index at the boundary must be rejected rather than wrapping,
            // which the fixtures do not cover but the specification asserts.
            if compute_shuffled_index(mapping.count, mapping.count, seed).is_ok() {
                return Err("an out-of-range index was accepted".to_string());
            }

            let whole_list = compute_shuffled_indices(mapping.count, seed);
            if whole_list != mapping.mapping {
                return Err(format!(
                    "compute_shuffled_indices produced {whole_list:?}, expected {:?}",
                    mapping.mapping
                ));
            }

            Ok(())
        }));
    }

    trials
}
