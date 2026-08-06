//! The `shuffling` runner.
//!
//! Each case gives a seed, a set size, and the full permutation the
//! specification's shuffle produces. `mapping[i]` is where index `i` ends up, so
//! checking every entry pins down `compute_shuffled_index` exactly, for every
//! index rather than for a sampled few.
//!
//! This is the only fixture suite that tests the shuffle directly. Everything
//! else depends on it only through committee assignment, where a subtle error
//! would show up as a confusing signature failure much later, so it is worth
//! getting green on its own before any of that is built.

use ethlambda_beacon::helpers::shuffling::compute_shuffled_index;
use ethlambda_beacon::primitives::Root;

use super::{PRESET, Report, collect};

#[derive(serde::Deserialize)]
struct Mapping {
    seed: String,
    count: u64,
    mapping: Vec<u64>,
}

#[test]
fn shuffling() {
    let mut report = Report::new();

    for case in collect(PRESET, "shuffling", "core") {
        let mapping: Mapping = case.yaml("mapping");

        let stripped = mapping.seed.strip_prefix("0x").unwrap_or(&mapping.seed);
        let seed_bytes = hex::decode(stripped).expect("the seed is a hex string");
        let seed = Root::from_slice(&seed_bytes);

        let outcome = (|| {
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

            Ok(())
        })();

        report.record(&case, outcome);
    }

    report.finish("shuffling");
}
