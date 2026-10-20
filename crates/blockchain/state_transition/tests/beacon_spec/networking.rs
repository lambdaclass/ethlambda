//! The `networking` runner: das-core's custody selection.
//!
//! Two handlers, both pure functions of public inputs, which is the whole
//! point of the deterministic selection: every peer can compute what every
//! other peer owes without asking. A disagreement here is invisible on the
//! wire until columns are requested from a peer that never custodied them.
//!
//! `node_id` arrives as a decimal integer of up to 78 digits, wider than any
//! Rust primitive, so it is read as a string and parsed into the 32 big-endian
//! bytes the helper takes.

use ethlambda_state_transition::beacon::das::{
    compute_columns_for_custody_group, get_custody_groups,
};
use libtest_mimic::Trial;
use num_bigint::BigUint;

use super::{Case, PRESET, collect_all_handlers};

#[derive(serde::Deserialize)]
struct CustodyGroupsMeta {
    node_id: String,
    custody_group_count: u64,
    result: Vec<u64>,
}

#[derive(serde::Deserialize)]
struct ColumnsMeta {
    custody_group: u64,
    result: Vec<u64>,
}

/// The fixture's decimal node id as 32 big-endian bytes, left-padded.
///
/// `BigUint::to_bytes_be` emits the minimum number of bytes, so a small node id
/// would land in the low bytes of a zeroed array if it were copied to the
/// front. Padding on the left is what keeps it the same number.
///
/// The over-32-bytes branch is unreachable against today's fixture tree, since
/// every case's `node_id` tops out at the all-ones 32-byte maximum. Kept
/// anyway as the direct statement of what this parse cannot promise, the same
/// reason `kzg.rs` keeps its own arms for outcomes the current release never
/// exercises.
fn node_id_bytes(decimal: &str) -> Result<[u8; 32], String> {
    let value = BigUint::parse_bytes(decimal.trim().as_bytes(), 10)
        .ok_or_else(|| format!("node_id {decimal} is not a decimal integer"))?;
    let bytes = value.to_bytes_be();
    if bytes.len() > 32 {
        return Err(format!("node_id {decimal} does not fit in 32 bytes"));
    }
    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(padded)
}

/// Compares a computed custody index list against the fixture's, the way
/// `shuffling.rs` compares a shuffle: a length mismatch is its own error,
/// otherwise the first differing position is reported alone. `get_custody_groups`
/// cases run up to `NUMBER_OF_CUSTODY_GROUPS` entries long, and printing both
/// full vectors on a mismatch would bury the one index that actually diverged.
fn expect_indices_eq(actual: &[u64], expected: &[u64]) -> Result<(), String> {
    if actual.len() != expected.len() {
        return Err(format!(
            "produced {} entries, fixture expects {}",
            actual.len(),
            expected.len()
        ));
    }
    for (index, (computed, wanted)) in actual.iter().zip(expected).enumerate() {
        if computed != wanted {
            return Err(format!("index {index}: got {computed}, expected {wanted}"));
        }
    }
    Ok(())
}

fn check_get_custody_groups(case: &Case) -> Result<(), String> {
    let meta: CustodyGroupsMeta = case.yaml("meta");
    let node_id = node_id_bytes(&meta.node_id)?;
    let computed =
        get_custody_groups(node_id, meta.custody_group_count).map_err(|err| format!("{err}"))?;
    expect_indices_eq(&computed, &meta.result)
}

fn check_compute_columns_for_custody_group(case: &Case) -> Result<(), String> {
    let meta: ColumnsMeta = case.yaml("meta");
    let computed =
        compute_columns_for_custody_group(meta.custody_group).map_err(|err| format!("{err}"))?;
    expect_indices_eq(&computed, &meta.result)
}

/// Dispatches one case to the check function its handler names.
///
/// The `other` arm is what makes a fixture release adding a third handler
/// under `networking/` visible: without it, an unrecognized handler would
/// simply contribute no trials, and neither `discovery_trial` counts by
/// handler name, so a silently-skipped handler would report nothing wrong.
/// Mirrors `kzg.rs`'s own dispatch for the same reason.
fn run(handler: &str, case: &Case) -> Result<(), String> {
    match handler {
        "get_custody_groups" => check_get_custody_groups(case),
        "compute_columns_for_custody_group" => check_compute_columns_for_custody_group(case),
        other => Err(format!("unhandled networking handler `{other}`")),
    }
}

pub fn trials() -> Vec<Trial> {
    let cases = collect_all_handlers(PRESET, "networking");

    let groups_count = cases
        .iter()
        .filter(|(handler, _)| handler == "get_custody_groups")
        .count();
    let columns_count = cases
        .iter()
        .filter(|(handler, _)| handler == "compute_columns_for_custody_group")
        .count();

    let mut trials = vec![
        super::discovery_trial("networking/get_custody_groups", groups_count),
        super::discovery_trial(
            "networking/compute_columns_for_custody_group",
            columns_count,
        ),
    ];

    for (handler, case) in cases {
        trials.push(super::case_trial("networking", case, move |case| {
            run(&handler, case)
        }));
    }

    trials
}
