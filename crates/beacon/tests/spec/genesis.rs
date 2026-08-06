//! The `genesis` runner.
//!
//! Two handlers, matching the specification's own split of the topic.
//! `initialization` replays Eth1 deposit history through
//! `initialize_beacon_state_from_eth1` and checks the resulting candidate
//! state against a fixture-provided expected state. `validity` feeds a
//! ready-made candidate state straight to `is_valid_genesis_state` and checks
//! the boolean it returns.
//!
//! This release's fixtures ship `genesis` cases for the `minimal` preset only
//! (there is no `genesis` directory anywhere under `mainnet` in the extracted
//! tree), so this whole runner is gated on the `preset-minimal` feature. That
//! keeps the mainnet build from failing [`Report::finish`]'s "matched no
//! fixture cases" check over a suite the release never populates for it,
//! without having to teach the shared harness a new kind of "expected empty"
//! outcome for one runner.
#![cfg(feature = "preset-minimal")]

use ethlambda_beacon::config::Config;
use ethlambda_beacon::containers::{BeaconState, phase0, shared};
use ethlambda_beacon::genesis::{initialize_beacon_state_from_eth1, is_valid_genesis_state};
use ethlambda_beacon::primitives::{HashTreeRoot as _, Root};
use libssz::SszDecode as _;

use super::{Case, PRESET, Report, collect};

#[derive(serde::Deserialize)]
struct Eth1 {
    eth1_block_hash: String,
    eth1_timestamp: u64,
}

#[derive(serde::Deserialize)]
struct Meta {
    deposits_count: usize,
}

fn parse_root(hex_root: &str) -> Root {
    let stripped = hex_root.strip_prefix("0x").unwrap_or(hex_root);
    let bytes = hex::decode(stripped).expect("the fixture holds a hex-encoded 32-byte root");
    Root::from_slice(&bytes)
}

/// Replays one `initialization` case and compares the resulting candidate's
/// root against the fixture's expected state.
///
/// Compared by `hash_tree_root` rather than by full structural equality,
/// matching how `ssz_static` checks a container: the root is the
/// specification's own notion of "the same state", and is far more readable
/// on failure than a field-by-field dump of two multi-thousand-validator
/// states would be.
fn initialization_case(case: &Case, config: &Config) -> Result<(), String> {
    let eth1: Eth1 = case.yaml("eth1");
    let meta: Meta = case.yaml("meta");

    let eth1_block_hash = parse_root(&eth1.eth1_block_hash);
    let deposits: Vec<shared::Deposit> = (0..meta.deposits_count)
        .map(|index| case.ssz::<shared::Deposit>(&format!("deposits_{index}")))
        .collect();

    let expected = phase0::BeaconState::from_ssz_bytes(&case.ssz_bytes("state"))
        .map_err(|err| format!("decoding the fixture's expected state: {err:?}"))?;

    let actual =
        initialize_beacon_state_from_eth1(eth1_block_hash, eth1.eth1_timestamp, &deposits, config)
            .map_err(|err| format!("initialize_beacon_state_from_eth1: {err}"))?;

    let expected_root = expected.hash_tree_root();
    let actual_root = actual.hash_tree_root();
    if actual_root != expected_root {
        return Err(format!(
            "hash_tree_root 0x{} != expected 0x{}",
            hex::encode(actual_root.0),
            hex::encode(expected_root.0),
        ));
    }

    Ok(())
}

/// Runs one `validity` case: decode the candidate state the fixture ships and
/// check `is_valid_genesis_state` against the fixture's expected boolean.
fn validity_case(case: &Case, config: &Config) -> Result<(), String> {
    let state = phase0::BeaconState::from_ssz_bytes(&case.ssz_bytes("genesis"))
        .map_err(|err| format!("decoding the candidate state: {err:?}"))?;
    let expected: bool = case.yaml("is_valid");

    let actual = is_valid_genesis_state(&BeaconState::Phase0(state), config);
    if actual != expected {
        return Err(format!(
            "is_valid_genesis_state returned {actual}, expected {expected}"
        ));
    }

    Ok(())
}

#[test]
fn initialization() {
    let config = Config::minimal();
    let mut report = Report::new();

    for case in collect(PRESET, "genesis", "initialization") {
        // Only phase0 has a genesis-construction fixture suite in this
        // release; a later fork adding one would need its own state type
        // here rather than silently being decoded as phase0's.
        if case.fork != ethlambda_beacon::ForkName::Phase0 {
            continue;
        }
        report.record(&case, initialization_case(&case, &config));
    }

    report.finish("genesis/initialization");
}

#[test]
fn validity() {
    let config = Config::minimal();
    let mut report = Report::new();

    for case in collect(PRESET, "genesis", "validity") {
        if case.fork != ethlambda_beacon::ForkName::Phase0 {
            continue;
        }
        report.record(&case, validity_case(&case, &config));
    }

    report.finish("genesis/validity");
}
