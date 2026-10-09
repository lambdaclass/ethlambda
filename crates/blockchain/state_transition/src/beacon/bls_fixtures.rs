//! The BLS fixture vectors (`general/.../bls/eth_*`) for the wrapper that now
//! lives in `ethlambda_crypto::bls`. They stay in this crate because the
//! fixture tree and the `beacon-spec-tests` feature that gates them are here.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use ethlambda_types::beacon::primitives::{BlsPubkey, BlsSignature, Root};

use super::bls::{eth_aggregate_pubkeys, eth_fast_aggregate_verify, verify};

/// The root the two BLS handlers this module tests live under.
///
/// BLS test vectors are configuration-independent (they do not touch any
/// preset constant), so they live under `general` rather than under a
/// preset name; see `crates/blockchain/state_transition/tests/beacon_spec/mod.rs` for the layout the
/// rest of the crate's spec tests share. This module keeps its own tiny,
/// local copy of just enough of that layout to run these two suites,
/// rather than depending on that harness.
fn handler_root(handler: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../consensus-spec-tests/tests/general/altair/bls")
        .join(handler);
    assert!(
        root.is_dir(),
        "BLS spec fixtures are missing from {}; run `make consensus-spec-tests`",
        root.display()
    );
    root
}

/// Every case's `data.yaml` under a handler: one directory level for the
/// handler's suite (named `bls` in every release seen so far), one for the
/// case itself.
fn fixture_cases(handler: &str) -> Vec<PathBuf> {
    let mut cases = Vec::new();
    for suite in fs::read_dir(handler_root(handler)).unwrap() {
        let suite_path = suite.unwrap().path();
        if !suite_path.is_dir() {
            continue;
        }
        for case in fs::read_dir(&suite_path).unwrap() {
            let case_path = case.unwrap().path();
            let data = case_path.join("data.yaml");
            if data.is_file() {
                cases.push(data);
            }
        }
    }
    cases
}

/// Decodes a `0x`-prefixed hex string into a fixed-size array, panicking
/// with the offending file's path on any mismatch. A malformed fixture is a
/// bug in the fixture release, not a condition the functions under test
/// need to handle, so this does not return a `Result`.
fn parse_hex<const N: usize>(path: &Path, value: &str) -> [u8; N] {
    let digits = value.strip_prefix("0x").unwrap_or(value);
    let bytes =
        hex::decode(digits).unwrap_or_else(|err| panic!("{}: invalid hex: {err}", path.display()));
    bytes.try_into().unwrap_or_else(|bytes: Vec<u8>| {
        panic!(
            "{}: expected {N} bytes, got {}",
            path.display(),
            bytes.len()
        )
    })
}

#[derive(Deserialize)]
struct EthAggregatePubkeysCase {
    input: Vec<String>,
    output: Option<String>,
}

#[test]
#[cfg_attr(
    not(feature = "beacon-spec-tests"),
    ignore = "needs the consensus-spec fixture tree; run `make consensus-spec-tests`"
)]
fn eth_aggregate_pubkeys_matches_spec_fixtures() {
    let mut executed = 0;
    for path in fixture_cases("eth_aggregate_pubkeys") {
        let text =
            fs::read_to_string(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
        let case: EthAggregatePubkeysCase = serde_yaml_ng::from_str(&text)
            .unwrap_or_else(|err| panic!("{}: {err}", path.display()));

        let pubkeys: Vec<BlsPubkey> = case
            .input
            .iter()
            .map(|hex| BlsPubkey(parse_hex(&path, hex)))
            .collect();
        let result = eth_aggregate_pubkeys(&pubkeys);

        match case.output {
            Some(expected_hex) => {
                let expected = BlsPubkey(parse_hex(&path, &expected_hex));
                let actual = result
                    .unwrap_or_else(|err| panic!("{}: expected Ok, got {err}", path.display()));
                assert_eq!(actual.0, expected.0, "{}", path.display());
            }
            None => {
                assert!(
                    result.is_err(),
                    "{}: expected an error, got {result:?}",
                    path.display()
                );
            }
        }
        executed += 1;
    }
    println!("eth_aggregate_pubkeys: {executed} cases executed");
    assert!(executed > 0, "no eth_aggregate_pubkeys cases were executed");
}

#[derive(Deserialize)]
struct EthFastAggregateVerifyInput {
    pubkeys: Vec<String>,
    message: String,
    signature: String,
}

#[derive(Deserialize)]
struct EthFastAggregateVerifyCase {
    input: EthFastAggregateVerifyInput,
    output: bool,
}

/// Parses one `eth_fast_aggregate_verify` case's `data.yaml` into the
/// crate's own BLS types.
fn parse_fast_aggregate_verify_case(path: &Path) -> (Vec<BlsPubkey>, Root, BlsSignature, bool) {
    let text = fs::read_to_string(path).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
    let case: EthFastAggregateVerifyCase =
        serde_yaml_ng::from_str(&text).unwrap_or_else(|err| panic!("{}: {err}", path.display()));

    let pubkeys: Vec<BlsPubkey> = case
        .input
        .pubkeys
        .iter()
        .map(|hex| BlsPubkey(parse_hex(path, hex)))
        .collect();
    let message = ethlambda_types::beacon::primitives::H256(parse_hex(path, &case.input.message));
    let signature = BlsSignature(parse_hex(path, &case.input.signature));
    (pubkeys, message, signature, case.output)
}

#[test]
#[cfg_attr(
    not(feature = "beacon-spec-tests"),
    ignore = "needs the consensus-spec fixture tree; run `make consensus-spec-tests`"
)]
fn eth_fast_aggregate_verify_matches_spec_fixtures() {
    let mut executed = 0;
    for path in fixture_cases("eth_fast_aggregate_verify") {
        let (pubkeys, message, signature, expected) = parse_fast_aggregate_verify_case(&path);
        let actual = eth_fast_aggregate_verify(&pubkeys, message, &signature);
        assert_eq!(actual, expected, "{}", path.display());
        executed += 1;
    }
    println!("eth_fast_aggregate_verify: {executed} cases executed");
    assert!(
        executed > 0,
        "no eth_fast_aggregate_verify cases were executed"
    );
}

#[test]
#[cfg_attr(
    not(feature = "beacon-spec-tests"),
    ignore = "needs the consensus-spec fixture tree; run `make consensus-spec-tests`"
)]
fn verify_accepts_a_known_good_vector_from_the_fixtures() {
    // `eth_fast_aggregate_verify_valid_0` has exactly one signer. A
    // FastAggregateVerify over a single signer is mathematically the same
    // check as a plain Verify, so this fixture vector doubles as a
    // known-good input for `verify` without this module needing its own
    // signing function to produce one.
    let path = handler_root("eth_fast_aggregate_verify")
        .join("bls")
        .join("eth_fast_aggregate_verify_valid_0")
        .join("data.yaml");
    let (pubkeys, message, signature, expected) = parse_fast_aggregate_verify_case(&path);
    assert_eq!(pubkeys.len(), 1, "fixture assumption: a single signer");
    assert!(expected, "fixture assumption: a valid signature");

    assert!(verify(&pubkeys[0], message, &signature));
}
