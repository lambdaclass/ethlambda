//! The `bls` runner.
//!
//! Covers the two BLS handlers the release ships: `eth_aggregate_pubkeys`
//! (summing a list of public keys into one) and `eth_fast_aggregate_verify`
//! (verifying an aggregate signature against a shared message, with the eth2
//! empty-committee carve-out). Both live in `crates/beacon/src/bls.rs`; see
//! that module's own doc for why they return the shapes they do
//! (`crate::Result` for aggregation, plain `bool` for verification).
//!
//! # Why `general`, not a preset
//!
//! Every other runner in this harness picks its fixture tree by [`super::PRESET`],
//! because the functions it exercises read a preset constant somewhere in their
//! call graph (committee sizes, epoch lengths, and so on). Neither BLS handler
//! does: aggregating public keys and checking a pairing equation are BLS12-381
//! operations with no notion of a validator count or a slots-per-epoch. The
//! release ships exactly one copy of these fixtures, under `general`, rather
//! than one per preset, which is what `general` signals across this whole
//! fixture tree (see `crates/beacon/tests/spec/mod.rs`'s module doc): a suite
//! that does not vary with the compiled-in preset.
//!
//! # What `output: null` means
//!
//! `eth_aggregate_pubkeys` can fail: the specification asserts `len(pubkeys) > 0`
//! and that every key passes `KeyValidate` before summing, and a fixture case
//! whose `output` is `null` is exactly one of those assertions firing (an empty
//! list, the all-zero encoding, a malformed compression flag, or the point at
//! infinity, which fails `KeyValidate`'s non-identity check). That is the same
//! contract [`super::check_transition`] enforces for a case with no `post`
//! state: absence of the success value is the expectation, not a gap in the
//! fixture, so a run that returns `Ok` for such a case is exactly as wrong as
//! one that returns the wrong pubkey. `eth_fast_aggregate_verify` has no such
//! case: it returns a plain `bool` because the specification gives it no failure
//! mode distinct from "the check did not pass", so every fixture under that
//! handler ships a `true` or `false`, never a `null`.

use ethlambda_beacon::bls;
use ethlambda_beacon::primitives::{BLS_PUBKEY_SIZE, BlsPubkey, BlsSignature, Root};
use libtest_mimic::Trial;

/// `eth_aggregate_pubkeys/<suite>/<case>/data.yaml`'s shape: a list of hex
/// pubkeys in, one hex pubkey out, or `null` when the input must be rejected.
#[derive(serde::Deserialize)]
struct AggregatePubkeysCase {
    input: Vec<String>,
    output: Option<String>,
}

/// `eth_fast_aggregate_verify/<suite>/<case>/data.yaml`'s `input` key: the
/// pubkeys and message the signature is checked against.
#[derive(serde::Deserialize)]
struct FastAggregateVerifyInput {
    pubkeys: Vec<String>,
    message: String,
    signature: String,
}

/// `eth_fast_aggregate_verify/<suite>/<case>/data.yaml`'s shape. `output` is
/// always a plain bool; see the module doc for why this handler has no `null`
/// case the way `eth_aggregate_pubkeys` does.
#[derive(serde::Deserialize)]
struct FastAggregateVerifyCase {
    input: FastAggregateVerifyInput,
    output: bool,
}

/// Decodes a `0x`-prefixed hex string into raw bytes.
fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    let digits = value.strip_prefix("0x").unwrap_or(value);
    hex::decode(digits).map_err(|err| format!("invalid hex `{value}`: {err}"))
}

/// Decodes a `0x`-prefixed hex string into an exact-size byte array.
///
/// Every fixed-length value these fixtures carry (pubkeys, signatures) has a
/// named size in [`ethlambda_beacon::primitives`], so a mismatch is a fixture
/// bug worth reporting through the case's own failure message rather than
/// panicking the whole run on it.
fn parse_hex<const N: usize>(value: &str) -> Result<[u8; N], String> {
    decode_hex(value)?
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("expected {N} bytes, got {} in `{value}`", bytes.len()))
}

/// Runs one `eth_aggregate_pubkeys` case.
fn eth_aggregate_pubkeys_case(case: &super::Case) -> Result<(), String> {
    let fixture: AggregatePubkeysCase = case.yaml("data");

    let mut pubkeys = Vec::with_capacity(fixture.input.len());
    for hex in &fixture.input {
        pubkeys.push(BlsPubkey(parse_hex(hex)?));
    }

    let result = bls::eth_aggregate_pubkeys(&pubkeys);

    match fixture.output {
        // A hex pubkey: aggregation must succeed and land exactly on it.
        Some(expected_hex) => {
            let expected: [u8; BLS_PUBKEY_SIZE] = parse_hex(&expected_hex)?;
            let actual = result.map_err(|err| format!("expected Ok(pubkey), got Err({err})"))?;
            if actual.0 != expected {
                return Err(format!(
                    "aggregated to 0x{}, expected 0x{}",
                    hex::encode(actual.0),
                    hex::encode(expected)
                ));
            }
            Ok(())
        }
        // `output: null`: one of the spec's own assertions must have rejected
        // this input (see the module doc). Accepting it here would mean the
        // implementation is looser than the spec, not that the fixture allows
        // it either way.
        None => {
            if result.is_ok() {
                return Err(
                    "accepted, but the fixture's output is null, so it must be rejected"
                        .to_string(),
                );
            }
            Ok(())
        }
    }
}

/// Runs one `eth_fast_aggregate_verify` case.
fn eth_fast_aggregate_verify_case(case: &super::Case) -> Result<(), String> {
    let fixture: FastAggregateVerifyCase = case.yaml("data");

    let mut pubkeys = Vec::with_capacity(fixture.input.pubkeys.len());
    for hex in &fixture.input.pubkeys {
        pubkeys.push(BlsPubkey(parse_hex(hex)?));
    }
    // `Root` (an alias of `H256`) has no fixed-size-array constructor of its
    // own to call through the alias, so this goes through `from_slice`
    // instead, matching how the rest of this harness turns a hex root into
    // one (see `shuffling.rs`).
    let message = Root::from_slice(&decode_hex(&fixture.input.message)?);
    let signature = BlsSignature(parse_hex(&fixture.input.signature)?);

    let actual = bls::eth_fast_aggregate_verify(&pubkeys, message, &signature);
    if actual != fixture.output {
        return Err(format!(
            "eth_fast_aggregate_verify returned {actual}, expected {}",
            fixture.output
        ));
    }
    Ok(())
}

/// This suite is not gated here: [`super::case_trial`] applies
/// [`super::Case::in_scope`]'s gate itself, and every case this handler
/// collects lands under altair, which is always in scope, so nothing here
/// needs to check the fork.
pub fn trials() -> Vec<Trial> {
    let cases = super::collect_all_handlers("general", "bls");
    let mut trials = vec![super::discovery_trial("bls", cases.len())];

    for (handler, case) in cases {
        trials.push(super::case_trial("bls", case, move |case| {
            match handler.as_str() {
                "eth_aggregate_pubkeys" => eth_aggregate_pubkeys_case(case),
                "eth_fast_aggregate_verify" => eth_fast_aggregate_verify_case(case),
                // A release that adds a handler must fail loudly here rather
                // than silently matching zero cases, the same rule
                // `epoch_processing`'s own dispatch follows.
                other => Err(format!("unhandled bls handler `{other}`")),
            }
        }));
    }

    trials
}
