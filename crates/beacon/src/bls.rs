//! The specification's `bls` module: `bls.Verify`, `bls.Aggregate`, and friends.
//!
//! The state transition never touches `blst` directly; it calls the functions
//! here, named exactly as the spec names them (`specs/phase0/beacon-chain.md`'s
//! "BLS signatures" section, extended by `specs/altair/bls.md`), so a reader can
//! match a call site against the spec line by line. `blst` is the only backend:
//! there is no trait to abstract over another one, since the consensus layer has
//! settled on `blst` as the reference implementation and a second backend would
//! only be dead code here.
//!
//! # Why every function treats its inputs as unvalidated
//!
//! [`crate::primitives::BlsPubkey`] is deliberately *not* validated on
//! construction: deposit processing has to be able to hold a public key that
//! never validates, because a deposit with a bad key is still a real message
//! that changes the state (it is simply never able to sign anything). Nothing
//! upstream of this module guarantees a `BlsPubkey` or `BlsSignature` is a valid,
//! subgroup-correct curve point, so every function below re-derives that from
//! the raw bytes on every call rather than assuming it. That costs an extra
//! point check per input compared to a backend that validates once at
//! deserialization time and trusts a typed wrapper afterward (the approach
//! Lighthouse's `blst` backend takes, and the approach `blst`'s own
//! `fast_aggregate_verify` helper assumes when it hardcodes its public-key
//! validation flag to skip the check). Here, skipping it would mean a garbage
//! or adversarial byte string could reach a pairing check unchecked.
//!
//! # `bool` versus `Result`
//!
//! The verification functions ([`verify`], [`aggregate_verify`],
//! [`fast_aggregate_verify`], [`eth_fast_aggregate_verify`], [`key_validate`])
//! return `bool`, matching the spec's own signatures (`bls.Verify(...) -> bool`
//! and so on): they are predicates, and a `false` covers every way a claim can
//! fail to hold, whether the signature does not match, the public key does not
//! decode, or a point is not subgroup-correct. The specification does not
//! distinguish "the key was gibberish" from "the key was valid but the
//! signature was wrong": both mean the check did not pass, so collapsing them
//! into one boolean is what lets a caller use the result directly as a gate
//! (`if !bls::verify(...) { return }`) instead of first deciding which `Err`
//! variants count as "reject" and which count as a bug worth propagating.
//!
//! The aggregation functions ([`aggregate`], [`eth_aggregate_pubkeys`]) return
//! [`crate::Result`] instead, because there is no boolean predicate to collapse
//! to: aggregation either produces a point or it structurally cannot (an empty
//! input, or an element that is not itself a valid point), and that is a
//! different kind of failure than "verification did not pass". Keeping it a
//! `Result` keeps that distinction visible at the call site instead of forcing
//! an aggregation failure to masquerade as a rejected signature.

use blst::BLST_ERROR;
use blst::min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, Signature};

use crate::error::Error;
use crate::primitives::{BLS_SIGNATURE_SIZE, BlsPubkey, BlsSignature, Root};

/// The ciphersuite the specification pins BLS signatures to: the IETF BLS
/// draft's proof-of-possession scheme over BLS12-381's G2, using SHA-256 in
/// the XMD hash-to-curve construction.
///
/// This is the domain separation tag threaded through every hash-to-curve call
/// in this module. Two signatures produced under different DSTs never verify
/// against each other, which is exactly the point: it is what lets the same
/// keys be reused for other purposes (or other chains) without cross-protocol
/// signature reuse.
const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Builds `specs/altair/bls.md`'s `G2_POINT_AT_INFINITY` constant: the
/// compressed encoding of the identity element of G2, which is the
/// specification's sentinel value for "no one signed anything".
///
/// A `const fn` rather than a byte literal so the encoding rule (the
/// compression flag and infinity flag bits set, every other bit zero) reads as
/// what it is instead of as a string of hex digits to take on faith.
const fn g2_point_at_infinity() -> [u8; BLS_SIGNATURE_SIZE] {
    let mut bytes = [0u8; BLS_SIGNATURE_SIZE];
    // The top two bits of the first byte are the compression flag and the
    // infinity flag; setting both and leaving every other bit zero is exactly
    // the encoding of the point at infinity, compressed.
    bytes[0] = 0b1100_0000;
    bytes
}

/// `specs/altair/bls.md`'s `G2_POINT_AT_INFINITY`, the compressed encoding of
/// the identity element of G2.
const G2_POINT_AT_INFINITY: [u8; BLS_SIGNATURE_SIZE] = g2_point_at_infinity();

/// The specification's `bls.Verify(pubkey, message, signature) -> bool`.
///
/// Deserializes and fully validates both inputs (subgroup membership for the
/// signature, subgroup membership and non-identity for the public key) before
/// checking the pairing equation, so a `pubkey` that never passed
/// [`key_validate`] and never will (see the module documentation) simply fails
/// here rather than panicking or returning an error: an unparseable or
/// invalid-point key is treated exactly like a valid key over the wrong
/// signature, since the specification never distinguishes the two.
pub fn verify(pubkey: &BlsPubkey, message: Root, signature: &BlsSignature) -> bool {
    let Ok(pubkey) = PublicKey::key_validate(pubkey.as_ref()) else {
        return false;
    };
    let Ok(signature) = Signature::sig_validate(signature.as_ref(), false) else {
        return false;
    };
    let result = signature.verify(false, message.as_bytes(), DST, &[], &pubkey, false);
    result == BLST_ERROR::BLST_SUCCESS
}

/// The specification's `bls.Aggregate(signatures) -> BLSSignature`.
///
/// Fails on an empty `signatures`, matching the spec's `Aggregate` (there is no
/// meaningful signature aggregating zero signatures), and fails if any element
/// does not deserialize to a subgroup-correct point in G2. Checking every
/// element here, rather than only the final sum, matters because elliptic
/// curve addition of two points outside the prime-order subgroup can still
/// land back inside it: an invalid share could otherwise cancel against
/// another invalid share and slip past a check performed only on the result.
pub fn aggregate(signatures: &[BlsSignature]) -> crate::Result<BlsSignature> {
    crate::verify(!signatures.is_empty(), "len(signatures) > 0")?;
    let encoded: Vec<&[u8]> = signatures
        .iter()
        .map(|signature| signature.as_ref())
        .collect();
    let aggregated = AggregateSignature::aggregate_serialized(&encoded, true)
        .map_err(|_| Error::InvalidSignature("aggregate: not a valid, subgroup-correct point"))?;
    Ok(BlsSignature(aggregated.to_signature().to_bytes()))
}

/// The specification's
/// `bls.AggregateVerify(pubkeys, messages, signature) -> bool`.
///
/// `pubkeys` and `messages` are matched up positionally, one message per
/// signer; an empty `pubkeys`, or a length mismatch between the two, fails
/// immediately rather than vacuously succeeding. As with [`verify`], every
/// public key and the signature are independently deserialized and validated
/// (subgroup membership, non-identity for the keys) before the pairing check
/// runs, so an invalid key or signature simply fails this predicate.
pub fn aggregate_verify(
    pubkeys: &[BlsPubkey],
    messages: &[Root],
    signature: &BlsSignature,
) -> bool {
    if pubkeys.is_empty() || pubkeys.len() != messages.len() {
        return false;
    }
    let Ok(signature) = Signature::sig_validate(signature.as_ref(), false) else {
        return false;
    };
    let mut points = Vec::with_capacity(pubkeys.len());
    for pubkey in pubkeys {
        match PublicKey::key_validate(pubkey.as_ref()) {
            Ok(point) => points.push(point),
            Err(_) => return false,
        }
    }
    let point_refs: Vec<&PublicKey> = points.iter().collect();
    let message_refs: Vec<&[u8]> = messages.iter().map(Root::as_bytes).collect();
    let result = signature.aggregate_verify(false, &message_refs, DST, &point_refs, false);
    result == BLST_ERROR::BLST_SUCCESS
}

/// The specification's
/// `bls.FastAggregateVerify(pubkeys, message, signature) -> bool`.
///
/// The same check as [`aggregate_verify`] specialized to one shared `message`,
/// which is the shape every attestation aggregate takes. An empty `pubkeys`
/// always fails here: this function has no notion of "no one signed, and that
/// is fine", unlike its eth2-specific wrapper [`eth_fast_aggregate_verify`],
/// which is exactly why that wrapper exists.
pub fn fast_aggregate_verify(
    pubkeys: &[BlsPubkey],
    message: Root,
    signature: &BlsSignature,
) -> bool {
    if pubkeys.is_empty() {
        return false;
    }
    let Ok(signature) = Signature::sig_validate(signature.as_ref(), false) else {
        return false;
    };
    let mut points = Vec::with_capacity(pubkeys.len());
    for pubkey in pubkeys {
        match PublicKey::key_validate(pubkey.as_ref()) {
            Ok(point) => points.push(point),
            Err(_) => return false,
        }
    }
    let point_refs: Vec<&PublicKey> = points.iter().collect();
    let result = signature.fast_aggregate_verify(false, message.as_bytes(), DST, &point_refs);
    result == BLST_ERROR::BLST_SUCCESS
}

/// `specs/altair/bls.md`'s `eth_aggregate_pubkeys(pubkeys) -> BLSPubkey`.
///
/// Follows the spec's own pseudocode: `assert len(pubkeys) > 0`, then
/// `assert all(bls.KeyValidate(pubkey) for pubkey in pubkeys)` before summing.
/// The `KeyValidate` step is not optional the way it might look from the name:
/// without it, an all-zero or otherwise invalid `pubkey` would silently
/// contribute nothing (or something unintended) to the sum instead of failing
/// the aggregation outright, which is why this returns [`crate::Result`] rather
/// than substituting a default.
pub fn eth_aggregate_pubkeys(pubkeys: &[BlsPubkey]) -> crate::Result<BlsPubkey> {
    crate::verify(!pubkeys.is_empty(), "len(pubkeys) > 0")?;
    let encoded: Vec<&[u8]> = pubkeys.iter().map(|pubkey| pubkey.as_ref()).collect();
    let aggregated = AggregatePublicKey::aggregate_serialized(&encoded, true)
        .map_err(|_| Error::SpecAssert("all(bls.KeyValidate(pubkey) for pubkey in pubkeys)"))?;
    Ok(BlsPubkey(aggregated.to_public_key().to_bytes()))
}

/// `specs/altair/bls.md`'s
/// `eth_fast_aggregate_verify(pubkeys, message, signature) -> bool`.
///
/// Identical to [`fast_aggregate_verify`] except for one case: an empty
/// `pubkeys` returns `true` exactly when `signature` is
/// [`G2_POINT_AT_INFINITY`], and `false` for every other signature in that
/// case. This carve-out exists because an
/// empty-committee attestation aggregate is a legitimate value on chain (no
/// validators were assigned, or none of them attested), and its signature is
/// the identity element by convention rather than "no signature was
/// provided"; [`fast_aggregate_verify`] itself has no such case, since the
/// underlying IETF ciphersuite it wraps was never given one.
pub fn eth_fast_aggregate_verify(
    pubkeys: &[BlsPubkey],
    message: Root,
    signature: &BlsSignature,
) -> bool {
    if pubkeys.is_empty() {
        return signature.as_ref() == G2_POINT_AT_INFINITY;
    }
    fast_aggregate_verify(pubkeys, message, signature)
}

/// The specification's `bls.KeyValidate(pubkey) -> bool`.
///
/// A `pubkey` passes when it deserializes to a point on the curve, that point
/// is in the correct prime-order subgroup, and it is not the identity element.
/// Exposed standalone because the spec calls `KeyValidate` directly in more
/// than one place (deposit processing, [`eth_aggregate_pubkeys`]'s own
/// assertion), not only as a step inside a signature check.
pub fn key_validate(pubkey: &BlsPubkey) -> bool {
    PublicKey::key_validate(pubkey.as_ref()).is_ok()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use serde::Deserialize;

    use super::*;

    /// The root the two BLS handlers this module tests live under.
    ///
    /// BLS test vectors are configuration-independent (they do not touch any
    /// preset constant), so they live under `general` rather than under a
    /// preset name; see `crates/beacon/tests/spec/mod.rs` for the layout the
    /// rest of the crate's spec tests share. This module keeps its own tiny,
    /// local copy of just enough of that layout to run these two suites,
    /// rather than depending on that harness.
    fn handler_root(handler: &str) -> PathBuf {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../consensus-spec-tests/tests/general/altair/bls")
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
        let bytes = hex::decode(digits)
            .unwrap_or_else(|err| panic!("{}: invalid hex: {err}", path.display()));
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
        let text =
            fs::read_to_string(path).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
        let case: EthFastAggregateVerifyCase = serde_yaml_ng::from_str(&text)
            .unwrap_or_else(|err| panic!("{}: {err}", path.display()));

        let pubkeys: Vec<BlsPubkey> = case
            .input
            .pubkeys
            .iter()
            .map(|hex| BlsPubkey(parse_hex(path, hex)))
            .collect();
        let message = crate::primitives::H256(parse_hex(path, &case.input.message));
        let signature = BlsSignature(parse_hex(path, &case.input.signature));
        (pubkeys, message, signature, case.output)
    }

    #[test]
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

    #[test]
    fn key_validate_rejects_the_all_zero_pubkey() {
        assert!(!key_validate(&BlsPubkey::default()));
    }
}
