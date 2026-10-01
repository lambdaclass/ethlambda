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
//! [`crate::beacon::primitives::BlsPubkey`] is deliberately *not* validated on
//! construction: deposit processing has to be able to hold a public key that
//! never validates, because a deposit with a bad key is still a real message
//! that changes the state (it is simply never able to sign anything). Nothing
//! upstream of this module guarantees a `BlsPubkey` or `BlsSignature` is a valid,
//! subgroup-correct curve point, so every function below derives that from the
//! raw bytes rather than assuming it from the type. That costs an extra point
//! check per input compared to a backend that validates once at deserialization
//! time and trusts a typed wrapper afterward (the approach Lighthouse's `blst`
//! backend takes, and the approach `blst`'s own `fast_aggregate_verify` helper
//! assumes when it hardcodes its public-key validation flag to skip the check).
//! Here, skipping it would mean a garbage or adversarial byte string could reach
//! a pairing check unchecked.
//!
//! # Why public keys are validated once per byte string, not once per call
//!
//! For a public key, that check is also the expensive half of a signature
//! check: decompressing a G1 point and proving it is in the prime-order
//! subgroup costs far more per key than adding it into an aggregate, and an
//! attestation aggregate carries a whole committee of keys. Re-deriving every
//! key on every call made a mainnet aggregate's verification almost entirely
//! key validation, and because every active validator's key signs again each
//! epoch, almost all of it was repeated work.
//!
//! So [`PublicKey::key_validate`]'s answer is memoized, keyed by the exact
//! compressed bytes it was asked about (see [`PubkeyCache`]). That keeps the
//! guarantee above intact rather than trading it away: `key_validate` is a
//! pure function of those bytes, so a hit hands back precisely the point a
//! fresh call would have produced, and a byte string only ever enters the
//! cache by passing it. Keying by the bytes rather than by validator index is
//! what makes that true without further argument: an index names whatever key
//! the state at hand says it does, which two forks need not agree on, while a
//! byte string names one point everywhere. A key that fails is never cached,
//! so an invalid key costs a full check every time, exactly as before, and
//! cannot grow the cache.
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
//! [`crate::beacon::Result`] instead, because there is no boolean predicate to collapse
//! to: aggregation either produces a point or it structurally cannot (an empty
//! input, or an element that is not itself a valid point), and that is a
//! different kind of failure than "verification did not pass". Keeping it a
//! `Result` keeps that distinction visible at the call site instead of forcing
//! an aggregation failure to masquerade as a rejected signature.
//!
//! # Why a cache miss is validated in parallel, and a hit is not
//!
//! [`aggregate_verify`] and [`fast_aggregate_verify`] each resolve `pubkeys`
//! to points before the pairing check runs; a single Electra block can carry
//! up to `MAX_ATTESTATIONS_ELECTRA` aggregates, each covering up to a whole
//! committee, so a cold cache (the first blocks after a start) turns that into
//! thousands of independent point checks per block import. The beacon state
//! transition runs on one actor thread (see `BlockChain` in
//! `crates/blockchain/src/lib.rs`), so on a multi-core host every one of those
//! checks but the one currently running would leave a core idle. Validating one
//! key never reads or writes anything another key's validation touches, so
//! nothing depends on which order they run in or finish in: the misses go
//! through `par_iter().map(...).collect::<Option<Vec<_>>>()`, which spreads the
//! checks across rayon's global thread pool and still collapses to `None` the
//! moment any key fails, without skipping or weakening [`key_validate`] for a
//! single key. Each validated point is written back to its own index, which
//! `aggregate_verify` relies on to keep `points[i]` paired with `messages[i]`.
//!
//! A hit is a hash-map read, far cheaper than handing work to another thread,
//! so hits resolve on the calling thread. That matters beyond the saving
//! itself: gossip validation runs many signature checks at once on blocking
//! threads, and if every one of them queued its keys on rayon's single global
//! pool, a burst of aggregates would stall there even with the keys already
//! validated.

use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};

use blst::BLST_ERROR;
use blst::min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, Signature};
use rayon::prelude::*;

use crate::beacon::error::Error;
use crate::beacon::primitives::{
    BLS_PUBKEY_SIZE, BLS_SIGNATURE_SIZE, BlsPubkey, BlsSignature, Root,
};

/// The ciphersuite the specification pins BLS signatures to: the IETF BLS
/// draft's proof-of-possession scheme over BLS12-381's G2, using SHA-256 in
/// the XMD hash-to-curve construction.
///
/// This is the domain separation tag threaded through every hash-to-curve call
/// in this module. Two signatures produced under different DSTs never verify
/// against each other, which is exactly the point: it is what lets the same
/// keys be reused for other purposes (or other chains) without cross-protocol
/// signature reuse.
pub const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// The minimum number of public keys rayon may put in one sequential chunk
/// when [`aggregate_verify`] and [`fast_aggregate_verify`] validate the
/// signers [`PubkeyCache`] has not seen yet in parallel.
///
/// A devnet or a spec-fixture aggregate can be as small as a single signer,
/// and splitting a handful of keys across worker threads would spend more
/// time on task dispatch than [`PublicKey::key_validate`] itself takes to
/// decompress and subgroup-check one key. `with_min_len` keeps that decision
/// inside rayon's own splitting logic rather than a hand-rolled length check
/// before choosing serial or parallel: sixteen is comfortably above the
/// single-digit-signer inputs a fixture or a small devnet produces, so those
/// stay on the calling thread, while a mainnet aggregate of hundreds to
/// thousands of signers still splits into far more chunks than there are
/// cores to run them on.
const KEY_VALIDATE_MIN_PAR_LEN: usize = 16;

/// How many shards [`PubkeyCache`] splits its map across.
///
/// Every signature check reads the cache once per signer, from whichever
/// thread runs it: the chain actor, rayon's workers, and every blocking thread
/// gossip validation has running at once. One lock would put every one of
/// those reads on the same cache line; a shard per lock spreads them out.
const PUBKEY_CACHE_SHARDS: usize = 64;

/// The most validated public keys [`VALIDATED_PUBKEYS`] holds, across all of
/// its shards.
///
/// Far above any real validator registry: the bound is not there to evict
/// anything a registry needs, but so that inputs which are not a registry
/// (deposits carrying arbitrary keys, or a test run over thousands of
/// generated ones) cannot grow the cache without limit. A key arriving past
/// the bound is still validated, just on every call, as it was before the
/// cache existed.
const MAX_CACHED_PUBKEYS: usize = 1 << 22;

/// Every public key that has passed [`PublicKey::key_validate`], by its
/// compressed bytes, for the whole process.
///
/// Process-wide rather than owned by a `Store`, because nothing about the
/// answer is per chain or per state: it is a pure function of the bytes (see
/// the module documentation), so one copy serves the state transition, fork
/// choice and gossip validation alike. Lean code never calls into this module,
/// so a lean run never allocates it.
static VALIDATED_PUBKEYS: LazyLock<PubkeyCache> =
    LazyLock::new(|| PubkeyCache::new(MAX_CACHED_PUBKEYS));

/// Validated, decompressed public keys, keyed by their compressed encoding.
///
/// A bounded, append-only memo of [`PublicKey::key_validate`]: an entry is
/// only ever added for a key that passed, never changed, and never removed,
/// since its answer can never change. See the module documentation for why
/// that is sound.
struct PubkeyCache {
    shards: [RwLock<HashMap<BlsPubkey, PublicKey>>; PUBKEY_CACHE_SHARDS],
    /// The most entries one shard takes, so the whole cache stays within the
    /// capacity it was built with.
    shard_capacity: usize,
}

impl PubkeyCache {
    fn new(capacity: usize) -> Self {
        Self {
            shards: std::array::from_fn(|_| RwLock::new(HashMap::new())),
            shard_capacity: capacity.div_ceil(PUBKEY_CACHE_SHARDS),
        }
    }

    /// The shard `pubkey` lives in, chosen by the last byte of its encoding:
    /// the low byte of the point's x-coordinate, so it spreads keys evenly
    /// without hashing them twice. The flag bits sit in the first byte.
    fn shard(&self, pubkey: &BlsPubkey) -> &RwLock<HashMap<BlsPubkey, PublicKey>> {
        let byte = usize::from(pubkey.0[BLS_PUBKEY_SIZE - 1]);
        &self.shards[byte % PUBKEY_CACHE_SHARDS]
    }

    /// The validated point for `pubkey`, if it has passed before.
    fn get(&self, pubkey: &BlsPubkey) -> Option<PublicKey> {
        self.shard(pubkey).read().unwrap().get(pubkey).copied()
    }

    /// Records that `pubkey` validated to `point`, unless its shard is full.
    fn insert(&self, pubkey: BlsPubkey, point: PublicKey) {
        let mut shard = self.shard(&pubkey).write().unwrap();
        if shard.len() < self.shard_capacity && shard.insert(pubkey, point).is_none() {
            crate::metrics::inc_pubkey_cache_entries();
        }
    }

    /// The number of keys held, across every shard.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| shard.read().unwrap().len())
            .sum()
    }
}

/// `pubkey` as a validated point, or `None` if it is not a valid,
/// subgroup-correct, non-identity key: [`PublicKey::key_validate`], through
/// [`VALIDATED_PUBKEYS`].
fn validated_pubkey(pubkey: &BlsPubkey) -> Option<PublicKey> {
    if let Some(point) = VALIDATED_PUBKEYS.get(pubkey) {
        crate::metrics::inc_pubkey_cache_lookups(1, 0);
        return Some(point);
    }
    crate::metrics::inc_pubkey_cache_lookups(0, 1);
    let point = PublicKey::key_validate(pubkey.as_ref()).ok()?;
    VALIDATED_PUBKEYS.insert(*pubkey, point);
    Some(point)
}

/// Every key in `pubkeys` as a validated point, in order, or `None` if any
/// one of them fails to validate.
///
/// Hits resolve on the calling thread and only the misses go to rayon; see
/// the module documentation for why. Each miss that validates is added to
/// [`VALIDATED_PUBKEYS`] before returning.
fn validated_pubkeys(pubkeys: &[BlsPubkey]) -> Option<Vec<PublicKey>> {
    let mut points: Vec<Option<PublicKey>> = pubkeys
        .iter()
        .map(|pubkey| VALIDATED_PUBKEYS.get(pubkey))
        .collect();
    let misses: Vec<usize> = points
        .iter()
        .enumerate()
        .filter_map(|(index, point)| point.is_none().then_some(index))
        .collect();
    let hits = pubkeys.len() - misses.len();
    crate::metrics::inc_pubkey_cache_lookups(hits as u64, misses.len() as u64);

    if !misses.is_empty() {
        let fresh: Vec<PublicKey> = misses
            .par_iter()
            .with_min_len(KEY_VALIDATE_MIN_PAR_LEN)
            .map(|&index| PublicKey::key_validate(pubkeys[index].as_ref()).ok())
            .collect::<Option<_>>()?;
        for (&index, point) in misses.iter().zip(fresh) {
            VALIDATED_PUBKEYS.insert(pubkeys[index], point);
            points[index] = Some(point);
        }
    }
    points.into_iter().collect()
}

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
pub const G2_POINT_AT_INFINITY: [u8; BLS_SIGNATURE_SIZE] = g2_point_at_infinity();

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
    let Some(pubkey) = validated_pubkey(pubkey) else {
        return false;
    };
    let Ok(signature) = Signature::sig_validate(signature.as_ref(), false) else {
        return false;
    };
    let result = signature.verify(false, message.as_slice(), DST, &[], &pubkey, false);
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
pub fn aggregate(signatures: &[BlsSignature]) -> crate::beacon::Result<BlsSignature> {
    crate::beacon::verify(!signatures.is_empty(), "len(signatures) > 0")?;
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
/// runs, so an invalid key or signature simply fails this predicate. Keys go
/// through [`PubkeyCache`], and the ones it has not seen are validated in
/// parallel; see the module documentation for why both are safe and why
/// `points` still lines up with `messages` afterward.
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
    let Some(points) = validated_pubkeys(pubkeys) else {
        return false;
    };
    let point_refs: Vec<&PublicKey> = points.iter().collect();
    let message_refs: Vec<&[u8]> = messages.iter().map(Root::as_slice).collect();
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
/// which is exactly why that wrapper exists. This is the hot path for a real
/// Electra block's attestations, where a single aggregate can carry
/// thousands of signers behind one shared message; keys go through
/// [`PubkeyCache`], see the module documentation for why that is safe.
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
    let Some(points) = validated_pubkeys(pubkeys) else {
        return false;
    };
    let point_refs: Vec<&PublicKey> = points.iter().collect();
    let result = signature.fast_aggregate_verify(false, message.as_slice(), DST, &point_refs);
    result == BLST_ERROR::BLST_SUCCESS
}

/// `specs/altair/bls.md`'s `eth_aggregate_pubkeys(pubkeys) -> BLSPubkey`.
///
/// Follows the spec's own pseudocode: `assert len(pubkeys) > 0`, then
/// `assert all(bls.KeyValidate(pubkey) for pubkey in pubkeys)` before summing.
/// The `KeyValidate` step is not optional the way it might look from the name:
/// without it, an all-zero or otherwise invalid `pubkey` would silently
/// contribute nothing (or something unintended) to the sum instead of failing
/// the aggregation outright, which is why this returns [`crate::beacon::Result`] rather
/// than substituting a default.
pub fn eth_aggregate_pubkeys(pubkeys: &[BlsPubkey]) -> crate::beacon::Result<BlsPubkey> {
    crate::beacon::verify(!pubkeys.is_empty(), "len(pubkeys) > 0")?;
    let points = validated_pubkeys(pubkeys).ok_or(Error::SpecAssert(
        "all(bls.KeyValidate(pubkey) for pubkey in pubkeys)",
    ))?;
    let point_refs: Vec<&PublicKey> = points.iter().collect();
    // Every point above already passed `key_validate`, so the sum skips
    // re-checking them.
    let aggregated = AggregatePublicKey::aggregate(&point_refs, false)
        .map_err(|_| Error::SpecAssert("len(pubkeys) > 0"))?;
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
    validated_pubkey(pubkey).is_some()
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
    /// preset constant). Since v1.7.0-alpha.13 (consensus-specs #5398) they ship
    /// from `ethereum/cryptography-specs` rather than consensus-spec-tests, in a
    /// flat `tests/bls/<handler>/<case>/` layout with no suite level; see
    /// `crates/blockchain/state_transition/tests/beacon_spec/mod.rs` for the
    /// layout the rest of the crate's spec tests share. This module keeps its
    /// own tiny, local copy of just enough of that layout to run these two
    /// suites, rather than depending on that harness.
    fn handler_root(handler: &str) -> PathBuf {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../cryptography-specs/tests/bls")
            .join(handler);
        assert!(
            root.is_dir(),
            "BLS spec fixtures are missing from {}; run `make cryptography-specs`",
            root.display()
        );
        root
    }

    /// Every case's `data.yaml` under a handler.
    fn fixture_cases(handler: &str) -> Vec<PathBuf> {
        let mut cases = Vec::new();
        for case in fs::read_dir(handler_root(handler)).unwrap() {
            let case_path = case.unwrap().path();
            if !case_path.is_dir() {
                continue;
            }
            let data = case_path.join("data.yaml");
            if data.is_file() {
                cases.push(data);
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
    #[cfg_attr(
        not(feature = "beacon-spec-tests"),
        ignore = "needs the BLS test vectors; run `make cryptography-specs`"
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
        let message = crate::beacon::primitives::H256(parse_hex(path, &case.input.message));
        let signature = BlsSignature(parse_hex(path, &case.input.signature));
        (pubkeys, message, signature, case.output)
    }

    #[test]
    #[cfg_attr(
        not(feature = "beacon-spec-tests"),
        ignore = "needs the BLS test vectors; run `make cryptography-specs`"
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
        ignore = "needs the BLS test vectors; run `make cryptography-specs`"
    )]
    fn verify_accepts_a_known_good_vector_from_the_fixtures() {
        // `eth_fast_aggregate_verify_valid_0` has exactly one signer. A
        // FastAggregateVerify over a single signer is mathematically the same
        // check as a plain Verify, so this fixture vector doubles as a
        // known-good input for `verify` without this module needing its own
        // signing function to produce one.
        let path = handler_root("eth_fast_aggregate_verify")
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

    /// A fresh keypair's public key, distinct per `seed` and distinct from
    /// [`build_aggregate`]'s signers (whose seeds start at one).
    fn fresh_pubkey(seed: u64) -> BlsPubkey {
        let mut ikm = [0xa5u8; 32];
        ikm[..8].copy_from_slice(&seed.to_le_bytes());
        let secret = blst::min_pk::SecretKey::key_gen(&ikm, &[])
            .expect("32 bytes of input material is enough for key generation");
        BlsPubkey(secret.sk_to_pk().to_bytes())
    }

    /// The compressed encoding of G1's identity element: a well-formed point,
    /// so it decodes, but one `key_validate` must refuse.
    fn identity_pubkey() -> BlsPubkey {
        let mut bytes = [0u8; BLS_PUBKEY_SIZE];
        bytes[0] = 0b1100_0000;
        BlsPubkey(bytes)
    }

    /// Resolves `pubkey` straight through `blst`, with no cache involved.
    fn uncached(pubkey: &BlsPubkey) -> Option<[u8; BLS_PUBKEY_SIZE]> {
        PublicKey::key_validate(pubkey.as_ref())
            .ok()
            .map(|point| point.to_bytes())
    }

    #[test]
    fn a_warm_cache_verifies_exactly_as_a_cold_one() {
        let (pubkeys, message, signature) = build_aggregate(24);
        assert!(fast_aggregate_verify(&pubkeys, message, &signature));
        for pubkey in &pubkeys {
            let cached = VALIDATED_PUBKEYS.get(pubkey).map(|point| point.to_bytes());
            assert_eq!(
                cached,
                uncached(pubkey),
                "a cached point must be key_validate's own"
            );
        }

        // Every key is a hit now; the answers must not change with that.
        assert!(fast_aggregate_verify(&pubkeys, message, &signature));
        let other_message = crate::beacon::primitives::H256([8u8; 32]);
        assert!(!fast_aggregate_verify(&pubkeys, other_message, &signature));
        assert!(!fast_aggregate_verify(&pubkeys[1..], message, &signature));
    }

    #[test]
    fn an_invalid_key_is_never_cached_and_always_refused() {
        let (mut pubkeys, message, signature) = build_aggregate(2);
        for invalid in [BlsPubkey::default(), identity_pubkey()] {
            assert_eq!(
                uncached(&invalid),
                None,
                "fixture assumption: an invalid key"
            );
            pubkeys.push(invalid);
            for _ in 0..2 {
                assert!(!key_validate(&invalid));
                assert!(!verify(&invalid, message, &signature));
                assert!(!fast_aggregate_verify(&pubkeys, message, &signature));
                assert!(eth_aggregate_pubkeys(&pubkeys).is_err());
                assert!(VALIDATED_PUBKEYS.get(&invalid).is_none());
            }
            pubkeys.pop();
        }
    }

    #[test]
    fn mixed_hits_and_misses_keep_their_positions() {
        let warm = [fresh_pubkey(1), fresh_pubkey(2)];
        assert!(warm.iter().all(key_validate));
        // Misses between hits, in a run long enough to go through rayon.
        let mut pubkeys = vec![warm[0]];
        pubkeys.extend((10..10 + 2 * KEY_VALIDATE_MIN_PAR_LEN as u64).map(fresh_pubkey));
        pubkeys.push(warm[1]);

        let points = validated_pubkeys(&pubkeys).expect("every key above is valid");
        assert_eq!(points.len(), pubkeys.len());
        for (pubkey, point) in pubkeys.iter().zip(&points) {
            assert_eq!(Some(point.to_bytes()), uncached(pubkey));
        }
    }

    #[test]
    fn eth_aggregate_pubkeys_matches_blst_s_own_sum() {
        let pubkeys: Vec<BlsPubkey> = (20..25).map(fresh_pubkey).collect();
        let encoded: Vec<&[u8]> = pubkeys.iter().map(|pubkey| pubkey.as_ref()).collect();
        let expected = AggregatePublicKey::aggregate_serialized(&encoded, true)
            .expect("every key above is valid")
            .to_public_key()
            .to_bytes();
        // Once cold, once warm.
        for _ in 0..2 {
            assert_eq!(eth_aggregate_pubkeys(&pubkeys).unwrap().0, expected);
        }
    }

    #[test]
    fn the_cache_stops_growing_at_its_capacity() {
        // One entry per shard.
        let cache = PubkeyCache::new(PUBKEY_CACHE_SHARDS);
        let pubkeys: Vec<BlsPubkey> = (100..100 + 4 * PUBKEY_CACHE_SHARDS as u64)
            .map(fresh_pubkey)
            .collect();
        for pubkey in &pubkeys {
            let point = PublicKey::key_validate(pubkey.as_ref()).unwrap();
            cache.insert(*pubkey, point);
            // Inserting the same key again must not take a second slot.
            cache.insert(*pubkey, point);
        }
        assert!(cache.len() <= PUBKEY_CACHE_SHARDS);
        let held = pubkeys
            .iter()
            .filter(|pubkey| cache.get(pubkey).is_some())
            .count();
        assert_eq!(held, cache.len());
    }

    /// Builds a realistic attestation aggregate of `count` independent
    /// signers over one shared message: each signer gets its own
    /// `key_gen`-derived keypair and signs [`message`](Root) under this
    /// module's own [`DST`], the same DST [`fast_aggregate_verify`] checks
    /// against, and the resulting signatures are folded together with this
    /// module's own [`aggregate`], the same call a real caller makes to
    /// produce one. This mirrors the shape of an Electra attestation
    /// aggregate, where every attester signs identical attestation data.
    fn build_aggregate(count: usize) -> (Vec<BlsPubkey>, Root, BlsSignature) {
        let message = crate::beacon::primitives::H256([7u8; 32]);
        let mut pubkeys = Vec::with_capacity(count);
        let mut signatures = Vec::with_capacity(count);
        for index in 0..count {
            // `key_gen` requires at least 32 bytes of input key material;
            // seeding it with the signer's index keeps every key distinct
            // and the whole aggregate reproducible run to run.
            let mut ikm = [0u8; 32];
            ikm[..8].copy_from_slice(&(index as u64 + 1).to_le_bytes());
            let secret = blst::min_pk::SecretKey::key_gen(&ikm, &[])
                .expect("32 bytes of input material is enough for key generation");
            pubkeys.push(BlsPubkey(secret.sk_to_pk().to_bytes()));
            let signature = secret.sign(message.as_slice(), DST, &[]);
            signatures.push(BlsSignature(signature.to_bytes()));
        }
        let aggregated = aggregate(&signatures)
            .expect("every signature above comes from a fresh, valid keypair");
        (pubkeys, message, aggregated)
    }

    /// Wall-clock timing for [`fast_aggregate_verify`] at the scale a real
    /// Electra attestation aggregate reaches: hundreds to thousands of
    /// attesters behind one shared message. Prints, for each size, the time
    /// with every key a cache miss (validated in parallel) and then with every
    /// key a hit, so the two paths (or two machines) can be compared by hand;
    /// the `assert!`s also make this a correctness check, not only a
    /// stopwatch, since a bug that dropped or misaligned a key on either path
    /// would make the aggregate fail to verify.
    ///
    /// `#[ignore]`d for the same reason the crate's other slow crypto tests
    /// are: generating and signing thousands of real BLS keypairs, twice,
    /// dominates the run time and has no place in a default `cargo test`.
    #[test]
    #[ignore = "slow: generates and signs thousands of real BLS keypairs"]
    fn fast_aggregate_verify_key_validation_timing() {
        for count in [512usize, 2048] {
            let (pubkeys, message, signature) = build_aggregate(count);
            for pass in ["cold", "warm"] {
                let start = std::time::Instant::now();
                let result = fast_aggregate_verify(&pubkeys, message, &signature);
                let elapsed = start.elapsed();
                println!("fast_aggregate_verify, {count} signers, {pass} cache: {elapsed:?}");
                assert!(
                    result,
                    "a correctly-aggregated signature over {count} signers must verify ({pass})"
                );
            }
        }
    }
}
