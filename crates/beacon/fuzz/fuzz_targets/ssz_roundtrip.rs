//! Differentially fuzzes SSZ decoding and encoding alone, with no state
//! transition involved: decode a `BeaconState` with both implementations,
//! compare `hash_tree_root`, then re-encode with both and compare the bytes.
//!
//! This is the cheapest target here (no signature checks, no committee or
//! reward computation) and the one covering the most fundamental layer the
//! other two targets both build on, which is why it is the one most likely to
//! find something and worth running on its own; see `README.md`.
#![no_main]

use ethlambda_beacon::containers::BeaconState;
use libfuzzer_sys::fuzz_target;
// Only `Encode` is needed: lighthouse's `BeaconState::from_ssz_bytes(bytes,
// spec)` is a hand-written, spec-aware inherent method (it has to be, to pick
// the right fork's shape; see `ethlambda_beacon::containers::BeaconState::from_ssz`
// for the same reason), not the one-argument `ssz::Decode::from_ssz_bytes`
// trait method, so calling it needs no trait import at all.
use ssz::Encode as _;

fuzz_target!(|data: &[u8]| {
    let Some((fork, state_bytes)) = ethlambda_beacon_fuzz::split_one(data) else {
        return;
    };
    if !ethlambda_beacon_fuzz::is_implemented(fork) {
        return;
    }

    let our_decoded = BeaconState::from_ssz(fork, state_bytes);

    let lh_fork = ethlambda_beacon_fuzz::to_lighthouse_fork(fork);
    let lh_spec = ethlambda_beacon_fuzz::lighthouse_spec();
    let lh_decoded =
        types::BeaconState::<ethlambda_beacon_fuzz::LhSpec>::from_ssz_bytes(state_bytes, &lh_spec);

    // Unlike the other two targets, a decode disagreement here *is* the
    // finding, not something to discard: raw SSZ decoding has no signatures
    // to verify and no committees to build, so there is no other implemented
    // fork or preset for it to be legitimately more or less permissive about.
    // A byte string long enough for one implementation's container bounds but
    // not the other's is the shape such a disagreement would actually take,
    // and this crate and lighthouse are meant to agree on preset bounds for
    // the same build (see `lighthouse_spec`'s doc comment), so that should
    // never be reachable in practice.
    let (our_state, lh_state) = match (our_decoded, lh_decoded) {
        (Ok(ours), Ok(theirs)) => (ours, theirs),
        (Err(_), Err(_)) => return,
        (ours, theirs) => panic!(
            "ethlambda and lighthouse disagree on whether these bytes decode as a \
             {fork:?} state: ethlambda = {}, lighthouse = {}",
            ours.is_ok(),
            theirs.is_ok(),
        ),
    };

    if lh_state.fork_name(&lh_spec) != Ok(lh_fork) {
        return;
    }

    let our_root = our_state.hash_tree_root();
    // `canonical_root` takes `&mut self` (it flushes lighthouse's own
    // persistent-data-structure caches before hashing; see
    // `types::BeaconState::canonical_root`'s doc comment), so the binding
    // above has to be mutable even though nothing else here mutates it.
    let mut lh_state = lh_state;
    let lh_root = lh_state
        .canonical_root()
        .expect("a state that just decoded should hash cleanly");
    assert_eq!(
        our_root.0, lh_root.0,
        "ethlambda and lighthouse decoded the same bytes as a {fork:?} state but \
         computed different hash_tree_roots"
    );

    let our_reencoded = our_state.to_ssz();
    let lh_reencoded = lh_state.as_ssz_bytes();
    assert_eq!(
        our_reencoded, lh_reencoded,
        "ethlambda and lighthouse agree on the {fork:?} state's hash_tree_root but \
         re-encoded it to different bytes"
    );

    // SSZ has exactly one valid encoding per value, so re-encoding a state
    // that decoded cleanly from `state_bytes` should reproduce it exactly.
    // This is not a differential check (nothing here compares the two
    // implementations), but it is a cheap way for this target to also catch
    // either one on its own failing to round-trip, which the assertion above
    // alone would miss if both happened to agree on a wrong encoding.
    assert_eq!(
        our_reencoded, state_bytes,
        "ethlambda decoded a {fork:?} state and re-encoded it to bytes different \
         from the input"
    );
});
