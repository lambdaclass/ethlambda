//! Coverage for the arena path of [`init_leanvm`].
//!
//! leanVM's arena engages process-wide and cannot be disengaged, so this cannot live in
//! the lib test binary: it would change the allocator under every other test. An
//! integration test gets its own process.

use ethlambda_crypto::{
    aggregate_signatures, init_leanvm,
    signature::{ValidatorPublicKey, ValidatorSignature},
    verify_aggregated_signature,
};
use ethlambda_types::primitives::H256;
use leanvm::xmss::{self, Encode as _, key_gen_from_seed};

/// Mirrors the lib tests' helper: a small slot range keeps key generation fast.
fn keypair_and_signature(
    seed: u64,
    first_slot: u32,
    signing_slot: u32,
    message: &H256,
) -> (ValidatorPublicKey, ValidatorSignature) {
    let mut seed_bytes = [0u8; 32];
    seed_bytes[..8].copy_from_slice(&seed.to_le_bytes());

    let (sk, pk) =
        key_gen_from_seed(seed_bytes, first_slot, first_slot + 63).expect("valid slot range");
    let sig = xmss::sign(&mut leanvm::rand::rng(), &sk, &message.0, signing_slot).expect("sign");

    (
        ValidatorPublicKey::from_bytes(&pk.as_ssz_bytes()).unwrap(),
        ValidatorSignature::from_bytes(&sig.as_ssz_bytes()).unwrap(),
    )
}

#[test]
#[ignore = "too slow"]
fn aggregates_on_the_arena_when_enabled() {
    init_leanvm(true);

    let message = H256::from([7u8; 32]);
    let slot = 10u32;
    let (pk, sig) = keypair_and_signature(1, 5, slot, &message);

    // Proves on the arena: the same round trip the lib tests run on the system allocator.
    let proof = aggregate_signatures(vec![pk.clone()], vec![sig], &message, slot)
        .expect("aggregation on the arena");
    verify_aggregated_signature(&proof, vec![pk], &message, slot).expect("verification");
}
