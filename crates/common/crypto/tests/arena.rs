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
use lean_multisig::{xmss_key_gen_from_seed, xmss_sign};
use ssz::Encode as _;

/// Mirrors the lib tests' helper: a small active range keeps key generation fast.
fn keypair_and_signature(
    seed: u64,
    activation_epoch: u32,
    signing_epoch: u32,
    message: &H256,
) -> (ValidatorPublicKey, ValidatorSignature) {
    let mut seed_bytes = [0u8; 32];
    seed_bytes[..8].copy_from_slice(&seed.to_le_bytes());

    let num_active_slots = 64u64;
    let (pk, sk) = xmss_key_gen_from_seed(seed_bytes, activation_epoch as u64, num_active_slots)
        .expect("valid activation range");
    let sig = xmss_sign(&sk, signing_epoch, &message.0).expect("sign");

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
