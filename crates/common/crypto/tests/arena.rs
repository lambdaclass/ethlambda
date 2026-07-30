//! Coverage for the arena opt-in.
//!
//! The choice latches process-wide on the first prove, so this cannot live in the lib
//! test binary: enabling the arena there would change the allocator under every other
//! test, and whether the call won the latch would depend on test ordering. An
//! integration test gets its own process.

use ethlambda_crypto::{
    aggregate_signatures, enable_prover_arena,
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
    assert!(
        enable_prover_arena(),
        "nothing has proved yet, so the choice must still be open"
    );
    assert!(
        !enable_prover_arena(),
        "the choice is latched once set, so a second call reports no effect"
    );

    let message = H256::from([7u8; 32]);
    let slot = 10u32;
    let (pk, sig) = keypair_and_signature(1, 5, slot, &message);

    // Proves on the arena: the same round trip the lib tests run on the system allocator.
    let proof = aggregate_signatures(vec![pk.clone()], vec![sig], &message, slot)
        .expect("aggregation on the arena");
    verify_aggregated_signature(&proof, vec![pk], &message, slot).expect("verification");
}
