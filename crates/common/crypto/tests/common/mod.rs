//! Helpers shared by the integration tests.

use ethlambda_crypto::signature::{ValidatorPublicKey, ValidatorSignature};
use ethlambda_types::primitives::H256;
use leanvm::xmss::{self, Encode as _, key_gen_from_seed};

/// Mirrors the lib tests' helper: a small slot range keeps key generation fast.
pub fn keypair_and_signature(
    seed: u64,
    first_slot: u32,
    signing_slot: u32,
    message: &H256,
) -> (ValidatorPublicKey, ValidatorSignature) {
    let mut seed_bytes = [0u8; 32];
    seed_bytes[..8].copy_from_slice(&seed.to_le_bytes());

    let (sk, pk) =
        key_gen_from_seed(seed_bytes, first_slot, first_slot + 63).expect("valid slot range");
    let sig = xmss::sign(&sk, &message.0, signing_slot).expect("sign");

    (
        ValidatorPublicKey::from_bytes(&pk.as_ssz_bytes()).unwrap(),
        ValidatorSignature::from_bytes(&sig.as_ssz_bytes()).unwrap(),
    )
}
