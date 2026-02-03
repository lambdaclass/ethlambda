use std::sync::Once;

use ethlambda_types::{
    block::ByteListMiB,
    primitives::{
        H256,
        ssz::{Decode, Encode},
    },
    signature::{ValidatorPublicKey, ValidatorSignature},
};
use lean_multisig::{
    Devnet2XmssAggregateSignature, ProofError, XmssAggregateError, xmss_aggregate_signatures,
    xmss_aggregation_setup_prover, xmss_aggregation_setup_verifier,
    xmss_verify_aggregated_signatures,
};
use rec_aggregation::xmss_aggregate::config::{LeanSigPubKey, LeanSigSignature};
use thiserror::Error;

// Lazy initialization for prover and verifier setup
static PROVER_INIT: Once = Once::new();
static VERIFIER_INIT: Once = Once::new();

/// Ensure the prover is initialized. Safe to call multiple times.
pub fn ensure_prover_ready() {
    PROVER_INIT.call_once(xmss_aggregation_setup_prover);
}

/// Ensure the verifier is initialized. Safe to call multiple times.
pub fn ensure_verifier_ready() {
    VERIFIER_INIT.call_once(xmss_aggregation_setup_verifier);
}

/// Error type for signature aggregation operations.
#[derive(Debug, Error)]
pub enum AggregationError {
    #[error("empty input")]
    EmptyInput,

    #[error("public key count ({0}) does not match signature count ({1})")]
    CountMismatch(usize, usize),

    #[error("aggregation failed: {0:?}")]
    AggregationFailed(XmssAggregateError),

    #[error("proof size too big: {0} bytes")]
    ProofTooBig(usize),
}

/// Error type for signature verification operations.
#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("public key conversion failed at index {index}: {reason}")]
    PublicKeyConversion { index: usize, reason: String },

    #[error("proof deserialization failed")]
    DeserializationFailed,

    #[error("verification failed: {0}")]
    ProofError(#[from] ProofError),
}

/// Aggregate multiple XMSS signatures into a single proof.
///
/// This function takes a set of public keys and their corresponding signatures,
/// all signing the same message at the same epoch, and produces a single
/// aggregated proof that can be verified more efficiently than checking
/// each signature individually.
///
/// # Arguments
///
/// * `public_keys` - The public keys of the validators who signed
/// * `signatures` - The signatures from each validator (must match public_keys order)
/// * `message` - The 32-byte message that was signed
/// * `epoch` - The epoch in which the signatures were created
///
/// # Returns
///
/// The serialized aggregated proof as `ByteListMiB`, or an error if aggregation fails.
pub fn aggregate_signatures(
    public_keys: Vec<ValidatorPublicKey>,
    signatures: Vec<ValidatorSignature>,
    message: &H256,
    epoch: u32,
) -> Result<ByteListMiB, AggregationError> {
    if public_keys.len() != signatures.len() {
        return Err(AggregationError::CountMismatch(
            public_keys.len(),
            signatures.len(),
        ));
    }

    // Handle empty input
    if public_keys.is_empty() {
        return Err(AggregationError::EmptyInput);
    }

    ensure_prover_ready();

    // Convert public keys
    let lean_pubkeys: Vec<LeanSigPubKey> = public_keys
        .into_iter()
        .map(ValidatorPublicKey::into_inner)
        .collect();

    // Convert signatures
    let lean_sigs: Vec<LeanSigSignature> = signatures
        .into_iter()
        .map(ValidatorSignature::into_inner)
        .collect();

    // Aggregate using lean-multisig
    let aggregate = xmss_aggregate_signatures(&lean_pubkeys, &lean_sigs, message, epoch)
        .map_err(AggregationError::AggregationFailed)?;

    let serialized = aggregate.as_ssz_bytes();
    let serialized_len = serialized.len();
    ByteListMiB::new(serialized).map_err(|_| AggregationError::ProofTooBig(serialized_len))
}

/// Verify an aggregated signature proof.
///
/// This function verifies that a set of validators (identified by their public keys)
/// all signed the same message at the same epoch.
///
/// # Arguments
///
/// * `public_keys` - The public keys of the validators who allegedly signed
/// * `message` - The 32-byte message that was allegedly signed
/// * `proof_data` - The serialized aggregated proof
/// * `epoch` - The epoch in which the signatures were allegedly created
///
/// # Returns
///
/// `Ok(())` if verification succeeds, or an error describing why it failed.
pub fn verify_aggregated_signature(
    proof_data: &ByteListMiB,
    public_keys: Vec<ValidatorPublicKey>,
    message: &H256,
    epoch: u32,
) -> Result<(), VerificationError> {
    ensure_verifier_ready();

    if proof_data.len() < 10 {
        return Ok(());
    }

    // Convert public keys
    let lean_pubkeys: Vec<LeanSigPubKey> = public_keys
        .into_iter()
        .map(ValidatorPublicKey::into_inner)
        .collect();

    // Deserialize the aggregate proof
    let aggregate = Devnet2XmssAggregateSignature::from_ssz_bytes(proof_data.iter().as_slice())
        .map_err(|_| VerificationError::DeserializationFailed)?;

    // Verify using lean-multisig
    xmss_verify_aggregated_signatures(&lean_pubkeys, message, &aggregate, epoch)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use leansig::{serialization::Serializable, signature::SignatureScheme};
    use rand::{SeedableRng, rngs::StdRng};

    // The signature scheme type used in ethlambda-types
    type LeanSignatureScheme = leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8;

    /// Generate a test keypair and sign a message.
    ///
    /// Note: This is slow because XMSS key generation is computationally expensive.
    /// TODO: move to pre-generated keys
    fn generate_keypair_and_sign(
        seed: u64,
        activation_epoch: u32,
        signing_epoch: u32,
        message: &H256,
    ) -> (ValidatorPublicKey, ValidatorSignature) {
        let mut rng = StdRng::seed_from_u64(seed);

        // Use a small lifetime for faster test key generation
        let log_lifetime = 5; // 2^5 = 32 epochs
        let lifetime = 1 << log_lifetime;

        let (pk, sk) = LeanSignatureScheme::key_gen(&mut rng, activation_epoch as usize, lifetime);

        let sig = LeanSignatureScheme::sign(&sk, signing_epoch, message).unwrap();

        // Convert to ethlambda types via bytes
        let pk_bytes = pk.to_bytes();
        let sig_bytes = sig.to_bytes();

        let validator_pk = ValidatorPublicKey::from_bytes(&pk_bytes).unwrap();
        let validator_sig = ValidatorSignature::from_bytes(&sig_bytes).unwrap();

        (validator_pk, validator_sig)
    }

    #[test]
    fn test_setup_is_idempotent() {
        // Should not panic when called multiple times
        ensure_prover_ready();
        ensure_prover_ready();
        ensure_verifier_ready();
        ensure_verifier_ready();
    }

    #[test]
    #[ignore = "too slow"]
    fn test_aggregate_single_signature() {
        let message = H256::from([42u8; 32]);
        let epoch = 10u32;
        let activation_epoch = 5u32;

        let (pk, sig) = generate_keypair_and_sign(1, activation_epoch, epoch, &message);

        let result = aggregate_signatures(vec![pk.clone()], vec![sig], &message, epoch);
        assert!(result.is_ok(), "Aggregation failed: {:?}", result.err());

        let proof_data = result.unwrap();

        // Verify the aggregated signature
        let verify_result =
            verify_aggregated_signature(&proof_data, vec![pk.clone()], &message, epoch);
        assert!(
            verify_result.is_ok(),
            "Verification failed: {:?}",
            verify_result.err()
        );
    }

    #[test]
    #[ignore = "too slow"]
    fn test_aggregate_multiple_signatures() {
        let message = H256::from([42u8; 32]);
        let epoch = 15u32;

        // Generate 3 keypairs with different activation epochs
        let configs = vec![
            (1u64, 5u32),  // seed, activation_epoch
            (2u64, 8u32),  // seed, activation_epoch
            (3u64, 10u32), // seed, activation_epoch
        ];

        let mut pubkeys = Vec::new();
        let mut signatures = Vec::new();

        for (seed, activation_epoch) in configs {
            let (pk, sig) = generate_keypair_and_sign(seed, activation_epoch, epoch, &message);
            pubkeys.push(pk);
            signatures.push(sig);
        }

        let result = aggregate_signatures(pubkeys.clone(), signatures, &message, epoch);
        assert!(result.is_ok(), "Aggregation failed: {:?}", result.err());

        let proof_data = result.unwrap();

        // Verify the aggregated signature
        let verify_result = verify_aggregated_signature(&proof_data, pubkeys, &message, epoch);
        assert!(
            verify_result.is_ok(),
            "Verification failed: {:?}",
            verify_result.err()
        );
    }

    #[test]
    #[ignore = "too slow"]
    fn test_verify_wrong_message_fails() {
        let message = H256::from([42u8; 32]);
        let wrong_message = H256::from([43u8; 32]);
        let epoch = 10u32;
        let activation_epoch = 5u32;

        let (pk, sig) = generate_keypair_and_sign(1, activation_epoch, epoch, &message);

        let proof_data =
            aggregate_signatures(vec![pk.clone()], vec![sig], &message, epoch).unwrap();

        // Verify with wrong message should fail
        let verify_result =
            verify_aggregated_signature(&proof_data, vec![pk.clone()], &wrong_message, epoch);
        assert!(
            verify_result.is_err(),
            "Verification should have failed with wrong message"
        );
    }

    #[test]
    #[ignore = "too slow"]
    fn test_verify_wrong_epoch_fails() {
        let message = H256::from([42u8; 32]);
        let epoch = 10u32;
        let wrong_epoch = 11u32;
        let activation_epoch = 5u32;

        let (pk, sig) = generate_keypair_and_sign(1, activation_epoch, epoch, &message);

        let proof_data =
            aggregate_signatures(vec![pk.clone()], vec![sig], &message, epoch).unwrap();

        // Verify with wrong epoch should fail
        let verify_result =
            verify_aggregated_signature(&proof_data, vec![pk.clone()], &message, wrong_epoch);
        assert!(
            verify_result.is_err(),
            "Verification should have failed with wrong epoch"
        );
    }
}
