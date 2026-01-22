use std::sync::Once;

use ethlambda_types::primitives::{Decode, Encode, VariableList};
use ethlambda_types::{
    block::ByteListMiB,
    primitives::H256,
    signature::{ValidatorPublicKey, ValidatorSignature},
};
use lean_multisig::{
    Devnet2XmssAggregateSignature, ProofError, XmssAggregateError,
    xmss_aggregate_signatures as lean_xmss_aggregate_signatures, xmss_aggregation_setup_prover,
    xmss_aggregation_setup_verifier,
    xmss_verify_aggregated_signatures as lean_xmss_verify_aggregated_signatures,
};
use leansig::serialization::Serializable;
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
    #[error("public key count ({0}) does not match signature count ({1})")]
    CountMismatch(usize, usize),

    #[error("failed to convert public key at index {index}: {reason}")]
    PublicKeyConversion { index: usize, reason: String },

    #[error("failed to convert signature at index {index}: {reason}")]
    SignatureConversion { index: usize, reason: String },

    #[error("aggregation failed: {0:?}")]
    AggregationFailed(XmssAggregateError),

    #[error("proof serialization failed")]
    SerializationFailed,
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

/// Convert a ValidatorPublicKey to lean-multisig's LeanSigPubKey.
fn convert_pubkey(
    pk: &ValidatorPublicKey,
    index: usize,
) -> Result<LeanSigPubKey, AggregationError> {
    let bytes = pk.to_bytes();
    LeanSigPubKey::from_bytes(&bytes).map_err(|e| AggregationError::PublicKeyConversion {
        index,
        reason: format!("{:?}", e),
    })
}

/// Convert a ValidatorSignature to lean-multisig's LeanSigSignature.
fn convert_signature(
    sig: &ValidatorSignature,
    index: usize,
) -> Result<LeanSigSignature, AggregationError> {
    let bytes = sig.to_bytes();
    LeanSigSignature::from_bytes(&bytes).map_err(|e| AggregationError::SignatureConversion {
        index,
        reason: format!("{:?}", e),
    })
}

/// Serialize a Devnet2XmssAggregateSignature to ByteListMiB.
fn serialize_aggregate(
    agg: &Devnet2XmssAggregateSignature,
) -> Result<ByteListMiB, AggregationError> {
    let bytes = agg.as_ssz_bytes();
    VariableList::new(bytes).map_err(|_| AggregationError::SerializationFailed)
}

/// Deserialize a ByteListMiB to Devnet2XmssAggregateSignature.
fn deserialize_aggregate(
    bytes: &ByteListMiB,
) -> Result<Devnet2XmssAggregateSignature, VerificationError> {
    Devnet2XmssAggregateSignature::from_ssz_bytes(bytes.iter().as_slice())
        .map_err(|_| VerificationError::DeserializationFailed)
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
    public_keys: &[ValidatorPublicKey],
    signatures: &[ValidatorSignature],
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
        return Err(AggregationError::CountMismatch(0, 0));
    }

    ensure_prover_ready();

    // Convert public keys
    let lean_pubkeys: Vec<LeanSigPubKey> = public_keys
        .iter()
        .enumerate()
        .map(|(i, pk)| convert_pubkey(pk, i))
        .collect::<Result<_, _>>()?;

    // Convert signatures
    let lean_sigs: Vec<LeanSigSignature> = signatures
        .iter()
        .enumerate()
        .map(|(i, sig)| convert_signature(sig, i))
        .collect::<Result<_, _>>()?;

    // Aggregate using lean-multisig
    let aggregate = lean_xmss_aggregate_signatures(&lean_pubkeys, &lean_sigs, message, epoch)
        .map_err(AggregationError::AggregationFailed)?;

    serialize_aggregate(&aggregate)
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
    public_keys: &[ValidatorPublicKey],
    message: &H256,
    epoch: u32,
) -> Result<(), VerificationError> {
    ensure_verifier_ready();

    // Convert public keys
    let lean_pubkeys: Vec<LeanSigPubKey> = public_keys
        .iter()
        .enumerate()
        .map(|(i, pk)| {
            let bytes = pk.to_bytes();
            LeanSigPubKey::from_bytes(&bytes).map_err(|e| VerificationError::PublicKeyConversion {
                index: i,
                reason: format!("{:?}", e),
            })
        })
        .collect::<Result<_, _>>()?;

    // Deserialize the aggregate proof
    let aggregate = deserialize_aggregate(proof_data)?;

    // Verify using lean-multisig
    lean_xmss_verify_aggregated_signatures(&lean_pubkeys, message, &aggregate, epoch)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use leansig::signature::{SignatureScheme, SignatureSchemeSecretKey};
    use rand::{SeedableRng, rngs::StdRng};

    // The signature scheme type used in ethlambda-types
    type LeanSignatureScheme = leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8;

    /// Generate a test keypair and sign a message.
    ///
    /// Note: This is slow because XMSS key generation is computationally expensive.
    /// For real tests, consider using cached test data.
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

        let (pk, mut sk) =
            LeanSignatureScheme::key_gen(&mut rng, activation_epoch as usize, lifetime);

        // Advance the key to the signing epoch
        let mut iterations = 0;
        while !sk.get_prepared_interval().contains(&(signing_epoch as u64))
            && iterations < signing_epoch
        {
            sk.advance_preparation();
            iterations += 1;
        }

        let sig = LeanSignatureScheme::sign(&sk, signing_epoch, message).unwrap();

        // Convert to ethlambda types via bytes
        let pk_bytes = pk.to_bytes();
        let sig_bytes = sig.to_bytes();

        let validator_pk = ValidatorPublicKey::from_bytes(&pk_bytes).unwrap();
        let validator_sig = ValidatorSignature::from_bytes(&sig_bytes).unwrap();

        (validator_pk, validator_sig)
    }

    #[test]
    #[ignore = "expensive: requires lean-multisig setup with large stack"]
    fn test_setup_is_idempotent() {
        // Should not panic when called multiple times
        ensure_prover_ready();
        ensure_prover_ready();
        ensure_verifier_ready();
        ensure_verifier_ready();
    }

    #[test]
    fn test_aggregate_mismatched_counts_fails() {
        // This test verifies the count check - we don't need valid keys
        let result = aggregate_signatures(&[], &[], &H256::ZERO, 10);
        assert!(matches!(result, Err(AggregationError::CountMismatch(0, 0))));
    }

    #[test]
    #[ignore = "expensive: requires XMSS key generation and proof generation"]
    fn test_aggregate_single_signature() {
        let message = H256::from([42u8; 32]);
        let epoch = 10u32;
        let activation_epoch = 5u32;

        let (pk, sig) = generate_keypair_and_sign(1, activation_epoch, epoch, &message);

        let result = aggregate_signatures(std::slice::from_ref(&pk), &[sig], &message, epoch);
        assert!(result.is_ok(), "Aggregation failed: {:?}", result.err());

        let proof_data = result.unwrap();

        // Verify the aggregated signature
        let verify_result =
            verify_aggregated_signature(&proof_data, std::slice::from_ref(&pk), &message, epoch);
        assert!(
            verify_result.is_ok(),
            "Verification failed: {:?}",
            verify_result.err()
        );
    }

    #[test]
    #[ignore = "expensive: requires XMSS key generation and proof generation"]
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

        let result = aggregate_signatures(&pubkeys, &signatures, &message, epoch);
        assert!(result.is_ok(), "Aggregation failed: {:?}", result.err());

        let proof_data = result.unwrap();

        // Verify the aggregated signature
        let verify_result = verify_aggregated_signature(&proof_data, &pubkeys, &message, epoch);
        assert!(
            verify_result.is_ok(),
            "Verification failed: {:?}",
            verify_result.err()
        );
    }

    #[test]
    #[ignore = "expensive: requires XMSS key generation and proof generation"]
    fn test_verify_wrong_message_fails() {
        let message = H256::from([42u8; 32]);
        let wrong_message = H256::from([43u8; 32]);
        let epoch = 10u32;
        let activation_epoch = 5u32;

        let (pk, sig) = generate_keypair_and_sign(1, activation_epoch, epoch, &message);

        let proof_data =
            aggregate_signatures(std::slice::from_ref(&pk), &[sig], &message, epoch).unwrap();

        // Verify with wrong message should fail
        let verify_result = verify_aggregated_signature(
            &proof_data,
            std::slice::from_ref(&pk),
            &wrong_message,
            epoch,
        );
        assert!(
            verify_result.is_err(),
            "Verification should have failed with wrong message"
        );
    }

    #[test]
    #[ignore = "expensive: requires XMSS key generation and proof generation"]
    fn test_verify_wrong_epoch_fails() {
        let message = H256::from([42u8; 32]);
        let epoch = 10u32;
        let wrong_epoch = 11u32;
        let activation_epoch = 5u32;

        let (pk, sig) = generate_keypair_and_sign(1, activation_epoch, epoch, &message);

        let proof_data =
            aggregate_signatures(std::slice::from_ref(&pk), &[sig], &message, epoch).unwrap();

        // Verify with wrong epoch should fail
        let verify_result = verify_aggregated_signature(
            &proof_data,
            std::slice::from_ref(&pk),
            &message,
            wrong_epoch,
        );
        assert!(
            verify_result.is_err(),
            "Verification should have failed with wrong epoch"
        );
    }
}
