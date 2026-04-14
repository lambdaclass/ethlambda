use std::sync::Once;

use ethlambda_types::{
    block::ByteListMiB,
    primitives::H256,
    signature::{ValidatorPublicKey, ValidatorSignature},
};
use lean_multisig::{
    AggregatedXMSS, ProofError, setup_prover, setup_verifier, xmss_aggregate,
    xmss_verify_aggregation,
};
use leansig_wrapper::{XmssPublicKey as LeanSigPubKey, XmssSignature as LeanSigSignature};
use thiserror::Error;

// Lazy initialization for prover and verifier setup
static PROVER_INIT: Once = Once::new();
static VERIFIER_INIT: Once = Once::new();

/// Ensure the prover is initialized. Safe to call multiple times.
pub fn ensure_prover_ready() {
    PROVER_INIT.call_once(setup_prover);
}

/// Ensure the verifier is initialized. Safe to call multiple times.
pub fn ensure_verifier_ready() {
    VERIFIER_INIT.call_once(setup_verifier);
}

/// Error type for signature aggregation operations.
#[derive(Debug, Error)]
pub enum AggregationError {
    #[error("empty input")]
    EmptyInput,

    #[error("public key count ({0}) does not match signature count ({1})")]
    CountMismatch(usize, usize),

    #[error("proof size too big: {0} bytes")]
    ProofTooBig(usize),

    #[error("child proof deserialization failed at index {0}")]
    ChildDeserializationFailed(usize),

    #[error("need at least 2 children for recursive aggregation, got {0}")]
    InsufficientChildren(usize),
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
/// all signing the same message at the same slot, and produces a single
/// aggregated proof that can be verified more efficiently than checking
/// each signature individually.
///
/// # Arguments
///
/// * `public_keys` - The public keys of the validators who signed
/// * `signatures` - The signatures from each validator (must match public_keys order)
/// * `message` - The 32-byte message that was signed
/// * `slot` - The slot in which the signatures were created
///
/// # Returns
///
/// The serialized aggregated proof as `ByteListMiB`, or an error if aggregation fails.
pub fn aggregate_signatures(
    public_keys: Vec<ValidatorPublicKey>,
    signatures: Vec<ValidatorSignature>,
    message: &H256,
    slot: u32,
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

    let raw_xmss: Vec<(LeanSigPubKey, LeanSigSignature)> = public_keys
        .into_iter()
        .zip(signatures)
        .map(|(pk, sig)| (pk.into_inner(), sig.into_inner()))
        .collect();

    // log_inv_rate=2 matches the devnet-4 cross-client convention (zeam, ream,
    // grandine, lantern's c-leanvm-xmss all use 2). Ethlambda previously
    // hardcoded 1, which produced proofs incompatible with every other client.
    let (_sorted_pubkeys, aggregate) = xmss_aggregate(&[], raw_xmss, &message.0, slot, 2);

    serialize_aggregate(aggregate)
}

/// Aggregate both existing proofs (children) and raw XMSS signatures in a single call.
///
/// This is the spec's gossip-time mixed aggregation: existing proofs from previous
/// rounds are fed as children, and only genuinely new signatures go as `raw_xmss`.
/// This avoids re-aggregating from scratch each round and keeps proof trees shallow.
///
/// Requires at least one raw signature OR at least 2 children. A lone child proof
/// is already valid and needs no further aggregation.
///
/// # Panics
///
/// Panics if any deserialized child proof is cryptographically invalid (e.g., was
/// produced for a different message or slot). This is an upstream constraint of
/// `xmss_aggregate`.
pub fn aggregate_mixed(
    children: Vec<(Vec<ValidatorPublicKey>, ByteListMiB)>,
    raw_public_keys: Vec<ValidatorPublicKey>,
    raw_signatures: Vec<ValidatorSignature>,
    message: &H256,
    slot: u32,
) -> Result<ByteListMiB, AggregationError> {
    if raw_public_keys.len() != raw_signatures.len() {
        return Err(AggregationError::CountMismatch(
            raw_public_keys.len(),
            raw_signatures.len(),
        ));
    }

    // Need at least one raw signature OR at least 2 children to merge.
    if raw_public_keys.is_empty() && children.len() < 2 {
        if children.is_empty() {
            return Err(AggregationError::EmptyInput);
        }
        return Err(AggregationError::InsufficientChildren(children.len()));
    }

    ensure_prover_ready();

    let deserialized = deserialize_children(children)?;
    let children_refs = to_children_refs(&deserialized);

    let raw_xmss: Vec<(LeanSigPubKey, LeanSigSignature)> = raw_public_keys
        .into_iter()
        .zip(raw_signatures)
        .map(|(pk, sig)| (pk.into_inner(), sig.into_inner()))
        .collect();

    let (_sorted_pubkeys, aggregate) =
        xmss_aggregate(&children_refs, raw_xmss, &message.0, slot, 2);

    serialize_aggregate(aggregate)
}

/// Recursively aggregate multiple already-aggregated proofs into one.
///
/// Each child is a `(public_keys, proof_data)` pair where `public_keys` are the
/// attestation public keys of the validators covered by that child proof, and
/// `proof_data` is the serialized `AggregatedXMSS`. At least 2 children are required.
///
/// This is used during block building to compact multiple proofs sharing the same
/// `AttestationData` into a single merged proof (leanSpec PR #510).
pub fn aggregate_proofs(
    children: Vec<(Vec<ValidatorPublicKey>, ByteListMiB)>,
    message: &H256,
    slot: u32,
) -> Result<ByteListMiB, AggregationError> {
    if children.len() < 2 {
        return Err(AggregationError::InsufficientChildren(children.len()));
    }

    ensure_prover_ready();

    let deserialized = deserialize_children(children)?;
    let children_refs = to_children_refs(&deserialized);

    let (_sorted_pubkeys, aggregate) = xmss_aggregate(&children_refs, vec![], &message.0, slot, 2);

    serialize_aggregate(aggregate)
}

/// Deserialize child proofs from `(public_keys, proof_bytes)` pairs into
/// lean-multisig types.
fn deserialize_children(
    children: Vec<(Vec<ValidatorPublicKey>, ByteListMiB)>,
) -> Result<Vec<(Vec<LeanSigPubKey>, AggregatedXMSS)>, AggregationError> {
    children
        .into_iter()
        .enumerate()
        .map(|(i, (pubkeys, proof_data))| {
            let lean_pks: Vec<LeanSigPubKey> =
                pubkeys.into_iter().map(|pk| pk.into_inner()).collect();
            let aggregate = AggregatedXMSS::deserialize(proof_data.iter().as_slice())
                .ok_or(AggregationError::ChildDeserializationFailed(i))?;
            Ok((lean_pks, aggregate))
        })
        .collect()
}

/// Build the reference slice that `xmss_aggregate` expects.
fn to_children_refs(
    deserialized: &[(Vec<LeanSigPubKey>, AggregatedXMSS)],
) -> Vec<(&[LeanSigPubKey], AggregatedXMSS)> {
    deserialized
        .iter()
        .map(|(pks, agg)| (pks.as_slice(), agg.clone()))
        .collect()
}

/// Serialize an `AggregatedXMSS` into the `ByteListMiB` wire format.
fn serialize_aggregate(aggregate: AggregatedXMSS) -> Result<ByteListMiB, AggregationError> {
    let serialized = aggregate.serialize();
    let serialized_len = serialized.len();
    ByteListMiB::try_from(serialized).map_err(|_| AggregationError::ProofTooBig(serialized_len))
}

/// Verify an aggregated signature proof.
///
/// This function verifies that a set of validators (identified by their public keys)
/// all signed the same message at the same slot.
///
/// # Arguments
///
/// * `proof_data` - The serialized aggregated proof
/// * `public_keys` - The public keys of the validators who allegedly signed
/// * `message` - The 32-byte message that was allegedly signed
/// * `slot` - The slot in which the signatures were allegedly created
///
/// # Returns
///
/// `Ok(())` if verification succeeds, or an error describing why it failed.
pub fn verify_aggregated_signature(
    proof_data: &ByteListMiB,
    public_keys: Vec<ValidatorPublicKey>,
    message: &H256,
    slot: u32,
) -> Result<(), VerificationError> {
    ensure_verifier_ready();

    // Convert public keys
    let lean_pubkeys: Vec<LeanSigPubKey> = public_keys
        .into_iter()
        .map(ValidatorPublicKey::into_inner)
        .collect();

    // Deserialize the aggregate proof
    let aggregate = AggregatedXMSS::deserialize(proof_data.iter().as_slice())
        .ok_or(VerificationError::DeserializationFailed)?;

    // Verify using lean-multisig
    xmss_verify_aggregation(lean_pubkeys, &aggregate, &message.0, slot)?;

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

        let sig = LeanSignatureScheme::sign(&sk, signing_epoch, &message.0).unwrap();

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
        let slot = 10u32;
        let activation_epoch = 5u32;

        let (pk, sig) = generate_keypair_and_sign(1, activation_epoch, slot, &message);

        let result = aggregate_signatures(vec![pk.clone()], vec![sig], &message, slot);
        assert!(result.is_ok(), "Aggregation failed: {:?}", result.err());

        let proof_data = result.unwrap();

        // Verify the aggregated signature
        let verify_result =
            verify_aggregated_signature(&proof_data, vec![pk.clone()], &message, slot);
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
        let slot = 15u32;

        // Generate 3 keypairs with different activation epochs
        let configs = vec![
            (1u64, 5u32),  // seed, activation_epoch
            (2u64, 8u32),  // seed, activation_epoch
            (3u64, 10u32), // seed, activation_epoch
        ];

        let mut pubkeys = Vec::new();
        let mut signatures = Vec::new();

        for (seed, activation_epoch) in configs {
            let (pk, sig) = generate_keypair_and_sign(seed, activation_epoch, slot, &message);
            pubkeys.push(pk);
            signatures.push(sig);
        }

        let result = aggregate_signatures(pubkeys.clone(), signatures, &message, slot);
        assert!(result.is_ok(), "Aggregation failed: {:?}", result.err());

        let proof_data = result.unwrap();

        // Verify the aggregated signature
        let verify_result = verify_aggregated_signature(&proof_data, pubkeys, &message, slot);
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
        let slot = 10u32;
        let activation_epoch = 5u32;

        let (pk, sig) = generate_keypair_and_sign(1, activation_epoch, slot, &message);

        let proof_data = aggregate_signatures(vec![pk.clone()], vec![sig], &message, slot).unwrap();

        // Verify with wrong message should fail
        let verify_result =
            verify_aggregated_signature(&proof_data, vec![pk.clone()], &wrong_message, slot);
        assert!(
            verify_result.is_err(),
            "Verification should have failed with wrong message"
        );
    }

    #[test]
    #[ignore = "too slow"]
    fn test_verify_wrong_slot_fails() {
        let message = H256::from([42u8; 32]);
        let slot = 10u32;
        let wrong_slot = 11u32;
        let activation_epoch = 5u32;

        let (pk, sig) = generate_keypair_and_sign(1, activation_epoch, slot, &message);

        let proof_data = aggregate_signatures(vec![pk.clone()], vec![sig], &message, slot).unwrap();

        // Verify with wrong slot should fail
        let verify_result =
            verify_aggregated_signature(&proof_data, vec![pk.clone()], &message, wrong_slot);
        assert!(
            verify_result.is_err(),
            "Verification should have failed with wrong slot"
        );
    }
}
