use std::sync::Once;

use ethlambda_types::{
    block::ByteListMiB,
    primitives::H256,
    signature::{ValidatorPublicKey, ValidatorSignature},
};
use lean_multisig::{
    ProofError, TypeOneMultiSignature as LMType1, TypeTwoMultiSignature as LMType2,
    aggregate_type_1, merge_many_type_1, setup_prover, setup_verifier, split_type_2, verify_type_1,
    verify_type_2,
};
use leansig_wrapper::{XmssPublicKey as LeanSigPubKey, XmssSignature as LeanSigSignature};
use thiserror::Error;

/// log(1/rate) for the WHIR commitment scheme used inside lean-multisig.
/// 2 matches the devnet-4 cross-client convention (zeam, ream, grandine, lantern
/// all use 2); the leanMultisig devnet5 examples also use 2 for recursion.
const LOG_INV_RATE: usize = 2;

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

    #[error("component count ({components}) does not match pubkey-set count ({pubkey_sets})")]
    ComponentPubkeyMismatch {
        components: usize,
        pubkey_sets: usize,
    },

    #[error("split index {index} out of bounds for type-2 with {components} components")]
    SplitIndexOutOfBounds { index: usize, components: usize },

    #[error("prover failure: {0}")]
    ProverFailure(String),
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

    #[error(
        "(message, slot) mismatch: proof binds {got_slot}/{got_msg:?}, expected {expected_slot}/{expected_msg:?}"
    )]
    BindingMismatch {
        expected_msg: H256,
        expected_slot: u32,
        got_msg: H256,
        got_slot: u32,
    },

    #[error("component count ({components}) does not match pubkey-set count ({pubkey_sets})")]
    ComponentPubkeyMismatch {
        components: usize,
        pubkey_sets: usize,
    },

    #[error("type-2 binds {got} components but {expected} were expected")]
    Type2ComponentCountMismatch { expected: usize, got: usize },
}

// =====================================================================
// Helpers
// =====================================================================

fn into_lean_pubkeys(pubkeys: Vec<ValidatorPublicKey>) -> Vec<LeanSigPubKey> {
    pubkeys
        .into_iter()
        .map(ValidatorPublicKey::into_inner)
        .collect()
}

/// Decompress a stored Type-1 proof (without-pubkeys form) into a native
/// `TypeOneMultiSignature` by attaching the resolved validator pubkeys.
fn decompress_type1(
    pubkeys: Vec<ValidatorPublicKey>,
    proof_bytes: &ByteListMiB,
    index: usize,
) -> Result<LMType1, AggregationError> {
    let lean_pks = into_lean_pubkeys(pubkeys);
    LMType1::decompress_without_pubkeys(proof_bytes.iter().as_slice(), lean_pks)
        .ok_or(AggregationError::ChildDeserializationFailed(index))
}

fn compress_type1_to_byte_list(sig: &LMType1) -> Result<ByteListMiB, AggregationError> {
    let serialized = sig.compress_without_pubkeys();
    let len = serialized.len();
    ByteListMiB::try_from(serialized).map_err(|_| AggregationError::ProofTooBig(len))
}

fn compress_type2_to_byte_list(sig: &LMType2) -> Result<ByteListMiB, AggregationError> {
    let serialized = sig.compress_without_pubkeys();
    let len = serialized.len();
    ByteListMiB::try_from(serialized).map_err(|_| AggregationError::ProofTooBig(len))
}

// =====================================================================
// Type-1 aggregation (single message, single slot)
// =====================================================================

/// Aggregate multiple XMSS signatures into a single Type-1 proof.
///
/// Equivalent to `aggregate_type_1([], raw_xmss, ...)` in lean-multisig.
///
/// All signatures must bind to the same `(message, slot)` pair.
///
/// Returns the lean-multisig `TypeOneMultiSignature::compress_without_pubkeys()`
/// bytes, packed as `ByteListMiB` for the on-wire SSZ proof field.
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
    if public_keys.is_empty() {
        return Err(AggregationError::EmptyInput);
    }

    ensure_prover_ready();

    let raw_xmss: Vec<(LeanSigPubKey, LeanSigSignature)> = public_keys
        .into_iter()
        .zip(signatures)
        .map(|(pk, sig)| (pk.into_inner(), sig.into_inner()))
        .collect();

    let proof = aggregate_type_1(&[], raw_xmss, message.0, slot, LOG_INV_RATE)
        .map_err(|err| AggregationError::ProverFailure(err.to_string()))?;

    compress_type1_to_byte_list(&proof)
}

/// Aggregate both existing Type-1 proofs (children) and raw XMSS signatures.
///
/// Existing Type-1s are reused as recursive children; raw XMSS are mixed in.
/// All inputs must bind to the same `(message, slot)`.
///
/// Requires at least one raw signature OR at least 2 children. A lone child is
/// already a valid Type-1; further aggregation is wasted work.
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
    if raw_public_keys.is_empty() && children.len() < 2 {
        return Err(AggregationError::InsufficientChildren(children.len()));
    }

    ensure_prover_ready();

    let children_native: Vec<LMType1> = children
        .into_iter()
        .enumerate()
        .map(|(i, (pubkeys, proof_bytes))| decompress_type1(pubkeys, &proof_bytes, i))
        .collect::<Result<_, _>>()?;

    let raw_xmss: Vec<(LeanSigPubKey, LeanSigSignature)> = raw_public_keys
        .into_iter()
        .zip(raw_signatures)
        .map(|(pk, sig)| (pk.into_inner(), sig.into_inner()))
        .collect();

    let proof = aggregate_type_1(&children_native, raw_xmss, message.0, slot, LOG_INV_RATE)
        .map_err(|err| AggregationError::ProverFailure(err.to_string()))?;

    compress_type1_to_byte_list(&proof)
}

/// Recursively aggregate two or more already-aggregated Type-1 proofs into one.
///
/// All children must bind to the same `(message, slot)`. Used during block
/// building to compact multiple proofs sharing an `AttestationData`.
pub fn aggregate_proofs(
    children: Vec<(Vec<ValidatorPublicKey>, ByteListMiB)>,
    message: &H256,
    slot: u32,
) -> Result<ByteListMiB, AggregationError> {
    if children.len() < 2 {
        return Err(AggregationError::InsufficientChildren(children.len()));
    }

    ensure_prover_ready();

    let children_native: Vec<LMType1> = children
        .into_iter()
        .enumerate()
        .map(|(i, (pubkeys, proof_bytes))| decompress_type1(pubkeys, &proof_bytes, i))
        .collect::<Result<_, _>>()?;

    let proof = aggregate_type_1(&children_native, vec![], message.0, slot, LOG_INV_RATE)
        .map_err(|err| AggregationError::ProverFailure(err.to_string()))?;

    compress_type1_to_byte_list(&proof)
}

/// Verify a Type-1 aggregated signature proof.
///
/// Cryptographically verifies that every `public_key` signed `message` at `slot`.
///
/// The verifier checks the bound `(message, slot)` matches what the caller
/// expects, defending against proofs reused from other binding contexts.
pub fn verify_aggregated_signature(
    proof_data: &ByteListMiB,
    public_keys: Vec<ValidatorPublicKey>,
    message: &H256,
    slot: u32,
) -> Result<(), VerificationError> {
    ensure_verifier_ready();

    let lean_pubkeys = into_lean_pubkeys(public_keys);
    let sig = LMType1::decompress_without_pubkeys(proof_data.iter().as_slice(), lean_pubkeys)
        .ok_or(VerificationError::DeserializationFailed)?;

    if sig.info.without_pubkeys.message != message.0 || sig.info.without_pubkeys.slot != slot {
        return Err(VerificationError::BindingMismatch {
            expected_msg: *message,
            expected_slot: slot,
            got_msg: H256(sig.info.without_pubkeys.message),
            got_slot: sig.info.without_pubkeys.slot,
        });
    }

    verify_type_1(&sig)?;
    Ok(())
}

// =====================================================================
// Type-2 merge / verify / split (block-level merged proofs)
// =====================================================================

/// Merge many independent Type-1 multi-signatures into a single Type-2 proof.
///
/// Each input is `(participant_pubkeys, type_1_proof_bytes)` where the bytes
/// are the `compress_without_pubkeys()` form of a `TypeOneMultiSignature`.
///
/// The returned blob is the `compress_without_pubkeys()` form of the resulting
/// `TypeTwoMultiSignature`. A verifier decoding it back needs the per-component
/// pubkey sets in the same order.
pub fn merge_type_1s_into_type_2(
    type_1s: Vec<(Vec<ValidatorPublicKey>, ByteListMiB)>,
) -> Result<ByteListMiB, AggregationError> {
    if type_1s.is_empty() {
        return Err(AggregationError::EmptyInput);
    }

    ensure_prover_ready();

    let type_1s_native: Vec<LMType1> = type_1s
        .into_iter()
        .enumerate()
        .map(|(i, (pubkeys, proof_bytes))| decompress_type1(pubkeys, &proof_bytes, i))
        .collect::<Result<_, _>>()?;

    let merged = merge_many_type_1(type_1s_native, LOG_INV_RATE)
        .map_err(|err| AggregationError::ProverFailure(err.to_string()))?;

    compress_type2_to_byte_list(&merged)
}

/// Verify a Type-2 merged proof against the per-component expected bindings.
///
/// The verifier re-derives each component's `(message, slot, pubkeys)` from the
/// caller-supplied lists, checks they match what the proof binds, and then runs
/// the inner SNARK verifier.
pub fn verify_type_2_signature(
    proof_data: &ByteListMiB,
    pubkeys_per_component: Vec<Vec<ValidatorPublicKey>>,
    expected_bindings: &[(H256, u32)],
) -> Result<(), VerificationError> {
    if expected_bindings.len() != pubkeys_per_component.len() {
        return Err(VerificationError::ComponentPubkeyMismatch {
            components: expected_bindings.len(),
            pubkey_sets: pubkeys_per_component.len(),
        });
    }

    ensure_verifier_ready();

    let pubkeys_per_info: Vec<Vec<LeanSigPubKey>> = pubkeys_per_component
        .into_iter()
        .map(into_lean_pubkeys)
        .collect();

    let sig = LMType2::decompress_without_pubkeys(proof_data.iter().as_slice(), pubkeys_per_info)
        .ok_or(VerificationError::DeserializationFailed)?;

    if sig.info.len() != expected_bindings.len() {
        return Err(VerificationError::Type2ComponentCountMismatch {
            expected: expected_bindings.len(),
            got: sig.info.len(),
        });
    }

    for (idx, ((expected_msg, expected_slot), info)) in
        expected_bindings.iter().zip(sig.info.iter()).enumerate()
    {
        if info.without_pubkeys.message != expected_msg.0
            || info.without_pubkeys.slot != *expected_slot
        {
            return Err(VerificationError::BindingMismatch {
                expected_msg: *expected_msg,
                expected_slot: *expected_slot,
                got_msg: H256(info.without_pubkeys.message),
                got_slot: info.without_pubkeys.slot,
            });
        }
        let _ = idx; // index reserved for richer diagnostics if needed
    }

    verify_type_2(&sig)?;
    Ok(())
}

/// Split (disaggregate) a Type-2 merged proof into a single Type-1 proof for
/// the component at `index`. Generates a fresh SNARK; expensive.
///
/// Returns the `compress_without_pubkeys()` form of the resulting Type-1.
pub fn split_type_2_signature(
    proof_data: &ByteListMiB,
    pubkeys_per_component: Vec<Vec<ValidatorPublicKey>>,
    index: usize,
) -> Result<ByteListMiB, AggregationError> {
    ensure_prover_ready();

    if index >= pubkeys_per_component.len() {
        return Err(AggregationError::SplitIndexOutOfBounds {
            index,
            components: pubkeys_per_component.len(),
        });
    }

    let pubkeys_per_info: Vec<Vec<LeanSigPubKey>> = pubkeys_per_component
        .into_iter()
        .map(into_lean_pubkeys)
        .collect();

    let type_2 =
        LMType2::decompress_without_pubkeys(proof_data.iter().as_slice(), pubkeys_per_info)
            .ok_or(AggregationError::ChildDeserializationFailed(0))?;

    let component = split_type_2(type_2, index, LOG_INV_RATE)
        .map_err(|err| AggregationError::ProverFailure(err.to_string()))?;

    compress_type1_to_byte_list(&component)
}

#[cfg(test)]
mod tests {
    use super::*;
    use leansig::{serialization::Serializable, signature::SignatureScheme};
    use rand::{SeedableRng, rngs::StdRng};

    // The signature scheme type used in ethlambda-types (Dim46 to match
    // production validator keys; lean-multisig's `aggregate_type_1` hard-codes
    // `SIG_SIZE_FE = 7 + (V + LOG_LIFETIME) * 8 = 631` for V=46).
    type LeanSignatureScheme = leansig::signature::generalized_xmss::instantiations_aborting::lifetime_2_to_the_32::SchemeAbortingTargetSumLifetime32Dim46Base8;

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

    /// End-to-end Type-2 round-trip: produce two Type-1s (different (msg, slot)),
    /// merge them into a Type-2, verify the Type-2, then split out one component
    /// and verify it as a Type-1.
    #[test]
    #[ignore = "too slow"]
    fn test_type_2_merge_verify_split_round_trip() {
        let msg_a = H256::from([0x11u8; 32]);
        let msg_b = H256::from([0x22u8; 32]);
        let slot_a: u32 = 7;
        let slot_b: u32 = 11;

        let (pk_a, sig_a) = generate_keypair_and_sign(101, 5, slot_a, &msg_a);
        let (pk_b, sig_b) = generate_keypair_and_sign(102, 5, slot_b, &msg_b);

        let pa = aggregate_signatures(vec![pk_a.clone()], vec![sig_a], &msg_a, slot_a).unwrap();
        let pb = aggregate_signatures(vec![pk_b.clone()], vec![sig_b], &msg_b, slot_b).unwrap();

        let merged =
            merge_type_1s_into_type_2(vec![(vec![pk_a.clone()], pa), (vec![pk_b.clone()], pb)])
                .expect("merge");

        verify_type_2_signature(
            &merged,
            vec![vec![pk_a.clone()], vec![pk_b.clone()]],
            &[(msg_a, slot_a), (msg_b, slot_b)],
        )
        .expect("verify type-2");

        let split =
            split_type_2_signature(&merged, vec![vec![pk_a.clone()], vec![pk_b.clone()]], 0)
                .expect("split");

        verify_aggregated_signature(&split, vec![pk_a.clone()], &msg_a, slot_a)
            .expect("verify split");
    }
}
