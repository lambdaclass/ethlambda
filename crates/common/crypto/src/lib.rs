use ethlambda_types::{block::ByteList512KiB, primitives::H256};

use crate::signature::{
    LeanSigPublicKey, LeanSigSignature, ValidatorPublicKey, ValidatorSignature,
};
use lean_multisig::{
    MultiMessageAggregateSignature as LMType2, SingleMessageAggregateSignature as LMType1,
    aggregate_single_message_signatures, merge_single_message_aggregates, setup_prover,
    setup_verifier, split_multi_message_aggregate, verify_multi_message_aggregate,
    verify_single_message_aggregate,
};
use std::sync::{Mutex, MutexGuard};
use thiserror::Error;
use tracing::error;

pub mod signature;

#[cfg(feature = "shadow-integration")]
pub mod shadow_cost;

/// log(1/rate) for the WHIR commitment scheme used inside the aggregation prover.
const LOG_INV_RATE: usize = 2;

/// leanVM allows one proof at a time per process; a second one panics.
static PROVER_PERMIT: Mutex<()> = Mutex::new(());

/// The permit guards no data, so a poisoned lock is recovered rather than propagated:
/// one panicking prover must not brick every later proof. It is still an incident.
fn prover_permit() -> MutexGuard<'static, ()> {
    PROVER_PERMIT.lock().unwrap_or_else(|poisoned| {
        error!("a previous proving job panicked while holding the permit; continuing");
        poisoned.into_inner()
    })
}

/// Engages leanVM's arena; skipping it stays correct but slow.
pub fn ensure_prover_ready() {
    setup_prover();
}

/// Needed before any decode, not just before verifying.
pub fn ensure_verifier_ready() {
    setup_verifier();
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

    #[error("outer proof deserialization failed")]
    DeserializationFailed,

    #[error("need at least 2 children for recursive aggregation, got {0}")]
    InsufficientChildren(usize),

    #[error("component count ({components}) does not match pubkey-set count ({pubkey_sets})")]
    ComponentPubkeyMismatch {
        components: usize,
        pubkey_sets: usize,
    },

    #[error("split-by-message target not found in type-2 components")]
    UnknownMessage,

    #[error("split-by-message target matched multiple components")]
    MultipleMessages,

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
    VerificationFailed(String),

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

fn into_lean_pubkeys(pubkeys: Vec<ValidatorPublicKey>) -> Vec<LeanSigPublicKey> {
    pubkeys
        .into_iter()
        .map(ValidatorPublicKey::into_inner)
        .collect()
}

/// Decompress a stored Type-1 proof (without-pubkeys form) into a native
/// `SingleMessageAggregateSignature` by attaching the resolved validator pubkeys.
///
/// leanVM sorts and de-duplicates the attached set itself, so the order here does
/// not matter. A set other than the one aggregated attaches fine but fails
/// verification: the proof binds a hash of the set.
fn decompress_type1(
    pubkeys: Vec<ValidatorPublicKey>,
    proof_bytes: &ByteList512KiB,
    index: usize,
) -> Result<LMType1, AggregationError> {
    let lean_pks = into_lean_pubkeys(pubkeys);
    LMType1::from_bytes_without_pubkeys(proof_bytes.iter().as_slice(), lean_pks)
        .ok_or(AggregationError::ChildDeserializationFailed(index))
}

fn compress_type1_to_byte_list(sig: &LMType1) -> Result<ByteList512KiB, AggregationError> {
    let serialized = sig.to_bytes_without_pubkeys();
    let len = serialized.len();
    ByteList512KiB::try_from(serialized).map_err(|_| AggregationError::ProofTooBig(len))
}

fn compress_type2_to_byte_list(sig: &LMType2) -> Result<ByteList512KiB, AggregationError> {
    let serialized = sig.to_bytes_without_pubkeys();
    let len = serialized.len();
    ByteList512KiB::try_from(serialized).map_err(|_| AggregationError::ProofTooBig(len))
}

// =====================================================================
// Type-1 aggregation (single message, single slot)
// =====================================================================

/// Aggregate multiple XMSS signatures into a single Type-1 proof.
///
/// Equivalent to `aggregate_single_message_signatures([], raw_xmss, ...)` in
/// leanVM's `rec_aggregation`.
///
/// All signatures must bind to the same `(message, slot)` pair.
///
/// Returns the leanVM `SingleMessageAggregateSignature::to_bytes_without_pubkeys()`
/// bytes, packed as `ByteList512KiB` for the on-wire SSZ proof field. The
/// participant pubkeys stay off the wire: a receiver rebuilds the set from the
/// aggregation bits and its own validator registry.
pub fn aggregate_signatures(
    public_keys: Vec<ValidatorPublicKey>,
    signatures: Vec<ValidatorSignature>,
    message: &H256,
    slot: u32,
) -> Result<ByteList512KiB, AggregationError> {
    if public_keys.len() != signatures.len() {
        return Err(AggregationError::CountMismatch(
            public_keys.len(),
            signatures.len(),
        ));
    }
    if public_keys.is_empty() {
        return Err(AggregationError::EmptyInput);
    }

    #[cfg(feature = "shadow-integration")]
    if crate::shadow_cost::fake_xmss() {
        let agg_n = public_keys.len();
        let count_bytes = public_keys.len().to_le_bytes();
        let slot_bytes = slot.to_le_bytes();
        let dummy = crate::shadow_cost::fill_fake_proof(
            crate::shadow_cost::fake_proof_size(),
            &[&message.0, &slot_bytes, &count_bytes],
        );
        crate::shadow_cost::sleep(crate::shadow_cost::aggregate_delay(agg_n));
        return Ok(dummy);
    }

    ensure_prover_ready();
    let _permit = prover_permit();

    let raw_xmss: Vec<(LeanSigPublicKey, LeanSigSignature)> = public_keys
        .into_iter()
        .zip(signatures)
        .map(|(pk, sig)| (pk.into_inner(), sig.into_inner()))
        .collect();

    let proof = aggregate_single_message_signatures(&[], raw_xmss, message.0, slot, LOG_INV_RATE)
        .map_err(|err| AggregationError::ProverFailure(err.to_string()))?;

    let result = compress_type1_to_byte_list(&proof)?;
    Ok(result)
}

/// Aggregate both existing Type-1 proofs (children) and raw XMSS signatures.
///
/// Existing Type-1s are reused as recursive children; raw XMSS are mixed in.
/// All inputs must bind to the same `(message, slot)`.
///
/// Requires at least one raw signature OR at least 2 children. A lone child is
/// already a valid Type-1; further aggregation is wasted work.
pub fn aggregate_mixed(
    children: Vec<(Vec<ValidatorPublicKey>, ByteList512KiB)>,
    raw_public_keys: Vec<ValidatorPublicKey>,
    raw_signatures: Vec<ValidatorSignature>,
    message: &H256,
    slot: u32,
) -> Result<ByteList512KiB, AggregationError> {
    if raw_public_keys.len() != raw_signatures.len() {
        return Err(AggregationError::CountMismatch(
            raw_public_keys.len(),
            raw_signatures.len(),
        ));
    }
    if raw_public_keys.is_empty() && children.len() < 2 {
        return Err(AggregationError::InsufficientChildren(children.len()));
    }

    #[cfg(feature = "shadow-integration")]
    if crate::shadow_cost::fake_xmss() {
        let agg_n = raw_public_keys.len();
        let count_bytes = raw_public_keys.len().to_le_bytes();
        let slot_bytes = slot.to_le_bytes();
        let mut parts: Vec<&[u8]> = vec![&message.0, &slot_bytes];
        for (_, proof) in &children {
            parts.push(proof.iter().as_slice());
        }
        parts.push(&count_bytes);
        let dummy =
            crate::shadow_cost::fill_fake_proof(crate::shadow_cost::fake_proof_size(), &parts);
        crate::shadow_cost::sleep(crate::shadow_cost::aggregate_delay(agg_n));
        return Ok(dummy);
    }

    ensure_prover_ready();
    let _permit = prover_permit();

    let children_native: Vec<LMType1> = children
        .into_iter()
        .enumerate()
        .map(|(i, (pubkeys, proof_bytes))| decompress_type1(pubkeys, &proof_bytes, i))
        .collect::<Result<_, _>>()?;

    let raw_xmss: Vec<(LeanSigPublicKey, LeanSigSignature)> = raw_public_keys
        .into_iter()
        .zip(raw_signatures)
        .map(|(pk, sig)| (pk.into_inner(), sig.into_inner()))
        .collect();

    let proof = aggregate_single_message_signatures(
        &children_native,
        raw_xmss,
        message.0,
        slot,
        LOG_INV_RATE,
    )
    .map_err(|err| AggregationError::ProverFailure(err.to_string()))?;

    let result = compress_type1_to_byte_list(&proof)?;
    Ok(result)
}

/// Recursively aggregate two or more already-aggregated Type-1 proofs into one.
///
/// All children must bind to the same `(message, slot)`. Used during block
/// building to compact multiple proofs sharing an `AttestationData`.
pub fn aggregate_proofs(
    children: Vec<(Vec<ValidatorPublicKey>, ByteList512KiB)>,
    message: &H256,
    slot: u32,
) -> Result<ByteList512KiB, AggregationError> {
    if children.len() < 2 {
        return Err(AggregationError::InsufficientChildren(children.len()));
    }

    #[cfg(feature = "shadow-integration")]
    if crate::shadow_cost::fake_xmss() {
        let agg_n = children.len();
        let slot_bytes = slot.to_le_bytes();
        let mut parts: Vec<&[u8]> = vec![&message.0, &slot_bytes];
        for (_, proof) in &children {
            parts.push(proof.iter().as_slice());
        }
        let dummy =
            crate::shadow_cost::fill_fake_proof(crate::shadow_cost::fake_proof_size(), &parts);
        crate::shadow_cost::sleep(crate::shadow_cost::aggregate_delay(agg_n));
        return Ok(dummy);
    }

    ensure_prover_ready();
    let _permit = prover_permit();

    let children_native: Vec<LMType1> = children
        .into_iter()
        .enumerate()
        .map(|(i, (pubkeys, proof_bytes))| decompress_type1(pubkeys, &proof_bytes, i))
        .collect::<Result<_, _>>()?;

    let proof = aggregate_single_message_signatures(
        &children_native,
        vec![],
        message.0,
        slot,
        LOG_INV_RATE,
    )
    .map_err(|err| AggregationError::ProverFailure(err.to_string()))?;

    let result = compress_type1_to_byte_list(&proof)?;
    Ok(result)
}

/// Verify a Type-1 aggregated signature proof.
///
/// Cryptographically verifies that every `public_key` signed `message` at `slot`.
///
/// The verifier checks the bound `(message, slot)` matches what the caller
/// expects, defending against proofs reused from other binding contexts.
pub fn verify_aggregated_signature(
    proof_data: &ByteList512KiB,
    public_keys: Vec<ValidatorPublicKey>,
    message: &H256,
    slot: u32,
) -> Result<(), VerificationError> {
    // Skip the real verifier under fake-XMSS; otherwise verify for real.
    #[cfg(feature = "shadow-integration")]
    if crate::shadow_cost::fake_xmss() {
        let verify_n = public_keys.len();
        // Model verify cost on the virtual clock (no-op unless a rate is set).
        crate::shadow_cost::sleep(crate::shadow_cost::verify_delay(verify_n));
        return Ok(());
    }
    ensure_verifier_ready();

    let lean_pubkeys = into_lean_pubkeys(public_keys);
    let sig = LMType1::from_bytes_without_pubkeys(proof_data.iter().as_slice(), lean_pubkeys)
        .ok_or(VerificationError::DeserializationFailed)?;

    if sig.info.core.message != message.0 || sig.info.core.slot != slot {
        return Err(VerificationError::BindingMismatch {
            expected_msg: *message,
            expected_slot: slot,
            got_msg: H256(sig.info.core.message),
            got_slot: sig.info.core.slot,
        });
    }

    verify_single_message_aggregate(&sig)
        .map_err(|err| VerificationError::VerificationFailed(format!("{err:?}")))?;
    Ok(())
}

// =====================================================================
// Type-2 merge / verify / split (block-level merged proofs)
// =====================================================================

/// Merge many independent Type-1 multi-signatures into a single Type-2 proof.
///
/// Each input is `(participant_pubkeys, type_1_proof_bytes)` where the bytes
/// are the `to_bytes_without_pubkeys()` form of a `SingleMessageAggregateSignature`.
///
/// The returned blob is the `to_bytes_without_pubkeys()` form of the resulting
/// `MultiMessageAggregateSignature`. A verifier decoding it back needs the per-component
/// pubkey sets in the same order.
pub fn merge_type_1s_into_type_2(
    type_1s: Vec<(Vec<ValidatorPublicKey>, ByteList512KiB)>,
) -> Result<ByteList512KiB, AggregationError> {
    if type_1s.is_empty() {
        return Err(AggregationError::EmptyInput);
    }

    #[cfg(feature = "shadow-integration")]
    if crate::shadow_cost::fake_xmss() {
        let merge_n = type_1s.len();
        let count_bytes = type_1s.len().to_le_bytes();
        let mut parts: Vec<&[u8]> = Vec::with_capacity(type_1s.len() + 1);
        for (_, proof) in &type_1s {
            parts.push(proof.iter().as_slice());
        }
        parts.push(&count_bytes);
        let dummy =
            crate::shadow_cost::fill_fake_proof(crate::shadow_cost::fake_proof_size(), &parts);
        crate::shadow_cost::sleep(crate::shadow_cost::merge_delay(merge_n));
        return Ok(dummy);
    }

    ensure_prover_ready();
    let _permit = prover_permit();

    let type_1s_native: Vec<LMType1> = type_1s
        .into_iter()
        .enumerate()
        .map(|(i, (pubkeys, proof_bytes))| decompress_type1(pubkeys, &proof_bytes, i))
        .collect::<Result<_, _>>()?;

    let merged = merge_single_message_aggregates(type_1s_native, LOG_INV_RATE)
        .map_err(|err| AggregationError::ProverFailure(err.to_string()))?;

    let result = compress_type2_to_byte_list(&merged)?;
    Ok(result)
}

/// Verify a Type-2 merged proof against the per-component expected bindings.
///
/// The verifier re-derives each component's `(message, slot, pubkeys)` from the
/// caller-supplied lists, checks they match what the proof binds, and then runs
/// the inner SNARK verifier.
pub fn verify_type_2_signature(
    proof_data: &[u8],
    pubkeys_per_component: Vec<Vec<ValidatorPublicKey>>,
    expected_bindings: &[(H256, u32)],
) -> Result<(), VerificationError> {
    if expected_bindings.len() != pubkeys_per_component.len() {
        return Err(VerificationError::ComponentPubkeyMismatch {
            components: expected_bindings.len(),
            pubkey_sets: pubkeys_per_component.len(),
        });
    }

    #[cfg(feature = "shadow-integration")]
    if crate::shadow_cost::fake_xmss() {
        return Ok(());
    }

    ensure_verifier_ready();

    let pubkeys_per_info: Vec<Vec<LeanSigPublicKey>> = pubkeys_per_component
        .into_iter()
        .map(into_lean_pubkeys)
        .collect();

    let sig = LMType2::from_bytes_without_pubkeys(proof_data, pubkeys_per_info)
        .ok_or(VerificationError::DeserializationFailed)?;

    if sig.info.len() != expected_bindings.len() {
        return Err(VerificationError::Type2ComponentCountMismatch {
            expected: expected_bindings.len(),
            got: sig.info.len(),
        });
    }

    for ((expected_msg, expected_slot), info) in expected_bindings.iter().zip(sig.info.iter()) {
        if info.core.message != expected_msg.0 || info.core.slot != *expected_slot {
            return Err(VerificationError::BindingMismatch {
                expected_msg: *expected_msg,
                expected_slot: *expected_slot,
                got_msg: H256(info.core.message),
                got_slot: info.core.slot,
            });
        }
    }

    verify_multi_message_aggregate(&sig)
        .map_err(|err| VerificationError::VerificationFailed(format!("{err:?}")))?;
    Ok(())
}

/// Split (disaggregate) a Type-2 merged proof into a single Type-1 proof for
/// the component bound to `message`. Generates a fresh SNARK; expensive.
///
/// Mirrors leanSpec PR #717 `split_multi_message_aggregate_by_message`: the caller
/// supplies the expected message (an attestation data root or the block
/// root) and the wrapper locates the unique matching component inside the
/// decompressed proof. Returns the `to_bytes_without_pubkeys()` form of the
/// resulting Type-1.
///
/// `pubkeys_per_component` gives one signer set per component, in the proof's
/// component order; they are not on the wire, so decoding needs them.
pub fn split_type_2_by_message(
    proof_data: &[u8],
    pubkeys_per_component: Vec<Vec<ValidatorPublicKey>>,
    message: &H256,
) -> Result<ByteList512KiB, AggregationError> {
    #[cfg(feature = "shadow-integration")]
    if crate::shadow_cost::fake_xmss() {
        return Ok(crate::shadow_cost::fill_fake_proof(
            crate::shadow_cost::fake_proof_size(),
            &[proof_data, &message.0],
        ));
    }

    ensure_prover_ready();
    let _permit = prover_permit();

    let pubkeys_per_info: Vec<Vec<LeanSigPublicKey>> = pubkeys_per_component
        .into_iter()
        .map(into_lean_pubkeys)
        .collect();

    let type_2 = LMType2::from_bytes_without_pubkeys(proof_data, pubkeys_per_info)
        .ok_or(AggregationError::DeserializationFailed)?;

    let matches: Vec<usize> = type_2
        .info
        .iter()
        .enumerate()
        .filter_map(|(i, info)| (info.core.message == message.0).then_some(i))
        .collect();
    let index = match matches.as_slice() {
        [i] => *i,
        [] => return Err(AggregationError::UnknownMessage),
        _ => return Err(AggregationError::MultipleMessages),
    };

    let component = split_multi_message_aggregate(type_2, index, LOG_INV_RATE)
        .map_err(|err| AggregationError::ProverFailure(err.to_string()))?;

    compress_type1_to_byte_list(&component)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lean_multisig::{xmss_key_gen_from_seed, xmss_sign};
    use ssz::Encode as _;

    /// Generate a test keypair and sign a message.
    ///
    /// Note: This is slow because XMSS key generation is computationally expensive.
    fn generate_keypair_and_sign(
        seed: u64,
        activation_epoch: u32,
        signing_epoch: u32,
        message: &H256,
    ) -> (ValidatorPublicKey, ValidatorSignature) {
        let mut seed_bytes = [0u8; 32];
        seed_bytes[..8].copy_from_slice(&seed.to_le_bytes());

        // Small active range (starting at the activation epoch and covering the
        // signing slot) for fast key generation.
        let num_active_slots = 64u64;
        let (pk, sk) =
            xmss_key_gen_from_seed(seed_bytes, activation_epoch as u64, num_active_slots)
                .expect("valid activation range");

        let sig = xmss_sign(&sk, signing_epoch, &message.0).expect("sign");

        // Convert to ethlambda types via SSZ wire bytes.
        let validator_pk = ValidatorPublicKey::from_bytes(&pk.as_ssz_bytes()).unwrap();
        let validator_sig = ValidatorSignature::from_bytes(&sig.as_ssz_bytes()).unwrap();

        (validator_pk, validator_sig)
    }

    #[test]
    #[ignore = "slow: compiles the leanVM aggregation bytecode (needs a release-sized stack)"]
    fn test_setup_is_idempotent() {
        // Should not panic when called multiple times. The first call compiles
        // the self-referential aggregation bytecode; subsequent calls are cheap
        // (`OnceLock::get_or_init`).
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

    /// The signer set is not carried on the wire, so it is the caller-supplied
    /// set that binds a proof to its participants. Supplying a different set of
    /// the same size must be rejected: the proof commits to a hash of the set,
    /// so it fails inside the SNARK verifier rather than at decode.
    #[test]
    #[ignore = "too slow"]
    fn test_verify_wrong_pubkey_set_fails() {
        let message = H256::from([42u8; 32]);
        let slot = 10u32;

        let (pk, sig) = generate_keypair_and_sign(1, 5, slot, &message);
        let (other_pk, _) = generate_keypair_and_sign(2, 5, slot, &message);

        let proof_data = aggregate_signatures(vec![pk], vec![sig], &message, slot).unwrap();

        let verify_result =
            verify_aggregated_signature(&proof_data, vec![other_pk], &message, slot);
        assert!(
            verify_result.is_err(),
            "Verification should have failed with a different signer set"
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
            merged.iter().as_slice(),
            vec![vec![pk_a.clone()], vec![pk_b.clone()]],
            &[(msg_a, slot_a), (msg_b, slot_b)],
        )
        .expect("verify type-2");

        let split = split_type_2_by_message(
            merged.iter().as_slice(),
            vec![vec![pk_a.clone()], vec![pk_b.clone()]],
            &msg_a,
        )
        .expect("split");

        verify_aggregated_signature(&split, vec![pk_a.clone()], &msg_a, slot_a)
            .expect("verify split");
    }
}
