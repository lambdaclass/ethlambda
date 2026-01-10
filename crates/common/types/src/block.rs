use leansig::{signature::SignatureScheme, serialization::Serializable};
use ssz_derive::{Decode, Encode};
use ssz_types::typenum::{Diff, U488, U3600, U4096};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;
use thiserror::Error;
use crate::{
    attestation::{Attestation, Attestations},
    primitives::H256,
    signature::{LeanPublicKey, LeanSignatureScheme, Signature, SignatureSize},
    state::{State, ValidatorRegistryLimit},
};

/// Envelope carrying a block, an attestation from proposer, and aggregated signatures.
#[derive(Clone, Encode, Decode)]
pub struct SignedBlockWithAttestation {
    /// The block plus an attestation from proposer being signed.
    pub message: BlockWithAttestation,

    /// Aggregated signature payload for the block.
    ///
    /// Signatures remain in attestation order followed by the proposer signature
    /// over entire message. For devnet 1, however the proposer signature is just
    /// over message.proposer_attestation since leanVM is not yet performant enough
    /// to aggregate signatures with sufficient throughput.
    ///
    /// Eventually this field will be replaced by a SNARK (which represents the
    /// aggregation of all signatures).
    pub signature: BlockSignatures,
}

#[derive(Error, Debug)]
pub enum VerifySignatureError {
    #[error("Number of signatures {0} does not match number of attestations {1}")]
    NumberOfSignaturesMismatch(usize, usize),
    #[error("Validator {0} index out of range")]
    ValidatorOutOfRange(u64),
    #[error("Failed to deserialize public key")]
    PublicKeyDeserializationError,
    #[error("Failed to deserialize signature")]
    SignatureDeserializationError,
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
}

impl SignedBlockWithAttestation {
    /// Verify all XMSS signatures in this signed block.

    /// This function ensures that every attestation included in the block
    /// (both on-chain attestations from the block body and the proposer's
    /// own attestation) is properly signed by the claimed validator using
    /// their registered XMSS public key.
    pub fn verify_signatures(&self, parent_state: &State) -> Result<bool, VerifySignatureError> {
        let block = &self.message.block;
        let signature = &self.signature;
        
        let all_attestations: Vec<_> = block.body.attestations
            .iter()
            .chain(std::iter::once(&self.message.proposer_attestation))
            .collect();
        
        let validators = &parent_state.validators;
        
        if signature.len() != all_attestations.len() {
            return Err(VerifySignatureError::NumberOfSignaturesMismatch(signature.len(), all_attestations.len()));
        }
        
        for (attestation, signature) in all_attestations.iter().zip(signature.iter()) {
            let validator_id = attestation.validator_id;
            
            // Ensure validator is in the active set
            if validator_id < validators.len() as u64 {
                return Err(VerifySignatureError::ValidatorOutOfRange(validator_id));
            }
            
            let validator = &validators[validator_id as usize];
            
            // Verify the XMSS signature
            let lean_public_key = LeanPublicKey::from_bytes(&validator.pubkey).map_err(|_| VerifySignatureError::PublicKeyDeserializationError)?;
            let lean_signature = Signature::from_bytes(signature).map_err(|_| VerifySignatureError::SignatureDeserializationError)?;
            if !LeanSignatureScheme::verify(&lean_public_key, attestation.data.slot as u32, &attestation.tree_hash_root(), &lean_signature) {
                return Err(VerifySignatureError::SignatureVerificationFailed);
            }
        }
        
        
        Ok(true)
    }
}

// Manual Debug impl because leanSig signatures don't implement Debug.
impl core::fmt::Debug for SignedBlockWithAttestation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignedBlockWithAttestation")
            .field("message", &self.message)
            .field("signature", &"...")
            .finish()
    }
}

/// Aggregated signature list included alongside the block.
pub type BlockSignatures =
    ssz_types::VariableList<ssz_types::FixedVector<u8, SignatureSize>, ValidatorRegistryLimit>;

/// Bundle containing a block and the proposer's attestation.
#[derive(Debug, Clone, Encode, Decode, TreeHash)]
pub struct BlockWithAttestation {
    /// The proposed block message.
    pub block: Block,

    /// The proposer's attestation corresponding to this block.
    pub proposer_attestation: Attestation,
}

/// The header of a block, containing metadata.
///
/// Block headers summarize blocks without storing full content. The header
/// includes references to the parent and the resulting state. It also contains
/// a hash of the block body.
///
/// Headers are smaller than full blocks. They're useful for tracking the chain
/// without storing everything.
#[derive(Debug, Clone, Encode, Decode, TreeHash)]
pub struct BlockHeader {
    /// The slot in which the block was proposed
    pub slot: u64,
    /// The index of the validator that proposed the block
    pub proposer_index: u64,
    /// The root of the parent block
    pub parent_root: H256,
    /// The root of the state after applying transactions in this block
    pub state_root: H256,
    /// The root of the block body
    pub body_root: H256,
}

/// A complete block including header and body.
#[derive(Debug, Clone, Encode, Decode, TreeHash)]
pub struct Block {
    /// The slot in which the block was proposed.
    pub slot: u64,
    /// The index of the validator that proposed the block.
    pub proposer_index: u64,
    /// The root of the parent block.
    pub parent_root: H256,
    /// The root of the state after applying transactions in this block.
    pub state_root: H256,
    /// The block's payload.
    pub body: BlockBody,
}

/// The body of a block, containing payload data.
///
/// Currently, the main operation is voting. Validators submit attestations which are
/// packaged into blocks.
#[derive(Debug, Default, Clone, Encode, Decode, TreeHash)]
pub struct BlockBody {
    /// Plain validator attestations carried in the block body.
    ///
    /// Individual signatures live in the aggregated block signature list, so
    /// these entries contain only attestation data without per-attestation signatures.
    pub attestations: Attestations,
}
