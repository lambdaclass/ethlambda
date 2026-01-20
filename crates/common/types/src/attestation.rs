use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

use crate::{signature::SignatureSize, state::Checkpoint};

/// Validator specific attestation wrapping shared attestation data.
#[derive(Debug, Clone, Encode, Decode, TreeHash)]
pub struct Attestation {
    /// The index of the validator making the attestation.
    pub validator_id: u64,

    /// The attestation data produced by the validator.
    pub data: AttestationData,
}

/// Attestation content describing the validator's observed chain view.
#[derive(Debug, Clone, Encode, Decode, TreeHash)]
pub struct AttestationData {
    /// The slot for which the attestation is made.
    pub slot: u64,

    /// The checkpoint representing the head block as observed by the validator.
    pub head: Checkpoint,

    /// The checkpoint representing the target block as observed by the validator.
    pub target: Checkpoint,

    /// The checkpoint representing the source block as observed by the validator.
    pub source: Checkpoint,
}

/// Validator attestation bundled with its signature.
#[derive(Debug, Clone, Encode, Decode)]
pub struct SignedAttestation {
    /// The index of the validator making the attestation.
    pub validator_id: u64,
    /// The attestation message signed by the validator.
    pub message: AttestationData,
    /// Signature aggregation produced by the leanVM (SNARKs in the future).
    pub signature: XmssSignature,
}

pub type XmssSignature = ssz_types::FixedVector<u8, SignatureSize>;
