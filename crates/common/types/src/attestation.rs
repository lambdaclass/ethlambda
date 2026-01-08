use ssz_derive::{Decode, Encode};
use ssz_types::typenum::U4096;
use tree_hash_derive::TreeHash;

use crate::{signature::Signature, state::Checkpoint};

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

/// List of validator attestations included in a block.
/// Size limited to [`crate::state::VALIDATOR_REGISTRY_LIMIT`].
pub type Attestations = ssz_types::VariableList<Attestation, U4096>;

/// Validator attestation bundled with its signature.
#[derive(Clone, Encode, Decode)]
pub struct SignedAttestation {
    /// The attestation message signed by the validator.
    message: Attestation,
    /// Signature aggregation produced by the leanVM (SNARKs in the future).
    signature: Signature,
}
