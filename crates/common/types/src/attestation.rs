use ssz_types::typenum::N4096;

use crate::state::Checkpoint;

/// Validator specific attestation wrapping shared attestation data.
pub struct Attestation {
    /// The index of the validator making the attestation.
    pub validator_id: u64,

    /// The attestation data produced by the validator.
    pub data: AttestationData,
}

/// Attestation content describing the validator's observed chain view.
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
pub type Attestations = ssz_types::VariableList<Attestation, N4096>;
