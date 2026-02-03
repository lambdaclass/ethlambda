use ethlambda_types::{
    block::AggregatedSignatureProof, primitives::ssz, signature::ValidatorSignature,
};

/// Gossip signature stored with slot for pruning.
///
/// Signatures are stored alongside the slot they pertain to, enabling
/// simple slot-based pruning when blocks become finalized.
#[derive(Debug, Clone, ssz::Encode, ssz::Decode)]
pub struct StoredSignature {
    pub slot: u64,
    pub signature_bytes: Vec<u8>,
}

impl StoredSignature {
    pub fn new(slot: u64, signature: ValidatorSignature) -> Self {
        Self {
            slot,
            signature_bytes: signature.to_bytes(),
        }
    }

    pub fn to_validator_signature(&self) -> Result<ValidatorSignature, ssz::DecodeError> {
        ValidatorSignature::from_bytes(&self.signature_bytes)
    }
}

/// Aggregated payload stored with slot for pruning.
///
/// Aggregated signature proofs are stored with their slot to enable
/// pruning when blocks become finalized.
#[derive(Debug, Clone, ssz::Encode, ssz::Decode)]
pub struct StoredAggregatedPayload {
    pub slot: u64,
    pub proof: AggregatedSignatureProof,
}
