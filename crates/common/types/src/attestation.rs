use crate::{
    block::AggregatedSignatureProof,
    checkpoint::Checkpoint,
    primitives::{
        SszBitlist, SszVector,
        ssz::{HashTreeRoot, SszDecode, SszEncode},
    },
    signature::SIGNATURE_SIZE,
};

/// Validator specific attestation wrapping shared attestation data.
#[derive(Debug, Clone, SszEncode, SszDecode, HashTreeRoot)]
pub struct Attestation {
    /// The index of the validator making the attestation.
    pub validator_id: u64,

    /// The attestation data produced by the validator.
    pub data: AttestationData,
}

/// Attestation content describing the validator's observed chain view.
#[derive(Debug, Clone, SszEncode, SszDecode, HashTreeRoot)]
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
#[derive(Debug, Clone, SszEncode, SszDecode)]
pub struct SignedAttestation {
    /// The index of the validator making the attestation.
    pub validator_id: u64,
    /// The attestation data signed by the validator.
    pub data: AttestationData,
    /// Signature aggregation produced by the leanVM (SNARKs in the future).
    pub signature: XmssSignature,
}

/// XMSS signature as a fixed-length byte vector (3112 bytes).
pub type XmssSignature = SszVector<u8, SIGNATURE_SIZE>;

/// Aggregated attestation consisting of participation bits and message.
#[derive(Debug, Clone, SszEncode, SszDecode, HashTreeRoot)]
pub struct AggregatedAttestation {
    /// Bitfield indicating which validators participated in the aggregation.
    pub aggregation_bits: AggregationBits,

    /// Combined attestation data similar to the beacon chain format.
    ///
    /// Multiple validator attestations are aggregated here without the complexity of
    /// committee assignments.
    pub data: AttestationData,
}

/// Bitlist representing validator participation in an attestation or signature.
///
/// A general-purpose bitfield for tracking which validators have participated
/// in some collective action (attestation, signature aggregation, etc.).
pub type AggregationBits = SszBitlist<4096>;

/// Returns the indices of set bits in an `AggregationBits` bitfield as validator IDs.
pub fn validator_indices(bits: &AggregationBits) -> impl Iterator<Item = u64> + '_ {
    (0..bits.len()).filter_map(move |i| {
        if bits.get(i) == Some(true) {
            Some(i as u64)
        } else {
            None
        }
    })
}

/// Aggregated attestation with its signature proof, used for gossip on the aggregation topic.
#[derive(Debug, Clone, SszEncode, SszDecode)]
pub struct SignedAggregatedAttestation {
    pub data: AttestationData,
    pub proof: AggregatedSignatureProof,
}
