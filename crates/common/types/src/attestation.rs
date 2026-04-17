use libssz::SszEncode as _;
use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::{SszBitlist, SszVector};
use serde::{Serialize, Serializer};

use crate::{
    block::AggregatedSignatureProof,
    checkpoint::Checkpoint,
    primitives::{H256, HashTreeRoot as _},
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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, SszEncode, SszDecode, HashTreeRoot)]
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
#[derive(Debug, Clone, SszEncode, SszDecode, HashTreeRoot)]
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
#[derive(Debug, Clone, Serialize, SszEncode, SszDecode, HashTreeRoot)]
pub struct AggregatedAttestation {
    /// Bitfield indicating which validators participated in the aggregation.
    #[serde(serialize_with = "serialize_aggregation_bits")]
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

/// Serialize an `AggregationBits` bitlist as a `0x`-prefixed hex string of its
/// SSZ encoding (matching the beacon API convention).
fn serialize_aggregation_bits<S>(bits: &AggregationBits, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let encoded = format!("0x{}", hex::encode(bits.to_ssz()));
    serializer.serialize_str(&encoded)
}

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
#[derive(Debug, Clone, SszEncode, SszDecode, HashTreeRoot)]
pub struct SignedAggregatedAttestation {
    pub data: AttestationData,
    pub proof: AggregatedSignatureProof,
}

/// Attestation data paired with its precomputed tree hash root.
///
/// Private fields ensure that `root == data.tree_hash_root()` is always true.
/// The only way to construct this is via [`HashedAttestationData::new`] or
/// [`From<AttestationData>`], both of which compute the root from the data.
#[derive(Debug, Clone)]
pub struct HashedAttestationData {
    root: H256,
    data: AttestationData,
}

impl HashedAttestationData {
    pub fn new(data: AttestationData) -> Self {
        Self {
            root: data.hash_tree_root(),
            data,
        }
    }

    pub fn root(&self) -> H256 {
        self.root
    }

    pub fn data(&self) -> &AttestationData {
        &self.data
    }

    pub fn into_parts(self) -> (H256, AttestationData) {
        (self.root, self.data)
    }
}

impl From<AttestationData> for HashedAttestationData {
    fn from(data: AttestationData) -> Self {
        Self::new(data)
    }
}
