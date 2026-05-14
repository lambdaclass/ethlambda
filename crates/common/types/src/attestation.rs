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
///
/// <div class="warning">
///
/// `HashTreeRoot` is intentionally not derived: `XmssSignature` is a fixed-size
/// byte vector for cross-client serialization but the spec Merkleizes it as a
/// container, so roots would diverge. No code hashes `SignedAttestation`.
///
/// </div>
#[derive(Debug, Clone, SszEncode, SszDecode)]
pub struct SignedAttestation {
    /// The index of the validator making the attestation.
    pub validator_id: u64,
    /// The attestation data signed by the validator.
    pub data: AttestationData,
    /// Signature aggregation produced by the leanVM (SNARKs in the future).
    pub signature: XmssSignature,
}

/// XMSS signature as a fixed-length byte vector (`SIGNATURE_SIZE` bytes).
pub type XmssSignature = SszVector<u8, SIGNATURE_SIZE>;

/// SSZ offset (in bytes) of the `path` body inside an XMSS `Signature` container.
///
/// Layout: 4-byte path offset + 28-byte rho + 4-byte hashes offset = 36.
const SIGNATURE_PATH_OFFSET: u32 = 36;

/// SSZ offset (in bytes) of the `hashes` body inside an XMSS `Signature`.
///
/// `path` body is 4-byte siblings offset + LOG_LIFETIME (32) siblings × 32-byte
/// digest = 1028, starting at byte 36, so hashes start at 36 + 1028 = 1064.
const SIGNATURE_HASHES_OFFSET: u32 = 1064;

/// SSZ offset (in bytes) of the `siblings` list inside the `path` container.
const SIGNATURE_PATH_SIBLINGS_OFFSET: u32 = 4;

/// Build a placeholder XMSS signature that decodes as a structurally valid
/// leanSpec `Signature` container of all-zero hashes.
///
/// Used for genesis-style anchor blocks that were never proposed and therefore
/// have no real signature. Parent containers inline this as an opaque
/// `SIGNATURE_SIZE`-byte blob; consumers that decode the inner `Signature`
/// container see `path = HashTreeOpening { siblings = [0; 32] }`, `rho = 0`,
/// `hashes = [0; 46]`. Matches ream's `Signature::blank()` so the wire format
/// is byte-identical across clients.
pub fn blank_xmss_signature() -> XmssSignature {
    let mut bytes = vec![0u8; SIGNATURE_SIZE];
    bytes[..4].copy_from_slice(&SIGNATURE_PATH_OFFSET.to_le_bytes());
    bytes[32..36].copy_from_slice(&SIGNATURE_HASHES_OFFSET.to_le_bytes());
    bytes[36..40].copy_from_slice(&SIGNATURE_PATH_SIBLINGS_OFFSET.to_le_bytes());
    XmssSignature::try_from(bytes).expect("size matches SIGNATURE_SIZE")
}

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

/// Returns `true` iff every bit set in `a` is also set in `b` (i.e., `a` is a subset of `b`).
pub fn bits_is_subset(a: &AggregationBits, b: &AggregationBits) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    for (i, &a_byte) in a_bytes.iter().enumerate() {
        if a_byte == 0 {
            continue;
        }
        let b_byte = b_bytes.get(i).copied().unwrap_or(0);
        if a_byte & !b_byte != 0 {
            return false;
        }
    }
    true
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an `AggregationBits` of `len` bits with the indices in `set` flipped on.
    fn bits(len: usize, set: &[usize]) -> AggregationBits {
        let mut b = AggregationBits::with_length(len).unwrap();
        for &i in set {
            b.set(i, true).unwrap();
        }
        b
    }

    #[test]
    fn subset_empty_bitlists() {
        let empty = AggregationBits::new();
        assert!(bits_is_subset(&empty, &empty));
    }

    #[test]
    fn subset_empty_a_is_subset_of_anything() {
        let empty = AggregationBits::new();
        let b = bits(8, &[0, 3, 7]);
        assert!(bits_is_subset(&empty, &b));
    }

    #[test]
    fn subset_zero_bits_a_is_subset_of_empty() {
        // a has length but no set bits: byte iteration skips zero bytes, so it's a subset of empty.
        let a = bits(8, &[]);
        let empty = AggregationBits::new();
        assert!(bits_is_subset(&a, &empty));
    }

    #[test]
    fn subset_nonempty_a_is_not_subset_of_empty() {
        let a = bits(8, &[2]);
        let empty = AggregationBits::new();
        assert!(!bits_is_subset(&a, &empty));
    }

    #[test]
    fn subset_reflexive_equal_bitlists() {
        let a = bits(16, &[0, 1, 5, 9, 15]);
        let b = bits(16, &[0, 1, 5, 9, 15]);
        assert!(bits_is_subset(&a, &b));
        assert!(bits_is_subset(&b, &a));
    }

    #[test]
    fn subset_strict_subset_returns_true() {
        let a = bits(8, &[1, 4]);
        let b = bits(8, &[1, 4, 6]);
        assert!(bits_is_subset(&a, &b));
        assert!(!bits_is_subset(&b, &a));
    }

    #[test]
    fn subset_disjoint_bits_returns_false() {
        let a = bits(8, &[0, 2]);
        let b = bits(8, &[1, 3]);
        assert!(!bits_is_subset(&a, &b));
        assert!(!bits_is_subset(&b, &a));
    }

    #[test]
    fn subset_partial_overlap_returns_false() {
        // a shares bit 1 with b but also has bit 5 that b lacks.
        let a = bits(8, &[1, 5]);
        let b = bits(8, &[0, 1, 2]);
        assert!(!bits_is_subset(&a, &b));
    }

    #[test]
    fn subset_a_shorter_than_b_with_bits_in_b() {
        // a has 8 bits, b has 16 bits. a's set bits are all present in b.
        let a = bits(8, &[1, 4]);
        let b = bits(16, &[1, 4, 11]);
        assert!(bits_is_subset(&a, &b));
    }

    #[test]
    fn subset_a_longer_than_b_with_zero_tail_is_subset() {
        // a has 16 bits but only sets bit 2; b has 8 bits with the same bit set.
        // a's tail byte is zero, so the loop skips it.
        let a = bits(16, &[2]);
        let b = bits(8, &[2]);
        assert!(bits_is_subset(&a, &b));
    }

    #[test]
    fn subset_a_longer_than_b_with_set_bit_past_b_returns_false() {
        // a sets bit 9 (byte 1) but b only has 8 bits (1 byte). Missing bytes in b are
        // treated as zero, so any bit in a's tail breaks the subset relation.
        let a = bits(16, &[9]);
        let b = bits(8, &[]);
        assert!(!bits_is_subset(&a, &b));
    }

    #[test]
    fn subset_multi_byte_bitlists() {
        // Spans multiple bytes (24 bits = 3 bytes) to exercise the byte-by-byte loop.
        let a = bits(24, &[0, 8, 16]);
        let b = bits(24, &[0, 1, 8, 9, 16, 17]);
        assert!(bits_is_subset(&a, &b));
        assert!(!bits_is_subset(&b, &a));
    }

    #[test]
    fn subset_violation_in_later_byte_returns_false() {
        // a's first byte matches b, but bit 17 (in byte 2) is set in a only.
        let a = bits(24, &[0, 1, 17]);
        let b = bits(24, &[0, 1, 16]);
        assert!(!bits_is_subset(&a, &b));
    }
}
