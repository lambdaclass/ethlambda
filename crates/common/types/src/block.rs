use serde::{Serialize, Serializer, ser::SerializeSeq};

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::SszList;

use crate::{
    attestation::{AggregatedAttestation, AggregationBits, validator_indices},
    primitives::{self, ByteList, H256},
};

// Convenience trait for calling hash_tree_root() without a hasher argument
use primitives::HashTreeRoot as _;

/// Envelope carrying a block and the single merged proof binding every
/// signature it depends on.
///
/// <div class="warning">
///
/// `HashTreeRoot` is intentionally not derived: consumers never hash a
/// `SignedBlock` directly — they always hash the inner `Block`. Keeping the
/// envelope structurally minimal also means the on-chain root is independent
/// of how the merged proof is serialised.
///
/// </div>
#[derive(Clone, SszEncode, SszDecode)]
pub struct SignedBlock {
    /// The block being signed.
    pub message: Block,

    /// Single full-block proof covering attestations and the proposer signature.
    pub proof: MultiMessageAggregate,
}

// Manual Debug impl because the merged proof bytes are large and opaque.
impl core::fmt::Debug for SignedBlock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignedBlock")
            .field("message", &self.message)
            .field("proof", &format_args!("<{} bytes>", self.proof.proof.len()))
            .finish()
    }
}

/// 512 KiB byte-list cap shared by every block-level / Type-1 proof field.
/// Matches leanSpec PR #717's `ByteList512KiB` SSZ container.
pub type ByteList512KiB = ByteList<524_288>;

/// A merged proof covering multiple messages with a single proof blob.
///
/// The proof bytes use lean-multisig's compact public-key-free
/// representation. SSZ encoding this container adds the offset required for
/// its variable-length field.
#[derive(Debug, Default, Clone, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
pub struct MultiMessageAggregate {
    /// Serialized multi-message aggregate proof bytes.
    pub proof: ByteList512KiB,
}

impl MultiMessageAggregate {
    /// Build an aggregate from an already bounded proof byte list.
    pub fn new(proof: ByteList512KiB) -> Self {
        Self { proof }
    }

    /// Copy raw lean-multisig proof bytes into the bounded SSZ container.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MultiMessageAggregateError> {
        let len = bytes.len();
        ByteList512KiB::try_from(bytes.to_vec())
            .map(Self::new)
            .map_err(|_| MultiMessageAggregateError::ProofTooLarge(len))
    }

    /// Return the raw lean-multisig proof bytes.
    pub fn proof_bytes(&self) -> &[u8] {
        self.proof.iter().as_slice()
    }
}

/// Errors returned when constructing a [`MultiMessageAggregate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MultiMessageAggregateError {
    /// Proof bytes exceed `ByteList512KiB`'s cap.
    #[error("proof {0} bytes exceeds 512 KiB cap")]
    ProofTooLarge(usize),
}

// ============================================================================
// Type-1 multi-signature
// ============================================================================
//
// Wire format mirrors leanSpec PR #717: `TypeOneMultiSignature` is a flat
// `{ participants, proof }` pair. The signed `message` and `slot` are NOT
// carried on the envelope — verifiers rederive each component's binding
// from the surrounding block body (attestation `data` + slot for body
// components, block root + slot for the proposer component).
//
// `MultiMessageAggregate` carries the raw lean-multisig Type-2 bytes.
// Component participant bitfields come from
// `block.body.attestations[i].aggregation_bits` (and `block.proposer_index` for
// the trailing proposer entry).

/// Maximum number of distinct `AttestationData` entries permitted in a single
/// block. Canonical home for the cap shared across `ethlambda-blockchain`,
/// `ethlambda-test-fixtures`, and the wire types in this crate.
pub const MAX_ATTESTATIONS_DATA: usize = 8;

/// A Type-1 single-message proof aggregating signatures from many validators.
///
/// Used:
///   - as a gossip-level `SignedAggregatedAttestation.proof`,
///   - as an in-memory entry in the aggregated payload pool,
///   - as one of the components fed into `merge_type_1s_into_type_2` when
///     building a block proof.
///
/// `participants` and `proof` are independent fields: the proof bytes are
/// the lean-multisig `compress_without_pubkeys()` form; `participants` is
/// the bitfield identifying which validators are bound by the proof. The
/// verifier resolves pubkeys from `participants` at verify time.
#[derive(Debug, Clone, SszEncode, SszDecode, HashTreeRoot)]
pub struct TypeOneMultiSignature {
    /// Bitfield identifying validators bound by this proof.
    pub participants: AggregationBits,
    /// Aggregated proof bytes in lean-multisig compact (no-pubkeys) form.
    pub proof: ByteList512KiB,
}

impl TypeOneMultiSignature {
    /// Build a Type-1 proof carrying the given participants and proof bytes.
    pub fn new(participants: AggregationBits, proof: ByteList512KiB) -> Self {
        Self {
            participants,
            proof,
        }
    }

    /// Build a Type-1 proof carrying the given participants and EMPTY proof
    /// bytes. Useful as a placeholder in fork-choice payload caches where only
    /// the participant set is needed; cannot drive a real Type-2 merge or
    /// pass cryptographic verification.
    pub fn empty(participants: AggregationBits) -> Self {
        Self::new(participants, SszList::new())
    }

    /// Wrap a proposer's Type-1 proof bytes with the singleton participant set.
    ///
    /// The bytes must be a real aggregated Type-1 over the proposer's XMSS
    /// signature (e.g. from `ethlambda_crypto::aggregate_signatures`), not
    /// raw XMSS bytes — `verify_type_2` rejects raw-XMSS placeholders.
    pub fn for_proposer(proposer_index: u64, proposer_proof_bytes: ByteList512KiB) -> Self {
        let mut participants = AggregationBits::with_length(proposer_index as usize + 1)
            .expect("validator index fits");
        participants
            .set(proposer_index as usize, true)
            .expect("index within capacity");
        Self::new(participants, proposer_proof_bytes)
    }

    /// Returns the validator indices that are set in the participants bitfield.
    pub fn participant_indices(&self) -> impl Iterator<Item = u64> + '_ {
        validator_indices(&self.participants)
    }
}

/// The header of a block, containing metadata.
///
/// Block headers summarize blocks without storing full content. The header
/// includes references to the parent and the resulting state. It also contains
/// a hash of the block body.
///
/// Headers are smaller than full blocks. They're useful for tracking the chain
/// without storing everything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, SszEncode, SszDecode, HashTreeRoot)]
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
#[derive(Debug, Clone, Serialize, SszEncode, SszDecode, HashTreeRoot)]
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

impl Block {
    /// Extract the block header, computing the body root.
    pub fn header(&self) -> BlockHeader {
        BlockHeader {
            slot: self.slot,
            proposer_index: self.proposer_index,
            parent_root: self.parent_root,
            state_root: self.state_root,
            body_root: self.body.hash_tree_root(),
        }
    }

    /// Reconstruct a block from header and body.
    ///
    /// The caller should ensure that `header.body_root` matches `body.hash_tree_root()`.
    /// This is verified with a debug assertion but not in release builds.
    pub fn from_header_and_body(header: BlockHeader, body: BlockBody) -> Self {
        debug_assert_eq!(
            header.body_root,
            body.hash_tree_root(),
            "body root mismatch"
        );
        Self {
            slot: header.slot,
            proposer_index: header.proposer_index,
            parent_root: header.parent_root,
            state_root: header.state_root,
            body,
        }
    }
}

/// The body of a block, containing payload data.
///
/// Currently, the main operation is voting. Validators submit attestations which are
/// packaged into blocks.
#[derive(Debug, Default, Clone, Serialize, SszEncode, SszDecode, HashTreeRoot)]
pub struct BlockBody {
    /// Plain validator attestations carried in the block body.
    ///
    /// Individual signatures live in the aggregated block signature list, so
    /// these entries contain only attestation data without per-attestation signatures.
    #[serde(serialize_with = "serialize_attestations")]
    pub attestations: AggregatedAttestations,
}

/// List of aggregated attestations included in a block.
pub type AggregatedAttestations = SszList<AggregatedAttestation, 4096>;

fn serialize_attestations<S>(
    attestations: &AggregatedAttestations,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut seq = serializer.serialize_seq(Some(attestations.len()))?;
    for attestation in attestations.iter() {
        seq.serialize_element(attestation)?;
    }
    seq.end()
}

#[cfg(test)]
mod tests {
    use super::*;
    use libssz::{SszDecode, SszEncode};

    fn sample_bits(len: usize, set: &[usize]) -> AggregationBits {
        let mut b = AggregationBits::with_length(len).unwrap();
        for &i in set {
            b.set(i, true).unwrap();
        }
        b
    }

    #[test]
    fn type_one_multi_signature_ssz_round_trip() {
        let proof_bytes: Vec<u8> = (0..64).collect();
        let sig = TypeOneMultiSignature {
            participants: sample_bits(8, &[0, 3, 7]),
            proof: ByteList512KiB::try_from(proof_bytes.clone()).unwrap(),
        };
        let bytes = sig.to_ssz();
        let decoded = TypeOneMultiSignature::from_ssz_bytes(&bytes).expect("decode");
        assert_eq!(decoded.proof.to_vec(), proof_bytes);
        assert_eq!(decoded.participants.as_bytes(), sig.participants.as_bytes());
    }

    #[test]
    fn signed_block_ssz_round_trip_empty_proof() {
        let block = Block {
            slot: 7,
            proposer_index: 3,
            parent_root: H256::ZERO,
            state_root: H256::ZERO,
            body: BlockBody::default(),
        };
        let signed = SignedBlock {
            message: block,
            proof: MultiMessageAggregate::default(),
        };
        let bytes = signed.to_ssz();
        let decoded = SignedBlock::from_ssz_bytes(&bytes).expect("decode");
        assert_eq!(decoded.proof.proof.len(), 0);
        assert_eq!(decoded.message.slot, signed.message.slot);
        assert_eq!(
            decoded.message.proposer_index,
            signed.message.proposer_index
        );
    }

    #[test]
    fn multi_message_aggregate_ssz_wraps_proof_bytes() {
        let proof_bytes: Vec<u8> = (0..64).collect();
        let aggregate = MultiMessageAggregate::from_bytes(&proof_bytes).unwrap();

        let encoded = aggregate.to_ssz();

        assert_eq!(&encoded[..4], &4u32.to_le_bytes());
        assert_eq!(&encoded[4..], proof_bytes);
        assert_eq!(aggregate.proof_bytes(), proof_bytes);
    }
}
