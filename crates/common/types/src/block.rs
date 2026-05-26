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
/// `proof` holds the SSZ-encoded form of a [`TypeTwoMultiSignature`]
/// container whose only field is a `ByteList512KiB` holding the raw
/// `compress_without_pubkeys()` Type-2 merged proof bytes. On the wire the
/// container collapses to `[4-byte offset = 4][type2_wire]` — a thin
/// 4-byte prefix in front of the lean-multisig bytes (leanSpec PR #717).
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

    /// SSZ-encoded `TypeTwoMultiSignature` envelope. Use
    /// [`SignedBlock::merged_proof_bytes`] to extract the raw
    /// lean-multisig Type-2 bytes inside, or
    /// [`SignedBlock::wrap_merged_proof`] when building an envelope from
    /// the prover output.
    pub proof: ByteList512KiB,
}

impl SignedBlock {
    /// Strip the SSZ-container offset header to return the raw
    /// lean-multisig Type-2 merged proof bytes the verifier consumes.
    pub fn merged_proof_bytes(&self) -> Result<&[u8], ProofEnvelopeError> {
        let bytes = self.proof.iter().as_slice();
        if bytes.len() < 4 {
            return Err(ProofEnvelopeError::TruncatedEnvelope);
        }
        let mut header = [0u8; 4];
        header.copy_from_slice(&bytes[..4]);
        let offset = u32::from_le_bytes(header) as usize;
        if offset != 4 {
            return Err(ProofEnvelopeError::UnexpectedOffset(offset));
        }
        Ok(&bytes[4..])
    }

    /// Wrap raw lean-multisig Type-2 bytes into a `SignedBlock.proof`
    /// envelope: prepend the 4-byte SSZ offset header so the wire matches
    /// the spec's `TypeTwoMultiSignature { proof: ByteList512KiB }`
    /// container.
    pub fn wrap_merged_proof(type2_wire: &[u8]) -> Result<ByteList512KiB, ProofEnvelopeError> {
        let mut wrapped = Vec::with_capacity(4 + type2_wire.len());
        wrapped.extend_from_slice(&4u32.to_le_bytes());
        wrapped.extend_from_slice(type2_wire);
        let len = wrapped.len();
        ByteList512KiB::try_from(wrapped).map_err(|_| ProofEnvelopeError::ExceedsCap(len))
    }
}

/// Errors returned by the [`SignedBlock`] proof-envelope helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofEnvelopeError {
    /// Envelope is shorter than the 4-byte SSZ offset header.
    TruncatedEnvelope,
    /// Offset header is not the expected single-field value `4`.
    UnexpectedOffset(usize),
    /// Wrapped proof would exceed `ByteList512KiB`'s cap.
    ExceedsCap(usize),
}

impl core::fmt::Display for ProofEnvelopeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TruncatedEnvelope => f.write_str("block proof envelope truncated"),
            Self::UnexpectedOffset(o) => write!(f, "block proof envelope offset {o}, expected 4"),
            Self::ExceedsCap(n) => write!(f, "wrapped proof {n} bytes exceeds 512 KiB cap"),
        }
    }
}

impl std::error::Error for ProofEnvelopeError {}

// Manual Debug impl because the merged proof bytes are large and opaque.
impl core::fmt::Debug for SignedBlock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignedBlock")
            .field("message", &self.message)
            .field("proof", &format_args!("<{} bytes>", self.proof.len()))
            .finish()
    }
}

/// 512 KiB byte-list cap shared by every block-level / Type-1 proof field.
/// Matches leanSpec PR #717's `ByteList512KiB` SSZ container.
pub type ByteList512KiB = ByteList<524_288>;

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
// `TypeTwoMultiSignature` has no Rust-side struct: the block carries the
// raw lean-multisig Type-2 bytes directly on `SignedBlock.proof`. Component
// participant bitfields come from `block.body.attestations[i].aggregation_bits`
// (and `block.proposer_index` for the trailing proposer entry).

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
            proof: ByteList512KiB::default(),
        };
        let bytes = signed.to_ssz();
        let decoded = SignedBlock::from_ssz_bytes(&bytes).expect("decode");
        assert_eq!(decoded.proof.len(), 0);
        assert_eq!(decoded.message.slot, signed.message.slot);
        assert_eq!(
            decoded.message.proposer_index,
            signed.message.proposer_index
        );
    }
}
