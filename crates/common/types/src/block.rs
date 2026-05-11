use serde::Serialize;

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::SszList;

use crate::{
    attestation::{AggregatedAttestation, AggregationBits, validator_indices},
    primitives::{self, ByteList, H256},
};

// Convenience trait for calling hash_tree_root() without a hasher argument
use primitives::HashTreeRoot as _;

/// Envelope carrying a block and a single merged proof binding every signature
/// it depends on.
///
/// The `proof` blob is the SSZ-encoded form of a [`TypeTwoMultiSignature`] that
/// covers, in order, every per-attestation Type-1 proof plus a singleton Type-1
/// proof carrying the proposer's signature over the block root. Decode with
/// `TypeTwoMultiSignature::from_ssz_bytes(&signed_block.proof)`.
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

    /// SSZ-encoded merged proof for every signature this block depends on.
    pub proof: ByteListMiB,
}

// Manual Debug impl because the merged proof bytes are large and opaque.
impl core::fmt::Debug for SignedBlock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignedBlock")
            .field("message", &self.message)
            .field("proof", &format_args!("<{} bytes>", self.proof.len()))
            .finish()
    }
}

pub type ByteListMiB = ByteList<1_048_576>;

// ============================================================================
// Type-1 / Type-2 multi-signature model
// ============================================================================
//
// New typed multi-signature surface introduced by leanSpec commit
// `anshalshukla/leanSpec@0ab09dd` ("dummy type 1 and type 2 aggregation with
// block proofs"). Defined alongside the legacy `AggregatedSignatureProof` /
// `BlockSignatures` types during the phased migration; consumers will switch
// over in later phases (gossip layer first, then block wire).

/// Trusted `Evaluation<EF>` field carried inside Type-1 / Type-2 proofs.
///
/// Upstream models this as a `Bytes32` placeholder until `lean_multisig_py`
/// bindings land with the concrete SSZ serialisation. Mirrored here as `H256`.
pub type BytecodeClaim = H256;

/// Per-message metadata for a Type-1 (single-message) multi-signer proof.
///
/// Carries everything a verifier needs to recompute the proof's binding inputs
/// without re-deriving from block content. Participants stay in bitfield form
/// for wire compactness; pubkeys are resolved at the binding boundary from the
/// validator registry.
#[derive(Debug, Clone, SszEncode, SszDecode, HashTreeRoot)]
pub struct TypeOneInfo {
    /// The 32-byte message that was signed
    /// (e.g. `hash_tree_root` of attestation data, or a block root).
    pub message: H256,
    /// The slot in which the signatures were created.
    pub slot: u64,
    /// Bitfield indicating which validators contributed signatures.
    pub participants: AggregationBits,
    /// Trusted evaluation tied to the proof. Recomputed by the verifier when
    /// received externally.
    pub bytecode_claim: BytecodeClaim,
}

/// SSZ-list of Type-1 info entries packed inside a Type-2 proof.
///
/// Holds at most `MAX_ATTESTATIONS_DATA` distinct attestation entries plus one
/// for the proposer's own signature. Mirrors upstream
/// `TypeOneInfos.LIMIT = MAX_ATTESTATIONS_DATA + 1` (= 16 + 1).
pub type TypeOneInfos = SszList<TypeOneInfo, 17>;

/// A Type-1 single-message proof aggregating signatures from many validators.
#[derive(Debug, Clone, SszEncode, SszDecode, HashTreeRoot)]
pub struct TypeOneMultiSignature {
    /// Message, slot, participants, and trusted bytecode claim.
    pub info: TypeOneInfo,
    /// Raw aggregated proof bytes (`ExecutionProof` on the Rust side).
    pub proof: ByteListMiB,
}

/// A Type-2 merged proof covering many distinct messages.
///
/// On the wire a `SignedBlock` will carry the SSZ-serialised form of this
/// container as its single proof blob (introduced in a later phase). The
/// block-level info list enumerates every `(message, slot, participants)`
/// tuple the proof binds to.
#[derive(Debug, Clone, SszEncode, SszDecode, HashTreeRoot)]
pub struct TypeTwoMultiSignature {
    /// Per-message metadata, one entry per merged Type-1 proof.
    pub info: TypeOneInfos,
    /// Aggregation-level trusted evaluation. Recomputed on receive.
    pub bytecode_claim: BytecodeClaim,
    /// Raw merged proof bytes (`ExecutionProof` on the Rust side).
    pub proof: ByteListMiB,
}

impl TypeOneMultiSignature {
    /// Build a Type-1 proof with the given participants, message, slot and
    /// raw proof bytes.
    pub fn new(
        participants: AggregationBits,
        message: H256,
        slot: u64,
        proof_data: ByteListMiB,
    ) -> Self {
        Self {
            info: TypeOneInfo {
                message,
                slot,
                participants,
                bytecode_claim: BytecodeClaim::ZERO,
            },
            proof: proof_data,
        }
    }

    /// Build an empty Type-1 proof with the given participants and message
    /// metadata. `proof` bytes are left empty — useful as a placeholder when
    /// actual aggregation is not yet performed (forkchoice tests, etc.).
    pub fn empty(participants: AggregationBits, message: H256, slot: u64) -> Self {
        Self::new(participants, message, slot, SszList::new())
    }

    /// Wrap a proposer's XMSS signature over a block root as a singleton Type-1.
    ///
    /// Used by block production and test fixtures to fold the proposer's
    /// signature into the block-level Type-2 merged proof.
    pub fn for_proposer(
        proposer_index: u64,
        proposer_signature: ByteListMiB,
        block_root: H256,
        slot: u64,
    ) -> Self {
        let mut participants = AggregationBits::with_length(proposer_index as usize + 1)
            .expect("validator index fits");
        participants
            .set(proposer_index as usize, true)
            .expect("index within capacity");
        Self::new(participants, block_root, slot, proposer_signature)
    }

    /// Returns the validator indices that are set in the participants bitfield.
    pub fn participant_indices(&self) -> impl Iterator<Item = u64> + '_ {
        validator_indices(&self.info.participants)
    }
}

impl TypeTwoMultiSignature {
    /// Merge a list of Type-1 single-message proofs into a single Type-2
    /// multi-message proof. Mirrors upstream leanSpec's `aggregate_type_2`
    /// stub: the metadata list (`TypeOneInfos`) is faithfully preserved so a
    /// verifier can re-derive the per-message binding inputs, but the merged
    /// `proof` bytes are left empty until the `lean_multisig_py` bindings ship
    /// real cryptographic merging. Block-level signature verification stays
    /// structural-only in the meantime, and per-attestation crypto verification
    /// continues to run at gossip ingestion.
    pub fn from_type_1s(type_1s: Vec<TypeOneMultiSignature>) -> Self {
        let infos: Vec<TypeOneInfo> = type_1s.into_iter().map(|t1| t1.info).collect();
        let info = TypeOneInfos::try_from(infos)
            .expect("type-1 infos within MAX_ATTESTATIONS_DATA + 1 limit");
        Self {
            info,
            bytecode_claim: BytecodeClaim::ZERO,
            proof: ByteListMiB::default(),
        }
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
#[derive(Debug, Clone, SszEncode, SszDecode, HashTreeRoot)]
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
#[derive(Debug, Default, Clone, SszEncode, SszDecode, HashTreeRoot)]
pub struct BlockBody {
    /// Plain validator attestations carried in the block body.
    ///
    /// Individual signatures live in the aggregated block signature list, so
    /// these entries contain only attestation data without per-attestation signatures.
    pub attestations: AggregatedAttestations,
}

/// List of aggregated attestations included in a block.
pub type AggregatedAttestations = SszList<AggregatedAttestation, 4096>;

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

    fn sample_type_one_info() -> TypeOneInfo {
        TypeOneInfo {
            message: H256([7u8; 32]),
            slot: 42,
            participants: sample_bits(8, &[0, 3, 7]),
            bytecode_claim: H256([1u8; 32]),
        }
    }

    #[test]
    fn type_one_info_ssz_round_trip() {
        let info = sample_type_one_info();
        let bytes = info.to_ssz();
        let decoded = TypeOneInfo::from_ssz_bytes(&bytes).expect("decode");
        assert_eq!(decoded.message, info.message);
        assert_eq!(decoded.slot, info.slot);
        assert_eq!(decoded.bytecode_claim, info.bytecode_claim);
        assert_eq!(
            decoded.participants.as_bytes(),
            info.participants.as_bytes()
        );
    }

    #[test]
    fn type_one_multi_signature_ssz_round_trip() {
        let proof_bytes: Vec<u8> = (0..64).collect();
        let sig = TypeOneMultiSignature {
            info: sample_type_one_info(),
            proof: ByteListMiB::try_from(proof_bytes.clone()).unwrap(),
        };
        let bytes = sig.to_ssz();
        let decoded = TypeOneMultiSignature::from_ssz_bytes(&bytes).expect("decode");
        assert_eq!(decoded.proof.to_vec(), proof_bytes);
        assert_eq!(decoded.info.slot, sig.info.slot);
    }

    #[test]
    fn type_two_multi_signature_ssz_round_trip() {
        let infos: Vec<TypeOneInfo> = (0..3)
            .map(|i| TypeOneInfo {
                message: H256([i as u8; 32]),
                slot: 100 + i as u64,
                participants: sample_bits(8, &[i, i + 1]),
                bytecode_claim: H256([0xAA; 32]),
            })
            .collect();
        let merged_bytes: Vec<u8> = (0..128).map(|i| (i % 256) as u8).collect();
        let sig = TypeTwoMultiSignature {
            info: TypeOneInfos::try_from(infos.clone()).unwrap(),
            bytecode_claim: H256([0xBB; 32]),
            proof: ByteListMiB::try_from(merged_bytes.clone()).unwrap(),
        };
        let bytes = sig.to_ssz();
        let decoded = TypeTwoMultiSignature::from_ssz_bytes(&bytes).expect("decode");
        assert_eq!(decoded.info.len(), 3);
        assert_eq!(decoded.proof.to_vec(), merged_bytes);
        assert_eq!(decoded.bytecode_claim, sig.bytecode_claim);
        for (got, want) in decoded.info.iter().zip(infos.iter()) {
            assert_eq!(got.slot, want.slot);
            assert_eq!(got.message, want.message);
        }
    }

    #[test]
    fn type_one_infos_respects_limit() {
        let too_many: Vec<TypeOneInfo> = (0..18)
            .map(|i| TypeOneInfo {
                message: H256([i as u8; 32]),
                slot: i as u64,
                participants: sample_bits(1, &[0]),
                bytecode_claim: H256([0u8; 32]),
            })
            .collect();
        assert!(TypeOneInfos::try_from(too_many).is_err());
    }
}
