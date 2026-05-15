use serde::{Serialize, Serializer, ser::SerializeSeq};

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
// Wire format mirrors leanSpec PR #717: the proof envelope carries only what
// the verifier cannot rederive from the block body. `message` / `slot` /
// `bytecode_claim` are intentionally absent — the verifier reconstructs each
// component's binding from the block-body attestation it sits next to (plus
// the block root + slot for the proposer entry).

/// Per-component metadata for a Type-1 multi-signer proof.
///
/// Holds the participant bitfield and the per-component proof bytes in
/// compact no-pubkeys form. Inside a Type-2 envelope, `proof` is the standalone
/// Type-1 wire for this single component, enabling cheap disaggregation
/// without running a fresh SNARK.
#[derive(Debug, Clone, SszEncode, SszDecode, HashTreeRoot)]
pub struct TypeOneInfo {
    /// Bitfield indicating which validators contributed signatures.
    pub participants: AggregationBits,
    /// Standalone Type-1 proof bytes (`compress_without_pubkeys`) for this
    /// component. Used by split-by-msg and by re-broadcast paths.
    pub proof: ByteListMiB,
}

/// Maximum number of distinct `AttestationData` entries permitted in a single
/// block. Canonical home for the cap shared across `ethlambda-blockchain`,
/// `ethlambda-test-fixtures`, and the wire types in this crate.
///
/// See: leanSpec commit 0c9528a (PR #536).
pub const MAX_ATTESTATIONS_DATA: usize = 16;

/// SSZ-list of Type-1 info entries packed inside a Type-2 proof.
///
/// Holds at most `MAX_ATTESTATIONS_DATA` distinct attestation entries plus one
/// for the proposer's own signature. Mirrors upstream
/// `TypeOneInfos.LIMIT = MAX_ATTESTATIONS_DATA + 1`.
pub type TypeOneInfos = SszList<TypeOneInfo, { MAX_ATTESTATIONS_DATA + 1 }>;

/// A Type-1 single-message proof aggregating signatures from many validators.
///
/// The outer `proof` field is the canonical aggregated proof bytes; `info.proof`
/// holds the same bytes (kept aligned so a Type-1 embedded inside a Type-2's
/// info list reads identically standalone). `message` and `slot` live on the
/// caller-side block body, not on this envelope.
#[derive(Debug, Clone, SszEncode, SszDecode, HashTreeRoot)]
pub struct TypeOneMultiSignature {
    /// Per-component participant bitfield plus the standalone proof bytes.
    pub info: TypeOneInfo,
    /// Aggregated proof bytes in compact no-pubkeys representation.
    pub proof: ByteListMiB,
}

/// A Type-2 merged proof covering many distinct messages.
///
/// `signed_block.proof` carries the SSZ-encoded form of this container. The
/// `info` list enumerates per-component (participants, standalone Type-1
/// proof bytes); messages and slots are reconstructed at verify time from the
/// block body.
#[derive(Debug, Clone, SszEncode, SszDecode, HashTreeRoot)]
pub struct TypeTwoMultiSignature {
    /// Per-component metadata, one entry per merged Type-1 proof.
    pub info: TypeOneInfos,
    /// Merged proof bytes in compact no-pubkeys representation.
    pub proof: ByteListMiB,
}

impl TypeOneMultiSignature {
    /// Build a Type-1 proof carrying the given participant bitfield and the
    /// aggregated proof bytes.
    ///
    /// `info.proof` and the outer `proof` carry the same bytes. This mirrors
    /// leanSpec PR #717's shape (`aggregate_type_1` returns
    /// `TypeOneMultiSignature(info=TypeOneInfo(participants, proof=wire),
    /// proof=wire)`) so that a Type-1 embedded inside a Type-2's `info[i]`
    /// reads the same as a standalone Type-1. The cost is one extra heap copy
    /// of ~225 KiB per Type-1 — acceptable in the gossip pipeline; if it
    /// shows up in profiling, swap the inner `ByteListMiB` for an
    /// `Arc<ByteListMiB>` once SSZ derive supports it.
    pub fn new(participants: AggregationBits, proof_data: ByteListMiB) -> Self {
        Self {
            info: TypeOneInfo {
                participants,
                proof: proof_data.clone(),
            },
            proof: proof_data,
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
    pub fn for_proposer(proposer_index: u64, proposer_proof_bytes: ByteListMiB) -> Self {
        let mut participants = AggregationBits::with_length(proposer_index as usize + 1)
            .expect("validator index fits");
        participants
            .set(proposer_index as usize, true)
            .expect("index within capacity");
        Self::new(participants, proposer_proof_bytes)
    }

    /// Returns the validator indices that are set in the participants bitfield.
    pub fn participant_indices(&self) -> impl Iterator<Item = u64> + '_ {
        validator_indices(&self.info.participants)
    }
}

impl TypeTwoMultiSignature {
    /// Build a Type-2 envelope from a list of Type-1 components with EMPTY
    /// merged proof bytes. Useful for tests that exercise the structural
    /// fast-fail leg of `verify_block_signatures` (participants mismatch,
    /// missing entries, …) without paying the lean-multisig SNARK cost.
    ///
    /// Production block production uses
    /// [`ethlambda_crypto::merge_type_1s_into_type_2`] to produce a real
    /// cryptographic Type-2 proof; do not use this helper for any path that
    /// actually verifies the merged proof.
    pub fn from_type_1s(type_1s: Vec<TypeOneMultiSignature>) -> Self {
        let infos: Vec<TypeOneInfo> = type_1s.into_iter().map(|t1| t1.info).collect();
        let info = TypeOneInfos::try_from(infos)
            .expect("type-1 infos within MAX_ATTESTATIONS_DATA + 1 limit");
        Self {
            info,
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

    fn sample_type_one_info() -> TypeOneInfo {
        TypeOneInfo {
            participants: sample_bits(8, &[0, 3, 7]),
            proof: ByteListMiB::try_from((0..32u8).collect::<Vec<u8>>()).unwrap(),
        }
    }

    #[test]
    fn type_one_info_ssz_round_trip() {
        let info = sample_type_one_info();
        let bytes = info.to_ssz();
        let decoded = TypeOneInfo::from_ssz_bytes(&bytes).expect("decode");
        assert_eq!(
            decoded.participants.as_bytes(),
            info.participants.as_bytes()
        );
        assert_eq!(decoded.proof.to_vec(), info.proof.to_vec());
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
        assert_eq!(
            decoded.info.participants.as_bytes(),
            sig.info.participants.as_bytes()
        );
    }

    #[test]
    fn type_two_multi_signature_ssz_round_trip() {
        let infos: Vec<TypeOneInfo> = (0..3)
            .map(|i| TypeOneInfo {
                participants: sample_bits(8, &[i, i + 1]),
                proof: ByteListMiB::try_from(vec![i as u8; 16]).unwrap(),
            })
            .collect();
        let merged_bytes: Vec<u8> = (0..128).map(|i| (i % 256) as u8).collect();
        let sig = TypeTwoMultiSignature {
            info: TypeOneInfos::try_from(infos.clone()).unwrap(),
            proof: ByteListMiB::try_from(merged_bytes.clone()).unwrap(),
        };
        let bytes = sig.to_ssz();
        let decoded = TypeTwoMultiSignature::from_ssz_bytes(&bytes).expect("decode");
        assert_eq!(decoded.info.len(), 3);
        assert_eq!(decoded.proof.to_vec(), merged_bytes);
        for (got, want) in decoded.info.iter().zip(infos.iter()) {
            assert_eq!(got.participants.as_bytes(), want.participants.as_bytes());
            assert_eq!(got.proof.to_vec(), want.proof.to_vec());
        }
    }

    #[test]
    fn type_one_infos_respects_limit() {
        let too_many: Vec<TypeOneInfo> = (0..18)
            .map(|_| TypeOneInfo {
                participants: sample_bits(1, &[0]),
                proof: ByteListMiB::default(),
            })
            .collect();
        assert!(TypeOneInfos::try_from(too_many).is_err());
    }
}
