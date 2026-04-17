use serde::Serialize;

use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
use libssz_types::SszList;

use crate::{
    attestation::{AggregatedAttestation, AggregationBits, XmssSignature, validator_indices},
    primitives::{self, ByteList, H256},
};

// Convenience trait for calling hash_tree_root() without a hasher argument
use primitives::HashTreeRoot as _;

/// Envelope carrying a block and its aggregated signatures.
///
/// `HashTreeRoot` is intentionally not derived: `XmssSignature` is encoded as a
/// fixed-size byte vector for cross-client serialization compatibility, but the
/// spec treats it as a container for Merkleization. We never hash a
/// `SignedBlock` directly — consumers always hash the inner `Block`.
#[derive(Clone, SszEncode, SszDecode)]
pub struct SignedBlock {
    /// The block being signed.
    pub message: Block,

    /// Aggregated signature payload for the block.
    ///
    /// Contains per-attestation aggregated proofs and the proposer's signature
    /// over the block root using the proposal key.
    pub signature: BlockSignatures,
}

// Manual Debug impl because leanSig signatures don't implement Debug.
impl core::fmt::Debug for SignedBlock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignedBlock")
            .field("message", &self.message)
            .field("signature", &"...")
            .finish()
    }
}

/// Signature payload for the block.
///
/// See the note on [`SignedBlock`] for why `HashTreeRoot` is omitted.
#[derive(Clone, SszEncode, SszDecode)]
pub struct BlockSignatures {
    /// Attestation signatures for the aggregated attestations in the block body.
    ///
    /// Each entry corresponds to an aggregated attestation from the block body and
    /// contains the leanVM aggregated signature proof bytes for the participating validators.
    ///
    /// TODO:
    /// - Eventually this field will be replaced by a single SNARK aggregating *all* signatures.
    pub attestation_signatures: AttestationSignatures,

    /// Proposer's signature over the block root using the proposal key.
    pub proposer_signature: XmssSignature,
}

/// List of per-attestation aggregated signature proofs.
///
/// Each entry corresponds to an aggregated attestation from the block body.
///
/// It contains:
///     - the participants bitfield,
///     - proof bytes from leanVM signature aggregation.
pub type AttestationSignatures = SszList<AggregatedSignatureProof, 4096>;

/// Cryptographic proof that a set of validators signed a message.
///
/// This container encapsulates the output of the leanVM signature aggregation,
/// combining the participant set with the proof bytes. This design ensures
/// the proof is self-describing: it carries information about which validators
/// it covers.
///
/// The proof can verify that all participants signed the same message in the
/// same epoch, using a single verification operation instead of checking
/// each signature individually.
#[derive(Debug, Clone, SszEncode, SszDecode, HashTreeRoot)]
pub struct AggregatedSignatureProof {
    /// Bitfield indicating which validators' signatures are included.
    pub participants: AggregationBits,
    /// The raw aggregated proof bytes from leanVM.
    pub proof_data: ByteListMiB,
}

pub type ByteListMiB = ByteList<1_048_576>;

impl AggregatedSignatureProof {
    /// Create a new aggregated signature proof.
    pub fn new(participants: AggregationBits, proof_data: ByteListMiB) -> Self {
        Self {
            participants,
            proof_data,
        }
    }

    /// Create an empty proof with the given participants bitfield.
    ///
    /// Used as a placeholder when actual aggregation is not yet implemented.
    pub fn empty(participants: AggregationBits) -> Self {
        Self {
            participants,
            proof_data: SszList::new(),
        }
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
