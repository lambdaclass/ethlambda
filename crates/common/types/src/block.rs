use serde::Serialize;
use ssz_types::typenum::U1048576;

use crate::{
    attestation::{AggregatedAttestation, Attestation, XmssSignature},
    primitives::{
        ByteList, H256,
        ssz::{Decode, Encode, TreeHash},
    },
    state::ValidatorRegistryLimit,
};

/// Envelope carrying a block, an attestation from proposer, and aggregated signatures.
#[derive(Clone, Encode, Decode)]
pub struct SignedBlockWithAttestation {
    /// The block plus an attestation from proposer being signed.
    pub message: BlockWithAttestation,

    /// Aggregated signature payload for the block.
    ///
    /// Signatures remain in attestation order followed by the proposer signature
    /// over entire message. For devnet 1, however the proposer signature is just
    /// over message.proposer_attestation since leanVM is not yet performant enough
    /// to aggregate signatures with sufficient throughput.
    ///
    /// Eventually this field will be replaced by a SNARK (which represents the
    /// aggregation of all signatures).
    pub signature: BlockSignatures,
}

// Manual Debug impl because leanSig signatures don't implement Debug.
impl core::fmt::Debug for SignedBlockWithAttestation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignedBlockWithAttestation")
            .field("message", &self.message)
            .field("signature", &"...")
            .finish()
    }
}

/// Signature payload for the block.
#[derive(Clone, Encode, Decode)]
pub struct BlockSignatures {
    /// Attestation signatures for the aggregated attestations in the block body.
    ///
    /// Each entry corresponds to an aggregated attestation from the block body and
    /// contains the leanVM aggregated signature proof bytes for the participating validators.
    ///
    /// TODO:
    /// - Eventually this field will be replaced by a single SNARK aggregating *all* signatures.
    pub attestation_signatures: AttestationSignatures,

    /// Signature for the proposer's attestation.
    pub proposer_signature: XmssSignature,
}

/// List of per-attestation aggregated signature proofs.
///
/// Each entry corresponds to an aggregated attestation from the block body.
///
/// It contains:
///     - the participants bitfield,
///     - proof bytes from leanVM signature aggregation.
pub type AttestationSignatures =
    ssz_types::VariableList<AggregatedSignatureProof, ValidatorRegistryLimit>;

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
#[derive(Debug, Clone, Encode, Decode)]
pub struct AggregatedSignatureProof {
    /// Bitfield indicating which validators' signatures are included.
    pub participants: AggregationBits,
    /// The raw aggregated proof bytes from leanVM.
    pub proof_data: ByteListMiB,
}

pub type ByteListMiB = ByteList<U1048576>;

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
            proof_data: ByteList::empty(),
        }
    }

    /// Get the participants bitfield.
    pub fn participants(&self) -> &AggregationBits {
        &self.participants
    }

    /// Get the proof data.
    pub fn proof_data(&self) -> &ByteListMiB {
        &self.proof_data
    }
}

/// Bitlist representing validator participation in an attestation or signature.
///
/// A general-purpose bitfield for tracking which validators have participated
/// in some collective action (attestation, signature aggregation, etc.).
pub type AggregationBits = ssz_types::BitList<ValidatorRegistryLimit>;

/// Bundle containing a block and the proposer's attestation.
#[derive(Debug, Clone, Encode, Decode, TreeHash)]
pub struct BlockWithAttestation {
    /// The proposed block message.
    pub block: Block,

    /// The proposer's attestation corresponding to this block.
    pub proposer_attestation: Attestation,
}

/// Stored block signatures and proposer attestation.
///
/// This type stores the data needed to reconstruct a `SignedBlockWithAttestation`
/// when combined with a `Block` from the blocks table.
#[derive(Clone, Encode, Decode)]
pub struct BlockSignaturesWithAttestation {
    /// The proposer's attestation for this block.
    pub proposer_attestation: Attestation,

    /// The aggregated signatures for the block.
    pub signatures: BlockSignatures,
}

impl BlockSignaturesWithAttestation {
    /// Create from a SignedBlockWithAttestation by consuming it.
    ///
    /// Takes ownership to avoid cloning large signature data.
    pub fn from_signed_block(signed_block: SignedBlockWithAttestation) -> Self {
        Self {
            proposer_attestation: signed_block.message.proposer_attestation,
            signatures: signed_block.signature,
        }
    }

    /// Reconstruct a SignedBlockWithAttestation given the block.
    ///
    /// Consumes self to avoid cloning large signature data.
    pub fn to_signed_block(self, block: Block) -> SignedBlockWithAttestation {
        SignedBlockWithAttestation {
            message: BlockWithAttestation {
                block,
                proposer_attestation: self.proposer_attestation,
            },
            signature: self.signatures,
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Encode, Decode, TreeHash)]
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
#[derive(Debug, Clone, Encode, Decode, TreeHash)]
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
            body_root: self.body.tree_hash_root(),
        }
    }

    /// Reconstruct a block from header and body.
    ///
    /// # Panics
    /// Panics if the body root doesn't match the header's body_root.
    pub fn from_header_and_body(header: BlockHeader, body: BlockBody) -> Self {
        debug_assert_eq!(
            header.body_root,
            body.tree_hash_root(),
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
#[derive(Debug, Default, Clone, Encode, Decode, TreeHash)]
pub struct BlockBody {
    /// Plain validator attestations carried in the block body.
    ///
    /// Individual signatures live in the aggregated block signature list, so
    /// these entries contain only attestation data without per-attestation signatures.
    pub attestations: AggregatedAttestations,
}

/// List of aggregated attestations included in a block.
pub type AggregatedAttestations =
    ssz_types::VariableList<AggregatedAttestation, ValidatorRegistryLimit>;
