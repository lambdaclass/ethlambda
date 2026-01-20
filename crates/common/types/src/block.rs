use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

use crate::{
    attestation::{Attestation, XmssSignature},
    primitives::H256,
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

/// Flat list of XMSS signatures for a block.
///
/// Signatures remain in attestation order followed by the proposer signature
/// over entire message. For devnet 1, however the proposer signature is just
/// over message.proposer_attestation since leanVM is not yet performant enough
/// to aggregate signatures with sufficient throughput.
///
/// Ordering: [attestation_sig_0, attestation_sig_1, ..., attestation_sig_n, proposer_sig]
/// where signatures[i] corresponds to attestations[i] for i < n.
pub type BlockSignatures = ssz_types::VariableList<XmssSignature, ValidatorRegistryLimit>;

/// Bundle containing a block and the proposer's attestation.
#[derive(Debug, Clone, Encode, Decode, TreeHash)]
pub struct BlockWithAttestation {
    /// The proposed block message.
    pub block: Block,

    /// The proposer's attestation corresponding to this block.
    pub proposer_attestation: Attestation,
}

/// The header of a block, containing metadata.
///
/// Block headers summarize blocks without storing full content. The header
/// includes references to the parent and the resulting state. It also contains
/// a hash of the block body.
///
/// Headers are smaller than full blocks. They're useful for tracking the chain
/// without storing everything.
#[derive(Debug, Clone, Encode, Decode, TreeHash)]
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

/// The body of a block, containing payload data.
///
/// Currently, the main operation is voting. Validators submit attestations which are
/// packaged into blocks.
#[derive(Debug, Default, Clone, Encode, Decode, TreeHash)]
pub struct BlockBody {
    /// Individual validator attestations carried in the block body.
    ///
    /// Individual signatures live in the flat block signature list, so
    /// these entries contain only attestation data without per-attestation signatures.
    /// Each attestation[i] corresponds to signature[i] in BlockSignatures.
    pub attestations: Attestations,
}

/// List of individual attestations included in a block.
pub type Attestations = ssz_types::VariableList<Attestation, ValidatorRegistryLimit>;
