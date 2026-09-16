use ethlambda_types::{
    attestation::{SignedAggregatedAttestation, SignedAttestation},
    beacon::containers::{SignedBeaconBlock, fulu::DataColumnSidecar},
    block::SignedBlock,
    primitives::H256,
};
use spawned_concurrency::error::ActorError;
use spawned_concurrency::message::Message;
use spawned_concurrency::protocol;

// --- Protocol: BlockChain -> P2P ---

#[protocol]
pub trait BlockChainToP2P: Send + Sync {
    fn publish_block(&self, block: SignedBlock) -> Result<(), ActorError>;
    fn publish_attestation(&self, attestation: SignedAttestation) -> Result<(), ActorError>;
    fn publish_aggregated_attestation(
        &self,
        attestation: SignedAggregatedAttestation,
    ) -> Result<(), ActorError>;
    /// Ask peers for whatever of one block this node is missing.
    fn fetch_block(&self, request: FetchRequest) -> Result<(), ActorError>;
}

/// What one block is missing, from the chain actor's point of view.
///
/// One message rather than a block fetch and a column fetch, because the
/// answer to "what does this node still need for this block" is one answer:
/// the block itself, some of its columns, or both. Splitting it left the
/// caller deciding which protocol to reach for, which is the p2p layer's
/// decision and not the chain's.
///
/// Chain-agnostic. A lean node never custodies a column, so it names an empty
/// `columns` and the request degenerates to the by-root block lookup it was
/// before.
#[derive(Clone, Debug)]
pub struct FetchRequest {
    /// The block all of this is about, and the key the p2p layer deduplicates
    /// an in-flight lookup on.
    pub block_root: H256,
    /// Whether the block itself is missing.
    ///
    /// Explicit rather than inferred from an empty `columns`: the two are
    /// disjoint today only by coincidence of the callers, and a p2p layer
    /// reading its own store to find out would pay a DB read per request to
    /// re-derive what the caller already knew.
    pub needs_block: bool,
    /// Columns of this block that this node custodies and does not have.
    ///
    /// Empty when nothing is missing, or when the block itself is, since a
    /// node that has never seen a block does not know what it committed to.
    pub columns: Vec<u64>,
}

/// How a block reached this node.
///
/// Distinguishes blocks announced on gossip from blocks pulled by req/resp
/// during sync: the two have very different arrival-time characteristics, so
/// consumers that care about timeliness must be able to tell them apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockSource {
    /// Received on the block gossip topic.
    Gossip,
    /// Fetched via req/resp (`BlocksByRoot` / `BlocksByRange`).
    Sync,
    /// Re-delivered by the chain actor to itself, for a block it received
    /// before that block's own slot had started and held until it did.
    ///
    /// The p2p layer never sends this one: it is the only variant that says
    /// the block is not arriving now but arriving again, which is what keeps
    /// a held block out of the timeliness measurements its first arrival
    /// already fed.
    Deferred,
}

// --- Protocol: P2P -> BlockChain ---

#[protocol]
pub trait P2PToBlockChain: Send + Sync {
    /// A block for whichever chain this node follows.
    ///
    /// [`SignedBeaconBlock`] rather than a lean [`SignedBlock`] because its
    /// `Lean` variant carries one, and its `message:` accessors answer for that
    /// variant too. That is what lets the actor's import cascade be written
    /// once for both chains rather than twice.
    fn new_block(&self, block: SignedBeaconBlock, source: BlockSource) -> Result<(), ActorError>;
    fn new_attestation(&self, attestation: SignedAttestation) -> Result<(), ActorError>;
    fn new_aggregated_attestation(
        &self,
        attestation: SignedAggregatedAttestation,
    ) -> Result<(), ActorError>;
    /// Data column sidecars that passed the cheap, stateless checks.
    ///
    /// The expensive ones (the inclusion proof, the KZG batch) and the ones
    /// needing state (the proposer, the header signature) run in the chain
    /// actor, which is where the store and fork choice live.
    ///
    /// A batch rather than one sidecar, because every producer but gossip has
    /// a batch to hand: a `DataColumnsByRoot` answer carries every column of
    /// one block a peer held, and a `DataColumnsByRange` answer carries a span
    /// of them. Sending those one message at a time put one mailbox hop per
    /// sidecar between the answer and the actor that needed it, on the path
    /// that drains a backlog. Gossip sends a batch of one.
    ///
    /// The subnet is not carried: the p2p actor has already checked that each
    /// sidecar's own index maps to the subnet it arrived on, and nothing on
    /// the far side would do anything with it but check that again.
    fn new_data_column_sidecars(&self, sidecars: Vec<DataColumnSidecar>) -> Result<(), ActorError>;
}

// --- Init messages ---
// Used to wire actors together after spawn.

#[derive(Clone)]
pub struct InitP2P {
    pub p2p: BlockChainToP2PRef,
}
impl Message for InitP2P {
    type Result = ();
}

#[derive(Clone)]
pub struct InitBlockChain {
    pub blockchain: P2PToBlockChainRef,
}
impl Message for InitBlockChain {
    type Result = ();
}
