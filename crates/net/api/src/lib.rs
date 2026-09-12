use ethlambda_types::{
    attestation::{SignedAggregatedAttestation, SignedAttestation},
    beacon::containers::SignedBeaconBlock,
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
    fn fetch_block(&self, root: H256) -> Result<(), ActorError>;
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
