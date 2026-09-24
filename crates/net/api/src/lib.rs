use std::time::Instant;

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
    /// Read from a corpus by the offline import benchmark
    /// (`ethlambda benchmark import replay`).
    ///
    /// The p2p layer never sends this one either. It exists so a replayed
    /// block's import sections are published under a label of their own:
    /// with no source at all they would not be published, and the harness
    /// reads its per-phase numbers from exactly those observations, while
    /// under `gossip` or `sync` they would pass for arrivals that crossed a
    /// wire.
    Replay,
}

/// When a block's payload reached this node.
///
/// Carried on the message rather than read by the chain actor when it handles
/// one, because the two differ by however long the block sat in that actor's
/// mailbox, and that wait is invisible from the far side. It is also the one
/// thing about a block's arrival that no store state records, which is why it
/// rides here instead of being derived on receipt.
///
/// Instants rather than wall-clock milliseconds: these exist to be subtracted
/// from one another, and a monotonic clock is the only one that may be.
#[derive(Clone, Copy, Debug)]
pub struct BlockArrival {
    /// The payload came off the wire, before decompression.
    ///
    /// `None` where this node did not decode the block itself, which is the
    /// req/resp path: its codec has already produced a block by the time any
    /// handler sees one, so the only instant that path can report is the
    /// hand-off. `None` rather than a copy of `handed_off`, because a decode
    /// of zero reads as "free" where the truth is "not measured".
    pub decode_start: Option<Instant>,
    /// The block is about to be handed to the chain actor.
    ///
    /// Where `decode_start` is set, this doubles as the end of the decode
    /// section: a producer hands a block over as soon as it has one. On the
    /// beacon wire that "as soon as" includes gossip validation, since a
    /// gossiped block is not handed off until it has a verdict
    /// (`crate::beacon::verdict` in `ethlambda-p2p`), so `decode` there also
    /// covers the cheap checks, the stateful check itself, and the verdict's
    /// trip back through the p2p actor's mailbox. Not a wait for a free
    /// validation slot: `try_acquire_owned` never blocks, and a message
    /// arriving with none free is reported `Ignore(Overloaded)` immediately.
    pub handed_off: Instant,
    /// Set when this delivery re-delivers a block held for a slot that had
    /// not started.
    ///
    /// `Some` only alongside [`BlockSource::Deferred`]. It is what lets the
    /// held block's end-to-end timing still start where it really started,
    /// rather than at the re-delivery.
    pub deferred_from: Option<DeferredFrom>,
}

/// Where a re-delivered block was before it was re-delivered.
///
/// Carries the original source as well as the instant, because
/// [`BlockSource::Deferred`] on the re-delivery says how the block reached the
/// actor this time, not how it reached the node. Reporting a deferred block
/// under its own source would take it out of the population it belongs to:
/// a gossip block held for 200ms is still a gossip block, and the hold is
/// already visible as its own section of the import.
#[derive(Clone, Copy, Debug)]
pub struct DeferredFrom {
    pub at: Instant,
    pub source: BlockSource,
}

impl BlockArrival {
    /// An arrival whose earliest knowable moment is now.
    ///
    /// For producers that did not decode the block themselves, so have no
    /// earlier instant to report than the one they hand it over at.
    pub fn now() -> Self {
        Self {
            decode_start: None,
            handed_off: Instant::now(),
            deferred_from: None,
        }
    }
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
    fn new_block(
        &self,
        block: SignedBeaconBlock,
        source: BlockSource,
        arrival: BlockArrival,
    ) -> Result<(), ActorError>;
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
