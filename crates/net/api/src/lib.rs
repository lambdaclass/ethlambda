use std::time::Instant;

use ethlambda_types::{
    attestation::{SignedAggregatedAttestation, SignedAttestation},
    beacon::containers::{
        SignedAggregateAndProof, SignedBeaconBlock, electra::SingleAttestation,
        fulu::DataColumnSidecar,
    },
    beacon::primitives::ValidatorIndex,
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
    /// Run the chain checks on sidecars the chain actor had parked, now that
    /// their parent has a post-state.
    ///
    /// The chain actor keeps a sidecar without checking it, so it hands these
    /// back rather than judging them itself: the p2p layer runs every column
    /// check, off both actors, and sends the ones that pass back through
    /// [`P2PToBlockChain::new_data_column_sidecars`].
    fn check_data_column_sidecars(
        &self,
        sidecars: Vec<DataColumnSidecar>,
    ) -> Result<(), ActorError>;
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

/// Whether the chain actor announces a block on the `block_gossip` chain
/// event when it arrives.
///
/// Separate from [`BlockSource`], which says how the block arrived and labels
/// its import metrics. The two disagree on the beacon wire: a gossip block
/// handed over on a `Queue` or `Ignore(Overloaded)` verdict arrived by gossip
/// without passing the `beacon_block` topic's validation rules, and a block a
/// validator client published through the Beacon API passed them without
/// arriving by gossip. The Beacon API's `block_gossip` names exactly the blocks
/// that passed, from either path, so only the sender knows which one this is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockAnnouncement {
    /// Emit `block_gossip`: a beacon block that passed gossip validation
    /// (on its gossip `Accept`, or checked by the Beacon API before
    /// publishing), or a lean block from gossip, which validates nothing
    /// before import and has always announced every gossip block.
    Announce,
    /// Emit nothing: fetched by req/resp, re-delivered after a hold, replayed,
    /// or handed over on a gossip verdict other than `Accept`.
    Silent,
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
        announcement: BlockAnnouncement,
    ) -> Result<(), ActorError>;
    fn new_attestation(&self, attestation: SignedAttestation) -> Result<(), ActorError>;
    fn new_aggregated_attestation(
        &self,
        attestation: SignedAggregatedAttestation,
    ) -> Result<(), ActorError>;
    /// Data column sidecars that passed every check: gossip's own, for one it
    /// accepted, or the chain checks (`beacon::gossip::column::chain_checks`
    /// in `ethlambda-state-transition`) for any other.
    ///
    /// The chain actor stores these without checking them again. That is the
    /// point of running the checks in the p2p layer: a KZG batch and a BLS
    /// verification per sidecar cost too much on the actor's single thread,
    /// which also imports every block. Debug builds do check again, so a path
    /// that sends a sidecar it never checked fails a test rather than reaching
    /// the store.
    ///
    /// A batch rather than one sidecar, because every producer but gossip has
    /// a batch to hand: a `DataColumnsByRoot` answer carries every column of
    /// one block a peer held, and a `DataColumnsByRange` answer carries a span
    /// of them. Sending those one message at a time put one mailbox hop per
    /// sidecar between the answer and the actor that needed it, on the path
    /// that drains a backlog. Gossip sends a batch of one.
    ///
    /// The subnet is not carried: the p2p actor has already checked that each
    /// gossiped sidecar's own index maps to the subnet it arrived on, and
    /// nothing on the far side would do anything with it but check that
    /// again.
    fn new_data_column_sidecars(&self, sidecars: Vec<DataColumnSidecar>) -> Result<(), ActorError>;
    /// Data column sidecars the chain checks could not judge yet, because
    /// their parent has no post-state: the chain actor parks them and sends
    /// them back through [`BlockChainToP2P::check_data_column_sidecars`] once
    /// the parent imports.
    fn data_column_sidecars_awaiting_parent(
        &self,
        sidecars: Vec<DataColumnSidecar>,
    ) -> Result<(), ActorError>;
    /// An aggregate that passed every `beacon_aggregate_and_proof` condition,
    /// `attesting_indices` included: either `ethlambda-p2p`'s beacon gossip
    /// verdict machinery accepted it, or the Beacon API ran the same checks on
    /// one a validator client submitted. The chain actor only has to apply it
    /// to fork choice.
    ///
    /// Separate from [`Self::new_aggregated_attestation`], which carries
    /// lean's unrelated [`SignedAggregatedAttestation`]: the two chains'
    /// aggregate containers share no type, so unlike [`Self::new_block`] there
    /// is nothing for one message to be generic over.
    ///
    /// Boxed for the reason `ethlambda-p2p`'s own gossip enum boxes it: two
    /// signed block headers' worth of payload would otherwise set the size of
    /// every message in this protocol.
    ///
    /// `attesting_indices` are the validators whose votes the aggregate
    /// signature verified, resolved once against the committee p2p's gossip
    /// validation already looked up. The chain actor never rebuilds a
    /// committee or checks a signature for this topic: its only consumer is
    /// `ethlambda_state_transition`'s apply-only
    /// `fork_choice::apply_verified_aggregate`.
    ///
    /// One aggregate per message rather than a batch, unlike
    /// [`Self::new_data_column_sidecars`]: each producer has exactly one to
    /// hand. There are two, gossip on `Accept` and
    /// [`RpcToP2P::publish_beacon_aggregate`], since gossip never delivers a
    /// node its own messages: without the second, an aggregate this node's
    /// validator client submitted would reach neither its fork choice nor its
    /// `attestation` event stream.
    fn new_beacon_aggregate(
        &self,
        aggregate: Box<SignedAggregateAndProof>,
        attesting_indices: Vec<ValidatorIndex>,
        arrival: AggregateArrival,
    ) -> Result<(), ActorError>;
}

/// When an aggregate reached this node, for the one metric that cannot be
/// derived on the far side of the mailbox.
///
/// The mailbox hop is the failure mode applying gossip aggregates introduces:
/// this topic carries up to `MAX_COMMITTEES_PER_SLOT * TARGET_AGGREGATORS_PER_COMMITTEE`
/// messages a slot, and if they start queueing behind block imports the votes
/// arrive too late to move the head while every per-aggregate timing still
/// looks healthy. Measuring it means capturing an instant before the queue and
/// reading it after, which is what this carries.
///
/// [`BlockArrival`]'s shape without its `deferred_from`: an aggregate held for
/// a slot that has not started is held *inside* the chain actor, so that wait
/// is measured where it happens rather than travelling on the message.
///
/// `decode_start` is not optional, unlike [`BlockArrival`]'s: an aggregate a
/// validator client submitted through the Beacon API crossed no wire, so it
/// reports [`AggregateArrival::now`], both instants at the hand-off, and its
/// end-to-end time is the mailbox wait plus the apply.
#[derive(Clone, Copy, Debug)]
pub struct AggregateArrival {
    /// The payload came off the wire, before decompression.
    pub decode_start: Instant,
    /// The aggregate is about to be handed to the chain actor, which is also
    /// the end of the decode.
    pub handed_off: Instant,
}

impl AggregateArrival {
    /// An arrival whose earliest knowable moment is now, for a producer that
    /// decoded nothing.
    pub fn now() -> Self {
        let now = Instant::now();
        Self {
            decode_start: now,
            handed_off: now,
        }
    }
}

// --- Protocol: RPC -> P2P ---

/// What the Beacon API asks of the network.
///
/// A protocol of its own rather than more methods on [`BlockChainToP2P`]:
/// these requests come from a validator client through the HTTP server, not
/// from the chain actor, and a beacon node's chain actor has nothing to publish
/// on its own behalf.
#[protocol]
pub trait RpcToP2P: Send + Sync {
    /// Gossip one unaggregated attestation on `beacon_attestation_{subnet_id}`.
    ///
    /// The caller has already validated it and computed its subnet: both need
    /// the committee assignment, which needs a state, and the p2p actor holds
    /// none.
    fn publish_beacon_attestation(
        &self,
        subnet_id: u64,
        attestation: SingleAttestation,
    ) -> Result<(), ActorError>;
    /// Gossip one signed aggregate on `beacon_aggregate_and_proof`, already
    /// validated by the caller for the same reason as above, and hand it to
    /// the chain actor, as [`Self::publish_beacon_block`] does with a block
    /// and for the same reason.
    ///
    /// `attesting_indices` are the validators the caller's validation
    /// resolved the aggregate's bits to, which is what the chain actor applies
    /// to fork choice; see [`P2PToBlockChain::new_beacon_aggregate`].
    fn publish_beacon_aggregate(
        &self,
        aggregate: SignedAggregateAndProof,
        attesting_indices: Vec<ValidatorIndex>,
    ) -> Result<(), ActorError>;
    /// Join attestation subnets a validator client's aggregators need, each
    /// until the end of the paired slot, so their committees' attestations
    /// reach this node's pool. `(subnet_id, slot)` pairs.
    fn subscribe_attestation_subnets(&self, subnets: Vec<(u64, u64)>) -> Result<(), ActorError>;
    /// Gossip a block a validator client signed, and import it: gossip never
    /// delivers a node its own messages, so without the second half this node
    /// would not follow its own proposal. Checked by the caller as above.
    fn publish_beacon_block(&self, block: SignedBeaconBlock) -> Result<(), ActorError>;
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
