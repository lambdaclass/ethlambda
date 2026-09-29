//! Chain-event pub-sub bus.
//!
//! The [`crate::BlockChainServer`] actor is the **sole publisher**: it emits a
//! [`ChainEvent`] whenever consensus state changes (block import, head move,
//! justification, finalization). Consumers subscribe read-only receivers and
//! never write back into the actor, keeping the write flow one-directional.
//!
//! The bus is intentionally best-effort: emission never blocks the actor, and
//! a slow subscriber loses events (the bounded broadcast channel overwrites
//! its backlog) rather than back-pressuring consensus.
//!
//! One bus carries both chains' events, but a node runs one chain and so only
//! ever emits one family: lean's variants (bare integers, `slot` standing in
//! for `epoch`) behind `/lean/v0/events`, and the Beacon API's (quoted
//! integers, the eventstream's own field names) behind `/eth/v1/events`. Each
//! surface accepts its own set of [`Topic`] names ([`Topic::LEAN`],
//! [`Topic::BEACON`]).

use ethlambda_state_transition::beacon::helpers::accessors::get_block_root_at_slot;
use ethlambda_storage::Store;
use ethlambda_types::ShortRoot;
use ethlambda_types::attestation::AttestationData;
use ethlambda_types::beacon::containers::{BeaconState, SignedAggregateAndProof, electra, phase0};
use ethlambda_types::beacon::serde_helpers::quoted_or_bare;
use ethlambda_types::beacon::signing::{compute_epoch_at_slot, compute_start_slot_at_epoch};
use ethlambda_types::checkpoint::Checkpoint;
use ethlambda_types::primitives::H256;
use serde::Serialize;
use std::str::FromStr;
use tokio::sync::broadcast;
use tracing::warn;

/// Wire-visible topic names for chain events.
///
/// These are the names consumers address events by (the SSE `event:` line and
/// `?topics=` filtering), kept separate from [`ChainEvent`] so the payload
/// stays flat with the topic travelling out-of-band.
///
/// One enum for both surfaces, so a name means the same thing on each: every
/// Beacon API eventstream topic, plus the two ethlambda extensions lean serves
/// (`justified_checkpoint`, `aggregate`). [`FromStr`] parses all of them; which
/// ones a surface *accepts* is [`Topic::LEAN`] or [`Topic::BEACON`]. Most beacon
/// names are accepted and never emitted: the node has no producer for them (no
/// operation pools, no light-client server, no gloas), and the specification
/// lists them all as valid subscriptions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Topic {
    Head,
    Block,
    /// ethlambda extension, lean only: the justified checkpoint advanced.
    JustifiedCheckpoint,
    FinalizedCheckpoint,
    /// A block that passed gossip validation, before import.
    BlockGossip,
    /// Lean: a single validator vote seen on gossip. Beacon: an accepted
    /// aggregate's `Attestation`, since after electra the subnet topics carry
    /// `SingleAttestation` and aggregates are the only `Attestation` left.
    Attestation,
    /// ethlambda extension, lean only: a committee-signature aggregate
    /// (produced locally or seen on gossip).
    Aggregate,
    ChainReorg,
    DataColumnSidecar,
    // Accepted on the beacon surface, never emitted. See `docs/rpc.md`.
    SingleAttestation,
    VoluntaryExit,
    BlsToExecutionChange,
    ProposerSlashing,
    AttesterSlashing,
    ContributionAndProof,
    LightClientFinalityUpdate,
    LightClientOptimisticUpdate,
    PayloadAttributes,
    /// Removed from the specification's `master` by beacon-APIs#577 but still
    /// in its last release, so a client built against that release may ask.
    BlobSidecar,
    HeadV2,
    ExecutionPayload,
    ExecutionPayloadGossip,
    ExecutionPayloadAvailable,
    ExecutionPayloadBid,
    PayloadAttestationMessage,
    FastConfirmation,
    ProposerPreferences,
}

impl Topic {
    /// Every topic, in declaration order. [`FromStr`] searches this, which is
    /// what makes it the exact inverse of [`Topic::as_str`].
    pub const ALL: &[Topic] = &[
        Topic::Head,
        Topic::Block,
        Topic::JustifiedCheckpoint,
        Topic::FinalizedCheckpoint,
        Topic::BlockGossip,
        Topic::Attestation,
        Topic::Aggregate,
        Topic::ChainReorg,
        Topic::DataColumnSidecar,
        Topic::SingleAttestation,
        Topic::VoluntaryExit,
        Topic::BlsToExecutionChange,
        Topic::ProposerSlashing,
        Topic::AttesterSlashing,
        Topic::ContributionAndProof,
        Topic::LightClientFinalityUpdate,
        Topic::LightClientOptimisticUpdate,
        Topic::PayloadAttributes,
        Topic::BlobSidecar,
        Topic::HeadV2,
        Topic::ExecutionPayload,
        Topic::ExecutionPayloadGossip,
        Topic::ExecutionPayloadAvailable,
        Topic::ExecutionPayloadBid,
        Topic::PayloadAttestationMessage,
        Topic::FastConfirmation,
        Topic::ProposerPreferences,
    ];

    /// The names `/lean/v0/events` accepts.
    pub const LEAN: &[Topic] = &[
        Topic::Head,
        Topic::Block,
        Topic::JustifiedCheckpoint,
        Topic::FinalizedCheckpoint,
        Topic::BlockGossip,
        Topic::Attestation,
        Topic::Aggregate,
    ];

    /// The names `/eth/v1/events` accepts: every topic in the Beacon API's
    /// eventstream specification, plus [`Topic::BlobSidecar`].
    pub const BEACON: &[Topic] = &[
        Topic::Head,
        Topic::Block,
        Topic::FinalizedCheckpoint,
        Topic::BlockGossip,
        Topic::Attestation,
        Topic::ChainReorg,
        Topic::DataColumnSidecar,
        Topic::SingleAttestation,
        Topic::VoluntaryExit,
        Topic::BlsToExecutionChange,
        Topic::ProposerSlashing,
        Topic::AttesterSlashing,
        Topic::ContributionAndProof,
        Topic::LightClientFinalityUpdate,
        Topic::LightClientOptimisticUpdate,
        Topic::PayloadAttributes,
        Topic::BlobSidecar,
        Topic::HeadV2,
        Topic::ExecutionPayload,
        Topic::ExecutionPayloadGossip,
        Topic::ExecutionPayloadAvailable,
        Topic::ExecutionPayloadBid,
        Topic::PayloadAttestationMessage,
        Topic::FastConfirmation,
        Topic::ProposerPreferences,
    ];

    /// Parse `name` as one of `accepted` (a surface's set, [`Topic::LEAN`] or
    /// [`Topic::BEACON`]).
    ///
    /// A name outside the set is the same [`UnknownTopic`] as one matching no
    /// topic at all: to a surface, a topic it does not serve is not a topic.
    pub fn parse_accepted(name: &str, accepted: &[Topic]) -> Result<Topic, UnknownTopic> {
        name.parse::<Topic>()
            .ok()
            .filter(|topic| accepted.contains(topic))
            .ok_or_else(|| UnknownTopic(name.to_string()))
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Topic::Head => "head",
            Topic::Block => "block",
            Topic::JustifiedCheckpoint => "justified_checkpoint",
            Topic::FinalizedCheckpoint => "finalized_checkpoint",
            Topic::BlockGossip => "block_gossip",
            Topic::Attestation => "attestation",
            Topic::Aggregate => "aggregate",
            Topic::ChainReorg => "chain_reorg",
            Topic::DataColumnSidecar => "data_column_sidecar",
            Topic::SingleAttestation => "single_attestation",
            Topic::VoluntaryExit => "voluntary_exit",
            Topic::BlsToExecutionChange => "bls_to_execution_change",
            Topic::ProposerSlashing => "proposer_slashing",
            Topic::AttesterSlashing => "attester_slashing",
            Topic::ContributionAndProof => "contribution_and_proof",
            Topic::LightClientFinalityUpdate => "light_client_finality_update",
            Topic::LightClientOptimisticUpdate => "light_client_optimistic_update",
            Topic::PayloadAttributes => "payload_attributes",
            Topic::BlobSidecar => "blob_sidecar",
            Topic::HeadV2 => "head_v2",
            Topic::ExecutionPayload => "execution_payload",
            Topic::ExecutionPayloadGossip => "execution_payload_gossip",
            Topic::ExecutionPayloadAvailable => "execution_payload_available",
            Topic::ExecutionPayloadBid => "execution_payload_bid",
            Topic::PayloadAttestationMessage => "payload_attestation_message",
            Topic::FastConfirmation => "fast_confirmation",
            Topic::ProposerPreferences => "proposer_preferences",
        }
    }
}

/// Error returned by [`Topic::from_str`] for a name matching no topic, and by
/// [`Topic::parse_accepted`] for one outside the accepted set.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown topic: '{0}'")]
pub struct UnknownTopic(String);

impl UnknownTopic {
    /// The name that was refused, for a surface that words its own error.
    pub fn name(&self) -> &str {
        &self.0
    }
}

impl FromStr for Topic {
    type Err = UnknownTopic;

    /// Exact inverse of [`Topic::as_str`].
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Topic::ALL
            .iter()
            .copied()
            .find(|topic| topic.as_str() == s)
            .ok_or_else(|| UnknownTopic(s.to_string()))
    }
}

/// A consensus event published by the blockchain actor.
///
/// The lean variants mirror the Beacon API eventstream payloads loosely, as
/// the lean surface always has: `block` is the block root, `state` the state
/// root, and `slot` stands in for the beacon `epoch`, all integers bare.
/// [`ChainEvent::JustifiedCheckpoint`] has no beacon analog; it mirrors
/// [`ChainEvent::FinalizedCheckpoint`]'s shape as an ethlambda extension.
///
/// The `Beacon*` variants, [`ChainEvent::ChainReorg`] and
/// [`ChainEvent::DataColumnSidecar`] are the Beacon API's own payloads, field
/// for field, with every integer a quoted decimal. Each wraps a struct, so the
/// shape a variant serializes to is stated once, on that struct.
///
/// `#[serde(untagged)]` serializes only the active variant's fields, so the SSE
/// `data:` body stays flat (`0x`-hex roots) while the topic name travels
/// out-of-band on the `event:` line via [`ChainEvent::topic`]. Only
/// `Serialize` is derived, never `Deserialize`: an untagged shape would
/// deserialize ambiguously since the `{slot, block, state}` variants are
/// structurally identical, but serialization always knows its variant.
#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum ChainEvent {
    /// Fork choice selected a new head.
    Head { slot: u64, block: H256, state: H256 },
    /// A block was imported into the store.
    Block { slot: u64, block: H256 },
    /// The justified checkpoint advanced.
    JustifiedCheckpoint { slot: u64, block: H256, state: H256 },
    /// The finalized checkpoint advanced.
    FinalizedCheckpoint { slot: u64, block: H256, state: H256 },
    /// A block seen on gossip, before import. Analog of beacon `block_gossip`;
    /// `block` is imported later once its parent chain is available.
    BlockGossip { slot: u64, block: H256 },
    /// A single validator vote seen on gossip. Carries the vote's
    /// [`AttestationData`] and the attester's validator id; the ~3 KB XMSS
    /// signature is deliberately omitted (too heavy for a high-rate stream).
    Attestation {
        validator_id: u64,
        data: AttestationData,
    },
    /// A committee-signature aggregate: its [`AttestationData`] and the
    /// participating validator ids. The SNARK proof bytes are omitted.
    Aggregate {
        participants: Vec<u64>,
        data: AttestationData,
    },
    /// Beacon `head`.
    BeaconHead(BeaconHeadEvent),
    /// Beacon `block`: a block was imported.
    BeaconBlock(BeaconBlockEvent),
    /// Beacon `block_gossip`: a block passed gossip validation.
    BeaconBlockGossip(BeaconBlockGossipEvent),
    /// Beacon `finalized_checkpoint`.
    BeaconFinalizedCheckpoint(BeaconFinalizedCheckpointEvent),
    /// Beacon `chain_reorg`: the new head does not descend from the previous
    /// one.
    ChainReorg(ChainReorgEvent),
    /// Beacon `attestation`: an accepted aggregate's attestation. Boxed, since
    /// it is the one payload much larger than the rest and every slot of the
    /// broadcast ring is sized for the largest variant.
    BeaconAttestation(Box<BeaconAttestationEvent>),
    /// Beacon `data_column_sidecar`: a column this node custodies was stored.
    DataColumnSidecar(DataColumnSidecarEvent),
}

impl ChainEvent {
    pub fn topic(&self) -> Topic {
        match self {
            ChainEvent::Head { .. } | ChainEvent::BeaconHead(_) => Topic::Head,
            ChainEvent::Block { .. } | ChainEvent::BeaconBlock(_) => Topic::Block,
            ChainEvent::JustifiedCheckpoint { .. } => Topic::JustifiedCheckpoint,
            ChainEvent::FinalizedCheckpoint { .. } | ChainEvent::BeaconFinalizedCheckpoint(_) => {
                Topic::FinalizedCheckpoint
            }
            ChainEvent::BlockGossip { .. } | ChainEvent::BeaconBlockGossip(_) => Topic::BlockGossip,
            ChainEvent::Attestation { .. } | ChainEvent::BeaconAttestation(_) => Topic::Attestation,
            ChainEvent::Aggregate { .. } => Topic::Aggregate,
            ChainEvent::ChainReorg(_) => Topic::ChainReorg,
            ChainEvent::DataColumnSidecar(_) => Topic::DataColumnSidecar,
        }
    }
}

/// The Beacon API `head` payload.
///
/// The two dependent roots are `get_block_root_at_slot(state,
/// compute_start_slot_at_epoch(epoch) - 1)` (current) and the same one epoch
/// earlier (previous), `epoch` being the head's own; a validator client
/// refetches its duties when one changes. Both fall back to the genesis block
/// root on underflow, as the specification's `head_v2` wording states for the
/// same computation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BeaconHeadEvent {
    #[serde(serialize_with = "quoted_or_bare::serialize")]
    pub slot: u64,
    pub block: H256,
    pub state: H256,
    /// Whether the head's epoch is later than the previous head's.
    pub epoch_transition: bool,
    pub previous_duty_dependent_root: H256,
    pub current_duty_dependent_root: H256,
    pub execution_optimistic: bool,
}

/// The Beacon API `block` payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BeaconBlockEvent {
    #[serde(serialize_with = "quoted_or_bare::serialize")]
    pub slot: u64,
    pub block: H256,
    pub execution_optimistic: bool,
}

/// The Beacon API `block_gossip` payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BeaconBlockGossipEvent {
    #[serde(serialize_with = "quoted_or_bare::serialize")]
    pub slot: u64,
    pub block: H256,
}

/// The Beacon API `finalized_checkpoint` payload. `state` is the finalized
/// block's post-state root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BeaconFinalizedCheckpointEvent {
    pub block: H256,
    pub state: H256,
    #[serde(serialize_with = "quoted_or_bare::serialize")]
    pub epoch: u64,
    pub execution_optimistic: bool,
}

/// The Beacon API `chain_reorg` payload.
///
/// `slot` and `epoch` are the new head's; `depth` is how many slots the
/// previous head sat above the two heads' common ancestor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ChainReorgEvent {
    #[serde(serialize_with = "quoted_or_bare::serialize")]
    pub slot: u64,
    #[serde(serialize_with = "quoted_or_bare::serialize")]
    pub depth: u64,
    pub old_head_block: H256,
    pub new_head_block: H256,
    pub old_head_state: H256,
    pub new_head_state: H256,
    #[serde(serialize_with = "quoted_or_bare::serialize")]
    pub epoch: u64,
    pub execution_optimistic: bool,
}

/// The Beacon API `attestation` payload: the `Attestation` an accepted
/// `SignedAggregateAndProof` carries, in its own fork's shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum BeaconAttestationEvent {
    Phase0(phase0::Attestation),
    Electra(electra::Attestation),
}

impl From<&SignedAggregateAndProof> for BeaconAttestationEvent {
    fn from(aggregate: &SignedAggregateAndProof) -> Self {
        match aggregate {
            SignedAggregateAndProof::Phase0(signed) => {
                Self::Phase0(signed.message.aggregate.clone())
            }
            SignedAggregateAndProof::Electra(signed) => {
                Self::Electra(signed.message.aggregate.clone())
            }
        }
    }
}

/// The Beacon API `data_column_sidecar` payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DataColumnSidecarEvent {
    pub block_root: H256,
    #[serde(serialize_with = "quoted_or_bare::serialize")]
    pub index: u64,
    #[serde(serialize_with = "quoted_or_bare::serialize")]
    pub slot: u64,
}

/// Capacity of the chain-event broadcast channel.
///
/// Chosen so a briefly-stalled subscriber is skipped past (lagged) rather than
/// back-pressuring the actor. Lagged subscribers re-sync via the blocks
/// endpoints.
///
/// All topics share this one ring buffer, so the high-rate `attestation` and
/// `aggregate` events (roughly one per validator per slot) dominate its
/// occupancy: the window a slow subscriber can tolerate is
/// `capacity / total_event_rate`, not per-topic. Sized for a few minutes of
/// history at devnet validator counts; a per-topic split behind the
/// [`EventBus`] facade is the escape hatch if the shared window bites.
const CHAIN_EVENT_CHANNEL_CAPACITY: usize = 8192;

/// Cloneable handle to the chain-event broadcast channel.
///
/// Owned solely by [`crate::BlockChainServer`] (never `Option`, never
/// threaded into `store.rs`): on lean the actor snapshots store state before a
/// call to `store::on_tick`/`store::on_block`, runs it unchanged, then diffs
/// and calls [`EventBus::emit`] itself; on beacon it diffs a
/// [`BeaconEventView`] it keeps between calls. Call sites that must stay
/// eventless (spec tests, `test_driver.rs`) simply never construct a live bus.
#[derive(Clone)]
pub struct EventBus {
    tx: broadcast::Sender<ChainEvent>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self { tx }
    }

    /// Publish an event to all current subscribers.
    ///
    /// Never blocks, never fails: without subscribers this is a no-op, and a
    /// send error (every subscriber dropped since the guard) is ignored.
    pub fn emit(&self, event: ChainEvent) {
        if self.tx.receiver_count() == 0 {
            return;
        }
        let _ = self.tx.send(event);
    }

    /// Subscribe a new receiver observing every event emitted from now on.
    pub fn subscribe(&self) -> broadcast::Receiver<ChainEvent> {
        self.tx.subscribe()
    }

    /// Whether any receiver is attached, the same test [`EventBus::emit`]
    /// runs.
    ///
    /// For emission sites whose payload costs something to build (a state
    /// read, a clone of an aggregate): asking first lets a node with no
    /// subscriber skip that work, where `emit` alone would build the payload
    /// only to drop it. Any subscriber counts, whatever topics it filters on,
    /// since filtering happens after the event is received.
    pub fn has_subscribers(&self) -> bool {
        self.tx.receiver_count() > 0
    }
}

impl Default for EventBus {
    /// A live bus with the default channel capacity
    /// ([`CHAIN_EVENT_CHANNEL_CAPACITY`]).
    fn default() -> Self {
        Self::new(CHAIN_EVENT_CHANNEL_CAPACITY)
    }
}

/// Suppresses `head` events whose slot has fallen too far behind the wall
/// clock: during startup catch-up or backfill, fork choice can walk through
/// many historical heads on its way to the tip, and none of those are
/// interesting to a live subscriber. Consumers that need to track sync
/// progress should watch `block` events instead, which are never gated on
/// recency. Mirrors Lighthouse's recency filter on its head SSE event
/// (`EARLY_ATTESTER_CACHE_HISTORIC_SLOTS`), but with a wider window since a
/// lagging head is far more common here during multi-slot catch-up ticks.
pub(crate) const HEAD_EVENT_RECENCY_SLOTS: u64 = 32;

/// Pre-call snapshot of the store values the lean chain-event bus reports on.
///
/// The actor — not the store — publishes chain events: it captures this
/// snapshot before a store call (`store::on_tick`, `store::on_block`) and
/// diffs the store against it afterwards, so `store.rs` needs no event
/// plumbing.
///
/// Lean only. A beacon head moves in `recompute_beacon_head`, outside any one
/// store call, so the beacon chain diffs against a [`BeaconEventView`] the
/// actor keeps between calls instead.
///
/// Multiple head moves within one store call coalesce into a single `head`
/// event; subscribers only care about the latest.
///
/// The proposer's pre-build catch-up (`get_proposal_head`) advances the store
/// too, so `propose_block` wraps that call in its own snapshot: the
/// head/justified/finalized moves it triggers surface exactly as they would on
/// a non-proposing node's interval-0 tick, rather than being silently folded
/// into the later block-import diff's baseline.
pub(crate) struct ChainEventSnapshot {
    head: H256,
    justified: Checkpoint,
    finalized: Checkpoint,
}

impl ChainEventSnapshot {
    pub(crate) fn capture(store: &Store) -> Self {
        Self {
            head: store.head().expect("head block exists"),
            justified: store
                .latest_justified()
                .expect("latest justified checkpoint exists"),
            finalized: store
                .latest_finalized()
                .expect("latest finalized checkpoint exists"),
        }
    }

    /// Emit one event per value that changed since the snapshot, in a fixed
    /// order: `head` → `justified_checkpoint` → `finalized_checkpoint`.
    /// (`block` is emitted separately by the import path, ahead of this diff.)
    ///
    /// `wall_clock_slot` is the caller's current slot, used only to gate the
    /// `head` event against [`HEAD_EVENT_RECENCY_SLOTS`]; the other events are
    /// ungated.
    pub(crate) fn diff_and_emit(&self, store: &Store, events: &EventBus, wall_clock_slot: u64) {
        let head = store.head().expect("head block exists");
        if head != self.head {
            // Read the block once and reuse it for slot and state root so they
            // stay consistent. Through `block_slot_and_state_root` rather than
            // `Store::get_block_header`, which decodes a lean `BlockHeader`
            // and so is lean-only: a beacon directory keeps the whole signed
            // block in that table, and this diff runs on both chains.
            if let Some((slot, state_root)) = store.block_slot_and_state_root(&head) {
                // Skip stale heads (catch-up/backfill): see HEAD_EVENT_RECENCY_SLOTS.
                if slot + HEAD_EVENT_RECENCY_SLOTS >= wall_clock_slot {
                    events.emit(ChainEvent::Head {
                        slot,
                        block: head,
                        state: state_root,
                    });
                }
            } else {
                warn!(
                    head_root = %ShortRoot(&head.0),
                    "Head header missing while emitting head event; skipping"
                );
            }
        }

        let justified = store
            .latest_justified()
            .expect("latest justified checkpoint exists");
        if justified != self.justified {
            if let Some(state) = checkpoint_state_root(store, justified.root) {
                events.emit(ChainEvent::JustifiedCheckpoint {
                    slot: justified.slot,
                    block: justified.root,
                    state,
                });
            } else {
                warn!(
                    justified_root = %ShortRoot(&justified.root.0),
                    "Justified block header missing while emitting event; skipping"
                );
            }
        }

        let finalized = store
            .latest_finalized()
            .expect("latest finalized checkpoint exists");
        if finalized != self.finalized {
            if let Some(state) = checkpoint_state_root(store, finalized.root) {
                events.emit(ChainEvent::FinalizedCheckpoint {
                    slot: finalized.slot,
                    block: finalized.root,
                    state,
                });
            } else {
                warn!(
                    finalized_root = %ShortRoot(&finalized.root.0),
                    "Finalized block header missing while emitting event; skipping"
                );
            }
        }
    }
}

/// Look up the state root of a checkpoint's block for the `{block, state}`
/// event shape. Returns `None` if the block is absent so the caller can skip
/// emission; finalized/justified blocks are never pruned from
/// `Table::BlockHeaders`, so this only fails on genuine store inconsistency.
///
/// Chain-generic, for the reason [`ChainEventSnapshot::diff_and_emit`] gives
/// where it reads the head's own pair.
fn checkpoint_state_root(store: &Store, root: H256) -> Option<H256> {
    store
        .block_slot_and_state_root(&root)
        .map(|(_, state_root)| state_root)
}

/// The head and finalized checkpoint the beacon chain events last reported
/// on, kept by the actor between calls.
///
/// Why a persistent view rather than a [`ChainEventSnapshot`] around each
/// store call: a beacon head moves in `recompute_beacon_head`, after the
/// import cascade and after the tick's clock advance, so a snapshot window
/// around either call misses it, and the next window captures the head it
/// already moved to. A view cannot be missed: whatever moved the head since
/// the last diff, the next diff sees it. Several moves between two diffs
/// coalesce into one event.
///
/// Roots only. The previous head's slot and state root are read back from the
/// store when a diff has a subscriber to report to, so a node nobody listens
/// to pays two metadata reads per diff and nothing more. Its block stays
/// readable: `Table::BlockHeaders` is not pruned on beacon, and an
/// invalidated branch loses only its `LiveChain` rows.
pub(crate) struct BeaconEventView {
    head: H256,
    finalized: Checkpoint,
}

impl BeaconEventView {
    pub(crate) fn capture(store: &Store) -> Self {
        Self {
            head: store.head().expect("head block exists"),
            finalized: store
                .latest_finalized()
                .expect("latest finalized checkpoint exists"),
        }
    }

    /// Emit what changed since the last call, then remember the store's
    /// current values whether or not anything was emitted.
    ///
    /// Order: `chain_reorg` -> `head` -> `finalized_checkpoint`. Only `head`
    /// is gated, against [`HEAD_EVENT_RECENCY_SLOTS`] of `wall_clock_slot`.
    pub(crate) fn publish_changes(
        &mut self,
        store: &Store,
        events: &EventBus,
        wall_clock_slot: u64,
    ) {
        let previous = std::mem::replace(self, Self::capture(store));
        if !events.has_subscribers() {
            return;
        }
        if self.head != previous.head {
            publish_head_change(store, events, &previous, self.head, wall_clock_slot);
        }
        if self.finalized != previous.finalized {
            publish_finalized_checkpoint(store, events, self.finalized);
        }
    }
}

/// `chain_reorg` (if the new head does not descend from the previous one) and
/// `head` (if recent enough) for a head move from `previous.head` to `head`.
fn publish_head_change(
    store: &Store,
    events: &EventBus,
    previous: &BeaconEventView,
    head: H256,
    wall_clock_slot: u64,
) {
    let (Some((old_slot, old_state)), Some((new_slot, new_state))) = (
        store.block_slot_and_state_root(&previous.head),
        store.block_slot_and_state_root(&head),
    ) else {
        warn!(
            old_head = %ShortRoot(&previous.head.0),
            new_head = %ShortRoot(&head.0),
            "Head block missing while emitting head events; skipping"
        );
        return;
    };
    let head_state = match store.get_state(&head) {
        Ok(Some(state)) => state,
        Ok(None) | Err(_) => {
            warn!(
                head_root = %ShortRoot(&head.0),
                "Head state missing while emitting head events; skipping"
            );
            return;
        }
    };
    let new_chain = NewChain {
        state: &head_state,
        root: head,
        slot: new_slot,
    };
    let execution_optimistic = store.is_beacon_optimistic(head);

    if !new_chain.contains(previous.head, old_slot) {
        let ancestor_slot = common_ancestor_slot(store, &new_chain, previous);
        events.emit(ChainEvent::ChainReorg(ChainReorgEvent {
            slot: new_slot,
            depth: old_slot.saturating_sub(ancestor_slot),
            old_head_block: previous.head,
            new_head_block: head,
            old_head_state: old_state,
            new_head_state: new_state,
            epoch: compute_epoch_at_slot(new_slot),
            execution_optimistic,
        }));
    }

    // Skip stale heads (catch-up/backfill): see HEAD_EVENT_RECENCY_SLOTS.
    if new_slot + HEAD_EVENT_RECENCY_SLOTS < wall_clock_slot {
        return;
    }
    let epoch = compute_epoch_at_slot(new_slot);
    events.emit(ChainEvent::BeaconHead(BeaconHeadEvent {
        slot: new_slot,
        block: head,
        state: new_state,
        epoch_transition: epoch > compute_epoch_at_slot(old_slot),
        previous_duty_dependent_root: new_chain.dependent_root(epoch.checked_sub(1)),
        current_duty_dependent_root: new_chain.dependent_root(Some(epoch)),
        execution_optimistic,
    }));
}

fn publish_finalized_checkpoint(store: &Store, events: &EventBus, finalized: Checkpoint) {
    let Some(state) = checkpoint_state_root(store, finalized.root) else {
        warn!(
            finalized_root = %ShortRoot(&finalized.root.0),
            "Finalized block missing while emitting event; skipping"
        );
        return;
    };
    events.emit(ChainEvent::BeaconFinalizedCheckpoint(
        BeaconFinalizedCheckpointEvent {
            block: finalized.root,
            state,
            // A beacon checkpoint is stored as its epoch's start slot.
            epoch: compute_epoch_at_slot(finalized.slot),
            execution_optimistic: store.is_beacon_optimistic(finalized.root),
        },
    ));
}

/// The chain ending at the new head, read through the head's post-state.
///
/// A post-state's `block_roots` names the latest block at or before each of
/// the `SLOTS_PER_HISTORICAL_ROOT` slots below its own, so "is this block on
/// the new chain" is one lookup rather than a walk down it, and the state is
/// already loaded for the dependent roots. That window spans more than a day
/// of slots, far more than a head moves between two diffs.
struct NewChain<'a> {
    state: &'a BeaconState,
    root: H256,
    slot: u64,
}

impl NewChain<'_> {
    /// Whether the block `root`, at `slot`, is the new head or one of its
    /// ancestors.
    fn contains(&self, root: H256, slot: u64) -> bool {
        root == self.root
            || (slot < self.slot
                && get_block_root_at_slot(self.state, slot).is_ok_and(|on_chain| on_chain == root))
    }

    /// `get_block_root_at_slot(state, compute_start_slot_at_epoch(epoch) - 1)`,
    /// or the genesis block root when `epoch` is `None` (the caller's own
    /// `epoch - 1` underflowed) or the start slot is zero.
    ///
    /// The lookup cannot fail for the two epochs asked about: both slots sit
    /// below the head's own and within two epochs of it. The head's root
    /// stands in if it ever did, rather than a panic on the actor.
    fn dependent_root(&self, epoch: Option<u64>) -> H256 {
        let slot = epoch.and_then(|epoch| compute_start_slot_at_epoch(epoch).checked_sub(1));
        match slot {
            Some(slot) => get_block_root_at_slot(self.state, slot).unwrap_or(self.root),
            None => self.genesis_root(),
        }
    }

    /// The genesis block's root: the head itself at slot zero, otherwise the
    /// root the state recorded for slot zero. Only asked for while the head is
    /// in epoch 0 or 1, which keeps slot zero inside the state's window.
    fn genesis_root(&self) -> H256 {
        if self.slot == 0 {
            return self.root;
        }
        get_block_root_at_slot(self.state, 0).unwrap_or(self.root)
    }
}

/// The slot of the latest block on both the previous head's chain and the
/// new one.
///
/// Walks the previous head's parent links (one block decode per step) until a
/// block is on the new chain, which a reorg keeps to a few steps. Every head
/// descends from the finalized checkpoint the previous diff saw, so the walk
/// meets the new chain by then; it stops once it has checked a block below
/// that checkpoint's slot and answers with that slot, which only a store
/// missing blocks reaches.
fn common_ancestor_slot(
    store: &Store,
    new_chain: &NewChain<'_>,
    previous: &BeaconEventView,
) -> u64 {
    let floor = previous.finalized.slot;
    let mut root = previous.head;
    while let Some((slot, parent)) = store.block_entry(&root) {
        if new_chain.contains(root, slot) {
            return slot;
        }
        if slot < floor {
            break;
        }
        root = parent;
    }
    warn!(
        old_head = %ShortRoot(&previous.head.0),
        new_head = %ShortRoot(&new_chain.root.0),
        "No common ancestor above the finalized checkpoint; reporting reorg depth from it"
    );
    floor
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_storage::{ForkCheckpoints, backend::InMemoryBackend};
    use ethlambda_types::constants::DEFAULT_MILLISECONDS_PER_SLOT;
    use ethlambda_types::{
        beacon::containers::SignedBeaconBlock,
        block::{Block, BlockBody, MultiMessageAggregate, SignedBlock},
        state::State,
    };
    use std::sync::Arc;
    use tokio::sync::broadcast::error::TryRecvError;

    fn head_event(slot: u64) -> ChainEvent {
        ChainEvent::Head {
            slot,
            block: H256([1u8; 32]),
            state: H256([2u8; 32]),
        }
    }

    fn test_attestation_data(slot: u64) -> AttestationData {
        AttestationData {
            slot,
            head: Checkpoint::default(),
            target: Checkpoint::default(),
            source: Checkpoint::default(),
        }
    }

    #[tokio::test]
    async fn subscriber_receives_emitted_event() {
        let bus = EventBus::default();
        let mut rx = bus.subscribe();

        bus.emit(head_event(7));

        match rx.recv().await.unwrap() {
            ChainEvent::Head { slot, .. } => assert_eq!(slot, 7),
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn topic_from_str_inverts_as_str() {
        for &topic in Topic::ALL {
            assert_eq!(topic.as_str().parse::<Topic>().unwrap(), topic);
        }
        let err = "bogus".parse::<Topic>().unwrap_err();
        assert_eq!(err.to_string(), "unknown topic: 'bogus'");
    }

    #[test]
    fn every_topic_is_listed_once_and_named_uniquely() {
        let names: std::collections::HashSet<&str> =
            Topic::ALL.iter().map(|topic| topic.as_str()).collect();
        assert_eq!(names.len(), Topic::ALL.len());
    }

    /// The lean surface's accepted set is exactly the seven it has always
    /// served, so adding beacon names changes nothing there.
    #[test]
    fn the_lean_set_is_the_original_seven() {
        let names: Vec<&str> = Topic::LEAN.iter().map(|topic| topic.as_str()).collect();
        assert_eq!(
            names,
            [
                "head",
                "block",
                "justified_checkpoint",
                "finalized_checkpoint",
                "block_gossip",
                "attestation",
                "aggregate",
            ]
        );
    }

    /// beacon-APIs `apis/eventstream/index.yaml`'s `topics` enum, plus
    /// `blob_sidecar` from its last release.
    #[test]
    fn the_beacon_set_is_the_specifications() {
        let mut names: Vec<&str> = Topic::BEACON.iter().map(|topic| topic.as_str()).collect();
        names.sort_unstable();
        let mut specification = vec![
            "head",
            "head_v2",
            "block",
            "block_gossip",
            "attestation",
            "single_attestation",
            "voluntary_exit",
            "bls_to_execution_change",
            "proposer_slashing",
            "attester_slashing",
            "finalized_checkpoint",
            "chain_reorg",
            "contribution_and_proof",
            "light_client_finality_update",
            "light_client_optimistic_update",
            "payload_attributes",
            "data_column_sidecar",
            "execution_payload",
            "execution_payload_gossip",
            "execution_payload_available",
            "execution_payload_bid",
            "payload_attestation_message",
            "fast_confirmation",
            "proposer_preferences",
            "blob_sidecar",
        ];
        specification.sort_unstable();
        assert_eq!(names, specification);
    }

    #[test]
    fn a_topic_outside_the_accepted_set_is_unknown() {
        assert_eq!(Topic::parse_accepted("head", Topic::LEAN), Ok(Topic::Head));
        let err = Topic::parse_accepted("chain_reorg", Topic::LEAN).unwrap_err();
        assert_eq!(err.name(), "chain_reorg");
        assert!(Topic::parse_accepted("aggregate", Topic::BEACON).is_err());
        assert!(Topic::parse_accepted("justified_checkpoint", Topic::BEACON).is_err());
        assert!(Topic::parse_accepted("weather_forecast", Topic::BEACON).is_err());
    }

    #[test]
    fn has_subscribers_follows_the_receivers() {
        let bus = EventBus::default();
        assert!(!bus.has_subscribers());
        let rx = bus.subscribe();
        assert!(bus.has_subscribers());
        drop(rx);
        assert!(!bus.has_subscribers());
    }

    #[test]
    fn emit_without_subscribers_is_a_noop() {
        let bus = EventBus::default();
        // No subscriber attached: must neither error nor panic.
        bus.emit(head_event(1));
    }

    #[test]
    fn topic_maps_every_variant() {
        let block = H256::ZERO;
        let state = H256::ZERO;
        let cases = [
            (head_event(1), Topic::Head),
            (ChainEvent::Block { slot: 1, block }, Topic::Block),
            (
                ChainEvent::JustifiedCheckpoint {
                    slot: 1,
                    block,
                    state,
                },
                Topic::JustifiedCheckpoint,
            ),
            (
                ChainEvent::FinalizedCheckpoint {
                    slot: 1,
                    block,
                    state,
                },
                Topic::FinalizedCheckpoint,
            ),
            (
                ChainEvent::BlockGossip { slot: 1, block },
                Topic::BlockGossip,
            ),
            (
                ChainEvent::Attestation {
                    validator_id: 0,
                    data: test_attestation_data(1),
                },
                Topic::Attestation,
            ),
            (
                ChainEvent::Aggregate {
                    participants: vec![0, 1],
                    data: test_attestation_data(1),
                },
                Topic::Aggregate,
            ),
        ];
        for (event, topic) in cases {
            assert_eq!(event.topic(), topic);
            assert_eq!(event.topic().as_str(), topic.as_str());
        }
    }

    fn test_store() -> Store {
        let genesis_state = State::from_genesis(1000, vec![]);
        Store::from_anchor_state(
            Arc::new(InMemoryBackend::new()),
            genesis_state,
            DEFAULT_MILLISECONDS_PER_SLOT,
        )
    }

    /// Insert a header-only block at `root` so header reads (block root, slot,
    /// state root) resolve for the event payloads.
    fn insert_test_block(
        store: &mut Store,
        root: H256,
        slot: u64,
        parent_root: H256,
        state_root: H256,
    ) {
        let signed_block = SignedBlock {
            message: Block {
                slot,
                proposer_index: 0,
                parent_root,
                state_root,
                body: BlockBody::default(),
            },
            proof: MultiMessageAggregate::default(),
        };
        store
            .insert_signed_block(root, SignedBeaconBlock::Lean(signed_block))
            .expect("insert test block should succeed");
    }

    #[test]
    fn chain_event_diff_emits_nothing_when_unchanged() {
        let store = test_store();
        let bus = EventBus::new(8);
        let mut rx = bus.subscribe();

        let snapshot = ChainEventSnapshot::capture(&store);
        snapshot.diff_and_emit(&store, &bus, 0);

        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
    }

    /// A head far below the wall-clock slot (catch-up/backfill) emits no
    /// `head` event, but `justified_checkpoint`/`finalized_checkpoint` still
    /// fire since only `head` is gated.
    #[test]
    fn chain_event_diff_gates_stale_head() {
        let mut store = test_store();
        let genesis = store.head().expect("store head exists");
        let bus = EventBus::new(8);
        let mut rx = bus.subscribe();

        let snapshot = ChainEventSnapshot::capture(&store);

        let new_root = H256([9u8; 32]);
        let new_state = H256([99u8; 32]);
        insert_test_block(&mut store, new_root, 1, genesis, new_state);
        let checkpoint = Checkpoint {
            root: new_root,
            slot: 1,
        };
        store
            .update_checkpoints(ForkCheckpoints::new(
                new_root,
                Some(checkpoint),
                Some(checkpoint),
            ))
            .expect("update_checkpoints should succeed");

        // Wall clock far ahead of the new head's slot (1): well past
        // HEAD_EVENT_RECENCY_SLOTS, so the head event must be suppressed.
        let wall_clock_slot = 1 + HEAD_EVENT_RECENCY_SLOTS + 100;
        snapshot.diff_and_emit(&store, &bus, wall_clock_slot);

        match rx.try_recv().unwrap() {
            ChainEvent::JustifiedCheckpoint { slot, block, state } => {
                assert_eq!((slot, block, state), (1, new_root, new_state));
            }
            other => panic!("expected justified_checkpoint first, got: {other:?}"),
        }
        match rx.try_recv().unwrap() {
            ChainEvent::FinalizedCheckpoint { slot, block, state } => {
                assert_eq!((slot, block, state), (1, new_root, new_state));
            }
            other => panic!("expected finalized_checkpoint second (head gated), got: {other:?}"),
        }
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
    }

    /// A head within the recency window emits normally, stated explicitly
    /// against the gate for clarity.
    #[test]
    fn chain_event_diff_emits_recent_head() {
        let mut store = test_store();
        let genesis = store.head().expect("store head exists");
        let bus = EventBus::new(8);
        let mut rx = bus.subscribe();

        let snapshot = ChainEventSnapshot::capture(&store);

        let new_root = H256([9u8; 32]);
        let new_state = H256([99u8; 32]);
        insert_test_block(&mut store, new_root, 1, genesis, new_state);
        store
            .update_checkpoints(ForkCheckpoints::head_only(new_root))
            .expect("update_checkpoints should succeed");

        // Wall clock equal to the head's own slot: as recent as it gets.
        snapshot.diff_and_emit(&store, &bus, 1);

        match rx.try_recv().unwrap() {
            ChainEvent::Head { slot, block, state } => {
                assert_eq!((slot, block, state), (1, new_root, new_state));
            }
            other => panic!("expected head event, got: {other:?}"),
        }
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
    }

    // -----------------------------------------------------------------
    // Beacon payloads against the specification's own examples
    // (beacon-APIs `apis/eventstream/index.yaml`)
    // -----------------------------------------------------------------

    fn root(hex: &str) -> H256 {
        serde_json::from_value(serde_json::Value::String(hex.to_string())).unwrap()
    }

    /// Serialize `event` and compare it with the specification's example,
    /// field for field (so quoting, names and booleans all count).
    fn assert_matches_example(event: ChainEvent, topic: Topic, example: &str) {
        assert_eq!(event.topic(), topic);
        let expected: serde_json::Value = serde_json::from_str(example).unwrap();
        assert_eq!(serde_json::to_value(&event).unwrap(), expected);
    }

    const BLOCK: &str = "0x9a2fefd2fdb57f74993c7780ea5b9030d2897b615b89f808011ca5aebed54eaf";
    const STATE: &str = "0x600e852a08c1200654ddf11025f1ceacb3c2e74bdd5c630cde0838b2591b69f9";

    #[test]
    fn beacon_head_matches_the_specification_example() {
        let dependent = root("0x5e0043f107cb57913498fbf2f99ff55e730bf1e151f02f221e977c91a90a0e91");
        let event = ChainEvent::BeaconHead(BeaconHeadEvent {
            slot: 10,
            block: root(BLOCK),
            state: root(STATE),
            epoch_transition: false,
            previous_duty_dependent_root: dependent,
            current_duty_dependent_root: dependent,
            execution_optimistic: false,
        });
        assert_matches_example(
            event,
            Topic::Head,
            r#"{"slot":"10", "block":"0x9a2fefd2fdb57f74993c7780ea5b9030d2897b615b89f808011ca5aebed54eaf", "state":"0x600e852a08c1200654ddf11025f1ceacb3c2e74bdd5c630cde0838b2591b69f9", "epoch_transition":false, "previous_duty_dependent_root":"0x5e0043f107cb57913498fbf2f99ff55e730bf1e151f02f221e977c91a90a0e91", "current_duty_dependent_root":"0x5e0043f107cb57913498fbf2f99ff55e730bf1e151f02f221e977c91a90a0e91", "execution_optimistic": false}"#,
        );
    }

    #[test]
    fn beacon_block_matches_the_specification_example() {
        let event = ChainEvent::BeaconBlock(BeaconBlockEvent {
            slot: 10,
            block: root(BLOCK),
            execution_optimistic: false,
        });
        assert_matches_example(
            event,
            Topic::Block,
            r#"{"slot":"10", "block":"0x9a2fefd2fdb57f74993c7780ea5b9030d2897b615b89f808011ca5aebed54eaf", "execution_optimistic": false}"#,
        );
    }

    #[test]
    fn beacon_block_gossip_matches_the_specification_example() {
        let event = ChainEvent::BeaconBlockGossip(BeaconBlockGossipEvent {
            slot: 10,
            block: root(BLOCK),
        });
        assert_matches_example(
            event,
            Topic::BlockGossip,
            r#"{"slot":"10", "block":"0x9a2fefd2fdb57f74993c7780ea5b9030d2897b615b89f808011ca5aebed54eaf"}"#,
        );
    }

    #[test]
    fn beacon_finalized_checkpoint_matches_the_specification_example() {
        let event = ChainEvent::BeaconFinalizedCheckpoint(BeaconFinalizedCheckpointEvent {
            block: root(BLOCK),
            state: root(STATE),
            epoch: 2,
            execution_optimistic: false,
        });
        assert_matches_example(
            event,
            Topic::FinalizedCheckpoint,
            r#"{"block":"0x9a2fefd2fdb57f74993c7780ea5b9030d2897b615b89f808011ca5aebed54eaf", "state":"0x600e852a08c1200654ddf11025f1ceacb3c2e74bdd5c630cde0838b2591b69f9", "epoch":"2", "execution_optimistic": false }"#,
        );
    }

    #[test]
    fn chain_reorg_matches_the_specification_example() {
        let event = ChainEvent::ChainReorg(ChainReorgEvent {
            slot: 200,
            depth: 50,
            old_head_block: root(BLOCK),
            new_head_block: root(
                "0x76262e91970d375a19bfe8a867288d7b9cde43c8635f598d93d39d041706fc76",
            ),
            old_head_state: root(BLOCK),
            new_head_state: root(STATE),
            epoch: 2,
            execution_optimistic: false,
        });
        assert_matches_example(
            event,
            Topic::ChainReorg,
            r#"{"slot":"200", "depth":"50", "old_head_block":"0x9a2fefd2fdb57f74993c7780ea5b9030d2897b615b89f808011ca5aebed54eaf", "new_head_block":"0x76262e91970d375a19bfe8a867288d7b9cde43c8635f598d93d39d041706fc76", "old_head_state":"0x9a2fefd2fdb57f74993c7780ea5b9030d2897b615b89f808011ca5aebed54eaf", "new_head_state":"0x600e852a08c1200654ddf11025f1ceacb3c2e74bdd5c630cde0838b2591b69f9", "epoch":"2", "execution_optimistic": false}"#,
        );
    }

    #[test]
    fn data_column_sidecar_matches_the_specification_example() {
        let event = ChainEvent::DataColumnSidecar(DataColumnSidecarEvent {
            block_root: root("0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"),
            index: 1,
            slot: 1,
        });
        assert_matches_example(
            event,
            Topic::DataColumnSidecar,
            r#"{"block_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2", "index": "1", "slot": "1"}"#,
        );
    }

    /// The example is an electra `Attestation`, which this node's own
    /// container decodes; carried through the event it must come back out
    /// unchanged.
    #[test]
    fn beacon_attestation_matches_the_specification_example() {
        let example = r#"{"aggregation_bits":"0x01", "data":{"slot":"1", "index":"1", "beacon_block_root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2", "source":{"epoch":"1", "root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"}, "target":{"epoch":"1", "root":"0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"}}, "signature":"0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505", "committee_bits":"0x0000000000000001"}"#;
        let attestation: electra::Attestation = serde_json::from_str(example).unwrap();
        let signed = SignedAggregateAndProof::Electra(electra::SignedAggregateAndProof {
            message: electra::AggregateAndProof {
                aggregator_index: 0,
                aggregate: attestation,
                selection_proof: Default::default(),
            },
            signature: Default::default(),
        });
        let event = ChainEvent::BeaconAttestation(Box::new(BeaconAttestationEvent::from(&signed)));
        assert_matches_example(event, Topic::Attestation, example);
    }
}
