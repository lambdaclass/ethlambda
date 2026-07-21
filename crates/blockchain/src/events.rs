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

use ethlambda_storage::Store;
use ethlambda_types::ShortRoot;
use ethlambda_types::checkpoint::Checkpoint;
use ethlambda_types::primitives::H256;
use serde::Serialize;
use std::str::FromStr;
use tokio::sync::broadcast;
use tracing::warn;

/// Wire-visible topic names for chain events.
///
/// These are the names consumers address events by (the SSE `event:` line and,
/// later, `?topics=` filtering), kept separate from [`ChainEvent`] so the
/// payload stays flat with the topic travelling out-of-band. Names match the
/// Ethereum beacon-API eventstream topics where an analog exists (`head`,
/// `block`, `finalized_checkpoint`, `chain_reorg`); `justified_checkpoint` and
/// `safe_target` are ethlambda extensions with no direct beacon topic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Topic {
    Head,
    Block,
    JustifiedCheckpoint,
    FinalizedCheckpoint,
    /// Fork choice switched to a head that is not a descendant of the old one.
    ChainReorg,
    /// The interval-3 fork-choice safe attestation target advanced.
    SafeTarget,
}

impl Topic {
    pub fn as_str(self) -> &'static str {
        match self {
            Topic::Head => "head",
            Topic::Block => "block",
            Topic::JustifiedCheckpoint => "justified_checkpoint",
            Topic::FinalizedCheckpoint => "finalized_checkpoint",
            Topic::ChainReorg => "chain_reorg",
            Topic::SafeTarget => "safe_target",
        }
    }
}

/// Error returned by [`Topic::from_str`] for a name matching no topic.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown topic: '{0}'")]
pub struct UnknownTopic(String);

impl FromStr for Topic {
    type Err = UnknownTopic;

    /// Exact inverse of [`Topic::as_str`].
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "head" => Ok(Topic::Head),
            "block" => Ok(Topic::Block),
            "justified_checkpoint" => Ok(Topic::JustifiedCheckpoint),
            "finalized_checkpoint" => Ok(Topic::FinalizedCheckpoint),
            "chain_reorg" => Ok(Topic::ChainReorg),
            "safe_target" => Ok(Topic::SafeTarget),
            other => Err(UnknownTopic(other.to_string())),
        }
    }
}

/// A consensus event published by the blockchain actor.
///
/// Fields mirror the Ethereum beacon-API eventstream payloads so the SSE
/// endpoint renders a beacon-compatible stream: `block` is the block root,
/// `state` the state root, and `slot` stands in for the beacon `epoch`.
/// [`ChainEvent::JustifiedCheckpoint`] has no beacon analog; it mirrors
/// [`ChainEvent::FinalizedCheckpoint`]'s shape as an ethlambda extension.
///
/// `#[serde(untagged)]` serializes only the active variant's fields, so the SSE
/// `data:` body stays flat (`0x`-hex roots, numeric slots) while the topic name
/// travels out-of-band on the `event:` line via [`ChainEvent::topic`]. Only
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
    /// Fork choice switched to a head off the old head's chain. `slot` is the
    /// new head's slot; `depth` the number of blocks rolled back. Mirrors the
    /// beacon `chain_reorg` payload minus `epoch`/`execution_optimistic`.
    ChainReorg {
        slot: u64,
        depth: u64,
        old_head_block: H256,
        old_head_state: H256,
        new_head_block: H256,
        new_head_state: H256,
    },
    /// The interval-3 safe attestation target advanced (ethlambda-specific).
    SafeTarget { slot: u64, block: H256 },
}

impl ChainEvent {
    pub fn topic(&self) -> Topic {
        match self {
            ChainEvent::Head { .. } => Topic::Head,
            ChainEvent::Block { .. } => Topic::Block,
            ChainEvent::JustifiedCheckpoint { .. } => Topic::JustifiedCheckpoint,
            ChainEvent::FinalizedCheckpoint { .. } => Topic::FinalizedCheckpoint,
            ChainEvent::ChainReorg { .. } => Topic::ChainReorg,
            ChainEvent::SafeTarget { .. } => Topic::SafeTarget,
        }
    }
}

/// Capacity of the chain-event broadcast channel.
///
/// Chosen so a briefly-stalled subscriber is skipped past (lagged) rather than
/// back-pressuring the actor. Lagged subscribers re-sync via the blocks
/// endpoints.
const CHAIN_EVENT_CHANNEL_CAPACITY: usize = 256;

/// Cloneable handle to the chain-event broadcast channel.
///
/// Owned solely by [`crate::BlockChainServer`] (never `Option`, never
/// threaded into `store.rs`): the actor snapshots store state before a call
/// to `store::on_tick`/`store::on_block`, runs it unchanged, then diffs and
/// calls [`EventBus::emit`] itself. Call sites that must stay eventless (spec
/// tests, `test_driver.rs`) simply never construct a live bus.
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
const HEAD_EVENT_RECENCY_SLOTS: u64 = 32;

/// Pre-call snapshot of the store values the chain-event bus reports on.
///
/// The actor — not the store — publishes chain events: it captures this
/// snapshot before a store call (`store::on_tick`, `store::on_block`) and
/// diffs the store against it afterwards, so `store.rs` needs no event
/// plumbing.
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
    safe_target: H256,
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
            safe_target: store.safe_target().expect("safe target exists"),
        }
    }

    /// Emit one event per value that changed since the snapshot, in a fixed
    /// order: `chain_reorg` → `head` → `justified_checkpoint` →
    /// `finalized_checkpoint` → `safe_target`. (`block` is emitted separately by
    /// the import path, ahead of this diff.)
    ///
    /// `wall_clock_slot` is the caller's current slot, used to gate the `head`
    /// and `chain_reorg` events against [`HEAD_EVENT_RECENCY_SLOTS`] (catch-up
    /// head walks are noise); `justified_checkpoint`, `finalized_checkpoint`,
    /// and `safe_target` are ungated (they coalesce to the latest value, which
    /// is the only one that matters).
    pub(crate) fn diff_and_emit(&self, store: &Store, events: &EventBus, wall_clock_slot: u64) {
        let head = store.head().expect("head block exists");
        if head != self.head {
            // Read the header once and reuse it for slot and state root so they
            // stay consistent.
            if let Some(header) = store
                .get_block_header(&head)
                .expect("block header read should succeed")
            {
                // Skip stale heads (catch-up/backfill): see HEAD_EVENT_RECENCY_SLOTS.
                if header.slot + HEAD_EVENT_RECENCY_SLOTS >= wall_clock_slot {
                    // A head change that leaves the old head's chain is a reorg;
                    // surface it just before the `head` event (beacon ordering).
                    // `reorg_depth` returns None for a plain extension. Reading
                    // the old-head header can fail only on genuine store
                    // inconsistency; that just drops the reorg detail, never the
                    // head event. Note: during a multi-move catch-up tick the
                    // diff sees only net (pre, post) heads, so a transient reorg
                    // that reverts within one call is invisible here (store
                    // metrics still count it).
                    if let Some(depth) = crate::store::reorg_depth(self.head, head, store)
                        && let Some(old_header) = store
                            .get_block_header(&self.head)
                            .expect("block header read should succeed")
                    {
                        events.emit(ChainEvent::ChainReorg {
                            slot: header.slot,
                            depth,
                            old_head_block: self.head,
                            old_head_state: old_header.state_root,
                            new_head_block: head,
                            new_head_state: header.state_root,
                        });
                    }
                    events.emit(ChainEvent::Head {
                        slot: header.slot,
                        block: head,
                        state: header.state_root,
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

        // Safe target is a fork-choice block root (not a checkpoint), advanced
        // at interval 3. Report its slot from the header; a missing header only
        // drops this event.
        let safe_target = store.safe_target().expect("safe target exists");
        if safe_target != self.safe_target {
            if let Some(header) = store
                .get_block_header(&safe_target)
                .expect("block header read should succeed")
            {
                events.emit(ChainEvent::SafeTarget {
                    slot: header.slot,
                    block: safe_target,
                });
            } else {
                warn!(
                    safe_target_root = %ShortRoot(&safe_target.0),
                    "Safe target header missing while emitting event; skipping"
                );
            }
        }
    }
}

/// Look up the state root of a checkpoint's block for the `{block, state}`
/// event shape. Returns `None` if the header is absent so the caller can skip
/// emission; finalized/justified block headers are never pruned, so this only
/// fails on genuine store inconsistency.
fn checkpoint_state_root(store: &Store, root: H256) -> Option<H256> {
    store
        .get_block_header(&root)
        .expect("block header read should succeed")
        .map(|header| header.state_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_storage::{ForkCheckpoints, backend::InMemoryBackend};
    use ethlambda_types::{
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

    const ALL_TOPICS: [Topic; 6] = [
        Topic::Head,
        Topic::Block,
        Topic::JustifiedCheckpoint,
        Topic::FinalizedCheckpoint,
        Topic::ChainReorg,
        Topic::SafeTarget,
    ];

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
        for topic in ALL_TOPICS {
            assert_eq!(topic.as_str().parse::<Topic>().unwrap(), topic);
        }
        let err = "bogus".parse::<Topic>().unwrap_err();
        assert_eq!(err.to_string(), "unknown topic: 'bogus'");
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
                ChainEvent::ChainReorg {
                    slot: 1,
                    depth: 1,
                    old_head_block: block,
                    old_head_state: state,
                    new_head_block: block,
                    new_head_state: state,
                },
                Topic::ChainReorg,
            ),
            (ChainEvent::SafeTarget { slot: 1, block }, Topic::SafeTarget),
        ];
        for (event, topic) in cases {
            assert_eq!(event.topic(), topic);
            assert_eq!(event.topic().as_str(), topic.as_str());
        }
    }

    fn test_store() -> Store {
        let genesis_state = State::from_genesis(1000, vec![]);
        Store::from_anchor_state(Arc::new(InMemoryBackend::new()), genesis_state)
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
            .insert_signed_block(root, signed_block)
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

    /// A head whose header cannot be read is skipped (warn), while checkpoint
    /// moves still emit.
    #[test]
    fn chain_event_diff_skips_head_with_missing_header() {
        let mut store = test_store();
        let bus = EventBus::new(8);
        let mut rx = bus.subscribe();

        let snapshot = ChainEventSnapshot::capture(&store);

        // Point the head at a root with no stored header; advance finalized to
        // a real block so its event still fires.
        let orphan_head = H256([7u8; 32]);
        let genesis = store.head().expect("store head exists");
        let finalized_root = H256([8u8; 32]);
        let finalized_state = H256([88u8; 32]);
        insert_test_block(&mut store, finalized_root, 1, genesis, finalized_state);
        let finalized = Checkpoint {
            root: finalized_root,
            slot: 1,
        };
        store
            .update_checkpoints(ForkCheckpoints::new(orphan_head, None, Some(finalized)))
            .expect("update_checkpoints should succeed");

        snapshot.diff_and_emit(&store, &bus, 1);

        match rx.try_recv().unwrap() {
            ChainEvent::FinalizedCheckpoint { slot, block, state } => {
                assert_eq!((slot, block, state), (1, finalized_root, finalized_state));
            }
            other => panic!("expected finalized_checkpoint only, got: {other:?}"),
        }
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

    /// Swinging the head onto a sibling chain fires `chain_reorg` ahead of the
    /// `head` event, with the rolled-back depth. (A plain extension is covered
    /// by `chain_event_diff_emits_recent_head`, which sees no reorg.)
    #[test]
    fn chain_event_diff_emits_chain_reorg_before_head() {
        let mut store = test_store();
        let genesis = store.head().expect("store head exists");
        let bus = EventBus::new(16);
        let mut rx = bus.subscribe();

        // Two forks off genesis: A(1) ← A2(2), and B(1) on its own.
        let a = H256([1u8; 32]);
        let a2 = H256([2u8; 32]);
        let b = H256([3u8; 32]);
        insert_test_block(&mut store, a, 1, genesis, H256([11u8; 32]));
        insert_test_block(&mut store, a2, 2, a, H256([22u8; 32]));
        insert_test_block(&mut store, b, 1, genesis, H256([33u8; 32]));

        // Head starts on A2; snapshot; then fork choice picks B, off A2's chain.
        store
            .update_checkpoints(ForkCheckpoints::head_only(a2))
            .expect("head A2");
        let snapshot = ChainEventSnapshot::capture(&store);
        store
            .update_checkpoints(ForkCheckpoints::head_only(b))
            .expect("head B");

        // Wall clock at B's slot so the recency gate lets both events through.
        snapshot.diff_and_emit(&store, &bus, 1);

        match rx.try_recv().unwrap() {
            ChainEvent::ChainReorg {
                slot,
                depth,
                old_head_block,
                new_head_block,
                ..
            } => {
                assert_eq!(slot, 1, "reorg slot is the new head's slot");
                assert_eq!(depth, 1, "A2 rolls back one block to the A/B fork point");
                assert_eq!(old_head_block, a2);
                assert_eq!(new_head_block, b);
            }
            other => panic!("expected chain_reorg first, got: {other:?}"),
        }
        match rx.try_recv().unwrap() {
            ChainEvent::Head { block, .. } => assert_eq!(block, b),
            other => panic!("expected head after reorg, got: {other:?}"),
        }
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
    }

    /// A safe-target move (interval-3 output) emits `safe_target` and nothing
    /// else when head/justified/finalized are unchanged.
    #[test]
    fn chain_event_diff_emits_safe_target() {
        let mut store = test_store();
        let genesis = store.head().expect("store head exists");
        let bus = EventBus::new(16);
        let mut rx = bus.subscribe();

        let target = H256([6u8; 32]);
        insert_test_block(&mut store, target, 2, genesis, H256([66u8; 32]));
        let snapshot = ChainEventSnapshot::capture(&store);
        store.set_safe_target(target).expect("set safe target");

        snapshot.diff_and_emit(&store, &bus, 2);

        match rx.try_recv().unwrap() {
            ChainEvent::SafeTarget { slot, block } => assert_eq!((slot, block), (2, target)),
            other => panic!("expected safe_target, got: {other:?}"),
        }
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
    }
}
