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

use ethlambda_types::primitives::H256;
use serde::Serialize;
use tokio::sync::broadcast;

/// Wire-visible topic names for chain events.
///
/// These are the names consumers address events by (the SSE `event:` line and,
/// later, `?topics=` filtering), kept separate from [`ChainEvent`] so the
/// payloads stay flat JSON with the topic travelling out-of-band.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Topic {
    Head,
    Block,
    JustifiedCheckpoint,
    FinalizedCheckpoint,
}

impl Topic {
    pub fn as_str(self) -> &'static str {
        match self {
            Topic::Head => "head",
            Topic::Block => "block",
            Topic::JustifiedCheckpoint => "justified_checkpoint",
            Topic::FinalizedCheckpoint => "finalized_checkpoint",
        }
    }
}

/// A consensus event published by the blockchain actor.
///
/// `untagged`: serializing yields only the variant's fields. The topic name
/// travels out-of-band (via [`ChainEvent::topic`], e.g. on the SSE `event:`
/// line), so the JSON body stays flat with no `event`/`data` wrapper.
#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum ChainEvent {
    /// Fork choice selected a new head.
    Head {
        slot: u64,
        root: H256,
        parent_root: H256,
    },
    /// A block was imported into the store.
    Block { slot: u64, root: H256 },
    /// The justified checkpoint advanced.
    JustifiedCheckpoint { slot: u64, root: H256 },
    /// The finalized checkpoint advanced.
    FinalizedCheckpoint { slot: u64, root: H256 },
}

impl ChainEvent {
    pub fn topic(&self) -> Topic {
        match self {
            ChainEvent::Head { .. } => Topic::Head,
            ChainEvent::Block { .. } => Topic::Block,
            ChainEvent::JustifiedCheckpoint { .. } => Topic::JustifiedCheckpoint,
            ChainEvent::FinalizedCheckpoint { .. } => Topic::FinalizedCheckpoint,
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

    /// Dormant bus: emits go nowhere. For tests and eventless call paths.
    pub fn disabled() -> Self {
        Self::new(1)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn head_event(slot: u64) -> ChainEvent {
        ChainEvent::Head {
            slot,
            root: H256([1u8; 32]),
            parent_root: H256([2u8; 32]),
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
    fn emit_without_subscribers_is_a_noop() {
        let bus = EventBus::default();
        // No subscriber attached: must neither error nor panic.
        bus.emit(head_event(1));
    }

    #[test]
    fn disabled_bus_accepts_emits() {
        let bus = EventBus::disabled();
        bus.emit(head_event(1));
        bus.emit(ChainEvent::Block {
            slot: 2,
            root: H256::ZERO,
        });
    }

    #[test]
    fn topic_maps_every_variant() {
        let root = H256::ZERO;
        let cases = [
            (head_event(1), Topic::Head),
            (ChainEvent::Block { slot: 1, root }, Topic::Block),
            (
                ChainEvent::JustifiedCheckpoint { slot: 1, root },
                Topic::JustifiedCheckpoint,
            ),
            (
                ChainEvent::FinalizedCheckpoint { slot: 1, root },
                Topic::FinalizedCheckpoint,
            ),
        ];
        for (event, topic) in cases {
            assert_eq!(event.topic(), topic);
            assert_eq!(event.topic().as_str(), topic.as_str());
        }
    }

    /// The JSON body must be the variant's fields only: the topic name travels
    /// out-of-band, so no `event`/`data` wrapper keys may appear (the #460
    /// double-tag bug).
    #[test]
    fn serialization_is_flat_untagged_json() {
        let json = serde_json::to_value(head_event(3)).unwrap();

        assert_eq!(json["slot"], 3);
        assert!(json["root"].is_string());
        assert!(json["parent_root"].is_string());
        assert!(json.get("event").is_none());
        assert!(json.get("data").is_none());
    }
}
