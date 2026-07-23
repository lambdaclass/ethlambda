//! The merged event bus: collector tasks publish, `GET /stream` subscribes,
//! and a bounded in-memory history lets `GET /api/history` backfill a
//! freshly-opened dashboard so it isn't blank on load (CONTRACT.md §4).

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tokio::sync::broadcast;

use crate::model::{NodeStatus, NormalizedEvent};

/// Capacity of the broadcast channel. A slow subscriber (browser) that falls
/// behind by more than this many messages will observe a `Lagged` error on
/// its receiver and skip ahead — best-effort, same contract as the upstream
/// ethlambda SSE endpoint (CONTRACT.md §4).
const HUB_CAPACITY: usize = 4096;

/// Hard upper bound on retained history events, independent of the slot-based
/// window, so a high-rate stream (attestation flood) can't grow memory
/// without bound before the slot-age prune catches up.
const HISTORY_MAX_EVENTS: usize = 50_000;

/// One message on the hub: either a normalized chain event (`event: chain`)
/// or a node status update (`event: status`) per CONTRACT.md §4.
#[derive(Debug, Clone)]
pub enum HubMessage {
    Chain(NormalizedEvent),
    Status(NodeStatus),
}

/// Point-in-time backfill payload served by `GET /api/history`: the retained
/// recent chain events plus the latest status per node (CONTRACT.md §4). Its
/// field names match that endpoint's JSON exactly, so it is serialized directly.
#[derive(Debug, Clone, Default, Serialize)]
pub struct HistorySnapshot {
    pub events: Vec<NormalizedEvent>,
    pub status: Vec<NodeStatus>,
}

/// Bounded ring of recent events: retained by slot age up to `retain_slots`
/// (relative to the newest slot seen) and hard-capped at
/// [`HISTORY_MAX_EVENTS`], plus the latest status per node.
struct History {
    events: VecDeque<NormalizedEvent>,
    status: BTreeMap<String, NodeStatus>,
    max_slot: u64,
    retain_slots: u64,
}

impl History {
    fn new(retain_slots: u64) -> Self {
        Self {
            events: VecDeque::new(),
            status: BTreeMap::new(),
            max_slot: 0,
            retain_slots,
        }
    }

    fn push_event(&mut self, event: NormalizedEvent) {
        self.max_slot = self.max_slot.max(event.slot);
        self.events.push_back(event);
        self.prune();
    }

    fn record_status(&mut self, status: NodeStatus) {
        self.status.insert(status.node.clone(), status);
    }

    /// Drops events older than `retain_slots` relative to the newest slot
    /// seen, then enforces the hard event cap from the front (oldest first).
    /// Events arrive in roughly slot order across nodes/topics, so scanning
    /// from the front is a good approximation of oldest-first.
    fn prune(&mut self) {
        while let Some(front) = self.events.front() {
            if self.max_slot.saturating_sub(front.slot) >= self.retain_slots {
                self.events.pop_front();
            } else {
                break;
            }
        }
        while self.events.len() > HISTORY_MAX_EVENTS {
            self.events.pop_front();
        }
    }

    fn snapshot(&self) -> HistorySnapshot {
        HistorySnapshot {
            events: self.events.iter().cloned().collect(),
            status: self.status.values().cloned().collect(),
        }
    }
}

/// Cheaply cloneable handle to the shared broadcast bus and history ring.
/// Every collector task and every `/stream` subscriber holds a clone.
#[derive(Clone)]
pub struct Hub {
    tx: broadcast::Sender<HubMessage>,
    history: Arc<Mutex<History>>,
}

impl Hub {
    /// `history_slots` is how many slots of recent events are retained for
    /// backfill; clamped to at least 1.
    pub fn new(history_slots: u64) -> Self {
        let (tx, _rx) = broadcast::channel(HUB_CAPACITY);
        Self {
            tx,
            history: Arc::new(Mutex::new(History::new(history_slots.max(1)))),
        }
    }

    /// Publishes a normalized chain event. Records it into history *before*
    /// broadcasting so a snapshot taken concurrently with a `/stream`
    /// subscribe can never miss an event a live subscriber will also see (the
    /// frontend de-dups the small overlap). Ignores the "no subscribers"
    /// send error: normal when no browser is connected yet.
    pub fn publish_chain(&self, event: NormalizedEvent) {
        if let Ok(mut history) = self.history.lock() {
            history.push_event(event.clone());
        }
        let _ = self.tx.send(HubMessage::Chain(event));
    }

    /// Publishes a node status update. See [`Hub::publish_chain`] for why
    /// send errors are ignored.
    pub fn publish_status(&self, status: NodeStatus) {
        if let Ok(mut history) = self.history.lock() {
            history.record_status(status.clone());
        }
        let _ = self.tx.send(HubMessage::Status(status));
    }

    pub fn subscribe(&self) -> broadcast::Receiver<HubMessage> {
        self.tx.subscribe()
    }

    /// Snapshot of retained history for `GET /api/history`. Returns an empty
    /// snapshot rather than propagating a (practically impossible) poisoned
    /// lock — the critical sections never panic.
    pub fn history_snapshot(&self) -> HistorySnapshot {
        self.history
            .lock()
            .map(|history| history.snapshot())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::NodeState;

    fn chain_event(node: &str, slot: u64) -> NormalizedEvent {
        NormalizedEvent {
            node: node.to_string(),
            topic: "block".to_string(),
            slot,
            arrival_ms: slot as i64 * 4_000,
            offset_ms: 0,
            id: Some(format!("0x{slot:064x}")),
            validator_id: None,
            participants: None,
        }
    }

    #[tokio::test]
    async fn subscriber_receives_published_messages() {
        let hub = Hub::new(64);
        let mut rx = hub.subscribe();

        hub.publish_status(NodeStatus {
            node: "node-2".to_string(),
            state: NodeState::Connected,
            events_per_sec: 1.5,
        });

        let msg = rx.recv().await.unwrap();
        match msg {
            HubMessage::Status(status) => assert_eq!(status.node, "node-2"),
            HubMessage::Chain(_) => panic!("expected a Status message"),
        }
    }

    #[test]
    fn publish_without_subscribers_does_not_panic() {
        let hub = Hub::new(64);
        hub.publish_status(NodeStatus {
            node: "node-2".to_string(),
            state: NodeState::Down,
            events_per_sec: 0.0,
        });
    }

    #[test]
    fn history_snapshot_returns_published_events_and_latest_status() {
        let hub = Hub::new(64);
        hub.publish_chain(chain_event("node-0", 10));
        hub.publish_chain(chain_event("node-1", 11));
        hub.publish_status(NodeStatus {
            node: "node-0".to_string(),
            state: NodeState::Reconnecting,
            events_per_sec: 0.0,
        });
        hub.publish_status(NodeStatus {
            node: "node-0".to_string(),
            state: NodeState::Connected,
            events_per_sec: 2.0,
        });

        let snap = hub.history_snapshot();
        assert_eq!(snap.events.len(), 2);
        assert_eq!(snap.events[0].slot, 10);
        // Only the latest status per node is retained.
        assert_eq!(snap.status.len(), 1);
        assert_eq!(snap.status[0].state, NodeState::Connected);
    }

    #[test]
    fn history_prunes_events_older_than_the_retain_window() {
        let hub = Hub::new(5); // retain 5 slots
        for slot in 0..10 {
            hub.publish_chain(chain_event("node-0", slot));
        }
        let snap = hub.history_snapshot();
        // max_slot = 9, retain 5 → keep slots with age < 5 (slots 5..=9).
        assert_eq!(snap.events.len(), 5);
        assert_eq!(snap.events.first().unwrap().slot, 5);
        assert_eq!(snap.events.last().unwrap().slot, 9);
    }
}
