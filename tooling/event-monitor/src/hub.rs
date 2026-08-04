//! The merged event bus: collector tasks publish, `GET /stream` subscribes,
//! and a bounded in-memory history lets `GET /api/history` backfill a
//! freshly-opened dashboard so it isn't blank on load (CONTRACT.md §4).

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tokio::sync::broadcast;

use crate::model::{NodeStatus, NormalizedEvent};
use crate::timing::Timing;

/// Capacity of the broadcast channel. A slow subscriber (browser) that falls
/// behind by more than this many messages will observe a `Lagged` error on
/// its receiver and skip ahead — best-effort, same contract as the upstream
/// ethlambda SSE endpoint (CONTRACT.md §4).
const HUB_CAPACITY: usize = 4096;

/// Hard upper bound on retained history events, independent of the slot-based
/// window, so a high-rate stream (attestation flood) can't grow memory
/// without bound before the slot-age prune catches up.
const HISTORY_MAX_EVENTS: usize = 50_000;

/// Per `(node, topic)` cap on what one `GET /api/history` response carries.
/// Matches `MAX_POINTS_PER_NODE` in `web/beeswarm.js`, the tightest cap on the
/// consuming side: shipping more than a panel can hold is megabytes the frontend
/// discards on arrival.
///
/// Keyed per topic as well as per node so an attestation flood can't crowd out
/// the block/aggregate events the propagation panel groups by `id` — there are
/// an order of magnitude more attestations than blocks, so a per-node-only cap
/// would starve exactly the series that panel needs.
const SNAPSHOT_MAX_EVENTS_PER_SERIES: usize = 2_000;

/// One message on the hub: a normalized chain event (`event: chain`), a node
/// status update (`event: status`), or a slot-geometry change
/// (`event: geometry`) per CONTRACT.md §4.
///
/// Chain events are `Arc`-wrapped because every one is fanned out to each
/// `/stream` subscriber *and* retained in the history ring; sharing one
/// allocation keeps that from being a deep copy per destination.
#[derive(Debug, Clone)]
pub enum HubMessage {
    Chain(Arc<NormalizedEvent>),
    Status(NodeStatus),
    Geometry(Timing),
}

/// Point-in-time backfill payload served by `GET /api/history`: the retained
/// recent chain events plus the latest status per node (CONTRACT.md §4). Its
/// field names match that endpoint's JSON exactly, so it is serialized directly.
/// `Arc` is transparent to serde (the `rc` feature), so the wire shape is
/// identical to a `/stream` `chain` event as the contract requires.
#[derive(Debug, Clone, Default, Serialize)]
pub struct HistorySnapshot {
    pub events: Vec<Arc<NormalizedEvent>>,
    pub status: Vec<NodeStatus>,
}

/// Bounded ring of recent events: retained by slot age up to `retain_slots`
/// (relative to the newest slot seen) and hard-capped at
/// [`HISTORY_MAX_EVENTS`], plus the latest status per node.
struct History {
    events: VecDeque<Arc<NormalizedEvent>>,
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

    fn push_event(&mut self, event: Arc<NormalizedEvent>) {
        self.max_slot = self.max_slot.max(event.slot);
        self.events.push_back(event);
        self.prune();
    }

    fn record_status(&mut self, status: NodeStatus) {
        self.status.insert(status.node.clone(), status);
    }

    /// Drops every retained event and the slot watermark, keeping per-node
    /// status (a connection's state survives a geometry change).
    fn reset(&mut self) {
        self.events.clear();
        self.max_slot = 0;
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

    /// Cheap because the events are `Arc`s: this copies pointers, not the
    /// events themselves, which matters because the caller holds the mutex
    /// across it while every collector is trying to publish.
    ///
    /// Walks newest-first so the per-series cap keeps the *most recent*
    /// [`SNAPSHOT_MAX_EVENTS_PER_SERIES`] events of each `(node, topic)`, then
    /// restores the oldest-first order the contract promises.
    fn snapshot(&self) -> HistorySnapshot {
        let mut kept: BTreeMap<(&str, &str), usize> = BTreeMap::new();
        let mut events = Vec::new();
        for event in self.events.iter().rev() {
            let count = kept
                .entry((event.node.as_str(), event.topic.as_str()))
                .or_default();
            if *count >= SNAPSHOT_MAX_EVENTS_PER_SERIES {
                continue;
            }
            *count += 1;
            events.push(Arc::clone(event));
        }
        events.reverse();
        HistorySnapshot {
            events,
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
        let event = Arc::new(event);
        if let Ok(mut history) = self.history.lock() {
            history.push_event(Arc::clone(&event));
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

    /// Publishes a slot-geometry change so already-loaded dashboards learn their
    /// `ms_per_slot` / `intervals_per_slot` and slot watermark are stale
    /// (CONTRACT.md §4). Deliberately *not* retained in history: a tab opening
    /// afterwards fetches current geometry from `/api/meta`, so replaying this
    /// would only tell it to reload into the state it already has.
    pub fn publish_geometry(&self, timing: Timing) {
        let _ = self.tx.send(HubMessage::Geometry(timing));
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

    /// Drops retained events and the slot watermark. Called when slot geometry
    /// changes, since events carrying the old epoch's `offset_ms` and the old
    /// chain's slot numbers are not comparable with what follows
    /// ([`crate::timing::run_refresher`]).
    pub fn reset_history(&self) {
        if let Ok(mut history) = self.history.lock() {
            history.reset();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::NodeState;

    fn chain_event(node: &str, slot: u64) -> NormalizedEvent {
        topic_event(node, "block", slot)
    }

    fn topic_event(node: &str, topic: &str, slot: u64) -> NormalizedEvent {
        NormalizedEvent {
            node: node.to_string(),
            topic: topic.to_string(),
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
            other => panic!("expected a Status message, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn geometry_is_broadcast_but_not_retained_in_history() {
        let hub = Hub::new(64);
        let mut rx = hub.subscribe();
        let timing = Timing {
            genesis_time: 1_770_407_233,
            ms_per_slot: 4_000,
            intervals_per_slot: 5,
        };

        hub.publish_geometry(timing);

        match rx.recv().await.unwrap() {
            HubMessage::Geometry(published) => assert_eq!(published, timing),
            other => panic!("expected a Geometry message, got {other:?}"),
        }
        // A tab opening after the change reads current geometry from /api/meta,
        // so there is nothing for the backfill to say.
        assert!(hub.history_snapshot().events.is_empty());
    }

    #[test]
    fn the_history_snapshot_caps_each_node_and_topic_independently() {
        // A flood of one topic must not crowd another out of the backfill: the
        // propagation panel groups block/aggregate by id, and there are an order
        // of magnitude more attestations than blocks.
        let hub = Hub::new(u64::MAX); // no slot-age pruning, so the cap is what bites
        let flood = SNAPSHOT_MAX_EVENTS_PER_SERIES + 500;
        for i in 0..flood {
            hub.publish_chain(topic_event("node-0", "attestation", i as u64));
        }
        for i in 0..10 {
            hub.publish_chain(topic_event("node-0", "block", i as u64));
        }

        let snap = hub.history_snapshot();
        let count = |topic: &str| {
            snap.events
                .iter()
                .filter(|event| event.topic == topic)
                .count()
        };
        assert_eq!(count("attestation"), SNAPSHOT_MAX_EVENTS_PER_SERIES);
        assert_eq!(count("block"), 10);
        // Newest kept, oldest dropped, and the contract's oldest-first order
        // survives the newest-first walk.
        let attestations: Vec<u64> = snap
            .events
            .iter()
            .filter(|event| event.topic == "attestation")
            .map(|event| event.slot)
            .collect();
        assert_eq!(attestations.first(), Some(&500));
        assert_eq!(attestations.last(), Some(&(flood as u64 - 1)));
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
    fn reset_history_drops_events_and_the_slot_watermark_but_keeps_status() {
        let hub = Hub::new(5);
        hub.publish_status(NodeStatus {
            node: "node-0".to_string(),
            state: NodeState::Connected,
            events_per_sec: 3.0,
        });
        for slot in 1_000..1_010 {
            hub.publish_chain(chain_event("node-0", slot));
        }
        hub.reset_history();

        let snap = hub.history_snapshot();
        assert!(snap.events.is_empty());
        // Status survives: a connection's state is unaffected by geometry.
        assert_eq!(snap.status.len(), 1);

        // The watermark reset is the point: a chain restarted at low slots must
        // not be pruned as "older than the retain window" by the old high mark.
        hub.publish_chain(chain_event("node-0", 1));
        hub.publish_chain(chain_event("node-0", 2));
        let snap = hub.history_snapshot();
        assert_eq!(snap.events.len(), 2);
        assert_eq!(snap.events[0].slot, 1);
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
