//! The head slot this node's peers report in `Status`, published on the
//! [`Store`](ethlambda_storage::Store) as the sync tracker's evidence that the
//! network is ahead of this node.
//!
//! Lighthouse and Prysm both decide "I am behind" against what their peers
//! report rather than against blocks they have imported: a node whose import
//! has stalled, or that is still catching up, has imported nothing recent, so
//! its own blocks cannot tell it the network moved on. A peer's head is a
//! claim, not a verified block, so it is bounded three ways: a head past the
//! wall clock is dropped (both clients refuse such a `Status` at the
//! handshake), several peers must agree before the value moves, and the sync
//! tracker also requires the node's own head to trail the clock, so no claim
//! can stop a node that is current.
//!
//! Peers send `Status` once per connection, so a claim would go stale while
//! the peer stays connected. [`STATUS_REFRESH_SLOTS_LEAN`] and
//! [`STATUS_REFRESH_SLOTS_BEACON`] pace a re-request, the way Lighthouse
//! re-statuses every 300 s and Prysm every half epoch.

use std::collections::{HashMap, HashSet};

use ethlambda_types::beacon::preset::SLOTS_PER_EPOCH;
use ethlambda_types::time::unix_now_ms;
use libp2p::PeerId;
use tracing::debug;

use crate::P2PServer;

/// From this many reporting peers on, the network head is the second-highest
/// report rather than the highest, so one peer alone cannot move it. Below
/// it the highest report counts: with one or two peers, a stale or still
/// syncing peer must not veto a fresher one, and the tracker's clock condition
/// already keeps a lone liar from idling a node that is current.
pub(crate) const PEER_HEAD_QUORUM: usize = 3;

/// Slots a `Status` head may sit past the wall clock and still count: Lighthouse's
/// `FUTURE_SLOT_TOLERANCE` and Prysm's `maxFutureStatusHeadSlot`.
pub(crate) const FUTURE_HEAD_TOLERANCE: u64 = 1;

/// How often a lean node re-asks every connected peer for its `Status`: every
/// lead the lean sync tracker tolerates (`SyncThresholds::LEAN.peer_lead`), so
/// a claim is never staler than the gap it is meant to detect.
pub(crate) const STATUS_REFRESH_SLOTS_LEAN: u64 = 4;

/// How often a beacon node re-asks every connected peer for its `Status`:
/// Prysm's half epoch (`maintainPeerStatuses`).
pub(crate) const STATUS_REFRESH_SLOTS_BEACON: u64 = SLOTS_PER_EPOCH / 2;

/// How far ahead a peer answering a *refresh* must be before its answer starts
/// a range sync, per chain. A handshake answer starts one at any lead, as it
/// always has; a refresh lands every few slots on a node that is keeping up
/// with gossip, where a peer one slot ahead is ordinary and a one-block range
/// request would only race gossip. Lighthouse makes a peer `Advanced`, the one
/// kind its range sync follows, only beyond `SLOT_IMPORT_TOLERANCE` (32).
pub(crate) const REFRESH_RANGE_SYNC_LEAD_LEAN: u64 = 4;
/// The beacon counterpart of [`REFRESH_RANGE_SYNC_LEAD_LEAN`].
pub(crate) const REFRESH_RANGE_SYNC_LEAD_BEACON: u64 = SLOTS_PER_EPOCH;

/// Every connected peer's latest `Status` head.
#[derive(Debug, Default)]
pub(crate) struct PeerHeads {
    /// The head slot each peer last reported, while it stays connected.
    heads: HashMap<PeerId, u64>,
    /// Peers whose outstanding `Status` request is a refresh rather than the
    /// handshake; see [`REFRESH_RANGE_SYNC_LEAD_LEAN`].
    refreshing: HashSet<PeerId>,
}

impl PeerHeads {
    /// Record `peer`'s head, unless it sits past `wall_slot` by more than
    /// [`FUTURE_HEAD_TOLERANCE`]; a peer whose head is dropped loses any
    /// earlier report too, since a peer that claims the future is not one to
    /// believe about the present. Returns whether the head was recorded.
    pub(crate) fn record(&mut self, peer: PeerId, head_slot: u64, wall_slot: u64) -> bool {
        if head_slot > wall_slot.saturating_add(FUTURE_HEAD_TOLERANCE) {
            self.heads.remove(&peer);
            return false;
        }
        self.heads.insert(peer, head_slot);
        true
    }

    /// Forget a disconnected peer.
    pub(crate) fn forget(&mut self, peer: &PeerId) {
        self.heads.remove(peer);
        self.refreshing.remove(peer);
    }

    /// The network's head as the peers report it: the second-highest report
    /// once [`PEER_HEAD_QUORUM`] peers have reported, the highest before that,
    /// `None` with no report at all.
    pub(crate) fn network_head(&self) -> Option<u64> {
        let mut heads: Vec<u64> = self.heads.values().copied().collect();
        heads.sort_unstable_by(|a, b| b.cmp(a));
        let rank = if heads.len() >= PEER_HEAD_QUORUM {
            1
        } else {
            0
        };
        heads.get(rank).copied()
    }

    /// Note that the `Status` request about to go to `peer` is a refresh.
    pub(crate) fn begin_refresh(&mut self, peer: PeerId) {
        self.refreshing.insert(peer);
    }

    /// Whether `peer`'s `Status` answer is to a refresh, clearing the mark.
    pub(crate) fn take_refresh(&mut self, peer: &PeerId) -> bool {
        self.refreshing.remove(peer)
    }
}

/// The slot the wall clock is in, on the store's time grid.
fn wall_clock_slot(server: &P2PServer) -> u64 {
    let grid = server.store.config().time_grid();
    unix_now_ms().saturating_sub(grid.genesis_time_ms()) / grid.milliseconds_per_slot
}

/// Record the head `peer` reported in a `Status` (request or answer) and
/// republish the network head.
pub(crate) fn observe(server: &mut P2PServer, peer: PeerId, head_slot: u64) {
    let wall_slot = wall_clock_slot(server);
    if !server.peer_heads.record(peer, head_slot, wall_slot) {
        debug!(
            %peer,
            peer_head_slot = head_slot,
            wall_slot,
            "Ignoring a Status head past the wall clock"
        );
    }
    publish(server);
}

/// Forget a disconnected peer's head and republish the network head.
pub(crate) fn forget(server: &mut P2PServer, peer: &PeerId) {
    server.peer_heads.forget(peer);
    publish(server);
}

fn publish(server: &P2PServer) {
    server
        .store
        .set_network_head(server.peer_heads.network_head());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_report_is_no_network_head() {
        assert_eq!(PeerHeads::default().network_head(), None);
    }

    #[test]
    fn below_quorum_the_highest_report_counts() {
        // Two peers, one of them stale: the fresher one is not vetoed.
        let mut heads = PeerHeads::default();
        heads.record(PeerId::random(), 100, 100);
        heads.record(PeerId::random(), 40, 100);
        assert_eq!(heads.network_head(), Some(100));
    }

    #[test]
    fn at_quorum_one_peer_cannot_move_the_head() {
        let mut heads = PeerHeads::default();
        heads.record(PeerId::random(), 100, 100);
        heads.record(PeerId::random(), 50, 100);
        heads.record(PeerId::random(), 50, 100);
        assert_eq!(heads.network_head(), Some(50));
        // A second peer at the clock is enough.
        heads.record(PeerId::random(), 100, 100);
        assert_eq!(heads.network_head(), Some(100));
    }

    #[test]
    fn a_head_past_the_clock_is_dropped_with_the_peers_earlier_report() {
        let mut heads = PeerHeads::default();
        let liar = PeerId::random();
        assert!(heads.record(liar, 90, 100));
        assert!(heads.record(liar, 100 + FUTURE_HEAD_TOLERANCE, 100));
        assert!(!heads.record(liar, 100 + FUTURE_HEAD_TOLERANCE + 1, 100));
        assert_eq!(heads.network_head(), None);
    }

    #[test]
    fn a_later_report_replaces_an_earlier_one() {
        // Latest, not highest: a peer that reorged to a lower head is believed.
        let mut heads = PeerHeads::default();
        let peer = PeerId::random();
        heads.record(peer, 100, 100);
        heads.record(peer, 95, 100);
        assert_eq!(heads.network_head(), Some(95));
    }

    #[test]
    fn a_disconnected_peer_is_forgotten() {
        let mut heads = PeerHeads::default();
        let peer = PeerId::random();
        heads.record(peer, 100, 100);
        heads.begin_refresh(peer);
        heads.forget(&peer);
        assert_eq!(heads.network_head(), None);
        assert!(!heads.take_refresh(&peer));
    }

    #[test]
    fn a_refresh_mark_is_taken_once() {
        let mut heads = PeerHeads::default();
        let peer = PeerId::random();
        heads.begin_refresh(peer);
        assert!(heads.take_refresh(&peer));
        assert!(!heads.take_refresh(&peer));
    }
}
