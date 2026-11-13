//! The head slot this node's peers report in `Status`, published on the
//! [`Store`] as the sync tracker's evidence that the network is ahead of this
//! node.
//!
//! Lighthouse and Prysm both decide "I am behind" against what their peers
//! report rather than against blocks they have imported: a node whose import
//! has stalled, or that is still catching up, has imported nothing recent, so
//! its own blocks cannot tell it the network moved on. The published value is
//! the highest report, as in Lighthouse, where a single `Advanced` peer starts
//! a range sync. A peer's head is a claim, not a verified block, so it is
//! bounded four ways: a head past the wall clock is dropped (both clients
//! refuse such a `Status` at the handshake); a head this node has already
//! imported is not a lead, since it says nothing about blocks the node lacks
//! (a peer on a lighter fork whose tip we hold is not ahead of us); the sync
//! tracker requires the node's own head to trail the clock, so no claim can
//! stop a node that is current; and the tracker gives up on a lead its head
//! does not advance towards (`SyncThresholds::stall_window`), so a claim
//! nobody delivers costs one window, not a stall's whole length.
//!
//! Peers send `Status` once per connection, so a claim would go stale while
//! the peer stays connected. `SyncThresholds::status_refresh_slots` paces a
//! re-request, the way Lighthouse re-statuses every 300 s and Prysm every half
//! epoch. The pace is per peer, counted from that peer's own last exchange,
//! and no slot asks more than its share of the peers (see
//! [`PeerHeads::due_for_refresh`]), so a node with hundreds of peers spreads
//! the requests over the interval instead of sending them all at once.

use std::collections::{HashMap, HashSet};

use ethlambda_network_api::sync::SyncThresholds;
use ethlambda_storage::{Chain, PeerView, Store};
use ethlambda_types::primitives::H256;
use libp2p::PeerId;
use tracing::debug;

use crate::P2PServer;
use crate::beacon::handler::StatusVersion;

/// Slots a `Status` head may sit past the wall clock and still count: Lighthouse's
/// `FUTURE_SLOT_TOLERANCE` and Prysm's `maxFutureStatusHeadSlot`.
pub(crate) const FUTURE_HEAD_TOLERANCE: u64 = 1;

/// This chain's sync thresholds. The chain actor's tracker judges the gate by
/// the same ones, which is why they live in `ethlambda-network-api`: the
/// refresh cadence ([`SyncThresholds::status_refresh_slots`]) and the lead a
/// refresh answer needs before it starts a range sync
/// ([`SyncThresholds::peer_lead`]) cannot drift from the gate they serve.
pub(crate) fn thresholds(store: &Store) -> SyncThresholds {
    match store.chain() {
        Chain::Lean => SyncThresholds::LEAN,
        Chain::Beacon => SyncThresholds::BEACON,
    }
}

/// What became of a reported head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Report {
    /// Counted towards the network head.
    Counted,
    /// A block this node has already imported: the peer is not ahead of it,
    /// whatever its slot, so it does not count.
    Held,
    /// Past the wall clock: dropped, along with the peer's earlier report.
    Future,
}

/// Every connected peer's latest `Status` head, and the per-peer state of the
/// `Status` exchange that keeps it fresh.
#[derive(Debug, Default)]
pub(crate) struct PeerHeads {
    /// The head slot each peer last reported, while it stays connected and
    /// the head is not one this node holds.
    heads: HashMap<PeerId, u64>,
    /// Connected peers whose latest report was not past the wall clock,
    /// including those whose head this node holds and so left out of
    /// `heads`: the sync tracker ends its startup hold on how many peers have
    /// spoken, and a peer that is level with us has spoken as much as one
    /// that is ahead.
    reporting: HashSet<PeerId>,
    /// Peers whose outstanding `Status` request is a refresh rather than the
    /// handshake; a refresh answer needs a larger lead to start a range sync.
    refreshing: HashSet<PeerId>,
    /// The wall-clock slot of each connected peer's last `Status` exchange, in
    /// either direction: the last time it told us its head, or we asked.
    last_exchange: HashMap<PeerId, u64>,
    /// Peers whose last beacon `Status` came from a fork digest this node does
    /// not hold, so a refresh that finds one still there is not a new event.
    foreign_digest: HashSet<PeerId>,
    /// The `Status` version each beacon peer last exchanged in, so a refresh
    /// asks in the version the peer is known to speak.
    status_versions: HashMap<PeerId, StatusVersion>,
}

impl PeerHeads {
    /// Record `peer`'s head, unless it sits past `wall_slot` by more than
    /// [`FUTURE_HEAD_TOLERANCE`] or names a block this node already `held`.
    /// A peer whose head is dropped loses any earlier report too: a peer that
    /// claims the future is not one to believe about the present, and one
    /// whose head we hold is no longer ahead of us. Either way the exchange
    /// postpones `peer`'s next refresh.
    pub(crate) fn record(
        &mut self,
        peer: PeerId,
        head_slot: u64,
        wall_slot: u64,
        held: bool,
    ) -> Report {
        self.last_exchange.insert(peer, wall_slot);
        if head_slot > wall_slot.saturating_add(FUTURE_HEAD_TOLERANCE) {
            self.heads.remove(&peer);
            self.reporting.remove(&peer);
            return Report::Future;
        }
        self.reporting.insert(peer);
        if held {
            self.heads.remove(&peer);
            return Report::Held;
        }
        self.heads.insert(peer, head_slot);
        Report::Counted
    }

    /// Forget a disconnected peer.
    pub(crate) fn forget(&mut self, peer: &PeerId) {
        self.heads.remove(peer);
        self.reporting.remove(peer);
        self.refreshing.remove(peer);
        self.last_exchange.remove(peer);
        self.foreign_digest.remove(peer);
        self.status_versions.remove(peer);
    }

    /// The network's head as the peers report it: the highest counted report,
    /// `None` with none at all.
    pub(crate) fn network_head(&self) -> Option<u64> {
        self.heads.values().copied().max()
    }

    /// How many connected peers have reported a head not past the wall
    /// clock, whether or not this node holds it.
    pub(crate) fn reporting_peers(&self) -> usize {
        self.reporting.len()
    }

    /// The connected peers to re-ask for their `Status` at `wall_slot`, at
    /// most one slot's share of them.
    ///
    /// A peer falls due `interval` slots after its last exchange. Each call
    /// sends at most `connected / interval` (rounded up) of the due peers,
    /// longest-waiting first, so 200 peers that connected together are
    /// re-asked across a whole interval rather than in one burst, and from
    /// then on stay spread out. A peer seen here for the first time is still
    /// in its handshake, so it counts as having just exchanged. The peers
    /// returned count as asked at `wall_slot`.
    pub(crate) fn due_for_refresh(
        &mut self,
        connected: impl IntoIterator<Item = PeerId>,
        wall_slot: u64,
        interval: u64,
    ) -> Vec<PeerId> {
        let interval = interval.max(1);
        let mut connected_count = 0usize;
        let mut due = Vec::new();
        for peer in connected {
            connected_count += 1;
            let last = *self.last_exchange.entry(peer).or_insert(wall_slot);
            if last.saturating_add(interval) <= wall_slot {
                due.push((last, peer));
            }
        }
        let per_slot = connected_count.div_ceil(usize::try_from(interval).unwrap_or(usize::MAX));
        due.sort_unstable_by_key(|(last, _)| *last);
        due.truncate(per_slot);
        due.into_iter()
            .map(|(_, peer)| {
                self.last_exchange.insert(peer, wall_slot);
                peer
            })
            .collect()
    }

    /// Note that the `Status` request about to go to `peer` is a refresh.
    pub(crate) fn begin_refresh(&mut self, peer: PeerId) {
        self.refreshing.insert(peer);
    }

    /// Whether `peer`'s `Status` answer is to a refresh, clearing the mark.
    pub(crate) fn take_refresh(&mut self, peer: &PeerId) -> bool {
        self.refreshing.remove(peer)
    }

    /// Note whether `peer`'s latest beacon `Status` came from a fork digest
    /// this node holds. Returns whether the peer has only now moved to one it
    /// does not: the event worth a warning and a count, once, rather than on
    /// every refresh of a connection that has been on a foreign digest all
    /// along.
    pub(crate) fn note_digest(&mut self, peer: PeerId, held: bool) -> bool {
        if held {
            self.foreign_digest.remove(&peer);
            false
        } else {
            self.foreign_digest.insert(peer)
        }
    }

    /// Note the `Status` version `peer` last exchanged in.
    pub(crate) fn note_status_version(&mut self, peer: PeerId, version: StatusVersion) {
        self.status_versions.insert(peer, version);
    }

    /// The `Status` version to ask `peer` in: the one it last exchanged in,
    /// or `status/1`, the handshake's own opening, before it has.
    pub(crate) fn status_version(&self, peer: &PeerId) -> StatusVersion {
        self.status_versions
            .get(peer)
            .copied()
            .unwrap_or(StatusVersion::V1)
    }
}

/// Whether this node has already imported `root`: its own head, or any block
/// it holds a post-state for. A pending or held block has no post-state, so it
/// does not count, the same as a block the node has never seen.
fn holds_block(store: &Store, root: &H256) -> bool {
    store.head().is_ok_and(|head| head == *root) || store.has_state(root).unwrap_or(false)
}

/// Record the head `peer` reported in a `Status` (request or answer) and
/// republish the network head. Returns what became of it, so an answer whose
/// head this node already holds can skip looking for a range to sync.
pub(crate) fn observe(
    server: &mut P2PServer,
    peer: PeerId,
    head_slot: u64,
    head_root: H256,
) -> Report {
    let wall_slot = crate::wall_clock_slot(&server.store);
    let held = holds_block(&server.store, &head_root);
    let report = server.peer_heads.record(peer, head_slot, wall_slot, held);
    if report == Report::Future {
        debug!(
            %peer,
            peer_head_slot = head_slot,
            wall_slot,
            "Ignoring a Status head past the wall clock"
        );
    }
    publish(server);
    report
}

/// Forget a disconnected peer's head and republish the network head.
pub(crate) fn forget(server: &mut P2PServer, peer: &PeerId) {
    server.peer_heads.forget(peer);
    publish(server);
}

fn publish(server: &P2PServer) {
    server.store.set_peer_view(PeerView {
        network_head: server.peer_heads.network_head(),
        reporting_peers: server.peer_heads.reporting_peers(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const BEACON_REFRESH: u64 = SyncThresholds::BEACON.status_refresh_slots;

    #[test]
    fn no_report_is_no_network_head() {
        assert_eq!(PeerHeads::default().network_head(), None);
    }

    #[test]
    fn the_highest_report_counts() {
        // A stale or still-syncing peer does not veto a fresher one.
        let mut heads = PeerHeads::default();
        heads.record(PeerId::random(), 100, 100, false);
        heads.record(PeerId::random(), 40, 100, false);
        assert_eq!(heads.network_head(), Some(100));
    }

    #[test]
    fn one_current_peer_among_stale_ones_is_enough() {
        // Finding: nodes restarted together, behind, and peered with each
        // other and one healthy peer. Their own reports must not outvote the
        // one peer that is current; the sync tracker's stall window is what
        // bounds a single peer that lies.
        let mut heads = PeerHeads::default();
        heads.record(PeerId::random(), 600, 600, false);
        heads.record(PeerId::random(), 50, 600, false);
        heads.record(PeerId::random(), 50, 600, false);
        assert_eq!(heads.network_head(), Some(600));
    }

    #[test]
    fn a_head_this_node_holds_is_not_a_lead() {
        // Finding: peers on a lighter fork whose tip we imported report a
        // higher slot than our head, but we are not missing anything from
        // them.
        let mut heads = PeerHeads::default();
        let on_lighter_fork = PeerId::random();
        assert_eq!(heads.record(on_lighter_fork, 110, 110, true), Report::Held);
        assert_eq!(heads.network_head(), None);
        // A peer that had reported an unknown head is dropped once its head is
        // one we hold.
        heads.record(on_lighter_fork, 109, 110, false);
        heads.record(on_lighter_fork, 110, 110, true);
        assert_eq!(heads.network_head(), None);
    }

    #[test]
    fn peers_level_with_us_count_as_reporting() {
        // At genesis every peer reports a head this node already holds. None
        // of them is a lead, but all of them have spoken, which is what ends
        // the sync tracker's startup hold.
        let mut heads = PeerHeads::default();
        let peers: Vec<_> = (0..5).map(|_| PeerId::random()).collect();
        for peer in &peers {
            assert_eq!(heads.record(*peer, 3, 6, true), Report::Held);
        }
        assert_eq!(heads.network_head(), None);
        assert_eq!(heads.reporting_peers(), 5);
        // A later report from one of them is still one peer.
        heads.record(peers[0], 4, 7, false);
        assert_eq!(heads.reporting_peers(), 5);
        heads.forget(&peers[1]);
        assert_eq!(heads.reporting_peers(), 4);
    }

    #[test]
    fn a_peer_reporting_the_future_is_not_reporting() {
        let mut heads = PeerHeads::default();
        let liar = PeerId::random();
        heads.record(liar, 100, 100, false);
        assert_eq!(heads.reporting_peers(), 1);
        heads.record(liar, 100 + FUTURE_HEAD_TOLERANCE + 1, 100, false);
        assert_eq!(heads.reporting_peers(), 0);
    }

    #[test]
    fn a_head_past_the_clock_is_dropped_with_the_peers_earlier_report() {
        let mut heads = PeerHeads::default();
        let liar = PeerId::random();
        assert_eq!(heads.record(liar, 90, 100, false), Report::Counted);
        assert_eq!(
            heads.record(liar, 100 + FUTURE_HEAD_TOLERANCE, 100, false),
            Report::Counted
        );
        assert_eq!(
            heads.record(liar, 100 + FUTURE_HEAD_TOLERANCE + 1, 100, false),
            Report::Future
        );
        assert_eq!(heads.network_head(), None);
    }

    #[test]
    fn a_later_report_replaces_an_earlier_one() {
        // Latest, not highest: a peer that reorged to a lower head is believed.
        let mut heads = PeerHeads::default();
        let peer = PeerId::random();
        heads.record(peer, 100, 100, false);
        heads.record(peer, 95, 100, false);
        assert_eq!(heads.network_head(), Some(95));
    }

    #[test]
    fn a_disconnected_peer_is_forgotten() {
        let mut heads = PeerHeads::default();
        let peer = PeerId::random();
        heads.record(peer, 100, 100, false);
        heads.begin_refresh(peer);
        heads.note_digest(peer, false);
        heads.note_status_version(peer, StatusVersion::V2);
        heads.forget(&peer);
        assert_eq!(heads.network_head(), None);
        assert!(!heads.take_refresh(&peer));
        assert_eq!(heads.status_version(&peer), StatusVersion::V1);
        // A reconnect on a foreign digest is news again.
        assert!(heads.note_digest(peer, false));
        // A reconnect is a fresh handshake, not a refresh that is overdue.
        assert!(heads.due_for_refresh([peer], 1_000, 4).is_empty());
    }

    #[test]
    fn a_foreign_digest_is_news_once_per_move() {
        // Finding: the refresh re-asks peers on a digest we do not hold every
        // half epoch; only the move onto that digest is worth a warning.
        let mut heads = PeerHeads::default();
        let peer = PeerId::random();
        assert!(heads.note_digest(peer, false));
        assert!(!heads.note_digest(peer, false));
        // Back on a held digest, then off again: a new move.
        assert!(!heads.note_digest(peer, true));
        assert!(heads.note_digest(peer, false));
    }

    #[test]
    fn a_refresh_asks_in_the_version_the_peer_speaks() {
        let mut heads = PeerHeads::default();
        let peer = PeerId::random();
        assert_eq!(heads.status_version(&peer), StatusVersion::V1);
        heads.note_status_version(peer, StatusVersion::V2);
        assert_eq!(heads.status_version(&peer), StatusVersion::V2);
    }

    #[test]
    fn a_peer_is_re_asked_one_interval_after_its_last_exchange() {
        let mut heads = PeerHeads::default();
        let peer = PeerId::random();
        // First seen at slot 10, mid-handshake.
        assert!(heads.due_for_refresh([peer], 10, 4).is_empty());
        assert!(heads.due_for_refresh([peer], 13, 4).is_empty());
        assert_eq!(heads.due_for_refresh([peer], 14, 4), vec![peer]);
        // Asked at 14, so not again until 18.
        assert!(heads.due_for_refresh([peer], 17, 4).is_empty());
        assert_eq!(heads.due_for_refresh([peer], 18, 4), vec![peer]);
    }

    #[test]
    fn a_status_from_the_peer_postpones_its_refresh() {
        // A peer that sent us its `Status` at slot 12 is as fresh as one we
        // asked then.
        let mut heads = PeerHeads::default();
        let peer = PeerId::random();
        heads.due_for_refresh([peer], 10, 4);
        heads.record(peer, 12, 12, false);
        assert!(heads.due_for_refresh([peer], 14, 4).is_empty());
        assert_eq!(heads.due_for_refresh([peer], 16, 4), vec![peer]);
    }

    #[test]
    fn peers_that_connected_together_are_re_asked_across_an_interval() {
        // A beacon node's default 200 peers, all connected at slot 0 and due
        // together one interval later: no slot asks more than its share of
        // them, and every one is asked within the interval after they fell
        // due.
        let peers: Vec<PeerId> = (0..200).map(|_| PeerId::random()).collect();
        let share = peers.len().div_ceil(BEACON_REFRESH as usize);
        let mut heads = PeerHeads::default();
        heads.due_for_refresh(peers.iter().copied(), 0, BEACON_REFRESH);
        let mut asked = HashSet::new();
        for slot in BEACON_REFRESH..2 * BEACON_REFRESH {
            let batch = heads.due_for_refresh(peers.iter().copied(), slot, BEACON_REFRESH);
            assert!(
                batch.len() <= share,
                "slot {slot} asked {} peers",
                batch.len()
            );
            asked.extend(batch);
        }
        assert_eq!(asked.len(), peers.len());
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
