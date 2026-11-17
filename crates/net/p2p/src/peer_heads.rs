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
//! the requests over the interval instead of sending them all at once. A
//! report counts for `SyncThresholds::report_lifetime` after it arrived, so a
//! peer that stays connected but stops answering does not keep its claim.

use std::collections::{HashMap, HashSet};

use ethlambda_network_api::sync::SyncThresholds;
use ethlambda_storage::{Chain, Store};
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
    /// From a peer that is no longer connected: a `Status` handled after its
    /// disconnect, whose head [`forget`] would never clear.
    Disconnected,
}

/// A peer's run of failed range requests: when the last one failed, and how
/// many in a row since its last successful answer.
#[derive(Debug, Clone, Copy)]
struct RangeFailures {
    last: u64,
    streak: u32,
}

/// Why a peer is a suspect: the highest slot it handed over that the head
/// did not reach, and the wall-clock slot it became one at.
#[derive(Debug, Clone, Copy)]
struct Suspicion {
    through: u64,
    since: u64,
}

/// Stall windows a peer stays a suspect for at most, if the head never
/// passes what it handed over: an execution client that was down while an
/// honest peer's blocks were handed over must not keep that peer out for
/// good.
const SUSPICION_WINDOWS: u64 = 4;

/// Most doublings of a failed peer's cooldown: 8 refresh intervals (16 slots
/// on lean, 128 on beacon). A slow honest peer that keeps timing out loses
/// its lead for that long at most.
const MAX_COOLDOWN_DOUBLINGS: u32 = 3;

/// A peer's reported head, and the wall-clock slot the report arrived at.
#[derive(Debug, Clone, Copy)]
struct Claim {
    head_slot: u64,
    reported_at: u64,
}

/// Every connected peer's latest `Status` head, and the per-peer state of the
/// `Status` exchange that keeps it fresh.
#[derive(Debug, Default)]
pub(crate) struct PeerHeads {
    /// The head each peer last reported, while it stays connected, the head
    /// is not one this node holds, and the report is not older than
    /// `SyncThresholds::report_lifetime`.
    heads: HashMap<PeerId, Claim>,
    /// Peers that have answered a `Status` of ours on this connection. The
    /// first answer is the handshake's, and every later one is a refresh's,
    /// which needs a larger lead to start a range sync. No refresh goes out
    /// while the handshake is (see [`Self::awaiting_handshake`]), so the
    /// answers cannot arrive out of order.
    answered: HashSet<PeerId>,
    /// Peers whose handshake `Status` is still out: neither answered nor
    /// failed. They are not refreshed meanwhile, or a refresh answered before
    /// a slow handshake answer would be taken for the handshake's.
    awaiting_handshake: HashSet<PeerId>,
    /// Each peer's failed range requests (an empty or refused answer, a
    /// timeout) since its last successful one. A peer that has just failed is
    /// cooling down (see [`Self::range_cooling_down`]): it is not synced
    /// towards, and its claim does not count towards the network head, for a
    /// refresh interval doubled for every further failure in a row.
    ///
    /// Not synced towards, because its own `Status` requests are not rate
    /// limited and the highest head gets the next batch, so a peer claiming a
    /// head it does not serve could otherwise take every batch. Not counted,
    /// because a lead its peer has just failed to serve is no evidence the
    /// node is behind: during a network-wide stall, when every node trails the
    /// clock, such a claim would otherwise idle the node for a stall window
    /// after every block the network manages to make.
    range_failures: HashMap<PeerId, RangeFailures>,
    /// Peers whose range blocks left the head where it was for a whole window
    /// (see `P2PServer::expire_range_watermark`). Like a peer cooling down,
    /// they are not synced towards and their claims do not count, but until
    /// the head passes the highest slot they handed over (or
    /// [`SUSPICION_WINDOWS`] stall windows pass), and no later answer of
    /// theirs clears it: they were not serving a chain the head can follow.
    /// Kept across a reconnect, which would otherwise shed it, and dropped
    /// only on those two conditions, which also bound how many are held.
    suspects: HashMap<PeerId, Suspicion>,
    /// The wall-clock slot of each connected peer's last `Status` request
    /// that was acted on: at most one a slot (see [`Self::inbound_due`]).
    inbound_at: HashMap<PeerId, u64>,
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
            return Report::Future;
        }
        if held {
            self.heads.remove(&peer);
            return Report::Held;
        }
        let claim = Claim {
            head_slot,
            reported_at: wall_slot,
        };
        self.heads.insert(peer, claim);
        Report::Counted
    }

    /// Forget the failure runs whose longest cooldown ran out twice over by
    /// `wall_slot`: kept across a reconnect, which would otherwise reset a
    /// peer's backoff, they are dropped only once they no longer matter.
    pub(crate) fn prune_range_failures(&mut self, wall_slot: u64, interval: u64) {
        let longest = interval.saturating_mul(1 << MAX_COOLDOWN_DOUBLINGS);
        self.range_failures
            .retain(|_, failures| failures.last.saturating_add(2 * longest) > wall_slot);
    }

    /// Drop every report older than `lifetime` slots at `wall_slot`. Returns
    /// whether any was dropped.
    pub(crate) fn expire(&mut self, wall_slot: u64, lifetime: u64) -> bool {
        let before = self.heads.len();
        self.heads
            .retain(|_, claim| claim.reported_at.saturating_add(lifetime) >= wall_slot);
        self.heads.len() != before
    }

    /// Forget a disconnected peer.
    pub(crate) fn forget(&mut self, peer: &PeerId) {
        self.heads.remove(peer);
        self.answered.remove(peer);
        self.awaiting_handshake.remove(peer);
        self.inbound_at.remove(peer);
        self.last_exchange.remove(peer);
        self.foreign_digest.remove(peer);
        self.status_versions.remove(peer);
    }

    /// The network's head as the peers report it: the highest counted report
    /// from a peer not cooling down from a failed range request (see
    /// [`Self::range_cooling_down`]), `None` with none at all.
    pub(crate) fn network_head(&self, wall_slot: u64, interval: u64) -> Option<u64> {
        self.heads
            .iter()
            .filter(|(peer, _)| !self.range_cooling_down(peer, wall_slot, interval))
            .filter(|(peer, _)| !self.suspects.contains_key(peer))
            .map(|(_, claim)| claim.head_slot)
            .max()
    }

    /// Whether `peer` is a suspect (see [`Self::suspects`]).
    pub(crate) fn is_suspect(&self, peer: &PeerId) -> bool {
        self.suspects.contains_key(peer)
    }

    /// Make `peer` a suspect for the blocks it handed over through slot
    /// `through`, as of `wall_slot`. Suspected again, it is answerable for
    /// more, but its time still runs from when it was first suspected, so a
    /// suspicion stays bounded however often it is renewed.
    pub(crate) fn suspect(&mut self, peer: PeerId, through: u64, wall_slot: u64) {
        let suspicion = self.suspects.entry(peer).or_insert(Suspicion {
            through,
            since: wall_slot,
        });
        suspicion.through = suspicion.through.max(through);
    }

    /// Clear the suspects the head at `head_slot` has passed, or that have
    /// been suspects for `lifetime` slots at `wall_slot`. Returns whether any
    /// was cleared.
    pub(crate) fn clear_suspects(&mut self, head_slot: u64, wall_slot: u64, lifetime: u64) -> bool {
        let before = self.suspects.len();
        self.suspects.retain(|_, suspicion| {
            head_slot < suspicion.through && suspicion.since.saturating_add(lifetime) > wall_slot
        });
        self.suspects.len() != before
    }

    /// Drop `peer`'s claim, returning whether it had one.
    pub(crate) fn drop_claim(&mut self, peer: &PeerId) -> bool {
        self.heads.remove(peer).is_some()
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
            if self.awaiting_handshake.contains(&peer) {
                continue;
            }
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

    /// Note that `peer` failed a range request at `wall_slot`.
    pub(crate) fn note_range_failure(&mut self, peer: PeerId, wall_slot: u64) {
        let failures = self.range_failures.entry(peer).or_insert(RangeFailures {
            last: wall_slot,
            streak: 0,
        });
        failures.last = wall_slot;
        failures.streak = failures.streak.saturating_add(1);
    }

    /// Note that `peer` answered a range request with blocks, ending its run
    /// of failures.
    pub(crate) fn note_range_success(&mut self, peer: &PeerId) {
        self.range_failures.remove(peer);
    }

    /// Whether `peer` is cooling down from a failed range request at
    /// `wall_slot`: for `interval` slots after the failure, doubled for every
    /// earlier failure in the same run, up to [`MAX_COOLDOWN_DOUBLINGS`].
    pub(crate) fn range_cooling_down(&self, peer: &PeerId, wall_slot: u64, interval: u64) -> bool {
        self.range_failures.get(peer).is_some_and(|failures| {
            let doublings = failures
                .streak
                .saturating_sub(1)
                .min(MAX_COOLDOWN_DOUBLINGS);
            let cooldown = interval.saturating_mul(1 << doublings);
            failures.last.saturating_add(cooldown) > wall_slot
        })
    }

    /// Whether a `Status` request from `peer` at `wall_slot` is to be acted
    /// on: the first in each slot is, later ones are only answered.
    pub(crate) fn inbound_due(&mut self, peer: PeerId, wall_slot: u64) -> bool {
        self.inbound_at.insert(peer, wall_slot) != Some(wall_slot)
    }

    /// Note that the handshake `Status` to `peer` has gone out.
    pub(crate) fn begin_handshake(&mut self, peer: PeerId) {
        self.awaiting_handshake.insert(peer);
    }

    /// Note that `peer`'s handshake is over, answered or failed, so it may be
    /// refreshed again.
    pub(crate) fn end_handshake(&mut self, peer: &PeerId) {
        self.awaiting_handshake.remove(peer);
    }

    /// Note an answer from `peer` to a `Status` of ours, returning whether it
    /// is a refresh's: every answer on a connection after the first, which
    /// is the handshake's.
    pub(crate) fn answer_is_refresh(&mut self, peer: PeerId) -> bool {
        !self.answered.insert(peer)
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
/// it holds a post-state for. On either chain: `Store::head` is the head key
/// both share (`Store::beacon_head` reads it too), and `has_state` covers
/// beacon states. A pending or held block has no post-state, so it
/// does not count, the same as a block the node has never seen.
fn holds_block(store: &Store, root: &H256) -> bool {
    store.head().is_ok_and(|head| head == *root) || store.has_state(root).unwrap_or(false)
}

/// Record the head `peer` reported in a `Status` (request or answer) and
/// republish the network head. Returns what became of it: only a
/// [`Report::Counted`] head is worth looking for a range to sync towards.
pub(crate) fn observe(
    server: &mut P2PServer,
    peer: PeerId,
    head_slot: u64,
    head_root: H256,
) -> Report {
    if !server.connected_peers.contains_key(&peer) {
        return Report::Disconnected;
    }
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

/// Republish the network head as of now, which drops reports past their
/// lifetime (see `publish`): run once a slot, since a report or a cooldown
/// running out changes the network head with nothing else happening.
pub(crate) fn refresh(server: &mut P2PServer) {
    publish(server);
}

/// Forget a disconnected peer's head and republish the network head.
pub(crate) fn forget(server: &mut P2PServer, peer: &PeerId) {
    server.peer_heads.forget(peer);
    publish(server);
}

/// Drop `peer`'s claim and republish the network head, for a peer whose
/// latest `Status` came from a fork digest this node does not sync from: its
/// earlier report is not about the chain being followed any more.
pub(crate) fn drop_claim(server: &mut P2PServer, peer: &PeerId) {
    if server.peer_heads.drop_claim(peer) {
        publish(server);
    }
}

/// Make `peer` a suspect for the blocks it handed over through slot
/// `through` (see [`PeerHeads::suspects`]), and republish the network head
/// without its claim.
pub(crate) fn suspect(server: &mut P2PServer, peer: &PeerId, through: u64) {
    let wall_slot = crate::wall_clock_slot(&server.store);
    server.peer_heads.suspect(*peer, through, wall_slot);
    publish(server);
}

/// Clear the suspects the head at `head_slot` has passed or that have served
/// their time at `wall_slot`, republishing the network head with their
/// claims if any was.
pub(crate) fn clear_suspects(server: &mut P2PServer, head_slot: u64, wall_slot: u64) {
    let lifetime = thresholds(&server.store)
        .stall_window
        .saturating_mul(SUSPICION_WINDOWS);
    if server
        .peer_heads
        .clear_suspects(head_slot, wall_slot, lifetime)
    {
        publish(server);
    }
}

/// Note a failed range request from `peer`, which starts or extends its
/// cooldown, and republish the network head without its claim. Only while it
/// is connected: libp2p reports a closed connection before the request it
/// failed, so a failure noted after `forget` would outlive the peer and hold
/// back its next connection's handshake.
pub(crate) fn note_range_failure(server: &mut P2PServer, peer: &PeerId) {
    if !server.connected_peers.contains_key(peer) {
        return;
    }
    let wall_slot = crate::wall_clock_slot(&server.store);
    server.peer_heads.note_range_failure(*peer, wall_slot);
    publish(server);
}

/// Publish the network head as of now, dropping reports past their lifetime
/// first, so no path republishes one between the refresh timer's ticks.
fn publish(server: &mut P2PServer) {
    let wall_slot = crate::wall_clock_slot(&server.store);
    let thresholds = thresholds(&server.store);
    server
        .peer_heads
        .expire(wall_slot, thresholds.report_lifetime());
    server
        .peer_heads
        .prune_range_failures(wall_slot, thresholds.status_refresh_slots);
    let network_head = server
        .peer_heads
        .network_head(wall_slot, thresholds.status_refresh_slots);
    server.store.set_network_head(network_head);
}

#[cfg(test)]
mod tests {
    use super::*;

    const BEACON_REFRESH: u64 = SyncThresholds::BEACON.status_refresh_slots;

    #[test]
    fn no_report_is_no_network_head() {
        assert_eq!(PeerHeads::default().network_head(0, 1), None);
    }

    #[test]
    fn the_highest_report_counts() {
        // A stale or still-syncing peer does not veto a fresher one.
        let mut heads = PeerHeads::default();
        heads.record(PeerId::random(), 100, 100, false);
        heads.record(PeerId::random(), 40, 100, false);
        assert_eq!(heads.network_head(0, 1), Some(100));
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
        assert_eq!(heads.network_head(0, 1), Some(600));
    }

    #[test]
    fn a_head_this_node_holds_is_not_a_lead() {
        // Finding: peers on a lighter fork whose tip we imported report a
        // higher slot than our head, but we are not missing anything from
        // them.
        let mut heads = PeerHeads::default();
        let on_lighter_fork = PeerId::random();
        assert_eq!(heads.record(on_lighter_fork, 110, 110, true), Report::Held);
        assert_eq!(heads.network_head(0, 1), None);
        // A peer that had reported an unknown head is dropped once its head is
        // one we hold.
        heads.record(on_lighter_fork, 109, 110, false);
        heads.record(on_lighter_fork, 110, 110, true);
        assert_eq!(heads.network_head(0, 1), None);
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
        assert_eq!(heads.network_head(0, 1), None);
    }

    #[test]
    fn a_later_report_replaces_an_earlier_one() {
        // Latest, not highest: a peer that reorged to a lower head is believed.
        let mut heads = PeerHeads::default();
        let peer = PeerId::random();
        heads.record(peer, 100, 100, false);
        heads.record(peer, 95, 100, false);
        assert_eq!(heads.network_head(0, 1), Some(95));
    }

    #[test]
    fn a_disconnected_peer_is_forgotten() {
        let mut heads = PeerHeads::default();
        let peer = PeerId::random();
        heads.record(peer, 100, 100, false);
        assert!(!heads.answer_is_refresh(peer));
        heads.note_digest(peer, false);
        heads.note_status_version(peer, StatusVersion::V2);
        heads.forget(&peer);
        assert_eq!(heads.network_head(0, 1), None);
        // The next connection's first answer is its handshake's again.
        assert!(!heads.answer_is_refresh(peer));
        heads.forget(&peer);
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
    fn a_peer_is_not_refreshed_while_its_handshake_is_out() {
        // Finding: a refresh answered before a slow handshake answer was
        // taken for the handshake's, and could start a one-block range sync.
        let mut heads = PeerHeads::default();
        let peer = PeerId::random();
        heads.begin_handshake(peer);
        heads.due_for_refresh([peer], 10, 4);
        assert!(heads.due_for_refresh([peer], 20, 4).is_empty());
        heads.end_handshake(&peer);
        assert_eq!(heads.due_for_refresh([peer], 20, 4), vec![peer]);
    }

    #[test]
    fn one_inbound_status_a_slot_is_acted_on() {
        let mut heads = PeerHeads::default();
        let peer = PeerId::random();
        assert!(heads.inbound_due(peer, 10));
        assert!(!heads.inbound_due(peer, 10));
        assert!(heads.inbound_due(peer, 11));
        heads.forget(&peer);
        assert!(heads.inbound_due(peer, 11));
    }

    #[test]
    fn only_the_first_answer_on_a_connection_is_the_handshakes() {
        // Finding: a mark per peer swapped the two when a slow handshake
        // answer arrived after the first refresh had gone out, so the refresh
        // answer started a one-block range sync that raced gossip.
        let mut heads = PeerHeads::default();
        let peer = PeerId::random();
        assert!(!heads.answer_is_refresh(peer));
        assert!(heads.answer_is_refresh(peer));
        assert!(heads.answer_is_refresh(peer));
    }

    #[test]
    fn a_peer_that_failed_a_range_request_cools_down_for_an_interval() {
        let mut heads = PeerHeads::default();
        let peer = PeerId::random();
        assert!(!heads.range_cooling_down(&peer, 100, 2));
        heads.note_range_failure(peer, 100);
        assert!(heads.range_cooling_down(&peer, 100, 2));
        assert!(heads.range_cooling_down(&peer, 101, 2));
        assert!(!heads.range_cooling_down(&peer, 102, 2));
        // A reconnect does not reset it, or a peer could shed its backoff by
        // reconnecting; it is pruned once it no longer matters.
        heads.note_range_failure(peer, 200);
        heads.forget(&peer);
        assert!(heads.range_cooling_down(&peer, 200, 2));
        heads.prune_range_failures(200 + 4 * (2 << MAX_COOLDOWN_DOUBLINGS), 2);
        assert!(heads.range_failures.is_empty());
    }

    #[test]
    fn each_failure_in_a_row_doubles_the_cooldown_until_a_success() {
        let mut heads = PeerHeads::default();
        let peer = PeerId::random();
        heads.note_range_failure(peer, 100);
        heads.note_range_failure(peer, 102);
        assert!(heads.range_cooling_down(&peer, 105, 2));
        assert!(!heads.range_cooling_down(&peer, 106, 2));
        heads.note_range_failure(peer, 106);
        assert!(heads.range_cooling_down(&peer, 113, 2));
        assert!(!heads.range_cooling_down(&peer, 114, 2));
        // Capped.
        for wall in 200..220 {
            heads.note_range_failure(peer, wall);
        }
        let cap = 2 << MAX_COOLDOWN_DOUBLINGS;
        assert!(heads.range_cooling_down(&peer, 219 + cap - 1, 2));
        assert!(!heads.range_cooling_down(&peer, 219 + cap, 2));
        // A successful answer ends the run.
        heads.note_range_success(&peer);
        heads.note_range_failure(peer, 300);
        assert!(!heads.range_cooling_down(&peer, 302, 2));
    }

    #[test]
    fn a_suspect_is_cleared_once_the_head_passes_what_it_handed_over_or_its_time_is_up() {
        let mut heads = PeerHeads::default();
        let peer = PeerId::random();
        heads.record(peer, 500, 100, false);
        heads.suspects.insert(
            peer,
            Suspicion {
                through: 300,
                since: 100,
            },
        );
        assert_eq!(heads.network_head(100, 2), None);
        // A head that moved, but not past what it handed over.
        assert!(!heads.clear_suspects(250, 110, 64));
        // A reconnect does not shed it.
        heads.forget(&peer);
        assert!(heads.is_suspect(&peer));
        // Past it: cleared.
        assert!(heads.clear_suspects(300, 120, 64));
        assert!(!heads.is_suspect(&peer));
        // Or once its time is up, the head never getting there; being
        // suspected again later does not restart it.
        heads.suspect(peer, 300, 100);
        heads.suspect(peer, 400, 150);
        assert!(!heads.clear_suspects(0, 163, 64));
        assert!(heads.clear_suspects(0, 164, 64));
    }

    #[test]
    fn a_cooling_peers_claim_does_not_count() {
        // Finding: during a network-wide stall every node trails the clock,
        // so a peer claiming a head it never serves idled the node for a
        // stall window after every block the network made.
        let mut heads = PeerHeads::default();
        let liar = PeerId::random();
        let honest = PeerId::random();
        heads.record(liar, 500, 500, false);
        heads.record(honest, 400, 500, false);
        assert_eq!(heads.network_head(500, 2), Some(500));
        heads.note_range_failure(liar, 500);
        assert_eq!(heads.network_head(501, 2), Some(400));
        assert_eq!(heads.network_head(502, 2), Some(500));
        // A digest the node does not sync from takes the claim away for good.
        assert!(heads.drop_claim(&liar));
        assert!(!heads.drop_claim(&liar));
        assert_eq!(heads.network_head(600, 2), Some(400));
    }

    #[test]
    fn a_report_counts_for_its_lifetime_and_no_longer() {
        // Finding: a connected peer that stopped answering kept its last
        // head in the network head for as long as it stayed connected.
        let lifetime = SyncThresholds::LEAN.report_lifetime();
        let refresh = SyncThresholds::LEAN.status_refresh_slots;
        let mut heads = PeerHeads::default();
        let peer = PeerId::random();
        heads.record(peer, 100, 100, false);
        // A refresh that times out (10 s, under 3 lean slots) and the one
        // after it come and go before the claim does.
        assert!(!heads.expire(100 + 2 * refresh + 3, lifetime));
        assert!(!heads.expire(100 + lifetime, lifetime));
        assert_eq!(heads.network_head(0, 1), Some(100));
        assert!(heads.expire(100 + lifetime + 1, lifetime));
        assert_eq!(heads.network_head(0, 1), None);
        // A fresh report counts again.
        heads.record(peer, 120, 120, false);
        assert_eq!(heads.network_head(0, 1), Some(120));
    }
}
