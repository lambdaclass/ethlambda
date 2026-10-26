//! The dial loop: turn what discv5 found into libp2p connections.
//!
//! Runs as a `P2PServer` tick paced by [`dial_interval`], drawing candidates
//! from the ethrex peer table, ranking them by subnet coverage, and dialing one
//! per tick until [`DiscoveryState::target_peers`] are connected.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Duration;

use ethrex_p2p::discovery::lookup_interval_function;
use ethrex_p2p::peer_table::{PeerTable, PeerTableServerProtocol as _};
use libp2p::PeerId;
use libp2p::swarm::dial_opts::DialOpts;
use tokio::sync::mpsc;
use tracing::trace;

use super::admission::{DiscoveredPeer, LeanFilter, rank_candidates};
use super::{
    DIAL_INTERVAL_AT_TARGET, DIAL_INTERVAL_AT_ZERO_PEERS, DISCOVERY_CANDIDATE_BATCH,
    DiscoveryHandle,
};
use crate::swarm_adapter::DialOutcome;
use crate::{ConnectionDirection, P2PServer, metrics};

/// Everything the dial loop needs from a running discovery server.
pub(crate) struct DiscoveryState {
    /// Contacts [`spawn_contact_poll`]'s task has drawn from the peer table and
    /// passed through admission, waiting to be ranked into `candidates`.
    ///
    /// A receiver rather than the `PeerTable` itself, because drawing a contact
    /// is an actor round trip and this side of it must never await one: the dial
    /// loop holds `&mut P2PServer` for the length of a tick.
    contacts: mpsc::Receiver<DiscoveredPeer>,
    /// Admitted candidates, best first, drained one per tick. Refilled from
    /// `contacts` when empty.
    candidates: VecDeque<DiscoveredPeer>,
    /// Subnets advertised by peers we dialed from discovery.
    peer_attnets: HashMap<PeerId, Vec<u64>>,
    /// Our own peer ID, so the loop never dials itself.
    local_peer_id: PeerId,
    /// Connected-peer count above which the loop stops dialing.
    target_peers: usize,
    /// A handle on the admission policy the peer table also runs, so a fork
    /// boundary can move both with one call. See [`LeanFilter::set_fork_id`].
    filter: LeanFilter,
}

impl DiscoveryState {
    /// Starts the contact poll task, so it must be called from inside a tokio
    /// runtime. Every call site builds a `P2PServer` from an async context.
    pub(crate) fn new(handle: DiscoveryHandle, local_peer_id: PeerId) -> Self {
        Self {
            contacts: spawn_contact_poll(handle.peer_table, handle.filter.clone()),
            candidates: VecDeque::new(),
            peer_attnets: HashMap::new(),
            local_peer_id,
            target_peers: handle.target_peers,
            filter: handle.filter,
        }
    }

    /// The admission policy shared with the peer table.
    pub(crate) fn filter(&self) -> &LeanFilter {
        &self.filter
    }

    /// Connected-peer count above which the loop stops dialing.
    pub(crate) fn target_peers(&self) -> usize {
        self.target_peers
    }
}

/// How long the poll task waits after the peer table offers nothing.
///
/// Not an end: ethrex clears its tried set once a full scan finds nothing
/// eligible, and discv5 keeps crawling underneath, so contacts reappear on
/// their own. This is only the rate of asking whether they have.
///
/// Under ethrex's own lookup interval, which is bounded by
/// `INITIAL_LOOKUP_INTERVAL_MS` and `LOOKUP_INTERVAL_MS`, so the crawl stays
/// the thing that decides when a new peer is available and this poll is never
/// what delays one. It matters most on an empty table at startup, where the
/// dial loop previously re-asked on every 20ms tick and this task is the only
/// thing asking at all.
const CONTACT_POLL_IDLE: Duration = Duration::from_millis(250);

/// Drop a peer's discovery bookkeeping.
///
/// Called from both teardown paths — a connection that closed and a dial that
/// never established — so the map cannot outlive the peers in it and
/// [`covered_subnets`] cannot credit a subnet to someone who left. Without
/// discovery there are no attnets to drop, but custody still goes.
pub(crate) fn forget_discovered_peer(server: &mut P2PServer, peer_id: &PeerId) {
    if let Some(discovery) = server.discovery.as_mut() {
        discovery.peer_attnets.remove(peer_id);
    }
    // Custody is keyed by peer id and a peer id is a public key, so a returning
    // peer recomputes to the same set. Dropped anyway: the map is only ever
    // read for a connected peer, and keeping entries for departed ones would
    // grow it for the life of the process.
    server.peer_custody.remove(peer_id);
}

/// Dials opened per tick.
///
/// One, because [`dial_interval`] is what sets the rate now. The loop used to
/// dial a whole batch per fixed 5s tick, which was a workaround for a tick too
/// slow to find a peer with room: 8 per 5s is 1.6 dials a second. Pacing the
/// tick instead reaches [`super::MAX_DIAL_RATE_PER_SECOND`] while short and
/// backs off smoothly as the table fills, which the batch could not do.
const DIALS_PER_TICK: usize = 1;

/// How full the peer table is, 0 when empty and 1 at target, as the pacing
/// curve reads it.
///
/// The *minimum* of two ratios, so the loop runs fast while either is short.
/// That mirrors [`dial_budget`] taking the maximum of the same two shortfalls,
/// and it is what keeps a table full of inbound peers from reading as "done":
/// at 140 inbound and no outbound the total ratio alone would say 0.7 and pace
/// the loop down to a crawl, which is the exact state that stalled the mainnet
/// follower for two days.
pub(crate) fn dial_progress(server: &P2PServer, target_peers: usize) -> f64 {
    let total = if target_peers == 0 {
        1.0
    } else {
        server.connected_peers.len() as f64 / target_peers as f64
    };

    // A ratio of 1 reads as "nothing to be short on here", which is the answer
    // in both of the cases that have no ratio to give: lean, which reserves no
    // outbound slots at all, and a zero reservation, which is a zero target and
    // so a node asking for no peers. Written out rather than left to the
    // division, which would hand back a NaN that only survives this because
    // `f64::min` happens to ignore one.
    let (outbound, reservation) = outbound_standing(server, target_peers);
    let outbound_ratio = match reservation {
        Some(0) | None => 1.0,
        Some(reserved) => outbound as f64 / reserved as f64,
    };

    total.min(outbound_ratio).clamp(0.0, 1.0)
}

/// Outbound peers held, and the reservation they count against (`None` on
/// lean, which reserves nothing).
///
/// One accessor because [`dial_progress`] and [`dial_budget`] have to read the
/// same two numbers to stay in step: the rate a tick is paced at and the budget
/// that tick spends are the same policy asked twice, and the pair drifting
/// apart is how the mainnet follower stalled in the first place.
fn outbound_standing(server: &P2PServer, target_peers: usize) -> (usize, Option<usize>) {
    let outbound = server
        .connected_peers
        .values()
        .filter(|direction| **direction == ConnectionDirection::Outbound)
        .count();
    // The share of the *target* the swarm reserves, not a fixed slot count:
    // `build_swarm` derived the limits libp2p enforces from the same number, so
    // a shortfall read here is one the swarm has somewhere to put. A flat
    // reservation is what made a target of 50 keep dialing to 60 outbound
    // peers, and a target of 0, meaning "do not dial", still have 60 to chase.
    let reservation = server
        .wire
        .beacon()
        .map(|_| crate::beacon::swarm::max_outbound_connections(target_peers) as usize);
    (outbound, reservation)
}

/// How long to wait before the next dial, given how full the peer table is.
///
/// ethrex's `lookup_interval_function`, the easeInOutCubic curve
/// (<https://easings.net/#easeInOutCubic>) it paces discv4 and discv5 lookups
/// with, applied to this node's dial loop so both layers ramp the same way. The
/// shape is what matters: it stays near the floor while the table is genuinely
/// short, then climbs steeply through the middle rather than trading rate away
/// linearly for every peer gained.
///
/// Called rather than transcribed, because "both layers ramp the same way" is
/// the whole reason for this curve and a copy stops being true the moment
/// ethrex retunes it. Upstream takes its bounds in milliseconds and does not
/// clamp, so both of those happen here.
///
/// [`DIAL_INTERVAL_AT_ZERO_PEERS`] at `progress` 0, which is
/// [`super::MAX_DIAL_RATE_PER_SECOND`], easing to [`DIAL_INTERVAL_AT_TARGET`]
/// at 1. The rate reaches literal zero rather than merely slowing, because
/// [`dial_budget`] returns 0 at target and this loop never dials at all.
pub(crate) fn dial_interval(progress: f64) -> Duration {
    lookup_interval_function(
        progress.clamp(0.0, 1.0),
        DIAL_INTERVAL_AT_ZERO_PEERS.as_micros() as f64 / 1_000.0,
        DIAL_INTERVAL_AT_TARGET.as_micros() as f64 / 1_000.0,
    )
}

/// How many peers this tick may dial, capped at [`DIALS_PER_TICK`].
///
/// Two shortfalls, whichever is larger. The first is the plain one: dial until
/// `target_peers` are connected. The second exists because the first is not
/// enough on a network that dials us harder than we dial it.
///
/// Counting only the total is what stalled the mainnet follower. Inbound demand
/// filled the table to its cap, the total shortfall went to zero, and the dial
/// loop went quiet with **zero** of its reserved outbound slots used, leaving
/// nothing that could reach a peer serving a column it needed. A reservation
/// the dial loop stops trying to fill reserves nothing, so the outbound
/// shortfall is asked separately and is not suppressed by inbound peers, which
/// are not substitutes for it.
///
/// Beacon only, because the reservation is: the lean swarm runs with
/// [`crate::unlimited_connections`], where a devnet's peer count is bounded by
/// the devnet and there is nothing to reserve against.
fn dial_budget(server: &P2PServer, target_peers: usize) -> usize {
    let (outbound, outbound_reservation) = outbound_standing(server, target_peers);
    dial_budget_from(
        target_peers,
        server.connected_peers.len(),
        outbound,
        outbound_reservation,
    )
}

/// The arithmetic behind [`dial_budget`], separated from the server it reads so
/// the rule can be stated on numbers alone.
fn dial_budget_from(
    target_peers: usize,
    connected: usize,
    outbound: usize,
    outbound_reservation: Option<usize>,
) -> usize {
    let total_shortfall = target_peers.saturating_sub(connected);
    let outbound_shortfall = outbound_reservation
        .map(|reserved| reserved.saturating_sub(outbound))
        .unwrap_or(0);

    total_shortfall.max(outbound_shortfall).min(DIALS_PER_TICK)
}

/// One tick of the dial loop. Returns whether it actually opened a dial, which
/// is what [`crate::P2PServer`] paces the next tick on.
///
/// A tick that dials nothing is not a tick that should come back in 20ms. The
/// budget alone cannot say so: it is a shortfall against `target_peers`, and a
/// network that has fewer peers than that to offer — every lean devnet, against
/// a default target of [`super::DEFAULT_DISCOVERY_TARGET_PEERS`] — leaves the
/// shortfall permanently open. Pacing on the shortfall alone would then hold
/// the loop at the floor forever, emptying the contact buffer tens of times a
/// second for peers it is already connected to and keeping
/// [`spawn_contact_poll`] drawing the peer table down to refill it.
///
/// `target_peers` is the running loop's own [`DiscoveryState::target_peers`],
/// read by the caller that already had to check discovery is on.
pub(crate) async fn dial_tick(server: &mut P2PServer, target_peers: usize) -> bool {
    // Read once, and spent below. Nothing in between can move it: the one
    // `.await` left in this tick is the dial itself, and the `&mut P2PServer`
    // borrow held across it keeps any swarm event from touching
    // `connected_peers` for the length of the tick.
    let budget = dial_budget(server, target_peers);
    if budget == 0 {
        return false;
    }
    refill_candidates(server);
    let Some(discovery) = server.discovery.as_mut() else {
        return false;
    };

    // One dial per tick, paced by `dial_interval`. Finding a peer with room is
    // a numbers game — a well-connected beacon node completes the handshake and
    // answers `Goodbye(129)`, "too many peers", within the same millisecond —
    // and the rate is what wins it. That rate used to be smuggled into the
    // batch size because the tick itself was a flat 5s; it is in the tick now.
    let local_peer_id = discovery.local_peer_id;
    let mut dialed = false;

    let mut to_dial = Vec::with_capacity(budget);
    while to_dial.len() < budget {
        let Some(candidate) = discovery.candidates.pop_front() else {
            break;
        };
        if candidate.peer_id == local_peer_id
            || server.connected_peers.contains_key(&candidate.peer_id)
        {
            continue;
        }
        to_dial.push(candidate);
    }

    for candidate in to_dial {
        trace!(
            peer_id = %candidate.peer_id,
            subnets = ?candidate.subnets,
            "Dialing discovered peer"
        );
        // One `DialOpts` carrying every address, not one dial per address:
        // libp2p races them within the attempt, which is what lets a live TCP
        // address rescue a peer whose advertised QUIC port does not answer.
        let opts = DialOpts::peer_id(candidate.peer_id)
            .addresses(candidate.addrs)
            .build();
        // The candidate has already been popped and marked tried in the peer
        // table, so this is the only chance to record its subnets: whatever
        // happens here, it will not be offered again. Which makes the refusal
        // the swarm gives back decide whether recording them is right.
        match server.swarm_handle.dial_outcome(opts).await {
            // Nothing in flight and nothing coming, so `forget_discovered_peer`
            // would never run: recording the subnets here would leave
            // `covered_subnets` counting a peer we never reach.
            DialOutcome::Unreachable => continue,
            // A dial to this peer is already in flight, from an earlier tick or
            // from the static bootnode path in `build_swarm`. Recording is
            // still right: that attempt has a terminal event coming, which
            // tears the entry down. Skipping it is what would drift, and
            // permanently — the peer connects, covers subnets, and
            // `covered_subnets` never counts them, so the dial loop keeps
            // hunting for coverage it already has.
            DialOutcome::AlreadyInProgress => {}
            DialOutcome::Queued => {
                metrics::inc_discovered_peers_dialed();
                dialed = true;
            }
        }
        // Seed custody from the record while we have it. `metadata/3` overwrites
        // this with the peer's own current answer once it replies; until then a
        // stale hint still aims a request far better than a random peer does.
        if let Some(count) = candidate.custody_group_count {
            crate::req_resp::handlers::record_peer_custody(server, candidate.peer_id, count);
        }
        if let Some(discovery) = server.discovery.as_mut() {
            discovery
                .peer_attnets
                .insert(candidate.peer_id, candidate.subnets);
        }
    }
    dialed
}

/// Rank whatever [`spawn_contact_poll`] has admitted since the last refill
/// into the candidate queue, once that queue has run out.
///
/// Refilled only when empty, which is what leaves `spawn_contact_poll`'s
/// bounded channel able to do its job: draining on every tick would move
/// contacts into this unbounded queue as fast as the table could serve them,
/// and the backpressure that stops it being drawn down for nobody would be
/// gone. Ranking is per refill either way, since it scores a batch against
/// coverage this node has right now.
fn refill_candidates(server: &mut P2PServer) {
    let Some(discovery) = server.discovery.as_mut() else {
        return;
    };
    if !discovery.candidates.is_empty() {
        return;
    }
    let mut admitted = Vec::with_capacity(DISCOVERY_CANDIDATE_BATCH);
    while let Ok(peer) = discovery.contacts.try_recv() {
        admitted.push(peer);
    }
    if admitted.is_empty() {
        return;
    }
    let covered = covered_subnets(&discovery.peer_attnets, &server.connected_peers);
    let wanted = undersupplied_custody_columns(server);
    rank_candidates(&mut admitted, &covered, &wanted);
    if let Some(discovery) = server.discovery.as_mut() {
        discovery.candidates.extend(admitted);
    }
}

/// Draw dialable peers from the peer table, off the p2p actor's thread.
///
/// `get_contact_to_initiate` is an actor round trip, and the dial loop used to
/// await up to [`DISCOVERY_CANDIDATE_BATCH`] of them inline, holding
/// `&mut P2PServer` across every one. That parked the entire actor — gossip
/// forwarding, req/resp, swarm events, every tick — behind the peer table for
/// the length of a refill. The round trips happen in this task now, and what
/// reaches the loop is a channel of already-admitted [`DiscoveredPeer`]s it can
/// drain without awaiting anything.
///
/// ethrex serves one contact per call, skipping anything its `PeerFilter`
/// (ours: [`LeanFilter`]) already rejected, and records each as *tried* before
/// returning it. So successive calls never repeat, and everything that arrives
/// here has already passed admission.
///
/// That "marked tried on the way out" is why the channel is bounded and why the
/// task reserves its slot before asking. A contact drawn with nowhere to put it
/// is not offered a second time, so it would be lost rather than queued, and a
/// task free to run ahead of the dial loop would draw the table's eligible set
/// down for candidates nobody ever dialed. A full buffer stops it asking
/// instead.
///
/// The task ends when the receiver does, which is when the `P2PServer` holding
/// [`DiscoveryState`] is dropped.
fn spawn_contact_poll(peer_table: PeerTable, filter: LeanFilter) -> mpsc::Receiver<DiscoveredPeer> {
    let (contacts, receiver) = mpsc::channel(DISCOVERY_CANDIDATE_BATCH);
    tokio::spawn(async move {
        while let Ok(permit) = contacts.reserve().await {
            let Ok(Some(contact)) = peer_table.get_contact_to_initiate().await else {
                drop(permit);
                tokio::time::sleep(CONTACT_POLL_IDLE).await;
                continue;
            };
            // A contact whose ENR has not arrived is unjudged, so the peer table
            // still offers it, but it carries no address or peer id to dial.
            // Skipping it costs nothing: it was marked tried on the way out
            // either way. The permit is released with it, so the slot goes to
            // the next contact rather than to this one's absence.
            if let Some(peer) = contact
                .record
                .as_ref()
                .and_then(|record| filter.dial_target(record))
            {
                permit.send(peer);
            }
        }
    });
    receiver
}

/// How many distinct custodians a sampled column needs before dialing stops
/// treating it as a gap.
///
/// Tied to [`crate::MAX_FETCH_RETRIES`]: a by-root column lookup gets that many
/// attempts, `handle_column_fetch_failure` in `req_resp/handlers.rs` tracks
/// `failed_peers` so each retry asks a custodian it has not already asked, and
/// a column with fewer custodians than the ladder has rounds runs out of fresh
/// peers before it runs out of retries. Below this count, a lookup can still
/// exhaust its ladder on a handful of peers that are slow, unreachable, or
/// simply don't have the column cached, with no untried custodian left to
/// fall back to.
///
/// Presence — at least one custodian — used to be the bar, and it was too low
/// to catch this: a mainnet follower whose `lean_custody_column_peers` showed
/// only 5-8 custodians per sampled column (of 129 connected peers) still read
/// every one of those columns as "covered", so custody stopped contributing to
/// [`rank_candidates`] and dialing optimized purely for attestation-subnet
/// coverage. 78% of that node's by-root column requests went unanswered
/// (81,073 requests against 17,785 response chunks) while it was off the tip
/// and depended on by-root fetches alone.
const CUSTODY_REDUNDANCY_TARGET: usize = crate::MAX_FETCH_RETRIES as usize;

/// The columns this node samples whose connected-peer custodian count is below
/// [`CUSTODY_REDUNDANCY_TARGET`].
///
/// Empty on lean, which samples nothing, and empty on a beacon node whose
/// peers already supply every sampled column at the target, which is what
/// lets the ranking skip the per-candidate custody shuffle entirely in the
/// common case.
///
/// `peer_custody` holds a peer only once its `metadata/3` answer, or the `cgc`
/// its ENR carried at dial time, has been recorded, so a peer that has told us
/// neither contributes to any column's count. That makes the ranking more
/// eager than strictly necessary, never wrong: the cost of over-counting a gap
/// is one dial aimed at a peer that would have been worth dialing anyway.
fn undersupplied_custody_columns(server: &P2PServer) -> HashSet<u64> {
    let Some(wire) = server.wire.beacon() else {
        return HashSet::new();
    };
    let custodian_counts =
        custodian_counts_by_column(&server.peer_custody, &server.connected_peers);
    wire.custody_columns
        .iter()
        .copied()
        .filter(|column| {
            custodian_counts.get(column).copied().unwrap_or(0) < CUSTODY_REDUNDANCY_TARGET
        })
        .collect()
}

/// Distinct connected-peer custodian counts per column, the custody
/// counterpart of [`covered_subnets`] and read the same way.
///
/// A peer's own column list is deduplicated before it contributes, so a
/// column listed twice for the same peer (which should not happen, but
/// `metadata/3` is peer-supplied) still counts that peer once.
fn custodian_counts_by_column(
    peer_custody: &HashMap<PeerId, Vec<u64>>,
    connected_peers: &HashMap<PeerId, ConnectionDirection>,
) -> HashMap<u64, usize> {
    let mut counts = HashMap::new();
    for (_, columns) in peer_custody
        .iter()
        .filter(|(peer, _)| connected_peers.contains_key(peer))
    {
        for column in columns.iter().copied().collect::<HashSet<_>>() {
            *counts.entry(column).or_insert(0) += 1;
        }
    }
    counts
}

/// Attestation subnets covered by peers we are currently connected to.
///
/// Only peers dialed from discovery contribute, since an inbound peer never
/// tells us its `attnets`. Treating an unknown peer as covering nothing makes
/// the ranking more eager, never wrong.
fn covered_subnets(
    peer_attnets: &HashMap<PeerId, Vec<u64>>,
    connected_peers: &HashMap<PeerId, ConnectionDirection>,
) -> HashSet<u64> {
    peer_attnets
        .iter()
        .filter(|(peer, _)| connected_peers.contains_key(peer))
        .flat_map(|(_, subnets)| subnets.iter().copied())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;

    fn random_peer() -> PeerId {
        PeerId::from_public_key(&Keypair::generate_ed25519().public())
    }

    #[test]
    fn covered_subnets_unions_only_connected_peers() {
        let connected = random_peer();
        let gone = random_peer();
        let peer_attnets = HashMap::from([(connected, vec![1u64, 2]), (gone, vec![7u64])]);

        let covered = covered_subnets(
            &peer_attnets,
            &HashMap::from([(connected, ConnectionDirection::Inbound)]),
        );

        assert_eq!(covered, HashSet::from([1, 2]));
    }

    #[test]
    fn a_departed_peers_columns_stop_counting_as_covered() {
        // The case that stops the chain: what a peer custodied is only
        // reachable while that peer is connected, so a lookup aimed at a
        // column only a departed peer held gets an empty answer from
        // everyone. Counting it as supplied would keep the dial loop from
        // looking for a replacement.
        let connected = random_peer();
        let gone = random_peer();
        let peer_custody = HashMap::from([(connected, vec![47u64, 63]), (gone, vec![97u64])]);

        let counts = custodian_counts_by_column(
            &peer_custody,
            &HashMap::from([(connected, ConnectionDirection::Inbound)]),
        );

        assert_eq!(counts, HashMap::from([(47, 1), (63, 1)]));
    }

    #[test]
    fn two_peers_custodying_the_same_column_count_as_two() {
        let first = random_peer();
        let second = random_peer();
        let peer_custody = HashMap::from([(first, vec![47u64]), (second, vec![47u64])]);
        let connected = HashMap::from([
            (first, ConnectionDirection::Inbound),
            (second, ConnectionDirection::Outbound),
        ]);

        let counts = custodian_counts_by_column(&peer_custody, &connected);

        assert_eq!(counts, HashMap::from([(47, 2)]));
    }

    #[test]
    fn the_same_peer_listed_twice_for_a_column_counts_once() {
        // `metadata/3` is peer-supplied, so a duplicate in its own answer must
        // not inflate that one peer into two custodians.
        let peer = random_peer();
        let peer_custody = HashMap::from([(peer, vec![47u64, 47u64])]);
        let connected = HashMap::from([(peer, ConnectionDirection::Inbound)]);

        let counts = custodian_counts_by_column(&peer_custody, &connected);

        assert_eq!(counts, HashMap::from([(47, 1)]));
    }

    /// A column already at the redundancy target is not a gap: dialing should
    /// not keep chasing coverage it already has.
    #[test]
    fn a_column_at_the_target_is_not_undersupplied() {
        let peers: Vec<PeerId> = (0..CUSTODY_REDUNDANCY_TARGET)
            .map(|_| random_peer())
            .collect();
        let peer_custody = peers.iter().map(|peer| (*peer, vec![9u64])).collect();
        let connected = peers
            .iter()
            .map(|peer| (*peer, ConnectionDirection::Inbound))
            .collect();

        let counts = custodian_counts_by_column(&peer_custody, &connected);

        assert_eq!(
            counts.get(&9).copied().unwrap_or(0),
            CUSTODY_REDUNDANCY_TARGET
        );
    }

    /// One custodian short of the target must still read as a gap, so dialing
    /// keeps looking for one more.
    #[test]
    fn a_column_below_the_target_is_undersupplied() {
        let peers: Vec<PeerId> = (0..CUSTODY_REDUNDANCY_TARGET - 1)
            .map(|_| random_peer())
            .collect();
        let peer_custody = peers.iter().map(|peer| (*peer, vec![9u64])).collect();
        let connected = peers
            .iter()
            .map(|peer| (*peer, ConnectionDirection::Inbound))
            .collect();

        let counts = custodian_counts_by_column(&peer_custody, &connected);

        assert!(counts.get(&9).copied().unwrap_or(0) < CUSTODY_REDUNDANCY_TARGET);
    }

    /// The mainnet-follower regression this budget exists for: the peer table
    /// was full, every slot held by an inbound peer, and the dial loop went
    /// quiet with its whole outbound reservation unused. Nothing was then left
    /// that could reach a peer serving a column the node needed.
    #[test]
    fn a_full_inbound_table_does_not_stop_the_loop_from_filling_the_reservation() {
        let budget = dial_budget_from(200, 200, 0, Some(60));

        assert_eq!(
            budget, DIALS_PER_TICK,
            "an idle outbound reservation has to keep the loop dialing"
        );
    }

    /// The reservation scales with the target, so the loop never chases slots
    /// the swarm would refuse. A flat 60 is what made a target of 50 keep
    /// dialing past it, and a target of 0 dial at all.
    #[test]
    fn the_reservation_follows_the_target() {
        use crate::beacon::swarm::max_outbound_connections;

        // At target, on the reservation that target derives: nothing left.
        assert_eq!(
            dial_budget_from(50, 50, 15, Some(max_outbound_connections(50) as usize)),
            0
        );
        // A flat 60-slot reservation would still read 45 short here and keep
        // dialing to 60 outbound peers, well past the 50 asked for.
        assert_eq!(max_outbound_connections(50), 15);
    }

    /// `--discovery.target-peers 0` is an explicit "hold no peers", so neither
    /// shortfall may ask for a dial. The reservation used to be a flat 60 and
    /// this case dialed against the operator.
    #[test]
    fn a_zero_target_never_dials() {
        use crate::beacon::swarm::max_outbound_connections;

        let reservation = max_outbound_connections(0) as usize;
        assert_eq!(reservation, 0);
        assert_eq!(dial_budget_from(0, 0, 0, Some(reservation)), 0);
    }

    #[test]
    fn a_filled_reservation_on_a_full_table_stops_the_loop() {
        // Both shortfalls closed, so there is nothing left to dial for. This is
        // the case the outbound clause must not defeat: it widens *when* to
        // dial, it does not make the loop dial forever.
        assert_eq!(dial_budget_from(200, 200, 60, Some(60)), 0);
    }

    #[test]
    fn the_outbound_shortfall_is_measured_against_outbound_peers_alone() {
        // The table is *at* target, so the total shortfall is zero and only the
        // outbound one can still ask for a dial. 200 inbound peers are not a
        // substitute for the 5 missing outbound ones, so the loop keeps going.
        // How fast it goes is `dial_interval`'s job, not the budget's.
        assert_eq!(dial_budget_from(200, 200, 55, Some(60)), DIALS_PER_TICK);
        // Fill that last shortfall and it stops, which is what makes the line
        // above about outbound rather than about always returning one.
        assert_eq!(dial_budget_from(200, 200, 60, Some(60)), 0);
    }

    #[test]
    fn lean_reserves_nothing_and_paces_on_the_total_alone() {
        // The lean swarm runs unlimited, so there is no reservation to chase
        // and a table at target stops the loop exactly as it always did.
        assert_eq!(dial_budget_from(50, 50, 0, None), 0);
        assert_eq!(dial_budget_from(50, 47, 0, None), DIALS_PER_TICK);
    }

    /// The floor is the rate the loop is asked for when it has nothing.
    #[test]
    fn a_node_with_no_peers_dials_at_the_configured_rate() {
        let interval = dial_interval(0.0);

        assert_eq!(interval, DIAL_INTERVAL_AT_ZERO_PEERS);
        // One dial per tick, so the tick rate *is* the dial rate.
        let per_second = 1_000_000 / interval.as_micros();
        assert_eq!(per_second as u64, super::super::MAX_DIAL_RATE_PER_SECOND);
    }

    #[test]
    fn a_full_table_paces_at_the_slow_end() {
        assert_eq!(dial_interval(1.0), DIAL_INTERVAL_AT_TARGET);
    }

    /// easeInOutCubic is symmetric about its midpoint, which is the property
    /// that makes it hold near the floor while the table is genuinely short
    /// instead of trading rate away linearly for every peer gained.
    #[test]
    fn the_curve_is_ethrex_ease_in_out_cubic() {
        let lower = DIAL_INTERVAL_AT_ZERO_PEERS.as_micros() as f64;
        let upper = DIAL_INTERVAL_AT_TARGET.as_micros() as f64;

        // Halfway along, easeInOutCubic is exactly 0.5.
        let midpoint = dial_interval(0.5).as_micros() as f64;
        assert!((midpoint - (lower + upper) / 2.0).abs() < 1.0);

        // A quarter in, it has spent only 1/16 of the range: 4 * 0.25^3.
        let quarter = dial_interval(0.25).as_micros() as f64;
        let expected = 0.0625 * (upper - lower) + lower;
        assert!((quarter - expected).abs() < 1.0, "{quarter} vs {expected}");

        // Still under a tenth of the way to the slow end at a quarter full,
        // where a linear ramp would already be a quarter of the way there.
        assert!(quarter < lower + (upper - lower) / 10.0);
    }

    #[test]
    fn the_curve_never_goes_backwards_and_stays_inside_its_bounds() {
        let mut previous = dial_interval(0.0);
        for step in 0..=100 {
            let interval = dial_interval(step as f64 / 100.0);
            assert!(interval >= previous, "interval fell at {step}");
            assert!(interval >= DIAL_INTERVAL_AT_ZERO_PEERS);
            assert!(interval <= DIAL_INTERVAL_AT_TARGET);
            previous = interval;
        }
    }

    /// Out-of-range input is clamped rather than extrapolated: a peer count
    /// above target would otherwise run the cubic past 1 and produce an
    /// interval longer than the slow end.
    #[test]
    fn progress_outside_the_unit_range_is_clamped() {
        assert_eq!(dial_interval(-1.0), DIAL_INTERVAL_AT_ZERO_PEERS);
        assert_eq!(dial_interval(4.2), DIAL_INTERVAL_AT_TARGET);
    }

    #[test]
    fn the_budget_never_exceeds_one_tick() {
        // A node at zero peers is short its whole target, and still opens one
        // dial per tick: the rate it recovers at is set by `dial_interval`, so
        // a large shortfall must not turn into a burst here.
        assert_eq!(dial_budget_from(200, 0, 0, Some(60)), DIALS_PER_TICK);
    }
}
