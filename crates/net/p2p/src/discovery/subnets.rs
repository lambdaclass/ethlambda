//! The subnet hunt: aim discv5 at the attestation subnets this node subscribes
//! to but has too few connected peers advertising.
//!
//! The dial loop draws whatever the crawl happened to find and ranks it, which
//! only reorders random draws. About one mainnet record in 32 advertises a given
//! subnet, so a subscribed subnet nobody connected covers can stay that way for
//! as long as the crawl takes to stumble on a peer for it. ethrex's predicate
//! queries let the search be aimed instead: discovery runs our test on every
//! record it sees and hands back the ones that pass.
//!
//! ```text
//!  dial tick ── wanted subnets ──► watch ──► hunt task (one hunt at a time)
//!      ▲                                       │ 1. records_matching: what discovery holds
//!      │                                       │ 2. find_nodes: walk the DHT for the rest
//!      └──── admitted peers ◄──── mpsc ◄───────┘
//! ```
//!
//! The dial tick says what is short, the task does the asking, and the finds
//! come back as ordinary candidates: [`rank_candidates`] puts a peer on a
//! wanted subnet ahead of the crawl's random draws, and the dial loop dials it
//! under the same budget as anything else. The task owns every `.await`, since
//! the dial loop holds `&mut P2PServer` for its whole tick and must never wait
//! on discovery.
//!
//! Lighthouse does the same with sigp/discv5's `find_node_predicate`, whose
//! semantics ethrex's `find_nodes` copies: a match counts only once its node has
//! answered the query, so dead records stay out. The predicate is
//! Lighthouse's too: everything admission checks, plus at least one wanted
//! `attnets` bit.
//!
//! [`rank_candidates`]: super::admission::rank_candidates

use std::collections::{BTreeSet, HashMap, HashSet};
use std::time::{Duration, Instant};

use ethrex_common::H256;
use ethrex_p2p::discovery::DiscoveryHandle;
use ethrex_p2p::types::NodeRecord;
use libp2p::PeerId;
use tokio::sync::{mpsc, watch};
use tracing::debug;

use super::admission::{DiscoveredPeer, LeanFilter};
use super::enr::{ATTNETS_ENR_KEY, attnets_has};
use crate::ConnectionDirection;

/// Connected peers advertising a subscribed subnet, below which the hunt looks
/// for more. Lighthouse's `TARGET_SUBNET_PEERS`.
///
/// More than one because a subnet's only peer is one disconnect away from
/// leaving it uncovered, and the crawl is in no hurry to replace it.
pub(crate) const TARGET_SUBNET_PEERS: usize = 3;

/// Most peers one hunt hands the dial loop. Lighthouse asks the same number of
/// each grouped subnet query (`TARGET_PEERS_FOR_GROUPED_QUERY`).
///
/// Not the shortfall itself: a match needs only one wanted bit, so the peers a
/// hunt finds can all land on the same subnet. The next hunt recounts.
const MAX_HUNT_RESULTS: usize = 6;

/// How long one network walk may run before it answers with what it found.
///
/// Short against ethrex's own cap (`MAX_QUERY_TIMEOUT`, 60 s): a find is only
/// worth something once it is dialed, and the next hunt can always walk again.
const HUNT_QUERY_TIMEOUT: Duration = Duration::from_secs(10);

/// Pause between the end of one hunt and the start of the next.
///
/// Long enough for the last hunt's dials to become connections, so the next
/// one counts them instead of hunting for peers already on their way; a dial
/// that times out takes ten seconds by itself. On a small network that has no
/// more peers on a subnet to give, this is also the rate a hunt that finds
/// nothing is repeated at.
const HUNT_INTERVAL: Duration = Duration::from_secs(30);

/// How long a peer the hunt handed over stays out of later hunts.
///
/// Discovery keeps offering a peer that turned us away: a mainnet node at its
/// inbound cap completes the handshake and then says goodbye, which reads as a
/// connection that closed, not one refused. Without this every hunt would
/// return the same few full nodes and the dial loop would spend its budget
/// on them every time.
const REOFFER_AFTER: Duration = Duration::from_secs(10 * 60);

/// The dial loop's end of the hunt.
pub(crate) struct SubnetHunt {
    /// Subnets this node subscribes to, which are what its ENR's `attnets`
    /// advertises. Fixed for the life of the process: neither chain rotates
    /// them (see `beacon::subnets`).
    subscribed: HashSet<u64>,
    /// What is short right now, read by the hunt task. Empty means nothing to
    /// hunt for, which is also what is published while the dial loop has no
    /// budget to dial a find with.
    wanted: watch::Sender<BTreeSet<u64>>,
    /// Peers the hunt found, already through admission.
    found: mpsc::UnboundedReceiver<DiscoveredPeer>,
}

impl SubnetHunt {
    /// Start the hunt task, idle until [`Self::update`] publishes a subnet.
    /// Must be called from inside a tokio runtime.
    ///
    /// The task ends once this value is dropped, at the end of the hunt it is
    /// in, which is when the `P2PServer` holding it goes away.
    pub(crate) fn spawn(
        handle: DiscoveryHandle,
        filter: LeanFilter,
        subscribed: HashSet<u64>,
    ) -> Self {
        let (wanted, wanted_rx) = watch::channel(BTreeSet::new());
        let (found_tx, found) = mpsc::unbounded_channel();
        tokio::spawn(hunt(handle, filter, wanted_rx, found_tx));
        Self {
            subscribed,
            wanted,
            found,
        }
    }

    /// Recount and publish which subscribed subnets are short of
    /// [`TARGET_SUBNET_PEERS`].
    ///
    /// `may_dial` is whether the dial loop has budget for a find this tick.
    /// Without it nothing is wanted, so the task does not walk the network for
    /// peers nobody would dial.
    pub(crate) fn update(
        &self,
        peer_attnets: &HashMap<PeerId, Vec<u64>>,
        connected_peers: &HashMap<PeerId, ConnectionDirection>,
        may_dial: bool,
    ) {
        let short = if may_dial {
            short_subnets(&self.subscribed, peer_attnets, connected_peers)
        } else {
            BTreeSet::new()
        };
        // Only a change wakes the task, and the dial tick runs up to fifty
        // times a second.
        self.wanted.send_if_modified(|wanted| {
            let changed = *wanted != short;
            *wanted = short;
            changed
        });
    }

    /// The subnets the hunt is looking for right now, for ranking.
    pub(crate) fn wanted(&self) -> HashSet<u64> {
        self.wanted.borrow().iter().copied().collect()
    }

    /// Whatever the hunt has found since the last call.
    pub(crate) fn drain_found(&mut self) -> Vec<DiscoveredPeer> {
        let mut found = Vec::new();
        while let Ok(peer) = self.found.try_recv() {
            found.push(peer);
        }
        found
    }
}

/// The subscribed subnets fewer than [`TARGET_SUBNET_PEERS`] connected peers
/// advertise.
///
/// Counted from `peer_attnets`, which holds the `attnets` of peers this node
/// dialed from discovery: an inbound peer never shows us its ENR, so it covers
/// nothing here. That undercounts, which makes the hunt more eager than it has
/// to be, never blind to a real gap.
fn short_subnets(
    subscribed: &HashSet<u64>,
    peer_attnets: &HashMap<PeerId, Vec<u64>>,
    connected_peers: &HashMap<PeerId, ConnectionDirection>,
) -> BTreeSet<u64> {
    let mut peers_on: HashMap<u64, usize> = HashMap::new();
    for subnets in peer_attnets
        .iter()
        .filter(|(peer, _)| connected_peers.contains_key(peer))
        .map(|(_, subnets)| subnets)
    {
        for subnet in subnets.iter().filter(|subnet| subscribed.contains(subnet)) {
            *peers_on.entry(*subnet).or_insert(0) += 1;
        }
    }
    subscribed
        .iter()
        .copied()
        .filter(|subnet| peers_on.get(subnet).copied().unwrap_or(0) < TARGET_SUBNET_PEERS)
        .collect()
}

/// The hunt task: one hunt per [`HUNT_INTERVAL`] while anything is wanted.
///
/// A hunt first offers the matches discovery already holds, which costs no
/// network round trip, and walks the network only for what that left short.
/// Both answers go through the same predicate, [`hunt_predicate`].
async fn hunt(
    handle: DiscoveryHandle,
    filter: LeanFilter,
    mut wanted: watch::Receiver<BTreeSet<u64>>,
    found: mpsc::UnboundedSender<DiscoveredPeer>,
) {
    let mut offered: HashMap<H256, Instant> = HashMap::new();
    loop {
        // An error is the dial loop's sender going away, which is shutdown.
        let Ok(subnets) = wanted
            .wait_for(|wanted| !wanted.is_empty())
            .await
            .map(|wanted| wanted.clone())
        else {
            return;
        };
        offered.retain(|_, at| at.elapsed() < REOFFER_AFTER);

        let predicate = hunt_predicate(&filter, &subnets, &offered);
        let cached = handle.records_matching(predicate).await;
        let mut handed = offer(&filter, cached, MAX_HUNT_RESULTS, &mut offered, &found);

        if handed < MAX_HUNT_RESULTS {
            // Rebuilt, so the walk does not count the peers just offered.
            let predicate = hunt_predicate(&filter, &subnets, &offered);
            match handle
                .find_nodes(predicate, MAX_HUNT_RESULTS - handed, HUNT_QUERY_TIMEOUT)
                .await
            {
                Ok(result) => {
                    let walked = offer(
                        &filter,
                        result.records,
                        MAX_HUNT_RESULTS - handed,
                        &mut offered,
                        &found,
                    );
                    debug!(
                        ?subnets,
                        cached = handed,
                        walked,
                        outcome = ?result.outcome,
                        nodes_seen = result.nodes_seen,
                        findnodes_sent = result.findnodes_sent,
                        "Subnet hunt finished"
                    );
                    handed += walked;
                }
                // Not running is shutdown or a discovery that failed to start,
                // and a refusal is a full query slot: either way, the next hunt
                // asks again.
                Err(err) => debug!(?subnets, cached = handed, %err, "Subnet hunt could not walk"),
            }
        } else {
            debug!(
                ?subnets,
                cached = handed,
                "Subnet hunt satisfied from known records"
            );
        }
        if found.is_closed() {
            return;
        }
        crate::metrics::inc_subnet_hunt_peers(handed as u64);
        tokio::time::sleep(HUNT_INTERVAL).await;
    }
}

/// Which records a hunt for `subnets` wants: one advertising at least one of
/// them, that admission would dial, and that the hunt has not offered within
/// [`REOFFER_AFTER`].
///
/// Runs inside discovery's message loop on every record a walk sees, so the
/// one-bit test goes first and turns most records away before admission
/// decodes anything. The rest costs what [`PeerFilter`] does on every record
/// discovery takes in, which is the bound ethrex's documentation asks for.
///
/// [`PeerFilter`]: ethrex_p2p::peer_filter::PeerFilter
fn hunt_predicate(
    filter: &LeanFilter,
    subnets: &BTreeSet<u64>,
    offered: &HashMap<H256, Instant>,
) -> impl Fn(&NodeRecord) -> bool + Send + 'static {
    let filter = filter.clone();
    let subnets = subnets.clone();
    let offered: HashSet<H256> = offered.keys().copied().collect();
    move |record| {
        let advertises_one = record
            .pairs()
            .extra(ATTNETS_ENR_KEY)
            .is_some_and(|bits| subnets.iter().any(|subnet| attnets_has(&bits, *subnet)));
        advertises_one
            && filter
                .dial_target(record)
                .is_some_and(|peer| !offered.contains(&peer.node_id))
    }
}

/// Send up to `limit` of `records` to the dial loop, noting each in `offered`.
/// Returns how many went.
///
/// Admission runs again here rather than trusting the predicate: a fork
/// boundary can move the policy between discovery matching a record and the
/// answer arriving, and a record it no longer admits has nothing to dial.
fn offer(
    filter: &LeanFilter,
    records: Vec<NodeRecord>,
    limit: usize,
    offered: &mut HashMap<H256, Instant>,
    found: &mpsc::UnboundedSender<DiscoveredPeer>,
) -> usize {
    let mut handed = 0;
    for peer in records
        .iter()
        .filter_map(|record| filter.dial_target(record))
    {
        if handed == limit {
            break;
        }
        if offered.contains_key(&peer.node_id) {
            continue;
        }
        offered.insert(peer.node_id, Instant::now());
        if found.send(peer).is_err() {
            break;
        }
        handed += 1;
    }
    handed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::enr::{EnrForkId, LocalEnrParams, build_local_enr};
    use libp2p::identity::Keypair;
    use std::net::Ipv4Addr;

    /// The committee count every record and filter below is built with.
    const COMMITTEE_COUNT: u64 = 8;

    fn random_peer() -> PeerId {
        PeerId::from_public_key(&Keypair::generate_ed25519().public())
    }

    /// A peer's ENR as this node would publish it, on `fork_id`'s network and
    /// subscribed to `subnets`.
    fn peer_record(fork_id: EnrForkId, subnets: &[u64]) -> NodeRecord {
        build_local_enr(&LocalEnrParams {
            signer: secp256k1::SecretKey::new(&mut rand::rngs::OsRng),
            ip: Ipv4Addr::LOCALHOST.into(),
            discovery_port: 9000,
            p2p_port: 9001,
            subscription_subnets: subnets.iter().copied().collect(),
            attestation_committee_count: COMMITTEE_COUNT,
            fork_id,
            custody_group_count: None,
        })
        .expect("a record builds")
    }

    fn filter() -> LeanFilter {
        LeanFilter::new(EnrForkId::local(), COMMITTEE_COUNT)
    }

    #[test]
    fn the_hunt_wants_an_admissible_peer_on_a_wanted_subnet() {
        let wanted = BTreeSet::from([2]);
        let predicate = hunt_predicate(&filter(), &wanted, &HashMap::new());

        assert!(predicate(&peer_record(EnrForkId::local(), &[2, 5])));
        assert!(
            !predicate(&peer_record(EnrForkId::local(), &[5])),
            "a peer on none of the wanted subnets is not what the hunt is for"
        );
        let mut elsewhere = EnrForkId::local();
        elsewhere.fork_digest = [0xde, 0xad, 0xbe, 0xef];
        assert!(
            !predicate(&peer_record(elsewhere, &[2])),
            "the wanted bit does not get a peer on another network past admission"
        );
    }

    #[test]
    fn a_peer_already_offered_is_left_out_of_the_next_hunt() {
        let filter = filter();
        let record = peer_record(EnrForkId::local(), &[2]);
        let node_id = filter.dial_target(&record).expect("admitted").node_id;
        let offered = HashMap::from([(node_id, Instant::now())]);

        let predicate = hunt_predicate(&filter, &BTreeSet::from([2]), &offered);

        assert!(!predicate(&record));
    }

    #[test]
    fn offer_stops_at_its_limit_and_never_hands_over_a_peer_twice() {
        let filter = filter();
        let records: Vec<NodeRecord> = (0..3)
            .map(|_| peer_record(EnrForkId::local(), &[1]))
            .collect();
        let (found, mut received) = mpsc::unbounded_channel();
        let mut offered = HashMap::new();

        assert_eq!(offer(&filter, records.clone(), 2, &mut offered, &found), 2);
        // The same three again: two were handed over already, one is left.
        assert_eq!(offer(&filter, records, 2, &mut offered, &found), 1);

        let mut handed = HashSet::new();
        while let Ok(peer) = received.try_recv() {
            assert!(handed.insert(peer.node_id), "handed over twice");
        }
        assert_eq!(handed.len(), 3);
    }

    #[tokio::test]
    async fn nothing_is_wanted_while_the_dial_loop_cannot_dial() {
        // An unset handle: the task it starts finds discovery not running,
        // which is all this test needs, since it reads only what is published.
        let hunt = SubnetHunt::spawn(DiscoveryHandle::new(), filter(), HashSet::from([1, 4]));

        hunt.update(&HashMap::new(), &HashMap::new(), true);
        assert_eq!(hunt.wanted(), HashSet::from([1, 4]));

        hunt.update(&HashMap::new(), &HashMap::new(), false);
        assert!(hunt.wanted().is_empty());
    }

    fn connected(peers: &[PeerId]) -> HashMap<PeerId, ConnectionDirection> {
        peers
            .iter()
            .map(|peer| (*peer, ConnectionDirection::Outbound))
            .collect()
    }

    #[test]
    fn a_subscribed_subnet_below_target_is_short() {
        let peers: Vec<PeerId> = (0..TARGET_SUBNET_PEERS).map(|_| random_peer()).collect();
        // Subnet 1 has a full complement, subnet 4 is one peer short of it.
        let mut peer_attnets: HashMap<PeerId, Vec<u64>> =
            peers.iter().map(|peer| (*peer, vec![1u64])).collect();
        for peer in peers.iter().skip(1) {
            peer_attnets.get_mut(peer).unwrap().push(4);
        }

        let short = short_subnets(&HashSet::from([1, 4]), &peer_attnets, &connected(&peers));

        assert_eq!(short, BTreeSet::from([4]));
    }

    #[test]
    fn only_connected_peers_and_subscribed_subnets_count() {
        let here = random_peer();
        let gone = random_peer();
        // `gone` advertised subnet 2, but is no longer connected; `here`
        // covers subnet 9, which this node does not subscribe to.
        let peer_attnets = HashMap::from([(here, vec![9u64]), (gone, vec![2u64])]);

        let short = short_subnets(&HashSet::from([2]), &peer_attnets, &connected(&[here]));

        assert_eq!(short, BTreeSet::from([2]));
    }

    #[test]
    fn a_node_subscribed_to_nothing_hunts_for_nothing() {
        let peer = random_peer();
        let peer_attnets = HashMap::from([(peer, vec![0u64])]);

        let short = short_subnets(&HashSet::new(), &peer_attnets, &connected(&[peer]));

        assert!(short.is_empty());
    }
}
