//! The dial loop: turn what discv5 found into libp2p QUIC connections.
//!
//! Runs as a `P2PServer` tick every [`DISCOVERY_DIAL_INTERVAL`], asking
//! discovery for candidates, ranking them by subnet coverage, and dialing one
//! per tick until [`DiscoveryState::target_peers`] are connected.
//!
//! Also the other direction: [`report_peer_connected`] and
//! [`report_peer_disconnected`] tell discovery what the swarm did, which is the
//! only way a libp2p connection becomes visible to it.

use std::collections::{HashMap, HashSet, VecDeque};

use ethrex_p2p::discovery::{DiscoveryHandle, PeerEvent};
use libp2p::PeerId;
use tracing::info;

use super::admission::{DialTargets, DiscoveredPeer, rank_by_uncovered_subnets};
use super::node_id::node_id_from_peer_id;
use super::{DISCOVERY_CANDIDATE_BATCH, SpawnedDiscovery};
use crate::{P2PServer, metrics};

/// Everything the dial loop needs from a running discovery server.
pub(crate) struct DiscoveryState {
    handle: DiscoveryHandle,
    /// How to dial the peers the filter admitted, filed as their ENRs arrived.
    dial_targets: DialTargets,
    /// Admitted candidates, best first, drained one per tick. Refilled from
    /// discovery when empty.
    candidates: VecDeque<DiscoveredPeer>,
    /// Subnets advertised by peers we dialed from discovery.
    peer_attnets: HashMap<PeerId, Vec<u64>>,
    /// Our own peer ID, so the loop never dials itself.
    local_peer_id: PeerId,
    /// Connected-peer count above which the loop stops dialing.
    target_peers: usize,
}

impl DiscoveryState {
    pub(crate) fn new(spawned: SpawnedDiscovery, local_peer_id: PeerId) -> Self {
        Self {
            handle: spawned.handle,
            dial_targets: spawned.dial_targets,
            candidates: VecDeque::new(),
            peer_attnets: HashMap::new(),
            local_peer_id,
            target_peers: spawned.target_peers,
        }
    }
}

/// Tell discovery we are connected to `peer_id`.
///
/// Two things follow upstream: the peer stops being offered as a dial
/// candidate, and it counts towards the completion figure that paces discv5
/// lookups, which eases off the startup rate as we approach `target_peers`.
/// Without this a libp2p node looks permanently peerless to discovery and keeps
/// looking at the startup rate for the life of the process.
///
/// A no-op when discovery is off, or for a peer whose id carries no secp256k1
/// key to name it by; see [`node_id_from_peer_id`].
pub(crate) fn report_peer_connected(server: &P2PServer, peer_id: &PeerId) {
    report(server, peer_id, PeerEvent::Connected);
}

/// Tell discovery our connection to `peer_id` is gone, so it is dialable again
/// and no longer counted.
pub(crate) fn report_peer_disconnected(server: &P2PServer, peer_id: &PeerId) {
    report(server, peer_id, PeerEvent::Disconnected);
}

fn report(server: &P2PServer, peer_id: &PeerId, event: PeerEvent) {
    let Some(discovery) = server.discovery.as_ref() else {
        return;
    };
    let Some(node_id) = node_id_from_peer_id(peer_id) else {
        return;
    };
    discovery.handle.record_peer_event(node_id, event);
}

/// Drop a peer's discovery bookkeeping.
///
/// Called from both teardown paths — a connection that closed and a dial that
/// never established — so the map cannot outlive the peers in it and
/// [`covered_subnets`] cannot credit a subnet to someone who left. A no-op when
/// discovery is off.
pub(crate) fn forget_discovered_peer(server: &mut P2PServer, peer_id: &PeerId) {
    if let Some(discovery) = server.discovery.as_mut() {
        discovery.peer_attnets.remove(peer_id);
    }
}

/// One tick of the dial loop. A no-op when discovery is disabled.
pub(crate) async fn dial_tick(server: &mut P2PServer) {
    // Snapshot what the refill needs before any `.await`, so no borrow of
    // `server.discovery` has to live across the async boundary. Both are handle
    // clones: an actor ref and an `Arc`, taken only when a refill is actually
    // due rather than on every tick that just drains the queue.
    let Some(discovery) = server.discovery.as_ref() else {
        return;
    };
    if server.connected_peers.len() >= discovery.target_peers {
        return;
    }
    let refill = discovery
        .candidates
        .is_empty()
        .then(|| (discovery.handle.clone(), discovery.dial_targets.clone()));
    let mut admitted = match refill {
        Some((handle, dial_targets)) => draw_candidates(&handle, &dial_targets).await,
        None => Vec::new(),
    };

    let Some(discovery) = server.discovery.as_mut() else {
        return;
    };
    if !admitted.is_empty() {
        let covered = covered_subnets(&discovery.peer_attnets, &server.connected_peers);
        rank_by_uncovered_subnets(&mut admitted, &covered);
        discovery.candidates.extend(admitted);
    }

    let mut next = None;
    while let Some(candidate) = discovery.candidates.pop_front() {
        if candidate.peer_id == discovery.local_peer_id
            || server.connected_peers.contains(&candidate.peer_id)
        {
            continue;
        }
        next = Some(candidate);
        break;
    }
    let Some(candidate) = next else {
        return;
    };

    info!(
        peer_id = %candidate.peer_id,
        subnets = ?candidate.subnets,
        "Dialing discovered peer"
    );
    // Record the peer only once the swarm has taken the dial. A dial it rejects
    // synchronously — already connected, already dialing, no addresses, denied —
    // raises no `OutgoingConnectionError`, so `forget_discovered_peer` would
    // never run and the entry would outlive the process's interest in it.
    if !server.swarm_handle.dial_accepted(candidate.addr).await {
        return;
    }
    metrics::inc_discovered_peers_dialed();
    if let Some(discovery) = server.discovery.as_mut() {
        discovery
            .peer_attnets
            .insert(candidate.peer_id, candidate.subnets);
    }
}

/// Draw up to [`DISCOVERY_CANDIDATE_BATCH`] dialable peers from discovery.
///
/// ethrex serves one node per call, skipping anything it has written off, is
/// already connected to, or whose ENR our [`LeanFilter`](super::admission::LeanFilter)
/// turned down, and records each as tried before returning it. So successive
/// calls never repeat, an early `None` means the pool is exhausted, and
/// everything that arrives here has already passed admission.
///
/// What arrives is a `Node`, which knows an address and a key and nothing about
/// `quic` or `attnets`, so the dial target is looked back up in [`DialTargets`]
/// under the node's id. A miss is ordinary: bootnodes are dialable to ethrex
/// before they have published an ENR, and one we never read a record for is one
/// we cannot build a libp2p multiaddr for. Skipping costs nothing, since the
/// node was marked tried on the way out either way and that set is cleared once
/// a full scan finds nothing eligible.
async fn draw_candidates(
    handle: &DiscoveryHandle,
    dial_targets: &DialTargets,
) -> Vec<DiscoveredPeer> {
    let mut admitted = Vec::with_capacity(DISCOVERY_CANDIDATE_BATCH);
    for _ in 0..DISCOVERY_CANDIDATE_BATCH {
        let Some(node) = handle.next_dial_candidate().await else {
            break;
        };
        let Some(peer) = dial_targets.get(&node.node_id()) else {
            continue;
        };
        admitted.push(peer);
    }
    admitted
}

/// Attestation subnets covered by peers we are currently connected to.
///
/// Only peers dialed from discovery contribute, since an inbound peer never
/// tells us its `attnets`. Treating an unknown peer as covering nothing makes
/// the ranking more eager, never wrong.
fn covered_subnets(
    peer_attnets: &HashMap<PeerId, Vec<u64>>,
    connected_peers: &HashSet<PeerId>,
) -> HashSet<u64> {
    peer_attnets
        .iter()
        .filter(|(peer, _)| connected_peers.contains(peer))
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

        let covered = covered_subnets(&peer_attnets, &HashSet::from([connected]));

        assert_eq!(covered, HashSet::from([1, 2]));
    }
}
