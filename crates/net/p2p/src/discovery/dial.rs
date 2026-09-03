//! The dial loop: turn what discv5 found into libp2p connections.
//!
//! Runs as a `P2PServer` tick every [`DISCOVERY_DIAL_INTERVAL`], drawing
//! candidates from the ethrex peer table, ranking them by subnet coverage, and
//! dialing one per tick until [`DiscoveryState::target_peers`] are connected.

use std::collections::{HashMap, HashSet, VecDeque};

use ethrex_p2p::peer_table::{PeerTable, PeerTableServerProtocol as _};
use libp2p::PeerId;
use libp2p::swarm::dial_opts::DialOpts;
use tracing::info;

use super::admission::{DiscoveredPeer, LeanFilter, rank_by_uncovered_subnets};
use super::{DISCOVERY_CANDIDATE_BATCH, DiscoveryHandle};
use crate::swarm_adapter::DialOutcome;
use crate::{P2PServer, metrics};

/// Everything the dial loop needs from a running discovery server.
pub(crate) struct DiscoveryState {
    peer_table: PeerTable,
    /// The same policy the peer table judges records with, asked here for the
    /// dial target behind an already-admitted record.
    filter: LeanFilter,
    /// Admitted candidates, best first, drained one per tick. Refilled from the
    /// peer table when empty.
    candidates: VecDeque<DiscoveredPeer>,
    /// Subnets advertised by peers we dialed from discovery.
    peer_attnets: HashMap<PeerId, Vec<u64>>,
    /// Our own peer ID, so the loop never dials itself.
    local_peer_id: PeerId,
    /// Connected-peer count above which the loop stops dialing.
    target_peers: usize,
}

impl DiscoveryState {
    pub(crate) fn new(handle: DiscoveryHandle, local_peer_id: PeerId) -> Self {
        Self {
            peer_table: handle.peer_table,
            filter: handle.filter,
            candidates: VecDeque::new(),
            peer_attnets: HashMap::new(),
            local_peer_id,
            target_peers: handle.target_peers,
        }
    }
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
    // clones: an actor ref and two `Copy` fields, taken only when a refill is
    // actually due rather than on every tick that just drains the queue.
    let Some(discovery) = server.discovery.as_ref() else {
        return;
    };
    if server.connected_peers.len() >= discovery.target_peers {
        return;
    }
    let refill = discovery
        .candidates
        .is_empty()
        .then(|| (discovery.peer_table.clone(), discovery.filter.clone()));
    let mut admitted = match refill {
        Some((peer_table, filter)) => draw_candidates(&peer_table, &filter).await,
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
    // One `DialOpts` carrying every address, not one dial per address: libp2p
    // races them within the attempt, which is what lets a live TCP address
    // rescue a peer whose advertised QUIC port does not answer.
    let opts = DialOpts::peer_id(candidate.peer_id)
        .addresses(candidate.addrs)
        .build();
    // The candidate has already been popped and marked tried in the peer table,
    // so this is the only chance to record its subnets: whatever happens here,
    // it will not be offered again. Which makes the refusal the swarm gives back
    // decide whether recording them is right.
    match server.swarm_handle.dial_outcome(opts).await {
        // Nothing in flight and nothing coming, so `forget_discovered_peer`
        // would never run: recording the subnets here would leave
        // `covered_subnets` counting a peer we never reach.
        DialOutcome::Unreachable => return,
        // A dial to this peer is already in flight, from an earlier tick or from
        // the static bootnode path in `build_swarm`. Recording is still right:
        // that attempt has a terminal event coming, which tears the entry down.
        // Skipping it is what would drift, and permanently — the peer connects,
        // covers subnets, and `covered_subnets` never counts them, so the dial
        // loop keeps hunting for coverage it already has.
        DialOutcome::AlreadyInProgress => {}
        DialOutcome::Queued => metrics::inc_discovered_peers_dialed(),
    }
    if let Some(discovery) = server.discovery.as_mut() {
        discovery
            .peer_attnets
            .insert(candidate.peer_id, candidate.subnets);
    }
}

/// Draw up to [`DISCOVERY_CANDIDATE_BATCH`] dialable peers from the peer table.
///
/// ethrex serves one contact per call, skipping anything its `PeerFilter` (ours:
/// [`LeanFilter`]) already rejected, and records each as tried before returning
/// it. So successive calls never repeat, an early `None` means the pool is
/// exhausted, and everything that arrives here has already passed admission.
async fn draw_candidates(peer_table: &PeerTable, filter: &LeanFilter) -> Vec<DiscoveredPeer> {
    let mut admitted = Vec::with_capacity(DISCOVERY_CANDIDATE_BATCH);
    for _ in 0..DISCOVERY_CANDIDATE_BATCH {
        let Ok(Some(contact)) = peer_table.get_contact_to_initiate().await else {
            break;
        };
        // A contact whose ENR has not arrived is unjudged, so the peer table
        // still offers it, but it carries no address or peer id to dial.
        // Skipping it costs nothing: it was marked tried on the way out either
        // way, and that set is cleared once a full scan finds nothing eligible.
        let Some(peer) = contact
            .record
            .as_ref()
            .and_then(|record| filter.dial_target(record))
        else {
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
