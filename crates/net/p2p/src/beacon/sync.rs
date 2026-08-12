//! The actor side of the beacon anchor-to-head fetch.
//!
//! Every decision lives in [`crate::beacon::range_sync`]; this module only
//! moves them onto the wire and back. The four entry points are a peer's
//! `Status` response (opens or extends a session), a `BeaconBlocks` response
//! (imports, completes the batch and asks for the next), a failure of either
//! kind (rotates the peer out), and a timer (reopens a session the failures
//! closed).

use std::collections::HashSet;

use ethlambda_network_api::BlockSource;
use ethlambda_types::beacon::containers::SignedBeaconBlock;
use ethlambda_types::beacon::primitives::Root;
use libp2p::PeerId;
use rand::seq::SliceRandom;
use tracing::{debug, error, info, warn};

use crate::beacon::messages::{BeaconBlocksByRootRequest, BeaconRequestedBlockRoots, BeaconStatus};
use crate::beacon::protocols;
use crate::beacon::range_sync::{
    BEACON_SYNC_LAG_THRESHOLD, best_peer_head, next_request, start_or_merge,
};
use crate::req_resp::{BeaconRequest, Request};
use crate::{P2PServer, PendingRequest, PendingRequestKind};

/// Record a peer's advertised head and open or extend the sync session.
pub(crate) async fn on_beacon_status(server: &mut P2PServer, peer: PeerId, status: &BeaconStatus) {
    let peer_head_slot = status.head_slot();
    server.beacon_peer_heads.insert(peer, peer_head_slot);

    let local_head_slot = server.store.beacon_highest_imported_slot();
    let opened = start_or_merge(
        &mut server.beacon_range_sync,
        peer,
        peer_head_slot,
        local_head_slot,
    );
    if opened {
        info!(
            %peer,
            local_head_slot,
            peer_head_slot,
            gap = peer_head_slot.saturating_sub(local_head_slot),
            "Anchor-to-head range sync started"
        );
    }
    request_next_beacon_batch(server).await;
}

/// Re-open a session that failures closed, or that the node fell behind after.
///
/// Lean only ever opens a session from a peer's first `Status`, which is enough
/// for a node that joins and catches up once. A beacon follower has to *stay*
/// at the head, so a session whose peers all failed must be reopenable without
/// a reconnect.
pub(crate) async fn on_beacon_resync_check(server: &mut P2PServer) {
    if server.beacon_range_sync.is_some() {
        return;
    }
    // Cloned rather than borrowed through `server`: two disjoint fields of the
    // same struct, one mutably, is a rule the reader should not have to check.
    // A `HashSet<PeerId>` of at most a few dozen entries, every 12 seconds.
    let connected = server.connected_peers.clone();
    server
        .beacon_peer_heads
        .retain(|peer, _| connected.contains(peer));

    let Some((peer, peer_head_slot)) = best_peer_head(&server.beacon_peer_heads) else {
        return;
    };
    let local_head_slot = server.store.beacon_highest_imported_slot();
    if peer_head_slot.saturating_sub(local_head_slot) <= BEACON_SYNC_LAG_THRESHOLD {
        return;
    }
    if start_or_merge(
        &mut server.beacon_range_sync,
        peer,
        peer_head_slot,
        local_head_slot,
    ) {
        info!(
            %peer,
            local_head_slot,
            peer_head_slot,
            "Anchor-to-head range sync reopened by the resync timer"
        );
    }
    request_next_beacon_batch(server).await;
}

/// Put the next batch on the wire, if there is one and nothing is in flight.
pub(crate) async fn request_next_beacon_batch(server: &mut P2PServer) {
    let Some((peer, request, batch)) = server.beacon_range_sync.as_ref().and_then(next_request)
    else {
        return;
    };

    let start_slot = request.start_slot;
    let count = request.count;
    let Some(request_id) = server
        .swarm_handle
        .send_request(
            peer,
            Request::Beacon(BeaconRequest::BlocksByRange(request)),
            libp2p::StreamProtocol::new(protocols::BEACON_BLOCKS_BY_RANGE_V2),
        )
        .await
    else {
        warn!(%peer, start_slot, count, "Failed to send BeaconBlocksByRange request");
        fail_beacon_range_request(server, &peer);
        return;
    };

    debug!(%peer, start_slot, count, "Sent BeaconBlocksByRange request");
    if let Some(state) = &mut server.beacon_range_sync {
        state.in_flight = true;
    }
    server.outbound_requests.insert(
        request_id,
        PendingRequestKind::BeaconRange {
            start_slot: batch.start,
            end_slot: batch.end - 1,
        },
    );
}

/// Hand a batch to the blockchain actor and ask for the next one.
pub(crate) async fn on_beacon_blocks_by_range_response(
    server: &mut P2PServer,
    blocks: Vec<SignedBeaconBlock>,
    peer: PeerId,
    start_slot: u64,
    end_slot: u64,
) {
    if blocks.is_empty() {
        warn!(%peer, start_slot, end_slot, "Empty BeaconBlocksByRange response");
        fail_beacon_range_request(server, &peer);
        request_next_beacon_batch(server).await;
        return;
    }

    let Some(blockchain) = server.blockchain.as_ref() else {
        server.beacon_range_sync = None;
        warn!(%peer, "No blockchain handler available");
        return;
    };

    let mut forwarded = 0u64;
    for block in blocks {
        let slot = block.slot();
        if slot < start_slot || slot > end_slot {
            warn!(%peer, slot, start_slot, end_slot, "Beacon block outside the requested range");
            continue;
        }
        match blockchain.new_beacon_block(block, BlockSource::Sync) {
            Ok(()) => forwarded += 1,
            Err(err) => error!(%err, slot, %peer, "Failed to forward range-fetched beacon block"),
        }
    }
    debug!(%peer, start_slot, end_slot, forwarded, "BeaconBlocksByRange batch applied");

    if let Some(state) = &mut server.beacon_range_sync {
        state.complete_batch(end_slot);
        if state.current_range.is_empty() {
            info!(end_slot, "Anchor-to-head range sync complete");
            server.beacon_range_sync = None;
            return;
        }
        if state.peer_set.is_empty() {
            warn!("Anchor-to-head range sync has no peers left; the resync timer will reopen it");
            server.beacon_range_sync = None;
            return;
        }
    }
    request_next_beacon_batch(server).await;
}

/// Drop a peer from the session, and the session itself if it was the last.
pub(crate) fn fail_beacon_range_request(server: &mut P2PServer, peer: &PeerId) {
    server.beacon_peer_heads.remove(peer);
    let emptied = match &mut server.beacon_range_sync {
        Some(state) => {
            state.fail_peer(peer);
            state.peer_set.is_empty()
        }
        None => false,
    };
    if emptied {
        server.beacon_range_sync = None;
    }
}

/// Ask a random connected peer for one block by root.
///
/// The fallback for a block still orphaned after the range fetch has passed its
/// slot: the gap was fetched on the canonical chain, and this block is on a
/// fork off it.
pub(crate) async fn fetch_beacon_block_from_peer(server: &mut P2PServer, root: Root) -> bool {
    let failed = server
        .beacon_pending_root_requests
        .get(&root)
        .map(|pending| &pending.failed_peers);
    let pool: Vec<PeerId> = server
        .connected_peers
        .iter()
        .copied()
        .filter(|peer| failed.is_none_or(|set| !set.contains(peer)))
        .collect();
    // Every peer has failed for this root, so start a fresh round of
    // elimination: peers may have caught up, and new ones may have connected.
    let pool = if pool.is_empty() {
        if let Some(pending) = server.beacon_pending_root_requests.get_mut(&root) {
            pending.failed_peers.clear();
        }
        server.connected_peers.iter().copied().collect()
    } else {
        pool
    };

    let Some(&peer) = pool.choose(&mut rand::thread_rng()) else {
        warn!(%root, "Cannot fetch beacon block: no connected peers");
        return false;
    };

    let mut roots = BeaconRequestedBlockRoots::new();
    roots
        .push(root)
        .expect("one root is within the request list's bound");
    let request = BeaconBlocksByRootRequest { roots };
    let Some(request_id) = server
        .swarm_handle
        .send_request(
            peer,
            Request::Beacon(BeaconRequest::BlocksByRoot(request)),
            libp2p::StreamProtocol::new(protocols::BEACON_BLOCKS_BY_ROOT_V2),
        )
        .await
    else {
        warn!(%root, "Failed to send BeaconBlocksByRoot request");
        return false;
    };

    info!(%peer, %root, "Fetching a still-orphaned beacon block by root");
    server
        .beacon_pending_root_requests
        .entry(root)
        .or_insert(PendingRequest {
            attempts: 1,
            failed_peers: HashSet::new(),
        });
    server
        .outbound_requests
        .insert(request_id, PendingRequestKind::BeaconRoot(root));
    true
}

/// Hand a by-root result to the blockchain actor.
pub(crate) async fn on_beacon_blocks_by_root_response(
    server: &mut P2PServer,
    blocks: Vec<SignedBeaconBlock>,
    peer: PeerId,
    requested_root: Root,
) {
    if blocks.is_empty() {
        warn!(%peer, %requested_root, "Empty BeaconBlocksByRoot response");
        if let Some(pending) = server.beacon_pending_root_requests.get_mut(&requested_root) {
            pending.failed_peers.insert(peer);
        }
        return;
    }
    server.beacon_pending_root_requests.remove(&requested_root);
    let Some(blockchain) = server.blockchain.as_ref() else {
        return;
    };
    for block in blocks {
        if block.message_hash_tree_root() != requested_root {
            warn!(%peer, %requested_root, "Beacon block root mismatch, ignoring");
            continue;
        }
        let _ = blockchain
            .new_beacon_block(block, BlockSource::Sync)
            .inspect_err(|err| error!(%err, "Failed to forward a by-root beacon block"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RangeSyncState;
    use crate::beacon::messages::MAX_REQUEST_BLOCKS_DENEB;
    use libp2p::identity::Keypair;

    fn peer_n(n: u8) -> PeerId {
        let mut seed = [0u8; 32];
        seed[0] = n;
        let keypair = Keypair::ed25519_from_bytes(seed).expect("32 bytes is a valid ed25519 seed");
        PeerId::from_public_key(&keypair.public())
    }

    /// `fail_beacon_range_request` without a `P2PServer`: the two effects it
    /// has on the session are the whole of its behaviour, and neither needs a
    /// swarm to observe.
    fn fail(session: &mut Option<RangeSyncState>, peer: &PeerId) {
        let emptied = match session {
            Some(state) => {
                state.fail_peer(peer);
                state.peer_set.is_empty()
            }
            None => false,
        };
        if emptied {
            *session = None;
        }
    }

    #[test]
    fn a_failure_with_another_peer_left_keeps_the_session_open() {
        let mut session = Some(RangeSyncState::with_max_batch(
            65..200,
            peer_n(1),
            199,
            MAX_REQUEST_BLOCKS_DENEB,
        ));
        session.as_mut().unwrap().merge_peer(peer_n(2), 199, 200);
        session.as_mut().unwrap().in_flight = true;

        fail(&mut session, &peer_n(1));

        let state = session.expect("one peer is left");
        assert!(!state.in_flight, "the batch must be reissuable at once");
        assert_eq!(state.current_range.start, 65, "and from the same slot");
        assert_eq!(state.peer_set.len(), 1);
    }

    #[test]
    fn the_last_failure_closes_the_session_for_the_timer_to_reopen() {
        let mut session = Some(RangeSyncState::with_max_batch(
            65..200,
            peer_n(1),
            199,
            MAX_REQUEST_BLOCKS_DENEB,
        ));

        fail(&mut session, &peer_n(1));

        assert!(
            session.is_none(),
            "an empty peer set ends the session; on_beacon_resync_check reopens \
             it once a peer with a higher head is known again"
        );
    }

    #[test]
    fn the_resync_threshold_ignores_a_lag_inside_the_band() {
        // Mirrors the guard in `on_beacon_resync_check`. A one-slot lag is what
        // a healthy follower has for most of every slot, and reopening a
        // session for it would put a request on the wire every 12 seconds
        // forever.
        let local_head_slot = 1_000u64;
        for peer_head in local_head_slot..=(local_head_slot + BEACON_SYNC_LAG_THRESHOLD) {
            assert!(
                peer_head.saturating_sub(local_head_slot) <= BEACON_SYNC_LAG_THRESHOLD,
                "a lag of {} slots must not reopen a session",
                peer_head - local_head_slot
            );
        }
        let over = local_head_slot + BEACON_SYNC_LAG_THRESHOLD + 1;
        assert!(over.saturating_sub(local_head_slot) > BEACON_SYNC_LAG_THRESHOLD);
    }
}
