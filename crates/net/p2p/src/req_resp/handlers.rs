use std::collections::HashSet;

use ethlambda_storage::Store;
use libp2p::{PeerId, request_response};
use rand::seq::SliceRandom;
use spawned_concurrency::tasks::{Context, send_after};
use std::time::Duration;
use tracing::{debug, error, info, warn};

use ethlambda_types::checkpoint::Checkpoint;
use ethlambda_types::primitives::ssz::HashTreeRoot;
use ethlambda_types::{block::SignedBlockWithAttestation, primitives::H256};

use super::{
    BLOCKS_BY_ROOT_PROTOCOL_V1, BlocksByRootRequest, Request, Response, ResponsePayload, Status,
};
use crate::{
    BACKOFF_MULTIPLIER, INITIAL_BACKOFF_MS, MAX_FETCH_RETRIES, P2PServer, PendingRequest,
    p2p_protocol, req_resp::RequestedBlockRoots,
};

pub async fn handle_req_resp_message(
    server: &mut P2PServer,
    event: request_response::Event<Request, Response>,
    ctx: &Context<P2PServer>,
) {
    match event {
        request_response::Event::Message { peer, message, .. } => match message {
            request_response::Message::Request {
                request, channel, ..
            } => match request {
                Request::Status(status) => {
                    handle_status_request(server, status, channel, peer).await;
                }
                Request::BlocksByRoot(request) => {
                    handle_blocks_by_root_request(server, request, channel, peer).await;
                }
            },
            request_response::Message::Response {
                request_id,
                response,
            } => match response {
                Response::Success { payload } => match payload {
                    ResponsePayload::Status(status) => {
                        handle_status_response(status, peer).await;
                    }
                    ResponsePayload::BlocksByRoot(blocks) => {
                        handle_blocks_by_root_response(server, blocks, peer, request_id, ctx).await;
                    }
                },
                Response::Error { code, message } => {
                    let error_str = String::from_utf8_lossy(&message);
                    warn!(%peer, ?code, %error_str, "Received error response");
                }
            },
        },
        request_response::Event::OutboundFailure {
            peer,
            request_id,
            error,
            ..
        } => {
            warn!(%peer, ?request_id, %error, "Outbound request failed");

            // Check if this was a block fetch request
            if let Some(root) = server.request_id_map.remove(&request_id) {
                handle_fetch_failure(server, root, peer, ctx).await;
            }
        }
        request_response::Event::InboundFailure {
            peer,
            request_id,
            error,
            ..
        } => {
            warn!(%peer, ?request_id, %error, "Inbound request failed");
        }
        request_response::Event::ResponseSent {
            peer, request_id, ..
        } => {
            debug!(%peer, ?request_id, "Response sent successfully");
        }
    }
}

async fn handle_status_request(
    server: &mut P2PServer,
    request: Status,
    channel: request_response::ResponseChannel<Response>,
    peer: PeerId,
) {
    info!(finalized_slot=%request.finalized.slot, head_slot=%request.head.slot, "Received status request from peer {peer}");
    let our_status = build_status(&server.store);
    let response = Response::success(ResponsePayload::Status(our_status));
    server.swarm_handle.send_response(channel, response);
}

async fn handle_status_response(status: Status, peer: PeerId) {
    info!(finalized_slot=%status.finalized.slot, head_slot=%status.head.slot, "Received status response from peer {peer}");
}

async fn handle_blocks_by_root_request(
    server: &mut P2PServer,
    request: BlocksByRootRequest,
    channel: request_response::ResponseChannel<Response>,
    peer: PeerId,
) {
    let num_roots = request.roots.len();
    info!(%peer, num_roots, "Received BlocksByRoot request");

    let mut blocks = Vec::new();
    for root in request.roots.iter() {
        if let Some(signed_block) = server.store.get_signed_block(root) {
            blocks.push(signed_block);
        }
        // Missing blocks are silently skipped (per spec)
    }

    let found = blocks.len();
    info!(%peer, num_roots, found, "Responding to BlocksByRoot request");

    let response = Response::success(ResponsePayload::BlocksByRoot(blocks));
    server.swarm_handle.send_response(channel, response);
}

async fn handle_blocks_by_root_response(
    server: &mut P2PServer,
    blocks: Vec<SignedBlockWithAttestation>,
    peer: PeerId,
    request_id: request_response::OutboundRequestId,
    ctx: &Context<P2PServer>,
) {
    info!(%peer, count = blocks.len(), "Received BlocksByRoot response");

    // Look up which root was requested for this specific request
    let Some(requested_root) = server.request_id_map.remove(&request_id) else {
        warn!(%peer, ?request_id, "Received response for unknown request_id");
        return;
    };

    if blocks.is_empty() {
        server.request_id_map.insert(request_id, requested_root);
        warn!(%peer, "Received empty BlocksByRoot response");
        handle_fetch_failure(server, requested_root, peer, ctx).await;
        return;
    }

    for block in blocks {
        let root = H256(block.message.block.hash_tree_root());

        // Validate that this block matches what we requested
        if root != requested_root {
            warn!(
                %peer,
                received_root = %ethlambda_types::ShortRoot(&root.0),
                expected_root = %ethlambda_types::ShortRoot(&requested_root.0),
                "Received block with mismatched root, ignoring"
            );
            continue;
        }

        // Clean up tracking for this root
        server.pending_requests.remove(&root);

        if let Some(ref blockchain) = server.blockchain {
            let _ = blockchain
                .new_block(block)
                .inspect_err(|err| error!(%err, "Failed to forward fetched block to blockchain"));
        }
    }
}

/// Build a Status message from the current Store state.
pub fn build_status(store: &Store) -> Status {
    let finalized = store.latest_finalized();
    let head_root = store.head();
    let head_slot = store
        .get_block_header(&head_root)
        .expect("head block exists")
        .slot;
    Status {
        finalized,
        head: Checkpoint {
            root: head_root,
            slot: head_slot,
        },
    }
}

/// Fetch a missing block from a random connected peer.
/// Handles tracking in both pending_requests and request_id_map.
pub async fn fetch_block_from_peer(server: &mut P2PServer, root: H256) -> bool {
    if server.connected_peers.is_empty() {
        warn!(%root, "Cannot fetch block: no connected peers");
        return false;
    }

    // Exclude peers that already returned empty responses for this root
    let failed = server.pending_requests.get(&root).map(|p| &p.failed_peers);
    let pool: Vec<_> = if failed.is_none_or(|f| f.is_empty()) {
        server.connected_peers.iter().copied().collect()
    } else {
        let failed = failed.unwrap();
        server
            .connected_peers
            .iter()
            .copied()
            .filter(|p| !failed.contains(p))
            .collect()
    };

    // Fall back to full set if all peers have failed (new peers may have connected,
    // or previously-failing peers may have caught up). Clear failed_peers so subsequent
    // retries start a fresh round of elimination.
    let pool = if pool.is_empty() {
        warn!(%root, "All peers failed for this block, retrying with full peer set");
        if let Some(pending) = server.pending_requests.get_mut(&root) {
            pending.failed_peers.clear();
        }
        server.connected_peers.iter().copied().collect()
    } else {
        pool
    };

    let peer = match pool.choose(&mut rand::thread_rng()) {
        Some(&p) => p,
        None => {
            warn!(%root, "Failed to select random peer");
            return false;
        }
    };

    // Create BlocksByRoot request with single root
    let mut roots = RequestedBlockRoots::new();
    if let Err(err) = roots.push(root) {
        error!(%root, ?err, "Failed to create BlocksByRoot request");
        return false;
    }
    let request = BlocksByRootRequest { roots };

    let excluded = server.connected_peers.len() - pool.len();
    info!(%peer, %root, excluded, "Sending BlocksByRoot request for missing block");
    let Some(request_id) = server
        .swarm_handle
        .send_request(
            peer,
            Request::BlocksByRoot(request),
            libp2p::StreamProtocol::new(BLOCKS_BY_ROOT_PROTOCOL_V1),
        )
        .await
    else {
        warn!(%root, "Failed to send BlocksByRoot request (swarm adapter closed)");
        return false;
    };

    // Track the request if not already tracked (new request)
    server
        .pending_requests
        .entry(root)
        .or_insert(PendingRequest {
            attempts: 1,
            failed_peers: HashSet::new(),
        });

    // Map request_id to root for failure handling
    server.request_id_map.insert(request_id, root);

    true
}

async fn handle_fetch_failure(
    server: &mut P2PServer,
    root: H256,
    peer: PeerId,
    ctx: &Context<P2PServer>,
) {
    let Some(pending) = server.pending_requests.get_mut(&root) else {
        return;
    };

    pending.failed_peers.insert(peer);

    if pending.attempts >= MAX_FETCH_RETRIES {
        error!(%root, %peer, attempts=%pending.attempts,
               "Block fetch failed after max retries, giving up");
        server.pending_requests.remove(&root);
        return;
    }

    let backoff_ms = INITIAL_BACKOFF_MS * BACKOFF_MULTIPLIER.pow(pending.attempts - 1);
    let backoff = Duration::from_millis(backoff_ms);

    warn!(%root, %peer, attempts=%pending.attempts, ?backoff, "Block fetch failed, scheduling retry");

    pending.attempts += 1;

    send_after(backoff, ctx.clone(), p2p_protocol::RetryBlockFetch { root });
}
