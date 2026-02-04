use ethlambda_storage::Store;
use libp2p::{PeerId, request_response};
use rand::seq::SliceRandom;
use tokio::time::Duration;
use tracing::{debug, error, info, warn};

use ethlambda_types::block::SignedBlockWithAttestation;
use ethlambda_types::primitives::ssz::TreeHash;

use super::{
    BLOCKS_BY_ROOT_PROTOCOL_V1, BlocksByRootRequest, Request, Response, ResponsePayload, Status,
};
use crate::{
    BACKOFF_MULTIPLIER, INITIAL_BACKOFF_MS, MAX_FETCH_RETRIES, P2PServer, PendingRequest,
    RetryMessage, req_resp::RequestedBlockRoots,
};

pub async fn handle_req_resp_message(
    server: &mut P2PServer,
    event: request_response::Event<Request, Response>,
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
                        handle_blocks_by_root_response(server, blocks, peer, request_id).await;
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
                handle_fetch_failure(server, root, peer, error).await;
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
    server
        .swarm
        .behaviour_mut()
        .req_resp
        .send_response(
            channel,
            Response::success(ResponsePayload::Status(our_status)),
        )
        .unwrap();
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
    let _ = server
        .swarm
        .behaviour_mut()
        .req_resp
        .send_response(channel, response)
        .inspect_err(|err| warn!(%peer, ?err, "Failed to send BlocksByRoot response"));
}

async fn handle_blocks_by_root_response(
    server: &mut P2PServer,
    blocks: Vec<SignedBlockWithAttestation>,
    peer: PeerId,
    request_id: request_response::OutboundRequestId,
) {
    info!(%peer, count = blocks.len(), "Received BlocksByRoot response");

    // Look up which root was requested for this specific request
    let Some(requested_root) = server.request_id_map.remove(&request_id) else {
        warn!(%peer, ?request_id, "Received response for unknown request_id");
        return;
    };

    for block in blocks {
        let root = block.message.block.tree_hash_root();

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

        server.blockchain.notify_new_block(block).await;
    }
}

/// Build a Status message from the current Store state.
pub fn build_status(store: &Store) -> Status {
    let finalized = store.latest_finalized();
    let head_root = store.head();
    let head_slot = store.get_block(&head_root).expect("head block exists").slot;
    Status {
        finalized,
        head: ethlambda_types::state::Checkpoint {
            root: head_root,
            slot: head_slot,
        },
    }
}

/// Fetch a missing block from a random connected peer.
/// Handles tracking in both pending_requests and request_id_map.
pub async fn fetch_block_from_peer(
    server: &mut P2PServer,
    root: ethlambda_types::primitives::H256,
) -> bool {
    if server.connected_peers.is_empty() {
        warn!(%root, "Cannot fetch block: no connected peers");
        return false;
    }

    // Select random peer
    let peers: Vec<_> = server.connected_peers.iter().copied().collect();
    let peer = match peers.choose(&mut rand::thread_rng()) {
        Some(&p) => p,
        None => {
            warn!(%root, "Failed to select random peer");
            return false;
        }
    };

    // Create BlocksByRoot request with single root
    let mut roots = RequestedBlockRoots::empty();
    if let Err(err) = roots.push(root) {
        error!(%root, ?err, "Failed to create BlocksByRoot request");
        return false;
    }
    let request = BlocksByRootRequest { roots };

    info!(%peer, %root, "Sending BlocksByRoot request for missing block");
    let request_id = server
        .swarm
        .behaviour_mut()
        .req_resp
        .send_request_with_protocol(
            &peer,
            Request::BlocksByRoot(request),
            libp2p::StreamProtocol::new(BLOCKS_BY_ROOT_PROTOCOL_V1),
        );

    // Track the request if not already tracked (new request)
    let pending = server
        .pending_requests
        .entry(root)
        .or_insert(PendingRequest {
            attempts: 1,
            last_peer: None,
        });

    // Update last_peer
    pending.last_peer = Some(peer);

    // Map request_id to root for failure handling
    server.request_id_map.insert(request_id, root);

    true
}

async fn handle_fetch_failure(
    server: &mut P2PServer,
    root: ethlambda_types::primitives::H256,
    peer: PeerId,
    error: request_response::OutboundFailure,
) {
    let Some(pending) = server.pending_requests.get_mut(&root) else {
        return;
    };

    if pending.attempts >= MAX_FETCH_RETRIES {
        error!(%root, %peer, attempts=%pending.attempts, %error,
               "Block fetch failed after max retries, giving up");
        server.pending_requests.remove(&root);
        return;
    }

    let backoff_ms = INITIAL_BACKOFF_MS * BACKOFF_MULTIPLIER.pow(pending.attempts - 1);
    let backoff = Duration::from_millis(backoff_ms);

    warn!(%root, %peer, attempts=%pending.attempts, ?backoff, %error,
          "Block fetch failed, scheduling retry");

    pending.attempts += 1;

    let retry_tx = server.retry_tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(backoff).await;
        let _ = retry_tx.send(RetryMessage::BlockFetch(root));
    });
}
