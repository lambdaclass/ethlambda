use ethlambda_storage::Store;
use libp2p::{PeerId, request_response};
use rand::seq::SliceRandom;
use tokio::time::Duration;
use tracing::{debug, error, info, warn};

use ethlambda_types::block::SignedBlockWithAttestation;
use ethlambda_types::primitives::TreeHash;

use super::{
    BLOCKS_BY_ROOT_PROTOCOL_V1, BlocksByRootRequest, Request, Response, ResponsePayload,
    ResponseResult, Status,
};
use crate::{BACKOFF_MULTIPLIER, INITIAL_BACKOFF_MS, MAX_FETCH_RETRIES, P2PServer, PendingRequest};

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
            request_response::Message::Response { response, .. } => match response.payload {
                ResponsePayload::Status(status) => {
                    handle_status_response(status, peer).await;
                }
                ResponsePayload::BlocksByRoot(blocks) => {
                    handle_blocks_by_root_response(server, blocks, peer).await;
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
            Response::new(ResponseResult::Success, ResponsePayload::Status(our_status)),
        )
        .unwrap();
}

async fn handle_status_response(status: Status, peer: PeerId) {
    info!(finalized_slot=%status.finalized.slot, head_slot=%status.head.slot, "Received status response from peer {peer}");
}

async fn handle_blocks_by_root_request(
    _server: &mut P2PServer,
    request: BlocksByRootRequest,
    _channel: request_response::ResponseChannel<Response>,
    peer: PeerId,
) {
    let num_roots = request.roots.len();
    info!(%peer, num_roots, "Received BlocksByRoot request");

    // TODO: Implement signed block storage and send response chunks
    // For now, we don't send any response (drop the channel)
    // In a full implementation, we would:
    // 1. Look up each requested block root
    // 2. Send a response chunk for each found block
    // 3. Each chunk contains: result byte + encoded SignedBlockWithAttestation
    warn!(%peer, num_roots, "BlocksByRoot request received but block storage not implemented");
}

async fn handle_blocks_by_root_response(
    server: &mut P2PServer,
    block: SignedBlockWithAttestation,
    peer: PeerId,
) {
    let slot = block.message.block.slot;
    let root = block.message.block.tree_hash_root();

    info!(%peer, %slot, %root, "Received BlocksByRoot response");

    // Clean up tracking (success!)
    if server.pending_requests.remove(&root).is_some() {
        info!(%root, "Block fetch succeeded");
        server.request_id_map.retain(|_, r| *r != root);
    }

    server.blockchain.notify_new_block(block).await;
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
    let mut roots = super::RequestedBlockRoots::empty();
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
        let _ = retry_tx.send(root);
    });
}
