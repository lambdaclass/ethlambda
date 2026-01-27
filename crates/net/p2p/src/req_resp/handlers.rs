use ethlambda_storage::Store;
use libp2p::{PeerId, request_response};
use rand::seq::SliceRandom;
use tracing::{debug, error, info, warn};

use ethlambda_types::block::SignedBlockWithAttestation;

use super::{BlocksByRootRequest, Request, Response, ResponsePayload, ResponseResult, Status};
use crate::P2PServer;

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
    let num_roots = request.len();
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
    info!(%peer, %slot, "Received BlocksByRoot response chunk");
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
pub async fn fetch_block_from_peer(
    server: &mut P2PServer,
    root: ethlambda_types::primitives::H256,
) {
    if server.connected_peers.is_empty() {
        warn!(%root, "Cannot fetch block: no connected peers");
        return;
    }

    // Select random peer
    let peers: Vec<_> = server.connected_peers.iter().copied().collect();
    let peer = match peers.choose(&mut rand::thread_rng()) {
        Some(&p) => p,
        None => {
            warn!(%root, "Failed to select random peer");
            return;
        }
    };

    // Create BlocksByRoot request with single root
    let mut request = BlocksByRootRequest::empty();
    if let Err(err) = request.push(root) {
        error!(%root, ?err, "Failed to create BlocksByRoot request");
        return;
    }

    info!(%peer, %root, "Sending BlocksByRoot request for missing block");
    server
        .swarm
        .behaviour_mut()
        .req_resp
        .send_request(&peer, Request::BlocksByRoot(request));
}
