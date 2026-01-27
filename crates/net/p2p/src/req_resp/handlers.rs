use ethlambda_blockchain::BlockChain;
use ethlambda_storage::Store;
use libp2p::{PeerId, request_response};
use tracing::{info, trace, warn};

use super::{
    BlocksByRootRequest, BlocksByRootResponse, Request, Response, ResponsePayload, ResponseResult,
    Status,
};
use crate::Behaviour;

pub async fn handle_req_resp_message(
    message: request_response::Message<Request, Response>,
    peer: PeerId,
    swarm: &mut libp2p::Swarm<Behaviour>,
    blockchain: &mut BlockChain,
    store: &Store,
) {
    match message {
        request_response::Message::Request {
            request, channel, ..
        } => match request {
            Request::Status(status) => {
                handle_status_request(swarm, status, channel, peer, store).await;
            }
            Request::BlocksByRoot(request) => {
                handle_blocks_by_root_request(swarm, request, channel, peer).await;
            }
        },
        request_response::Message::Response { response, .. } => match response.payload {
            ResponsePayload::Status(status) => {
                handle_status_response(status, peer).await;
            }
            ResponsePayload::BlocksByRoot(blocks) => {
                handle_blocks_by_root_response(blocks, blockchain, peer).await;
            }
        },
    }
}

async fn handle_status_request(
    swarm: &mut libp2p::Swarm<Behaviour>,
    request: Status,
    channel: request_response::ResponseChannel<Response>,
    peer: PeerId,
    store: &Store,
) {
    info!(finalized_slot=%request.finalized.slot, head_slot=%request.head.slot, "Received status request from peer {peer}");
    let our_status = build_status(store);
    swarm
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
    swarm: &mut libp2p::Swarm<Behaviour>,
    request: BlocksByRootRequest,
    channel: request_response::ResponseChannel<Response>,
    peer: PeerId,
) {
    let num_roots = request.len();
    info!(%peer, num_roots, "Received BlocksByRoot request");

    // TODO: Implement signature storage to serve BlocksByRoot requests
    // For now, return empty response
    let blocks: Vec<_> = vec![];
    let num_blocks = blocks.len();
    let response = BlocksByRootResponse::new(blocks).expect("within limit");

    info!(%peer, num_roots, num_blocks, "Sending BlocksByRoot response (no signed blocks available)");
    let _ = swarm
        .behaviour_mut()
        .req_resp
        .send_response(
            channel,
            Response::new(
                ResponseResult::Success,
                ResponsePayload::BlocksByRoot(response),
            ),
        )
        .inspect_err(|_| warn!(%peer, "Failed to send BlocksByRoot response"));
}

async fn handle_blocks_by_root_response(
    response: BlocksByRootResponse,
    blockchain: &mut BlockChain,
    peer: PeerId,
) {
    let num_blocks = response.len();
    info!(%peer, num_blocks, "Received BlocksByRoot response");

    for signed_block in response.iter() {
        let slot = signed_block.message.block.slot;
        trace!(%peer, %slot, "Processing block from BlocksByRoot response");
        blockchain.notify_new_block(signed_block.clone()).await;
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
