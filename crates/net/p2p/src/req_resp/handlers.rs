use ethlambda_blockchain::BlockChain;
use ethlambda_storage::Store;
use libp2p::{PeerId, request_response};
use tracing::{info, warn};

use ethlambda_types::block::SignedBlockWithAttestation;

use super::{BlocksByRootRequest, Request, Response, ResponsePayload, ResponseResult, Status};
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
    _swarm: &mut libp2p::Swarm<Behaviour>,
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
    block: SignedBlockWithAttestation,
    blockchain: &mut BlockChain,
    peer: PeerId,
) {
    let slot = block.message.block.slot;
    info!(%peer, %slot, "Received BlocksByRoot response chunk");
    blockchain.notify_new_block(block).await;
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
