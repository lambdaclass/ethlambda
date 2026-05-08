use std::collections::{HashMap, HashSet};

use ethlambda_storage::Store;
use libp2p::{PeerId, request_response};
use rand::seq::SliceRandom;
use spawned_concurrency::tasks::{Context, send_after};
use std::time::Duration;
use tracing::{debug, error, info, warn};

use ethlambda_types::checkpoint::Checkpoint;
use ethlambda_types::primitives::HashTreeRoot as _;
use ethlambda_types::{block::SignedBlock, primitives::H256};

use super::messages::{ResponseCode, error_message};
use super::{
    BLOCKS_BY_RANGE_PROTOCOL_V1, BLOCKS_BY_ROOT_PROTOCOL_V1, BlocksByRangeRequest,
    BlocksByRootRequest, MAX_REQUEST_BLOCKS, Request, Response, ResponsePayload, Status,
};
use crate::LONG_RANGE_SYNC_THRESHOLD;
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
            } => {
                let peer_count = server.connected_peers.len();
                match request {
                    Request::Status(status) => {
                        info!(kind = "status_request", peer_count, "P2P message received");
                        handle_status_request(server, status, channel, peer).await;
                    }
                    Request::BlocksByRoot(request) => {
                        info!(
                            kind = "blocks_by_root_request",
                            peer_count, "P2P message received"
                        );
                        handle_blocks_by_root_request(server, request, channel, peer).await;
                    }
                    Request::BlocksByRange(request) => {
                        info!(
                            kind = "blocks_by_range_request",
                            peer_count, "P2P message received"
                        );
                        handle_blocks_by_range_request(server, request, channel, peer).await;
                    }
                }
            }
            request_response::Message::Response {
                request_id,
                response,
            } => {
                let peer_count = server.connected_peers.len();
                match response {
                    Response::Success { payload } => match payload {
                        ResponsePayload::Status(status) => {
                            info!(kind = "status_response", peer_count, "P2P message received");
                            handle_status_response(server, status, peer).await;
                        }
                        ResponsePayload::BlocksByRoot(blocks) => {
                            info!(
                                kind = "blocks_by_root_response",
                                peer_count, "P2P message received"
                            );
                            handle_blocks_by_root_response(server, blocks, peer, request_id, ctx)
                                .await;
                        }
                        ResponsePayload::BlocksByRange(blocks) => {
                            info!(
                                kind = "blocks_by_range_response",
                                peer_count,
                                count = blocks.len(),
                                "P2P message received"
                            );
                            handle_blocks_by_range_response(server, blocks, peer).await;
                        }
                    },
                    Response::Error { code, message } => {
                        let error_str = String::from_utf8_lossy(&message);
                        warn!(%peer, ?code, %error_str, "Received error response");
                    }
                }
            }
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

async fn handle_status_response(server: &mut P2PServer, status: Status, peer: PeerId) {
    info!(finalized_slot=%status.finalized.slot, head_slot=%status.head.slot, "Received status response from peer {peer}");

    let our_head_slot = server.store.head_slot();
    if status.head.slot <= our_head_slot {
        return;
    }
    let gap = status.head.slot - our_head_slot;

    if gap > LONG_RANGE_SYNC_THRESHOLD {
        // Long-range sync: request blocks by range to efficiently fill large gap.
        let start_slot = our_head_slot.saturating_add(1);
        info!(%peer, start_slot, gap, "Long-range sync: using BlocksByRange");
        request_blocks_by_range_from_peer(server, peer, start_slot, gap).await;
    } else {
        // Short-range sync: fetch individual blocks by root, relying on gossip to fill any small gaps.
        info!(%peer, gap, "Short gap, relying on gossip / FetchBlock for missing slots");
    }
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

async fn handle_blocks_by_range_request(
    server: &mut P2PServer,
    request: BlocksByRangeRequest,
    channel: request_response::ResponseChannel<Response>,
    peer: PeerId,
) {
    info!(
        %peer,
        start_slot = request.start_slot,
        count = request.count,
        step = request.step,
        "Received BlocksByRange request"
    );

    if request.step == 0 || request.count == 0 || request.count > MAX_REQUEST_BLOCKS {
        let response = Response::error(
            ResponseCode::INVALID_REQUEST,
            error_message("invalid BlocksByRange request"),
        );
        server.swarm_handle.send_response(channel, response);
        return;
    }

    let blocks = canonical_blocks_by_range(
        &server.store,
        request.start_slot,
        request.count,
        request.step,
    );

    info!(
        %peer,
        start_slot = request.start_slot,
        count = request.count,
        step = request.step,
        found = blocks.len(),
        "Responding to BlocksByRange request"
    );

    let response = Response::success(ResponsePayload::BlocksByRange(blocks));
    server.swarm_handle.send_response(channel, response);
}

fn canonical_blocks_by_range(
    store: &Store,
    start_slot: u64,
    count: u64,
    step: u64,
) -> Vec<SignedBlock> {
    if count == 0 {
        return Vec::new();
    }

    let Some(last_offset) = count
        .checked_sub(1)
        .and_then(|value| value.checked_mul(step))
    else {
        return Vec::new();
    };
    let Some(end_slot) = start_slot.checked_add(last_offset) else {
        return Vec::new();
    };

    let mut roots_by_slot = HashMap::new();
    let mut current_root = store.head();

    while !current_root.is_zero() {
        let Some(header) = store.get_block_header(&current_root) else {
            break;
        };

        if header.slot < start_slot {
            break;
        }

        if header.slot <= end_slot && (header.slot - start_slot) % step == 0 {
            roots_by_slot.insert(header.slot, current_root);
        }

        current_root = header.parent_root;
    }

    (0..count)
        .filter_map(|index| {
            let slot = start_slot.checked_add(index.checked_mul(step)?)?;
            let root = roots_by_slot.get(&slot)?;
            store.get_signed_block(root)
        })
        .collect()
}

async fn handle_blocks_by_root_response(
    server: &mut P2PServer,
    blocks: Vec<SignedBlock>,
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
        let root = block.message.hash_tree_root();

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

async fn handle_blocks_by_range_response(
    server: &mut P2PServer,
    blocks: Vec<SignedBlock>,
    peer: PeerId,
) {
    info!(%peer, count = blocks.len(), "Received BlocksByRange response");

    if blocks.is_empty() {
        warn!(%peer, "Received empty BlocksByRange response");
        return;
    }

    if let Some(ref blockchain) = server.blockchain {
        for block in blocks {
            let block_root = block.message.hash_tree_root();
            let slot = block.message.slot;
            let _ = blockchain.new_block(block).inspect_err(|err| {
                error!(
                    %peer,
                    %slot,
                    block_root = %ethlambda_types::ShortRoot(&block_root.0),
                    %err,
                    "Failed to forward range-fetched block to blockchain"
                )
            });
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

async fn request_blocks_by_range_from_peer(
    server: &mut P2PServer,
    peer: PeerId,
    start_slot: u64,
    count: u64,
) -> bool {
    if count == 0 {
        return true;
    }

    let mut remaining = count;
    let mut next_slot = start_slot;

    while remaining > 0 {
        let batch_count = remaining.min(MAX_REQUEST_BLOCKS);
        let request = BlocksByRangeRequest {
            start_slot: next_slot,
            count: batch_count,
            step: 1,
        };

        info!(
            %peer,
            start_slot = next_slot,
            count = batch_count,
            "Sending BlocksByRange request"
        );

        if server
            .swarm_handle
            .send_request(
                peer,
                Request::BlocksByRange(request),
                libp2p::StreamProtocol::new(BLOCKS_BY_RANGE_PROTOCOL_V1),
            )
            .await
            .is_none()
        {
            warn!(
                %peer,
                start_slot = next_slot,
                count = batch_count,
                "Failed to send BlocksByRange request (swarm adapter closed)"
            );
            return false;
        }

        remaining -= batch_count;
        next_slot = next_slot.saturating_add(batch_count);
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_storage::{ForkCheckpoints, backend::InMemoryBackend};
    use ethlambda_types::{
        attestation::XmssSignature,
        block::{Block, BlockBody, BlockSignatures},
        signature::SIGNATURE_SIZE,
        state::State,
    };
    use libssz_types::SszList;
    use std::sync::Arc;

    fn signed_block(slot: u64, parent_root: H256) -> SignedBlock {
        SignedBlock {
            message: Block {
                slot,
                proposer_index: 0,
                parent_root,
                state_root: H256::ZERO,
                body: BlockBody::default(),
            },
            signature: BlockSignatures {
                attestation_signatures: SszList::new(),
                proposer_signature: XmssSignature::try_from(vec![0u8; SIGNATURE_SIZE]).unwrap(),
            },
        }
    }

    #[test]
    fn blocks_by_range_returns_canonical_blocks_in_requested_order() {
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::from_anchor_state(backend, State::from_genesis(0, vec![]));

        let block_1 = signed_block(1, store.head());
        let root_1 = block_1.message.hash_tree_root();
        store.insert_signed_block(root_1, block_1);

        let block_2 = signed_block(2, root_1);
        let root_2 = block_2.message.hash_tree_root();
        store.insert_signed_block(root_2, block_2);

        let side_block_3 = signed_block(3, root_1);
        let side_root_3 = side_block_3.message.hash_tree_root();
        store.insert_signed_block(side_root_3, side_block_3);

        let block_4 = signed_block(4, root_2);
        let root_4 = block_4.message.hash_tree_root();
        store.insert_signed_block(root_4, block_4);
        store.update_checkpoints(ForkCheckpoints::head_only(root_4));

        let blocks = canonical_blocks_by_range(&store, 1, 4, 1);
        let slots: Vec<_> = blocks.iter().map(|block| block.message.slot).collect();
        let roots: Vec<_> = blocks
            .iter()
            .map(|block| block.message.hash_tree_root())
            .collect();

        assert_eq!(slots, vec![1, 2, 4]);
        assert_eq!(roots, vec![root_1, root_2, root_4]);
        assert!(!roots.contains(&side_root_3));
    }
}
