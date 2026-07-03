use std::collections::HashSet;

use ethlambda_storage::Store;
use libp2p::{PeerId, request_response};
use rand::seq::SliceRandom;
use spawned_concurrency::tasks::{Context, send_after};
use std::time::Duration;
use tracing::{debug, error, info, warn};

use ethlambda_types::checkpoint::Checkpoint;
use ethlambda_types::primitives::HashTreeRoot as _;
use ethlambda_types::{block::SignedBlock, primitives::H256};

use super::{
    BLOCKS_BY_RANGE_PROTOCOL_V1, BLOCKS_BY_ROOT_PROTOCOL_V1, BlocksByRangeRequest,
    BlocksByRootRequest, MAX_REQUEST_BLOCKS, Request, Response, ResponsePayload, Status,
    messages::{ResponseCode, error_message},
};
use crate::{
    BACKOFF_MULTIPLIER, INITIAL_BACKOFF_MS, MAX_FETCH_RETRIES, MAX_SYNC_RANGE, P2PServer,
    PendingRequest, PendingRequestKind, RangeSyncState, p2p_protocol,
    req_resp::RequestedBlockRoots,
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
                        ResponsePayload::Blocks(blocks) => {
                            info!(kind = "blocks_response", peer_count, "P2P message received");

                            match server.outbound_requests.remove(&request_id) {
                                Some(PendingRequestKind::Range {
                                    start_slot,
                                    end_slot,
                                }) => {
                                    handle_blocks_by_range_response(
                                        server, blocks, peer, start_slot, end_slot,
                                    )
                                    .await;
                                }
                                Some(PendingRequestKind::Root(root)) => {
                                    handle_blocks_by_root_response(
                                        server, blocks, peer, request_id, root, ctx,
                                    )
                                    .await;
                                }
                                None => {
                                    warn!(%peer, ?request_id, "Received blocks response for unknown request_id");
                                }
                            }
                        }
                    },
                    Response::Error { code, message } => {
                        let error_str = String::from_utf8_lossy(&message);
                        warn!(%peer, ?code, %error_str, "Received error response");

                        match server.outbound_requests.remove(&request_id) {
                            Some(PendingRequestKind::Range { .. }) => {
                                fail_range_request(server, &peer);
                            }
                            Some(request @ PendingRequestKind::Root(_)) => {
                                server.outbound_requests.insert(request_id, request);
                            }
                            None => {}
                        }
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
            match server.outbound_requests.remove(&request_id) {
                Some(PendingRequestKind::Root(root)) => {
                    handle_fetch_failure(server, root, peer, ctx).await;
                }
                Some(PendingRequestKind::Range {
                    start_slot,
                    end_slot,
                }) => {
                    fail_range_request(server, &peer);
                    warn!(
                        %peer,
                        start_slot,
                        end_slot,
                        "BlocksByRange request failed; retry is disabled"
                    );
                }
                None => {}
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
    warn!(
        %peer,
        peer_head_slot = status.head.slot,
        local_head_slot = our_head_slot,
        slot_gap = gap,
        "Peer status head is ahead of local head"
    );

    let start_slot = our_head_slot.saturating_add(1);
    let end_exclusive = start_slot.saturating_add(gap.min(MAX_SYNC_RANGE));

    match &mut server.range_sync_state {
        Some(state) => state.merge_peer(peer, status.head.slot, end_exclusive),
        None => {
            server.range_sync_state = Some(RangeSyncState::new(
                start_slot..end_exclusive,
                peer,
                status.head.slot,
            ));
        }
    }

    request_next_range_batch(server).await;
    info!(%peer, start_slot, gap, "Long-range sync: using BlocksByRange");
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

    let response = Response::success(ResponsePayload::Blocks(blocks));
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
        "Received BlocksByRange request"
    );

    if request.count == 0 || request.count > MAX_REQUEST_BLOCKS {
        let response = Response::error(
            ResponseCode::INVALID_REQUEST,
            error_message("invalid BlocksByRange request"),
        );
        server.swarm_handle.send_response(channel, response);
        return;
    }

    let blocks = canonical_blocks_by_range(&server.store, request.start_slot, request.count);

    info!(
        %peer,
        start_slot = request.start_slot,
        count = request.count,
        found = blocks.len(),
        "Responding to BlocksByRange request"
    );

    let response = Response::success(ResponsePayload::Blocks(blocks));
    server.swarm_handle.send_response(channel, response);
}

fn canonical_blocks_by_range(store: &Store, start_slot: u64, count: u64) -> Vec<SignedBlock> {
    if count == 0 {
        return Vec::new();
    }

    let Some(end_slot) = count
        .checked_sub(1)
        .and_then(|last_offset| start_slot.checked_add(last_offset))
    else {
        return Vec::new();
    };

    (start_slot..=end_slot)
        .filter_map(|slot| {
            let root = store.get_block_root_by_slot(slot)?;
            store.get_signed_block(&root)
        })
        .collect()
}

async fn handle_blocks_by_root_response(
    server: &mut P2PServer,
    blocks: Vec<SignedBlock>,
    peer: PeerId,
    request_id: request_response::OutboundRequestId,
    requested_root: H256,
    ctx: &Context<P2PServer>,
) {
    info!(%peer, count = blocks.len(), "Received BlocksByRoot response");

    if blocks.is_empty() {
        // Re-insert so failure handling can find it
        server
            .outbound_requests
            .insert(request_id, PendingRequestKind::Root(requested_root));
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
        server.pending_root_requests.remove(&root);

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
    start_slot: u64,
    end_slot: u64,
) {
    info!(%peer, count = blocks.len(), "Received BlocksByRange response");

    if blocks.is_empty() {
        fail_range_request(server, &peer);
        warn!(%peer, start_slot, end_slot, "Received empty BlocksByRange response");
        return;
    }

    let Some(ref blockchain) = server.blockchain else {
        server.range_sync_state = None;
        warn!(%peer, "No blockchain handler available");
        return;
    };

    for block in blocks {
        let slot = block.message.slot;

        if slot < start_slot || slot > end_slot {
            warn!(%peer, %slot, start_slot, end_slot, "Received block outside requested range");
            continue;
        }

        let block_root = block.message.hash_tree_root();
        if let Err(err) = blockchain.new_block(block) {
            error!(
                %err, %slot, %peer,
                block_root = %ethlambda_types::ShortRoot(&block_root.0),
                "Failed to forward range-fetched block to blockchain"
            );
        }
    }

    if let Some(state) = &mut server.range_sync_state {
        state.complete_batch(end_slot);
        if state.current_range.is_empty() || state.peer_set.is_empty() {
            server.range_sync_state = None;
            return;
        }
    }

    request_next_range_batch(server).await;
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
    let failed = server
        .pending_root_requests
        .get(&root)
        .map(|p| &p.failed_peers);
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
        if let Some(pending) = server.pending_root_requests.get_mut(&root) {
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
        .pending_root_requests
        .entry(root)
        .or_insert(PendingRequest {
            attempts: 1,
            failed_peers: HashSet::new(),
        });

    // Map request_id to root for failure handling
    server
        .outbound_requests
        .insert(request_id, PendingRequestKind::Root(root));

    true
}

async fn request_next_range_batch(server: &mut P2PServer) -> bool {
    let Some((peer, batch)) = server
        .range_sync_state
        .as_ref()
        .and_then(RangeSyncState::next_batch)
    else {
        return true;
    };

    let request = BlocksByRangeRequest {
        start_slot: batch.start,
        count: batch.end - batch.start,
    };
    let count = request.count;

    info!(
        %peer,
        start_slot = batch.start,
        count,
        total_end_slot = server
            .range_sync_state
            .as_ref()
            .map_or(batch.end, |state| state.current_range.end)
            .saturating_sub(1),
        "Sending BlocksByRange request (single batch)"
    );

    let Some(request_id) = server
        .swarm_handle
        .send_request(
            peer,
            Request::BlocksByRange(request),
            libp2p::StreamProtocol::new(BLOCKS_BY_RANGE_PROTOCOL_V1),
        )
        .await
    else {
        warn!(
            %peer,
            start_slot = batch.start,
            count,
            "Failed to send BlocksByRange request"
        );
        fail_range_request(server, &peer);
        return false;
    };

    if let Some(state) = &mut server.range_sync_state {
        state.in_flight = true;
    }

    server.outbound_requests.insert(
        request_id,
        PendingRequestKind::Range {
            start_slot: batch.start,
            end_slot: batch.end - 1,
        },
    );

    true
}

fn fail_range_request(server: &mut P2PServer, peer: &PeerId) {
    let should_clear = if let Some(state) = &mut server.range_sync_state {
        state.fail_peer(peer);
        state.peer_set.is_empty()
    } else {
        false
    };

    if should_clear {
        server.range_sync_state = None;
    }
}

async fn handle_fetch_failure(
    server: &mut P2PServer,
    root: H256,
    peer: PeerId,
    ctx: &Context<P2PServer>,
) {
    let Some(pending) = server.pending_root_requests.get_mut(&root) else {
        return;
    };

    pending.failed_peers.insert(peer);

    if pending.attempts >= MAX_FETCH_RETRIES {
        error!(%root, %peer, attempts=%pending.attempts,
               "Block fetch failed after max retries, giving up");
        server.pending_root_requests.remove(&root);
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
        block::{Block, BlockBody, MultiMessageAggregate},
        state::State,
    };
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
            proof: MultiMessageAggregate::default(),
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

        let blocks = canonical_blocks_by_range(&store, 1, 4);
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
