use std::collections::{HashMap, HashSet};

use ethlambda_network_api::BlockSource;
use ethlambda_storage::Store;
use libp2p::{PeerId, request_response};
use rand::seq::SliceRandom;
use spawned_concurrency::tasks::{Context, send_after};
use std::time::Duration;
use tracing::{debug, error, trace, warn};

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
    PendingRequest, PendingRequestKind, ROOT_FETCH_WATCHDOG, RangeSyncState, p2p_protocol,
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
                        trace!(kind = "status_request", peer_count, "P2P message received");
                        handle_status_request(server, status, channel, peer).await;
                    }
                    Request::BlocksByRoot(request) => {
                        trace!(
                            kind = "blocks_by_root_request",
                            peer_count, "P2P message received"
                        );
                        handle_blocks_by_root_request(server, request, channel, peer).await;
                    }
                    Request::BlocksByRange(request) => {
                        trace!(
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
                            trace!(kind = "status_response", peer_count, "P2P message received");
                            handle_status_response(server, status, peer).await;
                        }
                        ResponsePayload::Blocks(blocks) => {
                            trace!(kind = "blocks_response", peer_count, "P2P message received");

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
                                    handle_blocks_by_root_response(server, blocks, peer, root, ctx)
                                        .await;
                                }
                                None => {
                                    debug!(%peer, ?request_id, "Received blocks response for unknown request_id");
                                }
                            }
                        }
                    },
                    Response::Error { code, message } => {
                        let error_str = String::from_utf8_lossy(&message);
                        debug!(%peer, ?code, %error_str, "Received error response");

                        match server.outbound_requests.remove(&request_id) {
                            Some(PendingRequestKind::Range { .. }) => {
                                fail_range_request(server, &peer);
                            }
                            Some(PendingRequestKind::Root(root)) => {
                                // An error response completes the exchange, so
                                // no `OutboundFailure` follows to retire the
                                // root. Fail it here or it stays pending
                                // forever and deduplicates every later fetch.
                                handle_fetch_failure(server, root, peer, ctx).await;
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
            debug!(%peer, ?request_id, %error, "Outbound request failed");

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
                    debug!(
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
            debug!(%peer, ?request_id, %error, "Inbound request failed");
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
    trace!(finalized_slot=%request.finalized.slot, head_slot=%request.head.slot, "Received status request from peer {peer}");
    let our_status = build_status(&server.store);
    let response = Response::success(ResponsePayload::Status(our_status));
    server.swarm_handle.send_response(channel, response);
}

async fn handle_status_response(server: &mut P2PServer, status: Status, peer: PeerId) {
    trace!(finalized_slot=%status.finalized.slot, head_slot=%status.head.slot, "Received status response from peer {peer}");

    let our_head_slot = server.store.head_slot();
    if status.head.slot <= our_head_slot {
        return;
    }
    let gap = status.head.slot - our_head_slot;
    debug!(
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
    trace!(%peer, start_slot, gap, "Long-range sync: using BlocksByRange");
}

async fn handle_blocks_by_root_request(
    server: &mut P2PServer,
    request: BlocksByRootRequest,
    channel: request_response::ResponseChannel<Response>,
    peer: PeerId,
) {
    let num_roots = request.roots.len();
    trace!(%peer, num_roots, "Received BlocksByRoot request");

    let mut blocks = Vec::new();
    for root in request.roots.iter() {
        if let Ok(Some(signed_block)) = server.store.get_signed_block(root) {
            blocks.push(signed_block);
        }
        // Missing blocks are silently skipped (per spec)
    }

    let found = blocks.len();
    trace!(%peer, num_roots, found, "Responding to BlocksByRoot request");

    let response = Response::success(ResponsePayload::Blocks(blocks));
    server.swarm_handle.send_response(channel, response);
}

async fn handle_blocks_by_range_request(
    server: &mut P2PServer,
    request: BlocksByRangeRequest,
    channel: request_response::ResponseChannel<Response>,
    peer: PeerId,
) {
    trace!(
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

    trace!(
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

    store
        .get_signed_blocks_by_slot_range(start_slot, end_slot)
        .inspect_err(|err| {
            warn!(
                start_slot,
                end_slot,
                ?err,
                "Failed to get signed blocks by slot range"
            )
        })
        .unwrap_or_default()
}

/// Pick the block that answers a `BlocksByRoot` request out of the response.
///
/// Requests carry a single root, so at most one block can answer one. Anything
/// else the peer sent is unsolicited and dropped.
fn matching_block(blocks: Vec<SignedBlock>, requested_root: H256) -> Option<SignedBlock> {
    blocks
        .into_iter()
        .find(|block| block.message.hash_tree_root() == requested_root)
}

async fn handle_blocks_by_root_response(
    server: &mut P2PServer,
    blocks: Vec<SignedBlock>,
    peer: PeerId,
    requested_root: H256,
    ctx: &Context<P2PServer>,
) {
    let received = blocks.len();
    trace!(%peer, count = received, "Received BlocksByRoot response");

    // A response that answers nothing is a failed attempt, whether it was empty
    // or carried only blocks we never asked for. Treating the latter as a
    // no-op would leave the root pending forever, and the deduplication in the
    // `FetchBlock` handler would swallow every later attempt to fetch it.
    let Some(block) = matching_block(blocks, requested_root) else {
        debug!(
            %peer,
            received,
            expected_root = %ethlambda_types::ShortRoot(&requested_root.0),
            "BlocksByRoot response carried no matching block"
        );
        handle_fetch_failure(server, requested_root, peer, ctx).await;
        return;
    };

    // Clean up tracking for this root
    server.pending_root_requests.remove(&requested_root);

    if let Some(ref blockchain) = server.blockchain {
        let _ = blockchain
            .new_block(block, BlockSource::Sync)
            .inspect_err(|err| error!(%err, "Failed to forward fetched block to blockchain"));
    }
}

async fn handle_blocks_by_range_response(
    server: &mut P2PServer,
    blocks: Vec<SignedBlock>,
    peer: PeerId,
    start_slot: u64,
    end_slot: u64,
) {
    trace!(%peer, count = blocks.len(), "Received BlocksByRange response");

    if blocks.is_empty() {
        fail_range_request(server, &peer);
        debug!(%peer, start_slot, end_slot, "Received empty BlocksByRange response");
        return;
    }

    let Some(ref blockchain) = server.blockchain else {
        server.range_sync_state = None;
        debug!(%peer, "No blockchain handler available");
        return;
    };

    for block in blocks {
        let slot = block.message.slot;

        if slot < start_slot || slot > end_slot {
            debug!(%peer, %slot, start_slot, end_slot, "Received block outside requested range");
            continue;
        }

        let block_root = block.message.hash_tree_root();
        if let Err(err) = blockchain.new_block(block, BlockSource::Sync) {
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
    let finalized = store.latest_finalized().expect("finalized block exists");
    let head_root = store.head().expect("head block exists");
    let head_slot = store
        .get_block_header(&head_root)
        .expect("head block exists")
        .unwrap()
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
pub async fn fetch_block_from_peer(
    server: &mut P2PServer,
    root: H256,
    ctx: &Context<P2PServer>,
) -> bool {
    if server.connected_peers.is_empty() {
        debug!(%root, "Cannot fetch block: no connected peers");
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
        debug!(%root, "All peers failed for this block, retrying with full peer set");
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
            debug!(%root, "Failed to select random peer");
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
    trace!(%peer, %root, excluded, "Sending BlocksByRoot request for missing block");
    let Some(request_id) = server
        .swarm_handle
        .send_request(
            peer,
            Request::BlocksByRoot(request),
            libp2p::StreamProtocol::new(BLOCKS_BY_ROOT_PROTOCOL_V1),
        )
        .await
    else {
        debug!(%root, "Failed to send BlocksByRoot request (swarm adapter closed)");
        return false;
    };

    // Track the request if not already tracked (new request)
    let attempt = server
        .pending_root_requests
        .entry(root)
        .or_insert(PendingRequest {
            attempts: 1,
            failed_peers: HashSet::new(),
        })
        .attempts;

    // Map request_id to root for failure handling
    server
        .outbound_requests
        .insert(request_id, PendingRequestKind::Root(root));

    // Every other exit from this attempt runs off a libp2p event, and libp2p
    // does not always emit one, so arm a backstop that fails the attempt if
    // nothing else does.
    send_after(
        ROOT_FETCH_WATCHDOG,
        ctx.clone(),
        p2p_protocol::BlockFetchTimeout {
            root,
            peer,
            request_id,
            attempt,
        },
    );

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

    trace!(
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
        debug!(
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

/// What follows a failed attempt to fetch a block by root.
#[derive(Debug, PartialEq, Eq)]
enum FetchFailure {
    /// Wait `backoff`, then try another peer.
    Retry { attempts: u32, backoff: Duration },
    /// Out of attempts. The root is no longer pending.
    GaveUp { attempts: u32 },
    /// Nothing was pending for this root, so the failure is late or duplicate.
    NotPending,
}

/// Charge a failed attempt to the pending table and decide what follows.
///
/// Split out of [`handle_fetch_failure`] so the retry accounting is testable
/// without a live actor.
fn record_fetch_failure(
    pending_root_requests: &mut HashMap<H256, PendingRequest>,
    root: H256,
    peer: PeerId,
) -> FetchFailure {
    let Some(pending) = pending_root_requests.get_mut(&root) else {
        return FetchFailure::NotPending;
    };

    pending.failed_peers.insert(peer);
    let attempts = pending.attempts;

    if attempts >= MAX_FETCH_RETRIES {
        pending_root_requests.remove(&root);
        return FetchFailure::GaveUp { attempts };
    }

    pending.attempts += 1;
    let backoff_ms = INITIAL_BACKOFF_MS * BACKOFF_MULTIPLIER.pow(attempts - 1);

    FetchFailure::Retry {
        attempts,
        backoff: Duration::from_millis(backoff_ms),
    }
}

/// Retire one failed attempt at fetching `root`.
///
/// Every path that ends an attempt must come through here: a root left in
/// `pending_root_requests` is deduplicated out of every later fetch, so a
/// silent exit loses that block for the life of the process.
pub(crate) async fn handle_fetch_failure(
    server: &mut P2PServer,
    root: H256,
    peer: PeerId,
    ctx: &Context<P2PServer>,
) {
    match record_fetch_failure(&mut server.pending_root_requests, root, peer) {
        FetchFailure::NotPending => {}
        FetchFailure::GaveUp { attempts } => {
            error!(%root, %peer, attempts, "Block fetch failed after max retries, giving up");
        }
        FetchFailure::Retry { attempts, backoff } => {
            debug!(%root, %peer, attempts, ?backoff, "Block fetch failed, scheduling retry");
            send_after(backoff, ctx.clone(), p2p_protocol::RetryBlockFetch { root });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_storage::{ForkCheckpoints, backend::InMemoryBackend};
    use ethlambda_types::constants::DEFAULT_MILLISECONDS_PER_SLOT;
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
        let mut store = Store::from_anchor_state(
            backend,
            State::from_genesis(0, vec![]),
            DEFAULT_MILLISECONDS_PER_SLOT,
        );

        let block_1 = signed_block(1, store.head().expect("head block exists"));
        let root_1 = block_1.message.hash_tree_root();
        store
            .insert_signed_block(root_1, block_1)
            .expect("insert test block should succeed");

        let block_2 = signed_block(2, root_1);
        let root_2 = block_2.message.hash_tree_root();
        store
            .insert_signed_block(root_2, block_2)
            .expect("insert test block should succeed");

        let side_block_3 = signed_block(3, root_1);
        let side_root_3 = side_block_3.message.hash_tree_root();
        store
            .insert_signed_block(side_root_3, side_block_3)
            .expect("insert test block should succeed");

        let block_4 = signed_block(4, root_2);
        let root_4 = block_4.message.hash_tree_root();
        store
            .insert_signed_block(root_4, block_4)
            .expect("insert test block should succeed");
        store
            .update_checkpoints(ForkCheckpoints::head_only(root_4))
            .expect("update_checkpoints should succeed");

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

    fn pending_root(root: H256, attempts: u32) -> HashMap<H256, PendingRequest> {
        HashMap::from([(
            root,
            PendingRequest {
                attempts,
                failed_peers: HashSet::new(),
            },
        )])
    }

    /// A response that answers nothing must not look like a success. Returning
    /// `Some` for an unrequested block would leave the requested root pending
    /// forever, and the `FetchBlock` deduplication would then swallow every
    /// later attempt to fetch it.
    #[test]
    fn matching_block_rejects_a_response_that_answers_a_different_root() {
        let wanted = signed_block(1, H256::ZERO);
        let wanted_root = wanted.message.hash_tree_root();
        let other = signed_block(2, H256::ZERO);

        assert!(matching_block(vec![other.clone()], wanted_root).is_none());
        assert!(matching_block(Vec::new(), wanted_root).is_none());

        let found = matching_block(vec![other, wanted], wanted_root)
            .expect("the requested block answers the request");
        assert_eq!(found.message.hash_tree_root(), wanted_root);
    }

    /// A failure for a root nobody is waiting on must stay a no-op, so a late
    /// or duplicate event cannot resurrect a root that already succeeded.
    #[test]
    fn record_fetch_failure_ignores_an_untracked_root() {
        let mut pending = HashMap::new();
        let outcome = record_fetch_failure(&mut pending, H256::ZERO, PeerId::random());

        assert_eq!(outcome, FetchFailure::NotPending);
        assert!(pending.is_empty());
    }

    #[test]
    fn record_fetch_failure_backs_off_and_excludes_the_failing_peer() {
        let root = H256::ZERO;
        let peer = PeerId::random();
        let mut pending = pending_root(root, 1);

        let first = record_fetch_failure(&mut pending, root, peer);
        assert_eq!(
            first,
            FetchFailure::Retry {
                attempts: 1,
                backoff: Duration::from_millis(INITIAL_BACKOFF_MS),
            }
        );

        let second = record_fetch_failure(&mut pending, root, PeerId::random());
        assert_eq!(
            second,
            FetchFailure::Retry {
                attempts: 2,
                backoff: Duration::from_millis(INITIAL_BACKOFF_MS * BACKOFF_MULTIPLIER),
            }
        );

        let entry = pending.get(&root).expect("root is still pending");
        assert_eq!(entry.attempts, 3);
        assert!(entry.failed_peers.contains(&peer));
    }

    /// Giving up has to clear the entry: leaving it behind is the same
    /// permanent lock as never failing the attempt at all.
    #[test]
    fn record_fetch_failure_clears_the_root_when_it_gives_up() {
        let root = H256::ZERO;
        let mut pending = pending_root(root, MAX_FETCH_RETRIES);

        let outcome = record_fetch_failure(&mut pending, root, PeerId::random());

        assert_eq!(
            outcome,
            FetchFailure::GaveUp {
                attempts: MAX_FETCH_RETRIES
            }
        );
        assert!(!pending.contains_key(&root));
    }

    /// The watchdog is a backstop for requests libp2p never reports on, so it
    /// must outlast libp2p's own timeout. Inverting these makes it fire on
    /// healthy-but-slow requests and hides the real failure path.
    #[test]
    fn the_fetch_watchdog_outlasts_the_libp2p_request_timeout() {
        assert!(ROOT_FETCH_WATCHDOG > crate::REQ_RESP_TIMEOUT);
    }
}
