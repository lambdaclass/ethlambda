//! What `P2PServer` does with a request/response message, whichever chain it
//! came from.
//!
//! One dispatch and one set of handlers: `handle_req_resp_message` matches the
//! flat `Request` and `ResponsePayload`, so the enum variant is the only place
//! the two chains are told apart. Handler names follow the same convention the
//! variants do, lean prefixed and beacon bare. What is chain-specific below the
//! dispatch is the *body* of a handler, never the path to it; encoding lives
//! further down still, in `crate::lean::encoding` and `crate::beacon::encoding`.

use std::collections::HashSet;

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
    Request, Response, ResponsePayload,
    messages::{ResponseCode, error_message},
};
use crate::beacon::BeaconWire;
use crate::beacon::handler::{self as beacon_handler, StatusVersion};
use crate::beacon::messages::{BeaconStatus, Goodbye, Ping};
use crate::lean::messages::{
    BlocksByRangeRequest, BlocksByRootRequest, RequestedBlockRoots, Status,
};
use crate::lean::protocols::{
    BLOCKS_BY_RANGE_V1 as BLOCKS_BY_RANGE_PROTOCOL_V1,
    BLOCKS_BY_ROOT_V1 as BLOCKS_BY_ROOT_PROTOCOL_V1, MAX_REQUEST_BLOCKS,
};
use crate::{
    BACKOFF_MULTIPLIER, INITIAL_BACKOFF_MS, MAX_FETCH_RETRIES, MAX_SYNC_RANGE, P2PServer,
    PendingRequest, PendingRequestKind, RangeSyncState, metrics, p2p_protocol,
};
use libp2p::request_response::ResponseChannel;

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
                    Request::LeanStatus(status) => {
                        trace!(kind = "status_request", peer_count, "P2P message received");
                        handle_lean_status_request(server, status, channel, peer).await;
                    }
                    Request::LeanBlocksByRoot(request) => {
                        trace!(
                            kind = "blocks_by_root_request",
                            peer_count, "P2P message received"
                        );
                        handle_lean_blocks_by_root_request(server, request, channel, peer).await;
                    }
                    Request::LeanBlocksByRange(request) => {
                        trace!(
                            kind = "blocks_by_range_request",
                            peer_count, "P2P message received"
                        );
                        handle_lean_blocks_by_range_request(server, request, channel, peer).await;
                    }
                    // The beacon protocols. One arm each rather than a grouping
                    // variant that the beacon handler would have to
                    // re-discriminate: the protocol id already decided which
                    // this is, in the codec.
                    Request::Status(peer_status) => {
                        trace!(
                            kind = "beacon_status_request",
                            peer_count, "P2P message received"
                        );
                        handle_status_request(server, peer, peer_status, channel).await;
                    }
                    Request::Ping(ping) => {
                        trace!(kind = "beacon_ping", peer_count, "P2P message received");
                        handle_ping(server, peer, ping, channel).await;
                    }
                    Request::MetaData(protocol) => {
                        trace!(
                            kind = "beacon_metadata_request",
                            peer_count, "P2P message received"
                        );
                        handle_metadata_request(server, peer, protocol, channel).await;
                    }
                    Request::Goodbye(goodbye) => {
                        trace!(kind = "beacon_goodbye", peer_count, "P2P message received");
                        // No response: goodbye is one-way, and dropping
                        // `channel` closes the stream, which is what the peer
                        // is waiting for.
                        handle_goodbye(peer, goodbye);
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
                        ResponsePayload::LeanStatus(status) => {
                            trace!(kind = "status_response", peer_count, "P2P message received");
                            handle_lean_status_response(server, status, peer).await;
                        }
                        ResponsePayload::Status(status) => {
                            trace!(
                                kind = "beacon_status_response",
                                peer_count, "P2P message received"
                            );
                            handle_status_response(server, peer, status);
                        }
                        ResponsePayload::Pong(ping) => {
                            trace!(kind = "beacon_pong", peer_count, "P2P message received");
                            handle_pong(peer, ping);
                        }
                        ResponsePayload::MetaData(_) => {
                            trace!(
                                kind = "beacon_metadata_response",
                                peer_count, "P2P message received"
                            );
                            handle_metadata_response(peer);
                        }
                        ResponsePayload::LeanBlocks(blocks) => {
                            trace!(kind = "blocks_response", peer_count, "P2P message received");

                            match server.outbound_requests.remove(&request_id) {
                                Some(PendingRequestKind::Range {
                                    start_slot,
                                    end_slot,
                                }) => {
                                    handle_lean_blocks_by_range_response(
                                        server, blocks, peer, start_slot, end_slot,
                                    )
                                    .await;
                                }
                                Some(PendingRequestKind::Root(root)) => {
                                    handle_lean_blocks_by_root_response(
                                        server, blocks, peer, root, ctx,
                                    )
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
                // Only the handshake is untracked, and only one failure of it
                // is worth acting on: a peer that has dropped `status/1`
                // refuses the stream outright, and without a handshake it never
                // enters the sync peer set at all.
                None => {
                    if matches!(
                        error,
                        request_response::OutboundFailure::UnsupportedProtocols
                    ) {
                        crate::beacon::handler::retry_status_on_other_version(server, peer).await;
                    }
                }
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

/// Answer a request with a success payload.
///
/// Every request handler on either chain ends here, which is most of what the
/// two have in common above encoding.
fn respond(server: &mut P2PServer, channel: ResponseChannel<Response>, payload: ResponsePayload) {
    server
        .swarm_handle
        .send_response(channel, Response::success(payload));
}

/// Answer a request with an error code and a reason.
fn refuse(
    server: &mut P2PServer,
    channel: ResponseChannel<Response>,
    code: ResponseCode,
    reason: &str,
) {
    server
        .swarm_handle
        .send_response(channel, Response::error(code, error_message(reason)));
}

async fn handle_lean_status_request(
    server: &mut P2PServer,
    request: Status,
    channel: request_response::ResponseChannel<Response>,
    peer: PeerId,
) {
    trace!(finalized_slot=%request.finalized.slot, head_slot=%request.head.slot, "Received status request from peer {peer}");
    let our_status = build_status(&server.store);
    respond(server, channel, ResponsePayload::LeanStatus(our_status));
}

async fn handle_lean_status_response(server: &mut P2PServer, status: Status, peer: PeerId) {
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

async fn handle_lean_blocks_by_root_request(
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

    respond(server, channel, ResponsePayload::LeanBlocks(blocks));
}

async fn handle_lean_blocks_by_range_request(
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
        refuse(
            server,
            channel,
            ResponseCode::INVALID_REQUEST,
            "invalid BlocksByRange request",
        );
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

    respond(server, channel, ResponsePayload::LeanBlocks(blocks));
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

async fn handle_lean_blocks_by_root_response(
    server: &mut P2PServer,
    blocks: Vec<SignedBlock>,
    peer: PeerId,
    requested_root: H256,
    ctx: &Context<P2PServer>,
) {
    let received = blocks.len();
    trace!(%peer, count = received, "Received BlocksByRoot response");

    // Requests carry a single root, so at most one block can answer one and
    // anything else the peer sent is unsolicited.
    let answer = blocks
        .into_iter()
        .find(|block| block.message.hash_tree_root() == requested_root);
    let Some(block) = answer else {
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

async fn handle_lean_blocks_by_range_response(
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
pub async fn fetch_block_from_peer(server: &mut P2PServer, root: H256) -> bool {
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
            Request::LeanBlocksByRoot(request),
            libp2p::StreamProtocol::new(BLOCKS_BY_ROOT_PROTOCOL_V1),
        )
        .await
    else {
        debug!(%root, "Failed to send BlocksByRoot request (swarm adapter closed)");
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
            Request::LeanBlocksByRange(request),
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

/// Retire one failed attempt at fetching `root`.
///
/// Every path that ends an attempt must come through here: a root left in
/// `pending_root_requests` is deduplicated out of every later fetch, so a
/// silent exit loses that block for the life of the process.
async fn handle_fetch_failure(
    server: &mut P2PServer,
    root: H256,
    peer: PeerId,
    ctx: &Context<P2PServer>,
) {
    // A root nobody is waiting on means a late or duplicate failure, which
    // must not resurrect a root that already succeeded.
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

    debug!(%root, %peer, attempts=%pending.attempts, ?backoff, "Block fetch failed, scheduling retry");

    pending.attempts += 1;

    send_after(backoff, ctx.clone(), p2p_protocol::RetryBlockFetch { root });
}

/// The beacon wire, or a refusal sent on `channel`.
///
/// A beacon request reaching a lean node means a peer negotiated a protocol
/// this process does not serve, which is the peer's error to hear about rather
/// than a stream to drop silently. Every request handler below opens with this,
/// which is what the beacon module's single request entry point did once at
/// the top of its match, before the dispatch grew an arm per protocol.
fn beacon_wire_or_refuse(
    server: &mut P2PServer,
    peer: PeerId,
    channel: ResponseChannel<Response>,
) -> Option<(&BeaconWire, ResponseChannel<Response>)> {
    if server.wire.beacon().is_none() {
        warn!(%peer, "Beacon request arrived on a lean node; refusing");
        refuse(
            server,
            channel,
            ResponseCode::INVALID_REQUEST,
            "this node does not speak the beacon protocols",
        );
        return None;
    }
    // Re-taken as a shared borrow now that the `send_response` above, which
    // needs `&mut server`, is behind us.
    server.wire.beacon().map(|wire| (wire, channel))
}

/// Answer `status/N` with our own, and record what the peer told us.
async fn handle_status_request(
    server: &mut P2PServer,
    peer: PeerId,
    peer_status: BeaconStatus,
    channel: ResponseChannel<Response>,
) {
    let Some((wire, channel)) = beacon_wire_or_refuse(server, peer, channel) else {
        return;
    };
    if peer_status.fork_digest() != wire.fork_digest {
        // Not grounds for closing the stream: the peer told us who it is and we
        // answer honestly. Counting it is how a digest that has moved under us
        // becomes visible.
        warn!(
            %peer,
            peer_digest = %hex::encode(peer_status.fork_digest()),
            our_digest = %hex::encode(wire.fork_digest),
            "Peer is on another fork digest"
        );
        metrics::inc_beacon_status_digest_mismatch();
    } else {
        trace!(
            %peer,
            peer_head_slot = peer_status.head_slot(),
            peer_finalized_epoch = peer_status.finalized_epoch(),
            "Beacon status received"
        );
    }
    let our_status = beacon_handler::build_status(wire, StatusVersion::of(&peer_status));
    respond(server, channel, ResponsePayload::Status(our_status));
}

/// Answer `ping/1` with our metadata sequence number.
async fn handle_ping(
    server: &mut P2PServer,
    peer: PeerId,
    ping: Ping,
    channel: ResponseChannel<Response>,
) {
    let Some((wire, channel)) = beacon_wire_or_refuse(server, peer, channel) else {
        return;
    };
    debug!(%peer, peer_seq_number = ping.seq_number, "Ping received");
    let pong = Ping {
        seq_number: wire.metadata_seq_number,
    };
    respond(server, channel, ResponsePayload::Pong(pong));
}

/// Answer `metadata/N` in the version the peer negotiated.
async fn handle_metadata_request(
    server: &mut P2PServer,
    peer: PeerId,
    protocol: &'static str,
    channel: ResponseChannel<Response>,
) {
    let Some((wire, channel)) = beacon_wire_or_refuse(server, peer, channel) else {
        return;
    };
    let Some(metadata) = beacon_handler::build_metadata(wire, protocol) else {
        warn!(%peer, protocol, "No metadata shape for this protocol");
        return;
    };
    respond(server, channel, ResponsePayload::MetaData(metadata));
}

/// Record a `goodbye/1`. One-way, so the caller drops the channel.
fn handle_goodbye(peer: PeerId, Goodbye { reason }: Goodbye) {
    trace!(%peer, reason, "Peer said goodbye");
}

/// Record the peer's answer to our handshake. Nothing is driven off one yet.
fn handle_status_response(server: &mut P2PServer, peer: PeerId, status: BeaconStatus) {
    let Some(wire) = server.wire.beacon() else {
        return;
    };
    if status.fork_digest() != wire.fork_digest {
        warn!(
            %peer,
            peer_digest = %hex::encode(status.fork_digest()),
            our_digest = %hex::encode(wire.fork_digest),
            "Handshake answered from another fork digest"
        );
        metrics::inc_beacon_status_digest_mismatch();
        return;
    }
    trace!(
        %peer,
        peer_head_slot = status.head_slot(),
        peer_finalized_epoch = status.finalized_epoch(),
        "Beacon handshake complete"
    );
}

/// Record a pong. Nothing is driven off one yet.
fn handle_pong(peer: PeerId, ping: Ping) {
    debug!(%peer, peer_seq_number = ping.seq_number, "Pong received");
}

/// Record a peer's metadata. Nothing is driven off one yet.
fn handle_metadata_response(peer: PeerId) {
    debug!(%peer, "Peer metadata received");
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
}
