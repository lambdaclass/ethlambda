//! What `P2PServer` does with a request/response message, whichever chain it
//! came from.
//!
//! One dispatch and one set of handlers: `handle_req_resp_message` matches the
//! flat `Request` and `ResponsePayload`, so the enum variant is the only place
//! the two chains are told apart. Handler names follow the same convention the
//! variants do, lean prefixed and beacon bare; a handler that serves both wires
//! carries neither chain's name, which is why `handle_blocks_by_root_response`
//! reads as it does. What is chain-specific below the dispatch is the *body* of
//! a handler, never the path to it; encoding lives further down still, in
//! `crate::lean::encoding` and `crate::beacon::encoding`.

use std::collections::HashSet;

use ethlambda_network_api::BlockSource;
use ethlambda_storage::{Chain, Store};
use libp2p::{PeerId, request_response};
use rand::seq::SliceRandom;
use spawned_concurrency::tasks::{Context, send_after};
use std::time::Duration;
use tracing::{debug, error, trace, warn};

use ethlambda_types::beacon::containers::SignedBeaconBlock;
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
use crate::beacon::protocols::{
    BLOCKS_BY_RANGE_V2 as BEACON_BLOCKS_BY_RANGE_PROTOCOL,
    BLOCKS_BY_ROOT_V2 as BEACON_BLOCKS_BY_ROOT_PROTOCOL,
    MAX_REQUEST_BLOCKS as MAX_BEACON_REQUEST_BLOCKS, MAX_REQUEST_BLOCKS_DENEB,
};
use crate::lean::messages::{BlocksByRootRequest, RequestedBlockRoots, Status};
use crate::lean::protocols::{
    BLOCKS_BY_RANGE_V1 as BLOCKS_BY_RANGE_PROTOCOL_V1,
    BLOCKS_BY_ROOT_V1 as BLOCKS_BY_ROOT_PROTOCOL_V1, MAX_REQUEST_BLOCKS,
};
use crate::req_resp::messages::BlocksByRangeRequest;
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
                    // One variant for both wires, so which handler answers it
                    // comes from `server.wire` rather than from the message.
                    // See `Wire::is_beacon`.
                    Request::BlocksByRoot(request) => {
                        trace!(
                            kind = "blocks_by_root_request",
                            peer_count, "P2P message received"
                        );
                        if server.wire.is_beacon() {
                            handle_beacon_blocks_by_root_request(server, peer, request, channel)
                                .await;
                        } else {
                            handle_lean_blocks_by_root_request(server, request, channel, peer)
                                .await;
                        }
                    }
                    Request::BlocksByRange(request) => {
                        trace!(
                            kind = "blocks_by_range_request",
                            peer_count, "P2P message received"
                        );
                        if server.wire.is_beacon() {
                            handle_beacon_blocks_by_range_request(server, peer, request, channel)
                                .await;
                        } else {
                            handle_lean_blocks_by_range_request(server, request, channel, peer)
                                .await;
                        }
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
                            handle_status_response(server, peer, status).await;
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
                        ResponsePayload::Blocks(blocks) => {
                            trace!(kind = "blocks_response", peer_count, "P2P message received");
                            // Dispatched on what was asked for first and on the
                            // wire second, because only the range answer is
                            // handled differently by the two chains: a by-root
                            // answer is one shared handler, since the block it
                            // carries either has the root that was asked for or
                            // the request has failed, on either wire.
                            match server.outbound_requests.remove(&request_id) {
                                Some(PendingRequestKind::Root(root)) => {
                                    handle_blocks_by_root_response(server, blocks, peer, root, ctx)
                                        .await;
                                }
                                Some(PendingRequestKind::Range {
                                    start_slot,
                                    end_slot,
                                }) => {
                                    if server.wire.is_beacon() {
                                        handle_beacon_blocks_by_range_response(
                                            server, peer, blocks, start_slot, end_slot,
                                        )
                                        .await;
                                    } else {
                                        // `new_block` takes lean's concrete
                                        // block, so the shared payload is
                                        // peeled here, at the one point that
                                        // needs the narrower type.
                                        let blocks = lean_blocks(blocks);
                                        handle_lean_blocks_by_range_response(
                                            server, blocks, peer, start_slot, end_slot,
                                        )
                                        .await;
                                    }
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

/// The lean blocks in a shared block payload.
///
/// `ResponsePayload::Blocks` spans both chains, but a lean import path needs
/// lean's own `SignedBlock`, so the narrowing happens once here. A block of any
/// other fork on this path means a peer answered a lean protocol with a beacon
/// block; it is dropped with a log rather than silently, since nothing else
/// would notice.
fn lean_blocks(blocks: Vec<SignedBeaconBlock>) -> Vec<SignedBlock> {
    blocks
        .into_iter()
        .filter_map(|block| match block {
            SignedBeaconBlock::Lean(block) => Some(block),
            other => {
                debug!(
                    slot = other.slot(),
                    fork = %other.fork_name(),
                    "Dropping a non-lean block from a lean block response"
                );
                None
            }
        })
        .collect()
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
        // A missing block is silently skipped, per spec. A block of the wrong
        // fork is not filtered here either: `write_blocks_response` refuses to
        // put one on this chain's wire, which is the only place it could do
        // harm.
        if let Ok(Some(block)) = server.store.get_signed_block(root) {
            blocks.push(block);
        }
    }

    let found = blocks.len();
    trace!(%peer, num_roots, found, "Responding to BlocksByRoot request");

    respond(server, channel, ResponsePayload::Blocks(blocks));
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

    respond(server, channel, ResponsePayload::Blocks(blocks));
}

/// The canonical blocks in `[start_slot, start_slot + count)`, on either chain.
///
/// One reader for both `blocks_by_range` protocols. The `BlockRoots` index it
/// walks is written for either chain and keyed by slot alone, and the store
/// dispatches on which chain's rows sit behind it, so there is nothing left
/// here for a chain to decide.
///
/// A window that overflows `u64` yields an empty answer rather than a panic,
/// which is not a nicety: `start_slot` and `count` are attacker-supplied. A
/// `count` of zero takes the same path, since there is no last offset to add.
fn canonical_blocks_by_range(store: &Store, start_slot: u64, count: u64) -> Vec<SignedBeaconBlock> {
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

/// Take delivery of a by-root answer, on either chain.
///
/// One handler for both wires, because a by-root answer is the same exchange
/// on each: a request carries exactly one root, so the peer either sent the
/// block under that root or it answered nothing, and the two outcomes are the
/// same either way. An answer that carries no matching block — an empty one
/// included, which is only the same case with nothing to search — is a failed
/// attempt and must go through [`handle_fetch_failure`], or the root stays in
/// `pending_root_requests` and deduplicates every later fetch of it.
///
/// The import at the end is where the chains part, and the split is already
/// made for us: `blockchain` is `None` on a beacon node, which has no
/// `BlockChain` actor to import into, so a beacon block fetched by root is
/// checked and dropped exactly as a gossiped one is.
async fn handle_blocks_by_root_response(
    server: &mut P2PServer,
    blocks: Vec<SignedBeaconBlock>,
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
        .find(|block| block.message_hash_tree_root() == requested_root);
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

    let Some(ref blockchain) = server.blockchain else {
        debug!(
            %peer,
            slot = block.slot(),
            block_root = %ethlambda_types::ShortRoot(&requested_root.0),
            "Block fetched by root has no importer; dropping"
        );
        return;
    };

    // A non-lean block on a lean node means a peer answered a lean protocol
    // with a beacon block; it is dropped with a log rather than silently, for
    // the reason `lean_blocks` gives. A beacon node asked on its own protocol
    // and forwards whatever fork came back.
    if !server.wire.is_beacon() && !matches!(block, SignedBeaconBlock::Lean(_)) {
        debug!(
            slot = block.slot(),
            fork = %block.fork_name(),
            "Dropping a non-lean block from a lean block response"
        );
        return;
    }

    let _ = blockchain
        .new_block(block, BlockSource::Sync)
        .inspect_err(|err| error!(%err, "Failed to forward fetched block to blockchain"));
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
        if let Err(err) = blockchain.new_block(SignedBeaconBlock::Lean(block), BlockSource::Sync) {
            error!(
                %err, %slot, %peer,
                block_root = %ethlambda_types::ShortRoot(&block_root.0),
                "Failed to forward range-fetched block to blockchain"
            );
        }
    }

    if let Some(state) = &mut server.range_sync_state {
        state.complete_batch(end_slot);
        if range_session_exhausted(state) {
            server.range_sync_state = None;
            return;
        }
    }

    request_next_range_batch(server).await;
}

/// Whether a range sync session has nothing left to do: either the requested
/// range is now empty, or every peer that had something left to offer has
/// dropped out of `peer_set`. Shared by both chains' range-response handlers,
/// since a session left in place once it is exhausted disables the resync
/// path permanently, on either wire.
fn range_session_exhausted(state: &RangeSyncState) -> bool {
    state.current_range.is_empty() || state.peer_set.is_empty()
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
///
/// Peer selection is chain-agnostic (which peers already failed to answer for
/// this root has nothing to do with which wire is speaking), but the actual
/// send is not: `Handler<FetchBlock>` in `lib.rs` calls this unconditionally,
/// so a beacon node must not put a lean-framed `BlocksByRoot` request on its
/// beacon streams, which is what asking via `Request::BlocksByRoot` +
/// `BLOCKS_BY_ROOT_PROTOCOL_V1` unconditionally would do.
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
    let excluded = server.connected_peers.len() - pool.len();

    let sent = if server.wire.is_beacon() {
        trace!(%peer, %root, excluded, "Sending BeaconBlocksByRoot request for missing block");
        request_beacon_block_by_root(server, peer, root)
            .await
            .is_some()
    } else {
        // Create BlocksByRoot request with single root
        let mut roots = RequestedBlockRoots::new();
        if let Err(err) = roots.push(root) {
            error!(%root, ?err, "Failed to create BlocksByRoot request");
            return false;
        }
        let request = BlocksByRootRequest { roots };

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
        // Map request_id to root for failure handling. `request_beacon_block_by_root`
        // does this itself in the beacon arm above.
        server
            .outbound_requests
            .insert(request_id, PendingRequestKind::Root(root));
        true
    };

    if !sent {
        debug!(%root, "Failed to send by-root request (swarm adapter closed)");
        return false;
    }

    // Track the request if not already tracked (new request). Common to both
    // arms: this is what dedupes a repeated fetch and what the retry path
    // reads.
    server
        .pending_root_requests
        .entry(root)
        .or_insert(PendingRequest {
            attempts: 1,
            failed_peers: HashSet::new(),
        });

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

    let request = BlocksByRangeRequest::new(batch.start, batch.end - batch.start);
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

/// The beacon counterpart of [`request_next_range_batch`].
///
/// Same [`RangeSyncState::next_batch`] planning, but sent through
/// [`request_beacon_blocks_by_range`] rather than a raw `swarm_handle.send_request`:
/// that is what makes the beacon protocol id apply instead of lean's, and what
/// makes [`MAX_REQUEST_BLOCKS_DENEB`] the real per-request ceiling rather than
/// the larger `MAX_REQUEST_BLOCKS` that `next_batch` plans a batch against.
/// `request_beacon_blocks_by_range` already records the `outbound_requests`
/// entry with whatever it actually sent (clamped or not), so
/// [`RangeSyncState::complete_batch`] still advances by the true request span
/// on the next response even when this batch was clamped smaller than
/// `next_batch` planned.
async fn request_next_beacon_range_batch(server: &mut P2PServer) -> bool {
    let Some((peer, batch)) = server
        .range_sync_state
        .as_ref()
        .and_then(RangeSyncState::next_batch)
    else {
        return true;
    };

    let planned = batch.end - batch.start;
    // `planned`, not `count`: `next_batch` plans against `MAX_REQUEST_BLOCKS`
    // and the send clamps to `MAX_REQUEST_BLOCKS_DENEB`, so the number that
    // goes on the wire is the one `request_beacon_blocks_by_range` traces.
    trace!(
        %peer,
        start_slot = batch.start,
        planned,
        "Planning a BeaconBlocksByRange request (single batch)"
    );

    if request_beacon_blocks_by_range(server, peer, batch.start, planned)
        .await
        .is_none()
    {
        debug!(
            %peer,
            start_slot = batch.start,
            planned,
            "Failed to send BeaconBlocksByRange request"
        );
        fail_range_request(server, &peer);
        return false;
    }

    if let Some(state) = &mut server.range_sync_state {
        state.in_flight = true;
    }

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
///
/// Does not use [`beacon_wire_or_refuse`]: that helper takes `&mut P2PServer`
/// and returns a `&BeaconWire` tied to its whole lifetime, which is fine for
/// [`handle_ping`] and [`handle_metadata_request`] below, neither of which
/// needs another field of `server` alive at the same time. This handler does:
/// `build_status` now reads `&server.store` alongside `wire`, and a `wire`
/// borrowed through that helper's `&mut P2PServer` parameter would hold the
/// whole server borrowed for as long as it lives, not just `server.wire`,
/// which would make `&server.store` a conflicting borrow. Reading
/// `server.wire.beacon()` directly, as below, borrows only that one field, so
/// `&server.store` can be taken alongside it.
async fn handle_status_request(
    server: &mut P2PServer,
    peer: PeerId,
    peer_status: BeaconStatus,
    channel: ResponseChannel<Response>,
) {
    if server.wire.beacon().is_none() {
        warn!(%peer, "Beacon request arrived on a lean node; refusing");
        refuse(
            server,
            channel,
            ResponseCode::INVALID_REQUEST,
            "this node does not speak the beacon protocols",
        );
        return;
    }
    // Re-taken as a shared borrow of just `server.wire`, now that the
    // `refuse` above (which needs `&mut server`) is behind us.
    let wire = server.wire.beacon().expect("checked above");

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
    let our_status =
        beacon_handler::build_status(&server.store, wire, StatusVersion::of(&peer_status));
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

/// The `[start_slot, end_exclusive)` a beacon range sync should now cover,
/// given how far this node has fetched and a peer's advertised head. `None`
/// when the peer is not ahead of `fetched_through`.
///
/// Takes `fetched_through` rather than a `Store`, deliberately: this is
/// `server.beacon_fetched_through`, not `server.store.head_slot()`. Delivery
/// to the chain actor is a message and import is work, so the store's own
/// head lags a delivered batch by the whole actor mailbox. Driven off the
/// store's head, the live follower kept re-requesting the part of the range
/// still draining and pulled 11,213 blocks off the wire to import 100; see
/// `beacon_fetched_through`'s own doc comment on `P2PServer`. Bounded by
/// [`MAX_SYNC_RANGE`], the same ceiling `handle_lean_status_response` bounds
/// its own request span by.
fn beacon_sync_target(fetched_through: u64, peer_head_slot: u64) -> Option<std::ops::Range<u64>> {
    if peer_head_slot <= fetched_through {
        return None;
    }
    let gap = peer_head_slot - fetched_through;
    let start_slot = fetched_through.saturating_add(1);
    let end_exclusive = start_slot.saturating_add(gap.min(MAX_SYNC_RANGE));
    Some(start_slot..end_exclusive)
}

/// Record the peer's answer to our handshake, and start or extend the
/// anchor-to-head range sync when [`beacon_sync_target`] says it leaves this
/// node behind.
///
/// The beacon counterpart of `handle_lean_status_response`: same merge-or-
/// create on `range_sync_state` and the same kick of the first batch,
/// differing only in what "behind" is measured against (see
/// [`beacon_sync_target`]) and in which function sends the batch
/// ([`request_next_beacon_range_batch`], so the beacon protocol id and
/// `MAX_REQUEST_BLOCKS_DENEB` apply).
async fn handle_status_response(server: &mut P2PServer, peer: PeerId, status: BeaconStatus) {
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
    let peer_head_slot = status.head_slot();
    trace!(
        %peer,
        peer_head_slot,
        peer_finalized_epoch = status.finalized_epoch(),
        "Beacon handshake complete"
    );

    let Some(target_range) = beacon_sync_target(server.beacon_fetched_through, peer_head_slot)
    else {
        return;
    };

    debug!(
        %peer,
        peer_head_slot,
        fetched_through = server.beacon_fetched_through,
        start_slot = target_range.start,
        end_exclusive = target_range.end,
        "Beacon peer status head is ahead of what has been fetched"
    );

    let end_exclusive = target_range.end;
    match &mut server.range_sync_state {
        Some(state) => state.merge_peer(peer, peer_head_slot, end_exclusive),
        None => {
            server.range_sync_state = Some(RangeSyncState::new(target_range, peer, peer_head_slot));
        }
    }

    request_next_beacon_range_batch(server).await;
    trace!(%peer, "Beacon long-range sync: using BeaconBlocksByRange");
}

/// Record a pong. Nothing is driven off one yet.
fn handle_pong(peer: PeerId, ping: Ping) {
    debug!(%peer, peer_seq_number = ping.seq_number, "Pong received");
}

/// Record a peer's metadata. Nothing is driven off one yet.
fn handle_metadata_response(peer: PeerId) {
    debug!(%peer, "Peer metadata received");
}

/// The beacon store this node can serve blocks out of, or a refusal.
///
/// Two things have to hold before a block request can be answered: this process
/// speaks the beacon wire at all, and the data directory behind it actually
/// holds a beacon chain. The anchor makes the second true for an ordinary
/// `ethlambda beacon` run, so this is a guard against a lean directory rather
/// than the common path. It is a refusal rather than an empty answer because
/// the difference matters to the peer: `RESOURCE_UNAVAILABLE` is the spec's own
/// code for a peer "unable to reply to block requests", where an empty stream
/// claims we looked and had nothing, and `INVALID_REQUEST` would blame the
/// asker for a request that was fine.
fn beacon_block_store_or_refuse(
    server: &mut P2PServer,
    peer: PeerId,
    channel: ResponseChannel<Response>,
) -> Option<ResponseChannel<Response>> {
    let (_, channel) = beacon_wire_or_refuse(server, peer, channel)?;
    if server.store.chain() != Chain::Beacon {
        debug!(%peer, "Beacon block request arrived with no beacon chain behind it; refusing");
        refuse(
            server,
            channel,
            ResponseCode::RESOURCE_UNAVAILABLE,
            "this node holds no beacon chain",
        );
        return None;
    }
    Some(channel)
}

/// Answer `beacon_blocks_by_range/2` off the canonical chain.
///
/// The counterpart of [`handle_lean_blocks_by_range_request`], and the same
/// shape: reject an empty or oversized window, then read the canonical branch
/// for the slots asked for. What differs is the ceiling. A `count` above
/// `MAX_REQUEST_BLOCKS` is a protocol violation and is refused; a `count` merely
/// above `MAX_REQUEST_BLOCKS_DENEB` is a peer on older logic, and the spec
/// allows "Clients MAY limit the number of blocks in the response", so it is
/// truncated rather than refused.
///
/// `step` is deprecated and legal only as 1. It is judged here rather than at
/// decode so the peer learns which rule it broke: a codec refusal drops the
/// stream with no response on it, where this answers `INVALID_REQUEST`. Phase0
/// does permit answering a larger step with a single block, but that leniency
/// is for a transition that finished years ago, and the spec's own requirement
/// on the requester is a MUST.
async fn handle_beacon_blocks_by_range_request(
    server: &mut P2PServer,
    peer: PeerId,
    request: BlocksByRangeRequest,
    channel: ResponseChannel<Response>,
) {
    let Some(channel) = beacon_block_store_or_refuse(server, peer, channel) else {
        return;
    };

    if request.count == 0 || request.count > MAX_BEACON_REQUEST_BLOCKS {
        refuse(
            server,
            channel,
            ResponseCode::INVALID_REQUEST,
            "invalid BeaconBlocksByRange request",
        );
        return;
    }
    if request.step != 1 {
        debug!(%peer, step = request.step, "BeaconBlocksByRange named a deprecated step");
        refuse(
            server,
            channel,
            ResponseCode::INVALID_REQUEST,
            "BeaconBlocksByRange step must be 1",
        );
        return;
    }

    let count = request.count.min(MAX_REQUEST_BLOCKS_DENEB);
    let blocks = canonical_blocks_by_range(&server.store, request.start_slot, count);

    trace!(
        %peer,
        start_slot = request.start_slot,
        count = request.count,
        served = count,
        found = blocks.len(),
        "Responding to BeaconBlocksByRange request"
    );

    respond(server, channel, ResponsePayload::Blocks(blocks));
}

/// Answer `beacon_blocks_by_root/2` with whichever of the roots is held.
///
/// The counterpart of [`handle_lean_blocks_by_root_request`]: a root this node
/// does not hold is skipped rather than answered with an error chunk, since the
/// response is "a list of `SignedBeaconBlock` whose length is less than or equal
/// to the number of requested blocks". The order the peer asked in is the order
/// it gets back, which is why the response cannot be described as a slot range.
async fn handle_beacon_blocks_by_root_request(
    server: &mut P2PServer,
    peer: PeerId,
    request: BlocksByRootRequest,
    channel: ResponseChannel<Response>,
) {
    let Some(channel) = beacon_block_store_or_refuse(server, peer, channel) else {
        return;
    };

    let requested = request.roots.len();
    let mut blocks = Vec::new();
    for root in request.roots.iter().take(MAX_REQUEST_BLOCKS_DENEB as usize) {
        match server.store.get_signed_block(root) {
            Ok(Some(SignedBeaconBlock::Lean(_))) => error!(
                %root,
                "BeaconBlocksByRoot found a lean block in a beacon store"
            ),
            Ok(Some(block)) => blocks.push(block),
            // A root we do not hold is not an error to report: the spec answers
            // it by simply leaving the block out.
            Ok(None) | Err(_) => {}
        }
    }

    trace!(
        %peer,
        requested,
        found = blocks.len(),
        "Responding to BeaconBlocksByRoot request"
    );

    respond(server, channel, ResponsePayload::Blocks(blocks));
}

/// Ask `peer` for the beacon blocks in `[start_slot, start_slot + count)`.
///
/// Returns the request id, so a caller can pair the answer with what it asked
/// for. `count` is clamped to `MAX_REQUEST_BLOCKS_DENEB`, the ceiling that has
/// applied since deneb and so the only one that matters on a live network:
/// asking for more is a protocol violation the peer is entitled to refuse.
pub async fn request_beacon_blocks_by_range(
    server: &mut P2PServer,
    peer: PeerId,
    start_slot: u64,
    count: u64,
) -> Option<request_response::OutboundRequestId> {
    let count = count.min(MAX_REQUEST_BLOCKS_DENEB);
    if count == 0 {
        return None;
    }
    let request = BlocksByRangeRequest::new(start_slot, count);
    trace!(%peer, start_slot, count, "Sending BeaconBlocksByRange request");
    let request_id = server
        .swarm_handle
        .send_request(
            peer,
            Request::BlocksByRange(request),
            libp2p::StreamProtocol::new(BEACON_BLOCKS_BY_RANGE_PROTOCOL),
        )
        .await?;
    server.outbound_requests.insert(
        request_id,
        PendingRequestKind::Range {
            start_slot,
            end_slot: start_slot.saturating_add(count - 1),
        },
    );
    Some(request_id)
}

/// Ask `peer` for one beacon block by root.
///
/// One root per request rather than a batch, matching
/// [`fetch_block_from_peer`]'s shape on the lean side: the tracking that pairs
/// an answer with a request is keyed on a single root, and a block fetched by
/// root is always fetched because one specific parent is missing.
pub async fn request_beacon_block_by_root(
    server: &mut P2PServer,
    peer: PeerId,
    root: H256,
) -> Option<request_response::OutboundRequestId> {
    let mut roots = RequestedBlockRoots::new();
    if let Err(err) = roots.push(root) {
        error!(%root, ?err, "Failed to create BeaconBlocksByRoot request");
        return None;
    }
    trace!(%peer, %root, "Sending BeaconBlocksByRoot request");
    let request_id = server
        .swarm_handle
        .send_request(
            peer,
            Request::BlocksByRoot(BlocksByRootRequest { roots }),
            libp2p::StreamProtocol::new(BEACON_BLOCKS_BY_ROOT_PROTOCOL),
        )
        .await?;
    server
        .outbound_requests
        .insert(request_id, PendingRequestKind::Root(root));
    Some(request_id)
}

/// Take delivery of a range answer, checking it against what was asked for,
/// and forward whatever passes to the chain actor.
///
/// The counterpart of [`handle_lean_blocks_by_range_response`]. The by-root
/// answer has no counterpart here, because it needs none:
/// [`handle_blocks_by_root_response`] answers for both wires. A block outside
/// the range is dropped on its own rather than failing the batch, since the
/// rest of the answer may still be what was requested. The chunk-level checks
/// that *do* fail the whole answer, on the fork digest and the SSZ shape,
/// already ran in the codec.
async fn handle_beacon_blocks_by_range_response(
    server: &mut P2PServer,
    peer: PeerId,
    blocks: Vec<SignedBeaconBlock>,
    start_slot: u64,
    end_slot: u64,
) {
    trace!(%peer, count = blocks.len(), "Received beacon blocks response");

    if blocks.is_empty() {
        fail_range_request(server, &peer);
        debug!(%peer, start_slot, end_slot, "Received empty BeaconBlocksByRange response");
        return;
    }

    let Some(ref blockchain) = server.blockchain else {
        // No actor to forward into. A range session makes no progress either
        // way, so it is dropped rather than spun uselessly on further
        // batches, matching handle_lean_blocks_by_range_response.
        server.range_sync_state = None;
        debug!(%peer, "No blockchain handler available");
        return;
    };

    let received = blocks.len();
    let mut accepted = 0usize;
    let mut highest_forwarded_slot: Option<u64> = None;

    for block in blocks {
        let slot = block.slot();
        if slot < start_slot || slot > end_slot {
            debug!(%peer, %slot, start_slot, end_slot, "Beacon block outside requested range");
            continue;
        }

        highest_forwarded_slot =
            Some(highest_forwarded_slot.map_or(slot, |max: u64| max.max(slot)));
        accepted += 1;

        // No block root in the failure log: reaching it means the actor
        // mailbox send failed, which `%peer` and `%slot` already identify,
        // and `message_hash_tree_root` is a whole-block merkleization
        // (execution payload included) that would then be paid for every
        // block on the sync path. [`handle_blocks_by_root_response`] computes
        // one because it has an answer to check; a range batch does not.
        let _ = blockchain.new_block(block, BlockSource::Sync).inspect_err(
            |err| error!(%err, %slot, %peer, "Failed to forward beacon block to blockchain"),
        );
    }

    debug!(%peer, received, accepted, "Beacon blocks received");

    // Highest slot *handed to* the actor, not the highest imported: see
    // `beacon_fetched_through`'s own doc comment on `P2PServer` for why range
    // sync must be driven off this rather than the store's head.
    if let Some(highest) = highest_forwarded_slot {
        server.beacon_fetched_through = server.beacon_fetched_through.max(highest);
    }
    if let Some(state) = &mut server.range_sync_state {
        state.complete_batch(end_slot);
        if range_session_exhausted(state) {
            server.range_sync_state = None;
            return;
        }
    }
    request_next_beacon_range_batch(server).await;
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
            .insert_signed_block(root_1, SignedBeaconBlock::Lean(block_1))
            .expect("insert test block should succeed");

        let block_2 = signed_block(2, root_1);
        let root_2 = block_2.message.hash_tree_root();
        store
            .insert_signed_block(root_2, SignedBeaconBlock::Lean(block_2))
            .expect("insert test block should succeed");

        let side_block_3 = signed_block(3, root_1);
        let side_root_3 = side_block_3.message.hash_tree_root();
        store
            .insert_signed_block(side_root_3, SignedBeaconBlock::Lean(side_block_3))
            .expect("insert test block should succeed");

        let block_4 = signed_block(4, root_2);
        let root_4 = block_4.message.hash_tree_root();
        store
            .insert_signed_block(root_4, SignedBeaconBlock::Lean(block_4))
            .expect("insert test block should succeed");
        store
            .update_checkpoints(ForkCheckpoints::head_only(root_4))
            .expect("update_checkpoints should succeed");

        let blocks = canonical_blocks_by_range(&store, 1, 4);
        let slots: Vec<_> = blocks.iter().map(SignedBeaconBlock::slot).collect();
        let roots: Vec<_> = blocks
            .iter()
            .map(SignedBeaconBlock::message_hash_tree_root)
            .collect();

        assert_eq!(slots, vec![1, 2, 4]);
        assert_eq!(roots, vec![root_1, root_2, root_4]);
        assert!(!roots.contains(&side_root_3));
    }

    #[test]
    fn beacon_sync_target_keys_off_fetched_through_not_store_head() {
        // A batch already handed to the chain actor but not yet imported
        // leaves the store's own head behind `fetched_through`; the sync
        // target must still be computed from `fetched_through`. See
        // `beacon_sync_target`'s own doc comment for why the store's head is
        // the wrong signal to drive this off: it is what pulled 11,213
        // blocks off the wire to import 100 on the live follower.
        assert_eq!(beacon_sync_target(100, 150), Some(101..151));
        // A peer at or behind what has already been fetched has nothing to
        // offer, regardless of what the store's own (possibly much lower)
        // head happens to be.
        assert_eq!(beacon_sync_target(150, 150), None);
        assert_eq!(beacon_sync_target(150, 100), None);
    }

    #[test]
    fn beacon_sync_target_is_bounded_by_max_sync_range() {
        let target = beacon_sync_target(0, u64::MAX).expect("peer is far ahead");
        assert_eq!(target, 1..(1 + MAX_SYNC_RANGE));
    }

    #[test]
    fn a_range_session_is_exhausted_by_an_empty_range_or_an_empty_peer_set() {
        let peer = PeerId::random();
        // Far more range than one batch covers.
        let mut state = RangeSyncState::new(10..1074, peer, 2000);
        state.in_flight = true;
        state.complete_batch(73);
        assert!(!range_session_exhausted(&state));

        // The whole range in one batch, which leaves nothing to ask for.
        let mut whole_range = RangeSyncState::new(10..74, peer, 200);
        whole_range.in_flight = true;
        whole_range.complete_batch(73);
        assert!(range_session_exhausted(&whole_range));

        // The range itself is not exhausted, but its only peer is gone.
        let lone_peer = PeerId::random();
        let mut peer_gone = RangeSyncState::new(10..20, lone_peer, 15);
        peer_gone.fail_peer(&lone_peer);
        assert!(range_session_exhausted(&peer_gone));
    }
}
