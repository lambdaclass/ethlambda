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

use std::collections::{HashMap, HashSet};

use ethlambda_network_api::{BlockArrival, BlockSource};
use ethlambda_storage::{Chain, Store};
use libp2p::{PeerId, request_response};
use rand::seq::SliceRandom;
use spawned_concurrency::tasks::{Context, send_after};
use std::time::{Duration, Instant};
use tracing::{debug, error, info, trace, warn};

use ethlambda_state_transition::beacon::das;
use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::constants;
use ethlambda_types::beacon::containers::SignedBeaconBlock;
use ethlambda_types::beacon::containers::fulu::{
    ColumnIndices, DataColumnSidecar, DataColumnsByRootIdentifier,
};
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::checkpoint::Checkpoint;
use ethlambda_types::primitives::HashTreeRoot as _;
use ethlambda_types::{block::SignedBlock, primitives::H256};

use super::{
    Request, Response, ResponsePayload,
    messages::{ResponseCode, error_message},
};
use crate::beacon::BeaconWire;
use crate::beacon::column_checks;
use crate::beacon::decode::{decode_data_column_sidecar, fork_at_slot};
use crate::beacon::handler::{self as beacon_handler, StatusVersion};
use crate::beacon::messages::{
    BeaconMetaData, BeaconStatus, DataColumnsByRangeRequest, Goodbye, Ping,
};
use crate::beacon::protocols::{
    MAX_REQUEST_BLOCKS as MAX_BEACON_REQUEST_BLOCKS, MAX_REQUEST_BLOCKS_DENEB,
};
use crate::discovery::enr::node_id_from_peer_id;
use crate::lean::messages::{BlocksByRootRequest, RequestedBlockRoots, Status};
use crate::lean::protocols::MAX_REQUEST_BLOCKS;
use crate::req_resp::messages::BlocksByRangeRequest;
use crate::{
    BACKOFF_MULTIPLIER, CustodyWait, INITIAL_BACKOFF_MS, MAX_FETCH_RETRIES, MAX_SYNC_RANGE,
    P2PServer, PendingColumnRequest, PendingRequest, PendingRequestKind, RANGE_BATCH_CUSTODY_WAIT,
    RangeSyncState, ReqRespProtocol, ReqRespRequestId, UNKNOWN_CUSTODY_RANGE_PEERS, metrics,
    p2p_protocol,
};
use libp2p::request_response::ResponseChannel;

/// `protocol` names which [`ReqResp`](super::ReqResp) field `event` came
/// from, which is what turns the bare `OutboundRequestId` a
/// [`request_response::Event::Message`] response or
/// [`request_response::Event::OutboundFailure`] carries back into the
/// composite [`ReqRespRequestId`] `server.outbound_requests` is actually keyed
/// on; see [`ReqRespProtocol`]'s doc comment for why a bare id is no longer
/// safe to look up on its own.
pub async fn handle_req_resp_message(
    server: &mut P2PServer,
    protocol: ReqRespProtocol,
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
                    // Beacon-only, like the four request arms above: lean
                    // custodies no data columns, so there is no lean-side
                    // handler to branch to the way `BlocksByRoot`/`BlocksByRange`
                    // do.
                    Request::DataColumnsByRoot(identifiers) => {
                        trace!(
                            kind = "data_column_sidecars_by_root_request",
                            peer_count, "P2P message received"
                        );
                        handle_data_column_sidecars_by_root_request(
                            server,
                            peer,
                            identifiers,
                            channel,
                        )
                        .await;
                    }
                    Request::DataColumnsByRange(request) => {
                        trace!(
                            kind = "data_column_sidecars_by_range_request",
                            peer_count, "P2P message received"
                        );
                        handle_data_column_sidecars_by_range_request(
                            server, peer, request, channel,
                        )
                        .await;
                    }
                }
            }
            request_response::Message::Response {
                request_id,
                response,
            } => {
                // See `handle_req_resp_message`'s own doc comment: `request_id`
                // alone is not a safe `outbound_requests` key any more, so it
                // is composited with the protocol this event's own field
                // named before anything below looks it up.
                let request_id = ReqRespRequestId {
                    protocol,
                    id: request_id,
                };
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
                            handle_status_response(server, peer, status, ctx).await;
                        }
                        ResponsePayload::Pong(ping) => {
                            trace!(kind = "beacon_pong", peer_count, "P2P message received");
                            handle_pong(peer, ping);
                        }
                        ResponsePayload::MetaData(metadata) => {
                            trace!(
                                kind = "beacon_metadata_response",
                                peer_count, "P2P message received"
                            );
                            handle_metadata_response(server, peer, metadata);
                            // A peer's custody usually becomes known here, so
                            // a range batch held back for it may go now.
                            resume_range_batch_held_for_custody(server, ctx).await;
                        }
                        ResponsePayload::DataColumnSidecars(sidecars) => {
                            trace!(
                                kind = "data_column_sidecars_response",
                                peer_count, "P2P message received"
                            );
                            // Two senders produce this payload: a `Columns`
                            // by-root lookup for one held block, and a
                            // `ColumnRange` prefetch riding alongside a range
                            // sync batch. Removed here, like `Blocks` removes
                            // its own entry, rather than left for a later
                            // event: this response is the terminal outcome for
                            // the id either way.
                            match server.outbound_requests.remove(&request_id) {
                                Some(PendingRequestKind::Columns(block_root)) => {
                                    handle_data_column_sidecars_response(
                                        server, peer, block_root, sidecars, ctx,
                                    )
                                    .await;
                                }
                                Some(PendingRequestKind::ColumnRange {
                                    start_slot,
                                    end_slot,
                                }) => {
                                    handle_data_column_sidecars_range_response(
                                        server, peer, start_slot, end_slot, sidecars,
                                    )
                                    .await;
                                }
                                // Unreachable by construction: a request_id's
                                // protocol is fixed at send time, and only the
                                // two column kinds are ever sent on this
                                // protocol, so the codec could not have
                                // produced this payload for a `Root`/`Range`
                                // id. Not re-inserted: the exchange this id
                                // named is already over, and putting a `Root`
                                // or `Range` entry back here would strand it
                                // exactly the way #608 fixed, since no further
                                // event will ever name this id again.
                                Some(
                                    PendingRequestKind::Root(_) | PendingRequestKind::Range { .. },
                                ) => {
                                    error!(
                                        %peer,
                                        ?request_id,
                                        count = sidecars.len(),
                                        "Data column sidecars response answered a non-column request id"
                                    );
                                }
                                None => {
                                    debug!(
                                        %peer,
                                        ?request_id,
                                        count = sidecars.len(),
                                        "Received data column sidecars response for unknown request_id"
                                    );
                                }
                            }
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
                                            server, peer, blocks, start_slot, end_slot, ctx,
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
                                // Unreachable: a column request negotiates the
                                // data column protocol, which answers with
                                // `DataColumnSidecars`, never with `Blocks`.
                                Some(
                                    PendingRequestKind::Columns(_)
                                    | PendingRequestKind::ColumnRange { .. },
                                ) => {
                                    error!(
                                        %peer,
                                        "Blocks response answered a data column request id"
                                    );
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
                            Some(PendingRequestKind::Columns(block_root)) => {
                                // Same reasoning as the `Root` arm above: an
                                // error response is the whole exchange, so
                                // this is the only place that can retire it.
                                handle_column_fetch_failure(server, block_root, peer, ctx).await;
                            }
                            // Nothing to retire: a range prefetch has no
                            // pending entry and nothing waits on it. A peer
                            // refusing the range (ResourceUnavailable, say)
                            // just means these columns come from gossip or
                            // from the by-root path instead.
                            Some(PendingRequestKind::ColumnRange { .. }) => {}
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
            // Same compositing as the `Message::Response` arm above, and for
            // the same reason.
            let request_id = ReqRespRequestId {
                protocol,
                id: request_id,
            };
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
                Some(PendingRequestKind::Columns(block_root)) => {
                    handle_column_fetch_failure(server, block_root, peer, ctx).await;
                }
                // Nothing waits on a range prefetch, so a failure is only
                // worth a line: the blocks it rode alongside have their own
                // failure path, and any column this would have delivered is
                // still reachable by root once a block is held for it.
                Some(PendingRequestKind::ColumnRange {
                    start_slot,
                    end_slot,
                }) => {
                    debug!(
                        %peer,
                        start_slot,
                        end_slot,
                        "DataColumnsByRange request failed; columns fall back to the by-root path"
                    );
                }
                // The handshake is the only *tracked* request kind absent
                // here: every other outcome for a `Root`, `Range` or `Columns`
                // id is handled above, so reaching `None` means either the
                // untracked handshake or an id this process never recorded.
                // Only the former is worth acting on: a peer that has dropped
                // `status/1` refuses the stream outright, and without a
                // handshake it never enters the sync peer set at all.
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
        .new_block(block, BlockSource::Sync, BlockArrival::now())
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
        if let Err(err) = blockchain.new_block(
            SignedBeaconBlock::Lean(block),
            BlockSource::Sync,
            BlockArrival::now(),
        ) {
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
/// [`ReqRespProtocol::LeanBlocksByRoot`] unconditionally would do.
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
        server.connected_peers.keys().copied().collect()
    } else {
        let failed = failed.unwrap();
        server
            .connected_peers
            .keys()
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
        server.connected_peers.keys().copied().collect()
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
                ReqRespProtocol::LeanBlocksByRoot,
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

/// Record what columns `peer` custodies, given the custody group count it
/// advertised.
///
/// Both inputs are public: the count comes from the peer's `metadata/3` answer
/// or its ENR `cgc`, and the node id is recovered from the `PeerId` itself.
/// `custody_columns` is the same function the peer ran to decide what to keep,
/// so this reproduces its answer rather than approximating it.
///
/// An out-of-range count or an unreadable node id leaves no entry at all,
/// which reads as "unknown" and not as "custodies nothing" — see
/// [`columns_custodied_by`].
pub(crate) fn record_peer_custody(server: &mut P2PServer, peer: PeerId, custody_group_count: u64) {
    if !(constants::CUSTODY_REQUIREMENT..=constants::NUMBER_OF_CUSTODY_GROUPS)
        .contains(&custody_group_count)
    {
        debug!(%peer, custody_group_count, "Ignoring an out-of-range custody group count");
        return;
    }
    let Some(node_id) = node_id_from_peer_id(&peer) else {
        debug!(%peer, "Cannot recover a node id for this peer; its custody stays unknown");
        return;
    };
    match das::custody_columns(node_id, custody_group_count) {
        Ok(columns) => {
            trace!(%peer, custody_group_count, count = columns.len(), "Recorded peer custody");
            server.peer_custody.insert(peer, columns);
            // Republished here rather than only on connection events: this is
            // where a peer's custody actually becomes known, and for the
            // `metadata/3` path that is after it connected.
            server.refresh_custody_column_metrics();
        }
        Err(err) => debug!(%peer, custody_group_count, ?err, "Cannot compute this peer's custody"),
    }
}

/// The peers known to custody `column`, among those currently connected.
///
/// A peer with no entry is omitted rather than assumed: its custody is unknown,
/// and [`fetch_data_columns_from_peer`] falls back to the whole connected set
/// when this comes back empty, so an unknown peer is still reachable — just not
/// preferred over one we know holds the column.
pub(crate) fn columns_custodied_by(server: &P2PServer, column: u64) -> Vec<PeerId> {
    server
        .connected_peers
        .keys()
        .filter(|peer| {
            server
                .peer_custody
                .get(*peer)
                .is_some_and(|columns| columns.contains(&column))
        })
        .copied()
        .collect()
}

/// Split `columns` across the peers that custody them, so each request goes
/// somewhere it can actually be answered.
///
/// Returns one entry per chosen peer with the columns that peer holds, plus the
/// columns no connected peer is known to custody. Mirrors lighthouse's
/// `select_columns_by_range_peers_to_request`: pick per column, prefer the peer
/// carrying the fewest of this lookup's columns so one peer is not asked for
/// everything, and report the gap rather than papering over it.
fn group_columns_by_custody_peer(
    server: &P2PServer,
    columns: &[u64],
    exclude: &HashSet<PeerId>,
) -> (HashMap<PeerId, Vec<u64>>, Vec<u64>) {
    let mut by_peer: HashMap<PeerId, Vec<u64>> = HashMap::new();
    let mut uncovered = Vec::new();

    for &column in columns {
        let candidates: Vec<PeerId> = columns_custodied_by(server, column)
            .into_iter()
            .filter(|peer| !exclude.contains(peer))
            .collect();
        // `min_by_key` over the load already assigned in this same call, with
        // the peer id breaking ties so the choice is deterministic for a given
        // peer set rather than dependent on HashSet iteration order.
        let chosen = candidates
            .iter()
            .min_by_key(|peer| (by_peer.get(*peer).map_or(0, Vec::len), **peer));
        match chosen {
            Some(&peer) => by_peer.entry(peer).or_default().push(column),
            None => uncovered.push(column),
        }
    }

    (by_peer, uncovered)
}

/// Ask a connected peer for specific columns of `block_root`, mirroring
/// [`fetch_block_from_peer`]'s peer selection, dedup and retry bookkeeping
/// against `pending_column_requests` rather than `pending_root_requests`.
///
/// Beacon-only, unconditionally: unlike [`fetch_block_from_peer`], which has
/// to dispatch on `server.wire` because both chains serve a block-shaped
/// request, `DataColumnsByRoot` has no lean counterpart, so there is no wire
/// to branch on. `fetch_missing_columns` in `lib.rs` calls this directly for
/// the same reason.
pub async fn fetch_data_columns_from_peer(
    server: &mut P2PServer,
    block_root: H256,
    columns: Vec<u64>,
) -> bool {
    if server.connected_peers.is_empty() {
        debug!(%block_root, "Cannot fetch data columns: no connected peers");
        metrics::inc_data_column_fetch_failure("no_peers");
        return false;
    }

    // Same pool-narrowing-then-fallback shape as `fetch_block_from_peer`.
    let failed = server
        .pending_column_requests
        .get(&block_root)
        .map(|p| &p.failed_peers);
    let pool: Vec<_> = if failed.is_none_or(|f| f.is_empty()) {
        server.connected_peers.keys().copied().collect()
    } else {
        let failed = failed.unwrap();
        server
            .connected_peers
            .keys()
            .copied()
            .filter(|p| !failed.contains(p))
            .collect()
    };

    let pool = if pool.is_empty() {
        debug!(%block_root, "All peers failed for this lookup, retrying with full peer set");
        if let Some(pending) = server.pending_column_requests.get_mut(&block_root) {
            pending.failed_peers.clear();
        }
        server.connected_peers.keys().copied().collect()
    } else {
        pool
    };
    let excluded = server.connected_peers.len() - pool.len();

    // Aim each column at a peer that custodies it. Whatever no connected peer
    // is known to custody falls back to one random peer from the pool, which
    // is all this function could ever do before: it may hold the column and
    // simply not have told us its count yet.
    let exclude: HashSet<PeerId> = server
        .connected_peers
        .keys()
        .filter(|peer| !pool.contains(peer))
        .copied()
        .collect();
    let (mut by_peer, uncovered) = group_columns_by_custody_peer(server, &columns, &exclude);

    if !uncovered.is_empty() {
        match pool.choose(&mut rand::thread_rng()) {
            Some(&peer) => {
                debug!(
                    %block_root,
                    %peer,
                    count = uncovered.len(),
                    "No connected peer is known to custody these columns; asking one at random"
                );
                by_peer.entry(peer).or_default().extend(uncovered);
            }
            None => {
                debug!(%block_root, "Failed to select random peer");
                return false;
            }
        }
    }

    let mut sent_count = 0usize;
    for (peer, columns) in by_peer {
        let count = columns.len();
        let column_indices = match ColumnIndices::try_from(columns) {
            Ok(indices) => indices,
            Err(err) => {
                // A caller asking for more than one block's worth of columns is a
                // programming error on the chain-actor side, not a peer or wire
                // fault, so this does not retry.
                error!(%block_root, ?err, "Too many columns requested in one DataColumnsByRoot lookup");
                return false;
            }
        };
        let identifier = DataColumnsByRootIdentifier {
            block_root,
            columns: column_indices,
        };

        trace!(%peer, %block_root, excluded, count, "Sending DataColumnsByRoot request for missing columns");
        let Some(request_id) = server
            .swarm_handle
            .send_request(
                peer,
                Request::DataColumnsByRoot(vec![identifier]),
                ReqRespProtocol::DataColumnSidecarsByRoot,
            )
            .await
        else {
            debug!(%block_root, %peer, "Failed to send DataColumnsByRoot request (swarm adapter closed)");
            continue;
        };
        server
            .outbound_requests
            .insert(request_id, PendingRequestKind::Columns(block_root));
        sent_count += 1;
    }

    if sent_count == 0 {
        return false;
    }

    // `or_insert` rather than unconditional insert: a retry re-enters here
    // with the same root already tracked, and must not reset `attempts` back
    // to a fresh lookup's value.
    let pending =
        server
            .pending_column_requests
            .entry(block_root)
            .or_insert(PendingColumnRequest {
                columns,
                attempts: 1,
                failed_peers: HashSet::new(),
                in_flight: 0,
                last_asked: Instant::now(),
            });
    // Set rather than added to: every request from the previous round has
    // already reported back, since this round only starts once the last one
    // did (see `PendingColumnRequest::in_flight`).
    pending.in_flight = sent_count;
    // Each round's own timestamp, not the lookup's first: a ladder still
    // working through the peer set is alive, however long it has been running.
    pending.last_asked = Instant::now();

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
            ReqRespProtocol::LeanBlocksByRange,
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
///
/// A batch that needs columns is held back, blocks included, until every one
/// of this node's custody columns has a known custodian among the connected
/// peers, or until [`RANGE_BATCH_CUSTODY_WAIT`] runs out. Lighthouse's range
/// sync holds its batches back the same way, and for the same reason: blocks
/// and columns go out together, and a column request sent before custody is
/// known asks peers that do not keep the columns. Holding returns `true`, since
/// nothing failed. The batch is re-checked when a peer's metadata arrives (see
/// [`resume_range_batch_held_for_custody`]), on every call that would have sent
/// it anyway, and at the deadline.
async fn request_next_beacon_range_batch(server: &mut P2PServer, ctx: &Context<P2PServer>) -> bool {
    let Some((peer, batch)) = server
        .range_sync_state
        .as_ref()
        .and_then(RangeSyncState::next_batch)
    else {
        return true;
    };

    let uncovered = if range_batch_needs_columns(server, &batch) {
        custody_columns_without_known_custodian(server)
    } else {
        Vec::new()
    };
    let Some(state) = &mut server.range_sync_state else {
        return true;
    };
    let now = Instant::now();
    if !uncovered.is_empty() {
        match state.wait_for_custody(now) {
            CustodyWait::Started => {
                debug!(
                    start_slot = batch.start,
                    uncovered = uncovered.len(),
                    "Holding a range batch until its custody columns have known custodians"
                );
                send_after(
                    RANGE_BATCH_CUSTODY_WAIT,
                    ctx.clone(),
                    p2p_protocol::RetryBeaconRangeBatch,
                );
                return true;
            }
            CustodyWait::Waiting => return true,
            CustodyWait::Expired => {}
        }
    }
    if let Some(waited) = state.end_custody_wait(now) {
        // `info!` rather than `debug!`: this is the whole of a follower's
        // catch-up start being delayed, it happens about once per restart, and
        // production runs at `INFO`.
        info!(
            start_slot = batch.start,
            waited_ms = waited.as_millis() as u64,
            uncovered = uncovered.len(),
            "Sending a range batch held back for custody"
        );
    }

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

    // Pull the columns for the same span alongside the blocks, so they are
    // already stored when each block reaches the availability gate rather than
    // chased one root at a time after it has been held. Not gated on success:
    // a batch whose custody wait expired still syncs its blocks, and the
    // by-root path remains behind every one that turns out to be missing.
    request_beacon_data_columns_by_range(server, batch.start, planned).await;

    if let Some(state) = &mut server.range_sync_state {
        state.in_flight = true;
    }

    true
}

/// Re-check a range batch held back for custody, and send it if it may go now.
/// Nothing happens unless a batch is held.
///
/// Called at the batch's deadline and after every peer metadata answer, which
/// is where a peer's custody usually becomes known. The other place it is
/// learned, a peer's ENR `cgc`, is read on connection, and the `Status`
/// exchange that follows a connection re-checks the batch through
/// [`handle_status_response`] already.
///
/// Only a *held* batch: a range session also sits idle after a failed batch,
/// until the next `Status` answer restarts it, and restarting it from here
/// would change that behavior on every metadata answer.
pub(crate) async fn resume_range_batch_held_for_custody(
    server: &mut P2PServer,
    ctx: &Context<P2PServer>,
) {
    let held = server
        .range_sync_state
        .as_ref()
        .is_some_and(RangeSyncState::is_waiting_for_custody);
    if held {
        request_next_beacon_range_batch(server, ctx).await;
    }
}

/// Whether a range batch over `batch` asks for data columns at all.
fn range_batch_needs_columns(server: &P2PServer, batch: &std::ops::Range<u64>) -> bool {
    server
        .wire
        .beacon()
        .is_some_and(|wire| range_needs_columns(&wire.config, &wire.custody_columns, batch))
}

/// Whether blocks over `batch` can carry columns this node custodies: its last
/// slot is at or after fulu, and the custody set is not empty. Lighthouse's
/// range sync skips its custody-peer check before PeerDAS for the same reason:
/// a batch with no columns to fetch has no custodian to wait for.
fn range_needs_columns(
    config: &Config,
    custody_columns: &[u64],
    batch: &std::ops::Range<u64>,
) -> bool {
    let last_slot = batch.end.saturating_sub(1);
    !custody_columns.is_empty() && fork_at_slot(config, last_slot) >= ForkName::Fulu
}

/// This node's custody columns that no connected peer is known to custody.
fn custody_columns_without_known_custodian(server: &P2PServer) -> Vec<u64> {
    let Some(wire) = server.wire.beacon() else {
        return Vec::new();
    };
    columns_without_known_custodian(server, &wire.custody_columns)
}

/// The columns among `columns` that no connected peer is known to custody.
///
/// Counted through [`columns_custodied_by`], the same answer
/// [`request_beacon_data_columns_by_range`] aims its requests with, so a batch
/// is released exactly when that request would find a custodian for every
/// column.
fn columns_without_known_custodian(server: &P2PServer, columns: &[u64]) -> Vec<u64> {
    columns
        .iter()
        .copied()
        .filter(|&column| columns_custodied_by(server, column).is_empty())
        .collect()
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

/// Retire one failed attempt at fetching `block_root`'s missing columns.
///
/// Mirrors [`handle_fetch_failure`]'s funnel and invariant: every path that
/// ends an attempt must come through here, or `block_root` stays in
/// `pending_column_requests` and `fetch_missing_columns` folds every later
/// call into it rather than starting a second lookup, for the life of the
/// process.
///
/// `MAX_FETCH_RETRIES` attempts, each bounded by the request-response layer's
/// own per-request timeout and spaced by the doubling backoff below, is the
/// whole bound on how long a lookup persists; see the comment above that
/// constant's definition. A held block is reclaimed by finality on its own
/// schedule regardless, and the ladder stays well inside that window.
async fn handle_column_fetch_failure(
    server: &mut P2PServer,
    block_root: H256,
    peer: PeerId,
    ctx: &Context<P2PServer>,
) {
    let Some(pending) = server.pending_column_requests.get_mut(&block_root) else {
        return;
    };

    match retire_column_attempt(pending, peer) {
        ColumnAttemptOutcome::RoundIncomplete { in_flight } => {
            trace!(
                %block_root,
                %peer,
                in_flight,
                "One peer of this column lookup failed; waiting for the rest of the round"
            );
        }
        ColumnAttemptOutcome::GiveUp { attempts } => {
            error!(%block_root, %peer, attempts,
                   "Data column fetch failed after max retries, giving up");
            server.pending_column_requests.remove(&block_root);
            metrics::inc_data_column_fetch_failure("max_retries");
        }
        ColumnAttemptOutcome::Retry { attempts, backoff } => {
            debug!(%block_root, %peer, attempts, ?backoff, "Data column fetch failed, scheduling retry");
            send_after(
                backoff,
                ctx.clone(),
                p2p_protocol::RetryDataColumnFetch { block_root },
            );
        }
    }
}

/// What a failed request means for the lookup it belonged to.
#[derive(Debug, PartialEq, Eq)]
enum ColumnAttemptOutcome {
    /// Other requests from this same attempt are still open, so the attempt
    /// has no outcome yet.
    RoundIncomplete { in_flight: usize },
    /// The ladder is exhausted; the caller retires the lookup.
    GiveUp { attempts: u32 },
    /// The attempt is spent and another is due after `backoff`.
    Retry { attempts: u32, backoff: Duration },
}

/// Charge `peer`'s failure against `pending` and say what follows.
///
/// Split out from [`handle_column_fetch_failure`] so the round arithmetic can
/// be tested without an actor context: everything the decision depends on is in
/// `pending`, and everything it causes (the store mutation, the metric, the
/// timer) is the caller's.
///
/// One attempt is one round, however many peers it was split across. While any
/// request of the round is still open, a sibling's failure is not the attempt's
/// outcome: the round may still be answered, and treating each failure as its
/// own attempt would burn the ladder several times faster *and* schedule one
/// fan-out per failure, which squares with every retry.
fn retire_column_attempt(pending: &mut PendingColumnRequest, peer: PeerId) -> ColumnAttemptOutcome {
    pending.failed_peers.insert(peer);
    pending.in_flight = pending.in_flight.saturating_sub(1);

    if pending.in_flight > 0 {
        return ColumnAttemptOutcome::RoundIncomplete {
            in_flight: pending.in_flight,
        };
    }

    if pending.attempts >= MAX_FETCH_RETRIES {
        return ColumnAttemptOutcome::GiveUp {
            attempts: pending.attempts,
        };
    }

    let backoff_ms = INITIAL_BACKOFF_MS * BACKOFF_MULTIPLIER.pow(pending.attempts - 1);
    let attempts = pending.attempts;
    pending.attempts += 1;

    ColumnAttemptOutcome::Retry {
        attempts,
        backoff: Duration::from_millis(backoff_ms),
    }
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
///
/// `debug!` rather than `trace!`: this is a peer stating why it is dropping us,
/// which is the one disconnect signal that is not inferred, and the follower
/// runs at `INFO` in production where a `trace!` reaches nobody. The counter is
/// what makes it readable without raising the level at all.
fn handle_goodbye(peer: PeerId, goodbye: Goodbye) {
    let label = goodbye.reason_label();
    metrics::inc_peer_goodbye(label);
    debug!(%peer, reason = goodbye.reason, label, "Peer said goodbye");
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
async fn handle_status_response(
    server: &mut P2PServer,
    peer: PeerId,
    status: BeaconStatus,
    ctx: &Context<P2PServer>,
) {
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

    request_next_beacon_range_batch(server, ctx).await;
    trace!(%peer, "Beacon long-range sync: using BeaconBlocksByRange");
}

/// Record a pong. Nothing is driven off one yet.
fn handle_pong(peer: PeerId, ping: Ping) {
    debug!(%peer, peer_seq_number = ping.seq_number, "Pong received");
}

/// Record a peer's metadata. Nothing is driven off one yet.
/// Take delivery of a peer's `MetaData`, and learn its custody from it.
///
/// Only v3 carries `custody_group_count`; v1 and v2 predate data availability
/// sampling and say nothing about it, so a peer answering in those versions
/// keeps whatever its ENR seeded and is otherwise treated as unknown. That is
/// the same graceful handling lighthouse gives a metadata/v2 peer.
fn handle_metadata_response(server: &mut P2PServer, peer: PeerId, metadata: BeaconMetaData) {
    debug!(%peer, "Peer metadata received");
    if let BeaconMetaData::V3(v3) = metadata {
        record_peer_custody(server, peer, v3.custody_group_count);
    }
}

/// The beacon store this node can serve blocks and data column sidecars out
/// of, or a refusal.
///
/// Two things have to hold before a block or data column sidecar request can
/// be answered: this process speaks the beacon wire at all, and the data
/// directory behind it actually holds a beacon chain. The anchor makes the
/// second true for an ordinary `ethlambda beacon` run, so this is a guard
/// against a lean directory rather than the common path. It is a refusal
/// rather than an empty answer because the difference matters to the peer:
/// `RESOURCE_UNAVAILABLE` is the spec's own code for a peer "unable to reply
/// to block requests" (data column sidecar requests name the same code for
/// the same reason), where an empty stream claims we looked and had nothing,
/// and `INVALID_REQUEST` would blame the asker for a request that was fine.
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

/// Answer `data_column_sidecars_by_root/1` with whichever of the named
/// sidecars this node custodies.
///
/// The counterpart of [`handle_beacon_blocks_by_root_request`], and the same
/// per-item leniency: a column this node never custodied is left out rather
/// than answered with an error, since a peer asking for it has no way to know
/// which of a custody set actually arrived here. The spec's own words for
/// this are "Clients MUST respond with at least one sidecar, if they have
/// it." An identifier naming a root this node holds no header for is skipped
/// whole, for the same reason a missing root is skipped on the block path.
async fn handle_data_column_sidecars_by_root_request(
    server: &mut P2PServer,
    peer: PeerId,
    identifiers: Vec<DataColumnsByRootIdentifier>,
    channel: ResponseChannel<Response>,
) {
    let Some(channel) = beacon_block_store_or_refuse(server, peer, channel) else {
        return;
    };

    let requested: usize = identifiers
        .iter()
        .map(|identifier| identifier.columns.len())
        .sum();
    let mut sidecars = Vec::new();
    for identifier in &identifiers {
        // The store keys a sidecar by slot, root and column, but the wire
        // names only the root: the slot has to be recovered from whatever
        // this node holds under that root before the columns can be looked
        // up at all. A root with no block is not this node's to answer for.
        //
        // Through `block_entry`, which decodes per chain, and not
        // `Store::get_block_header`, which is lean-only: this handler only
        // ever runs on a beacon store, and that table holds the whole signed
        // block there, so the lean accessor reads a whole block as a fixed-size
        // header and panics the P2P actor. A peer's request must not be able
        // to do that.
        let Some((slot, _)) = server.store.block_entry(&identifier.block_root) else {
            continue;
        };
        for &column in identifier.columns.iter() {
            let Ok(Some(encoded)) =
                server
                    .store
                    .get_data_column_sidecar(slot, &identifier.block_root, column)
            else {
                continue;
            };
            match decode_data_column_sidecar(&encoded) {
                Ok(sidecar) => sidecars.push(sidecar),
                Err(err) => error!(
                    %peer,
                    slot,
                    column,
                    %err,
                    "Stored data column sidecar failed to decode"
                ),
            }
        }
    }

    trace!(
        %peer,
        requested,
        found = sidecars.len(),
        "Responding to DataColumnSidecarsByRoot request"
    );

    respond(
        server,
        channel,
        ResponsePayload::DataColumnSidecars(sidecars),
    );
}

/// Answer `data_column_sidecars_by_range/1` from the slot window this node
/// has custodied.
///
/// The counterpart of [`handle_beacon_blocks_by_range_request`]: the same
/// `count` clamp to [`MAX_REQUEST_BLOCKS_DENEB`], which keeps the answer
/// within `max_request_data_column_sidecars()` sidecars regardless of
/// how many columns were asked for. What differs is the floor. A window this
/// node's canonical chain simply skipped is an empty answer, business as
/// usual; a `start_slot` before [`ethlambda_storage::Store::anchor_slot`]
/// cannot be served from any point in the response onward, since this node's
/// chain does not reach back that far at all. `RESOURCE_UNAVAILABLE` is the
/// code the specification names for exactly that peer, and the honest answer
/// for a node that started custodying at a checkpoint rather than at genesis.
///
/// The floor is where this directory's chain begins rather than the lowest
/// slot a sidecar was actually written at, so it matches the
/// `earliest_available_slot` this node advertises in `Status`. The two differ
/// only in the window between the anchor and the first column this node
/// custodied, where a request is answered with an empty list rather than
/// refused; a node that range-synced has already backfilled columns alongside
/// blocks across that window, so it is narrow in practice and never claims
/// data the node does not hold.
async fn handle_data_column_sidecars_by_range_request(
    server: &mut P2PServer,
    peer: PeerId,
    request: DataColumnsByRangeRequest,
    channel: ResponseChannel<Response>,
) {
    let Some(channel) = beacon_block_store_or_refuse(server, peer, channel) else {
        return;
    };

    if request.count == 0 {
        refuse(
            server,
            channel,
            ResponseCode::INVALID_REQUEST,
            "invalid DataColumnSidecarsByRange request",
        );
        return;
    }

    let earliest = server.store.anchor_slot();
    if request.start_slot < earliest {
        debug!(
            %peer,
            start_slot = request.start_slot,
            earliest,
            "DataColumnSidecarsByRange request starts before what this node has custodied"
        );
        refuse(
            server,
            channel,
            ResponseCode::RESOURCE_UNAVAILABLE,
            "requested range starts before this node's earliest custodied slot",
        );
        return;
    }

    let count = request.count.min(MAX_REQUEST_BLOCKS_DENEB);
    let end_slot = request.start_slot.saturating_add(count);
    let columns = request.columns.to_vec();
    let sidecars: Vec<_> = server
        .store
        .data_column_sidecars_in_range(request.start_slot, end_slot, &columns)
        .inspect_err(|err| {
            warn!(
                start_slot = request.start_slot,
                end_slot,
                ?err,
                "Failed to get data column sidecars by slot range"
            )
        })
        .unwrap_or_default()
        .into_iter()
        .filter_map(|encoded| {
            decode_data_column_sidecar(&encoded)
                .inspect_err(
                    |err| error!(%peer, %err, "Stored data column sidecar failed to decode"),
                )
                .ok()
        })
        .collect();

    trace!(
        %peer,
        start_slot = request.start_slot,
        count = request.count,
        served = count,
        found = sidecars.len(),
        "Responding to DataColumnSidecarsByRange request"
    );

    respond(
        server,
        channel,
        ResponsePayload::DataColumnSidecars(sidecars),
    );
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
) -> Option<ReqRespRequestId> {
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
            ReqRespProtocol::BeaconBlocksByRange,
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

/// Ask the peers that custody them for this node's columns over a slot range.
///
/// The companion of [`request_beacon_blocks_by_range`], sent for the same span
/// at the same time. The specification names this protocol for exactly this:
/// "`DataColumnSidecarsByRange` is primarily used to sync data columns that may
/// have been missed on gossip and to sync within the
/// `MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS` window", which is what a
/// follower backfilling from a checkpoint anchor is doing.
///
/// Without it the only source of a historical column was the by-root lookup a
/// block triggers *after* it has already arrived and been held, one block at a
/// time, against a peer chosen without regard to custody. Prefetching here
/// means the columns are usually already stored by the time their block is
/// checked, so the gate passes on the first try and the by-root path is left
/// for the genuine gaps.
///
/// Best effort by construction: it sends what it can, and the return value says
/// only whether anything went out. A range sync batch does not depend on this
/// succeeding, because a missing column still has the by-root path behind it.
/// Up to `limit` connected peers this node has recorded no custody for.
///
/// A peer lands here until its `metadata/3` answer or its ENR `cgc` has been
/// read, and some peers never leave: one answering `metadata/3` on a version
/// this node's codec rejects supplies nothing either way. "No opinion" is not
/// "custodies nothing", so these are the peers worth a speculative ask when no
/// known custodian covers a column — and the only ones, since a peer that has
/// said what it keeps has already answered the question.
fn peers_of_unknown_custody(server: &P2PServer, limit: usize) -> Vec<PeerId> {
    server
        .connected_peers
        .keys()
        .filter(|peer| !server.peer_custody.contains_key(peer))
        .copied()
        .take(limit)
        .collect()
}

/// Ask for this node's custody columns across a span of slots.
///
/// Sent by [`request_next_beacon_range_batch`] alongside every
/// `BeaconBlocksByRange` it plans, over the same span, so a synced block's
/// columns are already stored when it reaches the availability gate rather
/// than chased one root at a time after it has been held. Not driven from
/// outside this crate: a caller there has a block root, not a span, and the
/// span worth asking for is the one this crate is already syncing.
pub(crate) async fn request_beacon_data_columns_by_range(
    server: &mut P2PServer,
    start_slot: u64,
    count: u64,
) -> bool {
    let Some(wire) = server.wire.beacon() else {
        return false;
    };
    let columns = wire.custody_columns.clone();
    // The same ceiling `request_beacon_blocks_by_range` applies to its own
    // count, so the two requests cover exactly one span and this one cannot
    // ask for columns of slots whose blocks were never requested.
    let count = count.min(MAX_REQUEST_BLOCKS_DENEB);
    if columns.is_empty() || count == 0 {
        return false;
    }

    // No exclusions: unlike a by-root retry, this has no failed-peer history to
    // avoid, and a peer that cannot answer simply returns nothing.
    let (mut by_peer, uncovered) = group_columns_by_custody_peer(server, &columns, &HashSet::new());
    if !uncovered.is_empty() {
        // "Uncovered" means no peer is *known* to custody these, and custody is
        // only known once a peer's `metadata/3` answer or its ENR `cgc` has
        // been recorded. A peer that has told us neither is not a peer that
        // lacks the column; it is a peer this node cannot aim at yet, and on
        // mainnet there is always a handful of those — freshly connected, or
        // answering `metadata/3` on a version this node rejects.
        //
        // So the uncovered columns go to a couple of them, which is the same
        // bet `fetch_data_columns_from_peer` makes for the same reason. Not to
        // a peer already known to custody something else: that one has told us
        // what it keeps, and asking it for what it does not keep really is
        // waste. Bounded rather than broadcast, since a range request is
        // megabytes of answer when it does land.
        let unknown = peers_of_unknown_custody(server, UNKNOWN_CUSTODY_RANGE_PEERS);
        debug!(
            start_slot,
            count,
            uncovered = uncovered.len(),
            asked = unknown.len(),
            "No connected peer is known to custody some of this node's columns for the range"
        );
        for peer in unknown {
            by_peer
                .entry(peer)
                .or_default()
                .extend(uncovered.iter().copied());
        }
    }

    let end_slot = start_slot.saturating_add(count - 1);
    let mut sent = false;
    for (peer, columns) in by_peer {
        let Ok(column_indices) = ColumnIndices::try_from(columns) else {
            // This node's own custody set is bounded by NUMBER_OF_COLUMNS, so
            // a subset of it cannot overflow the request's list.
            error!("This node's custody set does not fit one DataColumnsByRange request");
            continue;
        };
        let request = DataColumnsByRangeRequest {
            start_slot,
            count,
            columns: column_indices,
        };
        trace!(%peer, start_slot, count, "Sending DataColumnsByRange request");
        let Some(request_id) = server
            .swarm_handle
            .send_request(
                peer,
                Request::DataColumnsByRange(request),
                ReqRespProtocol::DataColumnSidecarsByRange,
            )
            .await
        else {
            debug!(%peer, "Failed to send DataColumnsByRange request (swarm adapter closed)");
            continue;
        };
        server.outbound_requests.insert(
            request_id,
            PendingRequestKind::ColumnRange {
                start_slot,
                end_slot,
            },
        );
        sent = true;
    }

    sent
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
) -> Option<ReqRespRequestId> {
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
            ReqRespProtocol::BeaconBlocksByRoot,
        )
        .await?;
    server
        .outbound_requests
        .insert(request_id, PendingRequestKind::Root(root));
    Some(request_id)
}

/// Take delivery of a `DataColumnsByRoot` response and run every sidecar it
/// carried through the chain checks (`beacon::column_checks`), which send the
/// chain actor the ones that pass. The specification requires a sidecar
/// obtained by any other means to be treated as if it had arrived on gossip;
/// the chain checks are gossip's rules less the two that only mean something
/// on a topic (the subnet and the seen cache), and the chain actor keeps what
/// reaches it without checking it again, so they are the only checks a
/// fetched sidecar gets.
///
/// Unlike a block-by-root answer, which names exactly one document that
/// either matches the requested root or doesn't, the specification permits a
/// peer to return fewer sidecars than were asked for ("Clients MUST respond
/// with at least one sidecar, if they have it" — not with every one), so a
/// non-empty answer is treated as this lookup's success regardless of
/// whether it is the full requested set. Whatever is still missing is the
/// next task's concern: it is driven by a fresh `fetch_block` call naming
/// what is still missing once the held block is re-checked, not by this
/// function retrying for the remainder. Zero sidecars is the one case that is
/// not success: it means this peer had none of what was asked, and is charged
/// as a failed attempt the same way an empty `BlocksByRoot` answer is, backed
/// off and retried against another peer.
/// Take delivery of a `DataColumnsByRange` prefetch and forward what it carries.
///
/// No failure handling, unlike the by-root path: nothing is waiting on this
/// answer. An empty or short response means those columns simply arrive later
/// (or by root, when a block turns out to need one), not that an attempt was
/// spent. Retrying here would re-request a whole range over a single gap.
///
/// A sidecar outside the requested span is dropped on its own rather than
/// failing the batch, the same way a block outside its range is: the rest of
/// the answer may still be what was asked for. Every other check is the chain
/// checks' (`beacon::column_checks`), the same ones a fetched-by-root sidecar
/// passes through.
async fn handle_data_column_sidecars_range_response(
    server: &mut P2PServer,
    peer: PeerId,
    start_slot: u64,
    end_slot: u64,
    sidecars: Vec<DataColumnSidecar>,
) {
    let received = sidecars.len();
    trace!(%peer, start_slot, end_slot, received, "Received DataColumnsByRange response");

    if server.blockchain.is_none() {
        debug!(%peer, "No blockchain handler available");
        return;
    }

    let in_range: Vec<DataColumnSidecar> = sidecars
        .into_iter()
        .filter(|sidecar| {
            let slot = sidecar.signed_block_header.message.slot;
            let keep = slot >= start_slot && slot <= end_slot;
            if !keep {
                debug!(%peer, slot, start_slot, end_slot, "Dropping an out-of-range data column sidecar");
            }
            keep
        })
        .collect();
    if in_range.is_empty() {
        return;
    }

    // One batch through the checks, which forward what passes as one
    // message. A range answer is the largest batch this node ever takes
    // delivery of, and it arrives precisely when the chain actor is busiest
    // draining a backlog, so a message per sidecar would put that many
    // mailbox hops between the answer and the imports waiting on it.
    column_checks::check_and_forward(server, in_range);
}

async fn handle_data_column_sidecars_response(
    server: &mut P2PServer,
    peer: PeerId,
    block_root: H256,
    sidecars: Vec<DataColumnSidecar>,
    ctx: &Context<P2PServer>,
) {
    let received = sidecars.len();
    trace!(%peer, %block_root, received, "Received DataColumnsByRoot response");

    if sidecars.is_empty() {
        debug!(%peer, %block_root, "DataColumnsByRoot response carried no sidecars");
        handle_column_fetch_failure(server, block_root, peer, ctx).await;
        return;
    }

    // The lookup is done, whether or not every requested column arrived; see
    // this function's own doc comment for why a partial answer still retires
    // the entry rather than triggering a same-lookup retry for the rest.
    server.pending_column_requests.remove(&block_root);

    if server.blockchain.is_none() {
        debug!(%peer, %block_root, "No blockchain handler available");
        return;
    }

    column_checks::check_and_forward(server, sidecars);
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
    ctx: &Context<P2PServer>,
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
        let _ = blockchain
            .new_block(block, BlockSource::Sync, BlockArrival::now())
            .inspect_err(
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
    request_next_beacon_range_batch(server, ctx).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ConnectionDirection;
    use ethlambda_storage::{ForkCheckpoints, backend::InMemoryBackend};
    use ethlambda_types::constants::DEFAULT_MILLISECONDS_PER_SLOT;
    use ethlambda_types::enr::EnrForkId;
    use ethlambda_types::{
        block::{Block, BlockBody, MultiMessageAggregate},
        state::State,
    };
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    /// A real, unconnected `P2PServer`: a loopback swarm bound to an
    /// OS-assigned port, discv5 the same way, and no bootnodes or peers. Ports
    /// `0` throughout, so this cannot collide with a running node or a
    /// sibling test.
    ///
    /// This is the smallest server `fetch_data_columns_from_peer` can run
    /// against: unlike `handle_fetch_failure` and its beacon counterpart,
    /// which also take a live actor `Context` (and which the crate has never
    /// had a harness for; see 64a6bce9), the fetch path only touches
    /// `&mut P2PServer`, so building one real server is the whole cost of
    /// testing it.
    async fn unconnected_server() -> P2PServer {
        let built = crate::build_swarm(crate::SwarmConfig {
            node_key: vec![3u8; 32],
            bootnodes: Vec::new(),
            listening_socket: "127.0.0.1:0".parse().expect("valid socket"),
            target_peers: crate::discovery::DEFAULT_DISCOVERY_TARGET_PEERS,
            wire: crate::WireConfig::Lean(crate::LeanWireConfig {
                validator_ids: Vec::new(),
                attestation_committee_count: 1,
                subscription_subnets: HashSet::new(),
                milliseconds_per_slot: DEFAULT_MILLISECONDS_PER_SLOT,
            }),
        })
        .expect("swarm builds");

        let (_swarm_stream, swarm_handle) =
            crate::swarm_adapter::start_swarm_adapter(built.swarm, HashMap::new());

        let discovery = crate::discovery::spawn_discovery(crate::discovery::DiscoverySpawnConfig {
            node_key: secp256k1::SecretKey::new(&mut rand::rngs::OsRng)
                .secret_bytes()
                .to_vec(),
            bind_ip: IpAddr::from(Ipv4Addr::LOCALHOST),
            discovery_port: 0,
            p2p_port: 0,
            subscription_subnets: HashSet::new(),
            attestation_committee_count: 1,
            bootnodes: Vec::new(),
            advertise_ip: None,
            target_peers: 0,
            fork_id: EnrForkId::local(),
            custody_group_count: None,
        })
        .await
        .expect("discovery spawns");

        let backend = Arc::new(InMemoryBackend::new());
        let store = Store::from_anchor_state(
            backend,
            State::from_genesis(0, vec![]),
            DEFAULT_MILLISECONDS_PER_SLOT,
        );
        // Read before `built.wire` moves into the server below; this is a
        // lean wire, so `seen_attestations_capacity` floors it to one subnet.
        let backbone_attestation_subnets = built
            .wire
            .beacon()
            .map_or(0, |beacon| beacon.attestation_subnets.len());

        P2PServer {
            swarm_handle,
            store,
            blockchain: None,
            wire: built.wire,
            connected_peers: HashMap::new(),
            peer_custody: HashMap::new(),
            pending_root_requests: HashMap::new(),
            pending_column_requests: HashMap::new(),
            outbound_requests: HashMap::new(),
            range_sync_state: None,
            beacon_fetched_through: 0,
            bootnode_addrs: HashMap::new(),
            node_names: HashMap::new(),
            discovery: Some(crate::discovery::dial::DiscoveryState::new(
                discovery,
                built.local_peer_id,
            )),
            seen_blocks: ethlambda_state_transition::beacon::gossip::SeenBlocks::new(
                crate::SEEN_BLOCKS_CAPACITY,
            ),
            seen_columns: ethlambda_state_transition::beacon::gossip::SeenColumns::new(
                crate::SEEN_COLUMNS_CAPACITY,
            ),
            seen_aggregates:
                ethlambda_state_transition::beacon::gossip::aggregate::SeenAggregates::new(
                    crate::SEEN_AGGREGATES_CAPACITY,
                    crate::SEEN_AGGREGATES_CAPACITY,
                ),
            seen_attestations:
                ethlambda_state_transition::beacon::gossip::attestation::SeenAttestations::new(
                    crate::seen_attestations_capacity(backbone_attestation_subnets),
                ),
            gossip_validation_permits: std::sync::Arc::new(tokio::sync::Semaphore::new(
                crate::GOSSIP_VALIDATION_PERMITS,
            )),
            column_check_permits: std::sync::Arc::new(tokio::sync::Semaphore::new(
                crate::COLUMN_CHECK_PERMITS,
            )),
            attestation_validation_permits: std::sync::Arc::new(tokio::sync::Semaphore::new(
                crate::ATTESTATION_VALIDATION_PERMITS,
            )),
            attestation_pool: Default::default(),
            aggregator_subnets: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn fetch_data_columns_with_no_peers_is_dropped_and_counted() {
        let mut server = unconnected_server().await;
        let block_root = H256::repeat_byte(0xAB);

        let before = metrics::data_column_fetch_failures_total("no_peers");

        // Must not panic despite there being nobody to ask, and must not
        // leave a `pending_column_requests` entry behind: nothing will ever
        // answer a request that was never sent, so an entry here would be
        // stuck forever, deduplicating away every future retry.
        let sent = fetch_data_columns_from_peer(&mut server, block_root, vec![1, 2, 3]).await;

        assert!(!sent, "no connected peers means nothing can be sent");
        assert!(
            server.pending_column_requests.is_empty(),
            "a send that never happened must not be tracked as pending"
        );
        assert_eq!(
            metrics::data_column_fetch_failures_total("no_peers"),
            before + 1,
            "the no-peers path must count itself as a failed attempt"
        );
    }

    #[tokio::test]
    async fn columns_are_grouped_onto_the_peers_that_custody_them() {
        let mut server = unconnected_server().await;
        let holder_of_1 = PeerId::random();
        let holder_of_2 = PeerId::random();
        let holder_of_both = PeerId::random();
        for peer in [holder_of_1, holder_of_2, holder_of_both] {
            server
                .connected_peers
                .insert(peer, ConnectionDirection::Inbound);
        }
        server.peer_custody.insert(holder_of_1, vec![1]);
        server.peer_custody.insert(holder_of_2, vec![2]);
        server.peer_custody.insert(holder_of_both, vec![1, 2]);

        let (by_peer, uncovered) = group_columns_by_custody_peer(&server, &[1, 2], &HashSet::new());

        // Column 3 is nobody's, so it is reported rather than pinned on a peer
        // that would answer empty.
        let (_, uncovered_3) = group_columns_by_custody_peer(&server, &[3], &HashSet::new());
        assert_eq!(uncovered_3, vec![3]);

        assert!(uncovered.is_empty());
        // Every column went somewhere that holds it.
        for (peer, columns) in &by_peer {
            let custody = &server.peer_custody[peer];
            assert!(columns.iter().all(|column| custody.contains(column)));
        }
        let total: usize = by_peer.values().map(Vec::len).sum();
        assert_eq!(total, 2);
    }

    #[tokio::test]
    async fn a_peer_whose_custody_is_unknown_is_never_assumed_to_hold_a_column() {
        let mut server = unconnected_server().await;
        let unknown = PeerId::random();
        server
            .connected_peers
            .insert(unknown, ConnectionDirection::Inbound);

        // Absent must read as "no opinion", not "custodies nothing" and not
        // "custodies everything": the caller has its own random fallback for
        // this, and silently treating unknown as a holder would put us back to
        // asking arbitrary peers for specific columns.
        let (by_peer, uncovered) = group_columns_by_custody_peer(&server, &[7], &HashSet::new());

        assert!(by_peer.is_empty());
        assert_eq!(uncovered, vec![7]);
    }

    #[tokio::test]
    async fn a_range_prefetch_falls_back_only_to_peers_that_have_said_nothing() {
        // The follower stalled on mainnet with a block whose columns no known
        // custodian held: the by-root path asks someone anyway, the range path
        // asked no one, and the columns only arrived when the peer set churned.
        // A peer that has told us what it keeps has answered the question; one
        // that has told us nothing has not, and is the only worthwhile guess.
        let mut server = unconnected_server().await;
        let silent = PeerId::random();
        let known = PeerId::random();
        server
            .connected_peers
            .insert(silent, ConnectionDirection::Inbound);
        server
            .connected_peers
            .insert(known, ConnectionDirection::Inbound);
        server.peer_custody.insert(known, vec![4]);

        assert_eq!(peers_of_unknown_custody(&server, 2), vec![silent]);
    }

    #[tokio::test]
    async fn the_unknown_custody_fallback_asks_no_more_peers_than_it_is_allowed() {
        let mut server = unconnected_server().await;
        for _ in 0..5 {
            server
                .connected_peers
                .insert(PeerId::random(), ConnectionDirection::Inbound);
        }

        // A range answer is megabytes when it lands, so the speculative ask is
        // a couple of peers, not every peer that has said nothing.
        assert_eq!(peers_of_unknown_custody(&server, 2).len(), 2);
    }

    #[tokio::test]
    async fn a_column_is_covered_only_by_a_connected_peer_known_to_keep_it() {
        // A fresh follower's first range batch went out with two peers and
        // almost no custody known, and came back with no columns. The batch is
        // now held until this says every custody column has somewhere to go,
        // so it must not count a peer that has said nothing, nor one that has
        // left.
        let mut server = unconnected_server().await;
        let keeps_4 = PeerId::random();
        let silent = PeerId::random();
        let departed = PeerId::random();
        server
            .connected_peers
            .insert(keeps_4, ConnectionDirection::Inbound);
        server
            .connected_peers
            .insert(silent, ConnectionDirection::Inbound);
        server.peer_custody.insert(keeps_4, vec![4]);
        server.peer_custody.insert(departed, vec![5]);

        assert_eq!(
            columns_without_known_custodian(&server, &[4, 5, 6]),
            vec![5, 6]
        );
    }

    #[test]
    fn only_a_range_reaching_fulu_waits_for_column_custodians() {
        let config = Config::mainnet();
        let first_fulu_slot =
            config.fulu_fork_epoch * ethlambda_types::beacon::preset::SLOTS_PER_EPOCH;
        let custody = [4, 5];

        // Every slot before fulu: no columns exist, so nothing to wait for.
        assert!(!range_needs_columns(
            &config,
            &custody,
            &(first_fulu_slot - 64..first_fulu_slot)
        ));
        // A batch whose last slot is fulu's first does fetch columns.
        assert!(range_needs_columns(
            &config,
            &custody,
            &(first_fulu_slot - 63..first_fulu_slot + 1)
        ));
        // A node custodying nothing never asks for columns.
        assert!(!range_needs_columns(
            &config,
            &[],
            &(first_fulu_slot..first_fulu_slot + 64)
        ));
    }

    #[tokio::test]
    async fn an_excluded_peer_is_not_chosen_even_when_it_custodies_the_column() {
        let mut server = unconnected_server().await;
        let failed = PeerId::random();
        server
            .connected_peers
            .insert(failed, ConnectionDirection::Inbound);
        server.peer_custody.insert(failed, vec![4]);

        // The exclusion set is how a retry avoids the peer that just failed;
        // custody must not override it, or a retry would loop on one peer.
        let (by_peer, uncovered) =
            group_columns_by_custody_peer(&server, &[4], &HashSet::from([failed]));

        assert!(by_peer.is_empty());
        assert_eq!(uncovered, vec![4]);
    }

    #[test]
    fn a_split_lookup_spends_one_attempt_however_many_peers_it_used() {
        // Three requests open for one root, the shape custody-aware splitting
        // produces. Before `in_flight`, each failure was its own attempt and
        // scheduled its own fan-out, so one unanswered lookup against eight
        // custodians became eight retries, then sixty-four.
        let mut pending = PendingColumnRequest {
            columns: vec![1, 2, 3],
            attempts: 1,
            failed_peers: HashSet::new(),
            in_flight: 3,
            last_asked: Instant::now(),
        };

        assert_eq!(
            retire_column_attempt(&mut pending, PeerId::random()),
            ColumnAttemptOutcome::RoundIncomplete { in_flight: 2 }
        );
        assert_eq!(
            retire_column_attempt(&mut pending, PeerId::random()),
            ColumnAttemptOutcome::RoundIncomplete { in_flight: 1 }
        );
        assert_eq!(pending.attempts, 1, "the round's attempt is not spent yet");

        // Only the last failure of the round is the attempt's outcome, and it
        // schedules exactly one retry.
        assert_eq!(
            retire_column_attempt(&mut pending, PeerId::random()),
            ColumnAttemptOutcome::Retry {
                attempts: 1,
                backoff: Duration::from_millis(INITIAL_BACKOFF_MS),
            }
        );
        assert_eq!(pending.attempts, 2);
    }

    #[test]
    fn a_column_lookup_gives_up_once_the_ladder_is_exhausted() {
        let mut pending = PendingColumnRequest {
            columns: vec![1],
            attempts: MAX_FETCH_RETRIES,
            failed_peers: HashSet::new(),
            in_flight: 1,
            last_asked: Instant::now(),
        };

        assert_eq!(
            retire_column_attempt(&mut pending, PeerId::random()),
            ColumnAttemptOutcome::GiveUp {
                attempts: MAX_FETCH_RETRIES
            }
        );
    }

    #[test]
    fn an_out_of_range_custody_group_count_records_nothing() {
        // A count outside CUSTODY_REQUIREMENT..=NUMBER_OF_CUSTODY_GROUPS
        // describes no custody set the spec defines. Recording a guess would
        // aim requests at a peer that never agreed to hold those columns.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let mut server = runtime.block_on(unconnected_server());
        let peer = PeerId::random();

        record_peer_custody(&mut server, peer, 0);
        assert!(!server.peer_custody.contains_key(&peer));

        record_peer_custody(&mut server, peer, constants::NUMBER_OF_CUSTODY_GROUPS + 1);
        assert!(!server.peer_custody.contains_key(&peer));
    }

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
