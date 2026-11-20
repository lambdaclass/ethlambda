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

use ethlambda_network_api::{BlockAnnouncement, BlockArrival, BlockSource};
use ethlambda_storage::{Chain, Store};
use libp2p::{PeerId, request_response};
use rand::seq::SliceRandom;
use spawned_concurrency::tasks::{Context, send_after};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::{debug, error, info, trace, warn};

use ethlambda_state_transition::beacon::das;
use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::constants;
use ethlambda_types::beacon::containers::fulu::{ColumnIndices, DataColumnsByRootIdentifier};
use ethlambda_types::beacon::containers::{DataColumnSidecar, SignedBeaconBlock};
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::checkpoint::Checkpoint;
use ethlambda_types::primitives::HashTreeRoot as _;
use ethlambda_types::{block::SignedBlock, primitives::H256};

pub(crate) use super::envelope_client::release_envelope_gate;
use super::envelope_client::{
    handle_envelope_fetch_failure, handle_envelopes_by_range_response,
    handle_envelopes_by_root_response, request_beacon_envelopes_by_range,
};
use super::{
    Request, Response, ResponsePayload, envelopes,
    messages::{ResponseCode, error_message},
};
use crate::beacon::BeaconWire;
use crate::beacon::column_checks::{self, ColumnVerdict};
use crate::beacon::decode::fork_at_slot;
use crate::beacon::handler::{self as beacon_handler, StatusVersion};
use crate::beacon::messages::{
    BeaconMetaData, BeaconStatus, DataColumnsByRangeRequest, Goodbye, Ping,
};
use crate::beacon::protocols::{
    MAX_REQUEST_BLOCKS as MAX_BEACON_REQUEST_BLOCKS, MAX_REQUEST_BLOCKS_DENEB,
};
use crate::beacon::transition;
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
use ethlambda_types::time::unix_now_ms;
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
                    Request::ExecutionPayloadEnvelopesByRange(request) => {
                        trace!(
                            kind = "execution_payload_envelopes_by_range_request",
                            peer_count, "P2P message received"
                        );
                        envelopes::handle_execution_payload_envelopes_by_range_request(
                            server, peer, request, channel,
                        )
                        .await;
                    }
                    Request::ExecutionPayloadEnvelopesByRoot(roots) => {
                        trace!(
                            kind = "execution_payload_envelopes_by_root_request",
                            peer_count, "P2P message received"
                        );
                        envelopes::handle_execution_payload_envelopes_by_root_request(
                            server, peer, roots, channel,
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
                                Some(PendingRequestKind::Columns {
                                    block_root,
                                    columns,
                                    lookup,
                                }) => {
                                    let request = ColumnRequest {
                                        block_root,
                                        lookup,
                                        peer,
                                        columns,
                                    };
                                    handle_data_column_sidecars_response(
                                        server, request, sidecars, ctx,
                                    );
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
                                    kind @ (PendingRequestKind::Root(_)
                                    | PendingRequestKind::Range { .. }
                                    | PendingRequestKind::EnvelopeRoot(_)
                                    | PendingRequestKind::EnvelopeRange { .. }),
                                ) => {
                                    error!(
                                        %peer,
                                        ?request_id,
                                        count = sidecars.len(),
                                        "Data column sidecars response answered a non-column request id"
                                    );
                                    retire_unanswered(server, kind, peer, ctx).await;
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
                        ResponsePayload::ExecutionPayloadEnvelopes(envelopes) => {
                            trace!(
                                kind = "execution_payload_envelopes_response",
                                peer_count, "P2P message received"
                            );
                            // Removed here, like the other terminal answers: this
                            // response is the whole exchange for the id.
                            match server.outbound_requests.remove(&request_id) {
                                Some(PendingRequestKind::EnvelopeRoot(block_root)) => {
                                    handle_envelopes_by_root_response(
                                        server, peer, block_root, envelopes, ctx,
                                    )
                                    .await;
                                }
                                Some(PendingRequestKind::EnvelopeRange {
                                    start_slot,
                                    end_slot,
                                }) => {
                                    handle_envelopes_by_range_response(
                                        server, peer, start_slot, end_slot, envelopes, ctx,
                                    )
                                    .await;
                                }
                                // Unreachable by construction, as for the
                                // column payload above: only the two envelope
                                // kinds are sent on the envelope protocols.
                                Some(
                                    kind @ (PendingRequestKind::Root(_)
                                    | PendingRequestKind::Range { .. }
                                    | PendingRequestKind::Columns { .. }
                                    | PendingRequestKind::ColumnRange { .. }),
                                ) => {
                                    error!(
                                        %peer,
                                        ?request_id,
                                        count = envelopes.len(),
                                        "Envelopes response answered a non-envelope request id"
                                    );
                                    retire_unanswered(server, kind, peer, ctx).await;
                                }
                                None => {
                                    debug!(
                                        %peer,
                                        ?request_id,
                                        count = envelopes.len(),
                                        "Received envelopes response for unknown request_id"
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
                                    kind @ (PendingRequestKind::Columns { .. }
                                    | PendingRequestKind::ColumnRange { .. }
                                    | PendingRequestKind::EnvelopeRoot(_)
                                    | PendingRequestKind::EnvelopeRange { .. }),
                                ) => {
                                    error!(
                                        %peer,
                                        "Blocks response answered a non-block request id"
                                    );
                                    retire_unanswered(server, kind, peer, ctx).await;
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
                            Some(PendingRequestKind::Columns {
                                block_root,
                                columns,
                                lookup,
                            }) => {
                                // Same reasoning as the `Root` arm above: an
                                // error response is the whole exchange, so
                                // this is the only place that can settle it.
                                let request = ColumnRequest {
                                    block_root,
                                    lookup,
                                    peer,
                                    columns,
                                };
                                handle_column_fetch_failure(server, request, ctx);
                            }
                            // Nothing to retire: a range prefetch has no
                            // pending entry and nothing waits on it. A peer
                            // refusing the range (ResourceUnavailable, say)
                            // just means these columns come from gossip or
                            // from the by-root path instead.
                            Some(PendingRequestKind::ColumnRange { .. }) => {}
                            Some(PendingRequestKind::EnvelopeRoot(block_root)) => {
                                // Same reasoning as the `Root` arm above.
                                handle_envelope_fetch_failure(server, block_root, peer, ctx).await;
                            }
                            // Nothing retries it, and the chain actor re-asks
                            // by root; but range pacing waits on the answer,
                            // so it must be released here.
                            Some(PendingRequestKind::EnvelopeRange { .. }) => {
                                release_envelope_gate(server, ctx).await;
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
                Some(PendingRequestKind::Columns {
                    block_root,
                    columns,
                    lookup,
                }) => {
                    let request = ColumnRequest {
                        block_root,
                        lookup,
                        peer,
                        columns,
                    };
                    handle_column_fetch_failure(server, request, ctx);
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
                Some(PendingRequestKind::EnvelopeRoot(block_root)) => {
                    handle_envelope_fetch_failure(server, block_root, peer, ctx).await;
                }
                Some(PendingRequestKind::EnvelopeRange {
                    start_slot,
                    end_slot,
                }) => {
                    debug!(
                        %peer,
                        start_slot,
                        end_slot,
                        "ExecutionPayloadEnvelopesByRange request failed; envelopes fall back to the by-root path"
                    );
                    release_envelope_gate(server, ctx).await;
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
pub(super) fn respond(
    server: &mut P2PServer,
    channel: ResponseChannel<Response>,
    payload: ResponsePayload,
) {
    server
        .swarm_handle
        .send_response(channel, Response::success(payload));
}

/// Answer a request with an error code and a reason.
pub(super) fn refuse(
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
        .new_block(
            block,
            BlockSource::Sync,
            BlockArrival::now(),
            BlockAnnouncement::Silent,
        )
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
            BlockAnnouncement::Silent,
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

    let Some((peer, excluded)) = choose_fetch_peer(
        &server.connected_peers,
        server
            .pending_root_requests
            .get_mut(&root)
            .map(|pending| &mut pending.failed_peers),
        &root,
    ) else {
        debug!(%root, "Failed to select random peer");
        return false;
    };

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

/// Pick a random connected peer that has not already failed this lookup.
///
/// Returns the peer and how many were excluded. When every peer has failed it
/// falls back to the full set (new peers may have connected, or failing ones
/// may have caught up) and clears `failed`, so the next retries start a fresh
/// round of elimination. Shared by the block and envelope by-root fetches,
/// whose peer choice has nothing to do with what is being fetched.
pub(super) fn choose_fetch_peer<V>(
    connected: &HashMap<PeerId, V>,
    failed: Option<&mut HashSet<PeerId>>,
    root: &H256,
) -> Option<(PeerId, usize)> {
    let pool: Vec<PeerId> = match failed.as_deref() {
        Some(failed) if !failed.is_empty() => connected
            .keys()
            .copied()
            .filter(|peer| !failed.contains(peer))
            .collect(),
        _ => connected.keys().copied().collect(),
    };
    let pool = if pool.is_empty() {
        debug!(%root, "All peers failed for this lookup, retrying with full peer set");
        if let Some(failed) = failed {
            failed.clear();
        }
        connected.keys().copied().collect()
    } else {
        pool
    };
    let peer = *pool.choose(&mut rand::thread_rng())?;
    Some((peer, connected.len() - pool.len()))
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
/// and [`fetch_data_columns_from_peer`] asks such a peer for a column no known
/// custodian covers, so an unknown peer is still reachable — just not preferred
/// over one we know holds the column.
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
/// columns no connected peer outside `exclude` is known to custody. Mirrors
/// lighthouse's `select_columns_by_range_peers_to_request`: pick per column,
/// prefer the peer carrying the fewest of this lookup's columns so one peer is
/// not asked for everything, and report the gap rather than papering over it.
///
/// A custodian already asked for a column without delivering it (`missed`)
/// is not asked for it again, unless `retry_missed` (the block is at the tip,
/// where it may simply not have had the column yet): then it comes after
/// every other custodian of that column, so a retry tries someone new first
/// and comes back to it when it is the only one.
fn group_columns_by_custody_peer(
    server: &P2PServer,
    columns: &[u64],
    exclude: &HashSet<PeerId>,
    missed: &HashSet<(PeerId, u64)>,
    retry_missed: bool,
) -> (HashMap<PeerId, Vec<u64>>, Vec<u64>) {
    let mut by_peer: HashMap<PeerId, Vec<u64>> = HashMap::new();
    let mut uncovered = Vec::new();

    for &column in columns {
        let candidates: Vec<PeerId> = columns_custodied_by(server, column)
            .into_iter()
            .filter(|peer| !exclude.contains(peer))
            .filter(|peer| retry_missed || !missed.contains(&(*peer, column)))
            .collect();
        // `min_by_key` over the load already assigned in this same call, with
        // the peer id breaking ties so the choice is deterministic for a given
        // peer set rather than dependent on HashSet iteration order.
        let chosen = candidates.iter().min_by_key(|peer| {
            let load = by_peer.get(*peer).map_or(0, Vec::len);
            (missed.contains(&(**peer, column)), load, **peer)
        });
        match chosen {
            Some(&peer) => by_peer.entry(peer).or_default().push(column),
            None => uncovered.push(column),
        }
    }

    (by_peer, uncovered)
}

/// A fresh id for a column lookup, which its requests carry (see
/// [`PendingColumnRequest::lookup`]).
fn next_column_lookup() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// Ask connected peers for `columns` of `block_root`, starting a lookup in
/// `pending_column_requests` or adding to the one already there. Returns
/// whether any request went out.
///
/// Each column goes to a peer known to custody it; see
/// [`plan_column_requests`] for where the rest go. Peers this lookup has
/// written off (`failed_peers`) are not asked. A column with nobody left to
/// go to is not asked at all: the lookup ends once nothing else is open (see
/// [`retire_column_lookup`]), and the chain actor's per-slot re-ask starts a
/// new one against whatever peers it has then.
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

    let plan = plan_column_requests(server, block_root, &columns);
    let excluded = plan.excluded;
    let lookup = plan.lookup;

    let mut sent: Vec<(PeerId, Vec<u64>)> = Vec::new();
    for (peer, peer_columns) in plan.by_peer {
        let count = peer_columns.len();
        let column_indices = match ColumnIndices::try_from(peer_columns.clone()) {
            Ok(indices) => indices,
            Err(err) => {
                // Unreachable: a lookup holds distinct column indices, so no
                // request can name more than NUMBER_OF_COLUMNS of them. Were it
                // ever reached, these columns would stay unasked, and the lookup
                // would end once nothing else of it is on the wire.
                error!(%block_root, ?err, "Too many columns requested in one DataColumnsByRoot lookup");
                continue;
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
        let kind = PendingRequestKind::Columns {
            block_root,
            columns: peer_columns.clone(),
            lookup,
        };
        server.outbound_requests.insert(request_id, kind);
        sent.push((peer, peer_columns));
    }

    if sent.is_empty() {
        return false;
    }

    // `or_insert_with` rather than an unconditional insert: a retry re-enters
    // here with the same root already tracked, and must not reset `attempts`
    // back to a fresh lookup's value. A new lookup tracks every column it was
    // asked for, sent or not, so one nobody could be asked for still counts
    // as missing.
    let pending = server
        .pending_column_requests
        .entry(block_root)
        .or_insert_with(|| PendingColumnRequest::new(columns, lookup));
    for (peer, peer_columns) in sent {
        if plan.beyond_custody == Some(peer) {
            pending.asked_beyond_custody = true;
        }
        for column in peer_columns {
            pending.asked.insert(column, peer);
        }
    }
    // Each send's own timestamp, not the lookup's first: a ladder still
    // working through the peer set is alive, however long it has been running.
    pending.last_asked = Instant::now();

    true
}

/// Which peer [`fetch_data_columns_from_peer`] asks for which column.
struct ColumnPlan {
    /// The lookup's id: the existing one's, or a fresh one's.
    lookup: u64,
    by_peer: HashMap<PeerId, Vec<u64>>,
    /// How many connected peers the lookup's history rules out.
    excluded: usize,
    /// The peer asked for columns outside its known custody, if one is.
    beyond_custody: Option<PeerId>,
}

/// Plan the requests for `columns` of `block_root`'s lookup (a new one when
/// there is none yet).
///
/// Each column goes to a peer known to custody it. Whatever no known
/// custodian covers goes to a peer whose custody is unknown, the same bet the
/// range path makes (see [`peers_of_unknown_custody`]), one peer taking as many
/// of those columns as it may be asked for, so they cost as few requests as
/// possible.
///
/// A peer that already answered this lookup without a column is asked for it
/// again only while the block is at the tip (its slot is the wall clock's or
/// later), and then after every peer that has not: at the tip it may have
/// received the column since, as `hold_block_for_columns` explains. Past the
/// tip there is no gossip left to bring it, so asking again would only spend
/// the ladder; that peer is still asked for the columns it has not missed. A
/// lookup that has not read the block's slot yet counts as past the tip.
///
/// Only when no peer of unknown custody can take an uncovered column does it
/// go to a peer that has said what it keeps, and only once per lookup. Such a
/// peer may hold more than it custodies, and asking one at random each slot is
/// all this node did before custody was known; but walking every one of them,
/// a round each, is what a lookup for a column nobody holds used to cost.
fn plan_column_requests(server: &P2PServer, block_root: H256, columns: &[u64]) -> ColumnPlan {
    let no_peers = HashSet::new();
    let no_misses = HashSet::new();
    let pending = server.pending_column_requests.get(&block_root);
    let lookup = pending.map_or_else(next_column_lookup, |pending| pending.lookup);
    let failed = pending.map_or(&no_peers, |pending| &pending.failed_peers);
    let missed = pending.map_or(&no_misses, |pending| &pending.missed);
    let beyond_custody_spent = pending.is_some_and(|pending| pending.asked_beyond_custody);
    let wall_slot = server.wire.beacon().map(BeaconWire::wall_slot);
    let at_tip = pending
        .and_then(|pending| pending.slot)
        .zip(wall_slot)
        .is_some_and(|(slot, now)| slot >= now);

    let (mut by_peer, uncovered) =
        group_columns_by_custody_peer(server, columns, failed, missed, at_tip);
    let excluded = failed
        .iter()
        .filter(|peer| server.connected_peers.contains_key(*peer))
        .count();
    let mut plan = ColumnPlan {
        lookup,
        by_peer: HashMap::new(),
        excluded,
        beyond_custody: None,
    };

    let may_ask = |peer: &PeerId, column: u64| at_tip || !missed.contains(&(*peer, column));
    let misses = |peer: &PeerId, columns: &[u64]| {
        columns
            .iter()
            .filter(|&&column| missed.contains(&(*peer, column)))
            .count()
    };
    let unknown: Vec<PeerId> = peers_of_unknown_custody(server, usize::MAX)
        .into_iter()
        .filter(|peer| !failed.contains(peer))
        .collect();
    let mut remaining = uncovered;
    let mut picked: HashSet<PeerId> = HashSet::new();
    while !remaining.is_empty() {
        let candidates: Vec<PeerId> = unknown
            .iter()
            .filter(|peer| !picked.contains(*peer))
            .filter(|peer| remaining.iter().any(|&column| may_ask(peer, column)))
            .copied()
            .collect();
        let Some(fewest) = candidates.iter().map(|peer| misses(peer, &remaining)).min() else {
            break;
        };
        let least_missed: Vec<PeerId> = candidates
            .into_iter()
            .filter(|peer| misses(peer, &remaining) == fewest)
            .collect();
        let Some(&peer) = least_missed.choose(&mut rand::thread_rng()) else {
            break;
        };
        let (asked, left): (Vec<u64>, Vec<u64>) = remaining
            .iter()
            .partition(|&&column| may_ask(&peer, column));
        debug!(
            %block_root,
            %peer,
            count = asked.len(),
            "No connected peer is known to custody these columns; asking one whose custody is unknown"
        );
        picked.insert(peer);
        by_peer.entry(peer).or_default().extend(asked);
        remaining = left;
    }

    if !remaining.is_empty() && !beyond_custody_spent {
        let known: Vec<PeerId> = server
            .connected_peers
            .keys()
            .filter(|peer| server.peer_custody.contains_key(*peer) && !failed.contains(*peer))
            .filter(|peer| {
                remaining
                    .iter()
                    .any(|&column| !missed.contains(&(**peer, column)))
            })
            .copied()
            .collect();
        if let Some(&peer) = known.choose(&mut rand::thread_rng()) {
            let (asked, left): (Vec<u64>, Vec<u64>) = remaining
                .iter()
                .partition(|&&column| !missed.contains(&(peer, column)));
            debug!(
                %block_root,
                %peer,
                count = asked.len(),
                "No peer of unknown custody can take these columns; asking one beyond its custody, once"
            );
            plan.beyond_custody = Some(peer);
            by_peer.entry(peer).or_default().extend(asked);
            remaining = left;
        }
    }

    if !remaining.is_empty() {
        debug!(
            %block_root,
            count = remaining.len(),
            "No connected peer is known to custody these columns, and none is left to ask"
        );
    }
    plan.by_peer = by_peer;
    plan
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
pub(super) async fn request_next_beacon_range_batch(
    server: &mut P2PServer,
    ctx: &Context<P2PServer>,
) -> bool {
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
///
/// Gloas answers yes as fulu does, though its columns have a different shape
/// and decode as gloas sidecars by the chunk's context bytes. A batch ending in
/// gloas can begin in fulu, whose blocks need their columns; a batch lying
/// entirely in gloas still needs them too, since a later change makes the chain
/// actor gate a block's payload envelope on its columns.
fn range_needs_columns(
    config: &Config,
    custody_columns: &[u64],
    batch: &std::ops::Range<u64>,
) -> bool {
    let last_slot = batch.end.saturating_sub(1);
    let has_columns = match fork_at_slot(config, last_slot) {
        ForkName::Phase0
        | ForkName::Altair
        | ForkName::Bellatrix
        | ForkName::Capella
        | ForkName::Deneb
        | ForkName::Electra => false,
        ForkName::Fulu | ForkName::Gloas => true,
        ForkName::Lean => {
            unreachable!("fork_at_slot never returns Lean: it is absent from ForkName::ALL")
        }
    };
    !custody_columns.is_empty() && has_columns
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

    let attempts = pending.attempts;
    let Some(backoff) = retire_root_attempt(pending, peer) else {
        error!(%root, %peer, attempts,
               "Block fetch failed after max retries, giving up");
        server.pending_root_requests.remove(&root);
        return;
    };

    debug!(%root, %peer, attempts, ?backoff, "Block fetch failed, scheduling retry");

    send_after(backoff, ctx.clone(), p2p_protocol::RetryBlockFetch { root });
}

/// Charge `peer` with a failed attempt and say how long to wait before the
/// next one: `None` once the ladder is exhausted. The step shared by the block
/// and envelope by-root lookups, whose bookkeeping is the same
/// [`PendingRequest`].
pub(super) fn retire_root_attempt(pending: &mut PendingRequest, peer: PeerId) -> Option<Duration> {
    pending.failed_peers.insert(peer);

    if pending.attempts >= MAX_FETCH_RETRIES {
        return None;
    }

    let backoff_ms = INITIAL_BACKOFF_MS * BACKOFF_MULTIPLIER.pow(pending.attempts - 1);
    pending.attempts += 1;
    Some(Duration::from_millis(backoff_ms))
}

/// One request of a column lookup: which lookup sent it, to whom, and for
/// which columns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ColumnRequest {
    pub(crate) block_root: H256,
    /// The lookup that sent it (see [`PendingColumnRequest::lookup`]).
    pub(crate) lookup: u64,
    pub(crate) peer: PeerId,
    /// The columns it asked for.
    pub(crate) columns: Vec<u64>,
}

/// How one request of a column lookup ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ColumnReport {
    pub(crate) request: ColumnRequest,
    pub(crate) reply: ColumnReply,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ColumnReply {
    /// No answer: the request failed on the wire, timed out, or was refused
    /// with an error response.
    Failed,
    /// An answer, with each sidecar it carried for the request and what the
    /// chain checks made of it. Empty when it carried none.
    Answered(Vec<(u64, ColumnVerdict)>),
}

impl ColumnReport {
    /// The requested columns whose sidecars passed the checks, or were already
    /// stored.
    fn delivered(&self) -> Vec<u64> {
        let ColumnReply::Answered(verdicts) = &self.reply else {
            return Vec::new();
        };
        verdicts
            .iter()
            .filter(|(column, verdict)| {
                *verdict == ColumnVerdict::Delivered && self.request.columns.contains(column)
            })
            .map(|(column, _)| *column)
            .collect()
    }

    /// Whether the peer is not asked again in this lookup: its request failed,
    /// or it sent a sidecar the checks refused.
    ///
    /// An answer without a column is not held against the peer, whether it
    /// was asked as a known custodian or on the chance that it held the
    /// column. The specification lets a peer answer with what it has, and at
    /// the tip a peer often has not received the column yet, which is why the
    /// chain actor waits a slot before asking for a block still at the tip
    /// (see `hold_block_for_columns`). Such a peer is recorded in `missed`
    /// instead (see `plan_column_requests` for when it is asked again).
    fn peer_at_fault(&self) -> bool {
        matches!(self.reply, ColumnReply::Failed) || self.sent_invalid()
    }

    /// Whether the answer carried a sidecar the checks refused.
    fn sent_invalid(&self) -> bool {
        let ColumnReply::Answered(verdicts) = &self.reply else {
            return false;
        };
        verdicts
            .iter()
            .any(|(_, verdict)| *verdict == ColumnVerdict::Rejected)
    }
}

/// What one request reporting back means for its lookup.
#[derive(Debug, PartialEq, Eq)]
enum ColumnAttemptOutcome {
    /// Every column the lookup wanted has arrived. The lookup is retired.
    Complete,
    /// Nothing to ask for now: every column still missing is on the wire with
    /// another request (`asked` columns are), or a retry already due will ask
    /// for it.
    Waiting { asked: usize },
    /// Ask for whatever no open request covers after `backoff`: zero, and no
    /// attempt spent, when the request delivered everything it asked for.
    Retry { attempts: u32, backoff: Duration },
    /// The ladder is exhausted. The lookup is retired.
    GiveUp { attempts: u32 },
}

/// Settle one request of `pending` and say what follows.
///
/// Split out from [`report_column_request`] so the arithmetic can be tested
/// without a server: everything the decision depends on is in `pending` and
/// the report.
///
/// A lookup is split across the peers that custody its columns, so each
/// request settles its own columns only: what it delivered leaves the lookup,
/// and what it left out is asked again at once (after the backoff), without
/// waiting for the lookup's other requests, which may be waiting out a request
/// timeout. A lookup used to be retired on its first non-empty answer, which
/// left every column asked of another peer to wait for the chain actor's next
/// per-slot re-ask: on a devnet, about one gloas envelope in twenty waited
/// ~11.7 s for its columns.
///
/// Only a request that left out a column it was asked for spends an attempt
/// and doubles the backoff. A request that delivered its whole share spent
/// nothing: what is left is another request's, or a column merged into the
/// lookup after it was sent, which is asked for at once. However many of a
/// lookup's requests come back short, one retry is due at a time, and it asks
/// for all of their leftovers.
///
/// A short request whose leftover rides on a retry already due spends nothing
/// either, even when that retry is the zero-backoff one a whole share
/// scheduled: one leftover can then be asked again without backing off. That
/// is bounded: it takes a whole share to schedule such a retry, a whole share
/// takes columns off the lookup, and the next request to come back short
/// after the retry has fired spends an attempt as usual.
fn settle_column_report(
    pending: &mut PendingColumnRequest,
    report: &ColumnReport,
) -> ColumnAttemptOutcome {
    let request = &report.request;
    let delivered = report.delivered();
    pending.columns.retain(|column| !delivered.contains(column));

    // A request of a lookup this one replaced: its columns are here all the
    // same, but it is not one of this lookup's requests, so it closes none of
    // them and spends nothing. A peer that sent an invalid sidecar for this
    // root is still not one to ask for it again; a failure, though, may be
    // what got the old lookup replaced, and says little about the peer now.
    if request.lookup != pending.lookup {
        if report.sent_invalid() {
            pending.failed_peers.insert(request.peer);
        }
        return if pending.columns.is_empty() {
            ColumnAttemptOutcome::Complete
        } else {
            ColumnAttemptOutcome::Waiting {
                asked: pending.asked.len(),
            }
        };
    }

    for column in &request.columns {
        if pending.asked.get(column) == Some(&request.peer) {
            pending.asked.remove(column);
        }
    }
    if pending.columns.is_empty() {
        return ColumnAttemptOutcome::Complete;
    }

    let left_out: Vec<u64> = request
        .columns
        .iter()
        .copied()
        .filter(|column| !delivered.contains(column))
        .collect();
    for &column in &left_out {
        pending.missed.insert((request.peer, column));
    }
    if report.peer_at_fault() {
        pending.failed_peers.insert(request.peer);
    }

    if pending.retry_due || pending.unasked().is_empty() {
        return ColumnAttemptOutcome::Waiting {
            asked: pending.asked.len(),
        };
    }

    let missed = left_out
        .iter()
        .any(|column| pending.columns.contains(column));
    if !missed {
        pending.retry_due = true;
        return ColumnAttemptOutcome::Retry {
            attempts: pending.attempts,
            backoff: Duration::ZERO,
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
    pending.retry_due = true;
    ColumnAttemptOutcome::Retry {
        attempts,
        backoff: Duration::from_millis(backoff_ms),
    }
}

/// Settle `report` against its lookup, retiring the lookup when it is complete
/// or its ladder has run out. `None` when no lookup is waiting on this root:
/// it completed, gave up, or ran out of peers to ask before this request
/// reported back.
///
/// Every request of a lookup must report through here exactly once, or its
/// columns stay on the wire for good and are never asked again until the
/// lookup goes stale (see `STALE_COLUMN_LOOKUP`).
fn report_column_request(
    server: &mut P2PServer,
    report: &ColumnReport,
) -> Option<ColumnAttemptOutcome> {
    let block_root = report.request.block_root;
    let pending = server.pending_column_requests.get_mut(&block_root)?;
    let outcome = settle_column_report(pending, report);
    match outcome {
        ColumnAttemptOutcome::Complete => {
            retire_column_lookup(server, block_root, Retirement::Complete);
        }
        ColumnAttemptOutcome::GiveUp { attempts } => {
            // A ladder spent only on columns no connected peer is known to
            // keep has found nobody holding them, which is not a fault of
            // this node's or of any peer's.
            let uncovered_only =
                server
                    .pending_column_requests
                    .get(&block_root)
                    .is_some_and(|pending| {
                        pending
                            .columns
                            .iter()
                            .all(|&column| columns_custodied_by(server, column).is_empty())
                    });
            let why = if uncovered_only {
                Retirement::NobodyToAsk
            } else {
                let peer = report.request.peer;
                Retirement::GaveUp { attempts, peer }
            };
            retire_column_lookup(server, block_root, why);
        }
        ColumnAttemptOutcome::Waiting { .. } | ColumnAttemptOutcome::Retry { .. } => {}
    }
    Some(outcome)
}

/// Settle one request of a column lookup and schedule what follows: a failed
/// one from the request-response layer, an answer once its sidecars have been
/// through the checks.
pub(crate) fn settle_column_request(
    server: &mut P2PServer,
    report: ColumnReport,
    ctx: &Context<P2PServer>,
) {
    if let Some(outcome) = report_column_request(server, &report) {
        follow_column_attempt(&report.request, &outcome, ctx);
    }
}

/// A column request that got no answer: failed on the wire, timed out, or was
/// refused with an error response.
fn handle_column_fetch_failure(
    server: &mut P2PServer,
    request: ColumnRequest,
    ctx: &Context<P2PServer>,
) {
    let report = ColumnReport {
        request,
        reply: ColumnReply::Failed,
    };
    settle_column_request(server, report, ctx);
}

/// Schedule what [`report_column_request`] decided. A retired lookup has
/// nothing left to schedule: [`retire_column_lookup`] already said why.
fn follow_column_attempt(
    request: &ColumnRequest,
    outcome: &ColumnAttemptOutcome,
    ctx: &Context<P2PServer>,
) {
    let block_root = request.block_root;
    let peer = request.peer;
    match *outcome {
        ColumnAttemptOutcome::Waiting { asked } => {
            trace!(
                %block_root,
                %peer,
                asked,
                "A data column request reported back; the rest of the lookup is still on the wire"
            );
        }
        ColumnAttemptOutcome::Retry { attempts, backoff } => {
            debug!(%block_root, %peer, attempts, ?backoff, "Data column lookup still missing columns, scheduling retry");
            let retry = p2p_protocol::RetryDataColumnFetch {
                block_root,
                lookup: request.lookup,
            };
            send_after(backoff, ctx.clone(), retry);
        }
        ColumnAttemptOutcome::Complete | ColumnAttemptOutcome::GiveUp { .. } => {}
    }
}

/// Why a column lookup ended.
#[derive(Debug, PartialEq, Eq)]
enum Retirement {
    /// Every column it wanted has arrived.
    Complete,
    /// The ladder ran out, ending on a request to `peer`.
    GaveUp { attempts: u32, peer: PeerId },
    /// Nobody connected was found holding what is still missing: nothing is
    /// on the wire and no peer is left to ask (none is known to custody it,
    /// or every one asked past the tip answered without it), or the ladder
    /// ran out on columns no connected peer is known to custody.
    NobodyToAsk,
    /// Nothing is on the wire, and every connected peer has been written off
    /// in this lookup (a failed request or a refused sidecar), so whether one
    /// of them holds what is missing was never learned.
    PeersExhausted,
    /// Nothing is on the wire, and nothing is connected at all.
    NoPeers,
}

/// Retire `block_root`'s lookup, saying why. The one place a lookup ends;
/// `fetch_missing_columns` also drops a stale one to start its replacement.
///
/// A lookup that ends short of its columns is not lost for good: the chain
/// actor asks again on every slot tick for every block or envelope still
/// held, and that ask starts a new lookup against whatever peers this node
/// has by then.
fn retire_column_lookup(server: &mut P2PServer, block_root: H256, why: Retirement) {
    let Some(pending) = server.pending_column_requests.remove(&block_root) else {
        return;
    };
    match why {
        Retirement::Complete => {
            trace!(%block_root, "Every column of this data column lookup has arrived");
        }
        Retirement::GaveUp { attempts, peer } => {
            error!(%block_root, %peer, attempts,
                   "Data column fetch failed after max retries, giving up");
            metrics::inc_data_column_fetch_failure("max_retries");
        }
        // Not an error, unlike running out of retries: the columns are not
        // anywhere this node can reach yet, and the next re-ask may find a
        // peer that connected since.
        Retirement::NobodyToAsk => {
            let missing = pending.columns;
            debug!(
                %block_root,
                ?missing,
                "No connected peer is left to ask for these columns; leaving them to the next re-ask"
            );
            metrics::inc_data_column_fetch_failure("no_custodian");
        }
        // The old lookup cleared its written-off peers and asked them all
        // again; the next re-ask's fresh lookup does that now, a slot later.
        Retirement::PeersExhausted => {
            let missing = pending.columns;
            debug!(
                %block_root,
                ?missing,
                "Every connected peer failed this lookup; leaving its columns to the next re-ask"
            );
            metrics::inc_data_column_fetch_failure("peers_exhausted");
        }
        // Counted as `no_peers` where the send found nobody connected.
        Retirement::NoPeers => {
            debug!(%block_root, "No connected peers to ask for this lookup's columns");
        }
    }
}

/// The retry a column lookup scheduled for what its requests left out.
pub(crate) async fn retry_column_lookup(server: &mut P2PServer, block_root: H256, lookup: u64) {
    let Some(pending) = server
        .pending_column_requests
        .get_mut(&block_root)
        .filter(|pending| pending.lookup == lookup)
    else {
        trace!(%block_root, "Data column lookup ended during backoff, skipping retry");
        return;
    };
    pending.retry_due = false;
    ask_unasked_columns(server, block_root).await;
}

/// Ask for the columns of `block_root`'s lookup that no open request covers.
///
/// The store is read first: gossip often delivers a column while a lookup
/// started at the tip is still asking for it, and asking again would download
/// a sidecar the checks then drop as already stored. When that leaves nothing
/// missing, the lookup is complete. When something is missing but none of it
/// can be asked for and nothing is on the wire, the lookup ends: nothing would
/// ever ask for it again within it.
pub(crate) async fn ask_unasked_columns(server: &mut P2PServer, block_root: H256) {
    drop_stored_columns(server, block_root);
    let Some(pending) = server.pending_column_requests.get(&block_root) else {
        return;
    };
    if pending.columns.is_empty() {
        retire_column_lookup(server, block_root, Retirement::Complete);
        return;
    }
    let unasked = pending.unasked();
    if unasked.is_empty() {
        return;
    }
    let sent = fetch_data_columns_from_peer(server, block_root, unasked).await;
    let open = server
        .pending_column_requests
        .get(&block_root)
        .is_some_and(|pending| !pending.asked.is_empty());
    if !sent && !open {
        let all_failed = server
            .pending_column_requests
            .get(&block_root)
            .is_some_and(|pending| {
                server
                    .connected_peers
                    .keys()
                    .all(|peer| pending.failed_peers.contains(peer))
            });
        let why = if server.connected_peers.is_empty() {
            Retirement::NoPeers
        } else if all_failed {
            Retirement::PeersExhausted
        } else {
            Retirement::NobodyToAsk
        };
        retire_column_lookup(server, block_root, why);
    }
}

/// Take off `block_root`'s lookup the columns the store already holds.
///
/// The block's slot is read once per lookup, and only here: on beacon,
/// [`Store::block_entry`] decodes the whole block. A block the store does not
/// have leaves the lookup as it is.
fn drop_stored_columns(server: &mut P2PServer, block_root: H256) {
    let store = &server.store;
    let Some(pending) = server.pending_column_requests.get_mut(&block_root) else {
        return;
    };
    let slot = match pending.slot {
        Some(slot) => slot,
        None => {
            let Some((slot, _)) = store.block_entry(&block_root) else {
                return;
            };
            pending.slot = Some(slot);
            slot
        }
    };
    pending
        .columns
        .retain(|&column| !store.has_data_column(slot, &block_root, column));
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

    if !wire.holds_digest(peer_status.fork_digest()) {
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
/// given how far this node has the chain and a peer's advertised head. `None`
/// when the peer is not ahead of it.
///
/// How far this node has the chain is the higher of two floors, because each
/// one misses blocks the other sees:
///
/// - `fetched_through` is `server.beacon_fetched_through`, the highest slot a
///   range answer has handed to the chain actor. Delivery is a message and
///   import is work, so the store's head lags a delivered batch by the whole
///   actor mailbox. Driven off the store's head alone, the live follower kept
///   re-requesting the part of the range still draining and pulled 11,213
///   blocks off the wire to import 100.
/// - `head_slot` is the store's head, which gossip imports move and nothing on
///   the range path sees. Driven off `fetched_through` alone, a follower that
///   had caught up kept it at its last range batch, so every peer that
///   connected later was asked again for every block gossip had delivered
///   since: 748 blocks in 66 bursts on one follower, a single burst of
///   which held a gossip block 4.2 s in the chain actor's queue. The head is
///   a safe floor, since a head block's whole ancestry is already imported.
///
/// Bounded by [`MAX_SYNC_RANGE`], the same ceiling
/// `handle_lean_status_response` bounds its own request span by.
fn beacon_sync_target(
    fetched_through: u64,
    head_slot: u64,
    peer_head_slot: u64,
) -> Option<std::ops::Range<u64>> {
    let synced_through = fetched_through.max(head_slot);
    if peer_head_slot <= synced_through {
        return None;
    }
    let gap = peer_head_slot - synced_through;
    let start_slot = synced_through.saturating_add(1);
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
    if !wire.holds_digest(status.fork_digest()) {
        warn!(
            %peer,
            peer_digest = %hex::encode(status.fork_digest()),
            our_digest = %hex::encode(wire.fork_digest),
            "Handshake answered from another fork digest"
        );
        metrics::inc_beacon_status_digest_mismatch();
        return;
    }
    // Answered at any held digest, but only synced from on the current one (or
    // the next, within clock skew): after a boundary, a peer still on the old
    // digest has not upgraded, and its chain is not the one being followed.
    if !transition::is_syncable_digest(wire, status.fork_digest(), unix_now_ms()) {
        debug!(
            %peer,
            peer_digest = %hex::encode(status.fork_digest()),
            our_digest = %hex::encode(wire.fork_digest),
            "Not syncing from a peer on a superseded fork digest"
        );
        return;
    }
    let peer_head_slot = status.head_slot();
    trace!(
        %peer,
        peer_head_slot,
        peer_finalized_epoch = status.finalized_epoch(),
        "Beacon handshake complete"
    );

    // A whole-block decode per handshake, the same one `build_status` already
    // pays to send ours.
    let head_slot = server.store.beacon_head().map_or(0, |(slot, _)| slot);
    let Some(target_range) =
        beacon_sync_target(server.beacon_fetched_through, head_slot, peer_head_slot)
    else {
        return;
    };

    debug!(
        %peer,
        peer_head_slot,
        fetched_through = server.beacon_fetched_through,
        head_slot,
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
pub(super) fn beacon_block_store_or_refuse(
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
            match server
                .store
                .get_data_column(slot, &identifier.block_root, column)
            {
                Ok(Some(sidecar)) => sidecars.push(sidecar),
                Ok(None) => {}
                Err(err) => error!(
                    %peer,
                    slot,
                    column,
                    %err,
                    "Stored data column sidecar failed to read"
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
        .data_column_rows_in_range(request.start_slot, end_slot, &columns)
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
        .filter_map(|(slot, encoded)| {
            server
                .store
                .decode_data_column_sidecar(slot, &encoded)
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
    let (mut by_peer, uncovered) =
        group_columns_by_custody_peer(server, &columns, &HashSet::new(), &HashSet::new(), true);
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
            let slot = sidecar.slot();
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

    // The whole answer through the checks in one call, which forward per
    // block: the sidecars that pass as one message and the ones waiting on a
    // block as another, so at most two per block, not one per sidecar. A range
    // answer is the largest batch this node ever takes delivery of, and it
    // arrives precisely when the chain actor is busiest draining a backlog, so
    // a message per sidecar would put that many mailbox hops between the
    // answer and the imports waiting on it; a message per block lets the
    // actor count a block's columns toward availability as soon as that block
    // is checked, rather than after the slowest block of the span.
    column_checks::check_and_forward(server, in_range);
}

/// Keep the sidecars of `sidecars` that answer the request: the requested
/// block's, at a requested column. Returns them with how many were dropped.
///
/// Mirrors [`handle_blocks_by_root_response`], which keeps only the block the
/// request named. Nothing downstream re-asks whether a sidecar was wanted, and
/// an unsolicited one would otherwise be parked or stored on a peer's say-so.
fn retain_requested_columns(
    sidecars: Vec<DataColumnSidecar>,
    block_root: H256,
    requested: &[u64],
) -> (Vec<DataColumnSidecar>, usize) {
    let received = sidecars.len();
    let kept: Vec<_> = sidecars
        .into_iter()
        .filter(|sidecar| {
            sidecar.block_root() == block_root && requested.contains(&sidecar.index())
        })
        .collect();
    let dropped = received - kept.len();
    (kept, dropped)
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
/// The request's lookup is settled once the checks are done, on what passed
/// them ([`settle_column_request`], through the actor's own mailbox), not on
/// what the peer sent: a sidecar with the right root and index can still fail
/// them, and a gloas one carries no signature. Until then its columns count
/// as still on the wire, so they are not asked of anyone else meanwhile.
///
/// Unlike a block-by-root answer, which names exactly one document that
/// either matches the requested root or doesn't, the specification permits a
/// peer to return fewer sidecars than were asked for ("Clients MUST respond
/// with at least one sidecar, if they have it" — not with every one). So a
/// short answer settles what it brought, and the rest is asked again (see
/// [`settle_column_report`]); zero sidecars is the shortest answer, settled
/// at once since there is nothing to check.
///
/// The sidecars are checked and forwarded whether or not a lookup is still
/// waiting on them: one that already completed, gave up or was replaced has
/// no use for them, but the chain actor may.
fn handle_data_column_sidecars_response(
    server: &mut P2PServer,
    request: ColumnRequest,
    sidecars: Vec<DataColumnSidecar>,
    ctx: &Context<P2PServer>,
) {
    let back = ctx.clone();
    let on_checked = move |report: ColumnReport| {
        let message = p2p_protocol::ColumnAnswerChecked { report };
        let _ = back
            .send(message)
            .inspect_err(|err| warn!(%err, "Failed to settle a checked DataColumnsByRoot answer"));
    };
    if let Some(outcome) = take_column_answer(server, request.clone(), sidecars, on_checked) {
        follow_column_attempt(&request, &outcome, ctx);
    }
}

/// [`handle_data_column_sidecars_response`] without the actor: keep what
/// answers `request`, then either settle an answer with nothing left at once,
/// or hand the rest to the checks, which call `on_checked` with the report to
/// settle once they are done. Returns the outcome of a request settled here.
fn take_column_answer(
    server: &mut P2PServer,
    request: ColumnRequest,
    sidecars: Vec<DataColumnSidecar>,
    on_checked: impl FnOnce(ColumnReport) + Send + 'static,
) -> Option<ColumnAttemptOutcome> {
    let block_root = request.block_root;
    let peer = request.peer;
    let received = sidecars.len();
    trace!(%peer, %block_root, received, "Received DataColumnsByRoot response");

    let (sidecars, unrequested) = retain_requested_columns(sidecars, block_root, &request.columns);
    if unrequested > 0 {
        debug!(
            %peer,
            %block_root,
            unrequested,
            "Dropping data column sidecars the DataColumnsByRoot request did not ask for"
        );
    }

    if sidecars.is_empty() {
        debug!(%peer, %block_root, "DataColumnsByRoot response carried no sidecars");
        let report = ColumnReport {
            request,
            reply: ColumnReply::Answered(Vec::new()),
        };
        return report_column_request(server, &report);
    }

    if server.blockchain.is_none() {
        debug!(%peer, %block_root, "No blockchain handler available");
    }
    let done: column_checks::Done = Box::new(move |verdicts| {
        on_checked(ColumnReport {
            request,
            reply: ColumnReply::Answered(verdicts),
        });
    });
    column_checks::check_and_forward_then(server, sidecars, Some(done));
    None
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
            .new_block(
                block,
                BlockSource::Sync,
                BlockArrival::now(),
                BlockAnnouncement::Silent,
            )
            .inspect_err(
                |err| error!(%err, %slot, %peer, "Failed to forward beacon block to blockchain"),
            );
    }

    debug!(%peer, received, accepted, "Beacon blocks received");

    // The batch's blocks are all in the actor's mailbox now; ask for the
    // envelopes of the same span only after that. On a gloas span the next
    // batch is then held back until the answer has been delivered (see
    // `RangeSyncState::envelopes_pending`).
    let waiting_on_envelopes = request_beacon_envelopes_by_range(
        server,
        peer,
        start_slot,
        end_slot.saturating_sub(start_slot).saturating_add(1),
    )
    .await;

    // Highest slot *handed to* the actor, not the highest imported: see
    // [`beacon_sync_target`] for why range sync reads this beside the store's
    // head rather than the head alone.
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
    if waiting_on_envelopes {
        return;
    }
    request_next_beacon_range_batch(server, ctx).await;
}

/// Retire a request whose id was answered on a protocol that never carries its
/// kind. The codec cannot produce such an answer, but if one ever arrived the
/// exchange is over all the same: leaving the entry would keep its root in the
/// matching pending map, deduplicating every later ask for it, or leave range
/// sync waiting on a request that already ended.
async fn retire_unanswered(
    server: &mut P2PServer,
    kind: PendingRequestKind,
    peer: PeerId,
    ctx: &Context<P2PServer>,
) {
    match kind {
        PendingRequestKind::Root(root) => handle_fetch_failure(server, root, peer, ctx).await,
        PendingRequestKind::Range { .. } => fail_range_request(server, &peer),
        PendingRequestKind::Columns {
            block_root,
            columns,
            lookup,
        } => {
            let request = ColumnRequest {
                block_root,
                lookup,
                peer,
                columns,
            };
            handle_column_fetch_failure(server, request, ctx);
        }
        PendingRequestKind::ColumnRange { .. } => {}
        PendingRequestKind::EnvelopeRoot(block_root) => {
            handle_envelope_fetch_failure(server, block_root, peer, ctx).await;
        }
        PendingRequestKind::EnvelopeRange { .. } => release_envelope_gate(server, ctx).await,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::ConnectionDirection;
    use ethlambda_storage::{ForkCheckpoints, backend::InMemoryBackend};
    use ethlambda_types::beacon::containers::gloas;
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
    pub(crate) async fn unconnected_server() -> P2PServer {
        let built = crate::build_swarm(crate::SwarmConfig {
            node_key: vec![3u8; 32],
            bootnodes: Vec::new(),
            listening_socket: "127.0.0.1:0".parse().expect("valid socket"),
            target_peers: crate::discovery::DEFAULT_DISCOVERY_TARGET_PEERS,
            agent_version: "ethlambda/test",
            wire: crate::WireConfig::Lean(crate::LeanWireConfig {
                validator_ids: Vec::new(),
                attestation_committee_count: 1,
                subscription_subnets: HashSet::new(),
                milliseconds_per_slot: DEFAULT_MILLISECONDS_PER_SLOT,
            }),
        })
        .expect("swarm builds");

        let (swarm_stream, swarm_handle) =
            crate::swarm_adapter::start_swarm_adapter(built.swarm, HashMap::new());
        crate::test_support::drain_swarm_events(swarm_stream);

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
            peer_table: ethlambda_network_api::PeerTableController::default(),
            peer_custody: HashMap::new(),
            pending_root_requests: HashMap::new(),
            pending_envelope_requests: HashMap::new(),
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
            seen_block_columns: ethlambda_state_transition::beacon::gossip::SeenBlockColumns::new(
                crate::SEEN_COLUMNS_CAPACITY,
            ),
            seen_envelopes: ethlambda_state_transition::beacon::gossip::SeenEnvelopes::new(
                crate::SEEN_ENVELOPES_CAPACITY,
            ),
            seen_payload_attestations:
                ethlambda_state_transition::beacon::gossip::SeenPayloadAttestations::new(
                    crate::SEEN_PAYLOAD_ATTESTATIONS_CAPACITY,
                ),
            seen_aggregates:
                ethlambda_state_transition::beacon::gossip::aggregate::SeenAggregates::new(
                    crate::seen_aggregates_capacity(),
                    crate::seen_aggregates_capacity(),
                ),
            seen_attestations:
                ethlambda_state_transition::beacon::gossip::attestation::SeenAttestations::new(
                    crate::seen_attestations_capacity(backbone_attestation_subnets),
                ),
            seen_operations: Default::default(),
            gossip_validation_permits: std::sync::Arc::new(tokio::sync::Semaphore::new(
                crate::GOSSIP_VALIDATION_PERMITS,
            )),
            column_check_permits: std::sync::Arc::new(tokio::sync::Semaphore::new(
                crate::COLUMN_CHECK_PERMITS,
            )),
            attestation_validation_permits: std::sync::Arc::new(tokio::sync::Semaphore::new(
                crate::ATTESTATION_VALIDATION_PERMITS,
            )),
            seen_sync_messages:
                ethlambda_state_transition::beacon::gossip::sync_committee::SeenSyncCommitteeMessages::new(
                    crate::SEEN_SYNC_MESSAGES_CAPACITY,
                ),
            seen_sync_contributions:
                ethlambda_state_transition::beacon::gossip::sync_committee::SeenSyncContributions::new(
                    crate::SEEN_SYNC_AGGREGATORS_CAPACITY,
                    crate::SEEN_SYNC_DATA_CAPACITY,
                ),
            sync_validation_permits: std::sync::Arc::new(tokio::sync::Semaphore::new(
                crate::SYNC_VALIDATION_PERMITS,
            )),
            payload_attestation_pool: Default::default(),
            builder_market: Default::default(),
            builder_validation_permits: std::sync::Arc::new(tokio::sync::Semaphore::new(
                crate::BUILDER_VALIDATION_PERMITS,
            )),
            sync_committee_pool: Default::default(),
            aggregator_subnets: HashMap::new(),
            peer_scoring: None,
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

        let (by_peer, uncovered) =
            group_columns_by_custody_peer(&server, &[1, 2], &HashSet::new(), &HashSet::new(), true);

        // Column 3 is nobody's, so it is reported rather than pinned on a peer
        // that would answer empty.
        let (_, uncovered_3) =
            group_columns_by_custody_peer(&server, &[3], &HashSet::new(), &HashSet::new(), true);
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
        let (by_peer, uncovered) =
            group_columns_by_custody_peer(&server, &[7], &HashSet::new(), &HashSet::new(), true);

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
            config.fulu_fork_epoch * ethlambda_types::beacon::preset::slots_per_epoch();
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
        let (by_peer, uncovered) = group_columns_by_custody_peer(
            &server,
            &[4],
            &HashSet::from([failed]),
            &HashSet::new(),
            true,
        );

        assert!(by_peer.is_empty());
        assert_eq!(uncovered, vec![4]);
    }

    #[tokio::test]
    async fn a_custodian_that_missed_a_column_is_asked_after_the_others() {
        let mut server = unconnected_server().await;
        let first = PeerId::random();
        let second = PeerId::random();
        for peer in [first, second] {
            server
                .connected_peers
                .insert(peer, ConnectionDirection::Inbound);
            server.peer_custody.insert(peer, vec![4]);
        }
        let (asked_first, _) =
            group_columns_by_custody_peer(&server, &[4], &HashSet::new(), &HashSet::new(), true);
        let tried = *asked_first.keys().next().expect("a custodian is chosen");
        let other = if tried == first { second } else { first };

        // A retry tries the custodian that has not missed this column yet.
        let missed = HashSet::from([(tried, 4)]);
        let (by_peer, _) =
            group_columns_by_custody_peer(&server, &[4], &HashSet::new(), &missed, true);
        assert_eq!(by_peer, HashMap::from([(other, vec![4])]));

        // And comes back to one that has, rather than to nobody: at the tip a
        // custodian may simply not have had the column yet.
        let missed = HashSet::from([(first, 4), (second, 4)]);
        let (by_peer, uncovered) =
            group_columns_by_custody_peer(&server, &[4], &HashSet::new(), &missed, true);
        assert_eq!(by_peer.values().flatten().count(), 1);
        assert!(uncovered.is_empty());

        // Past the tip nothing is still arriving, so it does not.
        let (by_peer, uncovered) =
            group_columns_by_custody_peer(&server, &[4], &HashSet::new(), &missed, false);
        assert!(by_peer.is_empty());
        assert_eq!(uncovered, vec![4]);
    }

    /// The id of a lookup built by hand. `next_column_lookup` starts at 1, so
    /// no lookup started through `fetch_data_columns_from_peer` has it.
    const LOOKUP: u64 = 0;

    const FIRST_BACKOFF: Duration = Duration::from_millis(INITIAL_BACKOFF_MS);

    fn column_lookup(columns: Vec<u64>, asked: &[(u64, PeerId)]) -> PendingColumnRequest {
        let mut pending = PendingColumnRequest::new(columns, LOOKUP);
        pending.asked = asked.iter().copied().collect();
        pending
    }

    fn column_request(block_root: H256, peer: PeerId, columns: &[u64]) -> ColumnRequest {
        ColumnRequest {
            block_root,
            lookup: LOOKUP,
            peer,
            columns: columns.to_vec(),
        }
    }

    fn column_report(peer: PeerId, columns: &[u64], reply: ColumnReply) -> ColumnReport {
        ColumnReport {
            request: column_request(H256::repeat_byte(0xC0), peer, columns),
            reply,
        }
    }

    /// An answer carrying `columns`, every one of which passed the checks.
    fn delivering(columns: &[u64]) -> ColumnReply {
        let verdicts = columns
            .iter()
            .map(|&column| (column, ColumnVerdict::Delivered))
            .collect();
        ColumnReply::Answered(verdicts)
    }

    #[test]
    fn failures_across_a_split_lookup_share_one_retry() {
        // Three requests open for one root, the shape custody-aware splitting
        // produces. Each failure used to be able to schedule its own fan-out,
        // so one unanswered lookup against eight custodians became eight
        // retries, then sixty-four. The first failure's leftover is asked
        // after the first backoff; the others ride on that retry.
        let [a, b, c] = [PeerId::random(), PeerId::random(), PeerId::random()];
        let mut pending = column_lookup(vec![1, 2, 3], &[(1, a), (2, b), (3, c)]);

        let failed = column_report(a, &[1], ColumnReply::Failed);
        assert_eq!(
            settle_column_report(&mut pending, &failed),
            ColumnAttemptOutcome::Retry {
                attempts: 1,
                backoff: FIRST_BACKOFF,
            }
        );
        let failed = column_report(b, &[2], ColumnReply::Failed);
        assert_eq!(
            settle_column_report(&mut pending, &failed),
            ColumnAttemptOutcome::Waiting { asked: 1 }
        );
        let failed = column_report(c, &[3], ColumnReply::Failed);
        assert_eq!(
            settle_column_report(&mut pending, &failed),
            ColumnAttemptOutcome::Waiting { asked: 0 }
        );

        assert_eq!(pending.attempts, 2, "one attempt for the three failures");
        assert_eq!(pending.failed_peers, HashSet::from([a, b, c]));
        assert_eq!(pending.unasked(), vec![1, 2, 3], "all for the one retry");
    }

    #[test]
    fn a_column_lookup_gives_up_once_the_ladder_is_exhausted() {
        let peer = PeerId::random();
        let mut pending = column_lookup(vec![1], &[(1, peer)]);
        pending.attempts = MAX_FETCH_RETRIES;

        let failed = column_report(peer, &[1], ColumnReply::Failed);
        assert_eq!(
            settle_column_report(&mut pending, &failed),
            ColumnAttemptOutcome::GiveUp {
                attempts: MAX_FETCH_RETRIES
            }
        );
    }

    #[test]
    fn an_answer_carrying_every_missing_column_completes_the_lookup() {
        let peer = PeerId::random();
        let mut pending = column_lookup(vec![1, 2], &[(1, peer), (2, peer)]);

        let answer = column_report(peer, &[1, 2], delivering(&[1, 2]));
        assert_eq!(
            settle_column_report(&mut pending, &answer),
            ColumnAttemptOutcome::Complete
        );
        assert!(pending.failed_peers.is_empty());
    }

    #[test]
    fn a_short_answer_has_its_leftover_asked_without_waiting_for_its_siblings() {
        // A custodian of column 1 whose request hangs, and a peer of unknown
        // custody asked for 2 and 3 that answers with 2 only: the devnet's
        // shape. The leftover used to wait out the hung request's 10 s
        // timeout before anything asked for it again.
        let custodian = PeerId::random();
        let other = PeerId::random();
        let mut pending = column_lookup(vec![1, 2, 3], &[(1, custodian), (2, other), (3, other)]);

        let short = column_report(other, &[2, 3], delivering(&[2]));
        assert_eq!(
            settle_column_report(&mut pending, &short),
            ColumnAttemptOutcome::Retry {
                attempts: 1,
                backoff: FIRST_BACKOFF,
            }
        );
        assert_eq!(pending.columns, vec![1, 3]);
        assert_eq!(
            pending.unasked(),
            vec![3],
            "1 is still on the wire with the custodian"
        );
        assert!(
            pending.failed_peers.is_empty(),
            "at the tip it may not have had 3 yet"
        );
        assert!(pending.missed.contains(&(other, 3)));
    }

    #[test]
    fn a_custodian_answering_without_its_own_column_is_not_written_off() {
        // At the tip a custodian often has not received every column yet. It
        // used to be excluded for the rest of the lookup, leaving its column
        // to peers known not to keep it.
        let custodian = PeerId::random();
        let mut pending = column_lookup(vec![1, 2], &[(1, custodian), (2, custodian)]);

        let short = column_report(custodian, &[1, 2], delivering(&[1]));
        assert_eq!(
            settle_column_report(&mut pending, &short),
            ColumnAttemptOutcome::Retry {
                attempts: 1,
                backoff: FIRST_BACKOFF,
            }
        );
        assert!(pending.failed_peers.is_empty());
        assert!(
            pending.missed.contains(&(custodian, 2)),
            "another custodian of 2 is tried first, when there is one"
        );
    }

    #[test]
    fn a_request_that_delivered_its_whole_share_spends_no_attempt() {
        // Column 4 merged into the lookup after the request for 1 went out.
        // Nobody failed, so the retry that asks for it is due at once and
        // spends nothing.
        let peer = PeerId::random();
        let mut pending = column_lookup(vec![1, 4], &[(1, peer)]);

        let whole = column_report(peer, &[1], delivering(&[1]));
        assert_eq!(
            settle_column_report(&mut pending, &whole),
            ColumnAttemptOutcome::Retry {
                attempts: 1,
                backoff: Duration::ZERO,
            }
        );
        assert_eq!(pending.columns, vec![4]);
        assert!(pending.failed_peers.is_empty());

        // However many such rounds a lookup takes, one column delivered and
        // another merged in each time, none of them reaches the end of the
        // ladder.
        let rounds = 2 * u64::from(MAX_FETCH_RETRIES);
        for column in 4..4 + rounds {
            pending.retry_due = false;
            pending.asked.insert(column, peer);
            pending.columns.push(column + 1);
            let whole = column_report(peer, &[column], delivering(&[column]));
            assert_eq!(
                settle_column_report(&mut pending, &whole),
                ColumnAttemptOutcome::Retry {
                    attempts: 1,
                    backoff: Duration::ZERO,
                }
            );
        }
        assert_eq!(pending.attempts, 1);
    }

    #[test]
    fn a_report_from_a_replaced_lookup_settles_nothing_of_the_new_one() {
        // `STALE_COLUMN_LOOKUP` (8 s) is shorter than the request timeout
        // (10 s), so a request of a replaced lookup can report after its
        // replacement has started. Its failure used to close one of the new
        // lookup's requests early.
        let new_peer = PeerId::random();
        let old_peer = PeerId::random();
        let mut pending = column_lookup(vec![1, 2], &[(1, new_peer), (2, new_peer)]);
        let mut late = column_report(old_peer, &[1, 2], ColumnReply::Failed);
        late.request.lookup = LOOKUP + 1;

        assert_eq!(
            settle_column_report(&mut pending, &late),
            ColumnAttemptOutcome::Waiting { asked: 2 }
        );
        assert_eq!(
            pending.asked.len(),
            2,
            "the new lookup's requests stay open"
        );
        assert_eq!(pending.attempts, 1);
        assert!(
            pending.failed_peers.is_empty(),
            "a failure may be what got the old lookup replaced"
        );

        // An invalid sidecar still writes its sender off for this root.
        late.reply = ColumnReply::Answered(vec![(1, ColumnVerdict::Rejected)]);
        settle_column_report(&mut pending, &late);
        assert_eq!(pending.failed_peers, HashSet::from([old_peer]));
        assert_eq!(pending.asked.len(), 2);

        // What such a request delivers is here all the same.
        late.reply = delivering(&[1, 2]);
        assert_eq!(
            settle_column_report(&mut pending, &late),
            ColumnAttemptOutcome::Complete
        );
    }

    #[test]
    fn a_sidecar_the_checks_refuse_stays_missing_and_is_held_against_its_sender() {
        // The right root and index used to be enough to take a column off the
        // lookup and clear its sender, whatever its cells and proofs were.
        let custodian = PeerId::random();
        let mut pending = column_lookup(vec![1, 2], &[(1, custodian), (2, custodian)]);

        let verdicts = vec![(1, ColumnVerdict::Delivered), (2, ColumnVerdict::Rejected)];
        let answer = column_report(custodian, &[1, 2], ColumnReply::Answered(verdicts));
        assert_eq!(
            settle_column_report(&mut pending, &answer),
            ColumnAttemptOutcome::Retry {
                attempts: 1,
                backoff: FIRST_BACKOFF,
            }
        );
        assert_eq!(pending.columns, vec![2]);
        assert!(pending.failed_peers.contains(&custodian));
    }

    #[test]
    fn an_undecided_sidecar_stays_missing_without_blaming_its_sender() {
        let peer = PeerId::random();
        let mut pending = column_lookup(vec![1], &[(1, peer)]);

        let verdicts = vec![(1, ColumnVerdict::Undecided)];
        let answer = column_report(peer, &[1], ColumnReply::Answered(verdicts));
        assert!(matches!(
            settle_column_report(&mut pending, &answer),
            ColumnAttemptOutcome::Retry { .. }
        ));
        assert_eq!(pending.columns, vec![1]);
        assert!(pending.failed_peers.is_empty());
    }

    /// A beacon server with `peers` connected, each with the custody it has
    /// told this node (`None`: nothing yet).
    async fn beacon_server_with(peers: &[(PeerId, Option<Vec<u64>>)]) -> P2PServer {
        let mut server = crate::test_support::unconnected_beacon_server(Config::mainnet(), 0).await;
        for (peer, custody) in peers {
            server
                .connected_peers
                .insert(*peer, ConnectionDirection::Inbound);
            if let Some(custody) = custody {
                server.peer_custody.insert(*peer, custody.clone());
            }
        }
        server
    }

    /// A shaped fulu sidecar of `index`, with the root of the block it names.
    fn sidecar_of(index: u64) -> (DataColumnSidecar, H256) {
        let sidecar = DataColumnSidecar::Fulu(crate::test_support::valid_shaped_sidecar(5, index));
        let root = sidecar.block_root();
        (sidecar, root)
    }

    #[tokio::test]
    async fn a_column_no_known_custodian_covers_goes_only_to_a_peer_that_has_said_nothing() {
        // Uniformly random used to include peers whose recorded custody
        // excludes the column, and asking one of them is a round spent on a
        // request that cannot be answered.
        let holder = PeerId::random();
        let elsewhere = PeerId::random();
        let silent = PeerId::random();
        let mut server = beacon_server_with(&[
            (holder, Some(vec![1])),
            (elsewhere, Some(vec![9])),
            (silent, None),
        ])
        .await;
        let root = H256::repeat_byte(0x51);

        assert!(fetch_data_columns_from_peer(&mut server, root, vec![1, 2, 3]).await);

        let pending = &server.pending_column_requests[&root];
        assert_eq!(
            pending.asked,
            HashMap::from([(1, holder), (2, silent), (3, silent)])
        );
        assert_eq!(server.outbound_requests.len(), 2);
        assert!(server.outbound_requests.values().all(|kind| matches!(
            kind,
            PendingRequestKind::Columns { lookup, .. } if *lookup == pending.lookup
        )));
    }

    #[tokio::test]
    async fn a_column_nobody_is_known_to_keep_is_asked_beyond_custody_once_per_lookup() {
        // A held block's column that no connected peer keeps used to cost
        // every remaining rung of the ladder, a random peer a rung, then an
        // error and the max-retries count, once a slot. With nobody of unknown
        // custody connected, one peer that has said what it keeps is asked
        // once (it may hold more), and then the lookup ends quietly.
        let elsewhere = PeerId::random();
        let mut server = beacon_server_with(&[(elsewhere, Some(vec![9]))]).await;
        let root = H256::repeat_byte(0x52);

        assert!(fetch_data_columns_from_peer(&mut server, root, vec![2]).await);
        let pending = &server.pending_column_requests[&root];
        let lookup = pending.lookup;
        assert_eq!(pending.asked, HashMap::from([(2, elsewhere)]));
        assert!(pending.asked_beyond_custody);

        // It does not have 2 after all.
        let mut empty = column_report(elsewhere, &[2], delivering(&[]));
        empty.request.block_root = root;
        empty.request.lookup = lookup;
        assert!(matches!(
            report_column_request(&mut server, &empty),
            Some(ColumnAttemptOutcome::Retry { .. })
        ));

        let before = metrics::data_column_fetch_failures_total("no_custodian");
        retry_column_lookup(&mut server, root, lookup).await;

        assert!(server.pending_column_requests.is_empty());
        assert_eq!(
            server.outbound_requests.len(),
            1,
            "nobody was asked a second time"
        );
        assert!(
            metrics::data_column_fetch_failures_total("no_custodian") > before,
            "counted as having nobody to ask, not as running out of retries"
        );
    }

    #[tokio::test]
    async fn at_the_tip_a_peer_that_answered_short_is_asked_again() {
        // The devnet's shape: a custodian of one column, and the only peer of
        // unknown custody asked for the rest, which at the tip has 2 but not
        // yet 3. Writing it off would leave 3 nobody to ask until the next
        // slot's re-ask, the ~12 s hold this lookup exists to remove.
        let custodian = PeerId::random();
        let silent = PeerId::random();
        let mut server = beacon_server_with(&[(custodian, Some(vec![1])), (silent, None)]).await;
        let root = H256::repeat_byte(0x56);
        let now = server.wire.beacon().expect("a beacon wire").wall_slot();

        assert!(fetch_data_columns_from_peer(&mut server, root, vec![1, 2, 3]).await);
        let pending = server
            .pending_column_requests
            .get_mut(&root)
            .expect("a lookup");
        pending.slot = Some(now);
        let lookup = pending.lookup;
        let mut short = column_report(silent, &[2, 3], delivering(&[2]));
        short.request.block_root = root;
        short.request.lookup = lookup;
        assert!(matches!(
            report_column_request(&mut server, &short),
            Some(ColumnAttemptOutcome::Retry { .. })
        ));
        let mut whole = column_report(custodian, &[1], delivering(&[1]));
        whole.request.block_root = root;
        whole.request.lookup = lookup;
        report_column_request(&mut server, &whole);

        retry_column_lookup(&mut server, root, lookup).await;

        assert_eq!(
            server.pending_column_requests[&root].asked,
            HashMap::from([(3, silent)])
        );
    }

    #[tokio::test]
    async fn past_the_tip_each_peer_is_asked_for_a_column_once() {
        // The mainnet case: a held block re-asked a slot later for a
        // column no connected peer is known to keep. Nothing is still arriving
        // by then, so a peer that answered without it is not asked again: each
        // peer of unknown custody is asked once, and then the lookup ends
        // quietly instead of walking the ladder.
        let [first, second] = [PeerId::random(), PeerId::random()];
        let mut server = beacon_server_with(&[(first, None), (second, None)]).await;
        let root = H256::repeat_byte(0x58);

        assert!(fetch_data_columns_from_peer(&mut server, root, vec![2]).await);
        let pending = server
            .pending_column_requests
            .get_mut(&root)
            .expect("a lookup");
        pending.slot = Some(5);
        let lookup = pending.lookup;
        let before = metrics::data_column_fetch_failures_total("no_custodian");

        for _ in 0..2 {
            let asked = server.pending_column_requests[&root].asked[&2];
            let mut empty = column_report(asked, &[2], delivering(&[]));
            empty.request.block_root = root;
            empty.request.lookup = lookup;
            report_column_request(&mut server, &empty);
            retry_column_lookup(&mut server, root, lookup).await;
        }

        assert!(server.pending_column_requests.is_empty());
        assert_eq!(server.outbound_requests.len(), 2, "one ask each");
        assert!(metrics::data_column_fetch_failures_total("no_custodian") > before);
    }

    #[tokio::test]
    async fn past_the_tip_a_peer_is_still_asked_for_the_columns_it_has_not_missed() {
        // It used to be passed over for every uncovered column once it had
        // missed any one of them, so a column merged in after its short answer
        // went to nobody and waited for the next slot's re-ask.
        let silent = PeerId::random();
        let mut server = beacon_server_with(&[(silent, None)]).await;
        let root = H256::repeat_byte(0x59);
        let mut pending = column_lookup(vec![1, 2], &[]);
        pending.slot = Some(5);
        pending.missed.insert((silent, 1));
        server.pending_column_requests.insert(root, pending);

        ask_unasked_columns(&mut server, root).await;

        assert_eq!(
            server.pending_column_requests[&root].asked,
            HashMap::from([(2, silent)])
        );
    }

    #[tokio::test]
    async fn a_lookup_every_peer_failed_ends_as_peers_exhausted() {
        // Not "nobody holds the columns": nobody was left to say.
        let custodian = PeerId::random();
        let mut server = beacon_server_with(&[(custodian, Some(vec![1]))]).await;
        let root = H256::repeat_byte(0x5A);
        let mut pending = column_lookup(vec![1], &[]);
        pending.failed_peers.insert(custodian);
        server.pending_column_requests.insert(root, pending);
        let before = metrics::data_column_fetch_failures_total("peers_exhausted");

        ask_unasked_columns(&mut server, root).await;

        assert!(server.pending_column_requests.is_empty());
        assert!(metrics::data_column_fetch_failures_total("peers_exhausted") > before);
    }

    /// An empty fulu block at `slot`.
    fn fulu_block_at(slot: u64) -> SignedBeaconBlock {
        use ethlambda_types::beacon::containers::electra;
        SignedBeaconBlock::Fulu(electra::SignedBeaconBlock {
            message: electra::BeaconBlock {
                slot,
                proposer_index: 0,
                parent_root: H256::ZERO,
                state_root: H256::ZERO,
                body: electra::BeaconBlockBody::empty(),
            },
            signature: Default::default(),
        })
    }

    #[tokio::test]
    async fn a_lookup_reads_the_tip_from_its_held_block_in_the_store() {
        // Nothing tells a lookup its block's slot: a held envelope's block is
        // imported and a held fulu block is written as pending, so the store
        // has it, and a peer that answered short at the tip is asked again.
        let silent = PeerId::random();
        let mut server = beacon_server_with(&[(silent, None)]).await;
        let now = server.wire.beacon().expect("a beacon wire").wall_slot();
        let root = H256::repeat_byte(0x5B);
        server
            .store
            .insert_pending_block(root, fulu_block_at(now))
            .expect("stored");
        let mut pending = column_lookup(vec![1], &[]);
        pending.missed.insert((silent, 1));
        server.pending_column_requests.insert(root, pending);

        ask_unasked_columns(&mut server, root).await;

        let pending = &server.pending_column_requests[&root];
        assert_eq!(pending.slot, Some(now));
        assert_eq!(pending.asked, HashMap::from([(1, silent)]));
    }

    #[tokio::test]
    async fn a_retry_asks_only_for_what_the_store_does_not_have() {
        // Gossip often delivers a column while a lookup started at the tip is
        // still asking for it.
        let silent = PeerId::random();
        let mut server = beacon_server_with(&[(silent, None)]).await;
        let (stored, root) = sidecar_of(1);
        server.store.put_data_column(&stored).expect("stored");
        let mut pending = column_lookup(vec![1, 2], &[]);
        pending.slot = Some(5);
        pending.retry_due = true;
        server.pending_column_requests.insert(root, pending);

        retry_column_lookup(&mut server, root, LOOKUP).await;

        let pending = &server.pending_column_requests[&root];
        assert_eq!(pending.columns, vec![2]);
        assert_eq!(pending.asked, HashMap::from([(2, silent)]));
        assert!(!pending.retry_due);

        // Once the store has everything, the lookup is complete and the next
        // retry asks nobody.
        let (also_stored, _) = sidecar_of(2);
        server.store.put_data_column(&also_stored).expect("stored");
        let asked_before = server.outbound_requests.len();
        retry_column_lookup(&mut server, root, LOOKUP).await;
        assert!(server.pending_column_requests.is_empty());
        assert_eq!(server.outbound_requests.len(), asked_before);
    }

    #[tokio::test]
    async fn a_retry_for_a_lookup_that_was_replaced_does_nothing() {
        let silent = PeerId::random();
        let mut server = beacon_server_with(&[(silent, None)]).await;
        let root = H256::repeat_byte(0x53);
        let mut pending = column_lookup(vec![1], &[]);
        pending.retry_due = true;
        server.pending_column_requests.insert(root, pending);

        retry_column_lookup(&mut server, root, LOOKUP + 1).await;

        assert!(server.outbound_requests.is_empty());
        assert!(server.pending_column_requests[&root].retry_due);
    }

    #[tokio::test]
    async fn a_column_merged_into_a_lookup_is_asked_at_once() {
        // The re-ask that merges it used to send nothing while the lookup was
        // younger than `STALE_COLUMN_LOOKUP`, leaving it to the lookup's next
        // retry, which a hung request could hold back for its whole timeout.
        let holder = PeerId::random();
        let silent = PeerId::random();
        let mut server = beacon_server_with(&[(holder, Some(vec![1])), (silent, None)]).await;
        let root = H256::repeat_byte(0x54);
        server
            .pending_column_requests
            .insert(root, column_lookup(vec![1, 2], &[(1, holder)]));

        ask_unasked_columns(&mut server, root).await;

        assert_eq!(
            server.pending_column_requests[&root].asked,
            HashMap::from([(1, holder), (2, silent)])
        );
        let sent: Vec<_> = server.outbound_requests.values().collect();
        assert!(matches!(
            sent.as_slice(),
            [PendingRequestKind::Columns { columns, lookup: LOOKUP, .. }] if *columns == vec![2]
        ));
    }

    #[tokio::test]
    async fn an_answer_settles_its_lookup_once_its_sidecars_are_checked() {
        use crate::beacon::column_checks::tests::RecordingChain;

        let peer = PeerId::random();
        let mut server = beacon_server_with(&[(peer, None)]).await;
        let (sender, _forwarded) = tokio::sync::mpsc::unbounded_channel();
        server.blockchain = Some(Arc::new(RecordingChain(sender)));
        // Stored already, so the checks find the column here without the
        // parent state a sidecar of a new block would need.
        let (sidecar, root) = sidecar_of(1);
        server.store.put_data_column(&sidecar).expect("stored");
        server
            .pending_column_requests
            .insert(root, column_lookup(vec![1], &[(1, peer)]));

        let (reports, mut checked) = tokio::sync::mpsc::unbounded_channel();
        let request = column_request(root, peer, &[1]);
        let outcome = take_column_answer(&mut server, request, vec![sidecar], move |report| {
            let _ = reports.send(report);
        });

        assert_eq!(outcome, None, "nothing is settled before the checks");
        assert_eq!(
            server.pending_column_requests[&root].asked,
            HashMap::from([(1, peer)]),
            "a column being checked is not asked of anyone else"
        );

        let report = checked.recv().await.expect("the checks report back");
        assert_eq!(
            report.reply,
            ColumnReply::Answered(vec![(1, ColumnVerdict::Delivered)])
        );
        assert_eq!(
            report_column_request(&mut server, &report),
            Some(ColumnAttemptOutcome::Complete)
        );
        assert!(
            server.pending_column_requests.is_empty(),
            "a complete lookup is retired"
        );
    }

    #[tokio::test]
    async fn an_answer_no_lookup_waits_on_is_still_checked_and_forwarded() {
        use crate::beacon::column_checks::tests::{Forwarded, RecordingChain};

        let peer = PeerId::random();
        let mut server = beacon_server_with(&[(peer, None)]).await;
        let (sender, mut forwarded) = tokio::sync::mpsc::unbounded_channel();
        server.blockchain = Some(Arc::new(RecordingChain(sender)));
        // Its parent is not in the store, so the chain actor parks it.
        let (sidecar, root) = sidecar_of(1);

        let (reports, mut checked) = tokio::sync::mpsc::unbounded_channel();
        let request = column_request(root, peer, &[1]);
        let outcome =
            take_column_answer(&mut server, request, vec![sidecar.clone()], move |report| {
                let _ = reports.send(report);
            });

        assert_eq!(outcome, None);
        assert_eq!(
            forwarded.recv().await,
            Some(Forwarded::AwaitingParent(vec![sidecar]))
        );
        let report = checked.recv().await.expect("the checks report back");
        assert_eq!(report_column_request(&mut server, &report), None);
        assert!(
            server.pending_column_requests.is_empty(),
            "nothing is resurrected"
        );
    }

    #[tokio::test]
    async fn an_answer_at_the_end_of_the_ladder_gives_the_lookup_up() {
        // A custodian, so running out is a failure to fetch what someone
        // should have had.
        let peer = PeerId::random();
        let mut server = beacon_server_with(&[(peer, Some(vec![1, 2]))]).await;
        let root = H256::repeat_byte(0x55);
        let mut pending = column_lookup(vec![1, 2], &[(1, peer), (2, peer)]);
        pending.attempts = MAX_FETCH_RETRIES;
        server.pending_column_requests.insert(root, pending);
        let before = metrics::data_column_fetch_failures_total("max_retries");

        let request = column_request(root, peer, &[1, 2]);
        let outcome = take_column_answer(&mut server, request, Vec::new(), |_| {
            unreachable!("an empty answer has nothing to check")
        });

        assert_eq!(
            outcome,
            Some(ColumnAttemptOutcome::GiveUp {
                attempts: MAX_FETCH_RETRIES
            })
        );
        assert!(server.pending_column_requests.is_empty());
        assert!(metrics::data_column_fetch_failures_total("max_retries") > before);
    }

    #[tokio::test]
    async fn a_ladder_spent_on_columns_nobody_keeps_ends_as_no_custodian() {
        // Not an error: nobody connected was known to hold them.
        let silent = PeerId::random();
        let mut server = beacon_server_with(&[(silent, None)]).await;
        let root = H256::repeat_byte(0x57);
        let mut pending = column_lookup(vec![1], &[(1, silent)]);
        pending.attempts = MAX_FETCH_RETRIES;
        server.pending_column_requests.insert(root, pending);
        let before = metrics::data_column_fetch_failures_total("no_custodian");

        let request = column_request(root, silent, &[1]);
        let outcome = take_column_answer(&mut server, request, Vec::new(), |_| {
            unreachable!("an empty answer has nothing to check")
        });

        assert!(matches!(outcome, Some(ColumnAttemptOutcome::GiveUp { .. })));
        assert!(server.pending_column_requests.is_empty());
        assert!(metrics::data_column_fetch_failures_total("no_custodian") > before);
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
    fn beacon_sync_target_keys_off_fetched_through_while_the_head_lags() {
        // A batch already handed to the chain actor but not yet imported
        // leaves the store's own head behind `fetched_through`; the sync
        // target must still be computed from `fetched_through`. See
        // `beacon_sync_target`'s own doc comment for why the store's head
        // alone is the wrong signal to drive this off: it is what pulled
        // 11,213 blocks off the wire to import 100 on the live follower.
        assert_eq!(beacon_sync_target(100, 40, 150), Some(101..151));
        // A peer at or behind what has already been fetched has nothing to
        // offer, regardless of what the store's own (possibly much lower)
        // head happens to be.
        assert_eq!(beacon_sync_target(150, 40, 150), None);
        assert_eq!(beacon_sync_target(150, 40, 100), None);
    }

    #[test]
    fn beacon_sync_target_starts_after_a_head_gossip_moved_past_fetched_through() {
        // A caught-up follower imports from gossip, which leaves
        // `fetched_through` at its last range batch. A peer one block ahead
        // is owed that one block, not every block since that batch.
        assert_eq!(beacon_sync_target(100, 149, 150), Some(150..151));
        // A peer at or behind the head has nothing to offer, however far
        // behind `fetched_through` is.
        assert_eq!(beacon_sync_target(100, 150, 150), None);
        assert_eq!(beacon_sync_target(100, 160, 150), None);
    }

    #[test]
    fn beacon_sync_target_is_bounded_by_max_sync_range() {
        let target = beacon_sync_target(0, 0, u64::MAX).expect("peer is far ahead");
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

    fn gloas_column(block_root: H256, index: u64) -> DataColumnSidecar {
        DataColumnSidecar::Gloas(gloas::DataColumnSidecar {
            index,
            slot: 5,
            beacon_block_root: block_root,
            ..Default::default()
        })
    }

    #[test]
    fn a_by_root_answer_keeps_only_the_requested_block_and_columns() {
        let asked = H256::repeat_byte(1);
        let other = H256::repeat_byte(2);
        let answer = vec![
            gloas_column(asked, 3),
            // A column of the right block that was not asked for.
            gloas_column(asked, 4),
            // A column of a block that was not asked for.
            gloas_column(other, 3),
        ];

        let (kept, dropped) = retain_requested_columns(answer, asked, &[3]);

        assert_eq!(kept, vec![gloas_column(asked, 3)]);
        assert_eq!(dropped, 2);
    }
}
