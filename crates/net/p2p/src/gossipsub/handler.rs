//! What `P2PServer` does with gossip, on either chain.
//!
//! One entry point and one dispatch, the shape `crate::req_resp::handlers` has:
//! the topic says which chain a message belongs to, so nothing above this module
//! branches on which chain the node follows. Handler names follow the same
//! convention as there, lean prefixed and beacon bare.

use std::time::Instant;

use ethlambda_network_api::{AggregateArrival, BlockAnnouncement, BlockArrival, BlockSource};
use ethlambda_state_transition::beacon::das;
use ethlambda_state_transition::beacon::gossip::{self, IgnoreReason, Outcome, RejectReason};
use ethlambda_types::{
    ShortRoot,
    attestation::{SignedAggregatedAttestation, SignedAttestation},
    beacon::containers::{DataColumnSidecar, SignedBeaconBlock, electra::SingleAttestation},
    beacon::fork::ForkName,
    beacon::operation::BeaconOperation,
    beacon::primitives::ValidatorIndex,
    block::SignedBlock,
    primitives::HashTreeRoot as _,
    time::unix_now_ms,
};
use libp2p::PeerId;
use libp2p::gossipsub::{IdentTopic, Message, MessageId};
use libssz::{SszDecode, SszEncode};
use spawned_concurrency::tasks::Context;
use tracing::{debug, error, info, trace, warn};

use super::{
    encoding::{compress_message, decompress_message},
    messages::{
        AGGREGATION_TOPIC_KIND, ATTESTATION_SUBNET_TOPIC_PREFIX, BLOCK_TOPIC_KIND,
        attestation_subnet_topic, topic_kind,
    },
};
use crate::beacon::constants::ATTESTATION_SUBNET_COUNT;
use crate::beacon::decode::BeaconGossip;
use crate::beacon::verdict::{self, Dispatch, GossipId, Validated};
use crate::beacon::{BeaconWire, decode as beacon_decode, topics as beacon_topics};
use crate::{P2PServer, metrics};

/// What `P2PServer` does with a gossip message, whichever chain it came from.
///
/// Read the topic's kind, undo the snappy framing, dispatch. None of those three
/// is chain-specific: the two wires name their topics disjointly
/// (`/leanconsensus/…/block` against `/eth2/…/beacon_block`) and frame with the
/// same raw snappy, so the topic alone says where a message goes and nothing
/// here asks `server.wire`. That mirrors req/resp, where the protocol id plays
/// the same part.
///
/// One match, with both chains' topics at the same level. Only the SSZ container
/// behind the decompressed bytes differs, and that is a handler's business.
/// Beacon topics get a verdict through [`crate::beacon::verdict`]: gossipsub
/// holds the message until `verdict::report` answers for it. Lean topics are
/// forwarded by gossipsub without one, since lean gossip validation is out of
/// scope here.
pub async fn handle_gossip_message(
    server: &mut P2PServer,
    ctx: &Context<P2PServer>,
    propagation_source: PeerId,
    message_id: MessageId,
    message: Message,
) {
    // Taken before anything is done with the payload, so the decode a block
    // pays for is inside the span rather than before it. The lean block
    // handler uses it for its own import-arrival timing; every beacon topic
    // uses it too, via `GossipId::received_at`, since every beacon verdict is
    // timed from wire arrival. Lean's aggregation and attestation handlers
    // are the only paths that ignore it.
    let wire_at = Instant::now();
    let Some(kind) = topic_kind(message.topic.as_str()) else {
        trace!(topic = %message.topic, "Gossip on an unparseable topic");
        return;
    };
    // A beacon topic needs a verdict: gossipsub holds the message until
    // `verdict::report` answers for it. `None` for a lean topic, which the
    // lean wire forwards without asking.
    let beacon_id = beacon_topics::metric_kind(kind).map(|metric_kind| GossipId {
        message_id,
        propagation_source,
        received_at: wire_at,
        kind: metric_kind,
    });
    trace!(
        kind,
        peer_count = server.connected_peers.len(),
        "P2P message received"
    );

    let compressed_len = message.data.len();
    let Some(payload) = decompress(&message.data, kind) else {
        if let Some(id) = beacon_id {
            verdict::report(server, id, Outcome::Reject(RejectReason::Decompress));
        }
        return;
    };

    match kind {
        BLOCK_TOPIC_KIND => handle_lean_block(server, &payload, compressed_len, wire_at).await,
        AGGREGATION_TOPIC_KIND => handle_lean_aggregation(server, &payload, compressed_len).await,
        kind if kind.starts_with(ATTESTATION_SUBNET_TOPIC_PREFIX) => {
            handle_lean_attestation(server, &payload, compressed_len).await
        }
        _ => match beacon_id {
            Some(id) => {
                handle_beacon_gossip(server, ctx, id, message.topic.as_str(), kind, &payload)
            }
            None => trace!(topic = %message.topic, "Gossip on an unhandled topic"),
        },
    }
}

/// Undo the snappy framing both wires use.
///
/// The failure bookkeeping is the one asymmetric part, and stays that way:
/// beacon counts what it drops per topic kind, lean has no counterpart metric.
/// Both log.
///
/// Gated on [`beacon_topics::metric_kind`] rather than
/// [`beacon_topics::SUBSCRIBED_TOPIC_KINDS`] directly, and labelled with its
/// answer rather than the raw `kind`: a data column or attestation subnet's
/// `kind` is a per-subnet string (`data_column_sidecar_7`), and counting that
/// verbatim would give the metric one label value per subnet rather than one
/// per family, the same collapse every other beacon gossip counter already
/// does for those two families.
fn decompress(data: &[u8], kind: &str) -> Option<Vec<u8>> {
    decompress_message(data)
        .inspect_err(|err| {
            error!(%err, kind, "Failed to decompress gossipped message");
            if let Some(metric_kind) = beacon_topics::metric_kind(kind) {
                metrics::inc_beacon_gossip(metric_kind, "decompress_failed");
            }
        })
        .ok()
}

/// SSZ-decode a lean gossip payload, or `None` after logging why.
fn decode_lean<T: SszDecode>(payload: &[u8], what: &'static str) -> Option<T> {
    T::from_ssz_bytes(payload)
        .inspect_err(|err| error!(?err, what, "Failed to decode gossipped message"))
        .ok()
}

async fn handle_lean_block(
    server: &mut P2PServer,
    payload: &[u8],
    compressed_len: usize,
    wire_at: Instant,
) {
    metrics::observe_gossip_block_size(payload.len(), compressed_len);
    let Some(signed_block) = decode_lean::<SignedBlock>(payload, "block") else {
        return;
    };
    let block_root = signed_block.message.hash_tree_root();
    info!(
        slot = %signed_block.message.slot,
        proposer = signed_block.message.proposer_index,
        block_root = %ShortRoot(&block_root.0),
        parent_root = %ShortRoot(&signed_block.message.parent_root.0),
        attestation_count = signed_block.message.body.attestations.len(),
        "Received block from gossip"
    );
    if let Some(ref blockchain) = server.blockchain {
        let arrival = BlockArrival {
            decode_start: Some(wire_at),
            handed_off: Instant::now(),
            deferred_from: None,
        };
        let _ = blockchain
            .new_block(
                SignedBeaconBlock::Lean(signed_block),
                BlockSource::Gossip,
                arrival,
                BlockAnnouncement::Announce,
            )
            .inspect_err(|err| error!(%err, "Failed to forward block to blockchain"));
    }
}

async fn handle_lean_aggregation(server: &mut P2PServer, payload: &[u8], compressed_len: usize) {
    metrics::observe_gossip_aggregation_size(payload.len(), compressed_len);
    let Some(aggregation) = decode_lean::<SignedAggregatedAttestation>(payload, "aggregation")
    else {
        return;
    };
    info!(
        slot = %aggregation.data.slot,
        target_slot = aggregation.data.target.slot,
        target_root = %ShortRoot(&aggregation.data.target.root.0),
        source_slot = aggregation.data.source.slot,
        source_root = %ShortRoot(&aggregation.data.source.root.0),
        "Received aggregated attestation from gossip"
    );
    if let Some(ref blockchain) = server.blockchain {
        let _ = blockchain
            .new_aggregated_attestation(aggregation)
            .inspect_err(
                |err| error!(%err, "Failed to forward aggregated attestation to blockchain"),
            );
    }
}

async fn handle_lean_attestation(server: &mut P2PServer, payload: &[u8], compressed_len: usize) {
    metrics::observe_gossip_attestation_size(payload.len(), compressed_len);
    let Some(signed_attestation) = decode_lean::<SignedAttestation>(payload, "attestation") else {
        return;
    };
    trace!(
        slot = %signed_attestation.data.slot,
        validator = signed_attestation.validator_id,
        head_root = %ShortRoot(&signed_attestation.data.head.root.0),
        target_slot = signed_attestation.data.target.slot,
        target_root = %ShortRoot(&signed_attestation.data.target.root.0),
        source_slot = signed_attestation.data.source.slot,
        source_root = %ShortRoot(&signed_attestation.data.source.root.0),
        "Received attestation from gossip"
    );
    if let Some(ref blockchain) = server.blockchain {
        let _ = blockchain
            .new_attestation(signed_attestation)
            .inspect_err(|err| error!(%err, "Failed to forward attestation to blockchain"));
    }
}

/// Decide what to do with one beacon gossip message, then do it. Every path
/// ends in exactly one verdict for `id`, reported here or by the blocking
/// task a [`Dispatch::Validate`] spawns.
fn handle_beacon_gossip(
    server: &P2PServer,
    ctx: &Context<P2PServer>,
    id: GossipId,
    topic: &str,
    kind: &str,
    payload: &[u8],
) {
    let Some(wire) = server.wire.beacon() else {
        // Beacon topics are never subscribed on a lean node, whose gossipsub
        // holds nothing for a verdict.
        debug!(kind, "Beacon gossip arrived on a lean node");
        return;
    };
    // The fork comes from the topic's own digest: while a boundary's window is
    // open the node is subscribed under two, and `wire.fork` is only the one it
    // publishes under.
    let topic_fork = beacon_topics::topic_digest(topic)
        .and_then(|digest| wire.schedule.fork_for_digest(digest))
        .unwrap_or(wire.fork);
    let dispatch = if kind == beacon_topics::BEACON_BLOCK {
        triage_block(server, wire, payload)
    } else if let Some(subnet_id) = beacon_topics::data_column_subnet(kind) {
        triage_data_column(server, topic_fork, payload, subnet_id)
    } else if kind == beacon_topics::BEACON_AGGREGATE_AND_PROOF {
        triage_aggregate(server, wire, payload, id.received_at)
    } else if let Some(subnet_id) = beacon_topics::attestation_subnet(kind) {
        triage_attestation(server, topic_fork, payload, subnet_id)
    } else if kind == beacon_topics::EXECUTION_PAYLOAD {
        triage_envelope(server, payload)
    } else if kind == beacon_topics::PAYLOAD_ATTESTATION_MESSAGE {
        triage_payload_attestation(server, payload)
    } else if kind == beacon_topics::INCLUSION_LIST {
        triage_inclusion_list(server, payload)
    } else if matches!(
        kind,
        beacon_topics::VOLUNTARY_EXIT
            | beacon_topics::PROPOSER_SLASHING
            | beacon_topics::ATTESTER_SLASHING
            | beacon_topics::BLS_TO_EXECUTION_CHANGE
    ) {
        triage_operation(server, wire, kind, payload)
    } else if let Some(subnet_id) = beacon_topics::sync_committee_subnet(kind) {
        triage_sync_committee_message(server, payload, subnet_id)
    } else if kind == beacon_topics::SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF {
        triage_sync_contribution(server, payload)
    } else if kind == beacon_topics::EXECUTION_PAYLOAD_BID {
        crate::beacon::builder_market::triage_execution_payload_bid(server, payload)
    } else if kind == beacon_topics::PROPOSER_PREFERENCES {
        crate::beacon::builder_market::triage_proposer_preferences(server, payload)
    } else {
        triage_other(wire, kind, payload)
    };
    match dispatch {
        Dispatch::Report(outcome) => {
            // A cheap check never answers `Queue`: with no decoded object in
            // hand yet, there would be nothing here to forward. See
            // `Dispatch::Report`'s doc comment.
            debug_assert!(!matches!(outcome, Outcome::Queue(_)));
            verdict::report(server, id, outcome);
        }
        Dispatch::Validate(object) => verdict::spawn_stateful_checks(server, ctx, id, object),
    }
}

/// Decode a beacon block and run its cheap gossip checks: a verdict already,
/// or the object for [`verdict::spawn_stateful_checks`] to take further.
fn triage_block(server: &P2PServer, wire: &BeaconWire, payload: &[u8]) -> Dispatch {
    const KIND: &str = beacon_topics::BEACON_BLOCK;
    let block = match beacon_decode::decode_block(&wire.config, payload) {
        Ok(block) => block,
        // A block at a fork this build has no rules for, as on the aggregate
        // topic: an honest peer must not be scored as a bad decoder.
        Err(beacon_decode::DecodeError::UnsupportedFork) => {
            metrics::inc_beacon_gossip(KIND, "unsupported_fork");
            return Dispatch::Report(Outcome::Ignore(IgnoreReason::UnsupportedFork));
        }
        Err(err) => {
            metrics::inc_beacon_gossip(KIND, "decode_failed");
            debug!(kind = KIND, %err, bytes = payload.len(), "Beacon gossip decode failed");
            return Dispatch::Report(Outcome::Reject(RejectReason::Decode));
        }
    };
    metrics::inc_beacon_gossip(KIND, "decoded");
    let block_root = block.message_hash_tree_root();
    info!(
        slot = block.slot(),
        proposer = block.proposer_index(),
        fork = block.fork_name().as_str(),
        block_root = %ShortRoot(&block_root.0),
        bytes = payload.len(),
        "Beacon block decoded"
    );
    let now_ms = unix_now_ms();
    if let Err(outcome) =
        gossip::block::cheap_checks(&server.seen_blocks, &server.store, &block, now_ms)
    {
        return Dispatch::Report(outcome);
    }
    Dispatch::Validate(Validated::Block {
        block: Box::new(block),
        block_root,
    })
}

/// Decode a data column sidecar and run its cheap gossip checks. Same shape as
/// [`triage_block`].
///
/// Decodes first rather than gating on the clock: around a fork boundary the
/// node holds topics under two digests (see `beacon::transition`), so a late
/// but perfectly legitimate sidecar can still arrive on the old digest's
/// topic, and a clock check ahead of the decode would drop it, mistaking it for
/// the new fork's shape just because the clock has moved on. `fork` is the one
/// the message's own topic digest names, and it picks the container to decode
/// (fulu's and gloas's differ) and the cheap rules to run. On a decode failure
/// it also decides the verdict: a failure under a fork this build does not
/// follow is its own gap, so `Ignore`; under a followed fork it is the
/// sender's fault, so `Reject`.
fn triage_data_column(
    server: &P2PServer,
    fork: ForkName,
    payload: &[u8],
    subnet_id: u64,
) -> Dispatch {
    const KIND: &str = beacon_topics::DATA_COLUMN_SIDECAR_KIND;
    let sidecar = match beacon_decode::decode_data_column_sidecar(fork, payload) {
        Ok(sidecar) => sidecar,
        Err(err) => {
            if !fork.is_followed() {
                metrics::inc_beacon_gossip(KIND, "unsupported_fork");
                return Dispatch::Report(Outcome::Ignore(IgnoreReason::UnsupportedFork));
            }
            metrics::inc_beacon_gossip(KIND, "decode_failed");
            debug!(?err, "Dropping an undecodable data column sidecar");
            return Dispatch::Report(Outcome::Reject(RejectReason::Decode));
        }
    };
    metrics::inc_beacon_gossip(KIND, "decoded");
    let now_ms = unix_now_ms();
    let cheap = match &sidecar {
        DataColumnSidecar::Fulu(sidecar) => gossip::column::cheap_checks(
            &server.seen_columns,
            &server.store,
            sidecar,
            subnet_id,
            now_ms,
        ),
        DataColumnSidecar::Gloas(sidecar) => gossip::column::cheap_checks_gloas(
            &server.seen_block_columns,
            &server.store,
            sidecar,
            subnet_id,
            now_ms,
        ),
    };
    if let Err(outcome) = cheap {
        return Dispatch::Report(outcome);
    }
    Dispatch::Validate(Validated::Column(Box::new(sidecar)))
}

/// Decode a beacon aggregate and run its cheap gossip checks: a verdict
/// already, or the object for [`verdict::spawn_stateful_checks`] to take
/// further. Same shape as [`triage_block`]/[`triage_data_column`].
fn triage_aggregate(
    server: &P2PServer,
    wire: &BeaconWire,
    payload: &[u8],
    received_at: Instant,
) -> Dispatch {
    const KIND: &str = beacon_topics::BEACON_AGGREGATE_AND_PROOF;
    let aggregate = match beacon_decode::decode_aggregate_and_proof(&wire.config, payload) {
        Ok(aggregate) => aggregate,
        Err(err) => {
            metrics::inc_beacon_gossip(KIND, "decode_failed");
            debug!(kind = KIND, %err, bytes = payload.len(), "Beacon gossip decode failed");
            return Dispatch::Report(Outcome::Reject(RejectReason::Decode));
        }
    };
    metrics::inc_beacon_gossip(KIND, "decoded");
    metrics::observe_beacon_aggregate_decode(received_at.elapsed());

    let data = aggregate.data();
    let (target_epoch, target_root) = aggregate.target();
    // `debug` rather than `info`: a mainnet slot carries up to
    // `MAX_COMMITTEES_PER_SLOT * TARGET_AGGREGATORS_PER_COMMITTEE` of these,
    // and a line each at `info` buries every other line the node emits. What
    // an operator wants from this topic is the counters and the histograms,
    // not a per-message log.
    debug!(
        slot = data.slot,
        aggregator = aggregate.aggregator_index(),
        attesters = aggregate.attester_count(),
        target_epoch,
        target_root = %ShortRoot(&target_root.0),
        bytes = payload.len(),
        "Beacon aggregate attestation decoded"
    );

    if let Err(outcome) = gossip::aggregate::cheap_checks(
        &server.seen_aggregates,
        &server.store,
        &aggregate,
        unix_now_ms(),
    ) {
        return Dispatch::Report(outcome);
    }
    Dispatch::Validate(Validated::Aggregate {
        aggregate: Box::new(aggregate),
        attesting_indices: Vec::new(),
    })
}

/// Decode an unaggregated attestation off one of this node's backbone
/// subnets and run its cheap gossip checks. Same shape as [`triage_block`].
///
/// A phase0-shaped payload (see [`beacon_decode::Attestation`]) answers
/// `Ignore(NoConsumer)` without reaching [`gossip::attestation`] at all: that
/// module's rules are electra's `SingleAttestation` only, matching what every
/// subnet actually carries from electra onward, and a pre-electra shape has
/// never had a consumer on this node either way (see the module's earlier
/// transitional history).
///
/// Forwarding stays absent even once this topic gets a real verdict. See
/// [`crate::beacon::verdict::Validated::forward`] for why: `p2p-interface.md`
/// asks every beacon node to hold `SUBNETS_PER_NODE` of these subscriptions so
/// the subnets have a stable mesh for validators to publish into, and being in
/// that mesh, verifying and relaying what arrives, is the whole of what this
/// node owes it. A lighthouse node with no validators does exactly this too:
/// it verifies and re-propagates a subnet attestation but skips
/// `apply_attestation_to_fork_choice` unless a local aggregator duty or
/// `--import-all-attestations` says otherwise. Two subnets out of sixty-four
/// would in any case be a small slice of the votes the aggregate topic
/// already carries in full.
fn triage_attestation(
    server: &P2PServer,
    fork: ForkName,
    payload: &[u8],
    subnet_id: u64,
) -> Dispatch {
    const KIND: &str = beacon_topics::BEACON_ATTESTATION_KIND;
    let attestation = match beacon_decode::decode_attestation(fork, payload) {
        Ok(attestation) => attestation,
        Err(err) => {
            metrics::inc_beacon_gossip(KIND, "decode_failed");
            debug!(kind = KIND, %err, bytes = payload.len(), "Beacon gossip decode failed");
            return Dispatch::Report(Outcome::Reject(RejectReason::Decode));
        }
    };
    metrics::inc_beacon_gossip(KIND, "decoded");
    let single = match attestation {
        beacon_decode::Attestation::Electra(single) => single,
        beacon_decode::Attestation::Phase0(_) => {
            return Dispatch::Report(Outcome::Ignore(IgnoreReason::NoConsumer));
        }
    };
    let data = single.data;
    trace!(
        slot = data.slot,
        subnet_id,
        target_epoch = data.target.epoch,
        target_root = %ShortRoot(&data.target.root.0),
        bytes = payload.len(),
        "Beacon attestation decoded"
    );

    if let Err(outcome) = gossip::attestation::cheap_checks(
        &server.seen_attestations,
        &server.store,
        &single,
        unix_now_ms(),
    ) {
        return Dispatch::Report(outcome);
    }
    Dispatch::Validate(Validated::Attestation {
        attestation: Box::new(single),
        subnet_id,
    })
}

/// Decode a gloas execution payload envelope and run its cheap gossip checks.
/// Same shape as [`triage_block`].
fn triage_envelope(server: &P2PServer, payload: &[u8]) -> Dispatch {
    const KIND: &str = beacon_topics::EXECUTION_PAYLOAD;
    let envelope = match beacon_decode::decode_execution_payload_envelope(payload) {
        Ok(envelope) => envelope,
        Err(err) => {
            metrics::inc_beacon_gossip(KIND, "decode_failed");
            debug!(kind = KIND, %err, bytes = payload.len(), "Beacon gossip decode failed");
            return Dispatch::Report(Outcome::Reject(RejectReason::Decode));
        }
    };
    metrics::inc_beacon_gossip(KIND, "decoded");
    debug!(
        slot = envelope.message.payload.slot_number,
        builder_index = envelope.message.builder_index,
        block_root = %ShortRoot(&envelope.message.beacon_block_root.0),
        bytes = payload.len(),
        "Beacon execution payload envelope decoded"
    );
    if let Err(outcome) =
        gossip::envelope::cheap_checks(&server.seen_envelopes, &server.store, &envelope)
    {
        return Dispatch::Report(outcome);
    }
    Dispatch::Validate(Validated::Envelope(Box::new(envelope)))
}

/// Decode a gloas payload attestation message and run its cheap gossip
/// checks. Same shape as [`triage_block`].
fn triage_payload_attestation(server: &P2PServer, payload: &[u8]) -> Dispatch {
    const KIND: &str = beacon_topics::PAYLOAD_ATTESTATION_MESSAGE;
    let message = match beacon_decode::decode_payload_attestation_message(payload) {
        Ok(message) => message,
        Err(err) => {
            metrics::inc_beacon_gossip(KIND, "decode_failed");
            debug!(kind = KIND, %err, bytes = payload.len(), "Beacon gossip decode failed");
            return Dispatch::Report(Outcome::Reject(RejectReason::Decode));
        }
    };
    metrics::inc_beacon_gossip(KIND, "decoded");
    // `trace` rather than `debug`: the committee votes in one burst per slot.
    trace!(
        slot = message.data.slot,
        validator = message.validator_index,
        block_root = %ShortRoot(&message.data.beacon_block_root.0),
        "Beacon payload attestation message decoded"
    );
    if let Err(outcome) = gossip::payload_attestation::cheap_checks(
        &server.seen_payload_attestations,
        &server.store,
        &message,
        unix_now_ms(),
    ) {
        return Dispatch::Report(outcome);
    }
    Dispatch::Validate(Validated::PayloadAttestation(message))
}

/// Decode a heze inclusion list and run its cheap gossip checks. Same shape
/// as [`triage_payload_attestation`]. The receipt time travels with the list:
/// it decides the list's timeliness once the stateful checks accept it.
fn triage_inclusion_list(server: &P2PServer, payload: &[u8]) -> Dispatch {
    const KIND: &str = beacon_topics::INCLUSION_LIST;
    let signed = match beacon_decode::decode_inclusion_list(payload) {
        Ok(signed) => signed,
        Err(err) => {
            metrics::inc_beacon_gossip(KIND, "decode_failed");
            debug!(kind = KIND, %err, bytes = payload.len(), "Beacon gossip decode failed");
            return Dispatch::Report(Outcome::Reject(RejectReason::Decode));
        }
    };
    metrics::inc_beacon_gossip(KIND, "decoded");
    let received_ms = unix_now_ms();
    debug!(
        slot = signed.message.slot,
        validator = signed.message.validator_index,
        dependent_root = %ShortRoot(&signed.message.dependent_root.0),
        transactions = signed.message.transactions.len(),
        "Beacon inclusion list decoded"
    );
    if let Err(outcome) = gossip::inclusion_list::cheap_checks(
        &server.seen_inclusion_lists,
        &server.store,
        &signed,
        received_ms,
    ) {
        return Dispatch::Report(outcome);
    }
    Dispatch::Validate(Validated::InclusionList {
        signed: Box::new(signed),
        received_ms,
    })
}

/// Decode one of the four operation topics (`voluntary_exit`,
/// `proposer_slashing`, `attester_slashing`, `bls_to_execution_change`) and run
/// its cheap gossip checks: a verdict already, or the operation for
/// [`verdict::spawn_stateful_checks`] to take further.
fn triage_operation(server: &P2PServer, wire: &BeaconWire, kind: &str, payload: &[u8]) -> Dispatch {
    let operation = match beacon_decode::decode_gossip(&wire.config, kind, payload) {
        Ok(BeaconGossip::VoluntaryExit(exit)) => BeaconOperation::VoluntaryExit(exit),
        Ok(BeaconGossip::ProposerSlashing(slashing)) => {
            BeaconOperation::ProposerSlashing(*slashing)
        }
        Ok(BeaconGossip::AttesterSlashing(slashing)) => match *slashing {
            beacon_decode::AttesterSlashing::Electra(slashing) => {
                BeaconOperation::AttesterSlashing(slashing)
            }
            // The pool and the block builder only hold electra's shape:
            // electra is the earliest fork this node produces blocks for, and
            // it produces none for gloas.
            beacon_decode::AttesterSlashing::Phase0(_)
            | beacon_decode::AttesterSlashing::Gloas(_) => {
                return Dispatch::Report(Outcome::Ignore(IgnoreReason::NoConsumer));
            }
        },
        Ok(BeaconGossip::BlsToExecutionChange(change)) => {
            BeaconOperation::BlsToExecutionChange(change)
        }
        Ok(other) => {
            // `handle_beacon_gossip` routes only the four operation kinds
            // here, and `decode_gossip` answers by topic, so this is a bug.
            error!(
                kind,
                decoded = other.topic_kind(),
                "Operation topic decoded as another kind"
            );
            return Dispatch::Report(Outcome::Reject(RejectReason::Decode));
        }
        Err(err) => {
            metrics::inc_beacon_gossip(kind, "decode_failed");
            debug!(kind, %err, bytes = payload.len(), "Beacon gossip decode failed");
            return Dispatch::Report(Outcome::Reject(RejectReason::Decode));
        }
    };
    metrics::inc_beacon_gossip(kind, "decoded");
    // `debug` like the aggregate topic: operations are rare, but a per-message
    // line adds nothing the counters do not already say.
    debug!(kind, bytes = payload.len(), "Beacon operation decoded");

    if let Err(outcome) = gossip::operations::cheap_checks(
        &server.seen_operations,
        &server.store,
        &operation,
        unix_now_ms(),
    ) {
        return Dispatch::Report(outcome);
    }
    Dispatch::Validate(Validated::Operation(Box::new(operation)))
}

/// Decode a `sync_committee_{subnet_id}` message and run its cheap gossip
/// checks. Same shape as [`triage_block`]. The fork does not matter: the
/// container is the same everywhere it exists, and the stateful half picks
/// the signing domain from the message's own slot.
fn triage_sync_committee_message(server: &P2PServer, payload: &[u8], subnet_id: u64) -> Dispatch {
    const KIND: &str = beacon_topics::SYNC_COMMITTEE_KIND;
    let message = match beacon_decode::decode_sync_committee_message(payload) {
        Ok(message) => message,
        Err(err) => {
            metrics::inc_beacon_gossip(KIND, "decode_failed");
            debug!(kind = KIND, %err, bytes = payload.len(), "Beacon gossip decode failed");
            return Dispatch::Report(Outcome::Reject(RejectReason::Decode));
        }
    };
    metrics::inc_beacon_gossip(KIND, "decoded");
    // `trace` rather than `debug`: a subcommittee votes in one burst per slot.
    trace!(
        slot = message.slot,
        subnet_id,
        validator = message.validator_index,
        block_root = %ShortRoot(&message.beacon_block_root.0),
        "Beacon sync committee message decoded"
    );
    if let Err(outcome) = gossip::sync_committee::message_cheap_checks(
        &server.seen_sync_messages,
        &server.store,
        &message,
        subnet_id,
        unix_now_ms(),
    ) {
        return Dispatch::Report(outcome);
    }
    Dispatch::Validate(Validated::SyncCommitteeMessage {
        message,
        subnet_id,
        seats: Vec::new(),
    })
}

/// Decode a `sync_committee_contribution_and_proof` and run its cheap gossip
/// checks. Same shape as [`triage_block`].
fn triage_sync_contribution(server: &P2PServer, payload: &[u8]) -> Dispatch {
    const KIND: &str = beacon_topics::SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF;
    let signed = match beacon_decode::decode_sync_committee_contribution(payload) {
        Ok(signed) => signed,
        Err(err) => {
            metrics::inc_beacon_gossip(KIND, "decode_failed");
            debug!(kind = KIND, %err, bytes = payload.len(), "Beacon gossip decode failed");
            return Dispatch::Report(Outcome::Reject(RejectReason::Decode));
        }
    };
    metrics::inc_beacon_gossip(KIND, "decoded");
    let contribution = &signed.message.contribution;
    debug!(
        slot = contribution.slot,
        subcommittee_index = contribution.subcommittee_index,
        aggregator = signed.message.aggregator_index,
        block_root = %ShortRoot(&contribution.beacon_block_root.0),
        bytes = payload.len(),
        "Beacon sync committee contribution decoded"
    );
    if let Err(outcome) = gossip::sync_committee::contribution_cheap_checks(
        &server.seen_sync_contributions,
        &server.store,
        &signed,
        unix_now_ms(),
    ) {
        return Dispatch::Report(outcome);
    }
    Dispatch::Validate(Validated::SyncContribution(Box::new(signed)))
}

/// Decode one of the remaining beacon topics with nothing particular to
/// report, and count it. Ignored rather than validated: none of them has a
/// consumer, so this always answers `Dispatch::Report`.
fn triage_other(wire: &BeaconWire, kind: &str, payload: &[u8]) -> Dispatch {
    let outcome = match beacon_decode::decode_gossip(&wire.config, kind, payload) {
        Ok(decoded) => {
            metrics::inc_beacon_gossip(kind, "decoded");
            debug!(
                kind = decoded.topic_kind(),
                bytes = payload.len(),
                "Beacon gossip decoded"
            );
            Outcome::Ignore(IgnoreReason::NoConsumer)
        }
        // See `triage_aggregate`'s matching arm for why this scores as
        // `Ignore` rather than `Reject`.
        Err(beacon_decode::DecodeError::UnsupportedFork) => {
            metrics::inc_beacon_gossip(kind, "unsupported_fork");
            Outcome::Ignore(IgnoreReason::UnsupportedFork)
        }
        Err(err) => {
            metrics::inc_beacon_gossip(kind, "decode_failed");
            debug!(kind, %err, bytes = payload.len(), "Beacon gossip decode failed");
            Outcome::Reject(RejectReason::Decode)
        }
    };
    Dispatch::Report(outcome)
}

pub async fn publish_attestation(server: &mut P2PServer, attestation: SignedAttestation) {
    let slot = attestation.data.slot;
    let validator = attestation.validator_id;
    let Some(lean) = server.wire.lean() else {
        warn!("Publishing is suppressed on the beacon wire; dropping attestation");
        return;
    };
    let subnet_id = validator % lean.attestation_committee_count;

    // Encode to SSZ
    let ssz_bytes = attestation.to_ssz();

    // Compress with raw snappy
    let compressed = compress_message(&ssz_bytes);

    metrics::observe_gossip_attestation_size(ssz_bytes.len(), compressed.len());

    // Look up subscribed topic or construct on-the-fly for gossipsub fanout
    let topic = lean
        .attestation_topics
        .get(&subnet_id)
        .cloned()
        .unwrap_or_else(|| attestation_subnet_topic(subnet_id));

    server.swarm_handle.publish(topic, compressed);
    trace!(
        %slot,
        validator,
        subnet_id,
        target_slot = attestation.data.target.slot,
        target_root = %ShortRoot(&attestation.data.target.root.0),
        source_slot = attestation.data.source.slot,
        source_root = %ShortRoot(&attestation.data.source.root.0),
        "Published attestation to gossipsub"
    );
}

pub async fn publish_block(server: &mut P2PServer, signed_block: SignedBlock) {
    let slot = signed_block.message.slot;
    let proposer = signed_block.message.proposer_index;
    let block_root = signed_block.message.hash_tree_root();
    let parent_root = signed_block.message.parent_root;
    let attestation_count = signed_block.message.body.attestations.len();

    // Encode to SSZ
    let ssz_bytes = signed_block.to_ssz();

    // Compress with raw snappy
    let compressed = compress_message(&ssz_bytes);

    metrics::observe_gossip_block_size(ssz_bytes.len(), compressed.len());

    // Publish to gossipsub
    let Some(topic) = server.wire.lean().map(|lean| lean.block_topic.clone()) else {
        warn!("Publishing is suppressed on the beacon wire; dropping block");
        return;
    };
    server.swarm_handle.publish(topic, compressed);
    info!(
        %slot,
        proposer,
        block_root = %ShortRoot(&block_root.0),
        parent_root = %ShortRoot(&parent_root.0),
        attestation_count,
        "Published block to gossipsub"
    );
}

pub async fn publish_aggregated_attestation(
    server: &mut P2PServer,
    attestation: SignedAggregatedAttestation,
) {
    let slot = attestation.data.slot;

    // Encode to SSZ
    let ssz_bytes = attestation.to_ssz();

    // Compress with raw snappy
    let compressed = compress_message(&ssz_bytes);

    metrics::observe_gossip_aggregation_size(ssz_bytes.len(), compressed.len());

    // Publish to the aggregation topic
    let Some(topic) = server
        .wire
        .lean()
        .map(|lean| lean.aggregation_topic.clone())
    else {
        warn!("Publishing is suppressed on the beacon wire; dropping aggregate");
        return;
    };
    server.swarm_handle.publish(topic, compressed);
    info!(
        %slot,
        target_slot = attestation.data.target.slot,
        target_root = %ShortRoot(&attestation.data.target.root.0),
        source_slot = attestation.data.source.slot,
        source_root = %ShortRoot(&attestation.data.source.root.0),
        "Published aggregated attestation to gossipsub"
    );
}

/// Gossip one of a validator client's attestations, handed over by the Beacon
/// API, on its `beacon_attestation_{subnet_id}` topic.
///
/// The API has already validated the attestation and computed `subnet_id`; this
/// only refuses what would be a programming error on its side (a lean node, or
/// a subnet id past the last subnet) rather than publish to a topic no peer
/// listens on.
pub async fn publish_beacon_attestation(
    server: &mut P2PServer,
    subnet_id: u64,
    attestation: SingleAttestation,
) {
    let slot = attestation.data.slot;
    let validator = attestation.attester_index;
    let Some(beacon) = server.wire.beacon() else {
        error!(%slot, validator, "A beacon attestation reached a lean node; dropping it");
        return;
    };
    if subnet_id >= ATTESTATION_SUBNET_COUNT {
        error!(%slot, validator, subnet_id, "Attestation subnet out of range; dropping it");
        return;
    }
    let Some(digest) = beacon.publish_digest(slot) else {
        warn!(%slot, validator, "No held fork digest covers this attestation's slot; not publishing");
        return;
    };
    let topic = IdentTopic::new(beacon_topics::attestation_topic_name(digest, subnet_id));
    let compressed = compress_message(&attestation.to_ssz());
    server.swarm_handle.publish(topic, compressed);
    debug!(
        %slot,
        validator,
        subnet_id,
        target_epoch = attestation.data.target.epoch,
        target_root = %ShortRoot(&attestation.data.target.root.0),
        "Published attestation to gossipsub"
    );
}

/// Gossip one of a validator client's signed aggregates, handed over by the
/// Beacon API after validation, on `beacon_aggregate_and_proof`, and pass it
/// to the chain actor as an accepted gossip aggregate would be. This node is
/// subscribed to that topic, so it reaches the mesh rather than relying on
/// fanout; and gossipsub never delivers a node its own messages, so the
/// hand-off is the only way this node's fork choice and `attestation` event
/// stream see its own validator client's aggregates.
pub async fn publish_beacon_aggregate(
    server: &mut P2PServer,
    aggregate: ethlambda_types::beacon::containers::SignedAggregateAndProof,
    attesting_indices: Vec<ValidatorIndex>,
) {
    let slot = aggregate.slot();
    let aggregator = aggregate.aggregator_index();
    let Some(beacon) = server.wire.beacon() else {
        error!(%slot, aggregator, "A beacon aggregate reached a lean node; dropping it");
        return;
    };
    let Some(digest) = beacon.publish_digest(slot) else {
        warn!(%slot, aggregator, "No held fork digest covers this aggregate's slot; not publishing");
        return;
    };
    let topic = IdentTopic::new(beacon_topics::topic_name(
        digest,
        beacon_topics::BEACON_AGGREGATE_AND_PROOF,
    ));
    // Each fork's container encodes as itself on the wire; the enum is only
    // this node's way of holding either.
    let ssz = match &aggregate {
        ethlambda_types::beacon::containers::SignedAggregateAndProof::Phase0(signed) => {
            signed.to_ssz()
        }
        ethlambda_types::beacon::containers::SignedAggregateAndProof::Electra(signed) => {
            signed.to_ssz()
        }
        ethlambda_types::beacon::containers::SignedAggregateAndProof::Gloas(signed) => {
            signed.to_ssz()
        }
    };
    server.swarm_handle.publish(topic, compress_message(&ssz));
    debug!(%slot, aggregator, "Published aggregate to gossipsub");
    if let Some(ref blockchain) = server.blockchain {
        let _ = blockchain
            .new_beacon_aggregate(
                Box::new(aggregate),
                attesting_indices,
                AggregateArrival::now(),
            )
            .inspect_err(|err| error!(%err, "Failed to hand the published aggregate to the chain"));
    }
}

/// Gossip a block a validator client signed, handed over by the Beacon API,
/// on `beacon_block`, then each of its data column sidecars on its column
/// subnet (the proposer publishes all of them), and pass the block to the
/// chain actor as a gossiped block would be: gossipsub never delivers a node
/// its own messages, so this is the only way this node imports its own
/// proposal.
///
/// The block goes out before the columns so peers can start its state
/// transition while the columns arrive. The chain actor gets this node's
/// custody columns first and the block second: its mailbox is FIFO, so the
/// block finds its columns already stored and never waits in
/// `blocks_awaiting_columns`.
pub async fn publish_beacon_block(
    server: &mut P2PServer,
    block: SignedBeaconBlock,
    sidecars: Vec<DataColumnSidecar>,
) {
    let slot = block.slot();
    let Some(beacon) = server.wire.beacon() else {
        error!(slot, "A beacon block reached a lean node; dropping it");
        return;
    };
    let Some(digest) = beacon.publish_digest(slot) else {
        warn!(
            slot,
            "No held fork digest covers this block's slot; not publishing"
        );
        return;
    };
    let topic = IdentTopic::new(beacon_topics::topic_name(
        digest,
        beacon_topics::BEACON_BLOCK,
    ));
    server
        .swarm_handle
        .publish(topic, compress_message(&block.to_ssz()));
    info!(
        slot,
        proposer = block.proposer_index(),
        block_root = %ShortRoot(&block.message_hash_tree_root().0),
        "Published block to gossipsub"
    );
    // Under the block's own digest, like the block: the columns are for its
    // slot, whichever digest the node has switched to so far.
    for sidecar in &sidecars {
        let subnet = das::compute_subnet_for_data_column_sidecar(sidecar.index());
        let topic = IdentTopic::new(beacon_topics::data_column_topic_name(digest, subnet));
        server
            .swarm_handle
            .publish(topic, compress_message(&sidecar.to_ssz()));
    }
    if !sidecars.is_empty() {
        info!(
            slot,
            columns = sidecars.len(),
            "Published data columns to gossipsub"
        );
    }
    if let Some(ref blockchain) = server.blockchain {
        let custody: Vec<DataColumnSidecar> = sidecars
            .into_iter()
            .filter(|sidecar| beacon.custody_columns.contains(&sidecar.index()))
            .collect();
        if !custody.is_empty() {
            let _ = blockchain
                .new_data_column_sidecars(custody)
                .inspect_err(|err| error!(%err, "Failed to hand the custody columns to the chain"));
        }
        let _ = blockchain
            .new_block(
                block,
                BlockSource::Gossip,
                BlockArrival::now(),
                BlockAnnouncement::Announce,
            )
            .inspect_err(|err| error!(%err, "Failed to hand the published block to the chain"));
    }
}

/// Gossip a gloas execution payload envelope a validator client signed,
/// handed over by the Beacon API, on `execution_payload`, its data column
/// sidecars on their subnets, and pass all of them to the chain actor.
///
/// Like [`publish_beacon_block`], the only way this node takes its own
/// envelope in, since gossipsub never delivers a node its own messages. The
/// envelope goes to the actor as it is. It is safe to hand over before the
/// block it reveals has been imported, which is the usual case (the validator
/// client publishes the envelope as soon as the block is on its way): the
/// actor holds an envelope for a block it has not imported (`awaiting_block`),
/// or for one it has stored but not imported (`awaiting_import`), and applies
/// it when the block's post-state exists.
///
/// The sidecars take the route every sidecar gossip did not accept takes, the
/// chain checks (`column_checks::check_and_forward`), which parks one whose
/// block is not imported yet and hands it back once it is. Their subnet
/// topics are published to whether or not this node custodies the subnet:
/// gossipsub sends to a topic it is not subscribed to through its fanout
/// peers.
pub async fn publish_execution_payload_envelope(
    server: &mut P2PServer,
    envelope: ethlambda_types::beacon::containers::gloas::SignedExecutionPayloadEnvelope,
    sidecars: Vec<DataColumnSidecar>,
) {
    let slot = envelope.message.payload.slot_number;
    let block_root = envelope.message.beacon_block_root;
    // Gossip never echoes a node's own message, so its own envelope is a
    // known payload for bid validation only because it is recorded here.
    server
        .builder_market
        .record_execution_payload(&envelope.message);
    let Some(beacon) = server.wire.beacon() else {
        error!(
            slot,
            "An execution payload envelope reached a lean node; dropping it"
        );
        return;
    };
    let Some(digest) = beacon.publish_digest(slot) else {
        warn!(
            slot,
            "No held fork digest covers this envelope's slot; not publishing"
        );
        return;
    };
    let topic = IdentTopic::new(beacon_topics::topic_name(
        digest,
        beacon_topics::EXECUTION_PAYLOAD,
    ));
    server
        .swarm_handle
        .publish(topic, compress_message(&envelope.to_ssz()));
    info!(
        slot,
        builder_index = envelope.message.builder_index,
        block_root = %ShortRoot(&block_root.0),
        "Published execution payload envelope to gossipsub"
    );

    let mut published_columns = 0usize;
    for sidecar in &sidecars {
        let DataColumnSidecar::Gloas(gloas_sidecar) = sidecar else {
            warn!(
                slot,
                "Skipping a non-gloas sidecar published with a gloas envelope"
            );
            continue;
        };
        let subnet_id = gloas_sidecar.index
            % ethlambda_types::beacon::constants::DATA_COLUMN_SIDECAR_SUBNET_COUNT;
        let topic = IdentTopic::new(beacon_topics::data_column_topic_name(digest, subnet_id));
        server
            .swarm_handle
            .publish(topic, compress_message(&gloas_sidecar.to_ssz()));
        published_columns += 1;
    }
    if published_columns > 0 {
        info!(
            slot,
            block_root = %ShortRoot(&block_root.0),
            columns = published_columns,
            "Published data column sidecars to gossipsub"
        );
    }

    if let Some(blockchain) = server.blockchain.clone() {
        let _ = blockchain
            .new_execution_payload_envelope(Box::new(envelope), BlockArrival::now())
            .inspect_err(|err| error!(%err, "Failed to hand the published envelope to the chain"));
    }
    crate::beacon::column_checks::check_and_forward(server, sidecars);
}

/// Gossip a payload attestation message a validator client signed, handed
/// over by the Beacon API, on `payload_attestation_message`, and pass it to
/// the chain actor.
///
/// The API validated it with the checks gossip would apply, so it goes out
/// as is. Gossipsub never delivers a node its own message, so the chain actor
/// is handed it here to count the vote in its fork choice. The seen cache is
/// marked as well: a peer that echoes the vote back would otherwise pass
/// triage and be validated and forwarded a second time.
/// Gossip a heze inclusion list on `inclusion_list` under its slot's digest.
/// The caller validated and stored it; counting it as seen here keeps a copy
/// relayed back by a peer from being judged a second time as a new list.
pub fn publish_inclusion_list(
    server: &mut P2PServer,
    signed: ethlambda_types::beacon::containers::heze::SignedInclusionList,
) {
    let slot = signed.message.slot;
    let validator = signed.message.validator_index;
    let Some(beacon) = server.wire.beacon() else {
        error!(slot, "An inclusion list reached a lean node; dropping it");
        return;
    };
    let Some(digest) = beacon.publish_digest(slot) else {
        warn!(
            slot,
            "No held fork digest covers this inclusion list's slot; not publishing"
        );
        return;
    };
    let topic = IdentTopic::new(beacon_topics::topic_name(
        digest,
        beacon_topics::INCLUSION_LIST,
    ));
    server
        .swarm_handle
        .publish(topic, compress_message(&signed.to_ssz()));
    server.seen_inclusion_lists.record(&signed);
    info!(
        slot,
        validator,
        transactions = signed.message.transactions.len(),
        "Published inclusion list to gossipsub"
    );
}

pub async fn publish_payload_attestation_message(
    server: &mut P2PServer,
    message: ethlambda_types::beacon::containers::gloas::PayloadAttestationMessage,
) {
    let slot = message.data.slot;
    let validator = message.validator_index;
    let Some(beacon) = server.wire.beacon() else {
        error!(
            slot,
            "A payload attestation reached a lean node; dropping it"
        );
        return;
    };
    let Some(digest) = beacon.publish_digest(slot) else {
        warn!(
            slot,
            "No held fork digest covers this payload attestation's slot; not publishing"
        );
        return;
    };
    let topic = IdentTopic::new(beacon_topics::topic_name(
        digest,
        beacon_topics::PAYLOAD_ATTESTATION_MESSAGE,
    ));
    server
        .swarm_handle
        .publish(topic, compress_message(&message.to_ssz()));
    server.seen_payload_attestations.record(slot, validator);
    info!(
        slot,
        validator,
        block_root = %ShortRoot(&message.data.beacon_block_root.0),
        payload_present = message.data.payload_present,
        "Published payload attestation to gossipsub"
    );
    if let Some(ref blockchain) = server.blockchain {
        let _ = blockchain
            .new_payload_attestation_message(message, BlockArrival::now())
            .inspect_err(
                |err| error!(%err, "Failed to hand the published payload attestation to the chain"),
            );
    }
}

/// The beacon wall-clock slot, from the wire's genesis and slot duration.
pub(crate) fn beacon_wall_slot(wire: &BeaconWire) -> u64 {
    wire.wall_slot()
}

/// Join the attestation subnets a validator client's aggregators need, per
/// phase0's `validator.md` ("Attestation subnet subscription": an aggregator
/// joins its committee's subnet for the slot), and remember until when.
///
/// A backbone subnet is already joined for good and is left alone. A subnet
/// named twice keeps the later slot.
pub fn join_aggregator_subnets(server: &mut P2PServer, subnets: Vec<(u64, u64)>) {
    let Some(wire) = server.wire.beacon() else {
        return;
    };
    let mut joined = Vec::new();
    for (subnet_id, slot) in subnets {
        if subnet_id >= ATTESTATION_SUBNET_COUNT
            || wire.topics.attestation_topics.contains_key(&subnet_id)
        {
            continue;
        }
        let until = server
            .aggregator_subnets
            .entry(subnet_id)
            .or_insert_with(|| {
                joined.push(subnet_id);
                slot
            });
        *until = (*until).max(slot);
    }
    // Under every digest the node holds: while a boundary's window is open,
    // attestations are published on either side of it.
    for &subnet_id in &joined {
        for held in wire.held_topics() {
            let topic = beacon_topics::attestation_topic_name(held.fork_digest, subnet_id);
            server.swarm_handle.subscribe(IdentTopic::new(topic));
        }
    }
    if !joined.is_empty() {
        info!(?joined, "Joined attestation subnets for aggregation");
    }
}

/// Gossip one operation on its topic, handed over by the Beacon API after
/// validation. This node is subscribed to all four operation topics, so it
/// reaches the mesh rather than relying on fanout.
pub async fn publish_beacon_operation(server: &mut P2PServer, operation: BeaconOperation) {
    let kind = operation_kind(&operation);
    let Some(beacon) = server.wire.beacon() else {
        error!(kind, "A beacon operation reached a lean node; dropping it");
        return;
    };
    // An operation names no slot, so it goes out under the digest of the
    // wall-clock slot: the one peers on the current fork listen on, even before
    // this node's own switch at a boundary has run.
    let digest = beacon
        .publish_digest(beacon_wall_slot(beacon))
        .unwrap_or(beacon.fork_digest);
    let topic = IdentTopic::new(beacon_topics::topic_name(digest, kind));
    server
        .swarm_handle
        .publish(topic, compress_message(&operation.to_ssz()));
    debug!(kind, "Published operation to gossipsub");
}

/// The topic kind an operation travels on.
pub(crate) fn operation_kind(operation: &BeaconOperation) -> &'static str {
    match operation {
        BeaconOperation::ProposerSlashing(_) => beacon_topics::PROPOSER_SLASHING,
        BeaconOperation::AttesterSlashing(_) => beacon_topics::ATTESTER_SLASHING,
        BeaconOperation::VoluntaryExit(_) => beacon_topics::VOLUNTARY_EXIT,
        BeaconOperation::BlsToExecutionChange(_) => beacon_topics::BLS_TO_EXECUTION_CHANGE,
    }
}

/// Drop pooled operations the head state has already made pointless.
///
/// Beacon wire only. Returns silently while there is no head or no state for
/// it, since the next sweep will find one.
pub fn prune_operation_pool(server: &P2PServer) {
    if server.wire.beacon().is_none() {
        return;
    }
    let Some((_slot, root)) = server.store.beacon_head() else {
        return;
    };
    let Ok(Some(state)) = server.store.get_state(&root) else {
        return;
    };
    server.store.operation_pool().prune(&state);
}

/// Drop attestation pool entries more than an epoch old.
///
/// Inserts prune as they go; this also runs on the aggregator-subnet sweep, so
/// a pool nothing is inserted into does not keep stale entries.
pub fn prune_attestation_pool(server: &P2PServer) {
    let Some(wire) = server.wire.beacon() else {
        return;
    };
    let now = beacon_wall_slot(wire);
    server.store.attestation_pool().prune_before(now);
}

/// Leave every aggregator subnet whose last slot has passed.
pub fn leave_expired_aggregator_subnets(server: &mut P2PServer) {
    let Some(wire) = server.wire.beacon() else {
        return;
    };
    let now = beacon_wall_slot(wire);
    let expired: Vec<u64> = server
        .aggregator_subnets
        .iter()
        .filter(|&(_, &until)| until < now)
        .map(|(&subnet_id, _)| subnet_id)
        .collect();
    for subnet_id in &expired {
        server.aggregator_subnets.remove(subnet_id);
        for held in wire.held_topics() {
            let topic = beacon_topics::attestation_topic_name(held.fork_digest, *subnet_id);
            server.swarm_handle.unsubscribe(IdentTopic::new(topic));
        }
    }
    if !expired.is_empty() {
        debug!(
            ?expired,
            "Left attestation subnets whose aggregation slot has passed"
        );
    }
}

#[cfg(test)]
mod tests {
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::containers::{AttestationData, electra, gloas, phase0, shared};
    use ethlambda_types::beacon::fork::ForkName;
    use ethlambda_types::beacon::preset;
    use ethlambda_types::beacon::primitives::Slot;

    use super::*;
    use crate::test_support::{RecordingChain, unconnected_beacon_server, valid_shaped_sidecar};

    /// An electra-shaped aggregate at `slot` with `data.index` set to
    /// `data_index`. Only what [`gossip::aggregate::cheap_checks`]'s very
    /// first condition reads is meaningful; nothing here is signature-valid
    /// or has a real committee.
    fn electra_aggregate(slot: Slot, data_index: u64) -> electra::SignedAggregateAndProof {
        electra::SignedAggregateAndProof {
            message: electra::AggregateAndProof {
                aggregator_index: 0,
                aggregate: electra::Attestation {
                    aggregation_bits: Default::default(),
                    data: AttestationData {
                        slot,
                        index: data_index,
                        ..Default::default()
                    },
                    signature: Default::default(),
                    committee_bits: Default::default(),
                },
                selection_proof: Default::default(),
            },
            signature: Default::default(),
        }
    }

    /// An electra-shaped `SingleAttestation` at `slot` with `data.index` set
    /// to `data_index`. Same reasoning as [`electra_aggregate`].
    fn electra_single_attestation(slot: Slot, data_index: u64) -> electra::SingleAttestation {
        electra::SingleAttestation {
            committee_index: 0,
            attester_index: 0,
            data: AttestationData {
                slot,
                index: data_index,
                ..Default::default()
            },
            signature: Default::default(),
        }
    }

    /// A phase0-shaped attestation at `slot`: a whole `Attestation` with one
    /// bit set, the pre-electra subnet shape.
    fn phase0_attestation(slot: Slot) -> phase0::Attestation {
        let mut aggregation_bits = phase0::AggregationBits::with_length(1).unwrap();
        aggregation_bits.set(0, true).unwrap();
        phase0::Attestation {
            aggregation_bits,
            data: AttestationData {
                slot,
                ..Default::default()
            },
            signature: Default::default(),
        }
    }

    /// A config whose schedule already has electra active at epoch 0, so a
    /// server built from it reports `wire.fork >= ForkName::Electra`
    /// (`unconnected_beacon_server` fixes `wire.fork` at
    /// `config.fork_at_epoch(0)`) and an electra-shaped aggregate at any slot
    /// decodes as such too (its own fork comes from its slot, under this same
    /// config).
    fn electra_at_epoch_zero() -> Config {
        Config::mainnet().with_fork_epoch(ForkName::Electra, 0)
    }

    #[tokio::test]
    async fn garbage_bytes_on_the_block_topic_are_rejected_as_undecodable() {
        let server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let wire = server
            .wire
            .beacon()
            .expect("a beacon server has a beacon wire");

        assert!(matches!(
            triage_block(&server, wire, &[0xff; 3]),
            Dispatch::Report(Outcome::Reject(RejectReason::Decode))
        ));
    }

    /// Phase0-shaped bytes at `slot`: not a valid block at any later fork, so
    /// what `triage_block` answers depends on the fork `slot` names.
    fn mismatched_block_bytes(slot: Slot) -> Vec<u8> {
        phase0::SignedBeaconBlock {
            message: phase0::BeaconBlock {
                slot,
                proposer_index: 0,
                parent_root: Default::default(),
                state_root: Default::default(),
                body: phase0::BeaconBlockBody::default(),
            },
            signature: Default::default(),
        }
        .to_ssz()
    }

    async fn triage_block_under(config: Config, payload: &[u8]) -> Dispatch {
        let server = unconnected_beacon_server(config, 0).await;
        let wire = server
            .wire
            .beacon()
            .expect("a beacon server has a beacon wire");
        triage_block(&server, wire, payload)
    }

    #[tokio::test]
    async fn an_undecodable_block_at_a_gloas_slot_is_rejected() {
        let mut config = Config::mainnet();
        config.gloas_fork_epoch = config.fulu_fork_epoch + 1;
        let slot = config.gloas_fork_epoch * preset::SLOTS_PER_EPOCH;

        assert!(matches!(
            triage_block_under(config, &mismatched_block_bytes(slot)).await,
            Dispatch::Report(Outcome::Reject(RejectReason::Decode))
        ));
    }

    #[tokio::test]
    async fn garbage_bytes_are_still_rejected_once_gloas_is_active() {
        let config = Config::mainnet().with_fork_epoch(ForkName::Gloas, 0);

        assert!(matches!(
            triage_block_under(config, &[0xff; 3]).await,
            Dispatch::Report(Outcome::Reject(RejectReason::Decode))
        ));
    }

    #[tokio::test]
    async fn an_undecodable_block_at_a_fulu_slot_is_still_rejected_after_the_fork() {
        let mut config = Config::mainnet();
        config.gloas_fork_epoch = config.fulu_fork_epoch + 1;
        let slot = config.fulu_fork_epoch * preset::SLOTS_PER_EPOCH;

        assert!(matches!(
            triage_block_under(config, &mismatched_block_bytes(slot)).await,
            Dispatch::Report(Outcome::Reject(RejectReason::Decode))
        ));
    }

    #[tokio::test]
    async fn garbage_bytes_on_a_data_column_subnet_are_rejected_as_undecodable() {
        let server = unconnected_beacon_server(Config::mainnet(), 0).await;

        assert!(matches!(
            triage_data_column(&server, ForkName::Fulu, &[0xff; 3], 0),
            Dispatch::Report(Outcome::Reject(RejectReason::Decode))
        ));
    }

    #[tokio::test]
    async fn a_far_future_sidecar_is_ignored() {
        let server = unconnected_beacon_server(Config::mainnet(), 0).await;
        // `saturating_mul` in `is_future_slot` turns this into `u64::MAX`
        // regardless of `slot_duration_ms`, putting the slot's start
        // unreachably far beyond any real clock.
        let sidecar = valid_shaped_sidecar(u64::MAX, 0);
        let payload = sidecar.to_ssz();

        assert!(matches!(
            triage_data_column(&server, ForkName::Fulu, &payload, 0),
            Dispatch::Report(Outcome::Ignore(IgnoreReason::FutureSlot))
        ));
    }

    #[tokio::test]
    async fn a_valid_shaped_sidecar_on_its_subnet_at_a_current_slot_goes_to_stateful_checks() {
        // Five real seconds before "now": comfortably not future under any
        // clock disparity, and past slot 0 so it clears the finalized check
        // against a store anchored there.
        let now_ms = unix_now_ms();
        let config = Config {
            genesis_time: now_ms / 1_000 - 5,
            slot_duration_ms: 1_000,
            ..Config::mainnet()
        };
        let server = unconnected_beacon_server(config, 0).await;
        let sidecar = valid_shaped_sidecar(4, 0);
        let payload = sidecar.to_ssz();

        assert!(matches!(
            triage_data_column(&server, ForkName::Fulu, &payload, 0),
            Dispatch::Validate(Validated::Column(_))
        ));
    }

    #[tokio::test]
    async fn a_gloas_sidecar_decodes_by_its_topics_fork_and_is_judged_by_gloas_rules() {
        let now_ms = unix_now_ms();
        let config = Config {
            genesis_time: now_ms / 1_000 - 5,
            slot_duration_ms: 1_000,
            ..Config::mainnet()
        };
        let server = unconnected_beacon_server(config, 0).await;
        let sidecar = ethlambda_types::beacon::containers::gloas::DataColumnSidecar {
            index: 0,
            slot: 4,
            ..Default::default()
        };
        let payload = sidecar.to_ssz();

        assert!(matches!(
            triage_data_column(&server, ForkName::Gloas, &payload, 0),
            Dispatch::Validate(Validated::Column(_))
        ));
        // Gloas's rule has no header to read a proposer from, but it does have
        // a subnet rule.
        assert!(matches!(
            triage_data_column(&server, ForkName::Gloas, &payload, 1),
            Dispatch::Report(Outcome::Reject(RejectReason::WrongSubnet))
        ));
        // The same bytes under fulu's topic are not a fulu sidecar.
        assert!(matches!(
            triage_data_column(&server, ForkName::Fulu, &payload, 0),
            Dispatch::Report(Outcome::Reject(RejectReason::Decode))
        ));
    }

    #[tokio::test]
    async fn the_same_sidecar_asked_for_on_the_wrong_subnet_is_rejected() {
        let now_ms = unix_now_ms();
        let config = Config {
            genesis_time: now_ms / 1_000 - 5,
            slot_duration_ms: 1_000,
            ..Config::mainnet()
        };
        let server = unconnected_beacon_server(config, 0).await;
        let sidecar = valid_shaped_sidecar(4, 0);
        let payload = sidecar.to_ssz();

        assert!(matches!(
            triage_data_column(&server, ForkName::Fulu, &payload, 1),
            Dispatch::Report(Outcome::Reject(RejectReason::WrongSubnet))
        ));
    }

    #[tokio::test]
    async fn garbage_bytes_on_the_aggregate_topic_are_rejected_as_undecodable() {
        let server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let wire = server
            .wire
            .beacon()
            .expect("a beacon server has a beacon wire");

        assert!(matches!(
            triage_aggregate(&server, wire, &[0xff; 3], Instant::now()),
            Dispatch::Report(Outcome::Reject(RejectReason::Decode))
        ));
    }

    /// A cheap-check rejection that needs no clock and no state: electra
    /// requires `data.index == 0`, and `gossip::aggregate::cheap_checks`
    /// checks that before it even looks at the seen cache.
    #[tokio::test]
    async fn an_electra_aggregate_with_a_nonzero_data_index_is_rejected() {
        let server = unconnected_beacon_server(electra_at_epoch_zero(), 0).await;
        let wire = server
            .wire
            .beacon()
            .expect("a beacon server has a beacon wire");
        let payload = electra_aggregate(4, 1).to_ssz();

        assert!(matches!(
            triage_aggregate(&server, wire, &payload, Instant::now()),
            Dispatch::Report(Outcome::Reject(RejectReason::NonZeroDataIndex))
        ));
    }

    /// Gloas repurposes `data.index` as the payload flag, so an honest `1`
    /// passes the index rule electra would reject it on; it is turned away
    /// later, here by the empty `committee_bits` of the test message.
    #[tokio::test]
    async fn a_gloas_aggregate_with_a_payload_flag_passes_the_index_rule() {
        let config = Config::mainnet().with_fork_epoch(ForkName::Gloas, 0);
        let server = unconnected_beacon_server(config, 0).await;
        let wire = server
            .wire
            .beacon()
            .expect("a beacon server has a beacon wire");
        let payload = electra_aggregate(4, 1).to_ssz();

        assert!(matches!(
            triage_aggregate(&server, wire, &payload, Instant::now()),
            Dispatch::Report(Outcome::Reject(RejectReason::CommitteeBits))
        ));
    }

    #[tokio::test]
    async fn a_gloas_aggregate_with_a_data_index_above_one_is_rejected() {
        let config = Config::mainnet().with_fork_epoch(ForkName::Gloas, 0);
        let server = unconnected_beacon_server(config, 0).await;
        let wire = server
            .wire
            .beacon()
            .expect("a beacon server has a beacon wire");
        let payload = electra_aggregate(4, 2).to_ssz();

        assert!(matches!(
            triage_aggregate(&server, wire, &payload, Instant::now()),
            Dispatch::Report(Outcome::Reject(RejectReason::DataIndexOutOfRange))
        ));
    }

    #[tokio::test]
    async fn garbage_bytes_on_an_attestation_subnet_are_rejected_as_undecodable() {
        let server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let wire = server
            .wire
            .beacon()
            .expect("a beacon server has a beacon wire");

        assert!(matches!(
            triage_attestation(&server, wire.fork, &[0xff; 3], 0),
            Dispatch::Report(Outcome::Reject(RejectReason::Decode))
        ));
    }

    /// The other pre-electra shape a subnet can carry: unlike the aggregate
    /// topic, whose two shapes both have a validator
    /// (`gossip::aggregate` handles both `SignedAggregateAndProof` variants),
    /// `gossip::attestation`'s rules only understand electra's
    /// `SingleAttestation`. A phase0-shaped payload therefore never reaches
    /// them at all.
    #[tokio::test]
    async fn a_phase0_shaped_attestation_has_no_consumer() {
        let server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let wire = server
            .wire
            .beacon()
            .expect("a beacon server has a beacon wire");
        let payload = phase0_attestation(4).to_ssz();

        assert!(matches!(
            triage_attestation(&server, wire.fork, &payload, 0),
            Dispatch::Report(Outcome::Ignore(IgnoreReason::NoConsumer))
        ));
    }

    /// The same cheap, stateless rejection as the aggregate topic's, on its
    /// `SingleAttestation` sibling.
    #[tokio::test]
    async fn an_electra_attestation_with_a_nonzero_data_index_is_rejected() {
        let server = unconnected_beacon_server(electra_at_epoch_zero(), 0).await;
        let wire = server
            .wire
            .beacon()
            .expect("a beacon server has a beacon wire");
        let payload = electra_single_attestation(4, 1).to_ssz();

        assert!(matches!(
            triage_attestation(&server, wire.fork, &payload, 0),
            Dispatch::Report(Outcome::Reject(RejectReason::NonZeroDataIndex))
        ));
    }

    /// A gloas `SingleAttestation` has electra's bytes, but its `data.index`
    /// is the payload flag: an honest `1` must not be rejected as a nonzero
    /// index, while a value past the flag's range is.
    #[tokio::test]
    async fn a_gloas_attestation_is_judged_on_the_payload_flag_range() {
        let config = Config::mainnet().with_fork_epoch(ForkName::Gloas, 0);
        let server = unconnected_beacon_server(config, 0).await;
        let wire = server
            .wire
            .beacon()
            .expect("a beacon server has a beacon wire");

        let flagged = electra_single_attestation(4, 1).to_ssz();
        // Past the index rule, and turned away by the clock instead: slot 4 is
        // long outside the epoch window of a mainnet genesis.
        assert!(matches!(
            triage_attestation(&server, wire.fork, &flagged, 0),
            Dispatch::Report(Outcome::Ignore(IgnoreReason::OutsideEpochWindow))
        ));
        let out_of_range = electra_single_attestation(4, 2).to_ssz();
        assert!(matches!(
            triage_attestation(&server, wire.fork, &out_of_range, 0),
            Dispatch::Report(Outcome::Reject(RejectReason::DataIndexOutOfRange))
        ));
    }

    #[tokio::test]
    async fn garbage_bytes_on_a_consumerless_topic_are_rejected_as_undecodable() {
        let server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let wire = server
            .wire
            .beacon()
            .expect("a beacon server has a beacon wire");

        assert!(matches!(
            triage_other(
                wire,
                beacon_topics::SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF,
                &[0xff; 3]
            ),
            Dispatch::Report(Outcome::Reject(RejectReason::Decode))
        ));
    }

    #[tokio::test]
    async fn garbage_bytes_on_the_voluntary_exit_topic_are_rejected_as_undecodable() {
        let server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let wire = server
            .wire
            .beacon()
            .expect("a beacon server has a beacon wire");

        assert!(matches!(
            triage_operation(&server, wire, beacon_topics::VOLUNTARY_EXIT, &[0xff; 3]),
            Dispatch::Report(Outcome::Reject(RejectReason::Decode))
        ));
    }

    #[tokio::test]
    async fn a_decodable_voluntary_exit_goes_on_to_the_stateful_checks() {
        let server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let wire = server
            .wire
            .beacon()
            .expect("a beacon server has a beacon wire");
        let exit = shared::SignedVoluntaryExit {
            message: shared::VoluntaryExit {
                epoch: 0,
                validator_index: 0,
            },
            signature: Default::default(),
        };
        let payload = exit.to_ssz();

        assert!(matches!(
            triage_operation(&server, wire, beacon_topics::VOLUNTARY_EXIT, &payload),
            Dispatch::Validate(Validated::Operation(_))
        ));
    }

    /// Gossip never delivers a node its own message, so the hand-off is the
    /// only way the chain actor sees an aggregate this node's validator client
    /// submitted, and it needs the indices the Beacon API resolved.
    #[tokio::test]
    async fn a_published_aggregate_is_handed_to_the_chain_with_its_indices() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        // The test server's digest is a placeholder, and an aggregate whose
        // slot no held digest covers is neither published nor handed on.
        let crate::Wire::Beacon(beacon) = &mut server.wire else {
            unreachable!("unconnected_beacon_server builds a beacon wire");
        };
        beacon.topics.fork_digest = beacon.digest_for_slot(5);
        let chain = std::sync::Arc::new(RecordingChain::default());
        server.blockchain = Some(chain.clone());
        let aggregate = ethlambda_types::beacon::containers::SignedAggregateAndProof::Electra(
            electra_aggregate(5, 0),
        );

        publish_beacon_aggregate(&mut server, aggregate.clone(), vec![3, 4]).await;

        assert_eq!(*chain.aggregates.lock().unwrap(), [(aggregate, vec![3, 4])]);
    }

    /// A payload that does not decode as a gloas envelope is the sender's
    /// fault, on either gloas topic.
    #[tokio::test]
    async fn an_undecodable_gloas_message_is_rejected() {
        let server = unconnected_beacon_server(Config::mainnet(), 0).await;

        assert!(matches!(
            triage_envelope(&server, &[0xff; 3]),
            Dispatch::Report(Outcome::Reject(RejectReason::Decode))
        ));
        assert!(matches!(
            triage_payload_attestation(&server, &[0xff; 3]),
            Dispatch::Report(Outcome::Reject(RejectReason::Decode))
        ));
    }

    /// An envelope that clears the cheap checks goes on to the stateful ones,
    /// and a second one for a key the seen cache holds is ignored before them.
    #[tokio::test]
    async fn an_envelope_passes_triage_unless_its_key_was_seen() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let envelope = crate::test_support::envelope(1, 3);
        let payload = envelope.to_ssz();

        assert!(matches!(
            triage_envelope(&server, &payload),
            Dispatch::Validate(Validated::Envelope(decoded)) if *decoded == envelope
        ));

        server.seen_envelopes.record(
            envelope.message.beacon_block_root,
            envelope.message.builder_index,
        );
        assert!(matches!(
            triage_envelope(&server, &payload),
            Dispatch::Report(Outcome::Ignore(IgnoreReason::AlreadySeen))
        ));
    }

    /// A payload attestation for a slot before gloas is rejected by the cheap
    /// checks; mainnet's gloas epoch is not zero, so slot zero is before it.
    #[tokio::test]
    async fn a_payload_attestation_before_gloas_is_rejected() {
        let server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let message = gloas::PayloadAttestationMessage {
            validator_index: 1,
            data: Default::default(),
            signature: Default::default(),
        };

        assert!(matches!(
            triage_payload_attestation(&server, &message.to_ssz()),
            Dispatch::Report(Outcome::Reject(RejectReason::PreGloasSlot))
        ));
    }

    /// A payload attestation inside gloas but outside the current slot is
    /// ignored, and one in the current slot goes on to the stateful checks.
    #[tokio::test]
    async fn a_payload_attestation_is_judged_on_the_clock() {
        let config = Config::mainnet().with_fork_epoch(ForkName::Gloas, 0);
        let server = unconnected_beacon_server(config, 0).await;
        let mut message = gloas::PayloadAttestationMessage {
            validator_index: 1,
            data: Default::default(),
            signature: Default::default(),
        };
        message.data.slot = 1_000_000;
        assert!(matches!(
            triage_payload_attestation(&server, &message.to_ssz()),
            Dispatch::Report(Outcome::Ignore(IgnoreReason::NotCurrentSlot))
        ));
    }

    fn sync_message_bytes(slot: Slot) -> Vec<u8> {
        ethlambda_types::beacon::containers::altair::SyncCommitteeMessage {
            slot,
            beacon_block_root: Default::default(),
            validator_index: 3,
            signature: Default::default(),
        }
        .to_ssz()
    }

    #[tokio::test]
    async fn garbage_on_a_sync_committee_subnet_is_rejected_as_undecodable() {
        let server = unconnected_beacon_server(Config::mainnet(), 0).await;

        assert!(matches!(
            triage_sync_committee_message(&server, &[0xff; 3], 1),
            Dispatch::Report(Outcome::Reject(RejectReason::Decode))
        ));
    }

    #[tokio::test]
    async fn garbage_on_the_contribution_topic_is_rejected_as_undecodable() {
        let server = unconnected_beacon_server(Config::mainnet(), 0).await;

        assert!(matches!(
            triage_sync_contribution(&server, &[0xff; 3]),
            Dispatch::Report(Outcome::Reject(RejectReason::Decode))
        ));
    }

    #[tokio::test]
    async fn a_past_slot_sync_message_is_ignored_and_a_current_one_is_validated() {
        let server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let wall = server.wire.beacon().expect("beacon wire").wall_slot();

        assert!(matches!(
            triage_sync_committee_message(&server, &sync_message_bytes(wall - 5), 1),
            Dispatch::Report(Outcome::Ignore(IgnoreReason::NotCurrentSlot))
        ));
        assert!(matches!(
            triage_sync_committee_message(&server, &sync_message_bytes(wall), 1),
            Dispatch::Validate(Validated::SyncCommitteeMessage { subnet_id: 1, .. })
        ));
    }

    #[tokio::test]
    async fn a_sync_message_already_seen_on_its_subnet_is_ignored() {
        let mut server = unconnected_beacon_server(Config::mainnet(), 0).await;
        let wall = server.wire.beacon().expect("beacon wire").wall_slot();
        server.seen_sync_messages.record(wall, 3, 1);

        assert!(matches!(
            triage_sync_committee_message(&server, &sync_message_bytes(wall), 1),
            Dispatch::Report(Outcome::Ignore(IgnoreReason::AlreadySeen))
        ));
        // Another subnet is another key.
        assert!(matches!(
            triage_sync_committee_message(&server, &sync_message_bytes(wall), 2),
            Dispatch::Validate(_)
        ));
    }
}
