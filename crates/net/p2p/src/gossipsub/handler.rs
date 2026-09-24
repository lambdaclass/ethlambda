//! What `P2PServer` does with gossip, on either chain.
//!
//! One entry point and one dispatch, the shape `crate::req_resp::handlers` has:
//! the topic says which chain a message belongs to, so nothing above this module
//! branches on which chain the node follows. Handler names follow the same
//! convention as there, lean prefixed and beacon bare.

use std::time::Instant;

use ethlambda_network_api::{BlockArrival, BlockSource};
use ethlambda_state_transition::beacon::gossip::{self, IgnoreReason, Outcome, RejectReason};
use ethlambda_types::{
    ShortRoot,
    attestation::{SignedAggregatedAttestation, SignedAttestation},
    beacon::containers::SignedBeaconBlock,
    block::SignedBlock,
    primitives::HashTreeRoot as _,
    time::unix_now_ms,
};
use libp2p::PeerId;
use libp2p::gossipsub::{Message, MessageId};
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
            Some(id) => handle_beacon_gossip(server, ctx, id, kind, &payload),
            None => trace!(topic = %message.topic, "Gossip on an unhandled topic"),
        },
    }
}

/// Undo the snappy framing both wires use.
///
/// The failure bookkeeping is the one asymmetric part, and stays that way:
/// beacon counts what it drops per topic kind, lean has no counterpart metric.
/// Both log.
fn decompress(data: &[u8], kind: &str) -> Option<Vec<u8>> {
    decompress_message(data)
        .inspect_err(|err| {
            error!(%err, kind, "Failed to decompress gossipped message");
            if beacon_topics::SUBSCRIBED_TOPIC_KINDS.contains(&kind) {
                metrics::inc_beacon_gossip(kind, "decompress_failed");
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
    kind: &str,
    payload: &[u8],
) {
    let Some(wire) = server.wire.beacon() else {
        // Beacon topics are never subscribed on a lean node, whose gossipsub
        // holds nothing for a verdict.
        debug!(kind, "Beacon gossip arrived on a lean node");
        return;
    };
    let dispatch = if kind == beacon_topics::BEACON_BLOCK {
        triage_block(server, wire, payload)
    } else if let Some(subnet_id) = beacon_topics::data_column_subnet(kind) {
        triage_data_column(server, payload, subnet_id)
    } else if kind == beacon_topics::BEACON_AGGREGATE_AND_PROOF {
        triage_aggregate(wire, payload)
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
fn triage_data_column(server: &P2PServer, payload: &[u8], subnet_id: u64) -> Dispatch {
    const KIND: &str = beacon_topics::DATA_COLUMN_SIDECAR_KIND;
    let sidecar = match beacon_decode::decode_data_column_sidecar(payload) {
        Ok(sidecar) => sidecar,
        Err(err) => {
            metrics::inc_beacon_gossip(KIND, "decode_failed");
            debug!(?err, "Dropping an undecodable data column sidecar");
            return Dispatch::Report(Outcome::Reject(RejectReason::Decode));
        }
    };
    metrics::inc_beacon_gossip(KIND, "decoded");
    let now_ms = unix_now_ms();
    if let Err(outcome) = gossip::column::cheap_checks(
        &server.seen_columns,
        &server.store,
        &sidecar,
        subnet_id,
        now_ms,
    ) {
        return Dispatch::Report(outcome);
    }
    Dispatch::Validate(Validated::Column(Box::new(sidecar)))
}

/// Decode a beacon aggregate and log it. Never forwarded:
/// `beacon_aggregate_and_proof` is a global topic carrying roughly a thousand
/// aggregates per slot on mainnet at about 30ms each in `on_attestation`, more
/// work per slot than a slot lasts on a single-threaded actor, so fork choice
/// learns its votes from block bodies inside `on_block` instead of from this
/// topic. Ignored rather than validated until it has a consumer, so this
/// always answers `Dispatch::Report`.
fn triage_aggregate(wire: &BeaconWire, payload: &[u8]) -> Dispatch {
    const KIND: &str = beacon_topics::BEACON_AGGREGATE_AND_PROOF;
    let outcome = match beacon_decode::decode_aggregate_and_proof(&wire.config, payload) {
        Ok(aggregate) => {
            metrics::inc_beacon_gossip(KIND, "decoded");
            let (target_epoch, target_root) = aggregate.target();
            info!(
                slot = aggregate.slot(),
                aggregator = aggregate.aggregator_index(),
                attesters = aggregate.attester_count(),
                target_epoch,
                target_root = %ShortRoot(&target_root.0),
                bytes = payload.len(),
                "Beacon aggregate attestation decoded"
            );
            Outcome::Ignore(IgnoreReason::NoConsumer)
        }
        Err(err) => {
            metrics::inc_beacon_gossip(KIND, "decode_failed");
            debug!(kind = KIND, %err, bytes = payload.len(), "Beacon gossip decode failed");
            Outcome::Reject(RejectReason::Decode)
        }
    };
    Dispatch::Report(outcome)
}

/// Decode one of the five beacon topics with nothing particular to report,
/// and count it. Ignored rather than validated: none of the five has a
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

#[cfg(test)]
mod tests {
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::containers::shared;

    use super::*;
    use crate::test_support::{unconnected_beacon_server, valid_shaped_sidecar};

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

    #[tokio::test]
    async fn garbage_bytes_on_a_data_column_subnet_are_rejected_as_undecodable() {
        let server = unconnected_beacon_server(Config::mainnet(), 0).await;

        assert!(matches!(
            triage_data_column(&server, &[0xff; 3], 0),
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
            triage_data_column(&server, &payload, 0),
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
            triage_data_column(&server, &payload, 0),
            Dispatch::Validate(Validated::Column(_))
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
            triage_data_column(&server, &payload, 1),
            Dispatch::Report(Outcome::Reject(RejectReason::WrongSubnet))
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
            triage_other(wire, beacon_topics::VOLUNTARY_EXIT, &[0xff; 3]),
            Dispatch::Report(Outcome::Reject(RejectReason::Decode))
        ));
    }

    #[tokio::test]
    async fn a_valid_voluntary_exit_is_ignored_for_lack_of_a_consumer() {
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
            triage_other(wire, beacon_topics::VOLUNTARY_EXIT, &payload),
            Dispatch::Report(Outcome::Ignore(IgnoreReason::NoConsumer))
        ));
    }
}
