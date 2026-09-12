//! What `P2PServer` does with gossip, on either chain.
//!
//! One entry point and one dispatch, the shape `crate::req_resp::handlers` has:
//! the topic says which chain a message belongs to, so nothing above this module
//! branches on which chain the node follows. Handler names follow the same
//! convention as there, lean prefixed and beacon bare.

use ethlambda_network_api::BlockSource;
use ethlambda_types::{
    ShortRoot,
    attestation::{SignedAggregatedAttestation, SignedAttestation},
    beacon::containers::SignedBeaconBlock,
    block::SignedBlock,
    primitives::HashTreeRoot as _,
};
use libp2p::gossipsub::Message;
use libssz::{SszDecode, SszEncode};
use tracing::{debug, error, info, trace, warn};

use super::{
    encoding::{compress_message, decompress_message},
    messages::{
        AGGREGATION_TOPIC_KIND, ATTESTATION_SUBNET_TOPIC_PREFIX, BLOCK_TOPIC_KIND,
        attestation_subnet_topic, topic_kind,
    },
};
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
pub async fn handle_gossip_message(server: &mut P2PServer, message: Message) {
    let Some(kind) = topic_kind(message.topic.as_str()) else {
        trace!(topic = %message.topic, "Gossip on an unparseable topic");
        return;
    };
    trace!(
        kind,
        peer_count = server.connected_peers.len(),
        "P2P message received"
    );

    let compressed_len = message.data.len();
    let Some(payload) = decompress(&message.data, kind) else {
        return;
    };

    match kind {
        BLOCK_TOPIC_KIND => handle_lean_block(server, &payload, compressed_len).await,
        AGGREGATION_TOPIC_KIND => handle_lean_aggregation(server, &payload, compressed_len).await,
        kind if kind.starts_with(ATTESTATION_SUBNET_TOPIC_PREFIX) => {
            handle_lean_attestation(server, &payload, compressed_len).await
        }
        beacon_topics::BEACON_BLOCK => handle_beacon_block(server, &payload).await,
        beacon_topics::BEACON_AGGREGATE_AND_PROOF => {
            handle_beacon_aggregate(server, &payload).await
        }
        // The remaining five beacon topics share an arm because they share a
        // handler: this node decodes them to prove it can and logs that it did,
        // with nothing to say about any of them in particular.
        kind if beacon_topics::SUBSCRIBED_TOPIC_KINDS.contains(&kind) => {
            handle_beacon_other(server, &payload, kind).await
        }
        _ => trace!(topic = %message.topic, "Gossip on an unhandled topic"),
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

/// The beacon wire, or `None` on a lean node, which serves no beacon topic.
fn beacon_wire<'a>(server: &'a P2PServer, kind: &str) -> Option<&'a BeaconWire> {
    let wire = server.wire.beacon();
    if wire.is_none() {
        debug!(kind, "Beacon gossip arrived on a lean node");
    }
    wire
}

async fn handle_lean_block(server: &mut P2PServer, payload: &[u8], compressed_len: usize) {
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
        let _ = blockchain
            .new_block(SignedBeaconBlock::Lean(signed_block), BlockSource::Gossip)
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

/// Decode a beacon block and hand it to the beacon chain actor.
///
/// The anchor block puts a parent in the store before gossip starts, so
/// `on_block` no longer rejects these for want of one: forward every decoded
/// block the way [`handle_lean_block`] forwards its own.
async fn handle_beacon_block(server: &mut P2PServer, payload: &[u8]) {
    const KIND: &str = beacon_topics::BEACON_BLOCK;
    let Some(wire) = beacon_wire(server, KIND) else {
        return;
    };
    match beacon_decode::decode_block(&wire.config, payload) {
        Ok(block) => {
            metrics::inc_beacon_gossip(KIND, "decoded");
            info!(
                slot = block.slot(),
                proposer = block.proposer_index(),
                fork = block.fork_name().as_str(),
                block_root = %ShortRoot(&block.message_hash_tree_root().0),
                bytes = payload.len(),
                "Beacon block decoded"
            );
            if let Some(ref blockchain) = server.blockchain {
                let _ = blockchain
                    .new_block(block, BlockSource::Gossip)
                    .inspect_err(|err| error!(%err, "Failed to forward block to blockchain"));
            }
        }
        Err(err) => {
            metrics::inc_beacon_gossip(KIND, "decode_failed");
            debug!(kind = KIND, %err, bytes = payload.len(), "Beacon gossip decode failed");
        }
    }
}

/// Decode a beacon aggregate and record that it arrived. Forwards nothing:
/// `beacon_aggregate_and_proof` is a global topic carrying roughly a thousand
/// aggregates per slot on mainnet at about 30ms each in `on_attestation`, more
/// work per slot than a slot lasts on a single-threaded actor, so fork choice
/// learns its votes from block bodies inside `on_block` instead of from this
/// topic.
async fn handle_beacon_aggregate(server: &mut P2PServer, payload: &[u8]) {
    const KIND: &str = beacon_topics::BEACON_AGGREGATE_AND_PROOF;
    let Some(wire) = beacon_wire(server, KIND) else {
        return;
    };
    match beacon_decode::decode_aggregate_and_proof(&wire.config, payload) {
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
        }
        Err(err) => {
            metrics::inc_beacon_gossip(KIND, "decode_failed");
            debug!(kind = KIND, %err, bytes = payload.len(), "Beacon gossip decode failed");
        }
    }
}

/// Decode one of the five beacon topics with nothing particular to report, and
/// record that it arrived. Forwards nothing: none of these five has a
/// consumer.
async fn handle_beacon_other(server: &mut P2PServer, payload: &[u8], kind: &str) {
    let Some(wire) = beacon_wire(server, kind) else {
        return;
    };
    match beacon_decode::decode_gossip(&wire.config, kind, payload) {
        Ok(decoded) => {
            metrics::inc_beacon_gossip(kind, "decoded");
            debug!(
                kind = decoded.topic_kind(),
                bytes = payload.len(),
                "Beacon gossip decoded"
            );
        }
        Err(err) => {
            metrics::inc_beacon_gossip(kind, "decode_failed");
            debug!(kind, %err, bytes = payload.len(), "Beacon gossip decode failed");
        }
    }
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
