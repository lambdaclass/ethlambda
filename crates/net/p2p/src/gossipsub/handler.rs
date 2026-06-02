use ethlambda_types::{
    ShortRoot,
    attestation::{SignedAggregatedAttestation, SignedAttestation},
    block::SignedBlock,
    primitives::HashTreeRoot as _,
};
use libp2p::gossipsub::Event;
use libssz::{SszDecode, SszEncode};
use sha2::{Digest as _, Sha256};
use tracing::{error, info, trace};

use super::{
    encoding::{compress_message, decompress_message},
    messages::{
        AGGREGATION_TOPIC_KIND, ATTESTATION_SUBNET_TOPIC_PREFIX, BLOCK_TOPIC_KIND,
        attestation_subnet_topic,
    },
};
use crate::{P2PServer, gossip_message_id, metrics};

/// Short git SHA of this build, embedded by `build.rs`. Logged with publish-side
/// gossip diagnostics so a captured message can be traced to the emitting build.
const CLIENT_GIT_SHA: &str = env!("VERGEN_GIT_SHA");

/// Snappy implementation and resolved version (the Rust `snap` crate), embedded
/// by `build.rs`. Logged so cross-client byte comparisons can attribute the
/// compressed output to a specific snappy library.
const SNAPPY_LIB_VERSION: &str = concat!("rust-snap/", env!("SNAP_VERSION"));

/// Pre-publish diagnostics for a gossipsub message, capturing the exact bytes a
/// node is about to put on the wire. Used to debug cross-client snappy/SSZ
/// corruption (e.g. blockblaz/zeam#942): comparing these fields against what a
/// peer logs on receipt pinpoints whether divergence is at the compression,
/// transport, or decode stage.
struct PublishDiagnostics {
    /// Lowercase hex SHA256 of the uncompressed SSZ payload.
    ssz_sha256: String,
    /// Lowercase hex SHA256 of the snappy-compressed payload (the on-wire bytes).
    compressed_sha256: String,
    /// Length in bytes of the compressed payload.
    compressed_len: usize,
    /// Whether decompressing our own output round-trips back to the SSZ bytes.
    /// `false` signals a local snappy encoder bug before the message ever leaves.
    snappy_self_decode_ok: bool,
    /// Lowercase hex gossipsub message ID, computed identically to the receive
    /// path so it matches the ID peers will assign.
    message_id: String,
}

impl PublishDiagnostics {
    /// Compute diagnostics for `topic` from the uncompressed `ssz` and its
    /// `compressed` (on-wire) form.
    fn new(topic: &str, ssz: &[u8], compressed: &[u8]) -> Self {
        let snappy_self_decode_ok =
            decompress_message(compressed).is_ok_and(|decoded| decoded == ssz);
        Self {
            ssz_sha256: hex::encode(Sha256::digest(ssz)),
            compressed_sha256: hex::encode(Sha256::digest(compressed)),
            compressed_len: compressed.len(),
            snappy_self_decode_ok,
            message_id: hex::encode(gossip_message_id(topic, compressed)),
        }
    }
}

pub async fn handle_gossipsub_message(server: &mut P2PServer, event: Event) {
    let Event::Message {
        propagation_source,
        message_id: _,
        message,
    } = event
    else {
        unreachable!("we already matched on Message variant in handle_swarm_event");
    };
    let peer_count = server.connected_peers.len();
    let topic_kind = message.topic.as_str().split("/").nth(3);
    match topic_kind {
        Some(BLOCK_TOPIC_KIND) => {
            info!(kind = "block", peer_count, "P2P message received");
            let compressed_len = message.data.len();
            let Ok(uncompressed_data) = decompress_message(&message.data).inspect_err(
                |err| error!(%err, %propagation_source, "Failed to decompress gossipped block"),
            ) else {
                return;
            };
            metrics::observe_gossip_block_size(uncompressed_data.len(), compressed_len);

            let Ok(signed_block) = SignedBlock::from_ssz_bytes(&uncompressed_data)
                .inspect_err(|err| error!(?err, "Failed to decode gossipped block"))
            else {
                return;
            };
            let slot = signed_block.message.slot;
            let block_root = signed_block.message.hash_tree_root();
            let proposer = signed_block.message.proposer_index;
            let parent_root = signed_block.message.parent_root;
            let attestation_count = signed_block.message.body.attestations.len();
            info!(
                %slot,
                proposer,
                block_root = %ShortRoot(&block_root.0),
                parent_root = %ShortRoot(&parent_root.0),
                attestation_count,
                "Received block from gossip"
            );
            if let Some(ref blockchain) = server.blockchain {
                let _ = blockchain
                    .new_block(signed_block)
                    .inspect_err(|err| error!(%err, "Failed to forward block to blockchain"));
            }
        }
        Some(AGGREGATION_TOPIC_KIND) => {
            info!(kind = "aggregation", peer_count, "P2P message received");
            let compressed_len = message.data.len();
            let Ok(uncompressed_data) = decompress_message(&message.data)
                .inspect_err(|err| error!(%err, %propagation_source, "Failed to decompress gossipped aggregation"))
            else {
                return;
            };
            metrics::observe_gossip_aggregation_size(uncompressed_data.len(), compressed_len);

            let Ok(aggregation) = SignedAggregatedAttestation::from_ssz_bytes(&uncompressed_data)
                .inspect_err(|err| error!(?err, "Failed to decode gossipped aggregation"))
            else {
                return;
            };
            let slot = aggregation.data.slot;
            info!(
                %slot,
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
        Some(kind) if kind.starts_with(ATTESTATION_SUBNET_TOPIC_PREFIX) => {
            info!(kind = "attestation", peer_count, "P2P message received");
            let compressed_len = message.data.len();
            let Ok(uncompressed_data) = decompress_message(&message.data)
                .inspect_err(|err| error!(%err, %propagation_source, "Failed to decompress gossipped attestation"))
            else {
                return;
            };
            metrics::observe_gossip_attestation_size(uncompressed_data.len(), compressed_len);

            let Ok(signed_attestation) = SignedAttestation::from_ssz_bytes(&uncompressed_data)
                .inspect_err(|err| error!(?err, "Failed to decode gossipped attestation"))
            else {
                return;
            };
            let slot = signed_attestation.data.slot;
            let validator = signed_attestation.validator_id;
            info!(
                %slot,
                validator,
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
        _ => {
            trace!("Received message on unknown topic: {}", message.topic);
        }
    }
}

pub async fn publish_attestation(server: &mut P2PServer, attestation: SignedAttestation) {
    let slot = attestation.data.slot;
    let validator = attestation.validator_id;
    let subnet_id = validator % server.attestation_committee_count;

    // Encode to SSZ
    let ssz_bytes = attestation.to_ssz();

    // Compress with raw snappy
    let compressed = compress_message(&ssz_bytes);

    metrics::observe_gossip_attestation_size(ssz_bytes.len(), compressed.len());

    // Look up subscribed topic or construct on-the-fly for gossipsub fanout
    let topic = server
        .attestation_topics
        .get(&subnet_id)
        .cloned()
        .unwrap_or_else(|| attestation_subnet_topic(subnet_id));

    let topic_hash = topic.hash();
    let diagnostics = PublishDiagnostics::new(topic_hash.as_str(), &ssz_bytes, &compressed);
    info!(
        topic = %topic_hash,
        %slot,
        validator,
        ssz_sha256 = %diagnostics.ssz_sha256,
        compressed_sha256 = %diagnostics.compressed_sha256,
        compressed_len = diagnostics.compressed_len,
        snappy_self_decode_ok = diagnostics.snappy_self_decode_ok,
        message_id = %diagnostics.message_id,
        git_sha = CLIENT_GIT_SHA,
        snappy = SNAPPY_LIB_VERSION,
        "Publishing attestation to gossipsub (publish diagnostics)"
    );

    server.swarm_handle.publish(topic, compressed);
    info!(
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

    let topic_hash = server.block_topic.hash();
    let diagnostics = PublishDiagnostics::new(topic_hash.as_str(), &ssz_bytes, &compressed);
    info!(
        topic = %topic_hash,
        %slot,
        proposer,
        block_root = %hex::encode(block_root.0),
        ssz_sha256 = %diagnostics.ssz_sha256,
        compressed_sha256 = %diagnostics.compressed_sha256,
        compressed_len = diagnostics.compressed_len,
        snappy_self_decode_ok = diagnostics.snappy_self_decode_ok,
        message_id = %diagnostics.message_id,
        git_sha = CLIENT_GIT_SHA,
        snappy = SNAPPY_LIB_VERSION,
        "Publishing block to gossipsub (publish diagnostics)"
    );

    // Publish to gossipsub
    server
        .swarm_handle
        .publish(server.block_topic.clone(), compressed);
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

    let topic_hash = server.aggregation_topic.hash();
    let diagnostics = PublishDiagnostics::new(topic_hash.as_str(), &ssz_bytes, &compressed);
    info!(
        topic = %topic_hash,
        %slot,
        ssz_sha256 = %diagnostics.ssz_sha256,
        compressed_sha256 = %diagnostics.compressed_sha256,
        compressed_len = diagnostics.compressed_len,
        snappy_self_decode_ok = diagnostics.snappy_self_decode_ok,
        message_id = %diagnostics.message_id,
        git_sha = CLIENT_GIT_SHA,
        snappy = SNAPPY_LIB_VERSION,
        "Publishing aggregated attestation to gossipsub (publish diagnostics)"
    );

    // Publish to the aggregation topic
    server
        .swarm_handle
        .publish(server.aggregation_topic.clone(), compressed);
    info!(
        %slot,
        target_slot = attestation.data.target.slot,
        target_root = %ShortRoot(&attestation.data.target.root.0),
        source_slot = attestation.data.source.slot,
        source_root = %ShortRoot(&attestation.data.source.root.0),
        "Published aggregated attestation to gossipsub"
    );
}
