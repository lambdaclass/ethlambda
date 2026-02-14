use ethlambda_types::{
    ShortRoot,
    attestation::{SignedAggregatedAttestation, SignedAttestation},
    block::SignedBlockWithAttestation,
    primitives::ssz::{Decode, Encode, TreeHash},
};
use libp2p::gossipsub::Event;
use tracing::{error, info, trace};

use super::{
    encoding::{compress_message, decompress_message},
    messages::{AGGREGATION_TOPIC_KIND, ATTESTATION_SUBNET_TOPIC_PREFIX, BLOCK_TOPIC_KIND},
};
use crate::P2PServer;

pub async fn handle_gossipsub_message(server: &mut P2PServer, event: Event) {
    let Event::Message {
        propagation_source: _,
        message_id: _,
        message,
    } = event
    else {
        unreachable!("we already matched on event_loop");
    };
    let topic_kind = message.topic.as_str().split("/").nth(3);
    match topic_kind {
        Some(BLOCK_TOPIC_KIND) => {
            let Ok(uncompressed_data) = decompress_message(&message.data)
                .inspect_err(|err| error!(%err, "Failed to decompress gossipped block"))
            else {
                return;
            };

            let Ok(signed_block) = SignedBlockWithAttestation::from_ssz_bytes(&uncompressed_data)
                .inspect_err(|err| error!(?err, "Failed to decode gossipped block"))
            else {
                return;
            };
            let slot = signed_block.message.block.slot;
            let block_root = signed_block.message.block.tree_hash_root();
            let proposer = signed_block.message.block.proposer_index;
            let parent_root = signed_block.message.block.parent_root;
            let attestation_count = signed_block.message.block.body.attestations.len();
            info!(
                %slot,
                proposer,
                block_root = %ShortRoot(&block_root.0),
                parent_root = %ShortRoot(&parent_root.0),
                attestation_count,
                "Received block from gossip"
            );
            server.blockchain.notify_new_block(signed_block).await;
        }
        Some(AGGREGATION_TOPIC_KIND) => {
            let Ok(uncompressed_data) = decompress_message(&message.data)
                .inspect_err(|err| error!(%err, "Failed to decompress gossipped aggregation"))
            else {
                return;
            };

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
            server
                .blockchain
                .notify_new_aggregated_attestation(aggregation)
                .await;
        }
        Some(kind) if kind.starts_with(ATTESTATION_SUBNET_TOPIC_PREFIX) => {
            let Ok(uncompressed_data) = decompress_message(&message.data)
                .inspect_err(|err| error!(%err, "Failed to decompress gossipped attestation"))
            else {
                return;
            };

            let Ok(signed_attestation) = SignedAttestation::from_ssz_bytes(&uncompressed_data)
                .inspect_err(|err| error!(?err, "Failed to decode gossipped attestation"))
            else {
                return;
            };
            let slot = signed_attestation.message.slot;
            let validator = signed_attestation.validator_id;
            info!(
                %slot,
                validator,
                head_root = %ShortRoot(&signed_attestation.message.head.root.0),
                target_slot = signed_attestation.message.target.slot,
                target_root = %ShortRoot(&signed_attestation.message.target.root.0),
                source_slot = signed_attestation.message.source.slot,
                source_root = %ShortRoot(&signed_attestation.message.source.root.0),
                "Received attestation from gossip"
            );
            server
                .blockchain
                .notify_new_attestation(signed_attestation)
                .await;
        }
        _ => {
            trace!("Received message on unknown topic: {}", message.topic);
        }
    }
}

pub async fn publish_attestation(server: &mut P2PServer, attestation: SignedAttestation) {
    let slot = attestation.message.slot;
    let validator = attestation.validator_id;

    // Encode to SSZ
    let ssz_bytes = attestation.as_ssz_bytes();

    // Compress with raw snappy
    let compressed = compress_message(&ssz_bytes);

    // Publish to the attestation subnet topic
    let _ = server
        .swarm
        .behaviour_mut()
        .gossipsub
        .publish(server.attestation_topic.clone(), compressed)
        .inspect(|_| info!(
            %slot,
            validator,
            target_slot = attestation.message.target.slot,
            target_root = %ShortRoot(&attestation.message.target.root.0),
            source_slot = attestation.message.source.slot,
            source_root = %ShortRoot(&attestation.message.source.root.0),
            "Published attestation to gossipsub"
        ))
        .inspect_err(|err| {
            tracing::warn!(%slot, %validator, %err, "Failed to publish attestation to gossipsub")
        });
}

pub async fn publish_block(server: &mut P2PServer, signed_block: SignedBlockWithAttestation) {
    let slot = signed_block.message.block.slot;
    let proposer = signed_block.message.block.proposer_index;
    let block_root = signed_block.message.block.tree_hash_root();
    let parent_root = signed_block.message.block.parent_root;
    let attestation_count = signed_block.message.block.body.attestations.len();

    // Encode to SSZ
    let ssz_bytes = signed_block.as_ssz_bytes();

    // Compress with raw snappy
    let compressed = compress_message(&ssz_bytes);

    // Publish to gossipsub
    let _ = server
        .swarm
        .behaviour_mut()
        .gossipsub
        .publish(server.block_topic.clone(), compressed)
        .inspect(|_| {
            info!(
                %slot,
                proposer,
                block_root = %ShortRoot(&block_root.0),
                parent_root = %ShortRoot(&parent_root.0),
                attestation_count,
                "Published block to gossipsub"
            )
        })
        .inspect_err(
            |err| tracing::warn!(%slot, %proposer, %err, "Failed to publish block to gossipsub"),
        );
}

pub async fn publish_aggregated_attestation(
    server: &mut P2PServer,
    attestation: SignedAggregatedAttestation,
) {
    let slot = attestation.data.slot;

    // Encode to SSZ
    let ssz_bytes = attestation.as_ssz_bytes();

    // Compress with raw snappy
    let compressed = compress_message(&ssz_bytes);

    // Publish to the aggregation topic
    let _ = server
        .swarm
        .behaviour_mut()
        .gossipsub
        .publish(server.aggregation_topic.clone(), compressed)
        .inspect(|_| {
            info!(
                %slot,
                target_slot = attestation.data.target.slot,
                target_root = %ShortRoot(&attestation.data.target.root.0),
                source_slot = attestation.data.source.slot,
                source_root = %ShortRoot(&attestation.data.source.root.0),
                "Published aggregated attestation to gossipsub"
            )
        })
        .inspect_err(|err| {
            tracing::warn!(%slot, %err, "Failed to publish aggregated attestation to gossipsub")
        });
}
