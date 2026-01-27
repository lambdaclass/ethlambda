use ethlambda_blockchain::{BlockChain, OutboundGossip};
use ethlambda_types::{attestation::SignedAttestation, block::SignedBlockWithAttestation};
use libp2p::gossipsub::Event;
use ssz::{Decode, Encode};
use tracing::{error, info, trace};

use super::{
    encoding::{compress_message, decompress_message},
    messages::{ATTESTATION_TOPIC_KIND, BLOCK_TOPIC_KIND},
};
use crate::Behaviour;

pub async fn handle_gossipsub_message(blockchain: &mut BlockChain, event: Event) {
    let Event::Message {
        propagation_source: _,
        message_id: _,
        message,
    } = event
    else {
        unreachable!("we already matched on event_loop");
    };
    match message.topic.as_str().split("/").nth(3) {
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
            info!(%slot, "Received new block from gossipsub, sending for processing");
            blockchain.notify_new_block(signed_block).await;
        }
        Some(ATTESTATION_TOPIC_KIND) => {
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
            info!(%slot, %validator, "Received new attestation from gossipsub, sending for processing");
            blockchain.notify_new_attestation(signed_attestation).await;
        }
        _ => {
            trace!("Received message on unknown topic: {}", message.topic);
        }
    }
}

pub async fn handle_outgoing_gossip(
    swarm: &mut libp2p::Swarm<Behaviour>,
    message: OutboundGossip,
    attestation_topic: &libp2p::gossipsub::IdentTopic,
    block_topic: &libp2p::gossipsub::IdentTopic,
) {
    match message {
        OutboundGossip::PublishAttestation(attestation) => {
            let slot = attestation.message.slot;
            let validator = attestation.validator_id;

            // Encode to SSZ
            let ssz_bytes = attestation.as_ssz_bytes();

            // Compress with raw snappy
            let compressed = compress_message(&ssz_bytes);

            // Publish to gossipsub
            let _ = swarm
                .behaviour_mut()
                .gossipsub
                .publish(attestation_topic.clone(), compressed)
                .inspect(|_| trace!(%slot, %validator, "Published attestation to gossipsub"))
                .inspect_err(|err| {
                    tracing::warn!(%slot, %validator, %err, "Failed to publish attestation to gossipsub")
                });
        }
        OutboundGossip::PublishBlock(signed_block) => {
            let slot = signed_block.message.block.slot;
            let proposer = signed_block.message.block.proposer_index;

            // Encode to SSZ
            let ssz_bytes = signed_block.as_ssz_bytes();

            // Compress with raw snappy
            let compressed = compress_message(&ssz_bytes);

            // Publish to gossipsub
            let _ = swarm
                .behaviour_mut()
                .gossipsub
                .publish(block_topic.clone(), compressed)
                .inspect(|_| info!(%slot, %proposer, "Published block to gossipsub"))
                .inspect_err(|err| {
                    tracing::warn!(%slot, %proposer, %err, "Failed to publish block to gossipsub")
                });
        }
    }
}
