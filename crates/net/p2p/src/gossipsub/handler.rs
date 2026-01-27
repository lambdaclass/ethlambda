use ethlambda_blockchain::BlockChain;
use ethlambda_types::{attestation::SignedAttestation, block::SignedBlockWithAttestation};
use libp2p::gossipsub::Event;
use ssz::Decode;
use tracing::{error, info, trace};

use super::{
    encoding::decompress_message,
    messages::{ATTESTATION_TOPIC_KIND, BLOCK_TOPIC_KIND},
};

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
