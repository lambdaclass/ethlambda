use ethlambda_types::block::SignedBlockWithAttestation;
use libp2p::gossipsub::Event;
use ssz::Decode;
use tracing::{error, info, trace};

/// Topic kind for block gossip
pub const BLOCK_TOPIC_KIND: &str = "block";
/// Topic kind for attestation gossip
pub const ATTESTATION_TOPIC_KIND: &str = "attestation";

pub async fn handle_gossipsub_message(event: Event) {
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
            info!(slot=%signed_block.message.block.slot, "Received new block");
        }
        Some(ATTESTATION_TOPIC_KIND) => {
            info!(
                "Received attestation gossip message of size {} bytes",
                message.data.len()
            );
        }
        _ => {
            trace!("Received message on unknown topic: {}", message.topic);
        }
    }
}

fn decompress_message(data: &[u8]) -> snap::Result<Vec<u8>> {
    let uncompressed_size = snap::raw::decompress_len(&data)?;
    let mut uncompressed_data = vec![0u8; uncompressed_size];
    snap::raw::Decoder::new().decompress(&data, &mut uncompressed_data)?;
    Ok(uncompressed_data)
}
