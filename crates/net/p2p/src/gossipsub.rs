use crate::Behaviour;
use libp2p::gossipsub::Event;
use tracing::{info, trace};

/// Topic kind for block gossip
pub const BLOCK_TOPIC_KIND: &str = "block";
/// Topic kind for attestation gossip
pub const ATTESTATION_TOPIC_KIND: &str = "attestation";

pub async fn handle_gossipsub_message(swarm: &mut libp2p::Swarm<Behaviour>, event: Event) {
    let Event::Message {
        propagation_source: _,
        message_id: _,
        message,
    } = event
    else {
        unreachable!("we already matched on event_loop");
    };
    match message.topic.as_str().split("/").nth(2) {
        Some(BLOCK_TOPIC_KIND) => {
            info!(
                "Received block gossip message of size {} bytes",
                message.data.len()
            );
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
