mod encoding;
mod handler;
mod messages;

pub use encoding::decompress_message;
pub use handler::{
    handle_gossipsub_message, publish_aggregated_attestation, publish_attestation, publish_block,
    publish_heartbeat_attestation,
};
pub use messages::{aggregation_topic, attestation_subnet_topic, block_topic, heartbeat_topic};
