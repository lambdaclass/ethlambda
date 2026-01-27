mod encoding;
mod handler;
mod messages;

pub use encoding::compress_message;
pub use handler::handle_gossipsub_message;
pub use messages::{ATTESTATION_TOPIC_KIND, BLOCK_TOPIC_KIND};
