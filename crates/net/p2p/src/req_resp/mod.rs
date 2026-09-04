pub(crate) mod codec;
pub(crate) mod encoding;
pub mod handlers;
pub(crate) mod messages;

pub use codec::Codec;
pub use encoding::{MAX_COMPRESSED_PAYLOAD_SIZE, MAX_PAYLOAD_SIZE};
pub use handlers::{build_status, fetch_block_from_peer, handle_req_resp_message};
pub use messages::{Request, Response, ResponsePayload};
