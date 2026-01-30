mod codec;
mod encoding;
pub mod handlers;
mod messages;

pub use codec::Codec;
pub use encoding::MAX_COMPRESSED_PAYLOAD_SIZE;
pub use handlers::{build_status, fetch_block_from_peer, handle_req_resp_message};
pub use messages::{
    BLOCKS_BY_ROOT_PROTOCOL_V1, BlocksByRootRequest, Request, Response, ResponseCode,
    ResponsePayload, STATUS_PROTOCOL_V1, Status, error_message,
};
