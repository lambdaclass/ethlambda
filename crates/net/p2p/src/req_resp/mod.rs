mod codec;
/// The beacon-chain `ssz_snappy` request/response framing: a varint
/// uncompressed-length prefix followed by a snappy *frame*-compressed payload.
///
/// Public because it is the spec's wire format rather than anything specific to
/// lean's message set, so a client speaking a different set of req/resp
/// protocols over the same framing can reuse it. `examples/mainnet_gossip.rs`
/// does exactly that.
pub mod encoding;
pub mod handlers;
mod messages;

pub use codec::Codec;
pub use encoding::{MAX_COMPRESSED_PAYLOAD_SIZE, MAX_PAYLOAD_SIZE};
pub use handlers::{build_status, fetch_block_from_peer, handle_req_resp_message};
pub use messages::{
    BLOCKS_BY_RANGE_PROTOCOL_V1, BLOCKS_BY_ROOT_PROTOCOL_V1, BlocksByRangeRequest,
    BlocksByRootRequest, MAX_REQUEST_BLOCKS, Request, RequestedBlockRoots, Response,
    ResponsePayload, STATUS_PROTOCOL_V1, Status,
};
