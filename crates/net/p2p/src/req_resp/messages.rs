use ethlambda_types::{block::SignedBlockWithAttestation, primitives::H256, state::Checkpoint};
use ssz_derive::{Decode, Encode};
use ssz_types::typenum;

pub const STATUS_PROTOCOL_V1: &str = "/leanconsensus/req/status/1/ssz_snappy";
pub const BLOCKS_BY_ROOT_PROTOCOL_V1: &str = "/leanconsensus/req/blocks_by_root/1/ssz_snappy";

#[derive(Debug, Clone)]
pub enum Request {
    Status(Status),
    BlocksByRoot(BlocksByRootRequest),
}

#[derive(Debug, Clone)]
pub struct Response {
    pub result: ResponseResult,
    pub payload: ResponsePayload,
}

impl Response {
    pub fn new(result: ResponseResult, payload: ResponsePayload) -> Self {
        Self { result, payload }
    }
}

/// Response codes for req/resp protocol messages.
///
/// The first byte of every response indicates success or failure:
/// - On success (code 0), the payload contains the requested data.
/// - On failure (codes 1-3), the payload contains an error message.
///
/// Unknown codes are handled gracefully:
/// - Codes 4-127: Treated as SERVER_ERROR (reserved for future use).
/// - Codes 128-255: Treated as INVALID_REQUEST (invalid range).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResponseResult {
    /// Request completed successfully. Payload contains the response data.
    Success = 0,
    /// Request was malformed or violated protocol rules.
    InvalidRequest = 1,
    /// Server encountered an internal error processing the request.
    ServerError = 2,
    /// Requested resource (block, blob, etc.) is not available.
    ResourceUnavailable = 3,
}

impl ResponseResult {
    /// Parse a response code byte, mapping unknown codes gracefully per spec.
    pub fn from_u8(code: u8) -> Self {
        match code {
            0 => Self::Success,
            1 => Self::InvalidRequest,
            2 => Self::ServerError,
            3 => Self::ResourceUnavailable,
            // Codes 4-127: Reserved for future use, treat as SERVER_ERROR
            4..=127 => Self::ServerError,
            // Codes 128-255: Invalid range, treat as INVALID_REQUEST
            128..=255 => Self::InvalidRequest,
        }
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum ResponsePayload {
    Status(Status),

    // TODO: here we assume there's a single block per request
    BlocksByRoot(SignedBlockWithAttestation),

    /// Error message for non-success responses.
    /// SSZ-encoded as List[byte, 256] per spec.
    Error(ErrorMessage),
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct Status {
    pub finalized: Checkpoint,
    pub head: Checkpoint,
}

type MaxRequestBlocks = typenum::U1024;
type MaxErrorMessageLength = typenum::U256;

pub type BlocksByRootRequest = ssz_types::VariableList<H256, MaxRequestBlocks>;

/// Error message type for non-success responses.
/// SSZ-encoded as List[byte, 256] per spec.
pub type ErrorMessage = ssz_types::VariableList<u8, MaxErrorMessageLength>;

/// Helper to create an ErrorMessage from a string.
/// Truncates to 256 bytes if necessary.
pub fn error_message(msg: impl AsRef<str>) -> ErrorMessage {
    let bytes = msg.as_ref().as_bytes();
    let truncated = if bytes.len() > 256 {
        &bytes[..256]
    } else {
        bytes
    };

    let vec = truncated.to_vec();
    ErrorMessage::new(vec).expect("error message fits in 256 bytes")
}
