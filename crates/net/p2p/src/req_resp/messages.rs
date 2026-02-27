use ethlambda_types::{
    block::SignedBlockWithAttestation,
    primitives::{
        H256,
        ssz::{Decode, Encode},
    },
    state::Checkpoint,
};
use ssz_types::typenum;

pub const STATUS_PROTOCOL_V1: &str = "/leanconsensus/req/status/1/ssz_snappy";
pub const BLOCKS_BY_ROOT_PROTOCOL_V1: &str = "/leanconsensus/req/blocks_by_root/1/ssz_snappy";

#[derive(Debug, Clone)]
pub enum Request {
    Status(Status),
    BlocksByRoot(BlocksByRootRequest),
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum Response {
    Success {
        payload: ResponsePayload,
    },
    Error {
        code: ResponseCode,
        message: ErrorMessage,
    },
}

impl Response {
    /// Create a success response with the given payload.
    pub fn success(payload: ResponsePayload) -> Self {
        Self::Success { payload }
    }

    /// Create an error response with the given code and message.
    pub fn error(code: ResponseCode, message: ErrorMessage) -> Self {
        Self::Error { code, message }
    }
}

/// Response codes for req/resp protocol messages.
///
/// The first byte of every response indicates success or failure:
/// - On success (code 0), the payload contains the requested data.
/// - On failure (codes 1-3), the payload contains an error message.
///
/// Unknown codes are handled gracefully:
/// - Codes 4-127: Reserved for future use, treat as SERVER_ERROR.
/// - Codes 128-255: Invalid range, treat as INVALID_REQUEST.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ResponseCode(pub u8);

impl ResponseCode {
    /// Request completed successfully. Payload contains the response data.
    pub const SUCCESS: Self = Self(0);
    /// Request was malformed or violated protocol rules.
    pub const INVALID_REQUEST: Self = Self(1);
    /// Server encountered an internal error processing the request.
    pub const SERVER_ERROR: Self = Self(2);
    /// Requested resource (block, blob, etc.) is not available.
    pub const RESOURCE_UNAVAILABLE: Self = Self(3);
}

impl From<u8> for ResponseCode {
    fn from(code: u8) -> Self {
        Self(code)
    }
}

impl From<ResponseCode> for u8 {
    fn from(code: ResponseCode) -> Self {
        code.0
    }
}

impl std::fmt::Debug for ResponseCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::SUCCESS => write!(f, "SUCCESS(0)"),
            Self::INVALID_REQUEST => write!(f, "INVALID_REQUEST(1)"),
            Self::SERVER_ERROR => write!(f, "SERVER_ERROR(2)"),
            Self::RESOURCE_UNAVAILABLE => write!(f, "RESOURCE_UNAVAILABLE(3)"),
            // Unknown codes: treat 4-127 as SERVER_ERROR, 128-255 as INVALID_REQUEST
            Self(code @ 4..=127) => write!(f, "SERVER_ERROR({code})"),
            Self(code @ 128..=255) => write!(f, "INVALID_REQUEST({code})"),
        }
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum ResponsePayload {
    Status(Status),
    BlocksByRoot(Vec<SignedBlockWithAttestation>),
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct Status {
    pub finalized: Checkpoint,
    pub head: Checkpoint,
}

type MaxRequestBlocks = typenum::U1024;
type MaxErrorMessageLength = typenum::U256;

pub type RequestedBlockRoots = ssz_types::VariableList<H256, MaxRequestBlocks>;

/// Error message type for non-success responses.
/// SSZ-encoded as List[byte, 256] per spec.
pub type ErrorMessage = ssz_types::VariableList<u8, MaxErrorMessageLength>;

/// Helper to create an ErrorMessage from a string.
/// Debug builds panic if message exceeds 256 bytes (programming error).
/// Release builds truncate to 256 bytes.
#[expect(dead_code)]
// TODO: map errors to req/resp error messages
pub fn error_message(msg: impl AsRef<str>) -> ErrorMessage {
    let bytes = msg.as_ref().as_bytes();
    debug_assert!(
        bytes.len() <= 256,
        "Error message exceeds 256 byte protocol limit: {} bytes. Message: '{}'",
        bytes.len(),
        msg.as_ref()
    );

    let truncated = if bytes.len() > 256 {
        &bytes[..256]
    } else {
        bytes
    };

    ErrorMessage::new(truncated.to_vec()).expect("error message fits in 256 bytes")
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct BlocksByRootRequest {
    pub roots: RequestedBlockRoots,
}
