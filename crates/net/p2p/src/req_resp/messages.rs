use ethlambda_types::{ShortRoot, block::SignedBlock, checkpoint::Checkpoint, primitives::H256};
use libssz_derive::{SszDecode, SszEncode};
use libssz_types::SszList;

pub const STATUS_PROTOCOL_V1: &str = "/leanconsensus/req/status/1/ssz_snappy";
pub const BLOCKS_BY_ROOT_PROTOCOL_V1: &str = "/leanconsensus/req/blocks_by_root/1/ssz_snappy";
pub const BLOCKS_BY_RANGE_PROTOCOL_V1: &str = "/leanconsensus/req/blocks_by_range/1/ssz_snappy";
pub const MAX_REQUEST_BLOCKS: u64 = 1024; // Maximum number of blocks in a single request (1024).

#[derive(Debug, Clone)]
pub enum Request {
    Status(Status),
    BlocksByRoot(BlocksByRootRequest),
    BlocksByRange(BlocksByRangeRequest),
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

/// Bounded summary for logs.
///
/// Prefer this over `Debug` anywhere a `Response` reaches a log line. The derived
/// `Debug` on a `Blocks` payload expands every block header and every attestation
/// bitlist byte-by-byte, so a full `BlocksByRange` answer renders as hundreds of
/// kilobytes on a single line — enough to be rejected outright by a log backend.
/// `SignedBlock`'s own `Debug` already truncates the opaque proof bytes for the
/// same reason; this covers the rest of the envelope.
impl std::fmt::Display for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success {
                payload: ResponsePayload::Status(status),
            } => write!(
                f,
                "Success(Status head={}/{} finalized={}/{})",
                status.head.slot,
                ShortRoot(&status.head.root.0),
                status.finalized.slot,
                ShortRoot(&status.finalized.root.0),
            ),
            Self::Success {
                payload: ResponsePayload::Blocks(blocks),
            } => {
                write!(f, "Success(Blocks count={}", blocks.len())?;
                // Reported as first/last rather than a range: a BlocksByRoot
                // response follows the requested root order, so the slots are
                // not necessarily contiguous or ascending.
                if let (Some(first), Some(last)) = (blocks.first(), blocks.last()) {
                    let first_slot = first.message.slot;
                    let last_slot = last.message.slot;
                    write!(f, " first_slot={first_slot} last_slot={last_slot}")?;
                }
                write!(f, ")")
            }
            Self::Error { code, message } => {
                let message = String::from_utf8_lossy(message);
                write!(f, "Error({code:?}: {message})")
            }
        }
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
    Blocks(Vec<SignedBlock>),
}

#[derive(Debug, Clone, SszEncode, SszDecode)]
pub struct Status {
    pub finalized: Checkpoint,
    pub head: Checkpoint,
}

pub type RequestedBlockRoots = SszList<H256, 1024>;

/// Error message type for non-success responses.
/// SSZ-encoded as List[byte, 256] per spec.
pub type ErrorMessage = SszList<u8, 256>;

/// Helper to create an ErrorMessage from a string.
/// Debug builds panic if message exceeds 256 bytes (programming error).
/// Release builds truncate to 256 bytes.
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

    ErrorMessage::try_from(truncated.to_vec()).expect("error message fits in 256 bytes")
}

#[derive(Debug, Clone, SszEncode, SszDecode)]
pub struct BlocksByRootRequest {
    pub roots: RequestedBlockRoots,
}

#[derive(Debug, Clone, SszEncode, SszDecode)]
pub struct BlocksByRangeRequest {
    pub start_slot: u64,
    pub count: u64,
}
