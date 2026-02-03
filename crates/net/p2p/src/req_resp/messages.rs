use ethlambda_types::{
    block::SignedBlockWithAttestation,
    primitives::{
        H256,
        ssz::{Decode, Decode as SszDecode, Encode},
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
#[allow(dead_code)]
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

impl BlocksByRootRequest {
    /// Decode from SSZ bytes with backward compatibility.
    ///
    /// Tries to decode as new format (container with `roots` field) first.
    /// Falls back to old format (transparent - direct list of roots) if that fails.
    pub fn from_ssz_bytes_compat(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        // Try new format (container) first
        SszDecode::from_ssz_bytes(bytes).or_else(|_| {
            // Fall back to old format (transparent/direct list)
            SszDecode::from_ssz_bytes(bytes).map(|roots| Self { roots })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssz::Encode as SszEncode;

    #[test]
    fn test_blocks_by_root_backward_compatibility() {
        // Create some test roots
        let root1 = H256::from_slice(&[1u8; 32]);
        let root2 = H256::from_slice(&[2u8; 32]);
        let roots_list =
            RequestedBlockRoots::new(vec![root1, root2]).expect("Failed to create roots list");

        // Encode as old format (direct list, similar to transparent)
        let old_format_bytes = roots_list.as_ssz_bytes();

        // Encode as new format (container)
        let new_request = BlocksByRootRequest {
            roots: roots_list.clone(),
        };
        let new_format_bytes = new_request.as_ssz_bytes();

        // Both formats should decode successfully
        let decoded_from_old = BlocksByRootRequest::from_ssz_bytes_compat(&old_format_bytes)
            .expect("Failed to decode old format");
        let decoded_from_new = BlocksByRootRequest::from_ssz_bytes_compat(&new_format_bytes)
            .expect("Failed to decode new format");

        // Both should have the same roots
        assert_eq!(decoded_from_old.roots.len(), 2);
        assert_eq!(decoded_from_new.roots.len(), 2);
        assert_eq!(decoded_from_old.roots[0], root1);
        assert_eq!(decoded_from_old.roots[1], root2);
        assert_eq!(decoded_from_new.roots[0], root1);
        assert_eq!(decoded_from_new.roots[1], root2);
    }
}
