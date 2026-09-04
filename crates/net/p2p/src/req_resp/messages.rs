use ethlambda_types::{ShortRoot, block::SignedBlock};
use libssz_types::SszList;

use crate::beacon::messages::{BeaconMetaData, BeaconStatus, Goodbye, Ping};
use crate::lean::messages::{BlocksByRangeRequest, BlocksByRootRequest, Status};

/// Every request either chain can send, on one flat enum.
///
/// One variant per protocol. Flat rather than a `Lean(..)`/`Beacon(..)` pair of
/// sub-enums, because a request is dispatched once, on its protocol: grouping
/// them meant the codec built two enums to encode one request, and every
/// dispatch re-discriminated what the protocol id had already settled.
///
/// Only lean's variants are prefixed. `Status` exists on both wires and means
/// different things, so one of the two has to say which it is; the beacon
/// variants keep the name their protocol has in the beacon-chain spec, which is
/// what a reader comparing this against that spec is looking for.
#[derive(Debug, Clone)]
pub enum Request {
    LeanStatus(Status),
    LeanBlocksByRoot(BlocksByRootRequest),
    LeanBlocksByRange(BlocksByRangeRequest),
    Status(BeaconStatus),
    Ping(Ping),
    /// The negotiated `metadata/N` protocol id.
    ///
    /// The request is empty on the wire, but the responder has to answer in the
    /// version the peer asked for, and `request_response::Event::Message` does
    /// not carry the protocol id. The codec does, so it records it here.
    MetaData(&'static str),
    Goodbye(Goodbye),
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
/// `Debug` on a `LeanBlocks` payload expands every block header and every attestation
/// bitlist byte-by-byte, so a full `BlocksByRange` answer renders as hundreds of
/// kilobytes on a single line — enough to be rejected outright by a log backend.
/// `SignedBlock`'s own `Debug` already truncates the opaque proof bytes for the
/// same reason; this covers the rest of the envelope.
impl std::fmt::Display for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success {
                payload: ResponsePayload::LeanStatus(status),
            } => write!(
                f,
                "Success(LeanStatus head={}/{} finalized={}/{})",
                status.head.slot,
                ShortRoot(&status.head.root.0),
                status.finalized.slot,
                ShortRoot(&status.finalized.root.0),
            ),
            Self::Success {
                payload: ResponsePayload::LeanBlocks(blocks),
            } => {
                write!(f, "Success(LeanBlocks count={}", blocks.len())?;
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
            Self::Success {
                payload: ResponsePayload::Status(status),
            } => write!(
                f,
                "Success(Status head_slot={} finalized_epoch={} fork_digest={})",
                status.head_slot(),
                status.finalized_epoch(),
                hex::encode(status.fork_digest()),
            ),
            Self::Success {
                payload: ResponsePayload::Pong(ping),
            } => write!(f, "Success(Pong seq_number={})", ping.seq_number),
            Self::Success {
                payload: ResponsePayload::MetaData(metadata),
            } => {
                // The version is what a mismatch here would be about; the
                // bitfields behind it are not worth a log line.
                let (version, seq_number) = match metadata {
                    BeaconMetaData::V1(metadata) => (1, metadata.seq_number),
                    BeaconMetaData::V2(metadata) => (2, metadata.seq_number),
                    BeaconMetaData::V3(metadata) => (3, metadata.seq_number),
                };
                write!(f, "Success(MetaData v{version} seq_number={seq_number})")
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

/// Every success payload either chain can send, on one flat enum.
///
/// Mirrors [`Request`]: one variant per protocol, lean's prefixed. Not one
/// variant per request variant, because [`Request::Goodbye`] is answered by
/// closing the stream rather than by a payload.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum ResponsePayload {
    LeanStatus(Status),
    LeanBlocks(Vec<SignedBlock>),
    Status(BeaconStatus),
    Pong(Ping),
    MetaData(BeaconMetaData),
}

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
