use ethlambda_types::ShortRoot;
use ethlambda_types::beacon::containers::SignedBeaconBlock;
use ethlambda_types::beacon::containers::fulu::{DataColumnSidecar, DataColumnsByRootIdentifier};
use libssz_types::SszList;

use crate::beacon::messages::{
    BeaconMetaData, BeaconStatus, DataColumnsByRangeRequest, Goodbye, Ping,
};
use crate::lean::messages::{BlocksByRootRequest, Status};

/// A contiguous slot window, as either chain's `blocks_by_range` asks for it.
///
/// Carries `step` even though only beacon's wire has the field, and only ever
/// legally as 1. It is here rather than hidden in beacon's encoder so that a
/// peer sending another value can be told so with an `INVALID_REQUEST`
/// response: refusing it at decode would drop the stream instead, which says
/// nothing about why. Lean's decoder fills it with 1, which is what lean's
/// absence of the field means, and lean's encoder drops it again.
///
/// Deliberately **not** SSZ-derived, unlike the two chains' own containers.
/// Neither wire carries these three fields in this shape: lean's body is two
/// of them and beacon's is a different container that happens to agree. A
/// derive here would put a `to_ssz` on the shared type that is correct for
/// neither wire and wrong by 8 bytes on lean's, which is exactly the class of
/// mistake the split exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlocksByRangeRequest {
    pub start_slot: u64,
    pub count: u64,
    /// Deprecated by the beacon spec and absent from lean's wire; legal only
    /// as 1. See the container's doc comment.
    pub step: u64,
}

impl BlocksByRangeRequest {
    /// The blocks in `[start_slot, start_slot + count)`.
    pub fn new(start_slot: u64, count: u64) -> Self {
        Self {
            start_slot,
            count,
            step: 1,
        }
    }
}

/// Every request either chain can send, on one flat enum.
///
/// One variant per protocol. Flat rather than a `Lean(..)`/`Beacon(..)` pair of
/// sub-enums, because a request is dispatched once, on its protocol: grouping
/// them meant the codec built two enums to encode one request, and every
/// dispatch re-discriminated what the protocol id had already settled.
///
/// Only the variants that mean *different things* on the two wires are
/// prefixed, which is `Status` alone: lean's carries two checkpoints and
/// beacon's a fork digest and a head/finalized pair. The beacon variants keep
/// the name their protocol has in the beacon-chain spec, which is what a reader
/// comparing this against that spec is looking for.
///
/// The two block requests are **shared**. What a peer is asking for is the same
/// question on either chain, a slot window or a list of roots, and only the
/// framing of that question differs: lean wraps the root list in a container
/// where beacon sends it bare, and beacon's range body carries a deprecated
/// `step` that lean's does not. Framing is the encoder's business, so the range
/// request is a struct of this module's own, belonging to neither wire, the
/// root request is lean's container on both, and each chain's encoder
/// translates. Which chain a request arrived on is not recorded here either:
/// a node speaks one wire for its whole life, so `P2PServer::wire` already
/// answers it and a tag on the message would be a second copy of that.
#[derive(Debug, Clone)]
pub enum Request {
    LeanStatus(Status),
    /// The roots asked for. Bounded at 1024 by `RequestedBlockRoots`, which is
    /// both lean's cap and beacon's `MAX_REQUEST_BLOCKS`.
    BlocksByRoot(BlocksByRootRequest),
    BlocksByRange(BlocksByRangeRequest),
    Status(BeaconStatus),
    Ping(Ping),
    /// The negotiated `metadata/N` protocol id.
    ///
    /// The request is empty on the wire, but the responder has to answer in the
    /// version the peer asked for, and `request_response::Event::Message` does
    /// not carry the protocol id. The codec does, so it records it here.
    MetaData(&'static str),
    Goodbye(Goodbye),
    /// The identifiers asked for. A plain `Vec` here, unlike
    /// [`crate::beacon::messages::DataColumnsByRootIdentifiers`], which is
    /// what carries the wire's SSZ list bound; nothing above the codec needs
    /// to re-check a bound the wire type already enforces on decode and the
    /// codec already enforces on encode.
    DataColumnsByRoot(Vec<DataColumnsByRootIdentifier>),
    DataColumnsByRange(DataColumnsByRangeRequest),
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
                payload: ResponsePayload::Blocks(blocks),
            } => {
                write!(f, "Success(Blocks count={}", blocks.len())?;
                // Reported as first/last rather than a range: a BlocksByRoot
                // response follows the requested root order, so the slots are
                // not necessarily contiguous or ascending. The fork names the
                // chain too, since `ForkName::Lean` is one of its values.
                if let (Some(first), Some(last)) = (blocks.first(), blocks.last()) {
                    write!(
                        f,
                        " first_slot={} last_slot={} fork={}",
                        first.slot(),
                        last.slot(),
                        first.fork_name(),
                    )?;
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
            Self::Success {
                payload: ResponsePayload::DataColumnSidecars(sidecars),
            } => {
                // Count only, never the sidecars themselves: one sidecar's
                // `Debug` alone runs to tens of kilobytes of cell bytes.
                write!(f, "Success(DataColumnSidecars count={})", sidecars.len())
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
    /// The blocks answering any of the four block protocols, on either chain.
    ///
    /// One variant for all of them. `SignedBeaconBlock` already carries a
    /// `Lean` variant, so it spans both chains without a wrapper, and the two
    /// stores hand blocks back in exactly this type. Which protocol produced
    /// the answer is known from the outbound request id, and which chain from
    /// `P2PServer::wire`, so neither needs a variant of its own.
    ///
    /// Encoding still differs and still belongs to each chain's module: lean
    /// writes a bare chunk per block, beacon prefixes each with a fork digest.
    Blocks(Vec<SignedBeaconBlock>),
    Status(BeaconStatus),
    Pong(Ping),
    MetaData(BeaconMetaData),
    /// The sidecars answering either column protocol.
    ///
    /// One variant for both, mirroring how `Blocks` covers all four block
    /// protocols: which one produced the answer is known from the outbound
    /// request id, and the chunk framing is the same either way.
    DataColumnSidecars(Vec<DataColumnSidecar>),
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
