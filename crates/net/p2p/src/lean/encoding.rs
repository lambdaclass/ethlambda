//! How this chain's request/response bodies go on and off the wire.
//!
//! The counterpart of [`crate::beacon::encoding`]. Everything above these two
//! modules is shared: one `Request`, one `ResponsePayload`, one dispatch, one
//! set of handlers. Encoding is where the chains genuinely differ, so it is
//! where the split lives.
//!
//! Beacon's half is all version dispatch, because three of its protocols carry
//! a different container per negotiated version. This half has no versions at
//! all, and no `<context-bytes>` on any chunk: every container here has had one
//! shape for the chain's whole life, so there is nothing for a chunk to say
//! about which one it is.

use std::io;

use ethlambda_types::beacon::containers::SignedBeaconBlock;
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::block::SignedBlock;
use libp2p::futures::{AsyncRead, AsyncWrite};
use libssz::{SszDecode, SszEncode};
use tracing::{error, warn};

use super::messages::{BlocksByRootRequest, LeanBlocksByRangeRequest, Status};
use super::protocols;
use crate::req_resp::codec::write_success_chunk;
use crate::req_resp::encoding::{ChunkLimits, MAX_PAYLOAD_SIZE, invalid, read_chunked_response};
use crate::req_resp::messages::BlocksByRangeRequest;
use crate::req_resp::messages::{Request, Response, ResponsePayload};

/// This chain's chunks carry no context bytes. Named rather than written as a
/// bare `0`/`&[]` at each call site, so the reason travels with the value.
const NO_CONTEXT: &[u8] = &[];

/// Decode a request body on one of this chain's protocols.
///
/// `None` when `protocol` is not one of them, which is how the codec asks both
/// chains in turn without either knowing about the other.
pub fn decode_request(protocol: &str, payload: &[u8]) -> Option<io::Result<Request>> {
    let request = match protocol {
        protocols::STATUS_V1 => Status::from_ssz_bytes(payload).map(Request::LeanStatus),
        protocols::BLOCKS_BY_ROOT_V1 => {
            BlocksByRootRequest::from_ssz_bytes(payload).map(Request::BlocksByRoot)
        }
        protocols::BLOCKS_BY_RANGE_V1 => LeanBlocksByRangeRequest::from_ssz_bytes(payload)
            .map(|wire| Request::BlocksByRange(wire.into())),
        _ => return None,
    };
    Some(request.map_err(|err| invalid(format!("{err:?}"))))
}

/// Encode a `status/1` body.
pub fn encode_status(status: &Status) -> Vec<u8> {
    status.to_ssz()
}

/// Encode a `blocks_by_root/1` body.
pub fn encode_blocks_by_root(request: &BlocksByRootRequest) -> Vec<u8> {
    request.to_ssz()
}

/// Encode a `blocks_by_range/1` body, which is the shared request minus the
/// `step` this chain's wire has no field for.
pub fn encode_blocks_by_range(request: &BlocksByRangeRequest) -> Vec<u8> {
    LeanBlocksByRangeRequest::from(request).to_ssz()
}

/// This chain's wire body for a slot window: the shared request without `step`.
impl From<&BlocksByRangeRequest> for LeanBlocksByRangeRequest {
    fn from(request: &BlocksByRangeRequest) -> Self {
        Self {
            start_slot: request.start_slot,
            count: request.count,
        }
    }
}

/// The shared request a wire body describes.
///
/// `step` becomes 1, which is what this chain not having the field means. It is
/// never anything else, so the lean handler has nothing to check.
impl From<LeanBlocksByRangeRequest> for BlocksByRangeRequest {
    fn from(wire: LeanBlocksByRangeRequest) -> Self {
        Self::new(wire.start_slot, wire.count)
    }
}

/// Decode the body of a single-chunk `status/1` response.
pub fn decode_status_response(payload: &[u8]) -> io::Result<ResponsePayload> {
    Status::from_ssz_bytes(payload)
        .map(ResponsePayload::LeanStatus)
        .map_err(|err| invalid(format!("{err:?}")))
}

/// Read a block response, which is one chunk per block rather than one chunk.
///
/// The loop, the per-chunk metrics and the skip-on-error-code rule are
/// [`read_chunked_response`]'s, shared with beacon's block response; what is
/// this chain's own is that a chunk has no context bytes to read and decodes as
/// exactly one container.
///
/// Always `Ok(Response::Success)`, possibly with an empty vector: either no
/// chunk arrived, or none of them carried SUCCESS. It is `Err` only on an I/O
/// error other than `UnexpectedEof`, or on a chunk that is not a `SignedBlock`.
pub async fn decode_blocks_response<T>(io: &mut T, protocol_label: &str) -> io::Result<Response>
where
    T: AsyncRead + Unpin + Send,
{
    let limits = ChunkLimits {
        has_context: false,
        // The widest answer either of this chain's block protocols can be asked
        // for: `blocks_by_range` is refused above it, and `blocks_by_root`
        // cannot name more roots than the request list holds.
        max_chunks: protocols::MAX_REQUEST_BLOCKS as usize,
    };
    let blocks = read_chunked_response(io, protocol_label, limits, |_, payload| {
        SignedBlock::from_ssz_bytes(payload)
            .map(SignedBeaconBlock::Lean)
            .map_err(|err| invalid(format!("{err:?}")))
    })
    .await?;

    Ok(Response::success(ResponsePayload::Blocks(blocks)))
}

/// Write a block response: one result code and one payload per block.
///
/// Each block is encoded before its code byte goes out, so an oversized block
/// is skipped rather than leaving a SUCCESS byte on the wire with no payload
/// behind it. An empty response is a stream that just ends.
pub async fn write_blocks_response<T>(
    io: &mut T,
    label: &'static str,
    blocks: &[SignedBeaconBlock],
) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
{
    for block in blocks {
        // `SignedBeaconBlock` spans both chains, so this is the one place a
        // beacon-shaped block could be written onto a lean stream. It would
        // encode without complaint and decode as garbage at the peer, so it is
        // refused here rather than trusted to be impossible: a lean directory
        // holding one would mean the store's chain tag lied.
        if block.fork_name() != ForkName::Lean {
            error!(
                slot = block.slot(),
                fork = %block.fork_name(),
                "Refusing to write a non-lean block to a lean block response"
            );
            continue;
        }
        let encoded = block.to_ssz();
        if encoded.len() > MAX_PAYLOAD_SIZE - 1024 {
            warn!(
                size = encoded.len(),
                "Skipping oversized block in block response"
            );
            continue;
        }
        write_success_chunk(io, label, NO_CONTEXT, encoded).await?;
    }
    Ok(())
}
