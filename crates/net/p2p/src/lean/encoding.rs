//! How this chain's request/response bodies go on and off the wire.
//!
//! The counterpart of [`crate::beacon::encoding`]. Everything above these two
//! modules is shared: one `Request`, one `ResponsePayload`, one dispatch, one
//! set of handlers. Encoding is where the chains genuinely differ, so it is
//! where the split lives.
//!
//! Beacon's half is all version dispatch, because three of its protocols carry
//! a different container per negotiated version. This half has no versions at
//! all; what it has instead is the **multi-chunk** block response, which no
//! beacon protocol this node registers uses.

use std::io;

use ethlambda_types::block::SignedBlock;
use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite};
use libssz::{SszDecode, SszEncode};
use tracing::{debug, warn};

use super::messages::{BlocksByRangeRequest, BlocksByRootRequest, Status};
use super::protocols;
use crate::metrics;
use crate::req_resp::codec::write_success_chunk;
use crate::req_resp::encoding::{MAX_PAYLOAD_SIZE, decode_payload, invalid};
use crate::req_resp::messages::{ErrorMessage, Request, Response, ResponseCode, ResponsePayload};

/// Decode a request body on one of this chain's protocols.
///
/// `None` when `protocol` is not one of them, which is how the codec asks both
/// chains in turn without either knowing about the other.
pub fn decode_request(protocol: &str, payload: &[u8]) -> Option<io::Result<Request>> {
    let request = match protocol {
        protocols::STATUS_V1 => Status::from_ssz_bytes(payload).map(Request::LeanStatus),
        protocols::BLOCKS_BY_ROOT_V1 => {
            BlocksByRootRequest::from_ssz_bytes(payload).map(Request::LeanBlocksByRoot)
        }
        protocols::BLOCKS_BY_RANGE_V1 => {
            BlocksByRangeRequest::from_ssz_bytes(payload).map(Request::LeanBlocksByRange)
        }
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

/// Encode a `blocks_by_range/1` body.
pub fn encode_blocks_by_range(request: &BlocksByRangeRequest) -> Vec<u8> {
    request.to_ssz()
}

/// Decode the body of a single-chunk `status/1` response.
pub fn decode_status_response(payload: &[u8]) -> io::Result<ResponsePayload> {
    Status::from_ssz_bytes(payload)
        .map(ResponsePayload::LeanStatus)
        .map_err(|err| invalid(format!("{err:?}")))
}

/// Read a block response, which is one chunk per block rather than one chunk.
///
/// Reads until EOF, collecting the blocks that decoded. Each chunk carries its
/// own response code; a chunk with an error code is logged and skipped rather
/// than ending the stream, so a peer that holds some of what was asked for can
/// answer with that much. The stream ends at EOF, when the peer closes after
/// sending everything it has.
///
/// Always `Ok(Response::Success)`, possibly with an empty vector: either no
/// chunk arrived, or none of them carried SUCCESS. It is `Err` only on an I/O
/// error other than `UnexpectedEof`, or on a chunk that is not a `SignedBlock`.
pub async fn decode_blocks_response<T>(io: &mut T, protocol_label: &str) -> io::Result<Response>
where
    T: AsyncRead + Unpin + Send,
{
    let mut blocks = Vec::new();

    loop {
        let mut result_byte = 0_u8;
        if let Err(err) = io.read_exact(std::slice::from_mut(&mut result_byte)).await {
            if err.kind() == io::ErrorKind::UnexpectedEof {
                break;
            }
            return Err(err);
        }

        let code = ResponseCode::from(result_byte);
        let decoded = decode_payload(io).await?;
        let payload = decoded.uncompressed;
        metrics::observe_reqresp_response_chunk_size(
            protocol_label,
            payload.len(),
            decoded.compressed_size,
        );

        if code != ResponseCode::SUCCESS {
            let error_message = ErrorMessage::from_ssz_bytes(&payload)
                .map(|msg| String::from_utf8_lossy(&msg).into_owned())
                .unwrap_or_else(|_| "<invalid error message>".to_string());
            debug!(?code, %error_message, "Skipping block chunk with non-success code");
            continue;
        }

        let block =
            SignedBlock::from_ssz_bytes(&payload).map_err(|err| invalid(format!("{err:?}")))?;
        blocks.push(block);
    }

    Ok(Response::success(ResponsePayload::LeanBlocks(blocks)))
}

/// Write a block response: one result code and one payload per block.
///
/// Each block is encoded before its code byte goes out, so an oversized block
/// is skipped rather than leaving a SUCCESS byte on the wire with no payload
/// behind it. An empty response is a stream that just ends.
pub async fn write_blocks_response<T>(
    io: &mut T,
    label: &'static str,
    blocks: &[SignedBlock],
) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
{
    for block in blocks {
        let encoded = block.to_ssz();
        if encoded.len() > MAX_PAYLOAD_SIZE - 1024 {
            warn!(
                size = encoded.len(),
                "Skipping oversized block in block response"
            );
            continue;
        }
        write_success_chunk(io, label, encoded).await?;
    }
    Ok(())
}
