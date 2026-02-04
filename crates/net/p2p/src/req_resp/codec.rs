use std::io;

use ethlambda_types::primitives::ssz::{Decode, Encode};
use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, trace};

use super::{
    encoding::{decode_payload, write_payload},
    messages::{
        BLOCKS_BY_ROOT_PROTOCOL_V1, BlocksByRootRequest, ErrorMessage, Request, Response,
        ResponseCode, ResponsePayload, STATUS_PROTOCOL_V1, Status,
    },
};

use ethlambda_types::block::SignedBlockWithAttestation;

#[derive(Debug, Clone, Default)]
pub struct Codec;

#[async_trait::async_trait]
impl libp2p::request_response::Codec for Codec {
    type Protocol = libp2p::StreamProtocol;
    type Request = Request;
    type Response = Response;

    async fn read_request<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let payload = decode_payload(io).await?;

        match protocol.as_ref() {
            STATUS_PROTOCOL_V1 => {
                let status = Status::from_ssz_bytes(&payload).map_err(|err| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("{err:?}"))
                })?;
                Ok(Request::Status(status))
            }
            BLOCKS_BY_ROOT_PROTOCOL_V1 => {
                let request =
                    BlocksByRootRequest::from_ssz_bytes_compat(&payload).map_err(|err| {
                        io::Error::new(io::ErrorKind::InvalidData, format!("{err:?}"))
                    })?;
                Ok(Request::BlocksByRoot(request))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown protocol: {}", protocol.as_ref()),
            )),
        }
    }

    async fn read_response<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        match protocol.as_ref() {
            STATUS_PROTOCOL_V1 => decode_status_response(io).await,
            BLOCKS_BY_ROOT_PROTOCOL_V1 => decode_blocks_by_root_response(io).await,
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown protocol: {}", protocol.as_ref()),
            )),
        }
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        trace!(?req, "Writing request");

        let encoded = match req {
            Request::Status(status) => status.as_ssz_bytes(),
            Request::BlocksByRoot(request) => request.as_ssz_bytes(),
        };

        write_payload(io, &encoded).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        resp: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        match resp {
            Response::Success { payload } => {
                match &payload {
                    ResponsePayload::Status(status) => {
                        // Send success code (0)
                        io.write_all(&[ResponseCode::SUCCESS.into()]).await?;
                        let encoded = status.as_ssz_bytes();
                        write_payload(io, &encoded).await
                    }
                    ResponsePayload::BlocksByRoot(blocks) => {
                        // Write each block as separate chunk
                        for block in blocks {
                            io.write_all(&[ResponseCode::SUCCESS.into()]).await?;
                            let encoded = block.as_ssz_bytes();
                            write_payload(io, &encoded).await?;
                        }
                        // Empty response if no blocks found (stream just ends)
                        Ok(())
                    }
                }
            }
            Response::Error { code, message } => {
                // Send error code
                io.write_all(&[code.into()]).await?;

                // Error messages are SSZ-encoded as List[byte, 256]
                let encoded = message.as_ssz_bytes();

                write_payload(io, &encoded).await
            }
        }
    }
}

/// Decodes a Status protocol response from a single-chunk response stream.
///
/// Reads the response code byte and payload, returning either a success response
/// with the peer's Status or an error response with the error code and message.
/// Unlike multi-chunk protocols, any error code from the peer is treated as a
/// valid response rather than a connection failure.
///
/// # Returns
///
/// Returns `Ok(Response::Success)` containing the peer's `Status` if the response
/// code is `SUCCESS`.
///
/// Returns `Ok(Response::Error)` containing the error code and message if the peer
/// returned a non-success response code.
///
/// # Errors
///
/// Returns `Err` if:
/// - I/O error occurs while reading the response code or payload
/// - Peer's error message cannot be SSZ-decoded (InvalidData)
/// - Peer's Status payload cannot be SSZ-decoded (InvalidData)
async fn decode_status_response<T>(io: &mut T) -> io::Result<Response>
where
    T: AsyncRead + Unpin + Send,
{
    let mut result_byte = 0_u8;
    io.read_exact(std::slice::from_mut(&mut result_byte))
        .await?;

    let code = ResponseCode::from(result_byte);
    let payload = decode_payload(io).await?;

    if code != ResponseCode::SUCCESS {
        let message = ErrorMessage::from_ssz_bytes(&payload).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid error message: {err:?}"),
            )
        })?;
        let error_str = String::from_utf8_lossy(&message).to_string();
        trace!(?code, %error_str, "Received error response");
        return Ok(Response::error(code, message));
    }

    let status = Status::from_ssz_bytes(&payload)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, format!("{err:?}")))?;
    Ok(Response::success(ResponsePayload::Status(status)))
}

/// Decodes a BlocksByRoot protocol response from a multi-chunk response stream.
///
/// Reads chunks until EOF, collecting successfully decoded blocks. Each chunk has
/// its own response code - chunks with error codes are logged and skipped rather
/// than terminating the stream. This allows partial success when some requested
/// blocks are unavailable. The stream ends naturally at EOF (peer closes after
/// sending all available blocks).
///
/// # Returns
///
/// Always returns `Ok(Response::Success)` containing a vector of successfully
/// decoded blocks. The vector may be empty if no SUCCESS chunks were received
/// before EOF (either no chunks sent, or all chunks had non-SUCCESS codes)
///
/// # Errors
///
/// Returns `Err` if:
/// - I/O error occurs while reading response codes or payloads (except `UnexpectedEof`
///   which signals normal stream termination)
/// - Block payload cannot be SSZ-decoded into `SignedBlockWithAttestation` (InvalidData)
///
/// Note: Error chunks from the peer (non-SUCCESS response codes) do not cause this
/// function to return `Err` - they are logged and skipped.
async fn decode_blocks_by_root_response<T>(io: &mut T) -> io::Result<Response>
where
    T: AsyncRead + Unpin + Send,
{
    let mut blocks = Vec::new();

    loop {
        // Read chunk result code
        let mut result_byte = 0_u8;
        if let Err(e) = io.read_exact(std::slice::from_mut(&mut result_byte)).await {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                break;
            }
            return Err(e);
        }

        let code = ResponseCode::from(result_byte);
        let payload = decode_payload(io).await?;

        if code != ResponseCode::SUCCESS {
            let error_message = ErrorMessage::from_ssz_bytes(&payload)
                .map(|msg| String::from_utf8_lossy(&msg).to_string())
                .unwrap_or_else(|_| "<invalid error message>".to_string());
            debug!(?code, %error_message, "Skipping block chunk with non-success code");
            continue;
        }

        let block = SignedBlockWithAttestation::from_ssz_bytes(&payload)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, format!("{err:?}")))?;
        blocks.push(block);
    }

    Ok(Response::success(ResponsePayload::BlocksByRoot(blocks)))
}
