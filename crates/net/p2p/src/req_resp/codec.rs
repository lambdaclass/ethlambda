use std::io;

use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libssz::{SszDecode, SszEncode};
use tracing::{debug, trace, warn};

use super::{
    encoding::{MAX_PAYLOAD_SIZE, decode_payload, write_payload},
    messages::{
        BLOCKS_BY_ROOT_PROTOCOL_V1, ErrorMessage, Request, Response, ResponseCode, ResponsePayload,
        STATUS_PROTOCOL_V1, Status,
    },
};

use ethlambda_types::block::SignedBlock;

#[derive(Debug, Clone, Default)]
pub struct Codec;

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
                let request = SszDecode::from_ssz_bytes(&payload).map_err(|err| {
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
            Request::Status(status) => status.to_ssz(),
            Request::BlocksByRoot(request) => request.to_ssz(),
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
                        let encoded = status.to_ssz();
                        write_payload(io, &encoded).await
                    }
                    ResponsePayload::BlocksByRoot(blocks) => {
                        // Write each block as a separate chunk.
                        // Encode first, then check size before writing the SUCCESS
                        // code byte. This avoids corrupting the stream if a block
                        // exceeds MAX_PAYLOAD_SIZE (the SUCCESS byte would already
                        // be on the wire with no payload following).
                        for block in blocks {
                            let encoded = block.to_ssz();
                            if encoded.len() > MAX_PAYLOAD_SIZE - 1024 {
                                warn!(
                                    size = encoded.len(),
                                    "Skipping oversized block in BlocksByRoot response"
                                );
                                continue;
                            }
                            io.write_all(&[ResponseCode::SUCCESS.into()]).await?;
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
                let encoded = message.to_ssz();

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
        let error_str = String::from_utf8_lossy(&message).into_owned();
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
/// - Block payload cannot be SSZ-decoded into `SignedBlock` (InvalidData)
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
                .map(|msg| String::from_utf8_lossy(&msg).into_owned())
                .unwrap_or_else(|_| "<invalid error message>".to_string());
            debug!(?code, %error_message, "Skipping block chunk with non-success code");
            continue;
        }

        let block = SignedBlock::from_ssz_bytes(&payload)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, format!("{err:?}")))?;
        blocks.push(block);
    }

    Ok(Response::success(ResponsePayload::BlocksByRoot(blocks)))
}
