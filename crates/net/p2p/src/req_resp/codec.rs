use std::io;

use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use ssz::{Decode, Encode};
use tracing::trace;

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
        let mut result_byte = 0_u8;
        io.read_exact(std::slice::from_mut(&mut result_byte))
            .await?;

        let code = ResponseCode::from(result_byte);

        let payload = decode_payload(io).await?;

        // For non-success responses, the payload contains an SSZ-encoded error message
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

        // Success responses contain the actual data
        match protocol.as_ref() {
            STATUS_PROTOCOL_V1 => {
                let status = Status::from_ssz_bytes(&payload).map_err(|err| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("{err:?}"))
                })?;
                Ok(Response::success(ResponsePayload::Status(status)))
            }
            BLOCKS_BY_ROOT_PROTOCOL_V1 => {
                let mut blocks = Vec::new();

                // First chunk already read (result_byte, payload from above)
                if code == ResponseCode::SUCCESS {
                    let block =
                        SignedBlockWithAttestation::from_ssz_bytes(&payload).map_err(|err| {
                            io::Error::new(io::ErrorKind::InvalidData, format!("{err:?}"))
                        })?;
                    blocks.push(block);
                }

                // Read remaining chunks until EOF
                loop {
                    let mut result_byte = 0_u8;
                    match io.read_exact(std::slice::from_mut(&mut result_byte)).await {
                        Ok(()) => {}
                        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                        Err(e) => return Err(e),
                    }

                    let chunk_code = ResponseCode::from(result_byte);
                    let chunk_payload = decode_payload(io).await?;

                    if chunk_code == ResponseCode::SUCCESS {
                        let block = SignedBlockWithAttestation::from_ssz_bytes(&chunk_payload)
                            .map_err(|err| {
                                io::Error::new(io::ErrorKind::InvalidData, format!("{err:?}"))
                            })?;
                        blocks.push(block);
                    }
                    // Non-success codes (RESOURCE_UNAVAILABLE) are skipped - block not available
                }

                Ok(Response::success(ResponsePayload::BlocksByRoot(blocks)))
            }
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
