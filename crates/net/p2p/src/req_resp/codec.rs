use std::io;

use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use ssz::{Decode, Encode};
use tracing::trace;

use super::{
    encoding::{decode_payload, write_payload},
    messages::{
        BLOCKS_BY_ROOT_PROTOCOL_V1, BlocksByRootRequest, Request, Response, STATUS_PROTOCOL_V1,
        Status,
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
        let mut result = 0_u8;
        io.read_exact(std::slice::from_mut(&mut result)).await?;

        // TODO: move matching to ResponseResult impl
        let result_code = match result {
            0 => super::messages::ResponseResult::Success,
            1 => super::messages::ResponseResult::InvalidRequest,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid result code: {}", result),
                ));
            }
        };

        // TODO: send errors to event loop when result != Success?
        if result_code != super::messages::ResponseResult::Success {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "non-success result in response",
            ));
        }

        let payload = decode_payload(io).await?;

        match protocol.as_ref() {
            STATUS_PROTOCOL_V1 => {
                let status = Status::from_ssz_bytes(&payload).map_err(|err| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("{err:?}"))
                })?;
                Ok(Response::new(
                    result_code,
                    super::messages::ResponsePayload::Status(status),
                ))
            }
            BLOCKS_BY_ROOT_PROTOCOL_V1 => {
                let block =
                    SignedBlockWithAttestation::from_ssz_bytes(&payload).map_err(|err| {
                        io::Error::new(io::ErrorKind::InvalidData, format!("{err:?}"))
                    })?;
                Ok(Response::new(
                    result_code,
                    super::messages::ResponsePayload::BlocksByRoot(block),
                ))
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
        // Send result byte
        io.write_all(&[resp.result as u8]).await?;

        let encoded = match &resp.payload {
            super::messages::ResponsePayload::Status(status) => status.as_ssz_bytes(),
            super::messages::ResponsePayload::BlocksByRoot(response) => response.as_ssz_bytes(),
        };

        write_payload(io, &encoded).await
    }
}
