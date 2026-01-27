use std::io;

use ethlambda_types::state::Checkpoint;
use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use snap::read::FrameEncoder;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use tracing::trace;

use crate::messages::{
    blocks_by_root::{BLOCKS_BY_ROOT_PROTOCOL_V1, BlocksByRootRequest, BlocksByRootResponse},
    decode_payload, encode_varint,
    status::STATUS_PROTOCOL_V1,
};

#[derive(Debug, Clone)]
pub enum Request {
    Status(Status),
    BlocksByRoot(BlocksByRootRequest),
}

#[derive(Debug, Clone)]
pub enum Response {
    Status(Status),
    BlocksByRoot(BlocksByRootResponse),
}

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
                let request = BlocksByRootRequest::from_ssz_bytes(&payload).map_err(|err| {
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

        // TODO: send errors to event loop?
        if result != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "non-zero result in response",
            ));
        }

        let payload = decode_payload(io).await?;

        match protocol.as_ref() {
            STATUS_PROTOCOL_V1 => {
                let status = Status::from_ssz_bytes(&payload).map_err(|err| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("{err:?}"))
                })?;
                Ok(Response::Status(status))
            }
            BLOCKS_BY_ROOT_PROTOCOL_V1 => {
                let response = BlocksByRootResponse::from_ssz_bytes(&payload).map_err(|err| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("{err:?}"))
                })?;
                Ok(Response::BlocksByRoot(response))
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
        io.write_all(&[0]).await?;

        let encoded = match resp {
            Response::Status(status) => status.as_ssz_bytes(),
            Response::BlocksByRoot(response) => response.as_ssz_bytes(),
        };

        write_payload(io, &encoded).await
    }
}

async fn write_payload<T>(io: &mut T, encoded: &[u8]) -> io::Result<()>
where
    T: AsyncWrite + Unpin,
{
    let mut compressor = FrameEncoder::new(encoded);

    let mut buf = Vec::new();
    io::Read::read_to_end(&mut compressor, &mut buf)?;

    let mut size_buf = [0; 5];
    let varint_buf = encode_varint(buf.len() as u32, &mut size_buf);
    io.write_all(varint_buf).await?;
    io.write_all(&buf).await?;

    Ok(())
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct Status {
    pub finalized: Checkpoint,
    pub head: Checkpoint,
}
