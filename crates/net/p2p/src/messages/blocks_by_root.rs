use std::io;

use ethlambda_types::{block::SignedBlockWithAttestation, primitives::H256};
use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use snap::read::FrameEncoder;
use ssz::{Decode, Encode};
use ssz_types::typenum;
use tracing::trace;

use crate::messages::{decode_payload, encode_varint};

pub const BLOCKS_BY_ROOT_PROTOCOL_V1: &str = "/leanconsensus/req/blocks_by_root/1/ssz_snappy";

#[allow(dead_code)]
const MAX_REQUEST_BLOCKS: usize = 1024;
type MaxRequestBlocks = typenum::U1024;

pub type BlocksByRootRequest = ssz_types::VariableList<H256, MaxRequestBlocks>;
pub type BlocksByRootResponse =
    ssz_types::VariableList<SignedBlockWithAttestation, MaxRequestBlocks>;

#[derive(Debug, Clone, Default)]
pub struct BlocksByRootCodec;

#[async_trait::async_trait]
impl libp2p::request_response::Codec for BlocksByRootCodec {
    type Protocol = libp2p::StreamProtocol;
    type Request = BlocksByRootRequest;
    type Response = BlocksByRootResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let payload = decode_payload(io).await?;
        let request = BlocksByRootRequest::from_ssz_bytes(&payload)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, format!("{err:?}")))?;
        Ok(request)
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
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
        let response = BlocksByRootResponse::from_ssz_bytes(&payload)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, format!("{err:?}")))?;
        Ok(response)
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
        trace!(?req, "Writing BlocksByRoot request");

        let encoded = req.as_ssz_bytes();
        let mut compressor = FrameEncoder::new(&encoded[..]);

        let mut buf = Vec::new();
        io::Read::read_to_end(&mut compressor, &mut buf)?;

        let mut size_buf = [0; 5];
        let varint_buf = encode_varint(buf.len() as u32, &mut size_buf);
        io.write_all(varint_buf).await?;
        io.write_all(&buf).await?;

        Ok(())
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

        let encoded = resp.as_ssz_bytes();
        let mut compressor = FrameEncoder::new(&encoded[..]);

        let mut buf = Vec::new();
        io::Read::read_to_end(&mut compressor, &mut buf)?;

        let mut size_buf = [0; 5];
        let varint_buf = encode_varint(buf.len() as u32, &mut size_buf);
        io.write_all(varint_buf).await?;
        io.write_all(&buf).await?;

        Ok(())
    }
}
