use std::io;

use ethlambda_types::state::Checkpoint;
use ethrex_common::{H256, U256};
use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite};

pub const STATUS_PROTOCOL_V1: &str = "/leanconsensus/req/status/1/ssz_snappy";

#[derive(Debug, Clone, Default)]
pub struct StatusCodec;

#[async_trait::async_trait]
impl libp2p::request_response::Codec for StatusCodec {
    type Protocol = libp2p::StreamProtocol;
    type Request = Status;
    type Response = Status;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let payload = decode_payload(io).await?;
        let status = deserialize_payload(payload)?;
        Ok(status)
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let payload = decode_payload(io).await?;
        let status = deserialize_payload(payload)?;
        Ok(status)
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
        todo!();

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
        todo!();

        Ok(())
    }
}

async fn decode_payload<T>(io: &mut T) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let mut varint_buf = [0; std::mem::size_of::<usize>()];

    io.take(varint_buf.len() as u64)
        .read(&mut varint_buf)
        .await?;
    let (size, rest) = decode_varint(&varint_buf);

    let mut message = vec![0; size as usize];
    if rest.is_empty() {
        io.read_exact(&mut message).await?;
    } else {
        message[..rest.len()].copy_from_slice(rest);
        io.read_exact(&mut message[rest.len()..]).await?;
    }

    let mut decoder = snap::read::FrameDecoder::new(&message[..]);
    let mut uncompressed = Vec::new();
    io::Read::read_to_end(&mut decoder, &mut uncompressed)?;

    Ok(uncompressed)
}

fn deserialize_payload(payload: Vec<u8>) -> io::Result<Status> {
    if payload.len() != 80 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid status message length",
        ));
    }

    let finalized_root = H256(
        payload[..32]
            .try_into()
            .expect("slice with incorrect length"),
    );
    let finalized_slot = u64::from_be_bytes(
        payload[32..40]
            .try_into()
            .expect("slice with incorrect length"),
    );

    let head_root = H256(
        payload[40..72]
            .try_into()
            .expect("slice with incorrect length"),
    );
    let head_slot = u64::from_be_bytes(
        payload[72..]
            .try_into()
            .expect("slice with incorrect length"),
    );

    let status = Status {
        finalized: Checkpoint {
            root: finalized_root,
            slot: U256::from(finalized_slot),
        },
        head: Checkpoint {
            root: head_root,
            slot: U256::from(head_slot),
        },
    };
    Ok(status)
}

fn decode_varint(buf: &[u8]) -> (u32, &[u8]) {
    let mut result = 0_u32;
    let mut read_size = 0;

    for (i, byte) in buf.iter().enumerate() {
        let value = (byte & 0x7F) as u32;
        result |= value << (7 * i);
        if byte & 0x80 == 0 {
            read_size = i + 1;
            break;
        }
    }
    (result, &buf[read_size..])
}

#[derive(Debug, Clone)]
pub struct Status {
    pub finalized: Checkpoint,
    pub head: Checkpoint,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_varint() {
        // Example from https://protobuf.dev/programming-guides/encoding/
        let buf = [0b10010110, 0b00000001];
        let (value, rest) = decode_varint(&buf);
        assert_eq!(value, 150);

        let expected: &[u8] = &[];
        assert_eq!(rest, expected);
    }
}
