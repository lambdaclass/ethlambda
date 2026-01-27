use std::io;

use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use snap::read::FrameEncoder;

pub const MAX_PAYLOAD_SIZE: usize = 10 * 1024 * 1024; // 10 MB

// https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/p2p-interface.md#max_message_size
pub const MAX_COMPRESSED_PAYLOAD_SIZE: usize = 32 + MAX_PAYLOAD_SIZE + MAX_PAYLOAD_SIZE / 6 + 1024; // ~12 MB

/// Decode a varint-prefixed, snappy-compressed SSZ payload from an async reader.
pub async fn decode_payload<T>(io: &mut T) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let mut buf = vec![];
    let read = io
        .take(MAX_COMPRESSED_PAYLOAD_SIZE as u64)
        .read_to_end(&mut buf)
        .await?;

    if read < 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message too short",
        ));
    }
    let (size, rest) = decode_varint(&buf)?;

    if size as usize > MAX_PAYLOAD_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message size exceeds maximum allowed",
        ));
    }

    let mut decoder = snap::read::FrameDecoder::new(rest);
    let mut uncompressed = Vec::new();
    io::Read::read_to_end(&mut decoder, &mut uncompressed)?;
    if uncompressed.len() != size as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "uncompressed size does not match received size",
        ));
    }

    Ok(uncompressed)
}

pub async fn write_payload<T>(io: &mut T, encoded: &[u8]) -> io::Result<()>
where
    T: AsyncWrite + Unpin,
{
    let uncompressed_size = encoded.len();
    let mut compressor = FrameEncoder::new(encoded);

    let mut buf = Vec::new();
    io::Read::read_to_end(&mut compressor, &mut buf)?;

    let mut size_buf = [0; 5];
    let varint_buf = encode_varint(uncompressed_size as u32, &mut size_buf);
    io.write_all(varint_buf).await?;
    io.write_all(&buf).await?;

    Ok(())
}

/// Encodes a u32 as a varint into the provided buffer, returning a slice of the buffer
/// containing the encoded bytes.
pub fn encode_varint(mut value: u32, dst: &mut [u8; 5]) -> &[u8] {
    for i in 0..5 {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        dst[i] = byte;
        if value == 0 {
            return &dst[..=i];
        }
    }
    &dst[..]
}

/// Decode a varint from a byte buffer, returning the value and remaining bytes.
pub fn decode_varint(buf: &[u8]) -> io::Result<(u32, &[u8])> {
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
    if read_size == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message size is bigger than 28 bits",
        ));
    }
    Ok((result, &buf[read_size..]))
}

#[cfg(test)]
mod tests {
    use super::decode_varint;

    #[test]
    fn test_decode_varint() {
        // Example from https://protobuf.dev/programming-guides/encoding/
        let buf = [0b10010110, 0b00000001];
        let (value, rest) = decode_varint(&buf).unwrap();
        assert_eq!(value, 150);

        let expected: &[u8] = &[];
        assert_eq!(rest, expected);
    }
}
