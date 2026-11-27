use std::io;

use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use snap::read::FrameEncoder;
use tracing::debug;

use super::messages::{ErrorMessage, ResponseCode};
use crate::metrics;
use libssz::SszDecode as _;

pub const MAX_PAYLOAD_SIZE: usize = 10 * 1024 * 1024; // 10 MB

/// An `InvalidData` error, which is what every decode failure on this path is.
///
/// Shared with `lean::encoding` and `beacon::encoding`, which produce the same
/// error for the same reason.
pub fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

// https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/p2p-interface.md#max_message_size
pub const MAX_COMPRESSED_PAYLOAD_SIZE: usize = 32 + MAX_PAYLOAD_SIZE + MAX_PAYLOAD_SIZE / 6 + 1024; // ~12 MB

/// Decoded payload together with the size of its on-wire snappy-compressed
/// bytes (excluding the varint length prefix).
///
/// `compressed_size` excludes the varint length prefix and covers only the
/// snappy frame for this payload.
pub struct DecodedPayload {
    pub uncompressed: Vec<u8>,
    pub compressed_size: usize,
}

/// Decode a varint-prefixed, snappy-compressed SSZ payload from an async reader.
pub async fn decode_payload<T>(io: &mut T) -> io::Result<DecodedPayload>
where
    T: AsyncRead + Unpin + Send,
{
    let size = read_varint(io).await?;

    if size as usize > MAX_PAYLOAD_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message size exceeds maximum allowed",
        ));
    }

    if size == 0 {
        return Ok(DecodedPayload {
            uncompressed: Vec::new(),
            compressed_size: 0,
        });
    }

    let (uncompressed, compressed_size) = read_snappy_frame(io, size as usize).await?;

    Ok(DecodedPayload {
        uncompressed,
        compressed_size,
    })
}

async fn read_varint<T>(io: &mut T) -> io::Result<u32>
where
    T: AsyncRead + Unpin + Send,
{
    let mut buf = [0_u8; MAX_VARINT_LEN];

    for i in 0..MAX_VARINT_LEN {
        io.read_exact(&mut buf[i..=i]).await?;

        if buf[i] & 0x80 == 0 {
            return decode_varint(&buf[..=i]).map(|(size, _)| size);
        }
    }

    Err(invalid("message size prefix is longer than 5 bytes"))
}

async fn read_snappy_frame<T>(
    io: &mut T,
    expected_uncompressed_size: usize,
) -> io::Result<(Vec<u8>, usize)>
where
    T: AsyncRead + Unpin + Send,
{
    let mut frame = Vec::new();
    let mut uncompressed_len = 0_usize;

    while uncompressed_len < expected_uncompressed_size {
        let mut header = [0_u8; 4];
        io.read_exact(&mut header).await?;
        let chunk_type = header[0];
        let chunk_len = u32::from_le_bytes([header[1], header[2], header[3], 0]) as usize;

        if frame.len() + header.len() + chunk_len > MAX_COMPRESSED_PAYLOAD_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "compressed message size exceeds maximum allowed",
            ));
        }

        frame.extend_from_slice(&header);

        let data_start = frame.len();
        frame.resize(data_start + chunk_len, 0);
        io.read_exact(&mut frame[data_start..]).await?;
        let data = &frame[data_start..];

        let chunk_uncompressed_len = match chunk_type {
            0x00 => {
                let block = data.get(4..).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "compressed chunk too short")
                })?;
                snap::raw::decompress_len(block)
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?
            }
            0x01 => chunk_len.checked_sub(4).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "uncompressed chunk too short")
            })?,
            0x80..=0xff => 0,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported snappy chunk type",
                ));
            }
        };

        uncompressed_len = uncompressed_len
            .checked_add(chunk_uncompressed_len)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "uncompressed size overflow")
            })?;

        if uncompressed_len > expected_uncompressed_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "uncompressed size does not match received size",
            ));
        }
    }

    let mut decoder = snap::read::FrameDecoder::new(frame.as_slice());
    let mut uncompressed = vec![0; expected_uncompressed_size];
    io::Read::read_exact(&mut decoder, &mut uncompressed)?;

    Ok((uncompressed, frame.len()))
}

/// The width of a `<context-bytes>` field.
///
/// One value rather than a per-protocol number, because `ForkDigest`-context is
/// the only context shape either chain uses: "A fixed-width 4 byte
/// `<context-bytes>`, set to the `ForkDigest` matching the chunk". The spec does
/// leave the field "defined per req-resp method", so a method that ever defines
/// a different one would need more than [`ChunkLimits::has_context`] can say.
pub const FORK_DIGEST_CONTEXT_LEN: usize = 4;

/// What a chunked response is allowed to look like, on the two axes the two
/// chains disagree about.
pub struct ChunkLimits {
    /// Whether a successful chunk carries a [`FORK_DIGEST_CONTEXT_LEN`]-byte
    /// `ForkDigest` before its payload. False on every lean protocol, true on
    /// beacon's block and data-column-sidecar protocols.
    pub has_context: bool,
    /// The most chunks a peer may send before the answer is refused.
    ///
    /// The loop reads until the peer closes, so without this a peer can stream
    /// chunks for as long as the stream lives and every one of them is held in
    /// memory. Set to the widest answer the protocol can legitimately produce,
    /// which is the request ceiling: a peer sending more than was ever askable
    /// for is not answering a request.
    pub max_chunks: usize,
}

/// Read a response that is one chunk per item, until the peer closes.
///
/// Both chains' block responses have this shape, and the framing around them is
/// identical down to which byte comes first, so the loop lives here and each
/// chain supplies only what genuinely differs: its [`ChunkLimits`], and how a
/// chunk body becomes a value.
///
/// `response_chunk ::= <result> | <context-bytes> | <encoding-dependent-header>
/// | <encoded-payload>`. The context bytes are read only after a SUCCESS code,
/// because the spec leaves them empty on an error chunk, and `decode` is handed
/// whatever was read, empty slice included.
///
/// A chunk with a non-success code is logged and skipped rather than ending the
/// stream, so a peer that holds some of what was asked for can answer with that
/// much. The stream ends at EOF. `Err` only on an I/O error other than
/// `UnexpectedEof`, on more than `max_chunks` chunks, or when `decode` refuses
/// one, in which case nothing read so far is returned: a peer that mis-encodes
/// one chunk has not shown itself trustworthy about the others.
pub async fn read_chunked_response<T, V, F>(
    io: &mut T,
    protocol_label: &str,
    limits: ChunkLimits,
    decode: F,
) -> io::Result<Vec<V>>
where
    T: AsyncRead + Unpin + Send,
    F: Fn(&[u8], &[u8]) -> io::Result<V>,
{
    let ChunkLimits {
        has_context,
        max_chunks,
    } = limits;
    let mut items = Vec::new();
    // Counts every chunk, not just the ones that decoded: a stream of error
    // chunks costs the same to read as a stream of blocks.
    let mut chunks = 0_usize;

    loop {
        let mut result_byte = 0_u8;
        if let Err(err) = io.read_exact(std::slice::from_mut(&mut result_byte)).await {
            if err.kind() == io::ErrorKind::UnexpectedEof {
                break;
            }
            return Err(err);
        }
        let code = ResponseCode::from(result_byte);

        chunks += 1;
        if chunks > max_chunks {
            return Err(invalid(format!(
                "{protocol_label} response exceeded {max_chunks} chunks"
            )));
        }

        // Only on the success path: an error chunk carries an `ErrorMessage`
        // straight after the code byte, with the context field left empty. The
        // buffer is on the stack and reused, so a long response does not
        // allocate once per chunk for four bytes.
        let mut context_buf = [0_u8; FORK_DIGEST_CONTEXT_LEN];
        let context: &[u8] = if has_context && code == ResponseCode::SUCCESS {
            io.read_exact(&mut context_buf).await?;
            &context_buf
        } else {
            &[]
        };

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
            debug!(?code, %error_message, "Skipping response chunk with non-success code");
            continue;
        }

        items.push(decode(context, &payload)?);
    }

    Ok(items)
}

/// Write a varint-prefixed, snappy-compressed SSZ payload. Returns the size
/// of the snappy-compressed bytes (excluding the varint length prefix).
pub async fn write_payload<T>(io: &mut T, encoded: &[u8]) -> io::Result<usize>
where
    T: AsyncWrite + Unpin,
{
    let uncompressed_size = encoded.len();
    // Stop ourselves from sending messages our peers won't receive.
    // Leave some leeway for response codes and the varint encoding of the size.
    if uncompressed_size > MAX_PAYLOAD_SIZE - 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message size exceeds maximum allowed",
        ));
    }
    let mut compressor = FrameEncoder::new(encoded);

    let mut buf = Vec::new();
    io::Read::read_to_end(&mut compressor, &mut buf)?;

    let mut size_buf = [0; 5];
    let varint_buf = encode_varint(uncompressed_size as u32, &mut size_buf);
    io.write_all(varint_buf).await?;
    io.write_all(&buf).await?;

    Ok(buf.len())
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

/// The longest varint a `u32` needs: five 7-bit groups.
const MAX_VARINT_LEN: usize = 5;

/// Decode a varint from a byte buffer, returning the value and remaining bytes.
///
/// A varint that does not end within [`MAX_VARINT_LEN`] bytes, or whose value
/// does not fit a `u32`, is refused. Its fifth byte carries bits 28..35, and
/// keeping only the low 32 would read a length the peer never declared: `80 80
/// 80 80 10` is 2^32, which a `u32` accumulator read as 0, under every size
/// limit.
pub fn decode_varint(buf: &[u8]) -> io::Result<(u32, &[u8])> {
    let mut result = 0_u64;

    for (i, byte) in buf.iter().take(MAX_VARINT_LEN).enumerate() {
        result |= u64::from(byte & 0x7F) << (7 * i);
        if byte & 0x80 == 0 {
            let value =
                u32::try_from(result).map_err(|_| invalid("message size does not fit 32 bits"))?;
            return Ok((value, &buf[i + 1..]));
        }
    }

    Err(invalid(
        "message size prefix is unterminated or longer than 5 bytes",
    ))
}

#[cfg(test)]
mod tests {
    use super::{decode_payload, decode_varint, write_payload};
    use futures::{executor::block_on, io::Cursor};

    #[test]
    fn test_decode_varint() {
        // Example from https://protobuf.dev/programming-guides/encoding/
        let buf = [0b10010110, 0b00000001];
        let (value, rest) = decode_varint(&buf).unwrap();
        assert_eq!(value, 150);

        let expected: &[u8] = &[];
        assert_eq!(rest, expected);
    }

    /// The fifth byte of a length prefix carries bits 28..35, and the three
    /// above bit 31 were shifted out of a `u32` accumulator. `80 80 80 80 10`
    /// declares 2^32 bytes, far over `MAX_PAYLOAD_SIZE`, and was read as a
    /// length of zero, so the size check passed and the stream was answered as
    /// an empty payload.
    #[test]
    fn a_length_prefix_wider_than_u32_is_refused() {
        let wire = [0x80, 0x80, 0x80, 0x80, 0x10];
        assert!(decode_varint(&wire).is_err());

        let decoded = block_on(decode_payload(&mut Cursor::new(wire.to_vec())));
        assert!(
            decoded.is_err(),
            "a prefix declaring 2^32 bytes was accepted as {} bytes",
            decoded.unwrap().uncompressed.len()
        );
    }

    #[test]
    fn the_widest_length_prefix_that_fits_u32_is_read() {
        let (value, rest) = decode_varint(&[0xff, 0xff, 0xff, 0xff, 0x0f, 0xaa]).unwrap();
        assert_eq!(value, u32::MAX);
        assert_eq!(rest, &[0xaa]);
    }

    #[test]
    fn a_length_prefix_longer_than_five_bytes_is_refused() {
        // Non-minimal, and its value (zero) fits, but no `u32` needs six bytes.
        assert!(decode_varint(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x00]).is_err());
        // Unterminated.
        assert!(decode_varint(&[0x80, 0x80]).is_err());
    }

    #[tokio::test]
    async fn decode_payload_leaves_following_payload_in_stream() {
        let first = b"first payload";
        let second = b"second payload";

        let mut stream = Cursor::new(Vec::new());
        let first_compressed_size = write_payload(&mut stream, first).await.unwrap();
        let second_compressed_size = write_payload(&mut stream, second).await.unwrap();

        let mut stream = Cursor::new(stream.into_inner());

        let decoded = decode_payload(&mut stream).await.unwrap();
        assert_eq!(decoded.uncompressed, first);
        assert_eq!(decoded.compressed_size, first_compressed_size);

        let decoded = decode_payload(&mut stream).await.unwrap();
        assert_eq!(decoded.uncompressed, second);
        assert_eq!(decoded.compressed_size, second_compressed_size);
    }

    #[tokio::test]
    async fn decode_payload_reads_all_snappy_chunks_for_one_payload() {
        let payload = vec![42; 128 * 1024];

        let mut stream = Cursor::new(Vec::new());
        let compressed_size = write_payload(&mut stream, &payload).await.unwrap();

        let mut stream = Cursor::new(stream.into_inner());
        let decoded = decode_payload(&mut stream).await.unwrap();

        assert_eq!(decoded.uncompressed, payload);
        assert_eq!(decoded.compressed_size, compressed_size);
    }

    #[tokio::test]
    async fn decode_payload_handles_empty_payload_before_following_payload() {
        let second = b"after empty";

        let mut stream = Cursor::new(Vec::new());
        let empty_compressed_size = write_payload(&mut stream, &[]).await.unwrap();
        write_payload(&mut stream, second).await.unwrap();

        let mut stream = Cursor::new(stream.into_inner());

        let decoded = decode_payload(&mut stream).await.unwrap();
        assert!(decoded.uncompressed.is_empty());
        assert_eq!(decoded.compressed_size, empty_compressed_size);

        let decoded = decode_payload(&mut stream).await.unwrap();
        assert_eq!(decoded.uncompressed, second);
    }
}
