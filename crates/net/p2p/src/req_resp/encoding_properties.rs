//! Property tests for the req/resp wire framing: the protobuf varint length
//! prefix and the snappy frames after it (`encoding.rs`).
//!
//! Every byte these functions read comes from a peer, so the properties are
//! the two that matter for untrusted input: what we write reads back exactly,
//! and what a peer writes is either refused or read as the protobuf varint it
//! actually encodes. Driven by ephyra; a failure prints an
//! `EPHYRA_REPLAY=seed:iteration` line that reruns that exact input. See
//! `docs/property_testing.md`.

use ephyra::prelude::*;
use ephyra::{BoxGen, gens};
use futures::{executor::block_on, io::Cursor};

use super::encoding::{
    MAX_PAYLOAD_SIZE, decode_payload, decode_varint, encode_varint, write_payload,
};

/// Reference model of an unsigned protobuf varint: seven bits per byte, least
/// significant group first, high bit set on every byte but the last.
///
/// Decoded into a `u128`, which holds every varint up to 18 bytes long, so a
/// value too wide for the `u32` the codec uses is seen as too wide rather than
/// silently truncated. Returns the value and the number of bytes it took, or
/// `None` when the buffer ends before a byte without the continuation bit.
fn model_varint(buf: &[u8]) -> Option<(u128, usize)> {
    let mut value = 0u128;
    for (i, byte) in buf.iter().enumerate().take(18) {
        value |= u128::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None
}

/// Every `u32`, with the boundaries of each varint width (2^7, 2^14, 2^21,
/// 2^28) drawn far more often than a uniform draw would.
fn varint_values() -> BoxGen<u32> {
    let width_edges: Vec<u32> = [7, 14, 21, 28]
        .into_iter()
        .flat_map(|bits| [(1u32 << bits) - 1, 1u32 << bits])
        .chain([0, 1, u32::MAX])
        .collect();
    gens::frequency(vec![
        (2, gens::int(..).boxed()),
        (1, gens::pick_from(width_edges).boxed()),
    ])
    .boxed()
}

/// Bytes shaped like varints: mostly continuation bytes, so runs of four,
/// five or more of them (the widths where a `u32` runs out) are common.
fn varint_like_bytes() -> BoxGen<Vec<u8>> {
    let byte = gens::frequency(vec![
        (4, gens::int(0x80u8..=0xff).boxed()),
        (1, gens::int(0x00u8..=0x7f).boxed()),
        (
            1,
            gens::pick_from(vec![0x00, 0x01, 0x0f, 0x10, 0x7f, 0x80, 0x8f, 0xff]).boxed(),
        ),
    ]);
    gens::vec(byte).len(0..=12).boxed()
}

/// Payloads from empty to past snappy's 64 KiB chunk size, both compressible
/// (one byte repeated) and incompressible (uniform bytes), since the two take
/// different chunk types (0x00 compressed, 0x01 stored).
fn payloads() -> BoxGen<Vec<u8>> {
    let any_byte = || gens::int(0u8..=255);
    let repeated = (gens::int(0usize..=140_000), any_byte()).map(|(len, byte)| vec![byte; len]);
    gens::frequency(vec![
        (3, gens::vec(any_byte()).len(0..=64).boxed()),
        (2, gens::vec(any_byte()).len(0..=4096).boxed()),
        (1, gens::vec(any_byte()).len(60_000..=140_000).boxed()),
        (1, repeated.boxed()),
    ])
    .boxed()
}

fn written(payload: &[u8]) -> (Vec<u8>, usize) {
    let mut stream = Cursor::new(Vec::new());
    let compressed =
        block_on(write_payload(&mut stream, payload)).expect("payload under the limit");
    (stream.into_inner(), compressed)
}

#[ephyra::test]
fn a_varint_reads_back_as_written(
    #[ephyra(gen = varint_values())] value: u32,
    #[ephyra(gen = gens::vec(gens::int(0u8..=255)).len(0..=4))] trailing: Vec<u8>,
) {
    let mut buf = [0; 5];
    let mut bytes = encode_varint(value, &mut buf).to_vec();
    assert_eq!(model_varint(&bytes), Some((u128::from(value), bytes.len())));
    bytes.extend_from_slice(&trailing);

    let (decoded, rest) = decode_varint(&bytes).expect("an encoded varint decodes");
    assert_eq!(decoded, value);
    assert_eq!(rest, trailing.as_slice());
}

/// A peer's length prefix is either refused or read as the value it encodes.
/// Accepting it as some other value (a wider varint with its high bits
/// dropped, say) means checking `MAX_PAYLOAD_SIZE` against a length the peer
/// never sent.
#[ephyra::test]
fn a_varint_is_refused_or_read_as_the_value_it_encodes(
    #[ephyra(gen = varint_like_bytes())] bytes: Vec<u8>,
) {
    let Ok((decoded, rest)) = decode_varint(&bytes) else {
        return;
    };
    let (expected, consumed) =
        model_varint(&bytes).expect("decoder accepted bytes with no terminating byte");
    assert_eq!(
        u128::from(decoded),
        expected,
        "varint {bytes:02x?} read as {decoded}"
    );
    assert_eq!(rest, &bytes[consumed..]);
}

#[ephyra::test(tests = 400)]
fn a_payload_reads_back_as_written(#[ephyra(gen = payloads())] payload: Vec<u8>) {
    let (wire, compressed_size) = written(&payload);

    let mut stream = Cursor::new(wire);
    let decoded = block_on(decode_payload(&mut stream)).expect("a written payload decodes");
    assert_eq!(decoded.uncompressed, payload);
    assert_eq!(decoded.compressed_size, compressed_size);
    assert_eq!(
        stream.position() as usize,
        stream.get_ref().len(),
        "decoding left bytes of its own payload in the stream"
    );
}

/// One edit a peer (or a bad link) can make to a well-formed payload.
#[derive(Clone, Debug, ephyra::Arbitrary)]
enum Corruption {
    /// Cut the stream at a position (taken modulo its length).
    Truncate(#[ephyra(gen = gens::int(0usize..=4096))] usize),
    /// XOR one byte with a non-zero mask.
    Flip(
        #[ephyra(gen = gens::int(0usize..=4096))] usize,
        #[ephyra(gen = gens::int(1u8..=255))] u8,
    ),
    /// Insert a byte.
    Insert(
        #[ephyra(gen = gens::int(0usize..=4096))] usize,
        #[ephyra(gen = gens::int(0u8..=255))] u8,
    ),
    /// Replace the length prefix with other bytes.
    Prefix(#[ephyra(gen = varint_like_bytes())] Vec<u8>),
}

fn corrupt(mut wire: Vec<u8>, corruptions: &[Corruption]) -> Vec<u8> {
    for corruption in corruptions {
        match corruption {
            Corruption::Truncate(at) => wire.truncate(at % (wire.len() + 1)),
            Corruption::Flip(at, mask) if !wire.is_empty() => {
                let at = at % wire.len();
                wire[at] ^= mask;
            }
            Corruption::Flip(..) => {}
            Corruption::Insert(at, byte) => {
                let at = at % (wire.len() + 1);
                wire.insert(at, *byte);
            }
            Corruption::Prefix(prefix) => {
                let old = model_varint(&wire).map_or(0, |(_, len)| len);
                wire.splice(..old, prefix.iter().copied());
            }
        }
    }
    wire
}

/// Whatever a peer sends, decoding returns: no panic, and anything it accepts
/// is exactly as long as the prefix said, within the limit.
#[ephyra::test(tests = 2000)]
fn a_corrupted_payload_is_refused_or_read_at_its_declared_length(
    #[ephyra(gen = gens::vec(gens::int(0u8..=255)).len(0..=300))] payload: Vec<u8>,
    #[ephyra(gen = gens::vec(ephyra::any::<Corruption>()).len(1..=4))] corruptions: Vec<Corruption>,
) {
    let (wire, _) = written(&payload);
    let wire = corrupt(wire, &corruptions);

    let Ok(decoded) = block_on(decode_payload(&mut Cursor::new(wire.clone()))) else {
        return;
    };
    let (declared, _) = model_varint(&wire).expect("accepted a stream with no length prefix");
    assert!(
        declared <= MAX_PAYLOAD_SIZE as u128,
        "accepted a prefix declaring {declared} bytes, over MAX_PAYLOAD_SIZE"
    );
    assert_eq!(
        decoded.uncompressed.len() as u128,
        declared,
        "decoded length differs from the declared one"
    );
}
