#![no_main]

//! The varint length prefix every req/resp payload starts with.
//!
//! Decoding arbitrary bytes must never panic; a value that decoded must
//! re-encode to bytes that decode to the same value and nothing else; and
//! every `u32` must survive the round trip.

use ethlambda_p2p::{decode_varint, encode_varint};
use libfuzzer_sys::fuzz_target;

fn roundtrip(value: u32) {
    let mut buf = [0u8; 5];
    let encoded = encode_varint(value, &mut buf);
    let (decoded, rest) = decode_varint(encoded).expect("own encoding decodes");
    assert_eq!(decoded, value, "varint round trip changed the value");
    assert!(rest.is_empty(), "own encoding left bytes behind");
}

fuzz_target!(|data: &[u8]| {
    if let Ok((value, rest)) = decode_varint(data) {
        assert!(rest.len() < data.len(), "a decode consumed nothing");
        roundtrip(value);
    }

    if let Some(bytes) = data.get(..4) {
        roundtrip(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
    }
});
