#![no_main]

//! A req/resp payload as it arrives: varint length, then a snappy frame.
//!
//! `decode_payload` is what every request and response chunk goes through.
//! On arbitrary bytes it must never panic, must honour `MAX_PAYLOAD_SIZE`
//! whatever the prefix claims, and must report a compressed size that fits
//! in what was read. A payload it accepted must survive our own
//! `write_payload` and decode again to the same bytes.

use ethlambda_p2p::{MAX_PAYLOAD_SIZE, decode_payload, write_payload};
use futures::{executor::block_on, io::Cursor};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    let Ok(decoded) = block_on(decode_payload(&mut cursor)) else {
        return;
    };

    assert!(
        decoded.uncompressed.len() <= MAX_PAYLOAD_SIZE,
        "decoded {} bytes past the {MAX_PAYLOAD_SIZE}-byte cap",
        decoded.uncompressed.len()
    );
    assert!(
        decoded.compressed_size <= data.len(),
        "compressed size {} exceeds the {} bytes read",
        decoded.compressed_size,
        data.len()
    );

    let mut written = Vec::new();
    block_on(write_payload(&mut written, &decoded.uncompressed)).expect("own payload writes");
    let mut again = Cursor::new(written.as_slice());
    let redecoded = block_on(decode_payload(&mut again)).expect("own payload decodes");
    assert_eq!(
        redecoded.uncompressed, decoded.uncompressed,
        "write then decode is not the identity"
    );
});
