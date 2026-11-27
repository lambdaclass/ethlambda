#![no_main]

//! Raw snappy, the gossip payload compression.
//!
//! A gossip payload is the first thing a peer's bytes reach. Decompressing
//! arbitrary bytes must never panic and must respect `MAX_PAYLOAD_SIZE`
//! whatever length the snappy header claims; our own compression must
//! decompress back to the input.

use ethlambda_p2p::{MAX_PAYLOAD_SIZE, compress_message, decompress_message};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(decompressed) = decompress_message(data) {
        assert!(
            decompressed.len() <= MAX_PAYLOAD_SIZE,
            "decompressed {} bytes past the {MAX_PAYLOAD_SIZE}-byte cap",
            decompressed.len()
        );
    }

    if data.len() <= MAX_PAYLOAD_SIZE {
        let compressed = compress_message(data);
        let roundtrip = decompress_message(&compressed).expect("own compression decompresses");
        assert_eq!(
            roundtrip, data,
            "compress then decompress is not the identity"
        );
    }
});
