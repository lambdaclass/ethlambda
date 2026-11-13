#![no_main]

//! A chunked response stream: result byte, optional 4-byte fork-digest
//! context, payload, repeated until the peer closes the stream.
//!
//! The selector sets the two limits the chains disagree on (whether chunks
//! carry a context, and how many chunks are allowed). The reader must never
//! panic, must hand the decoder a context of exactly the expected width, and
//! must never return more chunks than the limit.

use ethlambda_fuzz::split;
use ethlambda_p2p::{ChunkLimits, read_chunked_response};
use futures::{executor::block_on, io::Cursor};
use libfuzzer_sys::fuzz_target;

const CONTEXT_LEN: usize = 4;

fuzz_target!(|data: &[u8]| {
    let (selector, bytes) = split(data);
    let has_context = selector & 1 == 1;
    let max_chunks = usize::from(selector >> 1);
    let limits = ChunkLimits {
        has_context,
        max_chunks,
    };

    let mut cursor = Cursor::new(bytes);
    let expected_context = if has_context { CONTEXT_LEN } else { 0 };
    let result = block_on(read_chunked_response(
        &mut cursor,
        "fuzz",
        limits,
        |context, payload| {
            assert_eq!(
                context.len(),
                expected_context,
                "a chunk's context is not the width the limits promised"
            );
            Ok(payload.len())
        },
    ));

    if let Ok(chunks) = result {
        assert!(
            chunks.len() <= max_chunks,
            "{} chunks returned past the limit of {max_chunks}",
            chunks.len()
        );
    }
});
