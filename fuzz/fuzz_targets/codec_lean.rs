#![no_main]

//! The lean req/resp codec as libp2p drives it, over an in-memory stream.
//!
//! `Codec::read_request` and `read_response` are the whole inbound path:
//! framing, chunking, and the per-protocol SSZ decoders. The selector picks
//! the protocol, including a beacon one: the codec is one type for both
//! wires and only refuses what needs the beacon context it lacks, so a
//! foreign protocol is a no-panic path here, not a refusal. A request or
//! response that was read must survive our own `write_*` and read back the
//! same.

use ethlambda_fuzz::split;
use ethlambda_p2p::{ReqRespCodec as Codec, beacon, lean::protocols};
use futures::{executor::block_on, io::Cursor};
use libfuzzer_sys::fuzz_target;
use libp2p::{StreamProtocol, request_response::Codec as _};

const PROTOCOLS: [&str; 3] = [
    protocols::STATUS_V1,
    protocols::BLOCKS_BY_ROOT_V1,
    protocols::BLOCKS_BY_RANGE_V1,
];

fuzz_target!(|data: &[u8]| {
    let (selector, bytes) = split(data);
    let foreign = usize::from(selector) >= PROTOCOLS.len();
    let protocol = StreamProtocol::new(if foreign {
        beacon::protocols::STATUS_V2
    } else {
        PROTOCOLS[usize::from(selector)]
    });
    let mut codec = Codec::lean();

    block_on(async {
        let mut cursor = Cursor::new(bytes);
        let request = codec.read_request(&protocol, &mut cursor).await;
        if let Ok(request) = request
            && !foreign
        {
            let shown = format!("{request:?}");
            let mut written = Vec::new();
            codec
                .write_request(&protocol, &mut written, request)
                .await
                .expect("own request writes");
            let again = codec
                .read_request(&protocol, &mut Cursor::new(written.as_slice()))
                .await
                .expect("own request reads back");
            assert_eq!(format!("{again:?}"), shown, "request round trip differs");
        }

        let mut cursor = Cursor::new(bytes);
        let response = codec.read_response(&protocol, &mut cursor).await;
        if let Ok(response) = response
            && !foreign
        {
            let shown = format!("{response:?}");
            let mut written = Vec::new();
            codec
                .write_response(&protocol, &mut written, response)
                .await
                .expect("own response writes");
            let again = codec
                .read_response(&protocol, &mut Cursor::new(written.as_slice()))
                .await
                .expect("own response reads back");
            assert_eq!(format!("{again:?}"), shown, "response round trip differs");
        }
    });
});
