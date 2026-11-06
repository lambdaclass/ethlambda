#![no_main]

//! The beacon req/resp codec as libp2p drives it, over an in-memory stream,
//! under the mainnet fork schedule.
//!
//! Beyond what the lean codec does, this path checks each response chunk's
//! 4-byte context against the fork digest of the block's own epoch, bounds
//! chunk counts per protocol, and dispatches gloas envelopes. The selector
//! picks the protocol, including a lean one, which is a no-panic path rather
//! than a refusal (see `codec_lean`). What was read must survive our own
//! `write_*` and read back the same.

use ethlambda_fuzz::{mainnet_config, split};
use ethlambda_p2p::{
    ReqRespCodec as Codec,
    beacon::{BeaconContext, protocols},
    lean,
};
use ethlambda_types::beacon::primitives::Root;
use futures::{executor::block_on, io::Cursor};
use libfuzzer_sys::fuzz_target;
use libp2p::{StreamProtocol, request_response::Codec as _};

const PROTOCOLS: [&str; 13] = [
    protocols::STATUS_V1,
    protocols::STATUS_V2,
    protocols::PING_V1,
    protocols::METADATA_V1,
    protocols::METADATA_V2,
    protocols::METADATA_V3,
    protocols::GOODBYE_V1,
    protocols::BLOCKS_BY_RANGE_V2,
    protocols::BLOCKS_BY_ROOT_V2,
    protocols::DATA_COLUMN_SIDECARS_BY_RANGE_V1,
    protocols::DATA_COLUMN_SIDECARS_BY_ROOT_V1,
    protocols::EXECUTION_PAYLOAD_ENVELOPES_BY_RANGE_V1,
    protocols::EXECUTION_PAYLOAD_ENVELOPES_BY_ROOT_V1,
];

fn codec() -> Codec {
    Codec::beacon(BeaconContext {
        config: mainnet_config().clone(),
        genesis_validators_root: Root::ZERO,
    })
}

fuzz_target!(|data: &[u8]| {
    let (selector, bytes) = split(data);
    let foreign = usize::from(selector) >= PROTOCOLS.len();
    let protocol = StreamProtocol::new(if foreign {
        lean::protocols::STATUS_V1
    } else {
        PROTOCOLS[usize::from(selector)]
    });
    let mut codec = codec();

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
