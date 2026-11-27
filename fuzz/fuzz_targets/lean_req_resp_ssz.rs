#![no_main]

//! Lean req/resp payloads after framing: the request of each protocol and
//! the `Status` response.
//!
//! The selector picks the protocol id, including one the node does not
//! serve, since `decode_request` is also the dispatch on the id.

use ethlambda_fuzz::split;
use ethlambda_p2p::lean::{
    encoding::{decode_request, decode_status_response},
    protocols,
};
use libfuzzer_sys::fuzz_target;

const PROTOCOLS: [&str; 3] = [
    protocols::STATUS_V1,
    protocols::BLOCKS_BY_ROOT_V1,
    protocols::BLOCKS_BY_RANGE_V1,
];
const UNKNOWN_PROTOCOL: &str = "/leanconsensus/req/not_a_protocol/1/ssz_snappy";

fuzz_target!(|data: &[u8]| {
    let (selector, payload) = split(data);
    let protocol = PROTOCOLS
        .get(usize::from(selector))
        .copied()
        .unwrap_or(UNKNOWN_PROTOCOL);

    let request = decode_request(protocol, payload);
    if protocol == UNKNOWN_PROTOCOL {
        assert!(
            request.is_none(),
            "an unknown protocol id decoded a request"
        );
    }

    let _ = decode_status_response(payload);
});
