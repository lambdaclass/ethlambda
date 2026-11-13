#![no_main]

//! Beacon `Status` and `MetaData` payloads, whose shape is chosen by the
//! protocol id the peer negotiated (V1/V2 status, V1/V2/V3 metadata).
//!
//! Every version must decode or refuse any bytes without panicking, and a
//! protocol id outside the set must be refused rather than guessed.

use ethlambda_fuzz::split;
use ethlambda_p2p::beacon::{
    encoding::{decode_metadata, decode_status},
    protocols,
};
use libfuzzer_sys::fuzz_target;

const UNKNOWN_PROTOCOL: &str = "/eth2/beacon_chain/req/not_a_protocol/1/ssz_snappy";

fuzz_target!(|data: &[u8]| {
    let (selector, payload) = split(data);
    match selector % 6 {
        0 => drop(decode_status(protocols::STATUS_V1, payload)),
        1 => drop(decode_status(protocols::STATUS_V2, payload)),
        2 => drop(decode_metadata(protocols::METADATA_V1, payload)),
        3 => drop(decode_metadata(protocols::METADATA_V2, payload)),
        4 => drop(decode_metadata(protocols::METADATA_V3, payload)),
        _ => {
            assert!(decode_status(UNKNOWN_PROTOCOL, payload).is_err());
            assert!(decode_metadata(UNKNOWN_PROTOCOL, payload).is_err());
        }
    }
});
