#![no_main]

//! The three lean gossip topics: `block`, `attestation_N`, `aggregation`.
//!
//! Each payload decodes straight into its container. Decoding must never
//! panic, and a value that decoded must re-encode to bytes that decode again
//! (a decoder accepting an encoding its encoder cannot reproduce is how two
//! clients come to disagree on a message).

use ethlambda_fuzz::split;
use ethlambda_types::{
    attestation::{SignedAggregatedAttestation, SignedAttestation},
    block::SignedBlock,
};
use libfuzzer_sys::fuzz_target;
use libssz::{SszDecode, SszEncode};

fn decode_and_reencode<T: SszDecode + SszEncode>(bytes: &[u8]) {
    if let Ok(value) = T::from_ssz_bytes(bytes) {
        let encoded = value.to_ssz();
        T::from_ssz_bytes(&encoded).expect("a decoded value re-encodes to bytes that decode");
    }
}

fuzz_target!(|data: &[u8]| {
    let (selector, bytes) = split(data);
    match selector % 3 {
        0 => decode_and_reencode::<SignedBlock>(bytes),
        1 => decode_and_reencode::<SignedAttestation>(bytes),
        _ => decode_and_reencode::<SignedAggregatedAttestation>(bytes),
    }
});
