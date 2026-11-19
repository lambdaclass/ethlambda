#![no_main]

//! The post-quantum signature material a lean peer sends: an XMSS signature,
//! a public key, and a block's aggregated proof.
//!
//! Decode only. Verification runs a SNARK verifier per input, which is far
//! too slow to fuzz and is not where parsing bugs live.

use ethlambda_crypto::signature::{ValidatorPublicKey, ValidatorSignature};
use ethlambda_fuzz::split;
use ethlambda_types::block::MultiMessageAggregate;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (selector, bytes) = split(data);
    match selector % 3 {
        0 => drop(ValidatorSignature::from_bytes(bytes)),
        1 => drop(ValidatorPublicKey::from_bytes(bytes)),
        _ => drop(MultiMessageAggregate::from_bytes(bytes)),
    }
});
