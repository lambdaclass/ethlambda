#![no_main]

//! The hand-rolled offset readers that find a message's slot before the full
//! decode, so the fork (and so the container) can be chosen.
//!
//! Two properties. The readers never panic on any bytes. And when the full
//! decode succeeds, the slot it carries is the one the reader found: a
//! disagreement would decode a message under the wrong fork's container.

use ethlambda_fuzz::mainnet_config;
use ethlambda_p2p::beacon::decode::{
    aggregate_slot, attester_slashing_slot, block_slot, decode_aggregate_and_proof, decode_block,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let config = mainnet_config();

    let slot = block_slot(data);
    if let Ok(block) = decode_block(config, data) {
        assert_eq!(
            slot,
            Ok(block.slot()),
            "block_slot disagrees with the decoded block"
        );
    }

    let slot = aggregate_slot(data);
    if let Ok(aggregate) = decode_aggregate_and_proof(config, data) {
        assert_eq!(
            slot,
            Ok(aggregate.slot()),
            "aggregate_slot disagrees with the decoded aggregate"
        );
    }

    let _ = attester_slashing_slot(data);
});
