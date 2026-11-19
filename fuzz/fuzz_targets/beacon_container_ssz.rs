#![no_main]

//! The beacon containers behind the subnet and gloas topics, decoded by fork.
//!
//! `decode_gossip` covers the global topics and picks the fork from the
//! payload's slot. The attestation subnets, data column subnets and gloas
//! topics take the fork from the topic's digest instead, so here the
//! selector picks the fork and the decoder: every `ForkName::ALL` entry
//! (never `Lean`, whose arms are `unreachable!` by design) against
//! `SignedBeaconBlock`, `DataColumnSidecar` and `Attestation`, plus the
//! fork-less decoders of the gloas and sync committee messages.

use ethlambda_fuzz::split;
use ethlambda_p2p::beacon::decode::{
    decode_attestation, decode_data_column_sidecar, decode_execution_payload_bid,
    decode_execution_payload_envelope, decode_payload_attestation_message,
    decode_proposer_preferences, decode_sync_committee_contribution, decode_sync_committee_message,
};
use ethlambda_types::beacon::{containers::SignedBeaconBlock, fork::ForkName};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (selector, bytes) = split(data);
    let fork = ForkName::ALL[usize::from(selector % 8)];
    match selector / 8 {
        0 => drop(SignedBeaconBlock::from_ssz(fork, bytes)),
        1 => drop(decode_data_column_sidecar(fork, bytes)),
        2 => drop(decode_attestation(fork, bytes)),
        3 => match selector % 8 {
            0 => drop(decode_execution_payload_envelope(bytes)),
            1 => drop(decode_payload_attestation_message(bytes)),
            2 => drop(decode_execution_payload_bid(bytes)),
            3 => drop(decode_proposer_preferences(bytes)),
            4 => drop(decode_sync_committee_message(bytes)),
            5 => drop(decode_sync_committee_contribution(bytes)),
            _ => {}
        },
        _ => {}
    }
});
