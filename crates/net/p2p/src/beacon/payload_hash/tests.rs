//! Every fork the node follows, against a payload taken from a real chain.
//! The vectors are SSZ as the Beacon API served it
//! (`beacon/testdata/payload_hash/`):
//!
//! | fork      | chain       | object               |
//! |-----------|-------------|----------------------|
//! | bellatrix | Sepolia     | block, slot 500000   |
//! | capella   | Sepolia     | block, slot 1900000  |
//! | deneb     | Hoodi       | block, slot 2003     |
//! | electra   | Hoodi       | block, slot 70001    |
//! | fulu      | mainnet     | block, slot 15576000 |
//! | gloas     | Plataberget | envelope, slot 593101 |

use ethlambda_types::beacon::containers::electra;
use ethlambda_types::beacon::fork::ForkName;
use libssz::SszDecode as _;

use super::*;

const BELLATRIX: &[u8] =
    include_bytes!("../testdata/payload_hash/sepolia_bellatrix_slot_500000.ssz");
const CAPELLA: &[u8] = include_bytes!("../testdata/payload_hash/sepolia_capella_slot_1900000.ssz");
const DENEB: &[u8] = include_bytes!("../testdata/payload_hash/hoodi_deneb_slot_2003.ssz");
const ELECTRA: &[u8] = include_bytes!("../testdata/payload_hash/hoodi_electra_slot_70001.ssz");
const FULU: &[u8] = include_bytes!("../testdata/payload_hash/mainnet_fulu_slot_15576000.ssz");
const GLOAS: &[u8] =
    include_bytes!("../testdata/payload_hash/plataberget_gloas_envelope_slot_593101.ssz");

fn block(fork: ForkName, bytes: &[u8]) -> SignedBeaconBlock {
    SignedBeaconBlock::from_ssz(fork, bytes).expect("a real block decodes")
}

fn envelope() -> gloas::SignedExecutionPayloadEnvelope {
    gloas::SignedExecutionPayloadEnvelope::from_ssz_bytes(GLOAS).expect("a real envelope decodes")
}

fn bellatrix_payload(
    block: &mut SignedBeaconBlock,
) -> &mut ethlambda_types::beacon::containers::bellatrix::ExecutionPayload {
    let SignedBeaconBlock::Bellatrix(inner) = block else {
        panic!("bellatrix");
    };
    &mut inner.message.body.execution_payload
}

/// An all-zero request: only its presence matters to the requests hash.
fn consolidation() -> electra::ConsolidationRequest {
    electra::ConsolidationRequest::from_ssz_bytes(&[0; 116]).expect("a fixed-size container")
}

fn withdrawal() -> capella::Withdrawal {
    capella::Withdrawal::from_ssz_bytes(&[0; 44]).expect("a fixed-size container")
}

fn assert_refused(result: Result<(), HashMismatch>, what: &str) {
    assert!(result.is_err(), "{what}: the hash must no longer match");
}

#[test]
fn every_real_payload_matches_its_hash() {
    for (fork, bytes) in [
        (ForkName::Bellatrix, BELLATRIX),
        (ForkName::Capella, CAPELLA),
        (ForkName::Deneb, DENEB),
        (ForkName::Electra, ELECTRA),
        (ForkName::Fulu, FULU),
    ] {
        let block = block(fork, bytes);
        assert_eq!(verify_block(&block), Ok(()), "{fork:?}");
    }
    assert_eq!(verify_envelope(&envelope()), Ok(()), "gloas");
}

#[test]
fn the_vectors_exercise_what_each_fork_adds() {
    let SignedBeaconBlock::Capella(capella) = block(ForkName::Capella, CAPELLA) else {
        panic!("capella");
    };
    assert!(
        !capella
            .message
            .body
            .execution_payload
            .withdrawals
            .is_empty(),
        "capella's vector must carry withdrawals"
    );
    let SignedBeaconBlock::Fulu(fulu) = block(ForkName::Fulu, FULU) else {
        panic!("fulu");
    };
    let SignedBeaconBlock::Bellatrix(bellatrix) = block(ForkName::Bellatrix, BELLATRIX) else {
        panic!("bellatrix");
    };
    // Past the merge: a pre-merge block carries the empty default payload.
    assert_ne!(
        bellatrix.message.body.execution_payload.block_hash.0,
        [0; 32]
    );
    assert!(!fulu.message.body.execution_payload.transactions.is_empty());
    assert!(!envelope().message.payload.transactions.is_empty());
}

#[test]
fn a_changed_bellatrix_field_is_refused() {
    let mut changed = block(ForkName::Bellatrix, BELLATRIX);
    bellatrix_payload(&mut changed).gas_used += 1;
    assert_refused(verify_block(&changed), "gas_used");

    let mut changed = block(ForkName::Bellatrix, BELLATRIX);
    bellatrix_payload(&mut changed).block_hash.0[0] ^= 1;
    assert_refused(verify_block(&changed), "block_hash");
}

#[test]
fn a_changed_capella_withdrawal_is_refused() {
    let mut changed = block(ForkName::Capella, CAPELLA);
    let SignedBeaconBlock::Capella(inner) = &mut changed else {
        panic!("capella");
    };
    inner.message.body.execution_payload.withdrawals[0].amount += 1;
    assert_refused(verify_block(&changed), "withdrawal amount");
}

#[test]
fn a_changed_deneb_field_is_refused() {
    for what in ["excess_blob_gas", "parent_root", "timestamp"] {
        let mut changed = block(ForkName::Deneb, DENEB);
        let SignedBeaconBlock::Deneb(inner) = &mut changed else {
            panic!("deneb");
        };
        match what {
            "excess_blob_gas" => inner.message.body.execution_payload.excess_blob_gas += 1,
            // The header commits to the parent beacon block root, which the
            // payload does not carry: it comes from the block.
            "parent_root" => inner.message.parent_root.0[0] ^= 1,
            _ => inner.message.body.execution_payload.timestamp += 1,
        }
        assert_refused(verify_block(&changed), what);
    }
}

#[test]
fn a_changed_electra_or_fulu_field_is_refused() {
    for (fork, bytes) in [(ForkName::Electra, ELECTRA), (ForkName::Fulu, FULU)] {
        for what in ["transaction", "parent_root", "request", "extra_data"] {
            let mut changed = block(fork, bytes);
            let (SignedBeaconBlock::Electra(inner) | SignedBeaconBlock::Fulu(inner)) = &mut changed
            else {
                panic!("electra or fulu");
            };
            match what {
                "transaction" => {
                    let payload = &mut inner.message.body.execution_payload;
                    let last = payload.transactions.len() - 1;
                    let tx = &mut payload.transactions[last];
                    let end = tx.len() - 1;
                    tx[end] ^= 1;
                }
                "parent_root" => inner.message.parent_root.0[0] ^= 1,
                // The requests hash covers a request however empty its
                // payload: one more consolidation moves it.
                "request" => inner
                    .message
                    .body
                    .execution_requests
                    .consolidations
                    .push(consolidation())
                    .expect("room for one more request"),
                _ => inner
                    .message
                    .body
                    .execution_payload
                    .extra_data
                    .push(1)
                    .expect("room for one more byte"),
            }
            assert_refused(verify_block(&changed), &format!("{fork:?} {what}"));
        }
    }
}

#[test]
fn a_changed_gloas_field_is_refused() {
    for what in [
        "slot_number",
        "block_access_list",
        "parent_beacon_block_root",
        "execution_requests",
        "withdrawal",
        "transaction",
        "base_fee_per_gas",
    ] {
        let mut changed = envelope();
        let message = &mut changed.message;
        match what {
            "slot_number" => message.payload.slot_number += 1,
            "block_access_list" => message.payload.block_access_list.push(0),
            "parent_beacon_block_root" => message.parent_beacon_block_root.0[0] ^= 1,
            "execution_requests" => message
                .execution_requests
                .consolidations
                .push(consolidation()),
            "withdrawal" => message.payload.withdrawals.push(withdrawal()),
            "transaction" => {
                let last = message.payload.transactions.len() - 1;
                let tx = &mut message.payload.transactions[last];
                let end = tx.len() - 1;
                tx[end] ^= 1;
            }
            _ => message.payload.base_fee_per_gas.0[31] ^= 1,
        }
        assert_refused(verify_envelope(&changed), what);
    }
}

#[test]
fn a_pre_merge_bellatrix_payload_has_nothing_to_check() {
    // Before the merge a block carries the empty default payload.
    let mut empty = block(ForkName::Bellatrix, BELLATRIX);
    let payload = bellatrix_payload(&mut empty);
    payload.block_hash = Default::default();
    payload.parent_hash = Default::default();
    assert_eq!(verify_block(&empty), Ok(()));
}

#[test]
fn a_mismatch_is_a_reject_with_its_own_reason() {
    let mut changed = envelope();
    changed.message.payload.gas_used += 1;
    let outcome = reject_envelope_on_mismatch(&changed).expect_err("a changed envelope");
    assert_eq!(outcome.labels(), ("reject", "payload_block_hash_mismatch"));
    assert!(reject_envelope_on_mismatch(&envelope()).is_ok());
}
