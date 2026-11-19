//! Every fork the node follows, against a payload taken from a real chain.
//! The vectors are SSZ as the Beacon API served it
//! (`beacon/testdata/payload_hash/`):
//!
//! | fork      | chain       | object                | carries                                |
//! |-----------|-------------|-----------------------|----------------------------------------|
//! | bellatrix | Sepolia     | block, slot 500000    |                                        |
//! | capella   | Sepolia     | block, slot 1900000   | withdrawals                            |
//! | deneb     | Hoodi       | block, slot 2003      | no transactions                        |
//! | electra   | Hoodi       | block, slot 70001     | no requests                            |
//! | fulu      | mainnet     | block, slot 15684701  | 238 transactions, 3 requests (2 types) |
//! | gloas     | Plataberget | envelope, slot 593101 |                                        |
//!
//! The fulu block is finalized and canonical; its bytes are the same from
//! ethlambda's and Lodestar's Beacon API. It carries one withdrawal request
//! and two consolidation requests, so its requests hash is over two request
//! types.

use ethlambda_state_transition::beacon::gossip::{QueueReason, RejectReason};
use ethlambda_types::beacon::containers::electra;
use ethlambda_types::beacon::fork::ForkName;
use libssz::SszDecode as _;

use super::*;

const BELLATRIX: &[u8] =
    include_bytes!("../testdata/payload_hash/sepolia_bellatrix_slot_500000.ssz");
const CAPELLA: &[u8] = include_bytes!("../testdata/payload_hash/sepolia_capella_slot_1900000.ssz");
const DENEB: &[u8] = include_bytes!("../testdata/payload_hash/hoodi_deneb_slot_2003.ssz");
const ELECTRA: &[u8] = include_bytes!("../testdata/payload_hash/hoodi_electra_slot_70001.ssz");
const FULU: &[u8] = include_bytes!("../testdata/payload_hash/mainnet_fulu_slot_15684701.ssz");
const GLOAS: &[u8] =
    include_bytes!("../testdata/payload_hash/plataberget_gloas_envelope_slot_593101.ssz");

fn block(fork: ForkName, bytes: &[u8]) -> SignedBeaconBlock {
    SignedBeaconBlock::from_ssz(fork, bytes).expect("a real block decodes")
}

fn envelope() -> gloas::SignedExecutionPayloadEnvelope {
    gloas::SignedExecutionPayloadEnvelope::from_ssz_bytes(GLOAS).expect("a real envelope decodes")
}

fn bellatrix_payload(block: &mut SignedBeaconBlock) -> &mut bellatrix::ExecutionPayload {
    let SignedBeaconBlock::Bellatrix(inner) = block else {
        panic!("bellatrix");
    };
    &mut inner.message.body.execution_payload
}

fn fulu_block(block: &mut SignedBeaconBlock) -> &mut electra::SignedBeaconBlock {
    let SignedBeaconBlock::Fulu(inner) = block else {
        panic!("fulu");
    };
    inner
}

/// The real fulu block with one header field changed.
fn changed_fulu_block() -> SignedBeaconBlock {
    let mut changed = block(ForkName::Fulu, FULU);
    fulu_block(&mut changed)
        .message
        .body
        .execution_payload
        .gas_used += 1;
    changed
}

/// An all-zero request: only its presence matters to the requests hash.
fn consolidation() -> electra::ConsolidationRequest {
    electra::ConsolidationRequest::from_ssz_bytes(&[0; 116]).expect("a fixed-size container")
}

/// An all-zero withdrawal request, for blocks whose consolidation list (two
/// at most) may already be full.
fn withdrawal_request() -> electra::WithdrawalRequest {
    electra::WithdrawalRequest::from_ssz_bytes(&[0; 76]).expect("a fixed-size container")
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
    let SignedBeaconBlock::Bellatrix(bellatrix) = block(ForkName::Bellatrix, BELLATRIX) else {
        panic!("bellatrix");
    };
    // Past the merge: a pre-merge block carries the empty default payload.
    assert_ne!(
        bellatrix.message.body.execution_payload,
        bellatrix::ExecutionPayload::default()
    );

    let mut fulu = block(ForkName::Fulu, FULU);
    let fulu = &fulu_block(&mut fulu).message.body;
    // The transactions trie keys a transaction by `rlp(index)`: one byte up to
    // index 127, two from index 128 (`0x81 0x80`), so the vector needs more
    // than 128 transactions to reach a two-byte key.
    assert_eq!(128usize.encode_to_vec(), [0x81, 0x80]);
    assert!(
        fulu.execution_payload.transactions.len() > 128,
        "fulu's vector must reach a two-byte transaction key"
    );
    // Real requests of more than one type, so the requests hash is over
    // several typed entries and not only the empty list's.
    let requests = ethlambda_state_transition::beacon::stf::electra::get_execution_requests_list(
        &fulu.execution_requests,
    );
    assert!(
        requests.len() >= 2,
        "fulu's vector must carry requests of two types"
    );

    // The empty cases on real blocks: deneb's has no transactions, so its
    // hash covers the empty transactions trie, and electra's has no requests,
    // so its hash covers the requests hash of an empty list.
    let SignedBeaconBlock::Deneb(deneb) = block(ForkName::Deneb, DENEB) else {
        panic!("deneb");
    };
    assert!(deneb.message.body.execution_payload.transactions.is_empty());
    let SignedBeaconBlock::Electra(electra_block) = block(ForkName::Electra, ELECTRA) else {
        panic!("electra");
    };
    let requests = ethlambda_state_transition::beacon::stf::electra::get_execution_requests_list(
        &electra_block.message.body.execution_requests,
    );
    assert!(
        requests.is_empty(),
        "electra's vector must carry no requests"
    );

    assert!(!envelope().message.payload.transactions.is_empty());
}

/// No vector has an empty withdrawals list (every one from capella on carries
/// 16), so the empty withdrawals root is pinned against the execution layer's
/// empty trie root, `keccak256(rlp(""))`, instead.
#[test]
fn an_empty_withdrawals_list_has_the_empty_trie_root() {
    let empty_trie_root =
        hex::decode("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
            .expect("hex");
    assert_eq!(keccak256(&[0x80]).to_vec(), empty_trie_root);
    assert_eq!(
        compute_withdrawals_root(&[], &NativeCrypto).0.to_vec(),
        empty_trie_root
    );
}

/// An absent optional header field writes nothing, so a present one after it
/// would shift into its place: `computed_hash` asserts the fields a fork adds
/// only ever extend the header's tail.
#[test]
#[cfg(debug_assertions)]
#[should_panic(expected = "a header field is present after an absent earlier one")]
fn a_header_field_after_an_absent_one_is_caught() {
    let block = block(ForkName::Electra, ELECTRA);
    let SignedBeaconBlock::Electra(inner) = &block else {
        panic!("electra");
    };
    let message = &inner.message;
    let payload = &message.body.execution_payload;
    let mut fields = Fields::deneb(payload, message.parent_root, Some(Vec::new()));
    fields.blob_gas = None;
    let _ = fields.computed_hash();
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
        for what in [
            "transaction",
            "parent_root",
            "request",
            "existing_request",
            "extra_data",
        ] {
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
                // payload: one more withdrawal request moves it.
                "request" => inner
                    .message
                    .body
                    .execution_requests
                    .withdrawals
                    .push(withdrawal_request())
                    .expect("room for one more request"),
                // A changed field inside a request the block already
                // carries; only the fulu vector has one.
                "existing_request" => {
                    let requests = &mut inner.message.body.execution_requests;
                    if requests.consolidations.is_empty() {
                        continue;
                    }
                    requests.consolidations[0].source_address.0[0] ^= 1;
                }
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
    *bellatrix_payload(&mut empty) = bellatrix::ExecutionPayload::default();
    assert_eq!(verify_block(&empty), Ok(()));
}

/// The pre-merge skip is the whole default payload, as the specification's
/// `is_execution_enabled` has it, not two zero hashes.
#[test]
fn a_payload_with_zero_hashes_but_other_fields_is_checked() {
    let mut zero_hashes = block(ForkName::Bellatrix, BELLATRIX);
    let payload = bellatrix_payload(&mut zero_hashes);
    payload.block_hash = Default::default();
    payload.parent_hash = Default::default();
    assert_refused(
        verify_block(&zero_hashes),
        "zero hashes over a real payload",
    );
}

#[test]
fn a_block_mismatch_is_ignored_once_its_checks_accept() {
    let changed = changed_fulu_block();
    let root = Root::ZERO;
    let outcome = block_verdict(Outcome::Accept, &changed, root);
    // IGNORE, never REJECT: other clients relay such a block.
    assert_eq!(outcome.labels(), ("ignore", "payload_block_hash_mismatch"));
    assert_eq!(
        block_verdict(Outcome::Accept, &block(ForkName::Fulu, FULU), root),
        Outcome::Accept
    );
}

/// Anything but `Accept` passes through unhashed: a queued block may not have
/// had its signature checked yet, and a rejected one is refused already.
#[test]
fn a_block_that_was_not_accepted_keeps_its_verdict() {
    let changed = changed_fulu_block();
    for outcome in [
        Outcome::Queue(QueueReason::ParentUnknown),
        Outcome::Ignore(IgnoreReason::Overloaded),
        Outcome::Reject(RejectReason::BadSignature),
    ] {
        assert_eq!(block_verdict(outcome, &changed, Root::ZERO), outcome);
    }
}

/// Gloas only counts a mismatch until the Amsterdam header is final: an
/// encoding this build gets wrong must not refuse every payload.
#[test]
fn a_gloas_mismatch_is_counted_but_not_refused() {
    let mut changed = envelope();
    changed.message.payload.gas_used += 1;
    assert!(verify_envelope(&changed).is_err());
    for source in [EnvelopeSource::Gossip, EnvelopeSource::Fetch] {
        let accepted = envelope_verdict(Outcome::Accept, &changed, source);
        assert_eq!(accepted, Outcome::Accept, "{source:?}");
        let queued = Outcome::Queue(QueueReason::StateNotCached);
        assert_eq!(envelope_verdict(queued, &changed, source), queued);
    }
}

/// Not a check: how long [`verify_block`] takes, copies included, on the real
/// fulu vector and on fulu blocks filled to the gossip size limit. `#[ignore]`d
/// because it only prints.
///
/// ```text
/// cargo test -p ethlambda-p2p --profile release-fast --lib \
///     payload_hash::tests::verify_block_cost -- --ignored --nocapture --test-threads=1
/// ```
#[test]
#[ignore = "benchmark: prints how long verify_block takes"]
fn verify_block_cost() {
    use std::hint::black_box;
    use std::time::{Duration, Instant};

    use ethlambda_types::beacon::containers::bellatrix::{Transaction, Transactions};
    use ethlambda_types::beacon::preset;

    use crate::req_resp::MAX_PAYLOAD_SIZE;

    fn time(label: &str, block: &SignedBeaconBlock, runs: u32) {
        let SignedBeaconBlock::Fulu(inner) = block else {
            panic!("fulu");
        };
        let transactions = inner.message.body.execution_payload.transactions.len();
        let bytes = block.to_ssz().len();
        assert!(bytes <= MAX_PAYLOAD_SIZE, "{label}: over the gossip limit");
        let _ = black_box(verify_block(black_box(block)));
        let mut fastest = Duration::MAX;
        let mut total = Duration::ZERO;
        for _ in 0..runs {
            let start = Instant::now();
            let _ = black_box(verify_block(black_box(block)));
            let elapsed = start.elapsed();
            fastest = fastest.min(elapsed);
            total += elapsed;
        }
        println!(
            "verify_block_cost {label}: {transactions} transactions, {bytes} SSZ bytes, \
             mean {:?}, min {fastest:?} over {runs} runs",
            total / runs
        );
    }

    /// The fulu vector with its transactions replaced by `count` of `len`
    /// bytes each.
    fn filled(count: usize, len: usize) -> SignedBeaconBlock {
        let mut filled = block(ForkName::Fulu, FULU);
        let transactions: Vec<Transaction> = (0..count)
            .map(|index| {
                let mut tx = vec![0x02u8; len];
                let tail = (index as u32).to_le_bytes();
                let keep = len.min(tail.len());
                tx[len - keep..].copy_from_slice(&tail[..keep]);
                Transaction::try_from(tx).expect("within MAX_BYTES_PER_TRANSACTION")
            })
            .collect();
        fulu_block(&mut filled)
            .message
            .body
            .execution_payload
            .transactions =
            Transactions::try_from(transactions).expect("within MAX_TRANSACTIONS_PER_PAYLOAD");
        filled
    }

    let real = block(ForkName::Fulu, FULU);
    time("mainnet vector", &real, 200);

    // What the block takes besides its transactions; each transaction adds
    // its bytes and a four-byte offset.
    let empty = filled(0, 0);
    let room = MAX_PAYLOAD_SIZE - empty.to_ssz().len();

    // As many transactions as the list allows, as small as the room leaves:
    // the most trie insertions a block at the limit can ask for.
    let count = preset::MAX_TRANSACTIONS_PER_PAYLOAD;
    time(
        "limit, most transactions",
        &filled(count, room / count - 4),
        5,
    );

    // The mainnet vector's mean transaction size.
    let SignedBeaconBlock::Fulu(inner) = &real else {
        panic!("fulu");
    };
    let real_transactions = &inner.message.body.execution_payload.transactions;
    let mean = real_transactions.iter().map(|tx| tx.len()).sum::<usize>() / real_transactions.len();
    time(
        "limit, mainnet-sized transactions",
        &filled(room / (mean + 4), mean),
        10,
    );

    // One transaction holding the whole room: keccak over ten megabytes.
    time("limit, one transaction", &filled(1, room - 4), 10);
}
