//! Every integer in a Beacon API response is a quoted string.
//!
//! A field whose `#[serde(with = …)]` attribute was forgotten serializes as a
//! bare JSON number, which is valid JSON, decodes fine in a permissive client,
//! and is wrong. Nothing in the type system catches it, so this walks the
//! serialized tree and fails on any number it finds.
//!
//! To actually reach a field, the walker has to be handed a value that has
//! one: an empty list never touches its element type, and a state never gets
//! built at all unless something here builds one. So every guard test below
//! is paired with a fixture that populates every collection on the container
//! it checks, at least one level into anything a list or vector holds, with
//! distinct nonzero scalars so a missing attribute cannot hide behind a
//! zero. `fixtures` holds the builders shared across forks (nothing in
//! `shared.rs`, plus the phase0 attestation family altair also uses
//! unchanged); each fork then gets its own `<fork>_block_body`/
//! `<fork>_block`/`<fork>_state` builders for the parts that do change shape,
//! plus a `carries_no_bare_numbers` test per block and per state. Adding a
//! fork means adding one such block of builders and two tests in the same
//! shape, reusing `fixtures` for everything unchanged from phase0.

use ethlambda_types::beacon::containers::{
    altair, bellatrix, capella, deneb, electra, fulu, phase0, shared,
};
use ethlambda_types::beacon::primitives::{
    BlsPubkey, BlsSignature, H160, H256, KzgCommitment, U256,
};
use libssz_types::{SszList, SszVector};

/// Every path in `value` whose leaf is a JSON number.
fn bare_numbers(value: &serde_json::Value, path: &str, found: &mut Vec<String>) {
    match value {
        serde_json::Value::Number(n) => found.push(format!("{path} = {n}")),
        serde_json::Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                bare_numbers(item, &format!("{path}[{i}]"), found);
            }
        }
        serde_json::Value::Object(fields) => {
            for (key, field) in fields {
                bare_numbers(field, &format!("{path}.{key}"), found);
            }
        }
        _ => {}
    }
}

/// Proof that [`bare_numbers`] actually catches what it exists to catch.
///
/// Every other test in this file asserts an *absence* of findings, which
/// passes just as well if the walker is broken and never finds anything. This
/// is the one test that has to see a finding: a `u64` field with no
/// `#[serde(with = …)]` attribute serializes to a bare JSON number, and the
/// walker must name it. Without this, a `bare_numbers` that silently matched
/// nothing would leave every "carries no bare numbers" test in this file
/// passing for the wrong reason.
#[test]
fn the_walker_catches_an_unannotated_integer() {
    #[derive(serde::Serialize)]
    struct Unannotated {
        count: u64,
    }

    let json = serde_json::to_value(Unannotated { count: 7 }).expect("serializes");
    let mut found = Vec::new();
    bare_numbers(&json, "Unannotated", &mut found);
    assert_eq!(found, vec!["Unannotated.count = 7".to_string()]);
}

/// Assert a serialized container carries no bare numbers, naming every one it
/// does carry so a failure points straight at the missing attribute.
pub fn assert_no_bare_numbers<T: serde::Serialize>(label: &str, value: &T) {
    let json = serde_json::to_value(value).expect("serializes");
    let mut found = Vec::new();
    bare_numbers(&json, label, &mut found);
    assert!(
        found.is_empty(),
        "{label}: {} field(s) serialized as bare JSON numbers, each missing a \
         #[serde(with = \"…\")] attribute:\n  {}",
        found.len(),
        found.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Element builders for the fields the guard tests below need populated:
/// everything in `shared.rs`, plus the phase0 attestation family (unchanged
/// through altair).
///
/// Every builder takes a `seed: u8` so two elements of the same field (a
/// `ProposerSlashing`'s two headers, an `AttesterSlashing`'s two
/// attestations) read as distinct in a failure message, and every scalar it
/// sets is derived from the seed so it is never zero.
mod fixtures {
    use super::*;

    /// An `SszVector<T, N>` filled with `N` clones of `value`, for the
    /// fixed-length fields (`block_roots`, `randao_mixes`, a sync
    /// committee's pubkeys, a deposit's merkle proof, …) that need exactly
    /// their declared length rather than "at least one" element.
    pub fn vector<T: Clone, const N: usize>(value: T) -> SszVector<T, N> {
        SszVector::try_from(vec![value; N]).expect("exactly N elements by construction")
    }

    pub fn checkpoint(seed: u8) -> shared::Checkpoint {
        shared::Checkpoint {
            epoch: u64::from(seed) + 1,
            root: H256::repeat_byte(seed),
        }
    }

    pub fn attestation_data(seed: u8) -> shared::AttestationData {
        shared::AttestationData {
            slot: u64::from(seed) + 200,
            index: u64::from(seed) + 1,
            beacon_block_root: H256::repeat_byte(seed.wrapping_add(1)),
            source: checkpoint(seed.wrapping_add(2)),
            target: checkpoint(seed.wrapping_add(3)),
        }
    }

    pub fn eth1_data(seed: u8) -> shared::Eth1Data {
        shared::Eth1Data {
            deposit_root: H256::repeat_byte(seed),
            deposit_count: u64::from(seed) + 1,
            block_hash: H256::repeat_byte(seed.wrapping_add(1)),
        }
    }

    pub fn validator(seed: u8) -> shared::Validator {
        shared::Validator {
            pubkey: BlsPubkey([seed; 48]),
            withdrawal_credentials: H256::repeat_byte(seed.wrapping_add(1)),
            effective_balance: 32_000_000_000 + u64::from(seed),
            slashed: seed % 2 == 1,
            activation_eligibility_epoch: u64::from(seed) + 1,
            activation_epoch: u64::from(seed) + 2,
            exit_epoch: u64::from(seed) + 3,
            withdrawable_epoch: u64::from(seed) + 4,
        }
    }

    pub fn beacon_block_header(seed: u8) -> shared::BeaconBlockHeader {
        shared::BeaconBlockHeader {
            slot: u64::from(seed) + 1,
            proposer_index: u64::from(seed) + 2,
            parent_root: H256::repeat_byte(seed),
            state_root: H256::repeat_byte(seed.wrapping_add(1)),
            body_root: H256::repeat_byte(seed.wrapping_add(2)),
        }
    }

    pub fn signed_beacon_block_header(seed: u8) -> shared::SignedBeaconBlockHeader {
        shared::SignedBeaconBlockHeader {
            message: beacon_block_header(seed),
            signature: BlsSignature([seed; 96]),
        }
    }

    pub fn proposer_slashing(seed: u8) -> shared::ProposerSlashing {
        shared::ProposerSlashing {
            signed_header_1: signed_beacon_block_header(seed),
            signed_header_2: signed_beacon_block_header(seed.wrapping_add(50)),
        }
    }

    pub fn signed_voluntary_exit(seed: u8) -> shared::SignedVoluntaryExit {
        shared::SignedVoluntaryExit {
            message: shared::VoluntaryExit {
                epoch: u64::from(seed) + 1,
                validator_index: u64::from(seed) + 2,
            },
            signature: BlsSignature([seed; 96]),
        }
    }

    /// A deposit with every proof slot filled, not left at its default
    /// length-33 zero vector: `DepositProof` is fixed-size, so it is always
    /// "fully populated" regardless, but a zero proof would still hide a
    /// forgotten annotation on `DepositData`'s scalars behind an
    /// otherwise-unremarkable all-zero neighbour in a failure listing.
    pub fn deposit(seed: u8) -> shared::Deposit {
        shared::Deposit {
            proof: vector(H256::repeat_byte(seed)),
            data: shared::DepositData {
                pubkey: BlsPubkey([seed; 48]),
                withdrawal_credentials: H256::repeat_byte(seed.wrapping_add(1)),
                amount: 32_000_000_000 + u64::from(seed),
                signature: BlsSignature([seed.wrapping_add(2); 96]),
            },
        }
    }

    /// An aggregate attestation with a nonempty `aggregation_bits`, the
    /// phase0 shape altair, bellatrix, capella, and deneb all reuse
    /// unchanged.
    pub fn attestation(seed: u8) -> phase0::Attestation {
        let mut bits = phase0::AggregationBits::with_length(8).expect("within capacity");
        bits.set(usize::from(seed % 8), true).expect("in bounds");
        phase0::Attestation {
            aggregation_bits: bits,
            data: attestation_data(seed),
            signature: BlsSignature([seed; 96]),
        }
    }

    /// An indexed attestation with a nonempty `attesting_indices`, which is
    /// the list one level below `AttesterSlashing` that an empty-body test
    /// would never reach.
    pub fn indexed_attestation(seed: u8) -> phase0::IndexedAttestation {
        phase0::IndexedAttestation {
            attesting_indices: SszList::try_from(vec![u64::from(seed) + 1, u64::from(seed) + 2])
                .expect("within capacity"),
            data: attestation_data(seed),
            signature: BlsSignature([seed; 96]),
        }
    }

    pub fn attester_slashing(seed: u8) -> phase0::AttesterSlashing {
        phase0::AttesterSlashing {
            attestation_1: indexed_attestation(seed),
            attestation_2: indexed_attestation(seed.wrapping_add(50)),
        }
    }

    /// Capella-onward: one validator's withdrawal payout. Shared here rather
    /// than defined per fork since deneb and electra carry `Withdrawal`
    /// unchanged.
    pub fn withdrawal(seed: u8) -> capella::Withdrawal {
        capella::Withdrawal {
            index: u64::from(seed) + 1,
            validator_index: u64::from(seed) + 2,
            address: H160::repeat_byte(seed.wrapping_add(3)),
            amount: 32_000_000_000 + u64::from(seed),
        }
    }

    /// Capella-onward: a validator's signed withdrawal-credential switch.
    /// Shared here for the same reason as [`withdrawal`].
    pub fn signed_bls_to_execution_change(seed: u8) -> capella::SignedBLSToExecutionChange {
        capella::SignedBLSToExecutionChange {
            message: capella::BLSToExecutionChange {
                validator_index: u64::from(seed) + 1,
                from_bls_pubkey: BlsPubkey([seed; 48]),
                to_execution_address: H160::repeat_byte(seed.wrapping_add(1)),
            },
            signature: BlsSignature([seed; 96]),
        }
    }

    /// Electra-onward: a deposit queued in the state, not yet credited to the
    /// validator registry. Shared here since fulu's `PendingDeposits` is
    /// electra's type, unchanged.
    pub fn pending_deposit(seed: u8) -> electra::PendingDeposit {
        electra::PendingDeposit {
            pubkey: BlsPubkey([seed; 48]),
            withdrawal_credentials: H256::repeat_byte(seed.wrapping_add(1)),
            amount: 32_000_000_000 + u64::from(seed),
            signature: BlsSignature([seed.wrapping_add(2); 96]),
            slot: u64::from(seed) + 3,
        }
    }

    /// Electra-onward: a partial withdrawal queued in the state, not yet paid
    /// out. Shared here for the same reason as [`pending_deposit`].
    pub fn pending_partial_withdrawal(seed: u8) -> electra::PendingPartialWithdrawal {
        electra::PendingPartialWithdrawal {
            validator_index: u64::from(seed) + 1,
            amount: 32_000_000_000 + u64::from(seed),
            withdrawable_epoch: u64::from(seed) + 2,
        }
    }

    /// Electra-onward: a validator consolidation queued in the state, not yet
    /// applied. Shared here for the same reason as [`pending_deposit`].
    pub fn pending_consolidation(seed: u8) -> electra::PendingConsolidation {
        electra::PendingConsolidation {
            source_index: u64::from(seed) + 1,
            target_index: u64::from(seed) + 2,
        }
    }
}

// ---------------------------------------------------------------------------
// Phase0
// ---------------------------------------------------------------------------

/// A body with one element in every `SszList` field, so each element type
/// (`Attestation`, `AttesterSlashing` and the `IndexedAttestation`s inside
/// it, `Deposit` and the proof vector inside it, `ProposerSlashing`,
/// `SignedVoluntaryExit`) is actually walked instead of serializing as `[]`.
fn phase0_block_body() -> phase0::BeaconBlockBody {
    phase0::BeaconBlockBody {
        randao_reveal: BlsSignature([0x44; 96]),
        eth1_data: fixtures::eth1_data(1),
        graffiti: H256::repeat_byte(0x55),
        proposer_slashings: SszList::try_from(vec![fixtures::proposer_slashing(2)])
            .expect("within capacity"),
        attester_slashings: SszList::try_from(vec![fixtures::attester_slashing(3)])
            .expect("within capacity"),
        attestations: SszList::try_from(vec![fixtures::attestation(4)]).expect("within capacity"),
        deposits: SszList::try_from(vec![fixtures::deposit(5)]).expect("within capacity"),
        voluntary_exits: SszList::try_from(vec![fixtures::signed_voluntary_exit(6)])
            .expect("within capacity"),
    }
}

fn phase0_block() -> phase0::SignedBeaconBlock {
    phase0::SignedBeaconBlock {
        message: phase0::BeaconBlock {
            slot: 12_345,
            proposer_index: 7,
            parent_root: H256([0x11; 32]),
            state_root: H256([0x22; 32]),
            body: phase0_block_body(),
        },
        signature: BlsSignature([0x33; 96]),
    }
}

/// Phase0-only: dropped from altair onward in favour of participation flags,
/// so it has no place in `fixtures`.
fn pending_attestation(seed: u8) -> phase0::PendingAttestation {
    let mut bits = phase0::AggregationBits::with_length(4).expect("within capacity");
    bits.set(0, true).expect("in bounds");
    phase0::PendingAttestation {
        aggregation_bits: bits,
        data: fixtures::attestation_data(seed),
        inclusion_delay: u64::from(seed) + 1,
        proposer_index: u64::from(seed) + 2,
    }
}

/// A state with every one of its 21 fields set: fixed-size vectors filled to
/// their declared length, lists given at least one element, and every scalar
/// nonzero, so nothing serializes as an empty collection or a suspiciously
/// absent field.
fn phase0_state() -> phase0::BeaconState {
    phase0::BeaconState {
        genesis_time: 1_700_000_000,
        genesis_validators_root: H256::repeat_byte(0x66),
        slot: 42,
        fork: shared::Fork {
            previous_version: [0x01, 0x02, 0x03, 0x04],
            current_version: [0x05, 0x06, 0x07, 0x08],
            epoch: 1,
        },
        latest_block_header: fixtures::beacon_block_header(7),
        block_roots: fixtures::vector(H256::repeat_byte(0x77)),
        state_roots: fixtures::vector(H256::repeat_byte(0x88)),
        historical_roots: SszList::try_from(vec![H256::repeat_byte(0x99)])
            .expect("within capacity"),
        eth1_data: fixtures::eth1_data(8),
        eth1_data_votes: SszList::try_from(vec![fixtures::eth1_data(9)]).expect("within capacity"),
        eth1_deposit_index: 3,
        validators: shared::Validators::try_from(vec![fixtures::validator(10)])
            .expect("within capacity"),
        balances: shared::Balances::try_from(vec![32_000_000_001u64]).expect("within capacity"),
        randao_mixes: fixtures::vector(H256::repeat_byte(0xaa)),
        slashings: fixtures::vector(1_000_000_000u64),
        previous_epoch_attestations: SszList::try_from(vec![pending_attestation(11)])
            .expect("within capacity"),
        current_epoch_attestations: SszList::try_from(vec![pending_attestation(12)])
            .expect("within capacity"),
        justification_bits: {
            let mut bits = shared::JustificationBits::new();
            bits.set(0, true).expect("in bounds");
            bits
        },
        previous_justified_checkpoint: fixtures::checkpoint(13),
        current_justified_checkpoint: fixtures::checkpoint(14),
        finalized_checkpoint: fixtures::checkpoint(15),
    }
}

#[test]
fn a_phase0_block_carries_no_bare_numbers() {
    assert_no_bare_numbers("phase0::SignedBeaconBlock", &phase0_block());
}

#[test]
fn a_phase0_block_quotes_its_slot_and_hexes_its_roots() {
    let json = serde_json::to_value(phase0_block()).unwrap();
    assert_eq!(json["message"]["slot"], "12345");
    assert_eq!(json["message"]["proposer_index"], "7");
    assert_eq!(
        json["message"]["parent_root"],
        "0x1111111111111111111111111111111111111111111111111111111111111111"
    );
    assert!(
        json["signature"].as_str().unwrap().starts_with("0x3333"),
        "got {}",
        json["signature"]
    );
}

#[test]
fn a_phase0_state_carries_no_bare_numbers() {
    assert_no_bare_numbers("phase0::BeaconState", &phase0_state());
}

// ---------------------------------------------------------------------------
// Altair
// ---------------------------------------------------------------------------

/// Phase0's body plus a populated `sync_aggregate`, altair's one addition to
/// the block body.
fn altair_block_body() -> altair::BeaconBlockBody {
    altair::BeaconBlockBody {
        randao_reveal: BlsSignature([0x44; 96]),
        eth1_data: fixtures::eth1_data(1),
        graffiti: H256::repeat_byte(0x55),
        proposer_slashings: SszList::try_from(vec![fixtures::proposer_slashing(2)])
            .expect("within capacity"),
        attester_slashings: SszList::try_from(vec![fixtures::attester_slashing(3)])
            .expect("within capacity"),
        attestations: SszList::try_from(vec![fixtures::attestation(4)]).expect("within capacity"),
        deposits: SszList::try_from(vec![fixtures::deposit(5)]).expect("within capacity"),
        voluntary_exits: SszList::try_from(vec![fixtures::signed_voluntary_exit(6)])
            .expect("within capacity"),
        sync_aggregate: altair::SyncAggregate {
            sync_committee_bits: {
                let mut bits = altair::SyncCommitteeBits::new();
                bits.set(0, true).expect("in bounds");
                bits
            },
            sync_committee_signature: BlsSignature([0x99; 96]),
        },
    }
}

fn altair_block() -> altair::SignedBeaconBlock {
    altair::SignedBeaconBlock {
        message: altair::BeaconBlock {
            slot: 12_345,
            proposer_index: 7,
            parent_root: H256([0x11; 32]),
            state_root: H256([0x22; 32]),
            body: altair_block_body(),
        },
        signature: BlsSignature([0x33; 96]),
    }
}

/// Altair-only: `SyncCommittee`'s `pubkeys` vector needs exactly
/// `SYNC_COMMITTEE_SIZE` entries, which no list-population helper covers.
fn sync_committee(seed: u8) -> altair::SyncCommittee {
    altair::SyncCommittee {
        pubkeys: fixtures::vector(BlsPubkey([seed; 48])),
        aggregate_pubkey: BlsPubkey([seed.wrapping_add(1); 48]),
    }
}

/// Phase0's 21 fields through `slashings`, altair's participation flags and
/// inactivity scores in place of the dropped pending-attestation lists, and
/// the two sync committees altair appends: 24 fields in all.
fn altair_state() -> altair::BeaconState {
    altair::BeaconState {
        genesis_time: 1_700_000_000,
        genesis_validators_root: H256::repeat_byte(0x66),
        slot: 42,
        fork: shared::Fork {
            previous_version: [0x01, 0x02, 0x03, 0x04],
            current_version: [0x05, 0x06, 0x07, 0x08],
            epoch: 1,
        },
        latest_block_header: fixtures::beacon_block_header(7),
        block_roots: fixtures::vector(H256::repeat_byte(0x77)),
        state_roots: fixtures::vector(H256::repeat_byte(0x88)),
        historical_roots: SszList::try_from(vec![H256::repeat_byte(0x99)])
            .expect("within capacity"),
        eth1_data: fixtures::eth1_data(8),
        eth1_data_votes: SszList::try_from(vec![fixtures::eth1_data(9)]).expect("within capacity"),
        eth1_deposit_index: 3,
        validators: shared::Validators::try_from(vec![fixtures::validator(10)])
            .expect("within capacity"),
        balances: shared::Balances::try_from(vec![32_000_000_001u64]).expect("within capacity"),
        randao_mixes: fixtures::vector(H256::repeat_byte(0xaa)),
        slashings: fixtures::vector(1_000_000_000u64),
        previous_epoch_participation: SszList::try_from(vec![7u8]).expect("within capacity"),
        current_epoch_participation: SszList::try_from(vec![9u8]).expect("within capacity"),
        justification_bits: {
            let mut bits = shared::JustificationBits::new();
            bits.set(0, true).expect("in bounds");
            bits
        },
        previous_justified_checkpoint: fixtures::checkpoint(13),
        current_justified_checkpoint: fixtures::checkpoint(14),
        finalized_checkpoint: fixtures::checkpoint(15),
        inactivity_scores: vec![4u64].try_into().expect("within capacity"),
        current_sync_committee: sync_committee(16),
        next_sync_committee: sync_committee(17),
    }
}

#[test]
fn an_altair_block_carries_no_bare_numbers() {
    assert_no_bare_numbers("altair::SignedBeaconBlock", &altair_block());
}

#[test]
fn an_altair_state_carries_no_bare_numbers() {
    assert_no_bare_numbers("altair::BeaconState", &altair_state());
}

// ---------------------------------------------------------------------------
// Bellatrix
// ---------------------------------------------------------------------------

/// An execution payload with `logs_bloom` filled to its exact length and
/// `extra_data`/`transactions` each holding a nonempty, nonzero element, so
/// `Transaction` — a byte list one level below `transactions` an empty-body
/// test would never reach — is actually walked.
fn execution_payload(seed: u8) -> bellatrix::ExecutionPayload {
    bellatrix::ExecutionPayload {
        parent_hash: H256::repeat_byte(seed),
        fee_recipient: H160::repeat_byte(seed.wrapping_add(1)),
        state_root: H256::repeat_byte(seed.wrapping_add(2)),
        receipts_root: H256::repeat_byte(seed.wrapping_add(3)),
        logs_bloom: fixtures::vector(seed.wrapping_add(4)),
        prev_randao: H256::repeat_byte(seed.wrapping_add(5)),
        block_number: u64::from(seed) + 1,
        gas_limit: u64::from(seed) + 2,
        gas_used: u64::from(seed) + 3,
        timestamp: u64::from(seed) + 4,
        extra_data: SszList::try_from(vec![seed.wrapping_add(6), seed.wrapping_add(7)])
            .expect("within capacity"),
        base_fee_per_gas: U256::from(u64::from(seed) + 5),
        block_hash: H256::repeat_byte(seed.wrapping_add(8)),
        transactions: SszList::try_from(vec![
            bellatrix::Transaction::try_from(vec![seed.wrapping_add(9), seed.wrapping_add(10)])
                .expect("within capacity"),
        ])
        .expect("within capacity"),
    }
}

/// [`execution_payload`] with `transactions` replaced by `transactions_root`,
/// the same substitution [`bellatrix::ExecutionPayloadHeader`] makes.
fn execution_payload_header(seed: u8) -> bellatrix::ExecutionPayloadHeader {
    bellatrix::ExecutionPayloadHeader {
        parent_hash: H256::repeat_byte(seed),
        fee_recipient: H160::repeat_byte(seed.wrapping_add(1)),
        state_root: H256::repeat_byte(seed.wrapping_add(2)),
        receipts_root: H256::repeat_byte(seed.wrapping_add(3)),
        logs_bloom: fixtures::vector(seed.wrapping_add(4)),
        prev_randao: H256::repeat_byte(seed.wrapping_add(5)),
        block_number: u64::from(seed) + 1,
        gas_limit: u64::from(seed) + 2,
        gas_used: u64::from(seed) + 3,
        timestamp: u64::from(seed) + 4,
        extra_data: SszList::try_from(vec![seed.wrapping_add(6), seed.wrapping_add(7)])
            .expect("within capacity"),
        base_fee_per_gas: U256::from(u64::from(seed) + 5),
        block_hash: H256::repeat_byte(seed.wrapping_add(8)),
        transactions_root: H256::repeat_byte(seed.wrapping_add(9)),
    }
}

/// Altair's body plus a populated `execution_payload`, bellatrix's one
/// addition to the block body.
fn bellatrix_block_body() -> bellatrix::BeaconBlockBody {
    bellatrix::BeaconBlockBody {
        randao_reveal: BlsSignature([0x44; 96]),
        eth1_data: fixtures::eth1_data(1),
        graffiti: H256::repeat_byte(0x55),
        proposer_slashings: SszList::try_from(vec![fixtures::proposer_slashing(2)])
            .expect("within capacity"),
        attester_slashings: SszList::try_from(vec![fixtures::attester_slashing(3)])
            .expect("within capacity"),
        attestations: SszList::try_from(vec![fixtures::attestation(4)]).expect("within capacity"),
        deposits: SszList::try_from(vec![fixtures::deposit(5)]).expect("within capacity"),
        voluntary_exits: SszList::try_from(vec![fixtures::signed_voluntary_exit(6)])
            .expect("within capacity"),
        sync_aggregate: altair::SyncAggregate {
            sync_committee_bits: {
                let mut bits = altair::SyncCommitteeBits::new();
                bits.set(0, true).expect("in bounds");
                bits
            },
            sync_committee_signature: BlsSignature([0x99; 96]),
        },
        execution_payload: execution_payload(20),
    }
}

fn bellatrix_block() -> bellatrix::SignedBeaconBlock {
    bellatrix::SignedBeaconBlock {
        message: bellatrix::BeaconBlock {
            slot: 12_345,
            proposer_index: 7,
            parent_root: H256([0x11; 32]),
            state_root: H256([0x22; 32]),
            body: bellatrix_block_body(),
        },
        signature: BlsSignature([0x33; 96]),
    }
}

/// Altair's 24 fields through `next_sync_committee` unchanged, plus
/// `latest_execution_payload_header`, bellatrix's one addition: 25 fields in
/// all.
fn bellatrix_state() -> bellatrix::BeaconState {
    bellatrix::BeaconState {
        genesis_time: 1_700_000_000,
        genesis_validators_root: H256::repeat_byte(0x66),
        slot: 42,
        fork: shared::Fork {
            previous_version: [0x01, 0x02, 0x03, 0x04],
            current_version: [0x05, 0x06, 0x07, 0x08],
            epoch: 1,
        },
        latest_block_header: fixtures::beacon_block_header(7),
        block_roots: fixtures::vector(H256::repeat_byte(0x77)),
        state_roots: fixtures::vector(H256::repeat_byte(0x88)),
        historical_roots: SszList::try_from(vec![H256::repeat_byte(0x99)])
            .expect("within capacity"),
        eth1_data: fixtures::eth1_data(8),
        eth1_data_votes: SszList::try_from(vec![fixtures::eth1_data(9)]).expect("within capacity"),
        eth1_deposit_index: 3,
        validators: shared::Validators::try_from(vec![fixtures::validator(10)])
            .expect("within capacity"),
        balances: shared::Balances::try_from(vec![32_000_000_001u64]).expect("within capacity"),
        randao_mixes: fixtures::vector(H256::repeat_byte(0xaa)),
        slashings: fixtures::vector(1_000_000_000u64),
        previous_epoch_participation: SszList::try_from(vec![7u8]).expect("within capacity"),
        current_epoch_participation: SszList::try_from(vec![9u8]).expect("within capacity"),
        justification_bits: {
            let mut bits = shared::JustificationBits::new();
            bits.set(0, true).expect("in bounds");
            bits
        },
        previous_justified_checkpoint: fixtures::checkpoint(13),
        current_justified_checkpoint: fixtures::checkpoint(14),
        finalized_checkpoint: fixtures::checkpoint(15),
        inactivity_scores: vec![4u64].try_into().expect("within capacity"),
        current_sync_committee: sync_committee(16),
        next_sync_committee: sync_committee(17),
        latest_execution_payload_header: execution_payload_header(30),
    }
}

#[test]
fn a_bellatrix_block_carries_no_bare_numbers() {
    assert_no_bare_numbers("bellatrix::SignedBeaconBlock", &bellatrix_block());
}

#[test]
fn a_bellatrix_state_carries_no_bare_numbers() {
    assert_no_bare_numbers("bellatrix::BeaconState", &bellatrix_state());
}

// ---------------------------------------------------------------------------
// Capella
// ---------------------------------------------------------------------------

/// Bellatrix's execution payload fields, with a nonempty `withdrawals`
/// appended — capella's one addition to the payload shape. `transactions`
/// stays nonempty too, so [`crate::beacon::serde_helpers::ssz_hex_seq`] (via
/// `serde_helpers::ssz_hex_seq::serialize`, shared with bellatrix's own
/// `ExecutionPayload`) is actually walked rather than serializing as `[]`.
fn capella_execution_payload(seed: u8) -> capella::ExecutionPayload {
    capella::ExecutionPayload {
        parent_hash: H256::repeat_byte(seed),
        fee_recipient: H160::repeat_byte(seed.wrapping_add(1)),
        state_root: H256::repeat_byte(seed.wrapping_add(2)),
        receipts_root: H256::repeat_byte(seed.wrapping_add(3)),
        logs_bloom: fixtures::vector(seed.wrapping_add(4)),
        prev_randao: H256::repeat_byte(seed.wrapping_add(5)),
        block_number: u64::from(seed) + 1,
        gas_limit: u64::from(seed) + 2,
        gas_used: u64::from(seed) + 3,
        timestamp: u64::from(seed) + 4,
        extra_data: SszList::try_from(vec![seed.wrapping_add(6), seed.wrapping_add(7)])
            .expect("within capacity"),
        base_fee_per_gas: U256::from(u64::from(seed) + 5),
        block_hash: H256::repeat_byte(seed.wrapping_add(8)),
        transactions: SszList::try_from(vec![
            bellatrix::Transaction::try_from(vec![seed.wrapping_add(9), seed.wrapping_add(10)])
                .expect("within capacity"),
        ])
        .expect("within capacity"),
        withdrawals: SszList::try_from(vec![fixtures::withdrawal(seed.wrapping_add(11))])
            .expect("within capacity"),
    }
}

/// Bellatrix's header fields plus `withdrawals_root`, capella's one addition
/// to the execution payload header shape.
fn capella_execution_payload_header(seed: u8) -> capella::ExecutionPayloadHeader {
    capella::ExecutionPayloadHeader {
        parent_hash: H256::repeat_byte(seed),
        fee_recipient: H160::repeat_byte(seed.wrapping_add(1)),
        state_root: H256::repeat_byte(seed.wrapping_add(2)),
        receipts_root: H256::repeat_byte(seed.wrapping_add(3)),
        logs_bloom: fixtures::vector(seed.wrapping_add(4)),
        prev_randao: H256::repeat_byte(seed.wrapping_add(5)),
        block_number: u64::from(seed) + 1,
        gas_limit: u64::from(seed) + 2,
        gas_used: u64::from(seed) + 3,
        timestamp: u64::from(seed) + 4,
        extra_data: SszList::try_from(vec![seed.wrapping_add(6), seed.wrapping_add(7)])
            .expect("within capacity"),
        base_fee_per_gas: U256::from(u64::from(seed) + 5),
        block_hash: H256::repeat_byte(seed.wrapping_add(8)),
        transactions_root: H256::repeat_byte(seed.wrapping_add(9)),
        withdrawals_root: H256::repeat_byte(seed.wrapping_add(10)),
    }
}

/// Bellatrix's body plus a populated `bls_to_execution_changes`, capella's
/// one addition to the block body.
fn capella_block_body() -> capella::BeaconBlockBody {
    capella::BeaconBlockBody {
        randao_reveal: BlsSignature([0x44; 96]),
        eth1_data: fixtures::eth1_data(1),
        graffiti: H256::repeat_byte(0x55),
        proposer_slashings: SszList::try_from(vec![fixtures::proposer_slashing(2)])
            .expect("within capacity"),
        attester_slashings: SszList::try_from(vec![fixtures::attester_slashing(3)])
            .expect("within capacity"),
        attestations: SszList::try_from(vec![fixtures::attestation(4)]).expect("within capacity"),
        deposits: SszList::try_from(vec![fixtures::deposit(5)]).expect("within capacity"),
        voluntary_exits: SszList::try_from(vec![fixtures::signed_voluntary_exit(6)])
            .expect("within capacity"),
        sync_aggregate: altair::SyncAggregate {
            sync_committee_bits: {
                let mut bits = altair::SyncCommitteeBits::new();
                bits.set(0, true).expect("in bounds");
                bits
            },
            sync_committee_signature: BlsSignature([0x99; 96]),
        },
        execution_payload: capella_execution_payload(20),
        bls_to_execution_changes: SszList::try_from(vec![
            fixtures::signed_bls_to_execution_change(40),
        ])
        .expect("within capacity"),
    }
}

fn capella_block() -> capella::SignedBeaconBlock {
    capella::SignedBeaconBlock {
        message: capella::BeaconBlock {
            slot: 12_345,
            proposer_index: 7,
            parent_root: H256([0x11; 32]),
            state_root: H256([0x22; 32]),
            body: capella_block_body(),
        },
        signature: BlsSignature([0x33; 96]),
    }
}

/// Bellatrix's 25 fields through `latest_execution_payload_header` (capella's
/// own header shape, with `withdrawals_root` appended), plus
/// `next_withdrawal_index`, `next_withdrawal_validator_index`, and
/// `historical_summaries`: 28 fields in all.
fn capella_state() -> capella::BeaconState {
    capella::BeaconState {
        genesis_time: 1_700_000_000,
        genesis_validators_root: H256::repeat_byte(0x66),
        slot: 42,
        fork: shared::Fork {
            previous_version: [0x01, 0x02, 0x03, 0x04],
            current_version: [0x05, 0x06, 0x07, 0x08],
            epoch: 1,
        },
        latest_block_header: fixtures::beacon_block_header(7),
        block_roots: fixtures::vector(H256::repeat_byte(0x77)),
        state_roots: fixtures::vector(H256::repeat_byte(0x88)),
        historical_roots: SszList::try_from(vec![H256::repeat_byte(0x99)])
            .expect("within capacity"),
        eth1_data: fixtures::eth1_data(8),
        eth1_data_votes: SszList::try_from(vec![fixtures::eth1_data(9)]).expect("within capacity"),
        eth1_deposit_index: 3,
        validators: shared::Validators::try_from(vec![fixtures::validator(10)])
            .expect("within capacity"),
        balances: shared::Balances::try_from(vec![32_000_000_001u64]).expect("within capacity"),
        randao_mixes: fixtures::vector(H256::repeat_byte(0xaa)),
        slashings: fixtures::vector(1_000_000_000u64),
        previous_epoch_participation: SszList::try_from(vec![7u8]).expect("within capacity"),
        current_epoch_participation: SszList::try_from(vec![9u8]).expect("within capacity"),
        justification_bits: {
            let mut bits = shared::JustificationBits::new();
            bits.set(0, true).expect("in bounds");
            bits
        },
        previous_justified_checkpoint: fixtures::checkpoint(13),
        current_justified_checkpoint: fixtures::checkpoint(14),
        finalized_checkpoint: fixtures::checkpoint(15),
        inactivity_scores: vec![4u64].try_into().expect("within capacity"),
        current_sync_committee: sync_committee(16),
        next_sync_committee: sync_committee(17),
        latest_execution_payload_header: capella_execution_payload_header(30),
        next_withdrawal_index: 40,
        next_withdrawal_validator_index: 41,
        historical_summaries: SszList::try_from(vec![shared::HistoricalSummary {
            block_summary_root: H256::repeat_byte(0xbb),
            state_summary_root: H256::repeat_byte(0xcc),
        }])
        .expect("within capacity"),
    }
}

#[test]
fn a_capella_block_carries_no_bare_numbers() {
    assert_no_bare_numbers("capella::SignedBeaconBlock", &capella_block());
}

#[test]
fn a_capella_state_carries_no_bare_numbers() {
    assert_no_bare_numbers("capella::BeaconState", &capella_state());
}

// ---------------------------------------------------------------------------
// Deneb
// ---------------------------------------------------------------------------

/// Capella's execution payload fields, with `blob_gas_used` and
/// `excess_blob_gas` appended — deneb's one addition to the payload shape.
/// `transactions` and `withdrawals` stay nonempty, same as capella's own
/// fixture, so both remain walked rather than serializing as `[]`.
fn deneb_execution_payload(seed: u8) -> deneb::ExecutionPayload {
    deneb::ExecutionPayload {
        parent_hash: H256::repeat_byte(seed),
        fee_recipient: H160::repeat_byte(seed.wrapping_add(1)),
        state_root: H256::repeat_byte(seed.wrapping_add(2)),
        receipts_root: H256::repeat_byte(seed.wrapping_add(3)),
        logs_bloom: fixtures::vector(seed.wrapping_add(4)),
        prev_randao: H256::repeat_byte(seed.wrapping_add(5)),
        block_number: u64::from(seed) + 1,
        gas_limit: u64::from(seed) + 2,
        gas_used: u64::from(seed) + 3,
        timestamp: u64::from(seed) + 4,
        extra_data: SszList::try_from(vec![seed.wrapping_add(6), seed.wrapping_add(7)])
            .expect("within capacity"),
        base_fee_per_gas: U256::from(u64::from(seed) + 5),
        block_hash: H256::repeat_byte(seed.wrapping_add(8)),
        transactions: SszList::try_from(vec![
            bellatrix::Transaction::try_from(vec![seed.wrapping_add(9), seed.wrapping_add(10)])
                .expect("within capacity"),
        ])
        .expect("within capacity"),
        withdrawals: SszList::try_from(vec![fixtures::withdrawal(seed.wrapping_add(11))])
            .expect("within capacity"),
        blob_gas_used: u64::from(seed) + 12,
        excess_blob_gas: u64::from(seed) + 13,
    }
}

/// [`deneb_execution_payload`] with `transactions`/`withdrawals` replaced by
/// their roots, the same substitution [`deneb::ExecutionPayloadHeader`]
/// makes.
fn deneb_execution_payload_header(seed: u8) -> deneb::ExecutionPayloadHeader {
    deneb::ExecutionPayloadHeader {
        parent_hash: H256::repeat_byte(seed),
        fee_recipient: H160::repeat_byte(seed.wrapping_add(1)),
        state_root: H256::repeat_byte(seed.wrapping_add(2)),
        receipts_root: H256::repeat_byte(seed.wrapping_add(3)),
        logs_bloom: fixtures::vector(seed.wrapping_add(4)),
        prev_randao: H256::repeat_byte(seed.wrapping_add(5)),
        block_number: u64::from(seed) + 1,
        gas_limit: u64::from(seed) + 2,
        gas_used: u64::from(seed) + 3,
        timestamp: u64::from(seed) + 4,
        extra_data: SszList::try_from(vec![seed.wrapping_add(6), seed.wrapping_add(7)])
            .expect("within capacity"),
        base_fee_per_gas: U256::from(u64::from(seed) + 5),
        block_hash: H256::repeat_byte(seed.wrapping_add(8)),
        transactions_root: H256::repeat_byte(seed.wrapping_add(9)),
        withdrawals_root: H256::repeat_byte(seed.wrapping_add(10)),
        blob_gas_used: u64::from(seed) + 11,
        excess_blob_gas: u64::from(seed) + 12,
    }
}

/// Capella's body plus a populated `blob_kzg_commitments`, deneb's one
/// addition to the block body.
fn deneb_block_body() -> deneb::BeaconBlockBody {
    deneb::BeaconBlockBody {
        randao_reveal: BlsSignature([0x44; 96]),
        eth1_data: fixtures::eth1_data(1),
        graffiti: H256::repeat_byte(0x55),
        proposer_slashings: SszList::try_from(vec![fixtures::proposer_slashing(2)])
            .expect("within capacity"),
        attester_slashings: SszList::try_from(vec![fixtures::attester_slashing(3)])
            .expect("within capacity"),
        attestations: SszList::try_from(vec![fixtures::attestation(4)]).expect("within capacity"),
        deposits: SszList::try_from(vec![fixtures::deposit(5)]).expect("within capacity"),
        voluntary_exits: SszList::try_from(vec![fixtures::signed_voluntary_exit(6)])
            .expect("within capacity"),
        sync_aggregate: altair::SyncAggregate {
            sync_committee_bits: {
                let mut bits = altair::SyncCommitteeBits::new();
                bits.set(0, true).expect("in bounds");
                bits
            },
            sync_committee_signature: BlsSignature([0x99; 96]),
        },
        execution_payload: deneb_execution_payload(20),
        bls_to_execution_changes: SszList::try_from(vec![
            fixtures::signed_bls_to_execution_change(40),
        ])
        .expect("within capacity"),
        blob_kzg_commitments: SszList::try_from(vec![KzgCommitment([0x77; 48])])
            .expect("within capacity"),
    }
}

fn deneb_block() -> deneb::SignedBeaconBlock {
    deneb::SignedBeaconBlock {
        message: deneb::BeaconBlock {
            slot: 12_345,
            proposer_index: 7,
            parent_root: H256([0x11; 32]),
            state_root: H256([0x22; 32]),
            body: deneb_block_body(),
        },
        signature: BlsSignature([0x33; 96]),
    }
}

/// Capella's 28 fields, field for field: only the type held in
/// `latest_execution_payload_header` changes, to deneb's own
/// [`deneb::ExecutionPayloadHeader`].
fn deneb_state() -> deneb::BeaconState {
    deneb::BeaconState {
        genesis_time: 1_700_000_000,
        genesis_validators_root: H256::repeat_byte(0x66),
        slot: 42,
        fork: shared::Fork {
            previous_version: [0x01, 0x02, 0x03, 0x04],
            current_version: [0x05, 0x06, 0x07, 0x08],
            epoch: 1,
        },
        latest_block_header: fixtures::beacon_block_header(7),
        block_roots: fixtures::vector(H256::repeat_byte(0x77)),
        state_roots: fixtures::vector(H256::repeat_byte(0x88)),
        historical_roots: SszList::try_from(vec![H256::repeat_byte(0x99)])
            .expect("within capacity"),
        eth1_data: fixtures::eth1_data(8),
        eth1_data_votes: SszList::try_from(vec![fixtures::eth1_data(9)]).expect("within capacity"),
        eth1_deposit_index: 3,
        validators: shared::Validators::try_from(vec![fixtures::validator(10)])
            .expect("within capacity"),
        balances: shared::Balances::try_from(vec![32_000_000_001u64]).expect("within capacity"),
        randao_mixes: fixtures::vector(H256::repeat_byte(0xaa)),
        slashings: fixtures::vector(1_000_000_000u64),
        previous_epoch_participation: SszList::try_from(vec![7u8]).expect("within capacity"),
        current_epoch_participation: SszList::try_from(vec![9u8]).expect("within capacity"),
        justification_bits: {
            let mut bits = shared::JustificationBits::new();
            bits.set(0, true).expect("in bounds");
            bits
        },
        previous_justified_checkpoint: fixtures::checkpoint(13),
        current_justified_checkpoint: fixtures::checkpoint(14),
        finalized_checkpoint: fixtures::checkpoint(15),
        inactivity_scores: vec![4u64].try_into().expect("within capacity"),
        current_sync_committee: sync_committee(16),
        next_sync_committee: sync_committee(17),
        latest_execution_payload_header: deneb_execution_payload_header(30),
        next_withdrawal_index: 40,
        next_withdrawal_validator_index: 41,
        historical_summaries: SszList::try_from(vec![shared::HistoricalSummary {
            block_summary_root: H256::repeat_byte(0xbb),
            state_summary_root: H256::repeat_byte(0xcc),
        }])
        .expect("within capacity"),
    }
}

#[test]
fn a_deneb_block_carries_no_bare_numbers() {
    assert_no_bare_numbers("deneb::SignedBeaconBlock", &deneb_block());
}

#[test]
fn a_deneb_state_carries_no_bare_numbers() {
    assert_no_bare_numbers("deneb::BeaconState", &deneb_state());
}

// ---------------------------------------------------------------------------
// Electra
// ---------------------------------------------------------------------------

/// Electra's aggregate attestation (EIP-7549): `aggregation_bits` now spans
/// every committee named in `committee_bits`, rather than one committee's
/// worth as in every fork before electra, so this needs its own fixture
/// distinct from [`fixtures::attestation`].
fn electra_attestation(seed: u8) -> electra::Attestation {
    let mut committee_bits = electra::CommitteeBits::default();
    committee_bits.set(0, true).expect("in bounds");
    let mut aggregation_bits = electra::AggregationBits::with_length(8).expect("within capacity");
    aggregation_bits
        .set(usize::from(seed % 8), true)
        .expect("in bounds");
    electra::Attestation {
        aggregation_bits,
        data: fixtures::attestation_data(seed),
        signature: BlsSignature([seed; 96]),
        committee_bits,
    }
}

/// Electra's indexed attestation: `attesting_indices` widens the same way
/// `aggregation_bits` does, following [`electra::AttestingIndices`].
fn electra_indexed_attestation(seed: u8) -> electra::IndexedAttestation {
    electra::IndexedAttestation {
        attesting_indices: SszList::try_from(vec![u64::from(seed) + 1, u64::from(seed) + 2])
            .expect("within capacity"),
        data: fixtures::attestation_data(seed),
        signature: BlsSignature([seed; 96]),
    }
}

fn electra_attester_slashing(seed: u8) -> electra::AttesterSlashing {
    electra::AttesterSlashing {
        attestation_1: electra_indexed_attestation(seed),
        attestation_2: electra_indexed_attestation(seed.wrapping_add(50)),
    }
}

fn deposit_request(seed: u8) -> electra::DepositRequest {
    electra::DepositRequest {
        pubkey: BlsPubkey([seed; 48]),
        withdrawal_credentials: H256::repeat_byte(seed.wrapping_add(1)),
        amount: 32_000_000_000 + u64::from(seed),
        signature: BlsSignature([seed.wrapping_add(2); 96]),
        index: u64::from(seed) + 3,
    }
}

fn withdrawal_request(seed: u8) -> electra::WithdrawalRequest {
    electra::WithdrawalRequest {
        source_address: H160::repeat_byte(seed),
        validator_pubkey: BlsPubkey([seed.wrapping_add(1); 48]),
        amount: 32_000_000_000 + u64::from(seed),
    }
}

fn consolidation_request(seed: u8) -> electra::ConsolidationRequest {
    electra::ConsolidationRequest {
        source_address: H160::repeat_byte(seed),
        source_pubkey: BlsPubkey([seed.wrapping_add(1); 48]),
        target_pubkey: BlsPubkey([seed.wrapping_add(2); 48]),
    }
}

/// A nonempty [`electra::ExecutionRequests`], so each of `DepositRequest`,
/// `WithdrawalRequest`, and `ConsolidationRequest` — one level below a field
/// an empty-body test would never reach — is actually walked.
fn execution_requests(seed: u8) -> electra::ExecutionRequests {
    electra::ExecutionRequests {
        deposits: SszList::try_from(vec![deposit_request(seed)]).expect("within capacity"),
        withdrawals: SszList::try_from(vec![withdrawal_request(seed.wrapping_add(10))])
            .expect("within capacity"),
        consolidations: SszList::try_from(vec![consolidation_request(seed.wrapping_add(20))])
            .expect("within capacity"),
    }
}

/// Deneb's body shape, with electra's widened attestation family and
/// `execution_requests` appended, electra's one addition to the block body.
/// `execution_payload` reuses [`deneb_execution_payload`] directly:
/// `electra::BeaconBlockBody::execution_payload` is `deneb::ExecutionPayload`
/// itself, imported unchanged rather than redefined, so there is no separate
/// `electra::ExecutionPayload` type to build a fixture for.
fn electra_block_body() -> electra::BeaconBlockBody {
    electra::BeaconBlockBody {
        randao_reveal: BlsSignature([0x44; 96]),
        eth1_data: fixtures::eth1_data(1),
        graffiti: H256::repeat_byte(0x55),
        proposer_slashings: SszList::try_from(vec![fixtures::proposer_slashing(2)])
            .expect("within capacity"),
        attester_slashings: SszList::try_from(vec![electra_attester_slashing(3)])
            .expect("within capacity"),
        attestations: SszList::try_from(vec![electra_attestation(4)]).expect("within capacity"),
        deposits: SszList::try_from(vec![fixtures::deposit(5)]).expect("within capacity"),
        voluntary_exits: SszList::try_from(vec![fixtures::signed_voluntary_exit(6)])
            .expect("within capacity"),
        sync_aggregate: altair::SyncAggregate {
            sync_committee_bits: {
                let mut bits = altair::SyncCommitteeBits::new();
                bits.set(0, true).expect("in bounds");
                bits
            },
            sync_committee_signature: BlsSignature([0x99; 96]),
        },
        execution_payload: deneb_execution_payload(20),
        bls_to_execution_changes: SszList::try_from(vec![
            fixtures::signed_bls_to_execution_change(40),
        ])
        .expect("within capacity"),
        blob_kzg_commitments: SszList::try_from(vec![KzgCommitment([0x77; 48])])
            .expect("within capacity"),
        execution_requests: execution_requests(50),
    }
}

fn electra_block() -> electra::SignedBeaconBlock {
    electra::SignedBeaconBlock {
        message: electra::BeaconBlock {
            slot: 12_345,
            proposer_index: 7,
            parent_root: H256([0x11; 32]),
            state_root: H256([0x22; 32]),
            body: electra_block_body(),
        },
        signature: BlsSignature([0x33; 96]),
    }
}

/// Deneb's 28 fields, field for field, plus the nine electra appends:
/// `deposit_requests_start_index` (EIP-6110) and the balance-churn accounting
/// plus three pending queues (EIP-7251): 37 fields in all.
/// `latest_execution_payload_header` reuses [`deneb_execution_payload_header`]
/// directly, the header-side counterpart of [`electra_block_body`]'s reuse of
/// [`deneb_execution_payload`].
fn electra_state() -> electra::BeaconState {
    electra::BeaconState {
        genesis_time: 1_700_000_000,
        genesis_validators_root: H256::repeat_byte(0x66),
        slot: 42,
        fork: shared::Fork {
            previous_version: [0x01, 0x02, 0x03, 0x04],
            current_version: [0x05, 0x06, 0x07, 0x08],
            epoch: 1,
        },
        latest_block_header: fixtures::beacon_block_header(7),
        block_roots: fixtures::vector(H256::repeat_byte(0x77)),
        state_roots: fixtures::vector(H256::repeat_byte(0x88)),
        historical_roots: SszList::try_from(vec![H256::repeat_byte(0x99)])
            .expect("within capacity"),
        eth1_data: fixtures::eth1_data(8),
        eth1_data_votes: SszList::try_from(vec![fixtures::eth1_data(9)]).expect("within capacity"),
        eth1_deposit_index: 3,
        validators: shared::Validators::try_from(vec![fixtures::validator(10)])
            .expect("within capacity"),
        balances: shared::Balances::try_from(vec![32_000_000_001u64]).expect("within capacity"),
        randao_mixes: fixtures::vector(H256::repeat_byte(0xaa)),
        slashings: fixtures::vector(1_000_000_000u64),
        previous_epoch_participation: SszList::try_from(vec![7u8]).expect("within capacity"),
        current_epoch_participation: SszList::try_from(vec![9u8]).expect("within capacity"),
        justification_bits: {
            let mut bits = shared::JustificationBits::new();
            bits.set(0, true).expect("in bounds");
            bits
        },
        previous_justified_checkpoint: fixtures::checkpoint(13),
        current_justified_checkpoint: fixtures::checkpoint(14),
        finalized_checkpoint: fixtures::checkpoint(15),
        inactivity_scores: vec![4u64].try_into().expect("within capacity"),
        current_sync_committee: sync_committee(16),
        next_sync_committee: sync_committee(17),
        latest_execution_payload_header: deneb_execution_payload_header(30),
        next_withdrawal_index: 40,
        next_withdrawal_validator_index: 41,
        historical_summaries: SszList::try_from(vec![shared::HistoricalSummary {
            block_summary_root: H256::repeat_byte(0xbb),
            state_summary_root: H256::repeat_byte(0xcc),
        }])
        .expect("within capacity"),
        deposit_requests_start_index: 50,
        deposit_balance_to_consume: 51,
        exit_balance_to_consume: 52,
        earliest_exit_epoch: 53,
        consolidation_balance_to_consume: 54,
        earliest_consolidation_epoch: 55,
        pending_deposits: SszList::try_from(vec![fixtures::pending_deposit(60)])
            .expect("within capacity"),
        pending_partial_withdrawals: SszList::try_from(vec![fixtures::pending_partial_withdrawal(
            70,
        )])
        .expect("within capacity"),
        pending_consolidations: SszList::try_from(vec![fixtures::pending_consolidation(80)])
            .expect("within capacity"),
    }
}

#[test]
fn an_electra_block_carries_no_bare_numbers() {
    assert_no_bare_numbers("electra::SignedBeaconBlock", &electra_block());
}

#[test]
fn an_electra_state_carries_no_bare_numbers() {
    assert_no_bare_numbers("electra::BeaconState", &electra_state());
}

// ---------------------------------------------------------------------------
// Fulu
// ---------------------------------------------------------------------------

/// Fulu defines no block types of its own: `BeaconBlockBody`, `BeaconBlock`,
/// and `SignedBeaconBlock` are unchanged from electra
/// (`SignedBeaconBlock::Fulu` in `containers/mod.rs` wraps
/// `electra::SignedBeaconBlock` directly), so this reuses [`electra_block`]
/// rather than redefining an identical builder for a type that does not
/// exist under `fulu::`.
fn fulu_block() -> electra::SignedBeaconBlock {
    electra_block()
}

/// Electra's 37 fields, field for field, plus `proposer_lookahead`, fulu's
/// one addition to the state: 38 fields in all. Reuses
/// [`deneb_execution_payload_header`] and the electra-onward pending-queue
/// fixtures the same way [`electra_state`] does, since none of those types
/// change again in fulu.
fn fulu_state() -> fulu::BeaconState {
    fulu::BeaconState {
        genesis_time: 1_700_000_000,
        genesis_validators_root: H256::repeat_byte(0x66),
        slot: 42,
        fork: shared::Fork {
            previous_version: [0x01, 0x02, 0x03, 0x04],
            current_version: [0x05, 0x06, 0x07, 0x08],
            epoch: 1,
        },
        latest_block_header: fixtures::beacon_block_header(7),
        block_roots: fixtures::vector(H256::repeat_byte(0x77)),
        state_roots: fixtures::vector(H256::repeat_byte(0x88)),
        historical_roots: SszList::try_from(vec![H256::repeat_byte(0x99)])
            .expect("within capacity"),
        eth1_data: fixtures::eth1_data(8),
        eth1_data_votes: SszList::try_from(vec![fixtures::eth1_data(9)]).expect("within capacity"),
        eth1_deposit_index: 3,
        validators: shared::Validators::try_from(vec![fixtures::validator(10)])
            .expect("within capacity"),
        balances: shared::Balances::try_from(vec![32_000_000_001u64]).expect("within capacity"),
        randao_mixes: fixtures::vector(H256::repeat_byte(0xaa)),
        slashings: fixtures::vector(1_000_000_000u64),
        previous_epoch_participation: SszList::try_from(vec![7u8]).expect("within capacity"),
        current_epoch_participation: SszList::try_from(vec![9u8]).expect("within capacity"),
        justification_bits: {
            let mut bits = shared::JustificationBits::new();
            bits.set(0, true).expect("in bounds");
            bits
        },
        previous_justified_checkpoint: fixtures::checkpoint(13),
        current_justified_checkpoint: fixtures::checkpoint(14),
        finalized_checkpoint: fixtures::checkpoint(15),
        inactivity_scores: vec![4u64].try_into().expect("within capacity"),
        current_sync_committee: sync_committee(16),
        next_sync_committee: sync_committee(17),
        latest_execution_payload_header: deneb_execution_payload_header(30),
        next_withdrawal_index: 40,
        next_withdrawal_validator_index: 41,
        historical_summaries: SszList::try_from(vec![shared::HistoricalSummary {
            block_summary_root: H256::repeat_byte(0xbb),
            state_summary_root: H256::repeat_byte(0xcc),
        }])
        .expect("within capacity"),
        deposit_requests_start_index: 50,
        deposit_balance_to_consume: 51,
        exit_balance_to_consume: 52,
        earliest_exit_epoch: 53,
        consolidation_balance_to_consume: 54,
        earliest_consolidation_epoch: 55,
        pending_deposits: SszList::try_from(vec![fixtures::pending_deposit(60)])
            .expect("within capacity"),
        pending_partial_withdrawals: SszList::try_from(vec![fixtures::pending_partial_withdrawal(
            70,
        )])
        .expect("within capacity"),
        pending_consolidations: SszList::try_from(vec![fixtures::pending_consolidation(80)])
            .expect("within capacity"),
        proposer_lookahead: fixtures::vector(90u64),
    }
}

#[test]
fn a_fulu_block_carries_no_bare_numbers() {
    assert_no_bare_numbers("fulu::SignedBeaconBlock", &fulu_block());
}

#[test]
fn a_fulu_state_carries_no_bare_numbers() {
    assert_no_bare_numbers("fulu::BeaconState", &fulu_state());
}

// ---------------------------------------------------------------------------
// The wrapping enums add no tag
// ---------------------------------------------------------------------------
//
// `SignedBeaconBlock` and `BeaconState` (in `containers/mod.rs`) wrap every
// fork's per-fork struct in one enum. The Beacon API's response envelope
// carries the fork name itself, as a `version` field and an
// `Eth-Consensus-Version` header, so the enum must serialize as exactly its
// inner value: no variant tag, no wrapper object.

#[test]
fn the_block_enum_serializes_as_its_inner_block_with_no_tag() {
    use ethlambda_types::beacon::containers::SignedBeaconBlock as Enum;

    let inner = phase0_block();
    let wrapped = Enum::Phase0(inner.clone());

    assert_eq!(
        serde_json::to_value(&wrapped).unwrap(),
        serde_json::to_value(&inner).unwrap(),
        "the enum must add no tag: the fork travels in the envelope's version field"
    );
}

#[test]
fn the_state_enum_serializes_as_its_inner_state_with_no_tag() {
    use ethlambda_types::beacon::containers::BeaconState as Enum;

    let inner = phase0_state();
    let wrapped = Enum::Phase0(inner.clone());

    assert_eq!(
        serde_json::to_value(&wrapped).unwrap(),
        serde_json::to_value(&inner).unwrap(),
        "the enum must add no tag: the fork travels in the envelope's version field"
    );
}

/// [`BeaconState::Lean`] wraps `crate::state::State`, which stays SSZ-only by
/// design: `/lean/v0/states/finalized` serves SSZ, never JSON, so this
/// variant deliberately has no encoding to produce. The enum's hand-written
/// `Serialize` impl (see its doc in `containers/mod.rs`) answers this with a
/// serde error rather than a panic or a silently-wrong encoding, and this
/// test pins that: an `Err`, not an `Ok` and not an abort.
#[test]
fn the_lean_state_variant_errors_rather_than_serializing() {
    use ethlambda_types::beacon::containers::BeaconState as Enum;

    let lean = ethlambda_types::state::State::from_genesis(0, Vec::new());
    let wrapped = Enum::Lean(lean);

    assert!(
        serde_json::to_value(&wrapped).is_err(),
        "a lean state has no JSON encoding and must not silently produce one"
    );
}
