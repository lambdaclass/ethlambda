//! JSON round trips of the containers a validator client submits, which the
//! Beacon API's request bodies carry: serialize, deserialize, compare. Each
//! value has every list non-empty and every integer non-zero, so an adapter
//! that dropped or misread a field shows up as a difference.

use super::{altair, capella, electra, gloas, shared};
use crate::beacon::primitives::{BlsPubkey, BlsSignature, KzgCommitment, Uint256};

fn round_trip<T>(value: &T)
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let json = serde_json::to_string(value).unwrap();
    let back: T = serde_json::from_str(&json).unwrap();
    assert_eq!(&back, value, "{json}");
}

fn signature(byte: u8) -> BlsSignature {
    let mut signature = BlsSignature::default();
    signature.0[0] = byte;
    signature.0[95] = byte;
    signature
}

fn pubkey(byte: u8) -> BlsPubkey {
    let mut pubkey = BlsPubkey::default();
    pubkey.0[0] = byte;
    pubkey
}

fn header(slot: u64) -> shared::SignedBeaconBlockHeader {
    shared::SignedBeaconBlockHeader {
        message: shared::BeaconBlockHeader {
            slot,
            proposer_index: 3,
            parent_root: [1; 32].into(),
            state_root: [2; 32].into(),
            body_root: [3; 32].into(),
        },
        signature: signature(9),
    }
}

fn data() -> shared::AttestationData {
    shared::AttestationData {
        slot: 12,
        index: 0,
        beacon_block_root: [4; 32].into(),
        source: shared::Checkpoint {
            epoch: 1,
            root: [5; 32].into(),
        },
        target: shared::Checkpoint {
            epoch: 2,
            root: [6; 32].into(),
        },
    }
}

fn deposit() -> shared::Deposit {
    shared::Deposit {
        proof: vec![[7u8; 32].into(); crate::beacon::constants::DEPOSIT_CONTRACT_TREE_DEPTH + 1]
            .try_into()
            .unwrap(),
        data: shared::DepositData {
            pubkey: pubkey(1),
            withdrawal_credentials: [8; 32].into(),
            amount: 32_000_000_000,
            signature: signature(2),
        },
    }
}

fn exit() -> shared::SignedVoluntaryExit {
    shared::SignedVoluntaryExit {
        message: shared::VoluntaryExit {
            epoch: 5,
            validator_index: 6,
        },
        signature: signature(3),
    }
}

fn bls_change() -> capella::SignedBLSToExecutionChange {
    capella::SignedBLSToExecutionChange {
        message: capella::BLSToExecutionChange {
            validator_index: 4,
            from_bls_pubkey: pubkey(4),
            to_execution_address: [0xaa; 20].into(),
        },
        signature: signature(4),
    }
}

fn sync_aggregate() -> altair::SyncAggregate {
    let mut aggregate = altair::SyncAggregate::default();
    aggregate.sync_committee_bits.set(3, true).unwrap();
    aggregate.sync_committee_signature = signature(5);
    aggregate
}

fn electra_attestation() -> electra::Attestation {
    let mut aggregation_bits = electra::AggregationBits::with_length(5).unwrap();
    aggregation_bits.set(1, true).unwrap();
    aggregation_bits.set(4, true).unwrap();
    let mut committee_bits = electra::CommitteeBits::default();
    committee_bits.set(2, true).unwrap();
    electra::Attestation {
        aggregation_bits,
        data: data(),
        signature: signature(6),
        committee_bits,
    }
}

fn electra_indexed() -> electra::IndexedAttestation {
    electra::IndexedAttestation {
        attesting_indices: vec![3, 9, 27].try_into().unwrap(),
        data: data(),
        signature: signature(7),
    }
}

fn electra_payload() -> super::deneb::ExecutionPayload {
    use super::{bellatrix, deneb};
    deneb::ExecutionPayload {
        parent_hash: [1; 32].into(),
        fee_recipient: [2; 20].into(),
        state_root: [3; 32].into(),
        receipts_root: [4; 32].into(),
        logs_bloom: bellatrix::LogsBloom::try_from(vec![
            0xab;
            crate::beacon::preset::BYTES_PER_LOGS_BLOOM
        ])
        .unwrap(),
        prev_randao: [5; 32].into(),
        block_number: 10,
        gas_limit: 30_000_000,
        gas_used: 21_000,
        timestamp: 1_700_000_000,
        extra_data: vec![0xde, 0xad].try_into().unwrap(),
        base_fee_per_gas: Uint256::from(7_000_000_000u64),
        block_hash: [6; 32].into(),
        transactions: vec![
            bellatrix::Transaction::try_from(vec![1, 2, 3]).unwrap(),
            bellatrix::Transaction::try_from(vec![4]).unwrap(),
        ]
        .try_into()
        .unwrap(),
        withdrawals: vec![capella::Withdrawal {
            index: 1,
            validator_index: 2,
            address: [3; 20].into(),
            amount: 4,
        }]
        .try_into()
        .unwrap(),
        blob_gas_used: 131_072,
        excess_blob_gas: 262_144,
    }
}

fn electra_requests() -> electra::ExecutionRequests {
    electra::ExecutionRequests {
        deposits: vec![electra::DepositRequest {
            pubkey: pubkey(5),
            withdrawal_credentials: [1; 32].into(),
            amount: 32_000_000_000,
            signature: signature(8),
            index: 11,
        }]
        .try_into()
        .unwrap(),
        withdrawals: vec![electra::WithdrawalRequest {
            source_address: [2; 20].into(),
            validator_pubkey: pubkey(6),
            amount: 5,
        }]
        .try_into()
        .unwrap(),
        consolidations: vec![electra::ConsolidationRequest {
            source_address: [3; 20].into(),
            source_pubkey: pubkey(7),
            target_pubkey: pubkey(8),
        }]
        .try_into()
        .unwrap(),
    }
}

fn electra_block() -> electra::SignedBeaconBlock {
    let mut body = electra::BeaconBlockBody::empty();
    body.randao_reveal = signature(1);
    body.graffiti = [9; 32].into();
    body.proposer_slashings = vec![shared::ProposerSlashing {
        signed_header_1: header(7),
        signed_header_2: header(7),
    }]
    .try_into()
    .unwrap();
    body.attester_slashings = vec![electra::AttesterSlashing {
        attestation_1: electra_indexed(),
        attestation_2: electra_indexed(),
    }]
    .try_into()
    .unwrap();
    body.attestations = vec![electra_attestation()].try_into().unwrap();
    body.deposits = vec![deposit()].try_into().unwrap();
    body.voluntary_exits = vec![exit()].try_into().unwrap();
    body.sync_aggregate = sync_aggregate();
    body.execution_payload = electra_payload();
    body.bls_to_execution_changes = vec![bls_change()].try_into().unwrap();
    body.blob_kzg_commitments = vec![KzgCommitment([5; 48])].try_into().unwrap();
    body.execution_requests = electra_requests();
    electra::SignedBeaconBlock {
        message: electra::BeaconBlock {
            slot: 33,
            proposer_index: 4,
            parent_root: [1; 32].into(),
            state_root: [2; 32].into(),
            body,
        },
        signature: signature(9),
    }
}

fn gloas_attestation() -> gloas::Attestation {
    gloas::Attestation::from(&electra_attestation())
}

fn gloas_payload() -> gloas::ExecutionPayload {
    let payload = electra_payload();
    gloas::ExecutionPayload {
        parent_hash: payload.parent_hash,
        fee_recipient: payload.fee_recipient,
        state_root: payload.state_root,
        receipts_root: payload.receipts_root,
        logs_bloom: payload.logs_bloom,
        prev_randao: payload.prev_randao,
        block_number: payload.block_number,
        gas_limit: payload.gas_limit,
        gas_used: payload.gas_used,
        timestamp: payload.timestamp,
        extra_data: payload.extra_data,
        base_fee_per_gas: payload.base_fee_per_gas,
        block_hash: payload.block_hash,
        transactions: payload
            .transactions
            .iter()
            .map(|transaction| gloas::Transaction::from(transaction.to_vec()))
            .collect::<Vec<_>>()
            .into(),
        withdrawals: payload
            .withdrawals
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .into(),
        blob_gas_used: payload.blob_gas_used,
        excess_blob_gas: payload.excess_blob_gas,
        block_access_list: vec![0xca, 0xfe].into(),
        slot_number: 33,
    }
}

fn gloas_requests() -> gloas::ExecutionRequests {
    let requests = electra_requests();
    gloas::ExecutionRequests {
        deposits: requests.deposits.iter().cloned().collect::<Vec<_>>().into(),
        withdrawals: requests
            .withdrawals
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .into(),
        consolidations: requests
            .consolidations
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .into(),
        builder_deposits: vec![gloas::BuilderDepositRequest {
            pubkey: pubkey(9),
            withdrawal_credentials: [4; 32].into(),
            amount: 1,
            signature: signature(1),
        }]
        .into(),
        builder_exits: vec![gloas::BuilderExitRequest {
            source_address: [5; 20].into(),
            pubkey: pubkey(10),
        }]
        .into(),
    }
}

fn payload_attestation() -> gloas::PayloadAttestation {
    let mut aggregation_bits = gloas::PayloadTimelinessCommitteeBits::default();
    aggregation_bits.set(1, true).unwrap();
    gloas::PayloadAttestation {
        aggregation_bits,
        data: gloas::PayloadAttestationData {
            beacon_block_root: [6; 32].into(),
            slot: 32,
            payload_present: true,
            blob_data_available: true,
        },
        signature: signature(2),
    }
}

fn gloas_block() -> gloas::SignedBeaconBlock {
    let electra = electra_block().message;
    let mut body = gloas::BeaconBlockBody::empty();
    body.randao_reveal = electra.body.randao_reveal;
    body.graffiti = electra.body.graffiti;
    body.proposer_slashings = electra
        .body
        .proposer_slashings
        .iter()
        .cloned()
        .collect::<Vec<_>>()
        .into();
    body.attestations = vec![gloas_attestation()].into();
    body.deposits = electra
        .body
        .deposits
        .iter()
        .cloned()
        .collect::<Vec<_>>()
        .into();
    body.voluntary_exits = electra
        .body
        .voluntary_exits
        .iter()
        .cloned()
        .collect::<Vec<_>>()
        .into();
    body.sync_aggregate = sync_aggregate();
    body.signed_execution_payload_bid = gloas::SignedExecutionPayloadBid {
        message: gloas::ExecutionPayloadBid {
            parent_block_hash: [1; 32].into(),
            parent_block_root: [2; 32].into(),
            block_hash: [3; 32].into(),
            prev_randao: [4; 32].into(),
            fee_recipient: [5; 20].into(),
            gas_limit: 30_000_000,
            builder_index: 7,
            slot: 33,
            value: 8,
            execution_payment: 9,
            execution_requests_root: [7; 32].into(),
            blob_kzg_commitments: vec![KzgCommitment([6; 48])].try_into().unwrap(),
        },
        signature: signature(3),
    };
    body.payload_attestations = vec![payload_attestation()].try_into().unwrap();
    body.parent_execution_requests = gloas_requests();
    gloas::SignedBeaconBlock {
        message: gloas::BeaconBlock {
            slot: 33,
            proposer_index: 4,
            parent_root: [1; 32].into(),
            state_root: [2; 32].into(),
            body,
        },
        signature: signature(9),
    }
}

#[test]
fn a_fulu_block_round_trips_through_json() {
    round_trip(&electra_block());
}

#[test]
fn a_gloas_block_round_trips_through_json() {
    round_trip(&gloas_block());
}

#[test]
fn a_gloas_envelope_round_trips_through_json() {
    round_trip(&gloas::SignedExecutionPayloadEnvelope {
        message: gloas::ExecutionPayloadEnvelope {
            payload: gloas_payload(),
            execution_requests: gloas_requests(),
            builder_index: 7,
            beacon_block_root: [1; 32].into(),
            parent_beacon_block_root: [2; 32].into(),
        },
        signature: signature(4),
    });
}

#[test]
fn an_oversized_list_is_refused_rather_than_truncated() {
    let mut json = serde_json::to_value(electra_block()).unwrap();
    let commitment = json["message"]["body"]["blob_kzg_commitments"][0].clone();
    json["message"]["body"]["blob_kzg_commitments"] = serde_json::Value::Array(vec![
        commitment;
        crate::beacon::preset::MAX_BLOB_COMMITMENTS_PER_BLOCK
            + 1
    ]);
    assert!(serde_json::from_value::<electra::SignedBeaconBlock>(json).is_err());
}
