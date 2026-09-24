//! Turning a beacon block into an Engine API question, and an answer into a
//! fork choice verdict.
//!
//! This module is the seam between two crates that must not depend on each
//! other. `ethlambda-engine` is pure wire and must not pull in `blst` and
//! `c-kzg` through the state transition; `ethlambda-state-transition` must not
//! pull in `reqwest`. This crate already depends on both, so the assembly that
//! needs a helper from each lives here.
//!
//! # Everything a request needs comes from the block alone
//!
//! `NewPayloadRequest` in the specification reads `parent_beacon_block_root`
//! off `state.latest_block_header.parent_root`, which after
//! `process_block_header` is the block's own `parent_root`. The other three
//! fields are body fields. So the whole question is answerable before the state
//! transition runs, which is what lets the engine round trip happen outside the
//! state transition and the state transition stay synchronous.

use ethlambda_engine::types::PayloadStatusValue;
use ethlambda_engine::{EngineClient, EngineError, PayloadStatusV1};
use ethlambda_state_transition::beacon::containers::{self, SignedBeaconBlock};
use ethlambda_state_transition::beacon::fork_choice::PayloadValidity;
use ethlambda_state_transition::beacon::primitives::{Bytes32, Root};
use ethlambda_state_transition::beacon::stf::deneb::kzg_commitment_to_versioned_hash;
use ethlambda_state_transition::beacon::stf::electra::get_execution_requests_list;

/// Everything `engine_newPayloadV4` takes, derived from one block.
pub struct NewPayloadRequest<'a> {
    pub execution_payload: &'a containers::deneb::ExecutionPayload,
    pub versioned_hashes: Vec<Bytes32>,
    pub parent_beacon_block_root: Root,
    pub execution_requests: Vec<Vec<u8>>,
}

/// The question to ask about `block`, or `None` if there is nothing to ask.
///
/// `None` for phase0 and altair, which predate the merge and carry no payload,
/// and for a lean block, which is not a Beacon Chain shape at all. Bellatrix
/// through deneb are also `None` here for a different reason: this node
/// checkpoint-syncs onto a mainnet far past those forks and never imports one,
/// and `engine_newPayloadV4` would reject their payloads as an unsupported fork
/// anyway. Supporting them would mean the V1 through V3 methods too, for chains
/// this follower cannot reach.
pub fn new_payload_request(block: &SignedBeaconBlock) -> Option<NewPayloadRequest<'_>> {
    let inner = match block {
        SignedBeaconBlock::Electra(inner) | SignedBeaconBlock::Fulu(inner) => inner,
        SignedBeaconBlock::Phase0(_)
        | SignedBeaconBlock::Altair(_)
        | SignedBeaconBlock::Bellatrix(_)
        | SignedBeaconBlock::Capella(_)
        | SignedBeaconBlock::Deneb(_)
        | SignedBeaconBlock::Lean(_) => return None,
    };

    let versioned_hashes = inner
        .message
        .body
        .blob_kzg_commitments
        .iter()
        .map(kzg_commitment_to_versioned_hash)
        .collect();

    Some(NewPayloadRequest {
        execution_payload: &inner.message.body.execution_payload,
        versioned_hashes,
        parent_beacon_block_root: inner.message.parent_root,
        execution_requests: get_execution_requests_list(&inner.message.body.execution_requests),
    })
}

/// Reads an execution client's status as the verdict `fork_choice::on_block`
/// takes.
///
/// A thin wrapper over the state transition's own `payload_validity`,
/// converting between the wire crate's status enum and the consensus crate's.
/// The two are separate types on purpose: the wire one is a JSON shape that
/// changes when the Engine API changes, and the consensus one is what
/// `optimistic-sync.md` defines.
pub fn verdict(status: &PayloadStatusV1) -> PayloadValidity {
    use ethlambda_state_transition::beacon::fork_choice::{
        PayloadStatusEnum, PayloadStatusV1 as ConsensusStatus, payload_validity,
    };

    let consensus_status = match status.status {
        PayloadStatusValue::Valid => PayloadStatusEnum::Valid,
        PayloadStatusValue::Invalid => PayloadStatusEnum::Invalid,
        PayloadStatusValue::Syncing => PayloadStatusEnum::Syncing,
        PayloadStatusValue::Accepted => PayloadStatusEnum::Accepted,
        PayloadStatusValue::InvalidBlockHash => PayloadStatusEnum::InvalidBlockHash,
    };
    payload_validity(&ConsensusStatus {
        status: consensus_status,
        latest_valid_hash: status.latest_valid_hash,
        validation_error: status.validation_error.clone(),
    })
}

/// Asks the execution client about `block`'s payload.
///
/// `Ok(None)` means there was nothing to ask, which is not a failure:
/// [`PayloadValidity::NotRequired`] is the right verdict and the block imports.
/// `Err` means no answer was obtained after the client's whole retry ladder, and
/// `optimistic-sync.md` requires the caller not to import the block and not to
/// touch fork choice.
pub async fn ask(
    client: &EngineClient,
    block: &SignedBeaconBlock,
) -> Result<Option<PayloadValidity>, EngineError> {
    let Some(request) = new_payload_request(block) else {
        return Ok(None);
    };
    let status = client
        .new_payload(
            request.execution_payload,
            &request.versioned_hashes,
            request.parent_beacon_block_root,
            &request.execution_requests,
        )
        .await?;
    Ok(Some(verdict(&status)))
}

#[cfg(test)]
mod tests {
    use ethlambda_state_transition::beacon::preset;
    use ethlambda_state_transition::beacon::primitives::{
        BlsSignature, ExecutionAddress, ExecutionBlockHash, KzgCommitment, Uint256,
    };

    use super::*;

    /// An otherwise-zero electra signed block with `parent_root` set.
    ///
    /// Hand-built because the consensus containers deliberately do not derive
    /// `Default`, and `logs_bloom` is a fixed-length vector that has none even
    /// among its `SszList` neighbours. Matches the idiom in `stf/fulu.rs` and
    /// `containers/bellatrix.rs`.
    fn electra_block(parent_root: Root) -> containers::electra::SignedBeaconBlock {
        let execution_payload = containers::deneb::ExecutionPayload {
            parent_hash: ExecutionBlockHash::ZERO,
            fee_recipient: ExecutionAddress::ZERO,
            state_root: Bytes32::ZERO,
            receipts_root: Bytes32::ZERO,
            logs_bloom: containers::bellatrix::LogsBloom::try_from(vec![
                0u8;
                preset::BYTES_PER_LOGS_BLOOM
            ])
            .expect("built at exactly BYTES_PER_LOGS_BLOOM"),
            prev_randao: Bytes32::ZERO,
            block_number: 0,
            gas_limit: 0,
            gas_used: 0,
            timestamp: 0,
            extra_data: Default::default(),
            base_fee_per_gas: Uint256::ZERO,
            block_hash: ExecutionBlockHash::ZERO,
            transactions: Default::default(),
            withdrawals: Default::default(),
            blob_gas_used: 0,
            excess_blob_gas: 0,
        };

        containers::electra::SignedBeaconBlock {
            message: containers::electra::BeaconBlock {
                slot: 0,
                proposer_index: 0,
                parent_root,
                state_root: Root::ZERO,
                body: containers::electra::BeaconBlockBody {
                    randao_reveal: BlsSignature::default(),
                    eth1_data: Default::default(),
                    graffiti: Bytes32::ZERO,
                    proposer_slashings: Default::default(),
                    attester_slashings: Default::default(),
                    attestations: Default::default(),
                    deposits: Default::default(),
                    voluntary_exits: Default::default(),
                    sync_aggregate: Default::default(),
                    execution_payload,
                    bls_to_execution_changes: Default::default(),
                    blob_kzg_commitments: Default::default(),
                    execution_requests: containers::electra::ExecutionRequests {
                        deposits: Default::default(),
                        withdrawals: Default::default(),
                        consolidations: Default::default(),
                    },
                },
            },
            signature: BlsSignature::default(),
        }
    }

    #[test]
    fn a_pre_bellatrix_block_has_nothing_to_ask_about() {
        let block = SignedBeaconBlock::Phase0(containers::phase0::SignedBeaconBlock {
            message: containers::phase0::BeaconBlock {
                slot: 0,
                proposer_index: 0,
                parent_root: Root::ZERO,
                state_root: Root::ZERO,
                body: containers::phase0::BeaconBlockBody {
                    randao_reveal: BlsSignature::default(),
                    eth1_data: Default::default(),
                    graffiti: Bytes32::ZERO,
                    proposer_slashings: Default::default(),
                    attester_slashings: Default::default(),
                    attestations: Default::default(),
                    deposits: Default::default(),
                    voluntary_exits: Default::default(),
                },
            },
            signature: BlsSignature::default(),
        });

        assert!(new_payload_request(&block).is_none());
    }

    #[test]
    fn a_request_takes_its_parent_beacon_block_root_from_the_blocks_parent() {
        let block = SignedBeaconBlock::Fulu(electra_block(Root::repeat_byte(9)));

        let request = new_payload_request(&block).expect("a fulu block carries a payload");

        assert_eq!(request.parent_beacon_block_root, Root::repeat_byte(9));
    }

    #[test]
    fn versioned_hashes_are_one_per_blob_commitment_and_versioned() {
        let mut inner = electra_block(Root::ZERO);
        inner
            .message
            .body
            .blob_kzg_commitments
            .push(KzgCommitment::default())
            .expect("one commitment fits");
        let block = SignedBeaconBlock::Fulu(inner);

        let request = new_payload_request(&block).expect("a fulu block carries a payload");

        assert_eq!(request.versioned_hashes.len(), 1);
        // EIP-4844 stamps the version byte over the first byte of the hash.
        assert_eq!(
            request.versioned_hashes[0].0[0],
            ethlambda_state_transition::beacon::constants::VERSIONED_HASH_VERSION_KZG
        );
    }

    #[test]
    fn an_execution_status_becomes_the_matching_consensus_verdict() {
        let syncing = PayloadStatusV1 {
            status: PayloadStatusValue::Syncing,
            latest_valid_hash: None,
            validation_error: None,
        };
        assert_eq!(verdict(&syncing), PayloadValidity::Optimistic);

        let invalid = PayloadStatusV1 {
            status: PayloadStatusValue::Invalid,
            latest_valid_hash: Some(ExecutionBlockHash::repeat_byte(3)),
            validation_error: Some("bad".to_string()),
        };
        assert_eq!(
            verdict(&invalid),
            PayloadValidity::Invalidated {
                latest_valid_hash: Some(ExecutionBlockHash::repeat_byte(3)),
            }
        );
    }
}
