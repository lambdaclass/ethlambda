//! PQ block production (`specs/_features/pq/validator.md`): gloas's
//! self-build with PQ's shapes. The randao reveal is the proposer's VRF proof,
//! the self-build bid carries the empty `XMSSSignature()`, attestations carry
//! no signatures and the body one merged `proof` of theirs, the execution
//! requests are PQ's, and the block has no sync aggregate, payload
//! attestations, exits or credential changes.

use crate::beacon::config::Config;
use crate::beacon::constants;
use crate::beacon::containers::{BeaconState, gloas, pq};
use crate::beacon::error::{Error, Result, verify};
use crate::beacon::gloas_block_production::GloasPayloadInputs;
use crate::beacon::helpers::accessors::{
    ActiveBalanceCache, CommitteeCache, PubkeyIndexCache, get_beacon_proposer_index,
    get_current_epoch, get_randao_mix,
};
use crate::beacon::helpers::gloas::gloas_state_ref;
use crate::beacon::primitives::{Bytes32, HashTreeRoot as _, KzgCommitment, Root};
use crate::beacon::stf;

/// `get_execution_requests` (PQ `validator.md`): the execution client's
/// EIP-7685 request list into PQ's `ExecutionRequests`, with its
/// preregistration and voluntary-exit request types. Strictly ascending
/// types and no empty element are checked, as gloas's are.
pub fn parse_pq_execution_requests(list: &[Vec<u8>]) -> Result<pq::ExecutionRequests> {
    let mut requests = pq::ExecutionRequests::default();
    let mut previous_type: Option<u8> = None;
    for element in list {
        let (&request_type, data) = element
            .split_first()
            .ok_or(Error::SpecAssert("an execution request carries its type"))?;
        verify(!data.is_empty(), "an execution request is not empty")?;
        verify(
            previous_type.is_none_or(|previous| request_type > previous),
            "execution request types are strictly ascending",
        )?;
        previous_type = Some(request_type);
        let malformed = |_| Error::SpecAssert("an execution request list decodes as SSZ");
        match request_type {
            constants::DEPOSIT_REQUEST_TYPE => {
                requests.deposits = libssz::SszDecode::from_ssz_bytes(data).map_err(malformed)?;
            }
            constants::WITHDRAWAL_REQUEST_TYPE => {
                requests.withdrawals =
                    libssz::SszDecode::from_ssz_bytes(data).map_err(malformed)?;
            }
            constants::CONSOLIDATION_REQUEST_TYPE => {
                requests.consolidations =
                    libssz::SszDecode::from_ssz_bytes(data).map_err(malformed)?;
            }
            constants::BUILDER_DEPOSIT_REQUEST_TYPE => {
                requests.builder_deposits =
                    libssz::SszDecode::from_ssz_bytes(data).map_err(malformed)?;
            }
            constants::BUILDER_EXIT_REQUEST_TYPE => {
                requests.builder_exits =
                    libssz::SszDecode::from_ssz_bytes(data).map_err(malformed)?;
            }
            constants::VALIDATOR_PREREGISTRATION_REQUEST_TYPE => {
                requests.validator_preregistrations =
                    libssz::SszDecode::from_ssz_bytes(data).map_err(malformed)?;
            }
            constants::BUILDER_PREREGISTRATION_REQUEST_TYPE => {
                requests.builder_preregistrations =
                    libssz::SszDecode::from_ssz_bytes(data).map_err(malformed)?;
            }
            constants::VOLUNTARY_EXIT_REQUEST_TYPE => {
                requests.voluntary_exits =
                    libssz::SszDecode::from_ssz_bytes(data).map_err(malformed)?;
            }
            _ => return Err(Error::SpecAssert("a known execution request type")),
        }
    }
    Ok(requests)
}

/// [`crate::beacon::gloas_block_production::gloas_payload_inputs`] on a PQ
/// state: the parent's requests, when building on its full payload, are PQ's
/// and applied by PQ's `apply_parent_execution_payload`.
pub fn pq_payload_inputs(
    state: &BeaconState,
    build_on_full: bool,
    parent_requests: &pq::ExecutionRequests,
    config: &Config,
) -> Result<GloasPayloadInputs> {
    let inner = gloas_state_ref(state, "pq_payload_inputs")?;
    let parent_bid = &inner.latest_execution_payload_bid;
    let (withdrawals, head_block_hash) = if build_on_full {
        let mut applied = state.clone();
        stf::pq::apply_parent_execution_payload(
            &mut applied,
            parent_requests,
            config,
            &ActiveBalanceCache::default(),
            &PubkeyIndexCache::default(),
        )?;
        (
            stf::gloas::get_expected_withdrawals(&applied)?.withdrawals,
            parent_bid.block_hash,
        )
    } else {
        (
            inner.payload_expected_withdrawals.iter().cloned().collect(),
            parent_bid.parent_block_hash,
        )
    };
    Ok(GloasPayloadInputs {
        timestamp: stf::bellatrix::compute_timestamp_at_slot(state, state.slot(), config),
        prev_randao: get_randao_mix(state, get_current_epoch(state)),
        withdrawals,
        head_block_hash,
        parent_beacon_block_root: state.latest_block_header().hash_tree_root(),
        slot_number: state.slot(),
        target_gas_limit: parent_bid.gas_limit,
    })
}

/// What a PQ block body carries beyond what this module derives from the
/// state.
#[derive(Debug, Clone)]
pub struct PqBlockInputs {
    /// The proposer's VRF proof for the slot.
    pub randao_reveal: pq::VrfProof,
    pub graffiti: Bytes32,
    pub attestations: Vec<pq::Attestation>,
    /// `stark.MergeProofs` of the attestations' aggregate proofs, in their
    /// order: empty with no attestations.
    pub proof: Vec<u8>,
    /// The parent envelope's requests when building on its full payload;
    /// empty otherwise.
    pub parent_execution_requests: pq::ExecutionRequests,
    pub execution_payload: gloas::ExecutionPayload,
    pub blob_kzg_commitments: Vec<KzgCommitment>,
    pub execution_requests: pq::ExecutionRequests,
}

/// A produced PQ block and the unsigned envelope that reveals its payload.
#[derive(Debug, Clone)]
pub struct PqProduced {
    pub block: pq::BeaconBlock,
    pub envelope: pq::ExecutionPayloadEnvelope,
}

/// The unsigned self-built PQ block for the slot `state` has been advanced
/// to, its state root computed by running PQ's `process_block` on a copy
/// (which also refuses a body the network would), and the unsigned envelope
/// for its payload, checked against that post-state but for its signature.
pub fn assemble_pq_block(
    state: &BeaconState,
    inputs: PqBlockInputs,
    config: &Config,
    options: stf::block::BlockProcessingOptions,
) -> Result<PqProduced> {
    verify(
        matches!(state, BeaconState::Pq(_)),
        "PQ block production runs on a PQ state",
    )?;
    let payload = &inputs.execution_payload;
    let bid = gloas::ExecutionPayloadBid {
        parent_block_hash: payload.parent_hash,
        parent_block_root: state.latest_block_header().hash_tree_root(),
        block_hash: payload.block_hash,
        prev_randao: payload.prev_randao,
        fee_recipient: payload.fee_recipient,
        gas_limit: payload.gas_limit,
        builder_index: constants::BUILDER_INDEX_SELF_BUILD,
        slot: state.slot(),
        value: 0,
        execution_payment: 0,
        blob_kzg_commitments: inputs.blob_kzg_commitments.into(),
        execution_requests_root: inputs.execution_requests.hash_tree_root(),
    };
    let proof = pq::AttestationProof::try_from(inputs.proof)
        .map_err(|_| Error::SpecAssert("the merged proof fits MAX_STARK_PROOF_SIZE"))?;
    let body = pq::BeaconBlockBody {
        randao_reveal: inputs.randao_reveal,
        eth1_data: state.eth1_data().clone(),
        graffiti: inputs.graffiti,
        attestations: inputs.attestations.into(),
        // Self-build: the empty `XMSSSignature()`, all zero bytes.
        signed_execution_payload_bid: pq::SignedExecutionPayloadBid {
            message: bid,
            signature: Default::default(),
        },
        parent_execution_requests: inputs.parent_execution_requests,
        proof,
        ..pq::BeaconBlockBody::empty()
    };
    let mut block = pq::BeaconBlock {
        slot: state.slot(),
        proposer_index: get_beacon_proposer_index(state)?,
        parent_root: state.latest_block_header().hash_tree_root(),
        state_root: Root::ZERO,
        body,
    };

    let mut post = state.clone();
    stf::pq::process_block(
        &mut post,
        &block,
        config,
        &CommitteeCache::default(),
        &ActiveBalanceCache::default(),
        &PubkeyIndexCache::default(),
        options,
    )?;
    post.apply_pending_mutations();
    block.state_root = post.hash_tree_root();

    let envelope = pq::ExecutionPayloadEnvelope {
        payload: inputs.execution_payload,
        execution_requests: inputs.execution_requests,
        builder_index: constants::BUILDER_INDEX_SELF_BUILD,
        beacon_block_root: block.hash_tree_root(),
        parent_beacon_block_root: block.parent_root,
    };
    check_envelope(&post, &block, &envelope, config)?;
    Ok(PqProduced { block, envelope })
}

/// `verify_execution_payload_envelope`'s conditions but the signature and
/// the engine, against `post`, the state after `block`.
fn check_envelope(
    post: &BeaconState,
    block: &pq::BeaconBlock,
    envelope: &pq::ExecutionPayloadEnvelope,
    config: &Config,
) -> Result<()> {
    let inner = gloas_state_ref(post, "assemble_pq_block")?;
    let bid = &inner.latest_execution_payload_bid;
    let payload = &envelope.payload;
    verify(
        envelope.beacon_block_root == block.hash_tree_root(),
        "the envelope names the block",
    )?;
    verify(
        payload.block_hash == bid.block_hash
            && payload.prev_randao == bid.prev_randao
            && payload.gas_limit == bid.gas_limit
            && envelope.execution_requests.hash_tree_root() == bid.execution_requests_root,
        "the envelope is the payload the bid commits to",
    )?;
    verify(
        payload.slot_number == post.slot(),
        "payload.slot_number == state.slot",
    )?;
    verify(
        payload.parent_hash == *inner.latest_block_hash,
        "payload.parent_hash == state.latest_block_hash",
    )?;
    verify(
        payload.timestamp == stf::bellatrix::compute_timestamp_at_slot(post, post.slot(), config),
        "payload.timestamp == compute_time_at_slot(state, state.slot)",
    )?;
    verify(
        payload.withdrawals.hash_tree_root() == inner.payload_expected_withdrawals.hash_tree_root(),
        "hash_tree_root(payload.withdrawals) == hash_tree_root(state.payload_expected_withdrawals)",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pq_request_types_parse_into_their_lists() {
        let exit = pq::VoluntaryExitRequest::default();
        let list = vec![
            [
                vec![constants::VOLUNTARY_EXIT_REQUEST_TYPE],
                libssz::SszEncode::to_ssz(&pq::VoluntaryExitRequests::from(vec![exit.clone()])),
            ]
            .concat(),
        ];
        let requests = parse_pq_execution_requests(&list).unwrap();
        assert_eq!(requests.voluntary_exits.len(), 1);
        assert!(requests.deposits.is_empty());
        // Round trip through the list builder.
        assert_eq!(stf::pq::get_execution_requests_list(&requests), list);
        // Out of order is refused.
        let twice = [list.clone(), list].concat();
        assert!(parse_pq_execution_requests(&twice).is_err());
    }
}
