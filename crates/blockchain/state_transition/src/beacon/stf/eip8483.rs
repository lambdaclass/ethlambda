//! EIP-8483's block processing (consensus-specs
//! `specs/_features/eip8483/beacon-chain.md`, on the `pq` branch at
//! `2f43bc0f989f47af81df390a90bc1f78e2436323`).
//!
//! Gloas's block processing, with two more execution-layer request lists in
//! the parent payload: validators and builders register post-quantum material
//! the PQ fork adopts. Everything but [`apply_parent_execution_payload`] and the
//! two request processors is gloas's own code, reached through the
//! gloas-family view (`containers::GloasFamily`).
//!
//! # A newer gloas underneath
//!
//! The `pq` branch builds on a newer gloas than this crate's pin. Its
//! `apply_parent_execution_payload` settles the parent's builder payment
//! *before* processing the parent's requests (so a builder exit request is
//! rejected while the payment is pending), its builders sweep pays a balance
//! net of the sweep's earlier withdrawals, and its `slash_validator` clears the
//! slashed validator's pending builder payments. All three apply from EIP-8483
//! on and are recorded in `docs/spec_deviations.md`; gloas itself keeps its
//! pinned rules until its own fixtures move.

use crate::beacon::config::Config;
use crate::beacon::constants;
use crate::beacon::containers::{BeaconState, eip8483};
use crate::beacon::error::{Error, Result, verify};
use crate::beacon::helpers::accessors::{ActiveBalanceCache, PubkeyIndexCache};
use crate::beacon::helpers::electra::has_execution_withdrawal_credential;
use crate::beacon::preset;
use crate::beacon::primitives::{HashTreeRoot as _, ValidatorIndex};
use crate::beacon::stf::signatures::SignatureBatch;
use crate::metrics::{StfPhase, timed};

use super::BlockCaches;
use super::gloas::{
    GloasRequests, mark_parent_payload_available, parent_payload_context,
    process_gloas_execution_requests, settle_parent_builder_payment,
};

/// `process_block`: gloas's, over EIP-8483's block.
pub fn process_block(
    state: &mut BeaconState,
    block: &eip8483::BeaconBlock,
    config: &Config,
    caches: BlockCaches<'_>,
    options: super::block::BlockProcessingOptions,
    signatures: &mut SignatureBatch,
) -> Result<()> {
    let parent_slot = state.latest_block_header().slot;
    timed(StfPhase::ExecutionPayload, || {
        process_parent_execution_payload(
            state,
            block,
            config,
            caches.active_balances,
            caches.pubkey_indices,
        )
    })?;
    timed(StfPhase::BlockHeader, || {
        super::block::process_block_header(
            state,
            block.slot,
            block.proposer_index,
            block.parent_root,
            block.body.hash_tree_root(),
        )
    })?;
    timed(StfPhase::ExecutionPayload, || -> Result<()> {
        super::gloas::process_withdrawals(state)?;
        super::gloas::process_execution_payload_bid(
            state,
            &block.body.signed_execution_payload_bid,
            config,
            signatures,
        )
    })?;
    super::block::process_randao(state, &block.body.randao_reveal, options.randao, signatures)?;
    super::block::process_eth1_data(state, &block.body.eth1_data)?;
    super::gloas::process_operations(
        state,
        &block.body,
        parent_slot,
        config,
        caches.committees,
        caches.active_balances,
        options.target_delta,
        signatures,
    )?;
    super::altair::process_sync_aggregate(
        state,
        &block.body.sync_aggregate,
        caches.active_balances,
        caches.pubkey_indices,
        signatures,
    )?;
    Ok(())
}

/// `process_parent_execution_payload`: gloas's, over EIP-8483's requests.
pub fn process_parent_execution_payload(
    state: &mut BeaconState,
    block: &eip8483::BeaconBlock,
    config: &Config,
    active_balances: &ActiveBalanceCache,
    pubkey_indices: &PubkeyIndexCache,
) -> Result<()> {
    let bid = &block.body.signed_execution_payload_bid.message;
    let (parent_bid, _, _) = parent_payload_context(state)?;
    let requests = &block.body.parent_execution_requests;

    if bid.parent_block_hash != parent_bid.block_hash {
        // Parent was EMPTY: no execution requests expected.
        verify(
            *requests == eip8483::ExecutionRequests::default(),
            "process_parent_execution_payload: requests == ExecutionRequests.empty()",
        )?;
        return Ok(());
    }

    verify(
        requests.hash_tree_root() == parent_bid.execution_requests_root,
        "process_parent_execution_payload: hash_tree_root(requests) == parent_bid.execution_requests_root",
    )?;
    apply_parent_execution_payload(state, requests, config, active_balances, pubkey_indices)
}

/// `apply_parent_execution_payload` (modified in EIP-8483): the two new
/// request lists' bounds and processing, on the newer gloas's settle-first
/// order (see the module doc).
pub fn apply_parent_execution_payload(
    state: &mut BeaconState,
    requests: &eip8483::ExecutionRequests,
    config: &Config,
    active_balances: &ActiveBalanceCache,
    pubkey_indices: &PubkeyIndexCache,
) -> Result<()> {
    let (parent_bid, parent_slot, parent_epoch) = parent_payload_context(state)?;

    verify(
        requests.withdrawals.len() <= preset::MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
        "apply_parent_execution_payload: len(requests.withdrawals) <= MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD",
    )?;
    verify(
        requests.consolidations.len() <= preset::MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
        "apply_parent_execution_payload: len(requests.consolidations) <= MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD",
    )?;
    verify(
        requests.builder_deposits.len() as u64 <= preset::MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD,
        "apply_parent_execution_payload: len(requests.builder_deposits) <= MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD",
    )?;
    verify(
        requests.builder_exits.len() as u64 <= preset::MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD,
        "apply_parent_execution_payload: len(requests.builder_exits) <= MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD",
    )?;
    // [New in EIP8483]
    verify(
        requests.validator_pq_registrations.len() as u64
            <= preset::MAX_VALIDATOR_PQ_REGISTRATION_REQUESTS_PER_PAYLOAD,
        "apply_parent_execution_payload: len(requests.validator_pq_registrations) <= MAX_VALIDATOR_PQ_REGISTRATION_REQUESTS_PER_PAYLOAD",
    )?;
    // [New in EIP8483]
    verify(
        requests.builder_pq_registrations.len() as u64
            <= preset::MAX_BUILDER_PQ_REGISTRATION_REQUESTS_PER_PAYLOAD,
        "apply_parent_execution_payload: len(requests.builder_pq_registrations) <= MAX_BUILDER_PQ_REGISTRATION_REQUESTS_PER_PAYLOAD",
    )?;

    // Settled before the requests, so a builder exit request is rejected while
    // the payment is pending.
    settle_parent_builder_payment(state, &parent_bid, parent_slot, parent_epoch)?;

    let gloas_requests = GloasRequests {
        deposits: &requests.deposits,
        withdrawals: &requests.withdrawals,
        consolidations: &requests.consolidations,
        builder_deposits: &requests.builder_deposits,
        builder_exits: &requests.builder_exits,
    };
    process_gloas_execution_requests(
        state,
        gloas_requests,
        config,
        active_balances,
        pubkey_indices,
    )?;
    // [New in EIP8483]
    for request in requests.validator_pq_registrations.iter() {
        process_validator_pq_registration_request(state, request)?;
    }
    // [New in EIP8483]
    for request in requests.builder_pq_registrations.iter() {
        process_builder_pq_registration_request(state, request)?;
    }

    mark_parent_payload_available(state, &parent_bid, parent_slot)
}

fn eip8483_state<'a>(
    state: &'a mut BeaconState,
    function: &'static str,
) -> Result<&'a mut eip8483::BeaconState> {
    match state {
        BeaconState::Eip8483(inner) => Ok(inner),
        other => Err(Error::UnsupportedForFork {
            function,
            fork: other.fork_name(),
        }),
    }
}

/// `process_validator_pq_registration_request`. Invalid requests are ignored.
/// No status is checked, so pending, active, exited and slashed validators can
/// all register, as long as the request comes from their withdrawal address
/// and neither half of its PQ data is registered already, to anyone,
/// themselves included.
pub fn process_validator_pq_registration_request(
    state: &mut BeaconState,
    request: &eip8483::ValidatorPqRegistrationRequest,
) -> Result<()> {
    let Some(validator_index) = state
        .iter_validators()
        .position(|validator| validator.pubkey == request.validator_pubkey)
    else {
        return Ok(());
    };
    let validator_index = validator_index as ValidatorIndex;
    let validator = state.validator(validator_index)?;

    // Verify the validator has execution withdrawal credentials.
    if !has_execution_withdrawal_credential(validator) {
        return Ok(());
    }
    // Verify the request comes from the validator's withdrawal address.
    if validator.withdrawal_credentials.0[12..] != request.source_address.0 {
        return Ok(());
    }

    let inner = eip8483_state(state, "process_validator_pq_registration_request")?;
    let (key_half, vrf_half) = request.pq_data.split_at(32);
    // Verify the PQ data is not already registered.
    if inner.validator_pq_registrations.iter().any(|registration| {
        registration.pq_data[..32] == *key_half || registration.pq_data[32..] == *vrf_half
    }) {
        return Ok(());
    }

    // Overwrite an existing registration for this validator.
    if let Some(registration) = inner
        .validator_pq_registrations
        .iter_mut()
        .find(|registration| registration.validator_index == validator_index)
    {
        registration.pq_data = request.pq_data;
        return Ok(());
    }

    inner
        .validator_pq_registrations
        .push(eip8483::ValidatorPqRegistration {
            validator_index,
            pq_data: request.pq_data,
        });
    Ok(())
}

/// `process_builder_pq_registration_request`. Invalid requests are ignored.
/// Active and exited builders can both register, as long as the request comes
/// from their execution address and its PQ data is not registered already.
pub fn process_builder_pq_registration_request(
    state: &mut BeaconState,
    request: &eip8483::BuilderPqRegistrationRequest,
) -> Result<()> {
    let inner = eip8483_state(state, "process_builder_pq_registration_request")?;
    let Some(builder) = inner
        .builders
        .iter()
        .find(|builder| builder.pubkey == request.builder_pubkey)
    else {
        return Ok(());
    };

    // Verify the request comes from the builder's execution address.
    if builder.execution_address != request.source_address {
        return Ok(());
    }

    // Verify the PQ data is not already registered.
    if inner
        .builder_pq_registrations
        .iter()
        .any(|registration| registration.pq_data == request.pq_data)
    {
        return Ok(());
    }

    // Overwrite an existing registration for this builder.
    if let Some(registration) = inner
        .builder_pq_registrations
        .iter_mut()
        .find(|registration| registration.builder_pubkey == request.builder_pubkey)
    {
        registration.pq_data = request.pq_data;
        return Ok(());
    }

    inner
        .builder_pq_registrations
        .push(eip8483::BuilderPqRegistration {
            builder_pubkey: request.builder_pubkey,
            pq_data: request.pq_data,
        });
    Ok(())
}

/// `get_execution_requests_list` (modified in EIP-8483): the EIP-7685
/// encoding of the payload's requests, the two registration lists included.
pub fn get_execution_requests_list(requests: &eip8483::ExecutionRequests) -> Vec<Vec<u8>> {
    use libssz::SszEncode as _;
    let typed: [(u8, Vec<u8>, bool); 7] = [
        (
            constants::DEPOSIT_REQUEST_TYPE,
            requests.deposits.to_ssz(),
            requests.deposits.is_empty(),
        ),
        (
            constants::WITHDRAWAL_REQUEST_TYPE,
            requests.withdrawals.to_ssz(),
            requests.withdrawals.is_empty(),
        ),
        (
            constants::CONSOLIDATION_REQUEST_TYPE,
            requests.consolidations.to_ssz(),
            requests.consolidations.is_empty(),
        ),
        (
            constants::BUILDER_DEPOSIT_REQUEST_TYPE,
            requests.builder_deposits.to_ssz(),
            requests.builder_deposits.is_empty(),
        ),
        (
            constants::BUILDER_EXIT_REQUEST_TYPE,
            requests.builder_exits.to_ssz(),
            requests.builder_exits.is_empty(),
        ),
        (
            constants::VALIDATOR_PQ_REGISTRATION_REQUEST_TYPE,
            requests.validator_pq_registrations.to_ssz(),
            requests.validator_pq_registrations.is_empty(),
        ),
        (
            constants::BUILDER_PQ_REGISTRATION_REQUEST_TYPE,
            requests.builder_pq_registrations.to_ssz(),
            requests.builder_pq_registrations.is_empty(),
        ),
    ];
    typed
        .into_iter()
        .filter(|(_, _, empty)| !empty)
        .map(|(request_type, data, _)| {
            let mut entry = Vec::with_capacity(1 + data.len());
            entry.push(request_type);
            entry.extend(data);
            entry
        })
        .collect()
}
