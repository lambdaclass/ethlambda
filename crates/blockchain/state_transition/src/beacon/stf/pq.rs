//! The PQ fork's block processing (consensus-specs
//! `specs/_features/pq/beacon-chain.md`, on the `pq` branch at
//! `2f43bc0f989f47af81df390a90bc1f78e2436323`).
//!
//! Gloas's block processing with leanXMSS in place of BLS:
//!
//! - the block, a bid, an envelope and a proposer slashing's headers are each
//!   signed at a leaf the message's slot and type determine
//!   (`compute_xmss_leaf_index`), a bid at any of the bid leaves;
//! - attestations carry no signature: the block's `proof` covers all of them,
//!   checked once in [`process_stark`] after every attestation is processed;
//! - the RANDAO reveal is a VRF proof, the leaf the proposer's committed
//!   tree holds for the slot ([`process_randao`]);
//! - voluntary exits are execution-layer requests, and the body loses
//!   `voluntary_exits`, `sync_aggregate`, `bls_to_execution_changes` and
//!   `payload_attestations`;
//! - deposits carry no signature: a 48-byte key field names an XMSS key after
//!   16 zero bytes, a legacy BLS key otherwise, and preregistrations
//!   (EIP-8205) bind a key to its credentials before anyone can front-run its
//!   first deposit.
//!
//! What is not new is gloas's code, reached through the gloas-family view:
//! withdrawals, the bid's body, attestation participation and builder-payment
//! weights, and the payment settlement. Every XMSS check goes through
//! [`crate::beacon::helpers::pq::xmss_verify`] directly, not the BLS
//! [`SignatureBatch`] the earlier forks defer their checks into.

use crate::beacon::config::Config;
use crate::beacon::constants;
use crate::beacon::containers::shared::BeaconBlockHeader;
use crate::beacon::containers::{BeaconState, electra, gloas, pq};
use crate::beacon::error::{Error, Result, verify};
use crate::beacon::helpers::accessors::{
    ActiveBalanceCache, CommitteeCache, PubkeyIndexCache, get_beacon_proposer_index,
    get_current_epoch, get_domain, get_randao_mix,
};
use crate::beacon::helpers::electra::get_pending_balance_to_withdraw;
use crate::beacon::helpers::gloas::{
    get_index_for_new_builder, gloas_state, initiate_builder_exit, is_builder_withdrawal_credential,
};
use crate::beacon::helpers::misc::{compute_epoch_at_slot, compute_signing_root};
use crate::beacon::helpers::mutators::slash_validator;
use crate::beacon::helpers::pq::{
    compute_deposit_pubkey, compute_xmss_leaf_index, get_active_builder_preregistration,
    get_active_validator_preregistration, get_attestation_statements, get_committee_indices,
    get_leaf_index, is_builder_bid_leaf_index, is_legacy_pubkey, is_valid_indexed_attestation,
    is_valid_vrf_proof, pq_state, verify_aggregates, xmss_verify,
};
use crate::beacon::helpers::predicates::{
    is_active_validator, is_slashable_attestation_data, is_slashable_validator,
};
use crate::beacon::helpers::target_balances::TargetBalanceDelta;
use crate::beacon::preset;
use crate::beacon::primitives::{
    ExecutionAddress, HashTreeRoot as _, Root, Slot, ValidatorIndex, XmssPubkey, XmssSignature,
};
use crate::metrics::{StfPhase, timed, try_for_each_timed};

use super::BlockCaches;
use super::block::RandaoVerification;
use super::gloas::{
    mark_parent_payload_available, parent_payload_context, settle_parent_builder_payment,
};

// ---------------------------------------------------------------------------
// Block processing
// ---------------------------------------------------------------------------

/// `process_block` (modified in PQ): gloas's without `process_sync_aggregate`.
pub fn process_block(
    state: &mut BeaconState,
    block: &pq::BeaconBlock,
    config: &Config,
    caches: BlockCaches<'_>,
    options: super::block::BlockProcessingOptions,
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
        process_execution_payload_bid(state, &block.body.signed_execution_payload_bid, config)
    })?;
    timed(StfPhase::Randao, || {
        process_randao(state, &block.body.randao_reveal, options.randao)
    })?;
    super::block::process_eth1_data(state, &block.body.eth1_data)?;
    process_operations(
        state,
        &block.body,
        parent_slot,
        config,
        caches.committees,
        caches.active_balances,
        options.target_delta,
    )
}

/// `verify_block_signature` (modified in PQ): the proposer's XMSS signature at
/// the block's slot's proposer leaf.
pub fn verify_block_signature(state: &BeaconState, signed_block: &pq::SignedBeaconBlock) -> bool {
    let block = &signed_block.message;
    let Ok(proposer) = state.pq_validator(block.proposer_index) else {
        return false;
    };
    let domain = get_domain(state, constants::DOMAIN_BEACON_PROPOSER, None);
    let signing_root = compute_signing_root(block.hash_tree_root(), domain);
    let Ok(leaf_index) =
        compute_xmss_leaf_index(block.slot, constants::LEAF_OFFSET_BEACON_PROPOSER)
    else {
        return false;
    };
    xmss_verify(
        &proposer.pubkey(),
        leaf_index,
        signing_root,
        &signed_block.signature,
    )
}

/// `process_randao` (modified in PQ): the reveal is the proposer's VRF proof
/// for the slot, and the leaf it reveals is mixed in. The proposer committed
/// to its leaves when it registered its VRF root, so it cannot grind the
/// reveal and can only withhold its block, as with BLS.
pub fn process_randao(
    state: &mut BeaconState,
    randao_reveal: &pq::VrfProof,
    verification: RandaoVerification,
) -> Result<()> {
    let epoch = get_current_epoch(state);
    if verification == RandaoVerification::Verify {
        let proposer_index = get_beacon_proposer_index(state)?;
        verify(
            is_valid_vrf_proof(state, proposer_index, state.slot(), randao_reveal)?,
            "process_randao: is_valid_vrf_proof(state, get_beacon_proposer_index(state), state.slot, body.randao_reveal)",
        )?;
    }
    let mut input = Vec::with_capacity(32 + 32 + 4);
    input.extend_from_slice(&get_randao_mix(state, epoch).0);
    input.extend_from_slice(&randao_reveal[0].0);
    input.extend_from_slice(&constants::DOMAIN_RANDAO);
    let mix = crate::beacon::hash::hash(&input);
    let position = epoch as usize % preset::epochs_per_historical_vector();
    state.randao_mixes_mut()[position] = mix;
    Ok(())
}

// ---------------------------------------------------------------------------
// Execution payload bid and envelope
// ---------------------------------------------------------------------------

/// `verify_execution_payload_bid_signature` (modified in PQ): the builder's
/// XMSS signature, at one of the bid leaves.
pub fn verify_execution_payload_bid_signature(
    state: &BeaconState,
    signed_bid: &pq::SignedExecutionPayloadBid,
) -> Result<bool> {
    let builder_index = signed_bid.message.builder_index;
    let inner = state.gloas_family().ok_or(Error::UnsupportedForFork {
        function: "verify_execution_payload_bid_signature",
        fork: state.fork_name(),
    })?;
    let builder = inner
        .builders
        .get(builder_index as usize)
        .ok_or(Error::IndexOutOfBounds {
            index: builder_index as usize,
            len: inner.builders.len(),
        })?;
    let domain = get_domain(state, constants::DOMAIN_BEACON_BUILDER, None);
    let signing_root = compute_signing_root(signed_bid.message.hash_tree_root(), domain);
    let leaf_index = get_leaf_index(&signed_bid.signature);
    if !is_builder_bid_leaf_index(leaf_index) {
        return Ok(false);
    }
    Ok(xmss_verify(
        &XmssPubkey::from_request_key(&builder.pubkey),
        leaf_index,
        signing_root,
        &signed_bid.signature,
    ))
}

/// `process_execution_payload_bid` (modified in PQ): gloas's, a self-build's
/// signature being the empty (all-zero) XMSS signature.
pub fn process_execution_payload_bid(
    state: &mut BeaconState,
    signed_bid: &pq::SignedExecutionPayloadBid,
    config: &Config,
) -> Result<()> {
    super::gloas::process_execution_payload_bid_with(
        state,
        &signed_bid.message,
        config,
        signed_bid.signature == XmssSignature::default(),
        |state| {
            verify(
                verify_execution_payload_bid_signature(state, signed_bid)?,
                "process_execution_payload_bid: verify_execution_payload_bid_signature(state, signed_bid)",
            )
        },
    )
}

/// `verify_execution_payload_envelope_signature` (modified in PQ): the
/// builder's (or, for a self-build, the proposer's) XMSS signature at the
/// envelope leaf of the block's slot.
pub fn verify_execution_payload_envelope_signature(
    state: &BeaconState,
    signed_envelope: &pq::SignedExecutionPayloadEnvelope,
) -> Result<bool> {
    let builder_index = signed_envelope.message.builder_index;
    let header = state.latest_block_header();
    let pubkey = if builder_index == constants::BUILDER_INDEX_SELF_BUILD {
        state.pq_validator(header.proposer_index)?.pubkey()
    } else {
        let inner = state.gloas_family().ok_or(Error::UnsupportedForFork {
            function: "verify_execution_payload_envelope_signature",
            fork: state.fork_name(),
        })?;
        let builder =
            inner
                .builders
                .get(builder_index as usize)
                .ok_or(Error::IndexOutOfBounds {
                    index: builder_index as usize,
                    len: inner.builders.len(),
                })?;
        XmssPubkey::from_request_key(&builder.pubkey)
    };
    let domain = get_domain(state, constants::DOMAIN_BEACON_BUILDER, None);
    let signing_root = compute_signing_root(signed_envelope.message.hash_tree_root(), domain);
    let leaf_index = compute_xmss_leaf_index(
        header.slot,
        constants::LEAF_OFFSET_EXECUTION_PAYLOAD_ENVELOPE,
    )?;
    Ok(xmss_verify(
        &pubkey,
        leaf_index,
        signing_root,
        &signed_envelope.signature,
    ))
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// `process_operations` (modified in PQ): slashings and attestations, then
/// [`process_stark`] over every attestation of the block.
pub fn process_operations(
    state: &mut BeaconState,
    body: &pq::BeaconBlockBody,
    parent_slot: Slot,
    config: &Config,
    committees: &CommitteeCache,
    active_balances: &ActiveBalanceCache,
    target_delta: Option<&TargetBalanceDelta>,
) -> Result<()> {
    verify(
        body.deposits.is_empty(),
        "process_operations: len(body.deposits) == 0",
    )?;
    verify(
        body.proposer_slashings.len() <= preset::MAX_PROPOSER_SLASHINGS,
        "process_operations: len(body.proposer_slashings) <= MAX_PROPOSER_SLASHINGS",
    )?;
    verify(
        body.attester_slashings.len() <= preset::MAX_ATTESTER_SLASHINGS_ELECTRA,
        "process_operations: len(body.attester_slashings) <= MAX_ATTESTER_SLASHINGS_ELECTRA",
    )?;
    verify(
        body.attestations.len() as u64 <= preset::MAX_ATTESTATIONS_PQ,
        "process_operations: len(body.attestations) <= MAX_ATTESTATIONS_PQ",
    )?;

    try_for_each_timed(
        StfPhase::ProposerSlashings,
        body.proposer_slashings.iter(),
        |slashing| process_proposer_slashing(state, slashing, config, active_balances),
    )?;
    try_for_each_timed(
        StfPhase::AttesterSlashings,
        body.attester_slashings.iter(),
        |slashing| process_attester_slashing(state, slashing, config, active_balances),
    )?;
    try_for_each_timed(
        StfPhase::Attestations,
        body.attestations.iter(),
        |attestation| {
            process_attestation(
                state,
                attestation,
                parent_slot,
                committees,
                active_balances,
                target_delta,
            )
        },
    )?;
    process_stark(state, body, committees)
}

/// `process_stark`: the block's `proof` proves, for each attestation and each
/// of its committees in order, its attesters' signatures.
pub fn process_stark(
    state: &BeaconState,
    body: &pq::BeaconBlockBody,
    committees: &CommitteeCache,
) -> Result<()> {
    let mut statements = Vec::new();
    for attestation in body.attestations.iter() {
        statements.extend(get_attestation_statements(state, attestation, committees)?);
    }
    verify(
        verify_aggregates(&statements, &body.proof),
        "process_stark: stark.VerifyAggregates(statements, body.proof)",
    )
}

/// `process_proposer_slashing` (modified in PQ): both headers are signed at
/// the same leaf, which exposes that leaf of the proposer's key; the leaf
/// belongs to a past slot, and the proposer is slashed. The slashed
/// proposer's pending builder payments are cleared by `slash_validator`.
pub fn process_proposer_slashing(
    state: &mut BeaconState,
    proposer_slashing: &pq::ProposerSlashing,
    config: &Config,
    active_balances: &ActiveBalanceCache,
) -> Result<()> {
    let header_1 = &proposer_slashing.signed_header_1.message;
    let header_2 = &proposer_slashing.signed_header_2.message;

    verify(
        header_1.slot == header_2.slot,
        "process_proposer_slashing: header_1.slot == header_2.slot",
    )?;
    verify(
        header_1.proposer_index == header_2.proposer_index,
        "process_proposer_slashing: header_1.proposer_index == header_2.proposer_index",
    )?;
    verify(
        header_1 != header_2,
        "process_proposer_slashing: header_1 != header_2",
    )?;
    let proposer_index = header_1.proposer_index;
    verify(
        is_slashable_validator(state.validator(proposer_index)?, get_current_epoch(state)),
        "process_proposer_slashing: is_slashable_validator(proposer, get_current_epoch(state))",
    )?;
    let pubkey = state.pq_validator(proposer_index)?.pubkey();
    for signed_header in [
        &proposer_slashing.signed_header_1,
        &proposer_slashing.signed_header_2,
    ] {
        verify(
            header_signature_valid(
                state,
                &pubkey,
                &signed_header.message,
                &signed_header.signature,
            )?,
            "process_proposer_slashing: xmss.Verify(proposer.pubkey, leaf_index, signing_root, signed_header.signature)",
        )?;
    }

    slash_validator(state, proposer_index, None, config, Some(active_balances))
}

pub(crate) fn header_signature_valid(
    state: &BeaconState,
    pubkey: &XmssPubkey,
    header: &BeaconBlockHeader,
    signature: &XmssSignature,
) -> Result<bool> {
    let domain = get_domain(
        state,
        constants::DOMAIN_BEACON_PROPOSER,
        Some(compute_epoch_at_slot(header.slot)),
    );
    let signing_root = compute_signing_root(header.hash_tree_root(), domain);
    let leaf_index = compute_xmss_leaf_index(header.slot, constants::LEAF_OFFSET_BEACON_PROPOSER)?;
    Ok(xmss_verify(pubkey, leaf_index, signing_root, signature))
}

/// `process_attester_slashing`: unchanged in shape, each indexed attestation
/// now carrying a proof of its attesters' signatures.
pub fn process_attester_slashing(
    state: &mut BeaconState,
    attester_slashing: &pq::AttesterSlashing,
    config: &Config,
    active_balances: &ActiveBalanceCache,
) -> Result<()> {
    let attestation_1 = &attester_slashing.attestation_1;
    let attestation_2 = &attester_slashing.attestation_2;
    verify(
        is_slashable_attestation_data(&attestation_1.data, &attestation_2.data),
        "process_attester_slashing: is_slashable_attestation_data(attestation_1.data, attestation_2.data)",
    )?;
    verify(
        is_valid_indexed_attestation(state, attestation_1)?,
        "process_attester_slashing: is_valid_indexed_attestation(state, attestation_1)",
    )?;
    verify(
        is_valid_indexed_attestation(state, attestation_2)?,
        "process_attester_slashing: is_valid_indexed_attestation(state, attestation_2)",
    )?;
    crate::beacon::stf::operations::slash_attesting_index_intersection(
        state,
        &attestation_1.attesting_indices,
        &attestation_2.attesting_indices,
        config,
        active_balances,
    )
}

/// `process_attestation` (modified in PQ): gloas's, with no signature to
/// check here ([`process_stark`] covers the block's attestations at once) and
/// the PQ fork's committee count.
pub fn process_attestation(
    state: &mut BeaconState,
    attestation: &pq::Attestation,
    parent_slot: Slot,
    committees: &CommitteeCache,
    active_balances: &ActiveBalanceCache,
    target_delta: Option<&TargetBalanceDelta>,
) -> Result<()> {
    super::gloas::process_attestation_with(
        state,
        attestation.data,
        &get_committee_indices(&attestation.committee_bits),
        &attestation.aggregation_bits,
        parent_slot,
        committees,
        active_balances,
        target_delta,
        |_, _| Ok(()),
    )
}

// ---------------------------------------------------------------------------
// Parent execution payload
// ---------------------------------------------------------------------------

/// `process_parent_execution_payload`: gloas's, over the PQ fork's requests.
pub fn process_parent_execution_payload(
    state: &mut BeaconState,
    block: &pq::BeaconBlock,
    config: &Config,
    active_balances: &ActiveBalanceCache,
    pubkey_indices: &PubkeyIndexCache,
) -> Result<()> {
    let bid = &block.body.signed_execution_payload_bid.message;
    let (parent_bid, _, _) = parent_payload_context(state)?;
    let requests = &block.body.parent_execution_requests;

    if bid.parent_block_hash != parent_bid.block_hash {
        verify(
            *requests == pq::ExecutionRequests::default(),
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

/// `apply_parent_execution_payload` (modified in PQ): settles the parent's
/// builder payment, then processes its requests, every one of them in the PQ
/// fork's own version, then marks its payload available.
pub fn apply_parent_execution_payload(
    state: &mut BeaconState,
    requests: &pq::ExecutionRequests,
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
    verify(
        requests.validator_preregistrations.len() as u64
            <= preset::MAX_VALIDATOR_PREREGISTRATION_REQUESTS_PER_PAYLOAD,
        "apply_parent_execution_payload: len(requests.validator_preregistrations) <= MAX_VALIDATOR_PREREGISTRATION_REQUESTS_PER_PAYLOAD",
    )?;
    verify(
        requests.builder_preregistrations.len() as u64
            <= preset::MAX_BUILDER_PREREGISTRATION_REQUESTS_PER_PAYLOAD,
        "apply_parent_execution_payload: len(requests.builder_preregistrations) <= MAX_BUILDER_PREREGISTRATION_REQUESTS_PER_PAYLOAD",
    )?;
    verify(
        requests.voluntary_exits.len() as u64 <= preset::MAX_VOLUNTARY_EXIT_REQUESTS_PER_PAYLOAD,
        "apply_parent_execution_payload: len(requests.voluntary_exits) <= MAX_VOLUNTARY_EXIT_REQUESTS_PER_PAYLOAD",
    )?;

    // Settled before the requests, so a builder exit request is rejected while
    // the payment is pending.
    settle_parent_builder_payment(state, &parent_bid, parent_slot, parent_epoch)?;

    for request in requests.deposits.iter() {
        process_deposit_request(state, request)?;
    }
    for request in requests.withdrawals.iter() {
        process_withdrawal_request(state, request, config, active_balances, pubkey_indices)?;
    }
    for request in requests.consolidations.iter() {
        process_consolidation_request(state, request, config, active_balances, pubkey_indices)?;
    }
    for request in requests.builder_deposits.iter() {
        process_builder_deposit_request(state, request, config)?;
    }
    for request in requests.builder_exits.iter() {
        process_builder_exit_request(state, request, config)?;
    }
    for request in requests.validator_preregistrations.iter() {
        process_validator_preregistration_request(state, request)?;
    }
    for request in requests.builder_preregistrations.iter() {
        process_builder_preregistration_request(state, request)?;
    }
    for request in requests.voluntary_exits.iter() {
        process_voluntary_exit_request(state, request, config, active_balances)?;
    }

    mark_parent_payload_available(state, &parent_bid, parent_slot)
}

/// `get_execution_requests_list` (modified in PQ): the EIP-7685 encoding of a
/// payload's requests, the preregistrations and voluntary exits in place of
/// EIP-8483's registrations.
pub fn get_execution_requests_list(requests: &pq::ExecutionRequests) -> Vec<Vec<u8>> {
    use libssz::SszEncode as _;
    let typed: [(u8, Vec<u8>, bool); 8] = [
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
            constants::VALIDATOR_PREREGISTRATION_REQUEST_TYPE,
            requests.validator_preregistrations.to_ssz(),
            requests.validator_preregistrations.is_empty(),
        ),
        (
            constants::BUILDER_PREREGISTRATION_REQUEST_TYPE,
            requests.builder_preregistrations.to_ssz(),
            requests.builder_preregistrations.is_empty(),
        ),
        (
            constants::VOLUNTARY_EXIT_REQUEST_TYPE,
            requests.voluntary_exits.to_ssz(),
            requests.voluntary_exits.is_empty(),
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

// ---------------------------------------------------------------------------
// Execution-layer requests
// ---------------------------------------------------------------------------

/// `process_deposit_request` (modified in PQ): an active preregistration of
/// the key discards a deposit that does not match its binding, and is used up
/// by one that does.
pub fn process_deposit_request(
    state: &mut BeaconState,
    request: &electra::DepositRequest,
) -> Result<()> {
    let pubkey = compute_deposit_pubkey(&request.pubkey);
    let inner = pq_state(state, "process_deposit_request")?;
    if let Some(preregistration) = get_active_validator_preregistration(inner, &pubkey) {
        if request.withdrawal_credentials != preregistration.withdrawal_credentials {
            return Ok(());
        }
        if Root::from_slice(&request.signature.0[..32]) != preregistration.vrf_root {
            return Ok(());
        }
        remove_validator_preregistration(inner, &pubkey);
    }
    inner.pending_deposits.push(electra::PendingDeposit {
        pubkey: request.pubkey,
        withdrawal_credentials: request.withdrawal_credentials,
        amount: request.amount,
        signature: request.signature,
        slot: inner.slot,
    })?;
    Ok(())
}

/// `process_withdrawal_request` (modified in PQ): a request naming a BLS key is
/// ignored; any other names its validator by XMSS key, which is how the
/// registry holds it (see `containers::pq`), so the rest is electra's.
pub fn process_withdrawal_request(
    state: &mut BeaconState,
    request: &electra::WithdrawalRequest,
    config: &Config,
    active_balances: &ActiveBalanceCache,
    pubkey_indices: &PubkeyIndexCache,
) -> Result<()> {
    if is_legacy_pubkey(&request.validator_pubkey) {
        return Ok(());
    }
    super::electra::process_withdrawal_request(
        state,
        request,
        config,
        active_balances,
        pubkey_indices,
    )
}

/// `process_consolidation_request` (modified in PQ): a request naming a BLS
/// key on either side is ignored; the rest is electra's, for the reason
/// [`process_withdrawal_request`] gives.
pub fn process_consolidation_request(
    state: &mut BeaconState,
    request: &electra::ConsolidationRequest,
    config: &Config,
    active_balances: &ActiveBalanceCache,
    pubkey_indices: &PubkeyIndexCache,
) -> Result<()> {
    if is_legacy_pubkey(&request.source_pubkey) || is_legacy_pubkey(&request.target_pubkey) {
        return Ok(());
    }
    super::electra::process_consolidation_request(
        state,
        request,
        config,
        active_balances,
        pubkey_indices,
    )
}

/// `process_builder_deposit_request` (modified in PQ): no signature to check,
/// an active preregistration binds the key's credentials, and a legacy
/// deposit's new builder initiates its exit at once.
pub fn process_builder_deposit_request(
    state: &mut BeaconState,
    request: &gloas::BuilderDepositRequest,
    config: &Config,
) -> Result<()> {
    // Ignore deposits with unexpected withdrawal credential prefixes.
    if !is_builder_withdrawal_credential(request.withdrawal_credentials) {
        return Ok(());
    }

    let pubkey = compute_deposit_pubkey(&request.pubkey);
    {
        let inner = pq_state(state, "process_builder_deposit_request")?;
        if let Some(preregistration) = get_active_builder_preregistration(inner, &pubkey) {
            if request.withdrawal_credentials != preregistration.withdrawal_credentials {
                return Ok(());
            }
            remove_builder_preregistration(inner, &pubkey);
        }
    }

    let record_key = pubkey.to_request_key();
    let mut inner = gloas_state(state, "process_builder_deposit_request")?;
    let existing = inner
        .builders
        .iter()
        .position(|builder| builder.pubkey == record_key);
    match existing {
        None => {
            let builder_index = get_index_for_new_builder(&inner.as_ref());
            let slot = *inner.slot;
            crate::beacon::helpers::gloas::add_builder_to_registry(
                &mut inner,
                record_key,
                constants::PAYLOAD_BUILDER_VERSION,
                ExecutionAddress::from_slice(&request.withdrawal_credentials.0[12..]),
                request.amount,
                slot,
            );
            if is_legacy_pubkey(&request.pubkey) {
                initiate_builder_exit(&mut inner, builder_index, config)?;
            }
        }
        Some(builder_index) => {
            let epoch = compute_epoch_at_slot(*inner.slot);
            let builder = &mut inner.builders[builder_index];
            // If exited and swept, reset the withdrawable epoch.
            if builder.withdrawable_epoch != constants::FAR_FUTURE_EPOCH && builder.balance == 0 {
                builder.withdrawable_epoch = epoch
                    .checked_add(config.min_builder_withdrawability_delay)
                    .ok_or(Error::ArithmeticOverflow(
                        "process_builder_deposit_request: epoch + MIN_BUILDER_WITHDRAWABILITY_DELAY",
                    ))?;
            }
            builder.balance =
                builder
                    .balance
                    .checked_add(request.amount)
                    .ok_or(Error::ArithmeticOverflow(
                        "process_builder_deposit_request: builder.balance + request.amount",
                    ))?;
        }
    }
    Ok(())
}

/// `process_builder_exit_request` (modified in PQ): the builder is named by
/// the XMSS key in the request's last 32 bytes; the rest is gloas's.
pub fn process_builder_exit_request(
    state: &mut BeaconState,
    request: &gloas::BuilderExitRequest,
    config: &Config,
) -> Result<()> {
    let named = gloas::BuilderExitRequest {
        source_address: request.source_address,
        pubkey: XmssPubkey::from_request_key(&request.pubkey).to_request_key(),
    };
    super::gloas::process_builder_exit_request(state, &named, config)
}

/// `process_validator_preregistration_request` (EIP-8205): binds a key that
/// has no validator and no pending deposit to its withdrawal credentials and
/// VRF root, until `PREREGISTRATION_EXPIRY_SLOTS` from now. An active binding
/// for the key makes a new request a no-op.
pub fn process_validator_preregistration_request(
    state: &mut BeaconState,
    request: &pq::ValidatorPreregistrationRequest,
) -> Result<()> {
    let pubkey = request.pubkey;
    let record_key = pubkey.to_request_key();
    let registered = state
        .iter_validators()
        .any(|validator| validator.pubkey == record_key);
    let inner = pq_state(state, "process_validator_preregistration_request")?;

    if get_active_validator_preregistration(inner, &pubkey).is_some() {
        return Ok(());
    }
    // A pubkey with an existing validator cannot be preregistered.
    if registered {
        return Ok(());
    }
    // A pubkey with a pending deposit cannot be preregistered.
    if inner
        .pending_deposits
        .iter()
        .any(|deposit| compute_deposit_pubkey(&deposit.pubkey) == pubkey)
    {
        return Ok(());
    }
    // Only active records count towards the limit, so the timing of the
    // garbage-collection sweep does not affect admission.
    let active = inner
        .validator_preregistrations
        .iter()
        .filter(|record| {
            crate::beacon::helpers::pq::is_active_validator_preregistration(inner, record)
        })
        .count() as u64;
    if active >= preset::preregistrations_limit() {
        return Ok(());
    }

    let preregistration = pq::ValidatorPreregistration {
        pubkey,
        withdrawal_credentials: request.withdrawal_credentials,
        vrf_root: request.vrf_root,
        expiry_slot: expiry_slot(inner.slot)?,
    };
    match inner
        .validator_preregistrations
        .iter()
        .position(|record| record.pubkey == pubkey)
    {
        // Replace the expired record in place.
        Some(index) => inner.validator_preregistrations[index] = preregistration,
        None => inner.validator_preregistrations.push(preregistration),
    }
    Ok(())
}

/// `process_builder_preregistration_request` (EIP-8205): the builder
/// counterpart of [`process_validator_preregistration_request`], with no VRF
/// root and no pending-deposit check.
pub fn process_builder_preregistration_request(
    state: &mut BeaconState,
    request: &pq::BuilderPreregistrationRequest,
) -> Result<()> {
    let pubkey = request.pubkey;
    let record_key = pubkey.to_request_key();
    let inner = pq_state(state, "process_builder_preregistration_request")?;

    if get_active_builder_preregistration(inner, &pubkey).is_some() {
        return Ok(());
    }
    // A pubkey with an existing builder cannot be preregistered.
    if inner
        .builders
        .iter()
        .any(|builder| builder.pubkey == record_key)
    {
        return Ok(());
    }
    let active = inner
        .builder_preregistrations
        .iter()
        .filter(|record| {
            crate::beacon::helpers::pq::is_active_builder_preregistration(inner, record)
        })
        .count() as u64;
    if active >= preset::preregistrations_limit() {
        return Ok(());
    }

    let preregistration = pq::BuilderPreregistration {
        pubkey,
        withdrawal_credentials: request.withdrawal_credentials,
        expiry_slot: expiry_slot(inner.slot)?,
    };
    match inner
        .builder_preregistrations
        .iter()
        .position(|record| record.pubkey == pubkey)
    {
        Some(index) => inner.builder_preregistrations[index] = preregistration,
        None => inner.builder_preregistrations.push(preregistration),
    }
    Ok(())
}

fn expiry_slot(slot: Slot) -> Result<Slot> {
    slot.checked_add(preset::preregistration_expiry_slots())
        .ok_or(Error::ArithmeticOverflow(
            "state.slot + PREREGISTRATION_EXPIRY_SLOTS",
        ))
}

/// `remove_validator_preregistration`: removal keeps the remaining records'
/// order, which the state root commits to.
fn remove_validator_preregistration(state: &mut pq::BeaconState, pubkey: &XmssPubkey) {
    let kept: Vec<pq::ValidatorPreregistration> = state
        .validator_preregistrations
        .iter()
        .filter(|record| record.pubkey != *pubkey)
        .cloned()
        .collect();
    state.validator_preregistrations = kept.into();
}

/// `remove_builder_preregistration`.
fn remove_builder_preregistration(state: &mut pq::BeaconState, pubkey: &XmssPubkey) {
    let kept: Vec<pq::BuilderPreregistration> = state
        .builder_preregistrations
        .iter()
        .filter(|record| record.pubkey != *pubkey)
        .cloned()
        .collect();
    state.builder_preregistrations = kept.into();
}

/// `process_voluntary_exit_request`: the system contract verified the
/// validator's exit signature at a reserved leaf before emitting the request,
/// so anyone may have submitted it. Ignored unless the validator could exit
/// voluntarily.
pub fn process_voluntary_exit_request(
    state: &mut BeaconState,
    request: &pq::VoluntaryExitRequest,
    config: &Config,
    active_balances: &ActiveBalanceCache,
) -> Result<()> {
    let record_key = request.pubkey.to_request_key();
    let Some(index) = state
        .iter_validators()
        .position(|validator| validator.pubkey == record_key)
    else {
        return Ok(());
    };
    let index = index as ValidatorIndex;
    let validator = state.validator(index)?;
    let current_epoch = get_current_epoch(state);

    if !is_active_validator(validator, current_epoch) {
        return Ok(());
    }
    if validator.exit_epoch != constants::FAR_FUTURE_EPOCH {
        return Ok(());
    }
    let eligible_epoch = validator
        .activation_epoch
        .checked_add(config.shard_committee_period)
        .ok_or(Error::ArithmeticOverflow(
            "validator.activation_epoch + SHARD_COMMITTEE_PERIOD",
        ))?;
    if current_epoch < eligible_epoch {
        return Ok(());
    }
    if get_pending_balance_to_withdraw(state, index)? != 0 {
        return Ok(());
    }
    crate::beacon::helpers::electra::initiate_validator_exit(
        state,
        index,
        config,
        Some(active_balances),
    )
}

#[cfg(test)]
mod tests {
    use ethlambda_crypto::lean_xmss;

    use super::*;
    use crate::beacon::fork::ForkName;
    use crate::beacon::hash::hash;
    use crate::beacon::helpers::accessors::{CommitteeCacheExt, get_block_root_at_slot};
    use crate::beacon::helpers::pq::{
        attestation_message, compute_xmss_attestation_leaf_index,
        initialize_aggregation_committee_window,
    };
    use crate::beacon::helpers::test_state::with_validators_at;
    use crate::beacon::primitives::Bytes32;

    /// A key real over `leaves`, for `seed`: a range key, so building one costs
    /// a few hashes rather than a whole top tree.
    fn key(seed: u8, first: u64, last: u64) -> lean_xmss::SecretKey {
        lean_xmss::range_key(&[seed; 32], first as u32, last as u32)
    }

    fn xmss_signature(signature: &lean_xmss::Signature) -> XmssSignature {
        XmssSignature(
            signature
                .to_bytes()
                .try_into()
                .expect("a leanXMSS signature is XMSS_SIGNATURE_SIZE bytes"),
        )
    }

    /// A VRF proof for `slot` under a root it determines: the leaf and every
    /// sibling chosen, the root folded up from the leaf, as
    /// `is_valid_vrf_proof` folds.
    fn vrf_proof_and_root(slot: Slot, leaf: Bytes32) -> (pq::VrfProof, Root) {
        let siblings: Vec<Bytes32> = (0..constants::VRF_TREE_DEPTH)
            // Distinct from any node a test folds, so no level's order is moot.
            .map(|level| Bytes32::repeat_byte(level as u8 + 0x40))
            .collect();
        let branch = siblings.iter().map(|sibling| &sibling.0);
        let root = ethlambda_crypto::vrf::fold_vrf_branch(&leaf.0, branch, slot);
        let mut proof = vec![leaf];
        proof.extend(siblings);
        (
            pq::VrfProof::try_from(proof).expect("VRF_TREE_DEPTH + 1 roots"),
            Root::from(root),
        )
    }

    fn set_key(state: &mut BeaconState, index: ValidatorIndex, pubkey: XmssPubkey, vrf_root: Root) {
        let BeaconState::Pq(inner) = state else {
            panic!("a PQ test state")
        };
        let validator = inner
            .validators
            .get_mut(index as usize)
            .expect("index is in the registry");
        validator.record.pubkey = pubkey.to_request_key();
        validator.vrf_root = vrf_root;
    }

    #[test]
    fn a_valid_vrf_proof_mixes_its_leaf_in() {
        let mut state = with_validators_at(ForkName::Pq, 64);
        let slot = state.slot();
        let proposer = get_beacon_proposer_index(&state).unwrap();
        let leaf = Bytes32::repeat_byte(0xab);
        let (proof, root) = vrf_proof_and_root(slot, leaf);
        set_key(&mut state, proposer, XmssPubkey::default(), root);

        let epoch = get_current_epoch(&state);
        let previous = get_randao_mix(&state, epoch);
        process_randao(&mut state, &proof, RandaoVerification::Verify).unwrap();
        let expected = hash(&[&previous.0[..], &leaf.0, &constants::DOMAIN_RANDAO].concat());
        assert_eq!(get_randao_mix(&state, epoch), expected);
    }

    #[test]
    fn a_vrf_proof_for_another_slot_or_leaf_is_refused() {
        let mut state = with_validators_at(ForkName::Pq, 64);
        let slot = state.slot();
        let proposer = get_beacon_proposer_index(&state).unwrap();
        // A root opening the leaf at the next slot: the same leaf and branch
        // revealed at this slot fold to a different root.
        let (proof, next_slot_root) = vrf_proof_and_root(slot + 1, Bytes32::repeat_byte(1));
        set_key(&mut state, proposer, XmssPubkey::default(), next_slot_root);
        assert!(process_randao(&mut state.clone(), &proof, RandaoVerification::Verify).is_err());

        let (_, root) = vrf_proof_and_root(slot, Bytes32::repeat_byte(1));
        set_key(&mut state, proposer, XmssPubkey::default(), root);
        let (wrong_leaf, _) = vrf_proof_and_root(slot, Bytes32::repeat_byte(2));
        assert!(
            process_randao(&mut state.clone(), &wrong_leaf, RandaoVerification::Verify).is_err()
        );
        // Block production's skip still mixes the reveal in, unchecked.
        assert!(process_randao(&mut state, &wrong_leaf, RandaoVerification::Skip).is_ok());
    }

    /// The tree is hashed with Keccak-256 (`2f43bc0f`). A proof whose root is
    /// folded with SHA-256, the rule before it, is refused.
    #[test]
    fn a_vrf_proof_under_the_earlier_sha256_tree_is_refused() {
        let mut state = with_validators_at(ForkName::Pq, 64);
        let slot = state.slot();
        let proposer = get_beacon_proposer_index(&state).unwrap();
        let (proof, _) = vrf_proof_and_root(slot, Bytes32::repeat_byte(0xab));
        let sha256_root =
            proof[1..]
                .iter()
                .enumerate()
                .fold(proof[0], |value, (level, sibling)| {
                    if (slot >> level) & 1 == 1 {
                        hash(&[sibling.0, value.0].concat())
                    } else {
                        hash(&[value.0, sibling.0].concat())
                    }
                });
        set_key(&mut state, proposer, XmssPubkey::default(), sha256_root);
        assert!(process_randao(&mut state, &proof, RandaoVerification::Verify).is_err());
    }

    #[test]
    fn the_block_signature_is_checked_at_the_slots_proposer_leaf() {
        let mut state = with_validators_at(ForkName::Pq, 64);
        let slot = state.slot() + 1;
        let proposer = 3;
        let leaf = compute_xmss_leaf_index(slot, constants::LEAF_OFFSET_BEACON_PROPOSER).unwrap();
        let secret = key(9, leaf, leaf + 1);
        let pubkey = XmssPubkey(secret.public_key().to_bytes());
        set_key(&mut state, proposer, pubkey, Root::ZERO);

        let block = pq::BeaconBlock {
            slot,
            proposer_index: proposer,
            parent_root: Root::repeat_byte(4),
            state_root: Root::repeat_byte(5),
            body: pq::BeaconBlockBody::empty(),
        };
        let domain = get_domain(&state, constants::DOMAIN_BEACON_PROPOSER, None);
        let signing_root = compute_signing_root(block.hash_tree_root(), domain);
        let sign = |leaf: u64| xmss_signature(&secret.sign(&signing_root.0, leaf as u32).unwrap());

        let signed = pq::SignedBeaconBlock {
            message: block.clone(),
            signature: sign(leaf),
        };
        assert!(verify_block_signature(&state, &signed));
        // The next leaf belongs to another message type of the same slot.
        let wrong_leaf = pq::SignedBeaconBlock {
            message: block,
            signature: sign(leaf + 1),
        };
        assert!(!verify_block_signature(&state, &wrong_leaf));
    }

    /// One attestation from a committee whose members signed at the target
    /// epoch's leaf: the block's proof is their signatures in committee order,
    /// and a proof missing one, or carrying them out of order, is refused.
    #[test]
    fn process_stark_checks_the_attesters_signatures() {
        let mut state = with_validators_at(ForkName::Pq, 64);
        // Attest to the previous slot, which the state has a root for.
        let data_slot = state.slot() - 1;
        let committees = CommitteeCache::default();
        let epoch = compute_epoch_at_slot(data_slot);
        let committee: Vec<ValidatorIndex> = committees
            .committees(&state, epoch)
            .committee(data_slot, 0)
            .unwrap()
            .to_vec();
        assert!(committee.len() >= 2, "the committee has members to sign");

        let data = crate::beacon::containers::shared::AttestationData {
            slot: data_slot,
            index: 0,
            beacon_block_root: get_block_root_at_slot(&state, data_slot).unwrap(),
            source: state.current_justified_checkpoint(),
            target: crate::beacon::containers::shared::Checkpoint {
                epoch,
                root: Root::repeat_byte(6),
            },
        };
        let leaf = compute_xmss_attestation_leaf_index(epoch).unwrap();
        let keys: Vec<lean_xmss::SecretKey> = committee
            .iter()
            .map(|&index| key(index as u8 + 20, leaf, leaf))
            .collect();
        for (&index, secret) in committee.iter().zip(&keys) {
            set_key(
                &mut state,
                index,
                XmssPubkey(secret.public_key().to_bytes()),
                Root::ZERO,
            );
        }
        let (message, statement_leaf) = attestation_message(&state, &data).unwrap();
        assert_eq!(statement_leaf, leaf);
        let signatures: Vec<Vec<u8>> = keys
            .iter()
            .map(|secret| secret.sign(&message.0, leaf as u32).unwrap().to_bytes())
            .collect();

        let mut aggregation_bits = pq::AggregationBits::with_length(committee.len());
        for position in 0..committee.len() {
            aggregation_bits.set(position, true).unwrap();
        }
        let mut committee_bits = pq::CommitteeBits::new();
        committee_bits.set(0, true).unwrap();
        let attestation = pq::Attestation {
            aggregation_bits,
            data,
            committee_bits,
        };

        let body_with = |proof: Vec<u8>| pq::BeaconBlockBody {
            attestations: vec![attestation.clone()].into(),
            proof: proof.try_into().expect("far below MAX_STARK_PROOF_SIZE"),
            ..pq::BeaconBlockBody::empty()
        };
        // The reference encoding: the signatures, in statement order.
        let proof = signatures.concat();
        assert!(process_stark(&state, &body_with(proof.clone()), &committees).is_ok());

        let short = signatures[1..].concat();
        assert!(process_stark(&state, &body_with(short), &committees).is_err());
        let mut reversed = signatures.clone();
        reversed.reverse();
        let reversed = reversed.concat();
        assert!(process_stark(&state, &body_with(reversed), &committees).is_err());
    }

    /// A full-committee attestation to `data_slot` voting for the head and
    /// target the state holds there.
    fn attestation_at(state: &BeaconState, data_slot: Slot) -> pq::Attestation {
        let epoch = compute_epoch_at_slot(data_slot);
        let committee_len = CommitteeCache::default()
            .committees(state, epoch)
            .committee(data_slot, 0)
            .unwrap()
            .len();
        let mut aggregation_bits = pq::AggregationBits::with_length(committee_len);
        for position in 0..committee_len {
            aggregation_bits.set(position, true).unwrap();
        }
        let mut committee_bits = pq::CommitteeBits::new();
        committee_bits.set(0, true).unwrap();
        let source = if epoch == get_current_epoch(state) {
            state.current_justified_checkpoint()
        } else {
            state.previous_justified_checkpoint()
        };
        pq::Attestation {
            aggregation_bits,
            data: crate::beacon::containers::shared::AttestationData {
                slot: data_slot,
                index: 0,
                beacon_block_root: get_block_root_at_slot(state, data_slot).unwrap(),
                source,
                target: crate::beacon::containers::shared::Checkpoint {
                    epoch,
                    root: crate::beacon::helpers::accessors::get_block_root(state, epoch).unwrap(),
                },
            },
            committee_bits,
        }
    }

    /// `MIN_ATTESTATION_INCLUSION_DELAY_PQ`: an attestation from the previous
    /// slot is too recent, and one from two slots back is timely for the head.
    #[test]
    fn attestations_wait_two_slots_and_two_is_timely_for_the_head() {
        let state = with_validators_at(ForkName::Pq, 64);
        let parent_slot = state.slot() - 1;
        let process = |data_slot: Slot| {
            process_attestation(
                &mut state.clone(),
                &attestation_at(&state, data_slot),
                parent_slot,
                &CommitteeCache::default(),
                &ActiveBalanceCache::default(),
                None,
            )
        };
        assert!(process(state.slot() - 1).is_err());
        assert!(process(state.slot() - 2).is_ok());

        let flags = |data_slot: Slot| {
            let data = attestation_at(&state, data_slot).data;
            crate::beacon::helpers::gloas::get_attestation_participation_flag_indices(
                &state,
                &data,
                state.slot() - data_slot,
                parent_slot,
            )
            .unwrap()
        };
        assert!(flags(state.slot() - 2).contains(&constants::TIMELY_HEAD_FLAG_INDEX));
        assert!(!flags(state.slot() - 3).contains(&constants::TIMELY_HEAD_FLAG_INDEX));
    }

    #[test]
    fn a_self_built_bid_must_carry_the_empty_signature() {
        let state = with_validators_at(ForkName::Pq, 64);
        let bid = gloas::ExecutionPayloadBid {
            builder_index: constants::BUILDER_INDEX_SELF_BUILD,
            ..Default::default()
        };
        let mut signed = pq::SignedExecutionPayloadBid {
            message: bid,
            signature: XmssSignature::default(),
        };
        let config = Config::active();
        // An all-zero signature passes the self-build check and fails later,
        // on the bid's slot; a nonzero one fails the self-build check itself.
        let err = process_execution_payload_bid(&mut state.clone(), &signed, &config).unwrap_err();
        assert!(!format!("{err:?}").contains("empty signature"));
        signed.signature.0[0] = 1;
        let err = process_execution_payload_bid(&mut state.clone(), &signed, &config).unwrap_err();
        assert!(format!("{err:?}").contains("empty signature"), "{err:?}");
    }

    #[test]
    fn a_bid_signature_off_the_bid_leaves_is_refused() {
        let mut state = with_validators_at(ForkName::Pq, 64);
        let bid_leaf = constants::XMSS_RESERVED_LEAVES + constants::XMSS_ATTESTATION_LEAVES;
        let secret = key(40, bid_leaf - 1, bid_leaf);
        {
            let inner = state.gloas_family_mut().unwrap();
            inner.builders.push(gloas::Builder {
                pubkey: XmssPubkey(secret.public_key().to_bytes()).to_request_key(),
                ..Default::default()
            });
        }
        let bid = gloas::ExecutionPayloadBid {
            builder_index: 0,
            ..Default::default()
        };
        let domain = get_domain(&state, constants::DOMAIN_BEACON_BUILDER, None);
        let signing_root = compute_signing_root(bid.hash_tree_root(), domain);
        let signed_at = |leaf: u64| pq::SignedExecutionPayloadBid {
            message: bid.clone(),
            signature: xmss_signature(&secret.sign(&signing_root.0, leaf as u32).unwrap()),
        };
        assert!(verify_execution_payload_bid_signature(&state, &signed_at(bid_leaf)).unwrap());
        assert!(!verify_execution_payload_bid_signature(&state, &signed_at(bid_leaf - 1)).unwrap());
    }

    #[test]
    fn preregistrations_bind_deposits_and_expire() {
        let mut state = with_validators_at(ForkName::Pq, 64);
        let pubkey = XmssPubkey([0x55; 32]);
        let credentials = Bytes32::repeat_byte(0x01);
        let vrf_root = Root::repeat_byte(0x77);
        let request = pq::ValidatorPreregistrationRequest {
            pubkey,
            withdrawal_credentials: credentials,
            vrf_root,
        };
        process_validator_preregistration_request(&mut state, &request).unwrap();
        let deposit = |credentials: Bytes32, vrf_root: Root| {
            let mut signature = [0u8; 96];
            signature[..32].copy_from_slice(&vrf_root.0);
            electra::DepositRequest {
                pubkey: pubkey.to_request_key(),
                withdrawal_credentials: credentials,
                amount: 32_000_000_000,
                signature: crate::beacon::primitives::BlsSignature(signature),
                index: 0,
            }
        };
        let pending = |state: &BeaconState| match state {
            BeaconState::Pq(inner) => inner.pending_deposits.len(),
            _ => unreachable!(),
        };
        // A deposit naming other credentials, or another VRF root, is discarded.
        process_deposit_request(&mut state, &deposit(Bytes32::repeat_byte(2), vrf_root)).unwrap();
        process_deposit_request(&mut state, &deposit(credentials, Root::repeat_byte(3))).unwrap();
        assert_eq!(pending(&state), 0);
        // The matching one is queued and uses the binding up.
        process_deposit_request(&mut state, &deposit(credentials, vrf_root)).unwrap();
        assert_eq!(pending(&state), 1);
        let BeaconState::Pq(inner) = &state else {
            unreachable!()
        };
        assert!(inner.validator_preregistrations.is_empty());
        // With a pending deposit for the key, it cannot be preregistered again.
        process_validator_preregistration_request(&mut state, &request).unwrap();
        let BeaconState::Pq(inner) = &state else {
            unreachable!()
        };
        assert!(inner.validator_preregistrations.is_empty());
    }

    #[test]
    fn a_voluntary_exit_request_exits_an_eligible_validator() {
        let mut state = with_validators_at(ForkName::Pq, 64);
        let mut config = Config::active();
        config.shard_committee_period = 0;
        let pubkey = XmssPubkey([0x31; 32]);
        set_key(&mut state, 7, pubkey, Root::ZERO);
        let request = pq::VoluntaryExitRequest { pubkey };
        process_voluntary_exit_request(
            &mut state,
            &request,
            &config,
            &ActiveBalanceCache::default(),
        )
        .unwrap();
        assert_ne!(
            state.validator(7).unwrap().exit_epoch,
            constants::FAR_FUTURE_EPOCH
        );
        // A key nobody holds changes nothing.
        let before = state.clone();
        let unknown = pq::VoluntaryExitRequest {
            pubkey: XmssPubkey([0x32; 32]),
        };
        process_voluntary_exit_request(
            &mut state,
            &unknown,
            &config,
            &ActiveBalanceCache::default(),
        )
        .unwrap();
        assert_eq!(state, before);
    }

    #[test]
    fn a_legacy_withdrawal_request_is_ignored() {
        let mut state = with_validators_at(ForkName::Pq, 64);
        let before = state.clone();
        let mut legacy = crate::beacon::primitives::BlsPubkey::default();
        legacy.0[0] = 0x80;
        let request = electra::WithdrawalRequest {
            source_address: Default::default(),
            validator_pubkey: legacy,
            amount: 0,
        };
        process_withdrawal_request(
            &mut state,
            &request,
            &Config::active(),
            &ActiveBalanceCache::default(),
            &PubkeyIndexCache::default(),
        )
        .unwrap();
        assert_eq!(state, before);
    }

    #[test]
    fn the_aggregation_committee_window_holds_a_sample_of_each_committee() {
        let state = with_validators_at(ForkName::Pq, 64);
        let window = initialize_aggregation_committee_window(&state).unwrap();
        let committees = CommitteeCache::default();
        let epoch = get_current_epoch(&state);
        let slot = crate::beacon::helpers::misc::compute_start_slot_at_epoch(epoch);
        let first = &window[preset::slots_per_epoch() as usize][0];
        let committee = committees
            .committees(&state, epoch)
            .committee(slot, 0)
            .unwrap()
            .to_vec();
        assert!(!first.is_empty());
        assert!(first.len() as u64 <= constants::AGGREGATORS_PER_COMMITTEE);
        assert!(first.iter().all(|member| committee.contains(member)));
        let mut unique = first.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), first.len(), "sampled without duplicates");
        // The previous epoch starts empty.
        assert!(window[0].is_empty());
    }
}
