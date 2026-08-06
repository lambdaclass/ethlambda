//! Deneb-specific block processing.
//!
//! Deneb's headline change is data blobs (EIP-4844): temporary storage for
//! rollup data that the beacon chain commits to but never itself processes.
//! A blob is far larger than everything else a block carries, and consensus
//! never reads its contents, only its existence, so the specification never
//! puts one in the block. Instead a block commits only to a KZG commitment
//! per blob (`blob_kzg_commitments`, appended to `BeaconBlockBody`), and each
//! blob is propagated separately as a [`crate::containers::deneb::BlobSidecar`]
//! over its own gossip subnet. [`kzg_commitment_to_versioned_hash`] is the
//! bridge between the two worlds: it turns a commitment into the same
//! versioned hash form the execution payload's blob-carrying transactions
//! reference, which is what lets [`process_execution_payload`] check that a
//! block's commitments and its payload's transactions agree on which blobs
//! this block actually depends on, without the beacon chain ever holding a
//! blob itself.
//!
//! Deneb's block itself is capella's `process_block` unchanged in structure
//! (header, withdrawals, execution payload, RANDAO, eth1 vote, operations,
//! sync aggregate); see [`process_block`] for exactly which steps are
//! capella's own and which are this module's. Three of those steps change:
//! [`process_attestation`] widens its inclusion-slot check and its
//! timely-target reward condition for EIP-7045, [`process_execution_payload`]
//! checks the block's blob commitments against the execution engine and
//! caches two new blob-gas fields for EIP-4844, and [`process_voluntary_exit`]
//! signs under a fixed fork version for EIP-7044.

use crate::bls;
use crate::config::Config;
use crate::constants::{self, FAR_FUTURE_EPOCH};
use crate::containers::capella::SignedBLSToExecutionChange;
use crate::containers::shared::{AttestationData, Deposit, ProposerSlashing, SignedVoluntaryExit};
use crate::containers::{BeaconState, deneb, phase0};
use crate::error::{Error, Result, verify};
use crate::hash::hash;
use crate::helpers::accessors::{
    get_beacon_committee, get_beacon_proposer_index, get_block_root, get_block_root_at_slot,
    get_committee_count_per_slot, get_current_epoch, get_previous_epoch, get_randao_mix,
};
use crate::helpers::altair::{add_flag, get_base_reward, has_flag};
use crate::helpers::attestation::{
    get_attesting_indices, get_indexed_attestation, is_valid_indexed_attestation,
};
use crate::helpers::math::integer_squareroot;
use crate::helpers::misc::{compute_domain, compute_epoch_at_slot, compute_signing_root};
use crate::helpers::mutators::{decrease_balance, increase_balance, initiate_validator_exit};
use crate::helpers::predicates::is_active_validator;
use crate::preset;
use crate::primitives::{
    Bytes32, Gwei, H256, HashTreeRoot as _, KzgCommitment, ParticipationFlags, ValidatorIndex,
};

use super::ExecutionEngine;

// ---------------------------------------------------------------------------
// Block processing
// ---------------------------------------------------------------------------

/// Deneb's block processing: capella's steps, unchanged in order.
///
/// The specification never lists a "Modified `process_block`" for deneb: the
/// only per-step notes it adds are to [`process_attestation`],
/// [`process_execution_payload`], and [`process_voluntary_exit`], so this
/// mirrors capella's own driver line for line rather than something this
/// module invents. That is also why this dispatches to [`process_operations`]
/// below rather than to [`super::operations::process_operations`] the way
/// bellatrix and altair do: deneb's own attestation and voluntary-exit rules
/// have to reach the block's operations somewhere, and
/// [`super::operations::process_operations`] has no fork check of its own to
/// hang them on. See [`process_operations`]'s own documentation for why that
/// is a full copy of the loop rather than a smaller patch.
pub fn process_block(
    state: &mut BeaconState,
    block: &deneb::BeaconBlock,
    config: &Config,
    engine: &ExecutionEngine,
) -> Result<()> {
    super::block::process_block_header(
        state,
        block.slot,
        block.proposer_index,
        block.parent_root,
        block.body.hash_tree_root(),
    )?;
    process_withdrawals(state, &block.body.execution_payload)?;
    process_execution_payload(
        state,
        &block.body.execution_payload,
        &block.body.blob_kzg_commitments,
        config,
        engine,
    )?;
    super::block::process_randao(state, &block.body.randao_reveal)?;
    super::block::process_eth1_data(state, &block.body.eth1_data)?;
    process_operations(
        state,
        &block.body.proposer_slashings,
        &block.body.attester_slashings,
        &block.body.attestations,
        &block.body.deposits,
        &block.body.voluntary_exits,
        &block.body.bls_to_execution_changes,
        config,
    )?;
    super::altair::process_sync_aggregate(state, &block.body.sync_aggregate)?;
    Ok(())
}

/// Runs every operation in a deneb block, in the specification's order.
///
/// Capella's own body adds exactly one list to phase0's five
/// (`bls_to_execution_changes`), and deneb adds none, so the operations this
/// loops over are identical to capella's. What is not identical is which
/// per-operation function two of those loops call: attestations go to this
/// module's own [`process_attestation`] rather than altair's, and voluntary
/// exits go to this module's own [`process_voluntary_exit`] rather than
/// phase0's, since [`super::operations::process_operations`] (which every
/// earlier fork's driver shares) hard-codes the other two. Rather than teach
/// that shared function a fork check for two operations it does not own the
/// rules for, this copies its loop structure wholesale, the same way the
/// specification itself redefines `process_operations` per fork whenever a
/// body's shape or a called function changes; see this module's own
/// documentation for the alternative (a fork check inside the shared
/// function) and why it was not the one picked.
///
/// The deposit count check is copied unchanged from
/// [`super::operations::process_operations`]: nothing about deposits changed
/// between phase0 and deneb.
///
/// Six lists, one per parameter, is one past clippy's default limit; capella's
/// own `process_operations` carries the identical six and the identical
/// allowance, since a block's operations really do not compress into fewer
/// arguments without inventing a body type this crate deliberately does not
/// have (see [`crate::stf`]'s module documentation).
#[allow(clippy::too_many_arguments)]
fn process_operations(
    state: &mut BeaconState,
    proposer_slashings: &[ProposerSlashing],
    attester_slashings: &[phase0::AttesterSlashing],
    attestations: &[phase0::Attestation],
    deposits: &[Deposit],
    voluntary_exits: &[SignedVoluntaryExit],
    bls_to_execution_changes: &[SignedBLSToExecutionChange],
    config: &Config,
) -> Result<()> {
    let outstanding = state
        .eth1_data()
        .deposit_count
        .checked_sub(state.eth1_deposit_index())
        .ok_or(Error::ArithmeticOverflow(
            "eth1_data.deposit_count - eth1_deposit_index",
        ))?;
    verify(
        deposits.len() as u64 == outstanding.min(preset::MAX_DEPOSITS as u64),
        "len(body.deposits) == min(MAX_DEPOSITS, eth1_data.deposit_count - eth1_deposit_index)",
    )?;

    for proposer_slashing in proposer_slashings {
        super::operations::process_proposer_slashing(state, proposer_slashing, config)?;
    }
    for attester_slashing in attester_slashings {
        super::operations::process_attester_slashing(state, attester_slashing, config)?;
    }
    for attestation in attestations {
        process_attestation(state, attestation)?;
    }
    for deposit in deposits {
        super::operations::process_deposit(state, deposit, config)?;
    }
    for voluntary_exit in voluntary_exits {
        process_voluntary_exit(state, voluntary_exit, config)?;
    }
    for signed_change in bls_to_execution_changes {
        super::capella::process_bls_to_execution_change(state, signed_change, config)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Withdrawals
// ---------------------------------------------------------------------------

/// Applies this slot's withdrawal sweep against a deneb execution payload.
///
/// [`super::capella::get_expected_withdrawals`] is reused unchanged: it
/// depends only on `state`, not on any payload type, since which validators
/// are due a withdrawal has nothing to do with which fork's execution payload
/// carries the result. This function itself cannot be capella's own, despite
/// applying an identical rule, because `payload.withdrawals` has to be
/// compared against a `payload` typed [`deneb::ExecutionPayload`], and that
/// is a different Rust type from `capella::ExecutionPayload` even though
/// both alias the same [`crate::containers::capella::Withdrawal`] element
/// type for the list itself.
///
/// Public, like capella's and electra's counterparts, because the `operations`
/// fixture suite drives each fork's withdrawal step directly rather than through
/// `process_block`.
pub fn process_withdrawals(
    state: &mut BeaconState,
    payload: &deneb::ExecutionPayload,
) -> Result<()> {
    let expected_withdrawals = super::capella::get_expected_withdrawals(state)?;
    verify(
        payload.withdrawals.to_vec() == expected_withdrawals,
        "payload.withdrawals == expected_withdrawals",
    )?;

    for withdrawal in &expected_withdrawals {
        decrease_balance(state, withdrawal.validator_index, withdrawal.amount)?;
    }

    if let Some(latest_withdrawal) = expected_withdrawals.last() {
        deneb_state(state, "process_withdrawals")?.next_withdrawal_index = latest_withdrawal
            .index
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("latest_withdrawal.index + 1"))?;
    }

    let validator_count = state.validators().len() as ValidatorIndex;
    let next_validator_index = if expected_withdrawals.len() == preset::MAX_WITHDRAWALS_PER_PAYLOAD
    {
        let latest_withdrawal = expected_withdrawals
            .last()
            .expect("MAX_WITHDRAWALS_PER_PAYLOAD is never zero, so a full payload is non-empty");
        latest_withdrawal
            .validator_index
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow(
                "latest_withdrawal.validator_index + 1",
            ))?
            % validator_count
    } else {
        let current_cursor =
            deneb_state_ref(state, "process_withdrawals")?.next_withdrawal_validator_index;
        current_cursor
            .checked_add(preset::MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP)
            .ok_or(Error::ArithmeticOverflow(
                "next_withdrawal_validator_index + MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP",
            ))?
            % validator_count
    };
    deneb_state(state, "process_withdrawals")?.next_withdrawal_validator_index =
        next_validator_index;

    Ok(())
}

// ---------------------------------------------------------------------------
// Attestations
// ---------------------------------------------------------------------------

/// Scores an attestation and pays its including proposer, widening altair's
/// rule for EIP-7045.
///
/// Shares its validation prologue with
/// [`crate::helpers::altair::get_attestation_participation_flag_indices`]'s
/// caller in altair (target epoch, committee shape, signature), with one
/// prologue check dropped: altair also demands `state.slot <= data.slot +
/// SLOTS_PER_EPOCH`, an upper bound on how late an attestation may still be
/// included. FFG justification itself has no such bound; a source vote
/// either extends the justified chain or it does not, however late it
/// lands. Deneb drops the bound to match, and widens
/// [`attestation_participation_flag_indices`] the same way: the timely-target
/// flag no longer checks `inclusion_delay` at all, so a late-but-correct
/// target vote is not paid for its correctness one moment and then refused
/// the reward for the exact same vote the moment altair's old window closed.
///
/// Structured as the same two-phase read-then-write split altair's version
/// uses, and for the identical reason: deciding which flags this attestation
/// newly grants only ever reads `state`, while flipping them needs `&mut
/// state`, and the two cannot interleave in one pass without conflicting
/// borrows (see altair's `process_attestation` for the borrow-checker
/// argument in full).
pub fn process_attestation(
    state: &mut BeaconState,
    attestation: &phase0::Attestation,
) -> Result<()> {
    let data = attestation.data;
    let current_epoch = get_current_epoch(state);
    let previous_epoch = get_previous_epoch(state);

    verify(
        data.target.epoch == previous_epoch || data.target.epoch == current_epoch,
        "data.target.epoch in (get_previous_epoch(state), get_current_epoch(state))",
    )?;
    verify(
        data.target.epoch == compute_epoch_at_slot(data.slot),
        "data.target.epoch == compute_epoch_at_slot(data.slot)",
    )?;

    // [EIP-7045]: no upper bound on `state.slot` here, unlike altair; see this
    // function's own documentation for why. `data.slot` still comes straight
    // off the wire, so the lower bound's own addition is still checked.
    let min_slot = data
        .slot
        .checked_add(preset::MIN_ATTESTATION_INCLUSION_DELAY)
        .ok_or(Error::ArithmeticOverflow(
            "data.slot + MIN_ATTESTATION_INCLUSION_DELAY",
        ))?;
    verify(
        min_slot <= state.slot(),
        "data.slot + MIN_ATTESTATION_INCLUSION_DELAY <= state.slot",
    )?;
    verify(
        data.index < get_committee_count_per_slot(state, data.target.epoch),
        "data.index < get_committee_count_per_slot(state, data.target.epoch)",
    )?;

    let committee = get_beacon_committee(state, data.slot, data.index)?;
    verify(
        attestation.aggregation_bits.len() == committee.len(),
        "len(attestation.aggregation_bits) == len(committee)",
    )?;

    // Safe: `min_slot <= state.slot()` above and `min_slot >= data.slot` (the
    // inclusion delay is non-negative), so `data.slot <= state.slot()`.
    let inclusion_delay = state.slot() - data.slot;
    let participation_flag_indices =
        attestation_participation_flag_indices(state, &data, inclusion_delay)?;

    let indexed_attestation = get_indexed_attestation(state, attestation)?;
    verify(
        is_valid_indexed_attestation(state, &indexed_attestation),
        "is_valid_indexed_attestation(state, get_indexed_attestation(state, attestation))",
    )?;

    // Read phase: for every attester, decide which flags this attestation
    // newly satisfies and add up the proposer's reward for granting them.
    let attesting_indices = get_attesting_indices(state, attestation)?;
    let current_epoch_target = data.target.epoch == current_epoch;
    // Through the fork-generic accessor, not a projection to a concrete
    // `altair::BeaconState`. The participation lists are unchanged from altair
    // through fulu, so a projection matching only `BeaconState::Altair` rejects
    // every deneb state, which is the only kind this function is ever called
    // with: it made deneb's attestation processing fail outright.
    let (previous_participation, current_participation, _) = state.altair_validator_lists()?;
    let epoch_participation = if current_epoch_target {
        current_participation
    } else {
        previous_participation
    };

    let mut proposer_reward_numerator: Gwei = 0;
    let mut updates: Vec<(ValidatorIndex, ParticipationFlags)> = Vec::new();
    for index in attesting_indices {
        let current_flags =
            epoch_participation
                .get(index as usize)
                .copied()
                .ok_or(Error::IndexOutOfBounds {
                    index: index as usize,
                    len: epoch_participation.len(),
                })?;

        let mut new_flags: ParticipationFlags = 0;
        for &flag_index in &participation_flag_indices {
            if has_flag(current_flags, flag_index) {
                continue;
            }
            new_flags = add_flag(new_flags, flag_index);
            let weight = constants::PARTICIPATION_FLAG_WEIGHTS[flag_index];
            let reward = get_base_reward(state, index)?.checked_mul(weight).ok_or(
                Error::ArithmeticOverflow("get_base_reward(state, index) * weight"),
            )?;
            proposer_reward_numerator = proposer_reward_numerator
                .checked_add(reward)
                .ok_or(Error::ArithmeticOverflow("proposer_reward_numerator"))?;
        }
        if new_flags != 0 {
            updates.push((index, new_flags));
        }
    }

    // Write phase: apply exactly the flags the read phase decided on.
    let (previous_participation, current_participation, _) = state.altair_validator_lists_mut()?;
    let epoch_participation = if current_epoch_target {
        current_participation
    } else {
        previous_participation
    };
    let epoch_participation_len = epoch_participation.len();
    for (index, new_flags) in updates {
        let flags = epoch_participation
            .get_mut(index as usize)
            .ok_or(Error::IndexOutOfBounds {
                index: index as usize,
                len: epoch_participation_len,
            })?;
        *flags |= new_flags;
    }

    const NON_PROPOSER_WEIGHT: u64 = constants::WEIGHT_DENOMINATOR - constants::PROPOSER_WEIGHT;
    const PROPOSER_REWARD_DENOMINATOR: u64 =
        NON_PROPOSER_WEIGHT * constants::WEIGHT_DENOMINATOR / constants::PROPOSER_WEIGHT;
    let proposer_reward = proposer_reward_numerator / PROPOSER_REWARD_DENOMINATOR;
    let proposer_index = get_beacon_proposer_index(state)?;
    increase_balance(state, proposer_index, proposer_reward)?;

    Ok(())
}

/// Which of the three participation flags an attestation with `data`,
/// included after `inclusion_delay` slots, satisfies.
///
/// Deneb's version of
/// [`crate::helpers::altair::get_attestation_participation_flag_indices`]:
/// EIP-7045 grants the timely-target flag to every correctly-targeted
/// attestation regardless of `inclusion_delay`, rather than only within
/// altair's one-epoch reward window. The source and head conditions are
/// altair's, unchanged. See [`process_attestation`]'s own documentation for
/// why the two forks diverge here at all.
fn attestation_participation_flag_indices(
    state: &BeaconState,
    data: &AttestationData,
    inclusion_delay: u64,
) -> Result<Vec<usize>> {
    let justified_checkpoint = if data.target.epoch == get_current_epoch(state) {
        state.current_justified_checkpoint()
    } else {
        state.previous_justified_checkpoint()
    };
    let is_matching_source = data.source == justified_checkpoint;

    let target_root = get_block_root(state, data.target.epoch)?;
    let target_root_matches = data.target.root == target_root;
    let is_matching_target = is_matching_source && target_root_matches;

    let head_root = get_block_root_at_slot(state, data.slot)?;
    let head_root_matches = data.beacon_block_root == head_root;
    let is_matching_head = is_matching_target && head_root_matches;

    verify(is_matching_source, "is_matching_source")?;

    let mut participation_flag_indices = Vec::new();
    if is_matching_source && inclusion_delay <= integer_squareroot(preset::SLOTS_PER_EPOCH) {
        participation_flag_indices.push(constants::TIMELY_SOURCE_FLAG_INDEX);
    }
    // [EIP-7045]: no `inclusion_delay` bound, unlike altair's
    // `inclusion_delay <= SLOTS_PER_EPOCH`.
    if is_matching_target {
        participation_flag_indices.push(constants::TIMELY_TARGET_FLAG_INDEX);
    }
    if is_matching_head && inclusion_delay == preset::MIN_ATTESTATION_INCLUSION_DELAY {
        participation_flag_indices.push(constants::TIMELY_HEAD_FLAG_INDEX);
    }

    Ok(participation_flag_indices)
}

// ---------------------------------------------------------------------------
// Execution payload
// ---------------------------------------------------------------------------

/// Validates this slot's execution payload and its blob commitments, then
/// caches the payload's header alongside deneb's two new blob-gas fields.
///
/// Takes `config`, which the specification's own three-argument
/// `process_execution_payload(state, body, execution_engine)` does not:
/// [`super::bellatrix::compute_timestamp_at_slot`] needs one, for the same
/// reason bellatrix's own version of this function does, and this crate
/// systematically hands every function needing a configuration value one
/// explicitly rather than reaching for a global.
///
/// Also takes `blob_kzg_commitments` on its own, separate from `payload`,
/// rather than a whole body, matching how every shared step in
/// [`super::block`] takes only the fields it reads (see [`crate::stf`]'s
/// module documentation for why no shared body type exists to pass instead):
/// the commitments live on the block body, not the payload, and this is the
/// one step that needs them, since [`kzg_commitment_to_versioned_hash`] turns
/// each into the same versioned-hash form a blob-carrying transaction inside
/// `payload.transactions` commits to, which is exactly what the
/// specification's `NewPayloadRequest.versioned_hashes` reconciles against
/// `is_valid_versioned_hashes`.
///
/// That reconciliation itself is not checked here, for the same reason
/// [`super::bellatrix::process_execution_payload`] cannot check
/// `payload.block_hash` against a transaction's own contents either: this
/// crate's `Transaction` is opaque bytes, never decoded, so nothing here can
/// extract a transaction's claimed versioned hashes to compare. It collapses,
/// like the rest of `verify_and_notify_new_payload`, into
/// [`ExecutionEngine::execution_valid`]; the versioned hashes are still
/// computed unconditionally, both so [`kzg_commitment_to_versioned_hash`] is
/// exercised the way the specification's own data flow exercises it, and so a
/// future engine model with something real to check against has the value
/// ready to hand it.
///
/// What this function can and does check on its own, without any engine at
/// all, is the commitment count: [`Config::max_blobs_per_block_deneb`] is
/// this fork's fixed cap, configuration rather than a preset because
/// electra raises it and fulu's blob schedule (EIP-7892) can raise it again
/// without a further hard fork; see [`Config::max_blobs_per_block`]'s own
/// documentation for why deneb reads the fixed field directly instead of
/// going through that schedule-aware lookup.
///
/// No `is_merge_transition_complete` check, unlike bellatrix's version:
/// capella's specification already removes it on the grounds that a chain
/// still pre-merge by capella cannot exist, and deneb inherits that removal
/// unchanged.
pub fn process_execution_payload(
    state: &mut BeaconState,
    payload: &deneb::ExecutionPayload,
    blob_kzg_commitments: &[KzgCommitment],
    config: &Config,
    engine: &ExecutionEngine,
) -> Result<()> {
    let deneb_ref = deneb_state_ref(state, "process_execution_payload")?;
    verify(
        payload.parent_hash == deneb_ref.latest_execution_payload_header.block_hash,
        "payload.parent_hash == state.latest_execution_payload_header.block_hash",
    )?;
    verify(
        payload.prev_randao == get_randao_mix(state, get_current_epoch(state)),
        "payload.prev_randao == get_randao_mix(state, get_current_epoch(state))",
    )?;
    verify(
        payload.timestamp
            == super::bellatrix::compute_timestamp_at_slot(state, state.slot(), config),
        "payload.timestamp == compute_time_at_slot(state, state.slot)",
    )?;
    verify(
        blob_kzg_commitments.len() as u64 <= config.max_blobs_per_block_deneb,
        "len(body.blob_kzg_commitments) <= MAX_BLOBS_PER_BLOCK",
    )?;

    // See this function's own documentation for why this is computed but not
    // itself checked against anything.
    let _versioned_hashes: Vec<Bytes32> = blob_kzg_commitments
        .iter()
        .map(kzg_commitment_to_versioned_hash)
        .collect();

    verify(
        engine.execution_valid,
        "verify_and_notify_new_payload(NewPayloadRequest(execution_payload=payload, \
         versioned_hashes=versioned_hashes, \
         parent_beacon_block_root=state.latest_block_header.parent_root))",
    )?;

    let header = deneb::ExecutionPayloadHeader {
        parent_hash: payload.parent_hash,
        fee_recipient: payload.fee_recipient,
        state_root: payload.state_root,
        receipts_root: payload.receipts_root,
        logs_bloom: payload.logs_bloom.clone(),
        prev_randao: payload.prev_randao,
        block_number: payload.block_number,
        gas_limit: payload.gas_limit,
        gas_used: payload.gas_used,
        timestamp: payload.timestamp,
        extra_data: payload.extra_data.clone(),
        base_fee_per_gas: payload.base_fee_per_gas,
        block_hash: payload.block_hash,
        // The header substitutes a root for each bulky list; see
        // `super::bellatrix`'s own documentation for why the state keeps only
        // that much.
        transactions_root: payload.transactions.hash_tree_root(),
        withdrawals_root: payload.withdrawals.hash_tree_root(),
        blob_gas_used: payload.blob_gas_used,
        excess_blob_gas: payload.excess_blob_gas,
    };
    deneb_state(state, "process_execution_payload")?.latest_execution_payload_header = header;

    Ok(())
}

/// A blob's versioned hash: the form its KZG commitment takes wherever a
/// blob-carrying transaction references it, so [`process_execution_payload`]
/// can reconcile the two without decoding a transaction itself.
///
/// Not a bare hash of the commitment: overwriting the hash's own first byte
/// with [`constants::VERSIONED_HASH_VERSION_KZG`] is what lets the execution
/// layer's transaction format tell a KZG-backed versioned hash apart from a
/// different kind of hash-derived identifier it might introduce later under a
/// different version byte, without either layer needing to know which
/// commitment scheme produced any given one.
pub fn kzg_commitment_to_versioned_hash(commitment: &KzgCommitment) -> Bytes32 {
    let digest = hash(&commitment.0);
    let mut versioned_hash = digest.0;
    versioned_hash[0] = constants::VERSIONED_HASH_VERSION_KZG;
    H256(versioned_hash)
}

// ---------------------------------------------------------------------------
// Voluntary exits
// ---------------------------------------------------------------------------

/// Starts a validator's voluntary exit, signed under a fixed fork version for
/// EIP-7044.
///
/// Every check but the last is phase0's, unchanged: still active, not already
/// exiting, past its own requested epoch, and past `SHARD_COMMITTEE_PERIOD`
/// since activation. What changes is the domain the signature is checked
/// against. Every other signed message in this crate calls
/// [`crate::helpers::accessors::get_domain`], which signs under whichever
/// fork version is active at the message's own epoch, so the same message
/// signed just before and just after a fork boundary produces two different,
/// mutually invalid signatures. A voluntary exit is deliberately signed far
/// in advance of the epoch it takes effect at (a validator may queue its exit
/// long before it is eligible to leave), so binding it to "whichever fork is
/// current" means a signature made under, say, capella would stop verifying
/// the moment the chain forked into deneb, silently expiring a validator's
/// already-signed intent to leave through no fault of its own. Fixing the
/// domain to [`Config::capella_fork_version`] instead, forever, regardless of
/// which fork actually processes the exit, is what makes a signed exit
/// perpetually valid: the same signature verifies whether it is processed the
/// moment it is signed or years and several forks later.
///
/// `CAPELLA_FORK_VERSION` specifically, not deneb's own, because EIP-7044
/// shipped at deneb but pins the version one fork earlier: capella is the
/// latest fork every already-signed exit on a live network could have been
/// signed under, so pinning there (rather than to deneb's own version, which
/// no exit signed before deneb activated could have used) is what keeps
/// every exit signed before this rule existed valid under it too.
pub fn process_voluntary_exit(
    state: &mut BeaconState,
    signed_voluntary_exit: &SignedVoluntaryExit,
    config: &Config,
) -> Result<()> {
    let voluntary_exit = signed_voluntary_exit.message;
    let current_epoch = get_current_epoch(state);
    let validator = state.validator(voluntary_exit.validator_index)?;

    verify(
        is_active_validator(validator, current_epoch),
        "is_active_validator(validator, get_current_epoch(state))",
    )?;
    verify(
        validator.exit_epoch == FAR_FUTURE_EPOCH,
        "validator.exit_epoch == FAR_FUTURE_EPOCH",
    )?;
    verify(
        current_epoch >= voluntary_exit.epoch,
        "get_current_epoch(state) >= voluntary_exit.epoch",
    )?;
    let eligible_epoch = validator
        .activation_epoch
        .checked_add(config.shard_committee_period)
        .ok_or(Error::ArithmeticOverflow(
            "validator.activation_epoch + SHARD_COMMITTEE_PERIOD",
        ))?;
    verify(
        current_epoch >= eligible_epoch,
        "get_current_epoch(state) >= validator.activation_epoch + SHARD_COMMITTEE_PERIOD",
    )?;

    // [EIP-7044]: a fixed fork version rather than `get_domain`'s
    // current-epoch lookup; see this function's own documentation for why.
    let domain = compute_domain(
        constants::DOMAIN_VOLUNTARY_EXIT,
        config.capella_fork_version,
        state.genesis_validators_root(),
    );
    let signing_root = compute_signing_root(voluntary_exit.hash_tree_root(), domain);
    verify(
        bls::verify(
            &validator.pubkey,
            signing_root,
            &signed_voluntary_exit.signature,
        ),
        "bls.Verify(validator.pubkey, signing_root, signed_voluntary_exit.signature)",
    )?;

    initiate_validator_exit(state, voluntary_exit.validator_index, config)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Fork projection
// ---------------------------------------------------------------------------

/// The deneb state, mutably, or an error naming the function that needs one.
///
/// Scoped to `BeaconState::Deneb` alone, the same deliberately narrow scope
/// [`super::bellatrix::bellatrix_state`] documents for itself: every caller
/// here is reached only through [`process_block`], which
/// [`super::block::process_block`] dispatches to precisely when `state` is
/// already `BeaconState::Deneb`.
fn deneb_state<'a>(
    state: &'a mut BeaconState,
    function: &'static str,
) -> Result<&'a mut deneb::BeaconState> {
    match state {
        BeaconState::Deneb(state) => Ok(state),
        other => Err(Error::UnsupportedForFork {
            function,
            fork: other.fork_name(),
        }),
    }
}

/// The deneb state, immutably. See [`deneb_state`].
fn deneb_state_ref<'a>(
    state: &'a BeaconState,
    function: &'static str,
) -> Result<&'a deneb::BeaconState> {
    match state {
        BeaconState::Deneb(state) => Ok(state),
        other => Err(Error::UnsupportedForFork {
            function,
            fork: other.fork_name(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kzg_commitment_to_versioned_hash_overwrites_only_the_first_byte() {
        let commitment = KzgCommitment([7; 48]);
        let digest = hash(&commitment.0);

        let versioned_hash = kzg_commitment_to_versioned_hash(&commitment);

        assert_eq!(versioned_hash.0[0], constants::VERSIONED_HASH_VERSION_KZG);
        assert_eq!(&versioned_hash.0[1..], &digest.0[1..]);
    }

    #[test]
    fn kzg_commitment_to_versioned_hash_is_sensitive_to_the_whole_commitment() {
        let a = KzgCommitment([1; 48]);
        let b = KzgCommitment([2; 48]);
        assert_ne!(
            kzg_commitment_to_versioned_hash(&a),
            kzg_commitment_to_versioned_hash(&b)
        );
    }
}
