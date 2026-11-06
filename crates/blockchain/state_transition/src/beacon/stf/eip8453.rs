//! EIP-8453's block processing: the finality gadget's attestations and height
//! events, head votes, and both kinds of attester slashing.
//!
//! [`process_block`] is heze's step list with [`process_operations`]
//! rewritten and [`process_height_events`] appended, which runs once, after
//! every attestation of the block. Every other step is gloas's own function
//! (heze keeps them, and so does this fork): the parent payload, header,
//! withdrawals, bid, RANDAO and sync aggregate steps, and among the
//! operations the proposer slashings, voluntary exits, BLS-to-execution
//! changes and payload attestations.
//!
//! Transcribed from `specs/_features/eip8453/beacon-chain.md` at
//! ethereum/consensus-specs `0f4fa3ffdd26ec083ff4dba65645d81433178413`.

use crate::beacon::bls;
use crate::beacon::config::Config;
use crate::beacon::constants;
use crate::beacon::containers::{BeaconState, eip8453, gloas};
use crate::beacon::error::{Error, Result, verify};
use crate::beacon::helpers::accessors::{
    ActiveBalanceCache, get_beacon_proposer_index, get_current_epoch, get_domain,
    get_previous_epoch, get_total_active_balance,
};
use crate::beacon::helpers::eip8453::{
    add_participation_flag, eip8453_state, eip8453_state_mut, get_attesting_indices,
    get_head_vote_committee, get_indexed_attestation, has_quorum, is_head_vote_same_slot,
    is_slashable_attestation_data, is_slashable_legacy_attestation_data, is_valid_aggregation_bits,
    is_valid_attestation_data, is_valid_indexed_attestation, is_valid_legacy_indexed_attestation,
    is_well_formed_attestation_data, round_base_reward,
};
use crate::beacon::helpers::misc::{compute_epoch_at_slot, compute_signing_root};
use crate::beacon::helpers::mutators::increase_balance;
use crate::beacon::preset;
use crate::beacon::primitives::{Gwei, HashTreeRoot as _, Root, ValidatorIndex};

use super::block::BlockProcessingOptions;

// ---------------------------------------------------------------------------
// Block processing
// ---------------------------------------------------------------------------

/// `process_block` (modified): heze's, with this fork's
/// [`process_operations`] (no `parent_slot` any more) and
/// [`process_height_events`] after the sync aggregate.
pub fn process_block(
    state: &mut BeaconState,
    block: &eip8453::BeaconBlock,
    config: &Config,
    active_balances: &ActiveBalanceCache,
    options: BlockProcessingOptions,
) -> Result<()> {
    eip8453_state(state, "process_block")?;
    let body = &block.body;
    super::gloas::process_parent_execution_payload(
        state,
        &body.signed_execution_payload_bid.message,
        &body.parent_execution_requests,
        config,
    )?;
    super::block::process_block_header(
        state,
        block.slot,
        block.proposer_index,
        block.parent_root,
        body.hash_tree_root(),
    )?;
    super::gloas::process_withdrawals(state)?;
    super::gloas::process_execution_payload_bid(state, &body.signed_execution_payload_bid, config)?;
    super::block::process_randao(state, &body.randao_reveal, options.randao)?;
    // [Modified in EIP8453]
    process_operations(state, body, config)?;
    super::altair::process_sync_aggregate(state, &body.sync_aggregate, active_balances, config)?;
    // [New in EIP8453]
    process_height_events(state)?;
    Ok(())
}

/// `process_operations` (modified): the new attester slashings, the legacy
/// ones, this fork's attestations and the head votes, each list bounded by
/// its preset maximum (the lists are progressive, so the container does not
/// bound them), and `head_vote_support` exactly as long as `head_votes`.
pub fn process_operations(
    state: &mut BeaconState,
    body: &eip8453::BeaconBlockBody,
    config: &Config,
) -> Result<()> {
    verify(
        body.proposer_slashings.len() <= preset::MAX_PROPOSER_SLASHINGS,
        "process_operations: len(body.proposer_slashings) <= MAX_PROPOSER_SLASHINGS",
    )?;
    verify(
        body.attester_slashings.len() <= preset::MAX_ATTESTER_SLASHINGS_ELECTRA,
        "process_operations: len(body.attester_slashings) <= MAX_ATTESTER_SLASHINGS_ELECTRA",
    )?;
    // [New in EIP8453]
    verify(
        body.legacy_attester_slashings.len() <= preset::MAX_ATTESTER_SLASHINGS_ELECTRA,
        "process_operations: len(body.legacy_attester_slashings) <= MAX_ATTESTER_SLASHINGS_ELECTRA",
    )?;
    verify(
        body.attestations.len() <= preset::MAX_ATTESTATIONS_ELECTRA,
        "process_operations: len(body.attestations) <= MAX_ATTESTATIONS_ELECTRA",
    )?;
    verify(
        body.voluntary_exits.len() <= preset::MAX_VOLUNTARY_EXITS,
        "process_operations: len(body.voluntary_exits) <= MAX_VOLUNTARY_EXITS",
    )?;
    verify(
        body.bls_to_execution_changes.len() <= preset::MAX_BLS_TO_EXECUTION_CHANGES,
        "process_operations: len(body.bls_to_execution_changes) <= MAX_BLS_TO_EXECUTION_CHANGES",
    )?;
    verify(
        body.payload_attestations.len() as u64 <= preset::MAX_PAYLOAD_ATTESTATIONS,
        "process_operations: len(body.payload_attestations) <= MAX_PAYLOAD_ATTESTATIONS",
    )?;
    // [New in EIP8453]
    verify(
        body.head_votes.len() as u64 <= preset::MAX_HEAD_VOTES,
        "process_operations: len(body.head_votes) <= MAX_HEAD_VOTES",
    )?;
    // [New in EIP8453]
    verify(
        body.head_vote_support.len() == body.head_votes.len(),
        "process_operations: len(body.head_vote_support) == len(body.head_votes)",
    )?;

    for proposer_slashing in body.proposer_slashings.iter() {
        super::gloas::process_proposer_slashing(state, proposer_slashing, config)?;
    }
    for attester_slashing in body.attester_slashings.iter() {
        process_attester_slashing(state, attester_slashing, config)?;
    }
    // [New in EIP8453]
    for attester_slashing in body.legacy_attester_slashings.iter() {
        process_legacy_attester_slashing(state, attester_slashing, config)?;
    }
    // [Modified in EIP8453]
    for attestation in body.attestations.iter() {
        process_attestation(state, attestation)?;
    }
    for voluntary_exit in body.voluntary_exits.iter() {
        super::electra::process_voluntary_exit(state, voluntary_exit, config)?;
    }
    for signed_change in body.bls_to_execution_changes.iter() {
        super::capella::process_bls_to_execution_change(state, signed_change, config)?;
    }
    for payload_attestation in body.payload_attestations.iter() {
        super::gloas::process_payload_attestation(state, payload_attestation, config)?;
    }
    // [New in EIP8453]
    for (vote, support_bits) in body.head_votes.iter().zip(body.head_vote_support.iter()) {
        process_head_vote(state, vote, support_bits, config)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Attester slashings
// ---------------------------------------------------------------------------

/// `process_attester_slashing`, which the specification does not restate:
/// phase0's rule over this fork's [`eip8453::AttesterSlashing`], with the
/// finality gadget's [`is_slashable_attestation_data`] and
/// [`is_valid_indexed_attestation`].
pub fn process_attester_slashing(
    state: &mut BeaconState,
    attester_slashing: &eip8453::AttesterSlashing,
    config: &Config,
) -> Result<()> {
    let attestation_1 = &attester_slashing.attestation_1;
    let attestation_2 = &attester_slashing.attestation_2;
    verify(
        is_slashable_attestation_data(&attestation_1.data, &attestation_2.data),
        "process_attester_slashing: is_slashable_attestation_data(attestation_1.data, attestation_2.data)",
    )?;
    verify(
        is_valid_indexed_attestation(state, attestation_1),
        "process_attester_slashing: is_valid_indexed_attestation(state, attestation_1)",
    )?;
    verify(
        is_valid_indexed_attestation(state, attestation_2),
        "process_attester_slashing: is_valid_indexed_attestation(state, attestation_2)",
    )?;
    super::operations::slash_attesting_index_intersection(
        state,
        &attestation_1.attesting_indices,
        &attestation_2.attesting_indices,
        config,
    )
}

/// `process_legacy_attester_slashing`: Casper FFG's rule for slashings of
/// attestations made before the upgrade, in heze's (gloas's)
/// [`gloas::AttesterSlashing`] shape.
pub fn process_legacy_attester_slashing(
    state: &mut BeaconState,
    attester_slashing: &gloas::AttesterSlashing,
    config: &Config,
) -> Result<()> {
    let attestation_1 = &attester_slashing.attestation_1;
    let attestation_2 = &attester_slashing.attestation_2;
    verify(
        is_slashable_legacy_attestation_data(&attestation_1.data, &attestation_2.data),
        "process_legacy_attester_slashing: is_slashable_legacy_attestation_data(attestation_1.data, attestation_2.data)",
    )?;
    verify(
        is_valid_legacy_indexed_attestation(state, attestation_1),
        "process_legacy_attester_slashing: is_valid_legacy_indexed_attestation(state, attestation_1)",
    )?;
    verify(
        is_valid_legacy_indexed_attestation(state, attestation_2),
        "process_legacy_attester_slashing: is_valid_legacy_indexed_attestation(state, attestation_2)",
    )?;
    super::operations::slash_attesting_index_intersection(
        state,
        &attestation_1.attesting_indices,
        &attestation_2.attesting_indices,
        config,
    )
}

// ---------------------------------------------------------------------------
// Attestations
// ---------------------------------------------------------------------------

/// `process_attestation` (rewritten for the finality gadget).
///
/// Records each attester's finality pair against the pending justification it
/// names and its height pair against the current target, crediting a flag
/// (and the proposer's share) only the first time each is recorded, in the
/// round the attestation is included.
///
/// `get_round_base_reward` reads `get_total_active_balance(state)`, which
/// nothing in this function changes, so it is computed once rather than per
/// attester.
pub fn process_attestation(
    state: &mut BeaconState,
    attestation: &eip8453::Attestation,
) -> Result<()> {
    let data = attestation.data;
    let current_epoch = get_current_epoch(state);
    {
        let inner = eip8453_state(state, "process_attestation")?;
        verify(
            is_well_formed_attestation_data(&data),
            "process_attestation: is_well_formed_attestation_data(data)",
        )?;
        verify(
            is_valid_attestation_data(inner, &data),
            "process_attestation: is_valid_attestation_data(state, data)",
        )?;
        verify(
            attestation.epoch <= current_epoch,
            "process_attestation: attestation.epoch <= get_current_epoch(state)",
        )?;
        verify(
            attestation.epoch >= compute_epoch_at_slot(inner.finalized_slot),
            "process_attestation: attestation.epoch >= compute_epoch_at_slot(state.finalized_slot)",
        )?;
    }
    verify(
        is_valid_aggregation_bits(state, attestation.epoch, attestation)?,
        "process_attestation: is_valid_aggregation_bits(state, attestation.epoch, attestation)",
    )?;
    verify(
        is_valid_indexed_attestation(state, &get_indexed_attestation(state, attestation)?),
        "process_attestation: is_valid_indexed_attestation(state, get_indexed_attestation(state, attestation))",
    )?;

    let attesting_indices = get_attesting_indices(state, attestation)?;
    let total_active_balance = get_total_active_balance(state)?;
    let mut base_rewards = Vec::with_capacity(attesting_indices.len());
    for &index in &attesting_indices {
        let effective_balance = state.validator(index)?.effective_balance;
        base_rewards.push((
            index,
            round_base_reward(effective_balance, total_active_balance),
        ));
    }

    let overflow = || Error::ArithmeticOverflow("process_attestation: proposer_reward_numerator");
    let mut proposer_reward_numerator: Gwei = 0;
    let inner = eip8453_state_mut(state, "process_attestation")?;
    for (index, base_reward) in base_rewards {
        let position = index as usize;
        // Pending checkpoints have distinct heights, so at most one matches;
        // its participation is read only when it does, as the
        // specification's `and` reads it.
        let mut finality_credits: u64 = 0;
        for pending in inner.pending_finality.iter_mut() {
            if pending.checkpoint != data.finality {
                continue;
            }
            let len = pending.participation.len();
            let participated =
                pending
                    .participation
                    .get_mut(position)
                    .ok_or(Error::IndexOutOfBounds {
                        index: position,
                        len,
                    })?;
            if !*participated {
                *participated = true;
                finality_credits += 1;
            }
        }
        for _ in 0..finality_credits {
            add_participation_flag(inner, index, constants::FINALITY_FLAG_INDEX)?;
            let reward = base_reward
                .checked_mul(constants::FINALITY_WEIGHT)
                .ok_or_else(overflow)?;
            proposer_reward_numerator = proposer_reward_numerator
                .checked_add(reward)
                .ok_or_else(overflow)?;
        }
        if data.target == inner.target_checkpoint {
            let len = inner.progress_participation.len();
            let progressed =
                inner
                    .progress_participation
                    .get_mut(position)
                    .ok_or(Error::IndexOutOfBounds {
                        index: position,
                        len,
                    })?;
            if !*progressed {
                *progressed = true;
                add_participation_flag(inner, index, constants::PROGRESS_FLAG_INDEX)?;
                let reward = base_reward
                    .checked_mul(constants::PROGRESS_WEIGHT)
                    .ok_or_else(overflow)?;
                proposer_reward_numerator = proposer_reward_numerator
                    .checked_add(reward)
                    .ok_or_else(overflow)?;
            }
            if !data.timeout {
                let len = inner.target_participation.len();
                *inner
                    .target_participation
                    .get_mut(position)
                    .ok_or(Error::IndexOutOfBounds {
                        index: position,
                        len,
                    })? = true;
            }
        }
    }

    let reward_divisor = (constants::WEIGHT_DENOMINATOR - constants::PROPOSER_WEIGHT)
        * constants::WEIGHT_DENOMINATOR
        / constants::PROPOSER_WEIGHT;
    let proposer_reward = proposer_reward_numerator / reward_divisor;
    let proposer_index = get_beacon_proposer_index(state)?;
    increase_balance(state, proposer_index, proposer_reward)
}

// ---------------------------------------------------------------------------
// Head votes
// ---------------------------------------------------------------------------

/// `process_head_vote`: checks a head vote of the previous or current epoch
/// against the cached head vote committee of its slot and its aggregate
/// signature, and records, for a vote for the block of its own slot, which
/// committee seats cast it (what builder payments are weighed by).
///
/// `support_bits` may only be set for a vote of the previous slot.
pub fn process_head_vote(
    state: &mut BeaconState,
    vote: &eip8453::HeadVote,
    support_bits: &eip8453::HeadVoteSupportBits,
    config: &Config,
) -> Result<()> {
    let data = vote.data;
    let state_slot = state.slot();
    let data_epoch = compute_epoch_at_slot(data.slot);
    verify(
        data.slot
            .checked_add(preset::MIN_ATTESTATION_INCLUSION_DELAY)
            .is_some_and(|slot| slot <= state_slot),
        "process_head_vote: data.slot + MIN_ATTESTATION_INCLUSION_DELAY <= state.slot",
    )?;
    verify(
        data_epoch == get_previous_epoch(state) || data_epoch == get_current_epoch(state),
        "process_head_vote: compute_epoch_at_slot(data.slot) in (get_previous_epoch(state), get_current_epoch(state))",
    )?;
    verify(
        matches!(
            data.payload_status,
            constants::PAYLOAD_STATUS_EMPTY
                | constants::PAYLOAD_STATUS_FULL
                | constants::PAYLOAD_STATUS_PENDING
        ),
        "process_head_vote: data.payload_status in (PAYLOAD_STATUS_EMPTY, PAYLOAD_STATUS_FULL, PAYLOAD_STATUS_PENDING)",
    )?;
    let same_slot = is_head_vote_same_slot(state, &data)?;
    if same_slot {
        verify(
            data.payload_status == constants::PAYLOAD_STATUS_PENDING,
            "process_head_vote: data.payload_status == PAYLOAD_STATUS_PENDING",
        )?;
    }

    let committee = get_head_vote_committee(state, data.slot, config)?;
    let voter_indices: &[ValidatorIndex] = &vote.voter_indices;
    verify(
        !voter_indices.is_empty(),
        "process_head_vote: len(vote.voter_indices) > 0",
    )?;
    verify(
        crate::beacon::helpers::predicates::are_indices_sorted_and_unique(voter_indices),
        "process_head_vote: list(vote.voter_indices) == sorted(set(vote.voter_indices))",
    )?;
    for index in voter_indices {
        verify(
            committee.contains(index),
            "process_head_vote: index in committee",
        )?;
    }

    verify(
        support_bits.len() == voter_indices.len(),
        "process_head_vote: len(support_bits) == len(vote.voter_indices)",
    )?;
    if (0..support_bits.len()).any(|bit| support_bits.get(bit) == Some(true)) {
        // `state_slot >= 1` here, by the inclusion delay check above.
        verify(
            data.slot == state_slot - 1,
            "process_head_vote: data.slot == state.slot - 1",
        )?;
    }

    // Verify signature
    let mut pubkeys = Vec::with_capacity(voter_indices.len());
    for index in voter_indices {
        pubkeys.push(state.validator(*index)?.pubkey);
    }
    let domain = get_domain(state, constants::DOMAIN_HEAD_VOTE, Some(data_epoch));
    let signing_root = compute_signing_root(data.hash_tree_root(), domain);
    verify(
        bls::fast_aggregate_verify(&pubkeys, signing_root, &vote.signature),
        "process_head_vote: bls.FastAggregateVerify(pubkeys, signing_root, vote.signature)",
    )?;

    // Record the seats that voted for the block of their slot
    if same_slot {
        let slot_in_epoch = (data.slot % preset::SLOTS_PER_EPOCH) as usize;
        let participation_index = if data_epoch == get_current_epoch(state) {
            preset::SLOTS_PER_EPOCH as usize + slot_in_epoch
        } else {
            slot_in_epoch
        };
        let inner = eip8453_state_mut(state, "process_head_vote")?;
        let seats = &mut inner.head_vote_participation[participation_index];
        for (position, index) in committee.iter().enumerate() {
            // `voter_indices` is sorted, as checked above.
            if voter_indices.binary_search(index).is_ok() {
                seats
                    .set(position, true)
                    .expect("a committee position is below HEAD_VOTE_COMMITTEE_SIZE");
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Height events
// ---------------------------------------------------------------------------

/// `process_height_events`: finalizes the highest pending justification whose
/// finality pairs reach a quorum and drops every pending one at or below it,
/// then moves to the next height, justifying the target when its target
/// votes reach a quorum, or, `TIMEOUT_DELAY_SLOTS` after the target, when
/// target votes and timeouts together do.
pub fn process_height_events(state: &mut BeaconState) -> Result<()> {
    // Finalize the highest pending justification with a quorum.
    let pending = eip8453_state(state, "process_height_events")?
        .pending_finality
        .to_vec();
    let mut finalized = None;
    for entry in &pending {
        if has_quorum(state, &entry.participation)? {
            finalized = Some((entry.checkpoint, entry.slot));
        }
    }
    let inner = eip8453_state_mut(state, "process_height_events")?;
    if let Some((checkpoint, slot)) = finalized {
        inner.finalized_checkpoint = checkpoint;
        inner.finalized_slot = slot;
    }
    let finalized_height = inner.finalized_checkpoint.height;
    let kept: Vec<eip8453::PendingFinality> = pending
        .into_iter()
        .filter(|entry| entry.checkpoint.height > finalized_height)
        .collect();
    inner.pending_finality = kept.try_into()?;

    let target_participation = inner.target_participation.clone();
    if has_quorum(state, &target_participation)? {
        let validator_count = state.validator_count();
        let inner = eip8453_state_mut(state, "process_height_events")?;
        inner.justified_checkpoint = inner.target_checkpoint;
        // Keep only the newest pending justifications.
        let mut pending: Vec<eip8453::PendingFinality> = inner.pending_finality.to_vec();
        if pending.len() == preset::PENDING_FINALITY_WINDOW {
            pending.remove(0);
        }
        pending.push(eip8453::PendingFinality {
            checkpoint: inner.target_checkpoint,
            slot: inner.target_slot,
            participation: vec![false; validator_count].into(),
        });
        inner.pending_finality = pending.try_into()?;
        advance_height(state)?;
    } else {
        let inner = eip8453_state(state, "process_height_events")?;
        let progress_participation = inner.progress_participation.clone();
        let target_slot = inner.target_slot;
        // The quorum first, then the delay, in the order the
        // specification's `and` evaluates them: only the sum can fail.
        if has_quorum(state, &progress_participation)? {
            // Timeouts count only after the delay.
            let timeout_slot = target_slot.checked_add(preset::TIMEOUT_DELAY_SLOTS).ok_or(
                Error::ArithmeticOverflow(
                    "process_height_events: target_slot + TIMEOUT_DELAY_SLOTS",
                ),
            )?;
            if state.slot() >= timeout_slot {
                advance_height(state)?;
            }
        }
    }
    Ok(())
}

/// `advance_height`: the next height's target is the latest block, whose root
/// the next `process_slot` fills in, with fresh height participation.
pub fn advance_height(state: &mut BeaconState) -> Result<()> {
    let validator_count = state.validator_count();
    let latest_block_slot = state.latest_block_header().slot;
    let inner = eip8453_state_mut(state, "advance_height")?;
    let height = inner
        .target_checkpoint
        .height
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow(
            "advance_height: target_checkpoint.height + 1",
        ))?;
    inner.target_checkpoint = eip8453::HeightCheckpoint {
        height,
        // Filled in by the next `process_slot`.
        root: Root::ZERO,
    };
    inner.target_slot = latest_block_slot;
    inner.target_participation = vec![false; validator_count].into();
    inner.progress_participation = vec![false; validator_count].into();
    Ok(())
}

