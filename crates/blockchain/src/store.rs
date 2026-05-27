use std::collections::HashSet;

use ethlambda_state_transition::{is_proposer, slot_is_justifiable_after};
use ethlambda_storage::{ForkCheckpoints, Store};
use ethlambda_types::{
    ShortRoot,
    attestation::{
        Attestation, AttestationData, HashedAttestationData, SignedAggregatedAttestation,
        SignedAttestation, validator_indices,
    },
    block::{Block, SignedBlock, TypeOneMultiSignature},
    checkpoint::Checkpoint,
    primitives::{H256, HashTreeRoot as _},
    signature::{ValidatorPublicKey, ValidatorSignature},
    state::State,
};
use tracing::{info, trace, warn};

use crate::{
    GOSSIP_DISPARITY_INTERVALS, INTERVALS_PER_SLOT, MAX_ATTESTATIONS_DATA,
    MILLISECONDS_PER_INTERVAL, MILLISECONDS_PER_SLOT,
    block_builder::{PostBlockCheckpoints, build_block},
    metrics,
};

const JUSTIFICATION_LOOKBACK_SLOTS: u64 = 3;

/// Accept new aggregated payloads, promoting them to known for fork choice.
fn accept_new_attestations(store: &mut Store, log_tree: bool) {
    store.promote_new_aggregated_payloads();
    metrics::update_latest_new_aggregated_payloads(store.new_aggregated_payloads_count());
    metrics::update_latest_known_aggregated_payloads(store.known_aggregated_payloads_count());
    update_head(store, log_tree);
}

/// Update the head based on the fork choice rule.
///
/// When `log_tree` is true, also computes block weights and logs an ASCII
/// fork choice tree to the terminal.
fn update_head(store: &mut Store, log_tree: bool) {
    let blocks = store.get_live_chain();
    let attestations = store.extract_latest_known_attestations();
    let old_head = store.head();
    let (new_head, weights) = ethlambda_fork_choice::compute_lmd_ghost_head(
        store.latest_justified().root,
        &blocks,
        &attestations,
        0,
    );
    if let Some(depth) = reorg_depth(old_head, new_head, store) {
        metrics::inc_fork_choice_reorgs();
        metrics::observe_fork_choice_reorg_depth(depth);
        info!(%old_head, %new_head, depth, "Fork choice reorg detected");
    }
    store.update_checkpoints(ForkCheckpoints::head_only(new_head));

    if old_head != new_head {
        let old_slot = store
            .get_block_header(&old_head)
            .map(|h| h.slot)
            .unwrap_or(0);
        let new_slot = store
            .get_block_header(&new_head)
            .map(|h| h.slot)
            .unwrap_or(0);
        let justified_slot = store.latest_justified().slot;
        let finalized_slot = store.latest_finalized().slot;
        info!(
            head_slot = new_slot,
            head_root = %ShortRoot(&new_head.0),
            previous_head_slot = old_slot,
            previous_head_root = %ShortRoot(&old_head.0),
            justified_slot,
            finalized_slot,
            "Fork choice head updated"
        );
    }

    if log_tree {
        let tree = crate::fork_choice_tree::format_fork_choice_tree(
            &blocks,
            &weights,
            new_head,
            store.latest_justified(),
            store.latest_finalized(),
        );
        info!("\n{tree}");
    }
}

/// Update the safe target for attestation.
///
/// Safe target is an *availability* signal, not a durable-knowledge signal:
/// only the "new" pool is considered. Migration from "new" to "known" runs at
/// interval 4, strictly after this computation at interval 3. 3sf-mini chose
/// that ordering deliberately so safe target sees only freshly received votes
/// from the current slot and ignores what was carried over from earlier slots
/// (block-included attestations, previously migrated gossip, self-attestations).
/// Counting "known" would let a node keep advancing its safe target on stale
/// evidence even when live participation has collapsed: exactly the failure
/// mode safe target is supposed to prevent. See leanSpec PR #680.
fn update_safe_target(store: &mut Store) {
    let head_state = store.get_state(&store.head()).expect("head state exists");
    let num_validators = head_state.validators.len() as u64;

    let min_target_score = (num_validators * 2).div_ceil(3);

    let blocks = store.get_live_chain();
    let attestations = store.extract_latest_new_attestations();
    let (safe_target, _weights) = ethlambda_fork_choice::compute_lmd_ghost_head(
        store.latest_justified().root,
        &blocks,
        &attestations,
        min_target_score,
    );
    store.set_safe_target(safe_target);
}

/// Validate incoming attestation before processing.
///
/// Ensures the vote respects the basic laws of time and topology:
///     1. The blocks voted for must exist in our store.
///     2. A vote cannot span backwards in time (source > target).
///     3. The head must be at least as recent as source and target.
///     4. Checkpoint slots must match the actual block slots.
///     5. The vote's slot must have started locally (a small disparity margin is allowed).
fn validate_attestation_data(store: &Store, data: &AttestationData) -> Result<(), StoreError> {
    let _timing = metrics::time_attestation_validation();

    // Availability Check - We cannot count a vote if we haven't seen the blocks involved.
    let source_header = store
        .get_block_header(&data.source.root)
        .ok_or(StoreError::UnknownSourceBlock(data.source.root))?;
    let target_header = store
        .get_block_header(&data.target.root)
        .ok_or(StoreError::UnknownTargetBlock(data.target.root))?;

    let head_header = store
        .get_block_header(&data.head.root)
        .ok_or(StoreError::UnknownHeadBlock(data.head.root))?;

    // Topology Check - Source must be older than Target, and Head must be at least as recent.
    if data.source.slot > data.target.slot {
        return Err(StoreError::SourceExceedsTarget);
    }
    if data.head.slot < data.target.slot {
        return Err(StoreError::HeadOlderThanTarget {
            head_slot: data.head.slot,
            target_slot: data.target.slot,
        });
    }

    // Consistency Check - Validate checkpoint slots match block slots.
    if source_header.slot != data.source.slot {
        return Err(StoreError::SourceSlotMismatch {
            checkpoint_slot: data.source.slot,
            block_slot: source_header.slot,
        });
    }
    if target_header.slot != data.target.slot {
        return Err(StoreError::TargetSlotMismatch {
            checkpoint_slot: data.target.slot,
            block_slot: target_header.slot,
        });
    }
    if head_header.slot != data.head.slot {
        return Err(StoreError::HeadSlotMismatch {
            checkpoint_slot: data.head.slot,
            block_slot: head_header.slot,
        });
    }

    // Time Check - Honest validators emit votes only after their slot has begun.
    // Allow a small disparity margin for clock skew between peers.
    //
    // The bound is in intervals, not slots: a whole-slot margin would let an
    // adversary pre-publish next-slot aggregates ahead of any honest validator.
    let attestation_start_interval = data.slot.saturating_mul(INTERVALS_PER_SLOT);
    if attestation_start_interval > store.time() + GOSSIP_DISPARITY_INTERVALS {
        return Err(StoreError::AttestationTooFarInFuture {
            attestation_slot: data.slot,
            store_time: store.time(),
        });
    }

    Ok(())
}

/// Process a tick event.
///
/// `store.time()` represents interval-count-since-genesis: each increment is one
/// 800ms interval. Slot and interval-within-slot are derived as:
///   slot     = store.time() / INTERVALS_PER_SLOT
///   interval = store.time() % INTERVALS_PER_SLOT
pub fn on_tick(store: &mut Store, timestamp_ms: u64, has_proposal: bool) {
    // Convert UNIX timestamp (ms) to interval count since genesis
    let genesis_time_ms = store.config().genesis_time * 1000;
    let time_delta_ms = timestamp_ms.saturating_sub(genesis_time_ms);
    let time = time_delta_ms / MILLISECONDS_PER_INTERVAL;

    // If we're more than a slot behind, fast-forward to a slot before.
    // Operations are idempotent, so this should be fine.
    if time.saturating_sub(store.time()) > INTERVALS_PER_SLOT {
        store.set_time(time - INTERVALS_PER_SLOT);
    }

    while store.time() < time {
        store.set_time(store.time() + 1);

        let slot = store.time() / INTERVALS_PER_SLOT;
        let interval = store.time() % INTERVALS_PER_SLOT;

        trace!(%slot, %interval, "processing tick");

        // has_proposal is only signaled for the final tick (matching Python spec behavior)
        let is_final_tick = store.time() == time;
        let should_signal_proposal = has_proposal && is_final_tick;

        // NOTE: here we assume on_tick never skips intervals.
        // Interval 2 (committee-signature aggregation) is no longer handled here:
        // the blockchain actor orchestrates the aggregation worker directly so
        // the actor's message loop stays unblocked during the expensive XMSS
        // proofs. See `BlockChainServer::start_aggregation_session` in `lib.rs`.
        match interval {
            0 => {
                // Start of slot - process attestations if proposal exists
                if should_signal_proposal {
                    accept_new_attestations(store, false);
                }
            }
            1 => {
                // Vote propagation — no action
            }
            2 => {
                // Aggregation is driven by the actor (off-thread); nothing to do here.
            }
            3 => {
                // Update safe target for validators
                update_safe_target(store);
            }
            4 => {
                // End of slot - accept accumulated attestations and log tree
                accept_new_attestations(store, true);
            }
            _ => unreachable!("slots only have 5 intervals"),
        }
    }
}

/// Process a gossiped attestation with signature verification.
///
/// Every subscriber validates the attestation data and verifies the XMSS
/// signature so invalid messages get caught at the edge. Only aggregators
/// store the signature for later aggregation at interval 2; non-aggregators
/// drop it after verification.
pub fn on_gossip_attestation(
    store: &mut Store,
    signed_attestation: &SignedAttestation,
    is_aggregator: bool,
) -> Result<(), StoreError> {
    let validator_id = signed_attestation.validator_id;
    let attestation = Attestation {
        validator_id,
        data: signed_attestation.data.clone(),
    };
    validate_attestation_data(store, &attestation.data)
        .inspect_err(|_| metrics::inc_attestations_invalid())?;

    let hashed = HashedAttestationData::new(attestation.data.clone());
    let data_root = hashed.root();

    let target = attestation.data.target;
    let target_state = store
        .get_state(&target.root)
        .ok_or(StoreError::MissingTargetState(target.root))?;
    if validator_id >= target_state.validators.len() as u64 {
        return Err(StoreError::InvalidValidatorIndex);
    }
    let validator_pubkey = target_state.validators[validator_id as usize]
        .get_attestation_pubkey()
        .map_err(|_| StoreError::PubkeyDecodingFailed(validator_id))?;

    // Verify the validator's XMSS signature
    let slot: u32 = attestation.data.slot.try_into().expect("slot exceeds u32");
    let signature = ValidatorSignature::from_bytes(&signed_attestation.signature)
        .map_err(|_| StoreError::SignatureDecodingFailed)?;
    let is_valid = {
        let _timing = metrics::time_pq_sig_attestation_verification();
        signature.is_valid(&validator_pubkey, slot, &data_root)
    };
    if !is_valid {
        metrics::inc_pq_sig_attestation_signatures_invalid();
        return Err(StoreError::SignatureVerificationFailed);
    }
    metrics::inc_pq_sig_attestation_signatures_valid();

    // Only aggregators persist the signature for later aggregation at
    // interval 2. Non-aggregators drop the validated attestation — they
    // still participate in the mesh so peers see the message propagate.
    if is_aggregator {
        store.insert_gossip_signature(hashed, validator_id, signature);
        metrics::update_gossip_signatures(store.gossip_signatures_count());
    }

    metrics::inc_attestations_valid(1);

    let slot = attestation.data.slot;
    let target_slot = attestation.data.target.slot;
    let source_slot = attestation.data.source.slot;
    info!(
        slot,
        validator = validator_id,
        target_slot,
        target_root = %ShortRoot(&attestation.data.target.root.0),
        source_slot,
        source_root = %ShortRoot(&attestation.data.source.root.0),
        "Attestation processed"
    );

    Ok(())
}

/// Process a gossiped aggregated attestation from the aggregation subnet.
///
/// Aggregated attestations arrive from committee aggregators and contain a proof
/// covering multiple validators. After signature verification, one entry is
/// stored per unique attestation data (not per participating validator) in the
/// pending pool; participant bits are carried in the proof itself.
pub fn on_gossip_aggregated_attestation(
    store: &mut Store,
    aggregated: SignedAggregatedAttestation,
) -> Result<(), StoreError> {
    validate_attestation_data(store, &aggregated.data)
        .inspect_err(|_| metrics::inc_attestations_invalid())?;

    let target_state = store
        .get_state(&aggregated.data.target.root)
        .ok_or(StoreError::MissingTargetState(aggregated.data.target.root))?;
    let validators = &target_state.validators;
    let num_validators = validators.len() as u64;

    let participant_indices: Vec<u64> = aggregated.proof.participant_indices().collect();
    if participant_indices.iter().any(|&vid| vid >= num_validators) {
        return Err(StoreError::InvalidValidatorIndex);
    }

    let pubkeys: Vec<_> = participant_indices
        .iter()
        .map(|&vid| {
            validators[vid as usize]
                .get_attestation_pubkey()
                .map_err(|_| StoreError::PubkeyDecodingFailed(vid))
        })
        .collect::<Result<_, _>>()?;

    let hashed = HashedAttestationData::new(aggregated.data.clone());
    let data_root = hashed.root();
    let slot: u32 = aggregated.data.slot.try_into().expect("slot exceeds u32");

    {
        let _timing = metrics::time_pq_sig_aggregated_signatures_verification();
        ethlambda_crypto::verify_aggregated_signature(
            &aggregated.proof.proof,
            pubkeys,
            &data_root,
            slot,
        )
    }
    .map_err(StoreError::AggregateVerificationFailed)?;

    // Read stats before moving the proof into the store.
    let num_participants = aggregated.proof.participants.count_ones();
    let target_slot = aggregated.data.target.slot;
    let target_root = aggregated.data.target.root;
    let source_slot = aggregated.data.source.slot;
    let slot = aggregated.data.slot;

    store.insert_new_aggregated_payload(hashed, aggregated.proof);
    metrics::update_latest_new_aggregated_payloads(store.new_aggregated_payloads_count());

    info!(
        slot,
        num_participants,
        target_slot,
        target_root = %ShortRoot(&target_root.0),
        source_slot,
        "Aggregated attestation processed"
    );

    metrics::inc_attestations_valid(1);

    Ok(())
}

/// Process a new block and update the forkchoice state (with signature verification).
///
/// This is the safe default: it always verifies cryptographic signatures
/// and stores them for future block building. Use this for all production paths.
pub fn on_block(store: &mut Store, signed_block: SignedBlock) -> Result<(), StoreError> {
    on_block_core(store, signed_block, true)
}

/// Process a new block without signature verification.
///
/// This skips all cryptographic checks and signature storage. Use only in tests
/// where signatures are absent or irrelevant (e.g., fork choice spec tests).
pub fn on_block_without_verification(
    store: &mut Store,
    signed_block: SignedBlock,
) -> Result<(), StoreError> {
    on_block_core(store, signed_block, false)
}

/// Core block processing logic.
///
/// When `verify` is true, cryptographic signatures are validated and stored
/// for future block building. When false, all signature checks are skipped.
fn on_block_core(
    store: &mut Store,
    signed_block: SignedBlock,
    verify: bool,
) -> Result<(), StoreError> {
    let _timing = metrics::time_fork_choice_block_processing();
    let block_start = std::time::Instant::now();

    let block = &signed_block.message;
    let block_root = block.hash_tree_root();
    let slot = block.slot;

    // Skip duplicate blocks (idempotent operation)
    if store.has_state(&block_root) {
        return Ok(());
    }

    // Verify parent state is available
    // Note: Parent block existence is checked by the caller before calling this function.
    // This check ensures the state has been computed for the parent block.
    let parent_state =
        store
            .get_state(&block.parent_root)
            .ok_or(StoreError::MissingParentState {
                parent_root: block.parent_root,
                slot,
            })?;

    // Each unique AttestationData must appear at most once per block.
    let attestations = &signed_block.message.body.attestations;
    let mut seen = HashSet::with_capacity(attestations.len());
    for att in attestations {
        if !seen.insert(&att.data) {
            return Err(StoreError::DuplicateAttestationData {
                count: attestations.len(),
                unique: seen.len(),
            });
        }
    }
    // Reject blocks exceeding the per-block distinct-attestation-data cap (leanSpec #536).
    if seen.len() > MAX_ATTESTATIONS_DATA {
        return Err(StoreError::TooManyAttestationData {
            count: seen.len(),
            max: MAX_ATTESTATIONS_DATA,
        });
    }

    let sig_verification_start = std::time::Instant::now();
    if verify {
        // Validate cryptographic signatures
        verify_block_signatures(&parent_state, &signed_block)?;
    }
    let sig_verification = sig_verification_start.elapsed();

    let block = signed_block.message.clone();

    // Execute state transition function to compute post-block state
    let state_transition_start = std::time::Instant::now();
    let mut post_state = parent_state;
    ethlambda_state_transition::state_transition(&mut post_state, &block)?;
    let state_transition = state_transition_start.elapsed();

    // Cache the state root in the latest block header
    let state_root = block.state_root;
    post_state.latest_block_header.state_root = state_root;

    // Update justified/finalized checkpoints if they have higher slots
    let justified = (post_state.latest_justified.slot > store.latest_justified().slot)
        .then_some(post_state.latest_justified);
    let finalized = (post_state.latest_finalized.slot > store.latest_finalized().slot)
        .then_some(post_state.latest_finalized);

    if justified.is_some() || finalized.is_some() {
        store.update_checkpoints(ForkCheckpoints::new(store.head(), justified, finalized));
    }

    // Store signed block and state
    store.insert_signed_block(block_root, signed_block.clone());
    store.insert_state(block_root, post_state);

    // Process block body attestations and feed them into the payload buffer
    // so fork choice's LMD GHOST overlay can see block-only votes.
    //
    // Per-attestation participant bitfields come straight from
    // `block.body.attestations[i].aggregation_bits`. Standalone Type-1
    // proof bytes are not recoverable from a block at import time;
    // downstream re-aggregation has to come from the gossip channel or be
    // recovered by SNARK-splitting `signed_block.proof` via
    // `split_type_2_by_message`. The entries inserted here are info-only,
    // used only for fork-choice vote bookkeeping.
    let aggregated_attestations = &block.body.attestations;

    let mut known_entries: Vec<(HashedAttestationData, TypeOneMultiSignature)> =
        Vec::with_capacity(aggregated_attestations.len());
    for att in aggregated_attestations.iter() {
        let hashed = HashedAttestationData::new(att.data.clone());
        let type_one = TypeOneMultiSignature::empty(att.aggregation_bits.clone());
        known_entries.push((hashed, type_one));
        // Count each participating validator as a valid attestation.
        let count = validator_indices(&att.aggregation_bits).count() as u64;
        metrics::inc_attestations_valid(count);
    }

    store.insert_known_aggregated_payloads_batch(known_entries);

    // Update forkchoice head based on new block and attestations
    update_head(store, false);

    let block_total = block_start.elapsed();
    info!(
        %slot,
        %block_root,
        %state_root,
        ?sig_verification,
        ?state_transition,
        ?block_total,
        "Processed new block"
    );
    Ok(())
}

/// Calculate target checkpoint for validator attestations.
///
/// NOTE: this assumes that we have all the blocks from the head back to the latest finalized.
pub fn get_attestation_target(store: &Store) -> Checkpoint {
    get_attestation_target_with_checkpoints(
        store,
        store.latest_justified(),
        store.latest_finalized(),
    )
}

/// Calculate target checkpoint using the provided justified and finalized checkpoints
/// instead of reading them from the store.
///
/// This is needed by the proposer, whose block hasn't been imported yet but whose
/// state transition may have advanced justification/finalization.
///
/// Note: the walk-back still starts from `store.head()` (the pre-import head), not
/// the new block. This is correct because the new block is only 1 slot ahead with less than 2/3 of votes — the
/// walk-back immediately reaches the same chain. The important fix is using the
/// post-state justified/finalized for the justifiability check and clamping guard.
pub fn get_attestation_target_with_checkpoints(
    store: &Store,
    justified: Checkpoint,
    finalized: Checkpoint,
) -> Checkpoint {
    // Start from current head
    let mut target_block_root = store.head();
    let mut target_header = store
        .get_block_header(&target_block_root)
        .expect("head block exists");

    let safe_target_block_slot = store
        .get_block_header(&store.safe_target())
        .expect("safe target exists")
        .slot;

    // Walk back toward safe target (up to `JUSTIFICATION_LOOKBACK_SLOTS` steps)
    //
    // This ensures the target doesn't advance too far ahead of safe target,
    // providing a balance between liveness and safety.
    for _ in 0..JUSTIFICATION_LOOKBACK_SLOTS {
        if target_header.slot > safe_target_block_slot {
            target_block_root = target_header.parent_root;
            target_header = store
                .get_block_header(&target_block_root)
                .expect("parent block exists");
        } else {
            break;
        }
    }

    let finalized_slot = finalized.slot;

    // Ensure target is in justifiable slot range
    //
    // Walk back until we find a slot that satisfies justifiability rules
    // relative to the latest finalized checkpoint.
    while target_header.slot > finalized_slot
        && !slot_is_justifiable_after(target_header.slot, finalized_slot)
    {
        target_block_root = target_header.parent_root;
        target_header = store
            .get_block_header(&target_block_root)
            .expect("parent block exists");
    }
    // Guard: clamp target to justified (not in the spec).
    //
    // The spec's walk-back has no lower bound, so it can produce attestations
    // where target.slot < source.slot (source = latest_justified). These would
    // fail is_valid_vote Rule 5 (target.slot > source.slot) and be discarded,
    // but producing them wastes work and pollutes the network.
    //
    // This happens when a block advances latest_justified between safe_target
    // updates (interval 2), causing the walk-back to land behind the new
    // justified checkpoint.
    //
    // See https://github.com/blockblaz/zeam/blob/697c293879e922942965cdb1da3c6044187ae00e/pkgs/node/src/forkchoice.zig#L654-L659
    if target_header.slot < justified.slot {
        warn!(
            target_slot = target_header.slot,
            justified_slot = justified.slot,
            "Attestation target walked behind justified source, clamping to justified"
        );
        return justified;
    }

    Checkpoint {
        root: target_block_root,
        slot: target_header.slot,
    }
}

/// Produce attestation data for the given slot.
///
/// The source comes from the store's global `latest_justified` checkpoint.
/// When the store's justified has advanced past the head state (a minority
/// fork justified a slot the head chain hasn't seen yet), the next block
/// produced on the head chain is expected to close the gap via the
/// fixed-point attestation loop in `build_block`.
///
/// See: <https://github.com/leanEthereum/leanSpec/pull/595>
pub fn produce_attestation_data(store: &Store, slot: u64) -> AttestationData {
    let head_root = store.head();

    let head_checkpoint = Checkpoint {
        root: head_root,
        slot: store
            .get_block_header(&head_root)
            .expect("head block exists")
            .slot,
    };

    let target_checkpoint = get_attestation_target(store);

    AttestationData {
        slot,
        head: head_checkpoint,
        target: target_checkpoint,
        source: store.latest_justified(),
    }
}

/// Get the head for block proposal at the given slot.
///
/// Ensures store is up-to-date and processes any pending attestations
/// before returning the canonical head.
fn get_proposal_head(store: &mut Store, slot: u64) -> H256 {
    // Calculate time corresponding to this slot
    let slot_time_ms = store.config().genesis_time * 1000 + slot * MILLISECONDS_PER_SLOT;

    // Advance time to current slot (ticking intervals)
    on_tick(store, slot_time_ms, true);

    // Process any pending attestations before proposal
    accept_new_attestations(store, false);

    store.head()
}

/// Produce a block and per-aggregated-attestation signature payloads for the target slot.
///
/// Returns the finalized block and attestation signature payloads aligned
/// with `block.body.attestations`.
pub fn produce_block_with_signatures(
    store: &mut Store,
    slot: u64,
    validator_index: u64,
) -> Result<(Block, Vec<TypeOneMultiSignature>, PostBlockCheckpoints), StoreError> {
    // Get parent block and state to build upon
    let head_root = get_proposal_head(store, slot);
    let head_state = store
        .get_state(&head_root)
        .ok_or(StoreError::MissingParentState {
            parent_root: head_root,
            slot,
        })?
        .clone();

    // Validate proposer authorization for this slot
    let num_validators = head_state.validators.len() as u64;
    if !is_proposer(validator_index, slot, num_validators) {
        return Err(StoreError::NotProposer {
            validator_index,
            slot,
        });
    }

    // Get known aggregated payloads: data_root -> (AttestationData, Vec<proof>)
    let aggregated_payloads = store.known_aggregated_payloads();

    let known_block_roots = store.get_block_roots();

    let (block, signatures, post_checkpoints) = {
        let _timing = metrics::time_block_building_payload_aggregation();
        build_block(
            &head_state,
            slot,
            validator_index,
            head_root,
            &known_block_roots,
            &aggregated_payloads,
        )?
    };

    // Invariant (leanSpec #595): the produced block must not lag the store's
    // justified checkpoint. Otherwise peers processing this block would never
    // see justification advance, degrading liveness: the fixed-point loop in
    // `build_block` is expected to incorporate pool attestations that close
    // any divergence inherited from a minority fork.
    let store_justified_slot = store.latest_justified().slot;
    if post_checkpoints.justified.slot < store_justified_slot {
        return Err(StoreError::JustifiedDivergenceNotClosed {
            block_justified_slot: post_checkpoints.justified.slot,
            store_justified_slot,
        });
    }

    metrics::observe_block_aggregated_payloads(signatures.len());

    Ok((block, signatures, post_checkpoints))
}

/// Errors that can occur during Store operations.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("Parent state not found for slot {slot}. Missing block: {parent_root}")]
    MissingParentState { parent_root: H256, slot: u64 },

    #[error("Validator index out of range")]
    InvalidValidatorIndex,

    #[error("Failed to decode validator {0}'s public key")]
    PubkeyDecodingFailed(u64),

    #[error("Validator signature could not be decoded")]
    SignatureDecodingFailed,

    #[error("Validator signature verification failed")]
    SignatureVerificationFailed,

    #[error("Block slot {0} exceeds u32 range")]
    SlotOutOfRange(u64),

    #[error("State transition failed: {0}")]
    StateTransitionFailed(#[from] ethlambda_state_transition::Error),

    #[error("Unknown source block: {0}")]
    UnknownSourceBlock(H256),

    #[error("Unknown target block: {0}")]
    UnknownTargetBlock(H256),

    #[error("Unknown head block: {0}")]
    UnknownHeadBlock(H256),

    #[error("Source checkpoint slot exceeds target")]
    SourceExceedsTarget,

    #[error("Head checkpoint slot {head_slot} is older than target slot {target_slot}")]
    HeadOlderThanTarget { head_slot: u64, target_slot: u64 },

    #[error("Source checkpoint slot {checkpoint_slot} does not match block slot {block_slot}")]
    SourceSlotMismatch {
        checkpoint_slot: u64,
        block_slot: u64,
    },

    #[error("Target checkpoint slot {checkpoint_slot} does not match block slot {block_slot}")]
    TargetSlotMismatch {
        checkpoint_slot: u64,
        block_slot: u64,
    },

    #[error("Head checkpoint slot {checkpoint_slot} does not match block slot {block_slot}")]
    HeadSlotMismatch {
        checkpoint_slot: u64,
        block_slot: u64,
    },

    #[error(
        "Attestation slot {attestation_slot} is too far in future (store time: {store_time} intervals)"
    )]
    AttestationTooFarInFuture {
        attestation_slot: u64,
        store_time: u64,
    },

    #[error("Aggregated signature verification failed: {0}")]
    AggregateVerificationFailed(ethlambda_crypto::VerificationError),

    #[error("Signature aggregation failed: {0}")]
    SignatureAggregationFailed(ethlambda_crypto::AggregationError),

    #[error("Missing target state for block: {0}")]
    MissingTargetState(H256),

    #[error("Validator {validator_index} is not the proposer for slot {slot}")]
    NotProposer { validator_index: u64, slot: u64 },

    #[error(
        "Block contains duplicate AttestationData entries: {count} entries but only {unique} unique"
    )]
    DuplicateAttestationData { count: usize, unique: usize },

    #[error("Block contains {count} distinct AttestationData entries; maximum is {max}")]
    TooManyAttestationData { count: usize, max: usize },

    #[error(
        "Produced block justified slot {block_justified_slot} \
         is behind store justified slot {store_justified_slot}; \
         fixed-point attestation loop did not converge"
    )]
    JustifiedDivergenceNotClosed {
        block_justified_slot: u64,
        store_justified_slot: u64,
    },
}

/// Full verification of a signed block's merged Type-2 proof.
///
/// Structural pre-checks (fast fail) ensure the merged proof's `info` list lines
/// up with the block body (one entry per attestation plus a trailing proposer
/// entry; messages, slots, and participants match what the body declares).
/// On success, the lean-multisig devnet5 `verify_type_2` primitive runs the
/// SNARK verifier over the merged proof bytes against the resolved pubkey set.
///
/// Exposed publicly so RPC handlers (notably the Hive test-driver
/// `verify_signatures/run` endpoint) can run the exact same verification path
/// the import pipeline uses; the production import path also calls this from
/// [`on_block_core`].
pub fn verify_block_signatures(
    state: &State,
    signed_block: &SignedBlock,
) -> Result<(), StoreError> {
    let total_start = std::time::Instant::now();

    let block = &signed_block.message;
    let attestations = &block.body.attestations;

    let validators = &state.validators;
    let num_validators = validators.len() as u64;

    // Bounds-check participants before paying for the SNARK verifier.
    // Per-component pubkeys are resolved from the block body itself; the
    // wire proof carries no separate participant declaration to cross-check
    // against (leanSpec PR #717).
    for attestation in attestations.iter() {
        for vid in validator_indices(&attestation.aggregation_bits) {
            if vid >= num_validators {
                return Err(StoreError::InvalidValidatorIndex);
            }
        }
    }
    if block.proposer_index >= num_validators {
        return Err(StoreError::InvalidValidatorIndex);
    }

    let block_root = block.hash_tree_root();
    let structural_elapsed = total_start.elapsed();

    // Resolve pubkeys per Type-2 component for verify_type_2 and rederive the
    // expected (message, slot) bindings from the block body. Attestation
    // components use each participant's attestation_pubkey; the trailing
    // proposer component uses the proposal_pubkey of `block.proposer_index`.
    let expected_components = attestations.len() + 1;
    let mut pubkeys_per_component: Vec<Vec<ValidatorPublicKey>> =
        Vec::with_capacity(expected_components);
    let mut expected_bindings: Vec<(H256, u32)> = Vec::with_capacity(expected_components);

    for attestation in attestations.iter() {
        let mut pubkeys = Vec::new();
        for vid in validator_indices(&attestation.aggregation_bits) {
            let validator = validators
                .get(vid as usize)
                .ok_or(StoreError::InvalidValidatorIndex)?;
            let pk = validator
                .get_attestation_pubkey()
                .map_err(|_| StoreError::PubkeyDecodingFailed(vid))?;
            pubkeys.push(pk);
        }
        pubkeys_per_component.push(pubkeys);
        let slot_u32 = u32::try_from(attestation.data.slot)
            .map_err(|_| StoreError::SlotOutOfRange(attestation.data.slot))?;
        expected_bindings.push((attestation.data.hash_tree_root(), slot_u32));
    }

    let proposer_validator = validators
        .get(block.proposer_index as usize)
        .ok_or(StoreError::InvalidValidatorIndex)?;
    let proposer_pubkey = proposer_validator
        .get_proposal_pubkey()
        .map_err(|_| StoreError::PubkeyDecodingFailed(block.proposer_index))?;
    pubkeys_per_component.push(vec![proposer_pubkey]);
    let block_slot_u32 =
        u32::try_from(block.slot).map_err(|_| StoreError::SlotOutOfRange(block.slot))?;
    expected_bindings.push((block_root, block_slot_u32));

    // Strip the thin SSZ container wrapper to recover the raw lean-multisig
    // Type-2 bytes the verifier consumes. The spec carries
    // `signed_block.proof = [4-byte offset = 4][type2_wire]` so other clients
    // can decode through the spec's `TypeTwoMultiSignature` SSZ container
    // (leanSpec PR #717).
    let merged_bytes = signed_block.merged_proof_bytes().map_err(|_| {
        StoreError::AggregateVerificationFailed(
            ethlambda_crypto::VerificationError::DeserializationFailed,
        )
    })?;

    let crypto_start = std::time::Instant::now();
    ethlambda_crypto::verify_type_2_signature(
        merged_bytes,
        pubkeys_per_component,
        &expected_bindings,
    )
    .map_err(StoreError::AggregateVerificationFailed)?;
    let crypto_elapsed = crypto_start.elapsed();

    let total_elapsed = total_start.elapsed();
    info!(
        slot = block.slot,
        attestation_count = attestations.len(),
        ?structural_elapsed,
        ?crypto_elapsed,
        ?total_elapsed,
        "Block Type-2 proof verified"
    );

    Ok(())
}

/// Check if a head change represents a reorg, returning the depth if so.
///
/// A reorg occurs when the chains diverge - i.e., when walking back from the higher
/// slot head to the lower slot head's slot, we don't arrive at the lower slot head.
/// Returns `Some(depth)` where depth is the number of blocks walked back, or `None`
/// if no reorg occurred.
fn reorg_depth(old_head: H256, new_head: H256, store: &Store) -> Option<u64> {
    if new_head == old_head {
        return None;
    }

    let old_head_header = store.get_block_header(&old_head)?;
    let new_head_header = store.get_block_header(&new_head)?;

    let old_slot = old_head_header.slot;
    let new_slot = new_head_header.slot;

    // Determine which head has the higher slot and walk back from it
    let (mut current_root, target_slot, target_root) = if new_slot >= old_slot {
        (new_head, old_slot, old_head)
    } else {
        (old_head, new_slot, new_head)
    };

    // Walk back through the chain until we reach the target slot, counting steps.
    // Bounded to avoid unbounded walks in pathological cases.
    const MAX_REORG_DEPTH: u64 = 128;
    let mut depth: u64 = 0;
    while let Some(current_header) = store.get_block_header(&current_root) {
        if current_header.slot <= target_slot {
            // We've reached the target slot - check if we're at the target block
            return (current_root != target_root).then_some(depth);
        }
        current_root = current_header.parent_root;
        depth += 1;
        if depth >= MAX_REORG_DEPTH {
            warn!(depth, "Reorg depth exceeded maximum, stopping walk");
            return Some(depth);
        }
    }

    // Couldn't walk back far enough (missing blocks in chain)
    // Assume the ancestor is behind the latest finalized block
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_types::{
        attestation::{AggregatedAttestation, AggregationBits, AttestationData},
        block::{
            AggregatedAttestations, BlockBody, ByteList512KiB, SignedBlock, TypeOneMultiSignature,
        },
        checkpoint::Checkpoint,
        state::State,
    };

    /// Test helper: placeholder block proof bytes.
    ///
    /// In production the merged proof is the raw `compress_without_pubkeys()`
    /// output of `merge_many_type_1`, which can only be built by the
    /// lean-multisig prover. Tests that don't go through
    /// `verify_block_signatures` use an empty blob.
    fn make_signed_block_proof(
        _proposer_index: u64,
        _attestation_proofs: Vec<TypeOneMultiSignature>,
    ) -> ByteList512KiB {
        ByteList512KiB::default()
    }

    fn make_bits(indices: &[usize]) -> AggregationBits {
        let max = indices.iter().copied().max().unwrap_or(0);
        let mut bits = AggregationBits::with_length(max + 1).unwrap();
        for &i in indices {
            bits.set(i, true).unwrap();
        }
        bits
    }

    #[test]
    fn on_block_rejects_duplicate_attestation_data() {
        use ethlambda_storage::backend::InMemoryBackend;
        use std::sync::Arc;

        let genesis_state = State::from_genesis(1000, vec![]);
        let backend = Arc::new(InMemoryBackend::new());
        // Use `from_anchor_state` here rather than `get_forkchoice_store`:
        // the latter now enforces `block.state_root == hash_tree_root(state)`,
        // which a synthetic genesis block with zero state_root cannot satisfy.
        let mut store = Store::from_anchor_state(backend, genesis_state);

        let head_root = store.head();
        let att_data = AttestationData {
            slot: 0,
            head: Checkpoint {
                root: head_root,
                slot: 0,
            },
            target: Checkpoint {
                root: head_root,
                slot: 0,
            },
            source: Checkpoint {
                root: head_root,
                slot: 0,
            },
        };

        let bits_a = make_bits(&[0]);
        let bits_b = make_bits(&[1]);

        // Two attestations with the SAME data - should be rejected
        let attestations = AggregatedAttestations::try_from(vec![
            AggregatedAttestation {
                aggregation_bits: bits_a.clone(),
                data: att_data.clone(),
            },
            AggregatedAttestation {
                aggregation_bits: bits_b.clone(),
                data: att_data.clone(),
            },
        ])
        .unwrap();

        let block = Block {
            slot: 1,
            proposer_index: 0,
            parent_root: head_root,
            state_root: H256::ZERO,
            body: BlockBody { attestations },
        };
        let block_root = block.hash_tree_root();
        let att_root = att_data.hash_tree_root();
        let _ = (block_root, att_root); // unused under the slim wire format
        let proof = make_signed_block_proof(
            0,
            vec![
                TypeOneMultiSignature::empty(bits_a),
                TypeOneMultiSignature::empty(bits_b),
            ],
        );
        let signed_block = SignedBlock {
            message: block,
            proof,
        };

        let result = on_block_without_verification(&mut store, signed_block);
        assert!(
            matches!(
                result,
                Err(StoreError::DuplicateAttestationData {
                    count: 2,
                    unique: 1,
                })
            ),
            "Expected DuplicateAttestationData, got: {result:?}"
        );
    }
}
