use std::collections::{HashMap, HashSet};

use ethlambda_crypto::aggregate_proofs;
use ethlambda_state_transition::{
    attestation_data_matches_chain, is_proposer, justified_slots_ops, process_block, process_slots,
    slot_is_justifiable_after,
};
use ethlambda_storage::{ForkCheckpoints, Store};
use ethlambda_types::{
    ShortRoot,
    attestation::{
        AggregatedAttestation, AggregationBits, Attestation, AttestationData,
        HashedAttestationData, SignedAggregatedAttestation, SignedAttestation, validator_indices,
    },
    block::{AggregatedAttestations, Block, BlockBody, SignedBlock, TypeOneMultiSignature},
    checkpoint::Checkpoint,
    primitives::{H256, HashTreeRoot as _},
    signature::{ValidatorPublicKey, ValidatorSignature},
    state::{JustifiedSlots, State},
};
use tracing::{info, trace, warn};

use crate::{
    GOSSIP_DISPARITY_INTERVALS, INTERVALS_PER_SLOT, MAX_ATTESTATIONS_DATA,
    MILLISECONDS_PER_INTERVAL, MILLISECONDS_PER_SLOT, metrics,
};

const JUSTIFICATION_LOOKBACK_SLOTS: u64 = 3;

/// Post-block checkpoints extracted from the state transition in `build_block`.
///
/// When building a block, the state transition processes attestations that may
/// advance justification/finalization. These checkpoints reflect the post-state
/// values, which the proposer needs for its attestation (since the block hasn't
/// been imported into the store yet).
pub struct PostBlockCheckpoints {
    pub justified: Checkpoint,
    pub finalized: Checkpoint,
}

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

/// Compute the bitwise union (OR) of two AggregationBits bitfields.
fn union_aggregation_bits(a: &AggregationBits, b: &AggregationBits) -> AggregationBits {
    let max_len = a.len().max(b.len());
    if max_len == 0 {
        return AggregationBits::with_length(0).expect("zero-length bitlist");
    }
    let mut result = AggregationBits::with_length(max_len).expect("union exceeds bitlist capacity");
    for i in 0..max_len {
        if a.get(i).unwrap_or(false) || b.get(i).unwrap_or(false) {
            result.set(i, true).expect("index within capacity");
        }
    }
    result
}

/// Compact attestations so each AttestationData appears at most once.
///
/// For each group of entries sharing the same AttestationData:
/// - Single entry: kept as-is.
/// - Multiple entries: merged into one using recursive proof aggregation
///   (leanSpec PR #510).
fn compact_attestations(
    entries: Vec<(AggregatedAttestation, TypeOneMultiSignature)>,
    head_state: &State,
) -> Result<Vec<(AggregatedAttestation, TypeOneMultiSignature)>, StoreError> {
    if entries.len() <= 1 {
        return Ok(entries);
    }

    // Group indices by AttestationData, preserving first-occurrence order
    let mut order: Vec<AttestationData> = Vec::new();
    let mut groups: HashMap<AttestationData, Vec<usize>> = HashMap::new();
    for (i, (att, _)) in entries.iter().enumerate() {
        match groups.entry(att.data.clone()) {
            std::collections::hash_map::Entry::Vacant(e) => {
                order.push(e.key().clone());
                e.insert(vec![i]);
            }
            std::collections::hash_map::Entry::Occupied(mut e) => {
                e.get_mut().push(i);
            }
        }
    }

    // Fast path: no duplicates
    if order.len() == entries.len() {
        return Ok(entries);
    }

    // Wrap in Option so we can .take() items by index without cloning
    let mut items: Vec<Option<(AggregatedAttestation, TypeOneMultiSignature)>> =
        entries.into_iter().map(Some).collect();

    let mut compacted = Vec::with_capacity(order.len());

    for data in order {
        let indices = &groups[&data];
        if indices.len() == 1 {
            let item = items[indices[0]].take().expect("index used once");
            compacted.push(item);
            continue;
        }

        // Collect all entries for this AttestationData
        let group_items: Vec<(AggregatedAttestation, TypeOneMultiSignature)> = indices
            .iter()
            .map(|&idx| items[idx].take().expect("index used once"))
            .collect();

        // Union participant bitfields
        let merged_bits = group_items.iter().skip(1).fold(
            group_items[0].0.aggregation_bits.clone(),
            |acc, (att, _)| union_aggregation_bits(&acc, &att.aggregation_bits),
        );

        // Recursively aggregate child proofs into one (leanSpec #510).
        let data_root = data.hash_tree_root();
        let children: Vec<(Vec<_>, _)> = group_items
            .iter()
            .map(|(_, proof)| {
                let pubkeys = proof
                    .participant_indices()
                    .map(|vid| {
                        head_state
                            .validators
                            .get(vid as usize)
                            .ok_or(StoreError::InvalidValidatorIndex)?
                            .get_attestation_pubkey()
                            .map_err(|_| StoreError::PubkeyDecodingFailed(vid))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok((pubkeys, proof.proof.clone()))
            })
            .collect::<Result<Vec<_>, StoreError>>()?;

        let slot: u32 = data.slot.try_into().expect("slot exceeds u32");
        let merged_proof_data = aggregate_proofs(children, &data_root, slot)
            .map_err(StoreError::SignatureAggregationFailed)?;

        let merged_proof = TypeOneMultiSignature::new(merged_bits.clone(), merged_proof_data);
        let merged_att = AggregatedAttestation {
            aggregation_bits: merged_bits,
            data,
        };
        compacted.push((merged_att, merged_proof));
    }

    Ok(compacted)
}

/// Greedily select proofs maximizing new validator coverage.
///
/// For a single attestation data entry, picks proofs that cover the most
/// uncovered validators. A proof is selected as long as it adds at least
/// one previously-uncovered validator; partially-overlapping participants
/// between selected proofs are allowed. `compact_attestations` later feeds
/// these proofs as children to `aggregate_proofs`, which delegates to
/// lean-multisig devnet5 `aggregate_type_1` — that function tracks duplicate
/// pubkeys across children via its `dup_pub_keys` machinery, so overlap is
/// supported by the underlying aggregation scheme.
///
/// Each selected proof is appended to `selected` paired with its
/// corresponding AggregatedAttestation.
fn extend_proofs_greedily(
    proofs: &[TypeOneMultiSignature],
    selected: &mut Vec<(AggregatedAttestation, TypeOneMultiSignature)>,
    att_data: &AttestationData,
) {
    if proofs.is_empty() {
        return;
    }

    let mut covered: HashSet<u64> = HashSet::new();
    let mut remaining_indices: HashSet<usize> = (0..proofs.len()).collect();

    while !remaining_indices.is_empty() {
        // Pick proof covering the most uncovered validators (count only, no allocation)
        let best = remaining_indices
            .iter()
            .map(|&idx| {
                let count = proofs[idx]
                    .participant_indices()
                    .filter(|vid| !covered.contains(vid))
                    .count();
                (idx, count)
            })
            .max_by_key(|&(_, count)| count);

        let Some((best_idx, best_count)) = best else {
            break;
        };
        if best_count == 0 {
            break;
        }

        let proof = &proofs[best_idx];

        // Collect coverage only for the winning proof
        let new_covered: Vec<u64> = proof
            .participant_indices()
            .filter(|vid| !covered.contains(vid))
            .collect();

        let att = AggregatedAttestation {
            aggregation_bits: proof.participants.clone(),
            data: att_data.clone(),
        };

        metrics::inc_pq_sig_aggregated_signatures();
        metrics::inc_pq_sig_attestations_in_aggregated_signatures(new_covered.len() as u64);

        covered.extend(new_covered);
        selected.push((att, proof.clone()));
        remaining_indices.remove(&best_idx);
    }
}

fn trace_skipped_attestation(reason: &'static str, att: &AttestationData, data_root: &H256) {
    trace!(
        reason,
        attestation_slot = att.slot,
        source_slot = att.source.slot,
        source_root = %ShortRoot(&att.source.root.0),
        target_slot = att.target.slot,
        target_root = %ShortRoot(&att.target.root.0),
        head_slot = att.head.slot,
        head_root = %ShortRoot(&att.head.root.0),
        data_root = %ShortRoot(&data_root.0),
        "skipped"
    );
}

/// Tiered score for a candidate `AttestationData` entry during block building.
///
/// Lower `tier` wins. Tier 1 = finalizes the attestation's source; tier 2 =
/// justifies the target (crosses 2/3); tier 3 = adds marginal voters toward
/// the target's 2/3 supermajority. Entries with zero new voters relative to
/// the running per-target-root voter set are dropped (returned as `None`).
///
/// Within a tier, ordering prefers more `new_voters` (descending), then
/// smaller `target_slot` (older chain progress first), then smaller
/// `att_slot`, then the entry's `data_root` for determinism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EntryScore {
    tier: u8,
    new_voters: usize,
    target_slot: u64,
    att_slot: u64,
}

impl EntryScore {
    fn ordering_key(&self, data_root: H256) -> (u8, std::cmp::Reverse<usize>, u64, u64, H256) {
        (
            self.tier,
            std::cmp::Reverse(self.new_voters),
            self.target_slot,
            self.att_slot,
            data_root,
        )
    }
}

/// Deserialize `state.justifications_validators` into a per-target-root voter
/// map for fast lookup and incremental update during proposer scoring.
///
/// The state's flattened layout is `bit[i * N + j] = validator j voted for
/// justifications_roots[i]` (see `serialize_justifications`).
fn build_running_votes(state: &State) -> HashMap<H256, HashSet<u64>> {
    let validator_count = state.validators.len();
    let mut votes: HashMap<H256, HashSet<u64>> = HashMap::new();
    for (i, root) in state.justifications_roots.iter().enumerate() {
        let mut voters = HashSet::new();
        for j in 0..validator_count {
            if state.justifications_validators.get(i * validator_count + j) == Some(true) {
                voters.insert(j as u64);
            }
        }
        votes.insert(*root, voters);
    }
    votes
}

/// Validate a candidate entry against the projected chain view.
///
/// Returns `Err(reason)` matching a `trace_skipped_attestation` label if any
/// check fails: the entry's head must be known, its source must be justified,
/// its (source, target) must match the candidate-block chain view, and (unless
/// it is the genesis self-vote, allowed for fork-choice bootstrapping) its
/// target must not already be justified.
fn entry_passes_filters(
    att_data: &AttestationData,
    known_block_roots: &HashSet<H256>,
    extended_historical_block_hashes: &[H256],
    projected_justified_slots: &JustifiedSlots,
    projected_finalized_slot: u64,
) -> Result<(), &'static str> {
    if !known_block_roots.contains(&att_data.head.root) {
        return Err("head_root_unknown");
    }
    if !justified_slots_ops::is_slot_justified(
        projected_justified_slots,
        projected_finalized_slot,
        att_data.source.slot,
    ) {
        return Err("source_not_justified");
    }
    if !attestation_data_matches_chain(extended_historical_block_hashes, att_data) {
        return Err("chain_mismatch");
    }
    let is_genesis_self_vote = att_data.source.slot == 0 && att_data.target.slot == 0;
    if !is_genesis_self_vote
        && justified_slots_ops::is_slot_justified(
            projected_justified_slots,
            projected_finalized_slot,
            att_data.target.slot,
        )
    {
        return Err("target_already_justified");
    }
    Ok(())
}

/// Score a single candidate entry under the current projected state.
///
/// Returns `None` if the entry has zero new validators relative to the
/// running voter set for its `target.root` (no marginal value, drop). A
/// genesis self-vote (source.slot == target.slot == 0) cannot justify or
/// finalize anything and is scored as tier 3 if it contributes new voters.
fn score_entry(
    att_data: &AttestationData,
    proofs: &[TypeOneMultiSignature],
    current_votes: &HashMap<H256, HashSet<u64>>,
    projected_finalized_slot: u64,
    validator_count: usize,
) -> Option<EntryScore> {
    let empty;
    let prior_voters = match current_votes.get(&att_data.target.root) {
        Some(set) => set,
        None => {
            empty = HashSet::new();
            &empty
        }
    };

    // Union over all proofs: `extend_proofs_greedily` ends up covering this
    // set (it keeps picking proofs while any add a new validator).
    let mut union: HashSet<u64> = prior_voters.clone();
    for proof in proofs {
        for vid in proof.participant_indices() {
            union.insert(vid);
        }
    }
    let new_voters = union.len() - prior_voters.len();
    if new_voters == 0 {
        return None;
    }

    let att_slot = att_data.slot;
    let target_slot = att_data.target.slot;

    let is_genesis_self_vote = att_data.source.slot == 0 && target_slot == 0;
    if is_genesis_self_vote {
        return Some(EntryScore {
            tier: 3,
            new_voters,
            target_slot,
            att_slot,
        });
    }

    let crosses_2_3 = 3 * union.len() >= 2 * validator_count;
    if !crosses_2_3 {
        return Some(EntryScore {
            tier: 3,
            new_voters,
            target_slot,
            att_slot,
        });
    }

    // Crossing 2/3 justifies target.slot. Finalization of source requires
    // no slot strictly between source.slot and target.slot to still be
    // justifiable per 3SF-mini's (delta in 0..=5 ∪ squares ∪ pronics) rule,
    // i.e., source and target must be two consecutive justified checkpoints
    // in the projected post-state.
    let finalizes = (att_data.source.slot + 1..target_slot)
        .all(|s| !slot_is_justifiable_after(s, projected_finalized_slot));

    Some(EntryScore {
        tier: if finalizes { 1 } else { 2 },
        new_voters,
        target_slot,
        att_slot,
    })
}

/// Static inputs to the attestation selection scan: the candidate pool and
/// the chain-level facts used to filter and score entries. Built once before
/// the round loop in `select_attestations`.
struct ChainContext<'a> {
    aggregated_payloads: &'a HashMap<H256, (AttestationData, Vec<TypeOneMultiSignature>)>,
    known_block_roots: &'a HashSet<H256>,
    extended_historical_block_hashes: &'a [H256],
    validator_count: usize,
}

/// Mutable projection of the post-state that `select_attestations` maintains
/// across rounds: which slots are justified, which slot is finalized, and the
/// running per-target-root voter set.
struct ProjectedState {
    justified_slots: JustifiedSlots,
    finalized_slot: u64,
    current_votes: HashMap<H256, HashSet<u64>>,
}

/// Scan candidate attestation entries and pick the highest-scoring one.
///
/// Skips entries already processed, those failing `entry_passes_filters`
/// (logging the reason), and those with zero new voters. Among remaining
/// entries, returns the `(data_root, score)` with the best
/// `EntryScore::ordering_key` (lower is better). Caller re-indexes
/// `chain.aggregated_payloads[&data_root]` to get the entry's data and proofs.
fn pick_best_candidate(
    chain: &ChainContext<'_>,
    processed_data_roots: &HashSet<H256>,
    projected: &ProjectedState,
) -> Option<(H256, EntryScore)> {
    let mut best: Option<(H256, EntryScore)> = None;
    let mut best_key: Option<(u8, std::cmp::Reverse<usize>, u64, u64, H256)> = None;

    for (data_root, (att_data, proofs)) in chain.aggregated_payloads {
        if processed_data_roots.contains(data_root) {
            continue;
        }
        if let Err(reason) = entry_passes_filters(
            att_data,
            chain.known_block_roots,
            chain.extended_historical_block_hashes,
            &projected.justified_slots,
            projected.finalized_slot,
        ) {
            trace_skipped_attestation(reason, att_data, data_root);
            continue;
        }

        let Some(score) = score_entry(
            att_data,
            proofs,
            &projected.current_votes,
            projected.finalized_slot,
            chain.validator_count,
        ) else {
            trace_skipped_attestation("zero_new_voters", att_data, data_root);
            continue;
        };

        let candidate_key = score.ordering_key(*data_root);
        if best_key.as_ref().is_none_or(|k| candidate_key < *k) {
            best = Some((*data_root, score));
            best_key = Some(candidate_key);
        }
    }

    best
}

/// Tiered greedy attestation selection for block proposal.
///
/// Each round scores remaining candidates against a projected post-state and
/// picks the best per `EntryScore`: tier 1 (finalizes source) beats tier 2
/// (justifies target) beats tier 3 (adds new voters). Justification and
/// finalization are projected incrementally so dependent attestations become
/// eligible on the next round without re-running the STF.
///
/// Stops at `MAX_ATTESTATIONS_DATA` distinct data entries or when no
/// remaining candidate has a positive score. Within-entry proof selection is
/// delegated to `extend_proofs_greedily`.
fn select_attestations(
    head_state: &State,
    slot: u64,
    parent_root: H256,
    known_block_roots: &HashSet<H256>,
    aggregated_payloads: &HashMap<H256, (AttestationData, Vec<TypeOneMultiSignature>)>,
) -> Vec<(AggregatedAttestation, TypeOneMultiSignature)> {
    let mut selected: Vec<(AggregatedAttestation, TypeOneMultiSignature)> = Vec::new();
    if aggregated_payloads.is_empty() {
        return selected;
    }

    // Chain view that `process_block_header` would produce on the candidate
    // block: covering [0, slot - 1] with parent_root at parent.slot and
    // ZERO_HASH for empty slots in between. Lets us validate source/target
    // roots without waiting for the STF to drop mismatches.
    let parent_slot = head_state.latest_block_header.slot;
    let num_empty_slots = slot.saturating_sub(parent_slot).saturating_sub(1) as usize;
    let mut extended_historical_block_hashes: Vec<H256> =
        head_state.historical_block_hashes.iter().copied().collect();
    extended_historical_block_hashes.push(parent_root);
    extended_historical_block_hashes.extend(std::iter::repeat_n(H256::ZERO, num_empty_slots));

    let chain = ChainContext {
        aggregated_payloads,
        known_block_roots,
        extended_historical_block_hashes: &extended_historical_block_hashes,
        validator_count: head_state.validators.len(),
    };

    // Running per-target-root voter set, seeded from state and updated
    // incrementally as entries are selected. Mirrors the role of Eth2
    // participation flags in Prysm/Lighthouse-style packing.
    let mut projected = ProjectedState {
        justified_slots: head_state.justified_slots.clone(),
        finalized_slot: head_state.latest_finalized.slot,
        current_votes: build_running_votes(head_state),
    };
    let mut processed_data_roots: HashSet<H256> = HashSet::new();

    for _round in 0..MAX_ATTESTATIONS_DATA {
        let Some((data_root, score)) =
            pick_best_candidate(&chain, &processed_data_roots, &projected)
        else {
            trace!(
                selected_total = processed_data_roots.len(),
                "converged: no scoring candidates"
            );
            break;
        };
        let (att_data, proofs) = &chain.aggregated_payloads[&data_root];

        processed_data_roots.insert(data_root);

        let before = selected.len();
        extend_proofs_greedily(proofs, &mut selected, att_data);

        // Project the contribution to current_votes for the target root.
        // `extend_proofs_greedily` ends up covering the union of all
        // proof participants, so we read the actual selected voters back
        // out of `selected[before..]`.
        let added_voters: HashSet<u64> = selected[before..]
            .iter()
            .flat_map(|(att, _)| validator_indices(&att.aggregation_bits))
            .collect();
        let target_root = att_data.target.root;
        projected
            .current_votes
            .entry(target_root)
            .or_default()
            .extend(added_voters.iter().copied());

        trace!(
            tier = score.tier,
            new_voters = score.new_voters,
            target_slot = score.target_slot,
            target_root = %ShortRoot(&target_root.0),
            data_root = %ShortRoot(&data_root.0),
            selected_proofs = selected.len() - before,
            "selected"
        );

        // Project justification / finalization. Tier 1 implies tier 2
        // (target is justified, AND source is finalized).
        if score.tier <= 2 {
            justified_slots_ops::extend_to_slot(
                &mut projected.justified_slots,
                projected.finalized_slot,
                att_data.target.slot,
            );
            justified_slots_ops::set_justified(
                &mut projected.justified_slots,
                projected.finalized_slot,
                att_data.target.slot,
            );
            // Justified target's voter bucket is no longer relevant for
            // scoring (no further entry can target it: filter rejects).
            projected.current_votes.remove(&target_root);
        }
        if score.tier == 1 {
            let new_finalized = att_data.source.slot;
            let delta = new_finalized.saturating_sub(projected.finalized_slot) as usize;
            justified_slots_ops::shift_window(&mut projected.justified_slots, delta);
            projected.finalized_slot = new_finalized;
        }
    }

    selected
}

/// Build a valid block on top of this state.
///
/// Selects attestations via `select_attestations`, compacts duplicate
/// `AttestationData` entries, and runs the STF once to seal the state root.
/// The proposer signature is NOT included; it is appended by the caller.
fn build_block(
    head_state: &State,
    slot: u64,
    proposer_index: u64,
    parent_root: H256,
    known_block_roots: &HashSet<H256>,
    aggregated_payloads: &HashMap<H256, (AttestationData, Vec<TypeOneMultiSignature>)>,
) -> Result<(Block, Vec<TypeOneMultiSignature>, PostBlockCheckpoints), StoreError> {
    info!(slot, proposer_index, "Building block");

    let selected = select_attestations(
        head_state,
        slot,
        parent_root,
        known_block_roots,
        aggregated_payloads,
    );

    // Compact: merge proofs sharing the same AttestationData via recursive
    // aggregation so each AttestationData appears at most once (leanSpec #510).
    let compacted = compact_attestations(selected, head_state)?;

    let (aggregated_attestations, aggregated_signatures): (Vec<_>, Vec<_>) =
        compacted.into_iter().unzip();

    // Build final block
    let attestations: AggregatedAttestations = aggregated_attestations
        .try_into()
        .expect("attestation count exceeds limit");
    let mut final_block = Block {
        slot,
        proposer_index,
        parent_root,
        state_root: H256::ZERO,
        body: BlockBody { attestations },
    };
    let mut post_state = head_state.clone();
    process_slots(&mut post_state, slot)?;
    process_block(&mut post_state, &final_block)?;
    final_block.state_root = post_state.hash_tree_root();

    let post_checkpoints = PostBlockCheckpoints {
        justified: post_state.latest_justified,
        finalized: post_state.latest_finalized,
    };

    Ok((final_block, aggregated_signatures, post_checkpoints))
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
        block::{BlockBody, ByteList512KiB, SignedBlock, TypeOneMultiSignature},
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

    /// Regression test for https://github.com/lambdaclass/ethlambda/issues/259
    ///
    /// Simulates a stall scenario by populating the payload pool with 50
    /// distinct attestation entries, each carrying a ~253 KB proof (realistic
    /// XMSS aggregated proof size). Without the byte budget cap this would
    /// produce a block with all 50 entries. Verifies that build_block caps
    /// at MAX_ATTESTATIONS_DATA (16) and stays under the gossip size limit.
    #[test]
    fn build_block_caps_attestation_data_entries() {
        use ethlambda_types::{
            block::BlockHeader,
            state::{ChainConfig, JustificationValidators, JustifiedSlots},
        };
        use libssz::SszEncode;
        use libssz_types::SszList;

        const MAX_PAYLOAD_SIZE: usize = 10 * 1024 * 1024; // 10 MiB (spec limit)
        // Each pool entry carries a fake Type-1 proof of this size. Realistic
        // lean-multisig devnet5 Type-1 SNARKs weigh in around 200-400 KiB; we
        // stay well under the 512 KiB cap so try_from never rejects.
        const PROOF_SIZE: usize = 50 * 1024;
        const NUM_VALIDATORS: usize = 50;
        const NUM_PAYLOAD_ENTRIES: usize = 50;

        const HEAD_SLOT: u64 = 51;
        const TARGET_SLOT: u64 = 5;

        let validators: Vec<_> = (0..NUM_VALIDATORS)
            .map(|i| ethlambda_types::state::Validator {
                attestation_pubkey: [i as u8; 52],
                proposal_pubkey: [i as u8; 52],
                index: i as u64,
            })
            .collect();

        // Build a head state at slot HEAD_SLOT with valid historical_block_hashes
        // so attestations referencing in-range slots match the chain (the
        // chain-match check in build_block now rejects mismatches).
        let hashes: Vec<H256> = (0..HEAD_SLOT).map(|i| H256([(i + 1) as u8; 32])).collect();
        let historical_block_hashes = SszList::try_from(hashes.clone()).unwrap();

        let head_header = BlockHeader {
            slot: HEAD_SLOT,
            proposer_index: 0,
            parent_root: H256::ZERO,
            state_root: H256::ZERO,
            body_root: BlockBody::default().hash_tree_root(),
        };

        let head_state = State {
            config: ChainConfig { genesis_time: 1000 },
            slot: HEAD_SLOT,
            latest_block_header: head_header,
            latest_justified: Checkpoint::default(),
            latest_finalized: Checkpoint::default(),
            historical_block_hashes,
            justified_slots: JustifiedSlots::new(),
            validators: SszList::try_from(validators).unwrap(),
            justifications_roots: Default::default(),
            justifications_validators: JustificationValidators::new(),
        };

        // process_slots fills in the parent header's state_root before
        // process_block_header computes the parent hash. Simulate that here.
        let mut header_for_root = head_state.latest_block_header.clone();
        header_for_root.state_root = head_state.hash_tree_root();
        let parent_root = header_for_root.hash_tree_root();

        let slot = HEAD_SLOT + 1;
        let proposer_index = slot % NUM_VALIDATORS as u64;

        // Common source / target / head referencing valid chain entries so the
        // chain-match check passes for every payload. We vary AttestationData.slot
        // alone to produce 50 distinct data_roots.
        let source = Checkpoint {
            root: hashes[0],
            slot: 0,
        };
        let target = Checkpoint {
            root: hashes[TARGET_SLOT as usize],
            slot: TARGET_SLOT,
        };
        let head = Checkpoint {
            root: hashes[0],
            slot: 0,
        };

        let mut known_block_roots = HashSet::new();
        known_block_roots.insert(parent_root);
        known_block_roots.insert(hashes[0]);

        // Simulate a stall: populate the payload pool with many distinct entries.
        // Each has a unique attestation slot and a large proof payload.
        let mut aggregated_payloads: HashMap<H256, (AttestationData, Vec<TypeOneMultiSignature>)> =
            HashMap::new();

        for i in 0..NUM_PAYLOAD_ENTRIES {
            let att_data = AttestationData {
                slot: (i + 1) as u64,
                head,
                target,
                source,
            };

            // Use the real hash_tree_root as the data_root key
            let data_root = att_data.hash_tree_root();

            // Create a single large proof per entry (one validator per proof)
            let validator_id = i % NUM_VALIDATORS;
            let mut bits = AggregationBits::with_length(NUM_VALIDATORS).unwrap();
            bits.set(validator_id, true).unwrap();

            let proof_bytes: Vec<u8> = vec![0xAB; PROOF_SIZE];
            let proof_data = SszList::try_from(proof_bytes).expect("proof fits in ByteList512KiB");
            let proof = TypeOneMultiSignature::new(bits, proof_data);

            aggregated_payloads.insert(data_root, (att_data, vec![proof]));
        }

        // Build the block; this should succeed (the bug: no size guard)
        let (block, signatures, _post_checkpoints) = build_block(
            &head_state,
            slot,
            proposer_index,
            parent_root,
            &known_block_roots,
            &aggregated_payloads,
        )
        .expect("build_block should succeed");

        // MAX_ATTESTATIONS_DATA should have been enforced: fewer than 50 entries included
        let attestation_count = block.body.attestations.len();
        assert!(attestation_count > 0, "block should contain attestations");
        assert!(
            attestation_count <= MAX_ATTESTATIONS_DATA,
            "MAX_ATTESTATIONS_DATA should cap attestations: got {attestation_count}"
        );

        // Substitute a worst-case-size proof to model what `propose_block`
        // would attach. The actual SNARK can't be built without lean-multisig,
        // but the size cap (`ByteList512KiB`) bounds the worst case.
        let _ = signatures;
        let proof =
            ByteList512KiB::try_from(vec![0xAB; 512 * 1024]).expect("worst-case proof fits in cap");
        let signed_block = SignedBlock {
            message: block,
            proof,
        };

        // SSZ-encode: this is exactly what publish_block does before compression
        let ssz_bytes = signed_block.to_ssz();

        // With MAX_ATTESTATIONS_DATA = 16, blocks should fit within gossip limits.
        assert!(
            ssz_bytes.len() <= MAX_PAYLOAD_SIZE,
            "block with {} attestations is {} bytes SSZ, exceeds MAX_PAYLOAD_SIZE ({} bytes)",
            signed_block.message.body.attestations.len(),
            ssz_bytes.len(),
            MAX_PAYLOAD_SIZE,
        );
    }

    /// Regression test for leanSpec PR #716: build_block must absorb
    /// gap-closing attestations whose source is justified on the head
    /// chain but older than `latest_justified` (e.g., a sibling fork
    /// advanced the store's justified past what the canonical head has
    /// proven). Without the relaxed `is_slot_justified(source.slot)`
    /// filter, the exact-equality check would drop the attestation and
    /// justification would never converge on this chain.
    #[test]
    fn build_block_absorbs_older_but_justified_source() {
        use ethlambda_state_transition::justified_slots_ops;
        use ethlambda_types::{
            block::BlockHeader,
            state::{ChainConfig, JustificationValidators, JustifiedSlots},
        };
        use libssz_types::SszList;

        const NUM_VALIDATORS: usize = 50;
        const SUPERMAJORITY: usize = 34; // ceil(2 * 50 / 3)
        const HEAD_SLOT: u64 = 5;
        const JUSTIFIED_SLOT: u64 = 1;
        const GAP_TARGET_SLOT: u64 = 2;

        let validators: Vec<_> = (0..NUM_VALIDATORS)
            .map(|i| ethlambda_types::state::Validator {
                attestation_pubkey: [i as u8; 52],
                proposal_pubkey: [i as u8; 52],
                index: i as u64,
            })
            .collect();

        let hashes: Vec<H256> = (0..HEAD_SLOT).map(|i| H256([(i + 1) as u8; 32])).collect();

        let mut justified_slots = JustifiedSlots::new();
        justified_slots_ops::extend_to_slot(&mut justified_slots, 0, JUSTIFIED_SLOT);
        justified_slots_ops::set_justified(&mut justified_slots, 0, JUSTIFIED_SLOT);

        let head_header = BlockHeader {
            slot: HEAD_SLOT,
            proposer_index: 0,
            parent_root: H256::ZERO,
            state_root: H256::ZERO,
            body_root: BlockBody::default().hash_tree_root(),
        };

        let head_state = State {
            config: ChainConfig { genesis_time: 1000 },
            slot: HEAD_SLOT,
            latest_block_header: head_header,
            latest_justified: Checkpoint {
                root: hashes[JUSTIFIED_SLOT as usize],
                slot: JUSTIFIED_SLOT,
            },
            latest_finalized: Checkpoint::default(),
            historical_block_hashes: SszList::try_from(hashes.clone()).unwrap(),
            justified_slots,
            validators: SszList::try_from(validators).unwrap(),
            justifications_roots: Default::default(),
            justifications_validators: JustificationValidators::new(),
        };

        let mut header_for_root = head_state.latest_block_header.clone();
        header_for_root.state_root = head_state.hash_tree_root();
        let parent_root = header_for_root.hash_tree_root();

        let slot = HEAD_SLOT + 1;
        let proposer_index = slot % NUM_VALIDATORS as u64;

        // source = genesis (slot 0): older than head.latest_justified at
        // slot 1. Pre-PR exact-equality filter would drop this; post-PR
        // it's absorbed and the candidate justifies GAP_TARGET_SLOT.
        let att_data = AttestationData {
            slot,
            head: Checkpoint {
                root: hashes[0],
                slot: 0,
            },
            target: Checkpoint {
                root: hashes[GAP_TARGET_SLOT as usize],
                slot: GAP_TARGET_SLOT,
            },
            source: Checkpoint {
                root: hashes[0],
                slot: 0,
            },
        };
        let data_root = att_data.hash_tree_root();

        let mut bits = AggregationBits::with_length(NUM_VALIDATORS).unwrap();
        for i in 0..SUPERMAJORITY {
            bits.set(i, true).unwrap();
        }
        let proof_data = SszList::try_from(vec![0xAB; 64]).unwrap();
        let proof = TypeOneMultiSignature::new(bits, proof_data);

        let mut aggregated_payloads = HashMap::new();
        aggregated_payloads.insert(data_root, (att_data.clone(), vec![proof]));

        let mut known_block_roots = HashSet::new();
        known_block_roots.insert(parent_root);
        known_block_roots.insert(hashes[0]);

        let (block, _signatures, post_checkpoints) = build_block(
            &head_state,
            slot,
            proposer_index,
            parent_root,
            &known_block_roots,
            &aggregated_payloads,
        )
        .expect("build_block should succeed");

        let targets: Vec<_> = block
            .body
            .attestations
            .iter()
            .map(|att| att.data.target)
            .collect();
        assert!(
            targets.contains(&att_data.target),
            "produced block missing gap-closing attestation: {targets:?}"
        );

        assert_eq!(post_checkpoints.justified.slot, GAP_TARGET_SLOT);
        assert_eq!(
            post_checkpoints.justified.root,
            hashes[GAP_TARGET_SLOT as usize]
        );
    }

    fn make_att_data(slot: u64) -> AttestationData {
        AttestationData {
            slot,
            head: Checkpoint::default(),
            target: Checkpoint::default(),
            source: Checkpoint::default(),
        }
    }

    fn make_bits(indices: &[usize]) -> AggregationBits {
        let max = indices.iter().copied().max().unwrap_or(0);
        let mut bits = AggregationBits::with_length(max + 1).unwrap();
        for &i in indices {
            bits.set(i, true).unwrap();
        }
        bits
    }

    /// Test helper: empty Type-1 proof carrying the given participants and slot
    /// metadata. Only the participant bitfield matters for the pipeline tests
    /// below; the proof envelope no longer carries a slot or message.
    fn make_type_one_proof(bits: AggregationBits, _slot: u64) -> TypeOneMultiSignature {
        TypeOneMultiSignature::empty(bits)
    }

    #[test]
    fn compact_attestations_no_duplicates() {
        let data_a = make_att_data(1);
        let data_b = make_att_data(2);
        let bits_a = make_bits(&[0]);
        let bits_b = make_bits(&[1]);

        let entries = vec![
            (
                AggregatedAttestation {
                    aggregation_bits: bits_a.clone(),
                    data: data_a.clone(),
                },
                make_type_one_proof(bits_a, data_a.slot),
            ),
            (
                AggregatedAttestation {
                    aggregation_bits: bits_b.clone(),
                    data: data_b.clone(),
                },
                make_type_one_proof(bits_b, data_b.slot),
            ),
        ];

        let state = State::from_genesis(1000, vec![]);
        let out = compact_attestations(entries, &state).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].0.data, data_a);
        assert_eq!(out[1].0.data, data_b);
    }

    #[test]
    fn compact_attestations_preserves_order_no_duplicates() {
        let data_a = make_att_data(1);
        let data_b = make_att_data(2);
        let data_c = make_att_data(3);

        let bits_0 = make_bits(&[0]);
        let bits_1 = make_bits(&[1]);
        let bits_2 = make_bits(&[2]);

        let entries = vec![
            (
                AggregatedAttestation {
                    aggregation_bits: bits_0.clone(),
                    data: data_a.clone(),
                },
                make_type_one_proof(bits_0, data_a.slot),
            ),
            (
                AggregatedAttestation {
                    aggregation_bits: bits_1.clone(),
                    data: data_b.clone(),
                },
                make_type_one_proof(bits_1, data_b.slot),
            ),
            (
                AggregatedAttestation {
                    aggregation_bits: bits_2.clone(),
                    data: data_c.clone(),
                },
                make_type_one_proof(bits_2, data_c.slot),
            ),
        ];

        let state = State::from_genesis(1000, vec![]);
        let out = compact_attestations(entries, &state).unwrap();
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].0.data, data_a);
        assert_eq!(out[1].0.data, data_b);
        assert_eq!(out[2].0.data, data_c);
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

    /// A partially-overlapping proof is still selected as long as it adds at
    /// least one previously-uncovered validator. The greedy prefers the
    /// largest proof first, then picks additional proofs whose coverage
    /// extends `covered`. The resulting overlap is handled downstream by
    /// `aggregate_proofs` → `aggregate_type_1` (which tracks duplicate pubkeys
    /// across children via its `dup_pub_keys` machinery).
    #[test]
    fn extend_proofs_greedily_allows_overlap_when_it_adds_coverage() {
        let data = make_att_data(1);

        // Distinct sizes to avoid tie-breaking ambiguity (HashSet iteration
        // order differs between debug/release):
        //   A = {0, 1, 2, 3}  (4 validators — largest, picked first)
        //   B = {2, 3, 4}     (overlaps A on {2,3} but adds validator 4)
        //   C = {1, 2}        (subset of A — adds nothing, must be skipped)
        let proof_a = make_type_one_proof(make_bits(&[0, 1, 2, 3]), data.slot);
        let proof_b = make_type_one_proof(make_bits(&[2, 3, 4]), data.slot);
        let proof_c = make_type_one_proof(make_bits(&[1, 2]), data.slot);

        let mut selected = Vec::new();
        extend_proofs_greedily(&[proof_a, proof_b, proof_c], &mut selected, &data);

        assert_eq!(
            selected.len(),
            2,
            "A and B selected (B adds validator 4); C adds nothing and is skipped"
        );

        let covered: HashSet<u64> = selected
            .iter()
            .flat_map(|(_, p)| p.participant_indices())
            .collect();
        assert_eq!(covered, HashSet::from([0, 1, 2, 3, 4]));

        // Attestation bits mirror the proof's participants for each entry.
        for (att, proof) in &selected {
            assert_eq!(att.aggregation_bits, proof.participants);
            assert_eq!(att.data, data);
        }
    }

    /// When no proof contributes new coverage (subset of a previously selected
    /// proof), greedy terminates without selecting it.
    #[test]
    fn extend_proofs_greedily_stops_when_no_new_coverage() {
        let data = make_att_data(1);

        // B's participants are a subset of A's. After picking A, B offers zero
        // new coverage and must not be selected (its inclusion would also
        // violate the disjoint invariant).
        let proof_a = make_type_one_proof(make_bits(&[0, 1, 2, 3]), data.slot);
        let proof_b = make_type_one_proof(make_bits(&[1, 2]), data.slot);

        let mut selected = Vec::new();
        extend_proofs_greedily(&[proof_a, proof_b], &mut selected, &data);

        assert_eq!(selected.len(), 1);
        let covered: HashSet<u64> = selected[0].1.participant_indices().collect();
        assert_eq!(covered, HashSet::from([0, 1, 2, 3]));
    }
}
