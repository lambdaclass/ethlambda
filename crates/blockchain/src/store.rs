use std::collections::{HashMap, HashSet};

use ethlambda_crypto::aggregate_proofs;
use ethlambda_state_transition::{
    is_proposer, process_block, process_slots, slot_is_justifiable_after,
};
use ethlambda_storage::{ForkCheckpoints, Store};
use ethlambda_types::{
    ShortRoot,
    attestation::{
        AggregatedAttestation, AggregationBits, Attestation, AttestationData,
        HashedAttestationData, SignedAggregatedAttestation, SignedAttestation, validator_indices,
    },
    block::{AggregatedAttestations, AggregatedSignatureProof, Block, BlockBody, SignedBlock},
    checkpoint::Checkpoint,
    primitives::{H256, HashTreeRoot as _},
    signature::ValidatorSignature,
    state::State,
};
use tracing::{info, trace, warn};

use crate::{
    INTERVALS_PER_SLOT, MAX_ATTESTATIONS_DATA, MILLISECONDS_PER_INTERVAL, MILLISECONDS_PER_SLOT,
    metrics,
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
///     5. A vote cannot be for a future slot.
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

    // Time Check - Validate attestation is not too far in the future.
    // We allow a small margin for clock disparity (1 slot), but no further.
    let current_slot = store.time() / INTERVALS_PER_SLOT;
    if data.slot > current_slot + 1 {
        return Err(StoreError::AttestationTooFarInFuture {
            attestation_slot: data.slot,
            current_slot,
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
            &aggregated.proof.proof_data,
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
        verify_signatures(&parent_state, &signed_block)?;
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

    // Process block body attestations and their signatures
    let aggregated_attestations = &block.body.attestations;
    let attestation_signatures = &signed_block.signature.attestation_signatures;

    // Store one proof per attestation data in known aggregated payloads.
    let mut known_entries: Vec<(HashedAttestationData, AggregatedSignatureProof)> = Vec::new();
    for (att, proof) in aggregated_attestations
        .iter()
        .zip(attestation_signatures.iter())
    {
        known_entries.push((HashedAttestationData::new(att.data.clone()), proof.clone()));
        // Count each participating validator as a valid attestation
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
) -> Result<(Block, Vec<AggregatedSignatureProof>, PostBlockCheckpoints), StoreError> {
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

    #[error("Proposer signature could not be decoded")]
    ProposerSignatureDecodingFailed,

    #[error("Proposer signature verification failed")]
    ProposerSignatureVerificationFailed,

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
        "Attestation slot {attestation_slot} is too far in future (current slot: {current_slot})"
    )]
    AttestationTooFarInFuture {
        attestation_slot: u64,
        current_slot: u64,
    },

    #[error(
        "Attestations and signatures don't match in length: got {signatures} signatures and {attestations} attestations"
    )]
    AttestationSignatureMismatch {
        signatures: usize,
        attestations: usize,
    },

    #[error("Aggregated proof participants don't match attestation aggregation bits")]
    ParticipantsMismatch,

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
    entries: Vec<(AggregatedAttestation, AggregatedSignatureProof)>,
    head_state: &State,
) -> Result<Vec<(AggregatedAttestation, AggregatedSignatureProof)>, StoreError> {
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
    let mut items: Vec<Option<(AggregatedAttestation, AggregatedSignatureProof)>> =
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
        let group_items: Vec<(AggregatedAttestation, AggregatedSignatureProof)> = indices
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
                Ok((pubkeys, proof.proof_data.clone()))
            })
            .collect::<Result<Vec<_>, StoreError>>()?;

        let slot: u32 = data.slot.try_into().expect("slot exceeds u32");
        let merged_proof_data = aggregate_proofs(children, &data_root, slot)
            .map_err(StoreError::SignatureAggregationFailed)?;

        let merged_proof = AggregatedSignatureProof::new(merged_bits.clone(), merged_proof_data);
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
/// `xmss_aggregate` — that function tracks duplicate pubkeys across
/// children via its `dup_pub_keys` machinery, so overlap is supported by
/// the underlying aggregation scheme.
///
/// Each selected proof is appended to `selected` paired with its
/// corresponding AggregatedAttestation.
fn extend_proofs_greedily(
    proofs: &[AggregatedSignatureProof],
    selected: &mut Vec<(AggregatedAttestation, AggregatedSignatureProof)>,
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

/// Build a valid block on top of this state.
///
/// Works directly with aggregated payloads keyed by data_root, filtering
/// and selecting proofs without reconstructing individual attestations.
///
/// Returns the block and a list of attestation signature proofs
/// (one per attestation in block.body.attestations). The proposer signature
/// is NOT included; it is appended by the caller.
fn build_block(
    head_state: &State,
    slot: u64,
    proposer_index: u64,
    parent_root: H256,
    known_block_roots: &HashSet<H256>,
    aggregated_payloads: &HashMap<H256, (AttestationData, Vec<AggregatedSignatureProof>)>,
) -> Result<(Block, Vec<AggregatedSignatureProof>, PostBlockCheckpoints), StoreError> {
    let mut selected: Vec<(AggregatedAttestation, AggregatedSignatureProof)> = Vec::new();

    if !aggregated_payloads.is_empty() {
        // Genesis edge case: when building on genesis (slot 0),
        // process_block_header will set latest_justified.root = parent_root.
        // Derive this upfront so attestation filtering matches.
        let mut current_justified = if head_state.latest_block_header.slot == 0 {
            Checkpoint {
                root: parent_root,
                slot: head_state.latest_justified.slot,
            }
        } else {
            head_state.latest_justified
        };

        let mut processed_data_roots: HashSet<H256> = HashSet::new();

        // Sort by target.slot to match the spec's processing order.
        let mut sorted_entries: Vec<_> = aggregated_payloads.iter().collect();
        sorted_entries.sort_by_key(|(_, (data, _))| data.target.slot);

        loop {
            let mut found_new = false;

            for &(data_root, (att_data, proofs)) in &sorted_entries {
                if processed_data_roots.contains(data_root) {
                    continue;
                }
                // Cap distinct AttestationData entries per block (leanSpec #536).
                if processed_data_roots.len() >= MAX_ATTESTATIONS_DATA {
                    break;
                }
                if !known_block_roots.contains(&att_data.head.root) {
                    continue;
                }
                if att_data.source != current_justified {
                    continue;
                }

                processed_data_roots.insert(*data_root);
                found_new = true;

                extend_proofs_greedily(proofs, &mut selected, att_data);
            }

            if !found_new {
                break;
            }

            // Check if justification advanced
            let attestations: AggregatedAttestations = selected
                .iter()
                .map(|(att, _)| att.clone())
                .collect::<Vec<_>>()
                .try_into()
                .expect("attestation count exceeds limit");
            let candidate = Block {
                slot,
                proposer_index,
                parent_root,
                state_root: H256::ZERO,
                body: BlockBody { attestations },
            };
            let mut post_state = head_state.clone();
            process_slots(&mut post_state, slot)?;
            process_block(&mut post_state, &candidate)?;

            if post_state.latest_justified != current_justified {
                current_justified = post_state.latest_justified;
                // Continue: new checkpoint may unlock more attestation data
            } else {
                break;
            }
        }
    }

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

/// Verify all signatures in a signed block.
///
/// Each attestation has a corresponding proof in the signature list.
fn verify_signatures(state: &State, signed_block: &SignedBlock) -> Result<(), StoreError> {
    use ethlambda_crypto::verify_aggregated_signature;
    use ethlambda_types::signature::ValidatorSignature;

    let total_start = std::time::Instant::now();

    let block = &signed_block.message;
    let attestations = &block.body.attestations;
    let attestation_signatures = &signed_block.signature.attestation_signatures;

    if attestations.len() != attestation_signatures.len() {
        return Err(StoreError::AttestationSignatureMismatch {
            signatures: attestation_signatures.len(),
            attestations: attestations.len(),
        });
    }
    let validators = &state.validators;
    let num_validators = validators.len() as u64;

    // Verify each attestation's signature proof in parallel
    let aggregated_start = std::time::Instant::now();

    // Prepare verification inputs sequentially (cheap: bit checks + pubkey lookups)
    let verification_inputs: Vec<_> = attestations
        .iter()
        .zip(attestation_signatures)
        .map(|(attestation, aggregated_proof)| {
            if attestation.aggregation_bits != aggregated_proof.participants {
                return Err(StoreError::ParticipantsMismatch);
            }

            let slot: u32 = attestation.data.slot.try_into().expect("slot exceeds u32");
            let message = attestation.data.hash_tree_root();

            // Collect attestation public keys with bounds check in a single pass
            let public_keys: Vec<_> = validator_indices(&attestation.aggregation_bits)
                .map(|vid| {
                    if vid >= num_validators {
                        return Err(StoreError::InvalidValidatorIndex);
                    }
                    validators[vid as usize]
                        .get_attestation_pubkey()
                        .map_err(|_| StoreError::PubkeyDecodingFailed(vid))
                })
                .collect::<Result<_, _>>()?;

            Ok((&aggregated_proof.proof_data, public_keys, message, slot))
        })
        .collect::<Result<_, StoreError>>()?;

    // Run expensive signature verification in parallel.
    // into_par_iter() moves each tuple, avoiding a clone of public_keys.
    use rayon::prelude::*;
    verification_inputs.into_par_iter().try_for_each(
        |(proof_data, public_keys, message, slot)| {
            let result = {
                let _timing = metrics::time_pq_sig_aggregated_signatures_verification();
                verify_aggregated_signature(proof_data, public_keys, &message, slot)
            };
            match result {
                Ok(()) => {
                    metrics::inc_pq_sig_aggregated_signatures_valid();
                    Ok(())
                }
                Err(e) => {
                    metrics::inc_pq_sig_aggregated_signatures_invalid();
                    Err(StoreError::AggregateVerificationFailed(e))
                }
            }
        },
    )?;

    let aggregated_elapsed = aggregated_start.elapsed();

    let proposer_start = std::time::Instant::now();

    // Verify proposer signature over block root using proposal key
    let proposer_signature =
        ValidatorSignature::from_bytes(&signed_block.signature.proposer_signature)
            .map_err(|_| StoreError::ProposerSignatureDecodingFailed)?;

    let proposer = validators
        .get(block.proposer_index as usize)
        .ok_or(StoreError::InvalidValidatorIndex)?;

    let proposer_pubkey = proposer
        .get_proposal_pubkey()
        .map_err(|_| StoreError::PubkeyDecodingFailed(proposer.index))?;

    let slot: u32 = block.slot.try_into().expect("slot exceeds u32");
    let block_root = block.hash_tree_root();

    if !proposer_signature.is_valid(&proposer_pubkey, slot, &block_root) {
        return Err(StoreError::ProposerSignatureVerificationFailed);
    }
    let proposer_elapsed = proposer_start.elapsed();

    let total_elapsed = total_start.elapsed();
    info!(
        slot = block.slot,
        attestation_count = attestations.len(),
        ?aggregated_elapsed,
        ?proposer_elapsed,
        ?total_elapsed,
        "Signature verification timing"
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
        attestation::{AggregatedAttestation, AggregationBits, AttestationData, XmssSignature},
        block::{
            AggregatedSignatureProof, AttestationSignatures, BlockBody, BlockSignatures,
            SignedBlock,
        },
        checkpoint::Checkpoint,
        signature::SIGNATURE_SIZE,
        state::State,
    };

    #[test]
    fn verify_signatures_rejects_participants_mismatch() {
        let state = State::from_genesis(1000, vec![]);

        let attestation_data = AttestationData {
            slot: 0,
            head: Checkpoint::default(),
            target: Checkpoint::default(),
            source: Checkpoint::default(),
        };

        // Create attestation with bits [0, 1] set
        let mut attestation_bits = AggregationBits::with_length(4).unwrap();
        attestation_bits.set(0, true).unwrap();
        attestation_bits.set(1, true).unwrap();

        // Create proof with different bits [0, 1, 2] set
        let mut proof_bits = AggregationBits::with_length(4).unwrap();
        proof_bits.set(0, true).unwrap();
        proof_bits.set(1, true).unwrap();
        proof_bits.set(2, true).unwrap();

        let attestation = AggregatedAttestation {
            aggregation_bits: attestation_bits,
            data: attestation_data,
        };
        let proof = AggregatedSignatureProof::empty(proof_bits);

        let attestations = AggregatedAttestations::try_from(vec![attestation]).unwrap();
        let attestation_signatures = AttestationSignatures::try_from(vec![proof]).unwrap();

        let signed_block = SignedBlock {
            message: Block {
                slot: 0,
                proposer_index: 0,
                parent_root: H256::ZERO,
                state_root: H256::ZERO,
                body: BlockBody { attestations },
            },
            signature: BlockSignatures {
                attestation_signatures,
                proposer_signature: XmssSignature::try_from(vec![0u8; SIGNATURE_SIZE]).unwrap(),
            },
        };

        let result = verify_signatures(&state, &signed_block);
        assert!(
            matches!(result, Err(StoreError::ParticipantsMismatch)),
            "Expected ParticipantsMismatch, got: {result:?}"
        );
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
        use libssz::SszEncode;
        use libssz_types::SszList;

        const MAX_PAYLOAD_SIZE: usize = 10 * 1024 * 1024; // 10 MiB (spec limit)
        const PROOF_SIZE: usize = 253 * 1024; // ~253 KB realistic XMSS proof
        const NUM_VALIDATORS: usize = 50;
        const NUM_PAYLOAD_ENTRIES: usize = 50;

        // Create genesis state with NUM_VALIDATORS validators.
        let validators: Vec<_> = (0..NUM_VALIDATORS)
            .map(|i| ethlambda_types::state::Validator {
                attestation_pubkey: [i as u8; 52],
                proposal_pubkey: [i as u8; 52],
                index: i as u64,
            })
            .collect();
        let head_state = State::from_genesis(1000, validators);

        // process_slots fills in the genesis header's state_root before
        // process_block_header computes the parent hash. Simulate that here.
        let mut header_for_root = head_state.latest_block_header.clone();
        header_for_root.state_root = head_state.hash_tree_root();
        let parent_root = header_for_root.hash_tree_root();

        // Proposer for slot 1 with NUM_VALIDATORS validators: 1 % 50 = 1
        let proposer_index = 1u64;
        let slot = 1u64;

        // The genesis edge case in build_block sets current_justified to:
        //   Checkpoint { root: parent_root, slot: 0 }
        let source = Checkpoint {
            root: parent_root,
            slot: 0,
        };

        let mut known_block_roots = HashSet::new();
        known_block_roots.insert(parent_root);

        // Simulate a stall: populate the payload pool with many distinct entries.
        // Each has a unique target (different slot) and a large proof payload.
        let mut aggregated_payloads: HashMap<
            H256,
            (AttestationData, Vec<AggregatedSignatureProof>),
        > = HashMap::new();

        for i in 0..NUM_PAYLOAD_ENTRIES {
            let target_slot = (i + 1) as u64;
            let att_data = AttestationData {
                slot: target_slot,
                head: Checkpoint {
                    root: parent_root,
                    slot: 0,
                },
                target: Checkpoint {
                    root: H256([target_slot as u8; 32]),
                    slot: target_slot,
                },
                source,
            };

            // Use the real hash_tree_root as the data_root key
            let data_root = att_data.hash_tree_root();

            // Create a single large proof per entry (one validator per proof)
            let validator_id = i % NUM_VALIDATORS;
            let mut bits = AggregationBits::with_length(NUM_VALIDATORS).unwrap();
            bits.set(validator_id, true).unwrap();

            let proof_bytes: Vec<u8> = vec![0xAB; PROOF_SIZE];
            let proof_data = SszList::try_from(proof_bytes).expect("proof fits in ByteListMiB");
            let proof = AggregatedSignatureProof::new(bits, proof_data);

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

        // Construct the full signed block as it would be sent over gossip
        let attestation_sigs: Vec<AggregatedSignatureProof> = signatures;
        let signed_block = SignedBlock {
            message: block,
            signature: BlockSignatures {
                attestation_signatures: AttestationSignatures::try_from(attestation_sigs).unwrap(),
                proposer_signature: XmssSignature::try_from(vec![0u8; SIGNATURE_SIZE]).unwrap(),
            },
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
                AggregatedSignatureProof::empty(bits_a),
            ),
            (
                AggregatedAttestation {
                    aggregation_bits: bits_b.clone(),
                    data: data_b.clone(),
                },
                AggregatedSignatureProof::empty(bits_b),
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
                AggregatedSignatureProof::empty(bits_0),
            ),
            (
                AggregatedAttestation {
                    aggregation_bits: bits_1.clone(),
                    data: data_b.clone(),
                },
                AggregatedSignatureProof::empty(bits_1),
            ),
            (
                AggregatedAttestation {
                    aggregation_bits: bits_2.clone(),
                    data: data_c.clone(),
                },
                AggregatedSignatureProof::empty(bits_2),
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
        let genesis_block = Block {
            slot: 0,
            proposer_index: 0,
            parent_root: H256::ZERO,
            state_root: H256::ZERO,
            body: BlockBody {
                attestations: AggregatedAttestations::default(),
            },
        };
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::get_forkchoice_store(backend, genesis_state, genesis_block);

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

        let attestation_signatures = AttestationSignatures::try_from(vec![
            AggregatedSignatureProof::empty(bits_a),
            AggregatedSignatureProof::empty(bits_b),
        ])
        .unwrap();

        let signed_block = SignedBlock {
            message: Block {
                slot: 1,
                proposer_index: 0,
                parent_root: head_root,
                state_root: H256::ZERO,
                body: BlockBody { attestations },
            },
            signature: BlockSignatures {
                attestation_signatures,
                proposer_signature: XmssSignature::try_from(vec![0u8; SIGNATURE_SIZE]).unwrap(),
            },
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
    /// `aggregate_proofs` → `xmss_aggregate` (which tracks duplicate pubkeys
    /// across children via its `dup_pub_keys` machinery).
    #[test]
    fn extend_proofs_greedily_allows_overlap_when_it_adds_coverage() {
        let data = make_att_data(1);

        // Distinct sizes to avoid tie-breaking ambiguity (HashSet iteration
        // order differs between debug/release):
        //   A = {0, 1, 2, 3}  (4 validators — largest, picked first)
        //   B = {2, 3, 4}     (overlaps A on {2,3} but adds validator 4)
        //   C = {1, 2}        (subset of A — adds nothing, must be skipped)
        let proof_a = AggregatedSignatureProof::empty(make_bits(&[0, 1, 2, 3]));
        let proof_b = AggregatedSignatureProof::empty(make_bits(&[2, 3, 4]));
        let proof_c = AggregatedSignatureProof::empty(make_bits(&[1, 2]));

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
        let proof_a = AggregatedSignatureProof::empty(make_bits(&[0, 1, 2, 3]));
        let proof_b = AggregatedSignatureProof::empty(make_bits(&[1, 2]));

        let mut selected = Vec::new();
        extend_proofs_greedily(&[proof_a, proof_b], &mut selected, &data);

        assert_eq!(selected.len(), 1);
        let covered: HashSet<u64> = selected[0].1.participant_indices().collect();
        assert_eq!(covered, HashSet::from([0, 1, 2, 3]));
    }
}
