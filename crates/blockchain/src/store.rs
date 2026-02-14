use std::collections::{HashMap, HashSet};

use ethlambda_crypto::aggregate_signatures;
use ethlambda_state_transition::{
    is_proposer, process_block, process_slots, slot_is_justifiable_after,
};
use ethlambda_storage::{ForkCheckpoints, SignatureKey, Store, StoredAggregatedPayload};
use ethlambda_types::{
    ShortRoot,
    attestation::{
        AggregatedAttestation, Attestation, AttestationData, SignedAggregatedAttestation,
        SignedAttestation,
    },
    block::{
        AggregatedAttestations, AggregatedSignatureProof, AggregationBits, Block, BlockBody,
        SignedBlockWithAttestation,
    },
    primitives::{H256, ssz::TreeHash},
    signature::ValidatorSignature,
    state::{Checkpoint, State},
};
use tracing::{info, trace, warn};

use crate::{INTERVALS_PER_SLOT, MILLISECONDS_PER_INTERVAL, MILLISECONDS_PER_SLOT, metrics};

const JUSTIFICATION_LOOKBACK_SLOTS: u64 = 3;

/// Accept new aggregated payloads, promoting them to known for fork choice.
fn accept_new_attestations(store: &mut Store) {
    store.promote_new_aggregated_payloads();
    update_head(store);
}

/// Update the head based on the fork choice rule.
fn update_head(store: &mut Store) {
    let blocks = store.get_live_chain();
    let attestations = extract_attestations_from_aggregated_payloads(
        store,
        store.iter_known_aggregated_payloads(),
    );
    let old_head = store.head();
    let new_head = ethlambda_fork_choice::compute_lmd_ghost_head(
        store.latest_justified().root,
        &blocks,
        &attestations,
        0,
    );
    if is_reorg(old_head, new_head, store) {
        metrics::inc_fork_choice_reorgs();
        info!(%old_head, %new_head, "Fork choice reorg detected");
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
}

/// Update the safe target for attestation.
fn update_safe_target(store: &mut Store) {
    let head_state = store.get_state(&store.head()).expect("head state exists");
    let num_validators = head_state.validators.len() as u64;

    let min_target_score = (num_validators * 2).div_ceil(3);

    let blocks = store.get_live_chain();
    let attestations =
        extract_attestations_from_aggregated_payloads(store, store.iter_new_aggregated_payloads());
    let safe_target = ethlambda_fork_choice::compute_lmd_ghost_head(
        store.latest_justified().root,
        &blocks,
        &attestations,
        min_target_score,
    );
    store.set_safe_target(safe_target);
}

/// Reconstruct per-validator attestation data from aggregated payloads.
///
/// For each (validator_id, data_root) key in the payloads, looks up the
/// attestation data by root. Returns the latest attestation per validator
/// (by slot).
fn extract_attestations_from_aggregated_payloads(
    store: &Store,
    payloads: impl Iterator<Item = (SignatureKey, Vec<StoredAggregatedPayload>)>,
) -> HashMap<u64, AttestationData> {
    let mut result: HashMap<u64, AttestationData> = HashMap::new();

    for ((validator_id, data_root), _payload_list) in payloads {
        let Some(data) = store.get_attestation_data_by_root(&data_root) else {
            continue;
        };

        let should_update = result
            .get(&validator_id)
            .is_none_or(|existing| existing.slot < data.slot);

        if should_update {
            result.insert(validator_id, data);
        }
    }

    result
}

/// Aggregate committee signatures at interval 2.
///
/// Collects individual gossip signatures, aggregates them by attestation data,
/// and stores the resulting proofs in `LatestNewAggregatedPayloads`.
fn aggregate_committee_signatures(store: &mut Store) {
    let gossip_sigs: Vec<(SignatureKey, _)> = store.iter_gossip_signatures().collect();
    if gossip_sigs.is_empty() {
        return;
    }

    let head_state = store.head_state();
    let validators = &head_state.validators;

    // Group gossip signatures by data_root for batch aggregation
    let mut groups: HashMap<H256, Vec<(u64, ValidatorSignature)>> = HashMap::new();
    let mut keys_to_delete: Vec<SignatureKey> = Vec::new();

    for ((validator_id, data_root), stored_sig) in &gossip_sigs {
        if let Ok(sig) = stored_sig.to_validator_signature() {
            groups
                .entry(*data_root)
                .or_default()
                .push((*validator_id, sig));
        }
    }

    for (data_root, validators_and_sigs) in groups {
        let Some(data) = store.get_attestation_data_by_root(&data_root) else {
            continue;
        };

        let slot = data.slot;
        let message = data.tree_hash_root();

        let mut sigs = vec![];
        let mut pubkeys = vec![];
        let mut ids = vec![];

        for (vid, sig) in &validators_and_sigs {
            let Some(validator) = validators.get(*vid as usize) else {
                continue;
            };
            let Ok(pubkey) = validator.get_pubkey() else {
                continue;
            };
            sigs.push(sig.clone());
            pubkeys.push(pubkey);
            ids.push(*vid);
        }

        if ids.is_empty() {
            continue;
        }

        let Ok(proof_data) = aggregate_signatures(pubkeys, sigs, &message, slot as u32)
            .inspect_err(|err| warn!(%err, "Failed to aggregate committee signatures"))
        else {
            continue;
        };

        let participants = aggregation_bits_from_validator_indices(&ids);
        let proof = AggregatedSignatureProof::new(participants, proof_data);
        let payload = StoredAggregatedPayload { slot, proof };

        // Store in new aggregated payloads for each covered validator
        for vid in &ids {
            store.insert_new_aggregated_payload((*vid, data_root), payload.clone());
        }

        // Only delete successfully aggregated signatures
        keys_to_delete.extend(ids.iter().map(|vid| (*vid, data_root)));

        metrics::inc_pq_sig_aggregated_signatures();
        metrics::inc_pq_sig_attestations_in_aggregated_signatures(ids.len() as u64);
    }

    // Delete aggregated entries from gossip_signatures
    store.delete_gossip_signatures(&keys_to_delete);
}

/// Validate incoming attestation before processing.
///
/// Ensures the vote respects the basic laws of time and topology:
///     1. The blocks voted for must exist in our store.
///     2. A vote cannot span backwards in time (source > target).
///     3. A vote cannot be for a future slot.
fn validate_attestation_data(store: &Store, data: &AttestationData) -> Result<(), StoreError> {
    let _timing = metrics::time_attestation_validation();

    // Availability Check - We cannot count a vote if we haven't seen the blocks involved.
    let source_header = store
        .get_block_header(&data.source.root)
        .ok_or(StoreError::UnknownSourceBlock(data.source.root))?;
    let target_header = store
        .get_block_header(&data.target.root)
        .ok_or(StoreError::UnknownTargetBlock(data.target.root))?;

    let _ = store
        .get_block_header(&data.head.root)
        .ok_or(StoreError::UnknownHeadBlock(data.head.root))?;

    // Topology Check - Source must be older than Target.
    if data.source.slot > data.target.slot {
        return Err(StoreError::SourceExceedsTarget);
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
pub fn on_tick(store: &mut Store, timestamp_ms: u64, has_proposal: bool, is_aggregator: bool) {
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

        // NOTE: here we assume on_tick never skips intervals
        match interval {
            0 => {
                // Start of slot - process attestations if proposal exists
                if should_signal_proposal {
                    accept_new_attestations(store);
                }
            }
            1 => {
                // Vote propagation — no action
            }
            2 => {
                // Aggregation interval
                if is_aggregator {
                    aggregate_committee_signatures(store);
                }
            }
            3 => {
                // Update safe target for validators
                update_safe_target(store);
            }
            4 => {
                // End of slot - accept accumulated attestations
                accept_new_attestations(store);
            }
            _ => unreachable!("slots only have 5 intervals"),
        }
    }
}

/// Process a gossiped attestation.
///
/// Verifies the signature, stores attestation data by root, and (if this node
/// is an aggregator) stores the gossip signature for later aggregation.
pub fn on_gossip_attestation(
    store: &mut Store,
    signed_attestation: SignedAttestation,
    is_aggregator: bool,
) -> Result<(), StoreError> {
    let validator_id = signed_attestation.validator_id;
    let attestation = Attestation {
        validator_id,
        data: signed_attestation.message,
    };
    validate_attestation_data(store, &attestation.data)
        .inspect_err(|_| metrics::inc_attestations_invalid("gossip"))?;

    let target = attestation.data.target;
    let target_state = store
        .get_state(&target.root)
        .ok_or(StoreError::MissingTargetState(target.root))?;
    if validator_id >= target_state.validators.len() as u64 {
        return Err(StoreError::InvalidValidatorIndex);
    }
    let validator_pubkey = target_state.validators[validator_id as usize]
        .get_pubkey()
        .map_err(|_| StoreError::PubkeyDecodingFailed(validator_id))?;
    let message = attestation.data.tree_hash_root();
    if cfg!(not(feature = "skip-signature-verification")) {
        use ethlambda_types::signature::ValidatorSignature;
        let epoch: u32 = attestation.data.slot.try_into().expect("slot exceeds u32");
        let signature = ValidatorSignature::from_bytes(&signed_attestation.signature)
            .map_err(|_| StoreError::SignatureDecodingFailed)?;
        if !signature.is_valid(&validator_pubkey, epoch, &message) {
            return Err(StoreError::SignatureVerificationFailed);
        }
    }

    // Store attestation data by root (content-addressed, idempotent)
    let data_root = attestation.data.tree_hash_root();
    store.insert_attestation_data_by_root(data_root, attestation.data.clone());

    if cfg!(feature = "skip-signature-verification") {
        // Without signature verification, insert directly into new aggregated payloads
        // with a dummy proof so the fork choice pipeline still sees attestations.
        let participants = aggregation_bits_from_validator_indices(&[validator_id]);
        let payload = StoredAggregatedPayload {
            slot: attestation.data.slot,
            proof: AggregatedSignatureProof::empty(participants),
        };
        store.insert_new_aggregated_payload((validator_id, data_root), payload);
    } else if is_aggregator {
        // With verification, store gossip signature for later aggregation at interval 2.
        // With ATTESTATION_COMMITTEE_COUNT=1, all validators are in the same subnet.
        let signature = ValidatorSignature::from_bytes(&signed_attestation.signature)
            .map_err(|_| StoreError::SignatureDecodingFailed)?;
        store.insert_gossip_signature(&attestation.data, validator_id, signature);
    }

    metrics::inc_attestations_valid("gossip");

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
/// covering multiple validators. We store one aggregated payload entry per
/// participating validator so the fork choice extraction works uniformly.
pub fn on_gossip_aggregated_attestation(
    store: &mut Store,
    aggregated: SignedAggregatedAttestation,
) -> Result<(), StoreError> {
    validate_attestation_data(store, &aggregated.data)
        .inspect_err(|_| metrics::inc_attestations_invalid("aggregated"))?;

    // Verify aggregated proof signature
    if cfg!(not(feature = "skip-signature-verification")) {
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
                    .get_pubkey()
                    .map_err(|_| StoreError::PubkeyDecodingFailed(vid))
            })
            .collect::<Result<_, _>>()?;

        let message = aggregated.data.tree_hash_root();
        let epoch: u32 = aggregated.data.slot.try_into().expect("slot exceeds u32");

        ethlambda_crypto::verify_aggregated_signature(
            &aggregated.proof.proof_data,
            pubkeys,
            &message,
            epoch,
        )
        .map_err(StoreError::AggregateVerificationFailed)?;
    }

    // Store attestation data by root (content-addressed, idempotent)
    let data_root = aggregated.data.tree_hash_root();
    store.insert_attestation_data_by_root(data_root, aggregated.data.clone());

    // Store one aggregated payload per participating validator
    for validator_id in aggregated.proof.participant_indices() {
        let payload = StoredAggregatedPayload {
            slot: aggregated.data.slot,
            proof: aggregated.proof.clone(),
        };
        store.insert_new_aggregated_payload((validator_id, data_root), payload);
    }

    let slot = aggregated.data.slot;
    let num_participants = aggregated.proof.participants.num_set_bits();
    info!(
        slot,
        num_participants,
        target_slot = aggregated.data.target.slot,
        target_root = %ShortRoot(&aggregated.data.target.root.0),
        source_slot = aggregated.data.source.slot,
        "Aggregated attestation processed"
    );

    metrics::inc_attestations_valid("aggregated");

    Ok(())
}

/// Process a new block and update the forkchoice state.
///
/// This method integrates a block into the forkchoice store by:
/// 1. Validating the block's parent exists
/// 2. Computing the post-state via the state transition function
/// 3. Processing attestations included in the block body (on-chain)
/// 4. Updating the forkchoice head
/// 5. Processing the proposer's attestation (as if gossiped)
pub fn on_block(
    store: &mut Store,
    signed_block: SignedBlockWithAttestation,
) -> Result<(), StoreError> {
    let _timing = metrics::time_fork_choice_block_processing();

    // Unpack block components
    let block = signed_block.message.block.clone();
    let proposer_attestation = signed_block.message.proposer_attestation.clone();
    let block_root = block.tree_hash_root();
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

    // Validate cryptographic signatures
    // TODO: extract signature verification to a pre-checks function
    // to avoid the need for this
    if cfg!(not(feature = "skip-signature-verification")) {
        verify_signatures(&parent_state, &signed_block)?;
    }

    // Execute state transition function to compute post-block state
    let mut post_state = parent_state.clone();
    ethlambda_state_transition::state_transition(&mut post_state, &block)?;

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

    // Process block body attestations.
    // Store attestation data by root and proofs in known aggregated payloads.
    for (att, proof) in aggregated_attestations
        .iter()
        .zip(attestation_signatures.iter())
    {
        let data_root = att.data.tree_hash_root();
        store.insert_attestation_data_by_root(data_root, att.data.clone());

        let validator_ids = aggregation_bits_to_validator_indices(&att.aggregation_bits);
        let payload = StoredAggregatedPayload {
            slot: att.data.slot,
            proof: proof.clone(),
        };

        for validator_id in &validator_ids {
            // Store proof in known aggregated payloads (active in fork choice)
            store.insert_known_aggregated_payload((*validator_id, data_root), payload.clone());

            metrics::inc_attestations_valid("block");
        }
    }

    // Update forkchoice head based on new block and attestations
    // IMPORTANT: This must happen BEFORE processing proposer attestation
    // to prevent the proposer from gaining circular weight advantage.
    update_head(store);

    // Process proposer attestation as pending (enters "new" stage via gossip path)
    // The proposer's attestation should NOT affect this block's fork choice position.
    let proposer_vid = proposer_attestation.validator_id;
    let proposer_data_root = proposer_attestation.data.tree_hash_root();
    store.insert_attestation_data_by_root(proposer_data_root, proposer_attestation.data.clone());

    if cfg!(feature = "skip-signature-verification") {
        // Without sig verification, insert directly with a dummy proof
        let participants = aggregation_bits_from_validator_indices(&[proposer_vid]);
        let payload = StoredAggregatedPayload {
            slot: proposer_attestation.data.slot,
            proof: AggregatedSignatureProof::empty(participants),
        };
        store.insert_new_aggregated_payload((proposer_vid, proposer_data_root), payload);
    } else {
        // Store the proposer's signature for potential future block building
        let proposer_sig =
            ValidatorSignature::from_bytes(&signed_block.signature.proposer_signature)
                .map_err(|_| StoreError::SignatureDecodingFailed)?;
        store.insert_gossip_signature(&proposer_attestation.data, proposer_vid, proposer_sig);
    }

    info!(%slot, %block_root, %state_root, "Processed new block");
    Ok(())
}

/// Calculate target checkpoint for validator attestations.
///
/// NOTE: this assumes that we have all the blocks from the head back to the latest finalized.
pub fn get_attestation_target(store: &Store) -> Checkpoint {
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

    let finalized_slot = store.latest_finalized().slot;

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
    // Ensure target is at or after the source (latest_justified) to maintain
    // the invariant: source.slot <= target.slot. When a block advances
    // latest_justified between safe_target updates (interval 2), the walk-back
    // above can land on a slot behind the new justified checkpoint.
    //
    // See https://github.com/blockblaz/zeam/blob/697c293879e922942965cdb1da3c6044187ae00e/pkgs/node/src/forkchoice.zig#L654-L659
    let latest_justified = store.latest_justified();
    if target_header.slot < latest_justified.slot {
        warn!(
            target_slot = target_header.slot,
            justified_slot = latest_justified.slot,
            "Attestation target walked behind justified source, clamping to justified"
        );
        return latest_justified;
    }

    Checkpoint {
        root: target_block_root,
        slot: target_header.slot,
    }
}

/// Produce attestation data for the given slot.
pub fn produce_attestation_data(store: &Store, slot: u64) -> AttestationData {
    // Get the head block the validator sees for this slot
    let head_checkpoint = Checkpoint {
        root: store.head(),
        slot: store
            .get_block_header(&store.head())
            .expect("head block exists")
            .slot,
    };

    // Calculate the target checkpoint for this attestation
    let target_checkpoint = get_attestation_target(store);

    // Construct attestation data
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
    on_tick(store, slot_time_ms, true, false);

    // Process any pending attestations before proposal
    accept_new_attestations(store);

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
) -> Result<(Block, Vec<AggregatedSignatureProof>), StoreError> {
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

    // Convert known aggregated payloads to Attestation objects for build_block
    let known_attestations = extract_attestations_from_aggregated_payloads(
        store,
        store.iter_known_aggregated_payloads(),
    );
    let available_attestations: Vec<Attestation> = known_attestations
        .into_iter()
        .map(|(validator_id, data)| Attestation { validator_id, data })
        .collect();

    // Get known block roots for attestation validation
    let known_block_roots = store.get_block_roots();

    // Collect existing proofs for block building from known aggregated payloads
    let aggregated_payloads: HashMap<SignatureKey, Vec<AggregatedSignatureProof>> = store
        .iter_known_aggregated_payloads()
        .map(|(key, stored_payloads)| {
            let proofs = stored_payloads.into_iter().map(|sp| sp.proof).collect();
            (key, proofs)
        })
        .collect();

    // Build the block using fixed-point attestation collection
    let (block, _post_state, signatures) = build_block(
        &head_state,
        slot,
        validator_index,
        head_root,
        &available_attestations,
        &known_block_roots,
        &aggregated_payloads,
    )?;

    Ok((block, signatures))
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
}

/// Extract validator indices from aggregation bits.
fn aggregation_bits_to_validator_indices(bits: &AggregationBits) -> Vec<u64> {
    bits.iter()
        .enumerate()
        .filter_map(|(i, bit)| if bit { Some(i as u64) } else { None })
        .collect()
}

/// Extract validator indices from aggregation bits.
fn aggregation_bits_from_validator_indices(bits: &[u64]) -> AggregationBits {
    if bits.is_empty() {
        return AggregationBits::with_capacity(0).expect("max capacity is non-zero");
    }
    let max_id = bits
        .iter()
        .copied()
        .max()
        .expect("already checked it's non-empty") as usize;
    let mut aggregation_bits =
        AggregationBits::with_capacity(max_id + 1).expect("validator count exceeds limit");

    for &vid in bits {
        aggregation_bits
            .set(vid as usize, true)
            .expect("capacity support highest validator id");
    }
    aggregation_bits
}

/// Group individual attestations by their data and create aggregated attestations.
///
/// Attestations with identical `AttestationData` are combined into a single
/// `AggregatedAttestation` with a bitfield indicating participating validators.
fn aggregate_attestations_by_data(attestations: &[Attestation]) -> Vec<AggregatedAttestation> {
    // Group attestations by their data root
    let mut groups: HashMap<H256, (AttestationData, Vec<u64>)> = HashMap::new();

    for attestation in attestations {
        let data_root = attestation.data.tree_hash_root();
        groups
            .entry(data_root)
            .or_insert_with(|| (attestation.data.clone(), Vec::new()))
            .1
            .push(attestation.validator_id);
    }

    // Convert groups into aggregated attestations
    groups
        .into_values()
        .map(|(data, validator_ids)| {
            // Find max validator id to determine bitlist capacity
            let max_id = validator_ids.iter().copied().max().unwrap_or(0) as usize;
            let mut bits =
                AggregationBits::with_capacity(max_id + 1).expect("validator count exceeds limit");

            for vid in validator_ids {
                bits.set(vid as usize, true)
                    .expect("validator id exceeds capacity");
            }

            AggregatedAttestation {
                aggregation_bits: bits,
                data,
            }
        })
        .collect()
}

/// Build a valid block on top of this state.
///
/// Returns the block, post-state, and a list of attestation signature proofs
/// (one per attestation in block.body.attestations). The proposer signature
/// proof is NOT included; it is appended by the caller.
fn build_block(
    head_state: &State,
    slot: u64,
    proposer_index: u64,
    parent_root: H256,
    available_attestations: &[Attestation],
    known_block_roots: &HashSet<H256>,
    aggregated_payloads: &HashMap<SignatureKey, Vec<AggregatedSignatureProof>>,
) -> Result<(Block, State, Vec<AggregatedSignatureProof>), StoreError> {
    // Start with empty attestation set
    let mut included_attestations: Vec<Attestation> = Vec::new();

    // Track which attestations we've already considered (by validator_id, data_root)
    let mut included_keys: HashSet<SignatureKey> = HashSet::new();

    // Fixed-point loop: collect attestations until no new ones can be added
    let _post_state = loop {
        // Aggregate attestations by data for the candidate block
        let aggregated = aggregate_attestations_by_data(&included_attestations);
        let attestations: AggregatedAttestations = aggregated
            .clone()
            .try_into()
            .expect("attestation count exceeds limit");

        // Create candidate block with current attestations (state_root is placeholder)
        let candidate_block = Block {
            slot,
            proposer_index,
            parent_root,
            state_root: H256::ZERO,
            body: BlockBody { attestations },
        };

        // Apply state transition: process_slots + process_block
        let mut post_state = head_state.clone();
        process_slots(&mut post_state, slot)?;
        process_block(&mut post_state, &candidate_block)?;

        // No attestation source provided: done after computing post_state
        if available_attestations.is_empty() || known_block_roots.is_empty() {
            break post_state;
        }

        // Find new valid attestations matching post-state requirements
        let mut new_attestations: Vec<Attestation> = Vec::new();

        for attestation in available_attestations {
            let data_root = attestation.data.tree_hash_root();
            let sig_key: SignatureKey = (attestation.validator_id, data_root);

            // Skip if target block is unknown
            if !known_block_roots.contains(&attestation.data.head.root) {
                continue;
            }

            // Skip if attestation source does not match post-state's latest justified
            if attestation.data.source != post_state.latest_justified {
                continue;
            }

            // Avoid adding duplicates of attestations already in the candidate set
            if included_keys.contains(&sig_key) {
                continue;
            }

            // Only include if we have a proof for this attestation
            if aggregated_payloads.contains_key(&sig_key) {
                new_attestations.push(attestation.clone());
                included_keys.insert(sig_key);
            }
        }

        // Fixed point reached: no new attestations found
        if new_attestations.is_empty() {
            break post_state;
        }

        // Add new attestations and continue iteration
        included_attestations.extend(new_attestations);
    };

    // Select existing proofs for the attestations to include in the block.
    let (aggregated_attestations, aggregated_signatures) =
        select_aggregated_proofs(&included_attestations, aggregated_payloads)?;

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

    // Recompute post-state with final block to get correct state root
    let mut post_state = head_state.clone();
    process_slots(&mut post_state, slot)?;
    process_block(&mut post_state, &final_block)?;

    final_block.state_root = post_state.tree_hash_root();

    Ok((final_block, post_state, aggregated_signatures))
}

/// Select existing aggregated proofs for attestations to include in a block.
///
/// Fresh gossip aggregation happens at interval 2 (`aggregate_committee_signatures`).
/// This function only selects from existing proofs in the `LatestKnownAggregatedPayloads` table
/// (proofs from previously received blocks and promoted gossip aggregations).
///
/// Returns a list of (attestation, proof) pairs ready for block inclusion.
fn select_aggregated_proofs(
    attestations: &[Attestation],
    aggregated_payloads: &HashMap<SignatureKey, Vec<AggregatedSignatureProof>>,
) -> Result<(Vec<AggregatedAttestation>, Vec<AggregatedSignatureProof>), StoreError> {
    let mut results = vec![];

    for aggregated in aggregate_attestations_by_data(attestations) {
        let data = &aggregated.data;
        let message = data.tree_hash_root();

        let validator_ids = aggregation_bits_to_validator_indices(&aggregated.aggregation_bits);
        let mut remaining: HashSet<u64> = validator_ids.into_iter().collect();

        // Select existing proofs that cover the most remaining validators
        while !remaining.is_empty() {
            let Some(&target_id) = remaining.iter().next() else {
                break;
            };

            let Some(candidates) = aggregated_payloads
                .get(&(target_id, message))
                .filter(|v| !v.is_empty())
            else {
                break;
            };

            let (proof, covered) = candidates
                .iter()
                .map(|p| {
                    let covered: Vec<_> = aggregation_bits_to_validator_indices(&p.participants)
                        .into_iter()
                        .filter(|vid| remaining.contains(vid))
                        .collect();
                    (p, covered)
                })
                .max_by_key(|(_, covered)| covered.len())
                .expect("candidates is not empty");

            // No proof covers any remaining validator
            if covered.is_empty() {
                break;
            }

            let aggregate = AggregatedAttestation {
                aggregation_bits: proof.participants.clone(),
                data: data.clone(),
            };
            results.push((aggregate, proof.clone()));

            metrics::inc_pq_sig_aggregated_signatures();
            metrics::inc_pq_sig_attestations_in_aggregated_signatures(covered.len() as u64);

            for vid in covered {
                remaining.remove(&vid);
            }
        }
    }

    Ok(results.into_iter().unzip())
}

/// Verify all signatures in a signed block.
///
/// Each attestation has a corresponding proof in the signature list.
fn verify_signatures(
    state: &State,
    signed_block: &SignedBlockWithAttestation,
) -> Result<(), StoreError> {
    use ethlambda_crypto::verify_aggregated_signature;
    use ethlambda_types::signature::ValidatorSignature;

    let block = &signed_block.message.block;
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

    // Verify each attestation's signature proof
    for (attestation, aggregated_proof) in attestations.iter().zip(attestation_signatures) {
        let validator_ids = aggregation_bits_to_validator_indices(&attestation.aggregation_bits);
        if validator_ids.iter().any(|vid| *vid >= num_validators) {
            return Err(StoreError::InvalidValidatorIndex);
        }

        let epoch: u32 = attestation.data.slot.try_into().expect("slot exceeds u32");
        let message = attestation.data.tree_hash_root();

        // Collect public keys for all participating validators
        let public_keys: Vec<_> = validator_ids
            .iter()
            .map(|&vid| {
                validators[vid as usize]
                    .get_pubkey()
                    .map_err(|_| StoreError::PubkeyDecodingFailed(vid))
            })
            .collect::<Result<_, _>>()?;

        match verify_aggregated_signature(
            &aggregated_proof.proof_data,
            public_keys,
            &message,
            epoch,
        ) {
            Ok(()) => metrics::inc_pq_sig_aggregated_signatures_valid(),
            Err(e) => {
                metrics::inc_pq_sig_aggregated_signatures_invalid();
                return Err(StoreError::AggregateVerificationFailed(e));
            }
        }
    }

    let proposer_attestation = &signed_block.message.proposer_attestation;

    let proposer_signature =
        ValidatorSignature::from_bytes(&signed_block.signature.proposer_signature)
            .map_err(|_| StoreError::ProposerSignatureDecodingFailed)?;

    let proposer = validators
        .get(block.proposer_index as usize)
        .ok_or(StoreError::InvalidValidatorIndex)?;

    let proposer_pubkey = proposer
        .get_pubkey()
        .map_err(|_| StoreError::PubkeyDecodingFailed(proposer.index))?;

    let epoch = proposer_attestation
        .data
        .slot
        .try_into()
        .expect("slot exceeds u32");
    let message = proposer_attestation.data.tree_hash_root();

    if !proposer_signature.is_valid(&proposer_pubkey, epoch, &message) {
        return Err(StoreError::ProposerSignatureVerificationFailed);
    }
    Ok(())
}

/// Check if a head change represents a reorg.
///
/// A reorg occurs when the chains diverge - i.e., when walking back from the higher
/// slot head to the lower slot head's slot, we don't arrive at the lower slot head.
fn is_reorg(old_head: H256, new_head: H256, store: &Store) -> bool {
    if new_head == old_head {
        return false;
    }

    let Some(old_head_header) = store.get_block_header(&old_head) else {
        return false;
    };

    let Some(new_head_header) = store.get_block_header(&new_head) else {
        return false;
    };

    let old_slot = old_head_header.slot;
    let new_slot = new_head_header.slot;

    // Determine which head has the higher slot and walk back from it
    let (mut current_root, target_slot, target_root) = if new_slot >= old_slot {
        (new_head, old_slot, old_head)
    } else {
        (old_head, new_slot, new_head)
    };

    // Walk back through the chain until we reach the target slot
    while let Some(current_header) = store.get_block_header(&current_root) {
        if current_header.slot <= target_slot {
            // We've reached the target slot - check if we're at the target block
            return current_root != target_root;
        }
        current_root = current_header.parent_root;
    }

    // Couldn't walk back far enough (missing blocks in chain)
    // Assume the ancestor is behind the latest finalized block
    false
}
