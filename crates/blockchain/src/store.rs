use std::collections::{HashMap, HashSet};

use ethlambda_crypto::signature::{ValidatorPublicKey, ValidatorSignature};
use ethlambda_state_transition::{
    effective_heartbeat_committee_size, is_heartbeat_committee_member, is_proposer,
};
use ethlambda_storage::{ForkCheckpoints, Store};
use ethlambda_types::{
    ShortRoot,
    attestation::{
        Attestation, AttestationData, HashedAttestationData, SignedAggregatedAttestation,
        SignedAttestation, validator_indices,
    },
    block::{Block, BlockBody, BlockHeader, SignedBlock, SingleMessageAggregate},
    checkpoint::Checkpoint,
    primitives::{H256, HashTreeRoot as _},
    state::{HISTORICAL_ROOTS_LIMIT, State},
};
use tracing::{info, trace, warn};

use crate::{
    GOSSIP_DISPARITY_INTERVALS, INTERVALS_PER_SLOT, MAX_ATTESTATIONS_DATA,
    MILLISECONDS_PER_INTERVAL, MILLISECONDS_PER_SLOT, RLMD_LOOKBACK_LIMIT, SlotInterval,
    block_builder::{BlockTarget, PostBlockCheckpoints, ProposerConfig, build_block},
    metrics,
};

const JUSTIFICATION_LOOKBACK_SLOTS: u64 = 3;

/// Extract the heartbeat committee votes a block carries for its predecessor slot.
///
/// A block for slot `T` carries slot-`T-1` committee bits: the view-merge payload
/// the next fast head is computed from. The gate is `data.slot == T - 1`
/// *strictly* — no window, no fallback to an earlier slot when slots were
/// skipped. That makes this an exact mirror of the packer's `Tier::Heartbeat`
/// gate, so "which slot's committee bits does this block carry" has exactly one
/// answer and never needs reconciling. Degrading on a missed slot is the fast
/// head's job, via its expanding fallback, not the packer's or this function's.
///
/// This is a plain read of the body: no proofs, no filters, no cap. In particular
/// it must **not** reuse [`crate::reaggregate`]'s candidate selection, whose
/// filters (drop attestations whose target is already justified, skip
/// participants already covered locally, truncate to a per-block maximum) are
/// right for deciding what is worth a SNARK split and wrong for fork choice: the
/// fast head needs the `head` field of every committee vote regardless of whether
/// its target is already justified.
///
/// Kept standalone over `(body, slot, n, committee_size)` so the restart replay
/// path can run the identical extraction over blocks read back from the database.
pub fn extract_heartbeat_votes(
    body: &BlockBody,
    block_slot: u64,
    num_validators: u64,
    committee_size: u64,
) -> Vec<(u64, AttestationData)> {
    // Slot 0 has no predecessor, so a genesis-adjacent block carries nothing.
    let Some(cttee_slot) = block_slot.checked_sub(1) else {
        return Vec::new();
    };

    let mut votes = Vec::new();
    for entry in body.attestations.iter() {
        if entry.data.slot != cttee_slot {
            continue;
        }
        for validator_id in validator_indices(&entry.aggregation_bits) {
            if is_heartbeat_committee_member(
                validator_id,
                cttee_slot,
                num_validators,
                committee_size,
            ) {
                votes.push((validator_id, entry.data.clone()));
            }
        }
    }
    votes
}

/// Rebuild the heartbeat vote set from the last [`RLMD_LOOKBACK_LIMIT`] blocks
/// on disk.
///
/// `votes_per_slot`, `known_payloads` and the signature buffers are all
/// in-memory, so without this a restart blinds fork choice: `fast_head` finds
/// nothing, expands to the full window, and collapses to `lagging_head`, which
/// has no heartbeat evidence of its own either. Replaying the window makes a
/// restart deterministic instead of "recovers after a few slots".
///
/// Cheap: at most `RLMD_LOOKBACK_LIMIT` blocks, each contributing at most `K'`
/// votes, and no new storage. Runs the identical extraction the live import path
/// uses, which is why [`extract_heartbeat_votes`] is factored out.
pub fn replay_heartbeat_votes(store: &Store) {
    let mut root = store.head().expect("head block exists");
    let committee_size = store.heartbeat_committee_size();
    let mut replayed = 0usize;

    for _ in 0..RLMD_LOOKBACK_LIMIT {
        let Some(block) = store.get_block(&root).expect("block read should succeed") else {
            break;
        };
        // The anchor block has no parent to walk to, and a slot-0 block carries
        // no predecessor committee.
        if block.slot == 0 {
            break;
        }

        // Registry as of the committee's own slot: the parent state is the
        // closest state at or before `block.slot - 1`. Fall back to the head
        // state when the parent predates the anchor (checkpoint-synced node).
        let num_validators = store
            .get_state(&block.parent_root)
            .expect("state read should succeed")
            .map_or_else(
                || store.head_state().validators.len() as u64,
                |state| state.validators.len() as u64,
            );

        for (validator_id, data) in
            extract_heartbeat_votes(&block.body, block.slot, num_validators, committee_size)
        {
            store.insert_heartbeat_vote(validator_id, data);
            replayed += 1;
        }

        root = block.parent_root;
    }

    if replayed > 0 {
        info!(
            replayed,
            window_slots = RLMD_LOOKBACK_LIMIT,
            "Replayed heartbeat votes from stored blocks"
        );
    }
}

/// Merge a block's heartbeat votes into the store's vote set.
///
/// A union, not a replacement: `insert_heartbeat_vote` is last-write-wins per
/// `(slot, validator)`, so the block's copy overwrites a gossip copy for the same
/// validator while validators present only via gossip keep theirs. Convergence
/// comes from the proposer's set normally *dominating* — it had a full interval to
/// collect — not from discarding local votes.
fn merge_heartbeat_votes(store: &Store, body: &BlockBody, block_slot: u64, num_validators: u64) {
    let votes = extract_heartbeat_votes(
        body,
        block_slot,
        num_validators,
        store.heartbeat_committee_size(),
    );
    metrics::observe_heartbeat_votes_in_block(votes.len());
    for (validator_id, data) in votes {
        store.insert_heartbeat_vote(validator_id, data);
        metrics::inc_heartbeat_votes_received(metrics::HeartbeatVoteSource::Block);
    }
}

/// Intermediate fork-choice data produced by [`update_head`], carried so the
/// fork choice tree can be rendered without recomputing LMD GHOST.
pub struct HeadUpdate {
    blocks: HashMap<H256, (u64, H256)>,
    weights: HashMap<H256, u64>,
    head: H256,
}

/// Log an ASCII fork choice tree to the terminal, reusing the weights and
/// block set already computed by [`update_head`].
fn log_fork_choice_tree(store: &Store, update: &HeadUpdate) {
    let tree = crate::fork_choice_tree::format_fork_choice_tree(
        &update.blocks,
        &update.weights,
        update.head,
        store
            .latest_justified()
            .expect("latest justified checkpoint exists"),
        store
            .latest_finalized()
            .expect("latest finalized checkpoint exists"),
    );
    info!("\n{tree}");
}

/// Accept new aggregated payloads, promoting them to known for fork choice.
fn accept_new_attestations(store: &mut Store) -> HeadUpdate {
    store.promote_new_aggregated_payloads();
    metrics::update_latest_new_aggregated_payloads(store.new_aggregated_payloads_count());
    metrics::update_latest_known_aggregated_payloads(store.known_aggregated_payloads_count());
    update_head(store)
}

/// Update the fast head (the store head) via GHOST-Eph over the previous slot's
/// heartbeat committee votes.
///
/// Rooted at [`update_lagging_head`]'s output rather than at the justified
/// checkpoint, so the two-tier structure is explicit: the lagging head is the
/// tree base the full validator set backs, and the fast head is the fast-moving
/// tip chosen within it.
///
/// `min_score = 0` is easy to misread. The GHOST walk descends while the current
/// head has *any* child, picking `max_by_key(weight, root)`, so a freshly
/// proposed block with zero votes still becomes head as long as it is the only
/// child. The previous slot's committee votes do not *authorise* extension; they
/// only break ties between competing branches. That is exactly what view-merge
/// protects: without it, two nodes seeing different gossip could break the same
/// tie differently.
///
/// Returns the block set, block weights, and new head computed during the
/// update so callers can render the fork choice tree without recomputing it.
pub fn update_head(store: &mut Store) -> HeadUpdate {
    let blocks = store
        .get_live_chain()
        .expect("get_live_chain should succeed");
    let old_head = store.head().expect("head block exists");
    let base = store.lagging_head().expect("lagging head exists");

    // GHOST-Eph: the previous slot's committee votes, which the current slot's
    // block just delivered. The window widens on an empty slot (see
    // `heartbeat_votes_expanding_back`); after RLMD_LOOKBACK_LIMIT slots of
    // nothing it is empty and the fast head collapses to `base`.
    let (attestations, window_slots) =
        store.heartbeat_votes_expanding_back(store.current_slot(), RLMD_LOOKBACK_LIMIT);
    metrics::observe_fast_head_window_slots(window_slots);

    let (new_head, weights) =
        ethlambda_fork_choice::compute_lmd_ghost_head(base, &blocks, &attestations, 0);
    if let Some(depth) = reorg_depth(old_head, new_head, store) {
        metrics::inc_fork_choice_reorgs();
        metrics::observe_fork_choice_reorg_depth(depth);
        info!(%old_head, %new_head, depth, "Fork choice reorg detected");
    }

    // Override the store's latest finalized with the head state's
    let finalized = store
        .get_state(&new_head)
        .expect("head state exists")
        .map(|state| state.latest_finalized)
        .filter(|finalized| {
            store
                .get_block_header(&finalized.root)
                .expect("block header exists")
                .is_some()
        });
    store
        .update_checkpoints(ForkCheckpoints::new(new_head, None, finalized))
        .expect("update_checkpoints should succeed");

    if old_head != new_head {
        let old_slot = store
            .get_block_header(&old_head)
            .expect("block header exists")
            .map(|h| h.slot)
            .unwrap_or(0);
        let new_slot = store
            .get_block_header(&new_head)
            .expect("block header exists")
            .map(|h| h.slot)
            .unwrap_or(0);
        let justified_slot = store
            .latest_justified()
            .expect("latest justified checkpoint exists")
            .slot;
        let finalized_slot = store
            .latest_finalized()
            .expect("latest finalized checkpoint exists")
            .slot;
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

    HeadUpdate {
        blocks,
        weights,
        head: new_head,
    }
}

/// Update the lagging head: the RLMD-window tree base the fast head sits on.
///
/// Recency-latest-message-driven, so it reads the latest message per validator
/// over the half-open window `[S - N, S)` — excluding the current slot,
/// including `S - 1`. The fast head's slot-`S-1` votes are therefore a subset of
/// this window; that overlap is intended.
///
/// Both vote pools are merged. `min_score = ceil(2n/3)` is denominated in the
/// full validator set, so the heartbeat pool alone could never reach it: the
/// aggregate pool is what carries full-set weight, and dropping it would pin the
/// lagging head to `latest_justified` forever.
fn update_lagging_head(store: &mut Store) {
    let current_slot = store.current_slot();
    let window = current_slot.saturating_sub(RLMD_LOOKBACK_LIMIT)..current_slot;
    let attestations = store.latest_message_per_validator(window);

    let num_validators = store.head_state().validators.len() as u64;
    let min_target_score = (2 * num_validators).div_ceil(3);

    let blocks = store
        .get_live_chain()
        .expect("get_live_chain should succeed");
    let (lagging_head, _weights) = ethlambda_fork_choice::compute_lmd_ghost_head(
        store
            .latest_justified()
            .expect("latest justified checkpoint exists")
            .root,
        &blocks,
        &attestations,
        min_target_score,
    );
    store
        .set_lagging_head(lagging_head)
        .expect("set_lagging_head should succeed");
}

/// Update the safe target for attestation.
///
/// Safe target is an *availability* signal, not a durable-knowledge signal, and
/// under the heartbeat design it is backed by the committee rather than the full
/// validator set. Two properties differ deliberately from the other two
/// fork-choice values:
///
/// - **Current slot only.** No RLMD window, no expanding fallback. Its whole
///   purpose is to say "this branch is backed *right now*", so evidence from
///   slot `S-1` or earlier is not merely unhelpful, it is wrong: it would hold
///   the clamp open on a branch the current committee has stopped voting for.
///   Block import writes slot-`S-1` votes into the same store, so restricting to
///   the current slot is also what keeps the block-merged copies out.
/// - **3/4 of the committee, not 2/3.** At `K' = 16` the formulas separate
///   (`ceil(2K'/3)` is 11, `ceil(3K'/4)` is 12). The clamp gates what every
///   validator is allowed to target, so it asks for a strict supermajority.
///
/// When no branch clears the threshold, `compute_lmd_ghost_head` returns
/// `start_root`, so the safe target falls back to `latest_justified` and the
/// clamp degrades to "target the justified checkpoint" rather than doing
/// something surprising. See leanSpec PR #680.
fn update_safe_target(store: &mut Store) {
    let attestations = store.heartbeat_votes_at(store.current_slot());

    let num_validators = store.head_state().validators.len() as u64;
    let committee_size =
        effective_heartbeat_committee_size(store.heartbeat_committee_size(), num_validators);
    metrics::update_heartbeat_committee_size(committee_size);
    let min_target_score = (3 * committee_size).div_ceil(4);

    let blocks = store
        .get_live_chain()
        .expect("get_live_chain should succeed");
    let (safe_target, _weights) = ethlambda_fork_choice::compute_lmd_ghost_head(
        store
            .latest_justified()
            .expect("latest justified checkpoint exists")
            .root,
        &blocks,
        &attestations,
        min_target_score,
    );
    store
        .set_safe_target(safe_target)
        .expect("set_safe_target should succeed");
}

/// Return whether `ancestor` lies on `descendant`'s parent chain.
///
/// `descendant_header` is the descendant's already-fetched header, so the walk
/// starts from its parent without re-reading it. Walks parent links down to the
/// ancestor's slot. Empty (skipped) slots on the path are traversed transparently
/// since they carry no block. A block missing from the store yields `false`.
fn checkpoint_is_ancestor(
    store: &Store,
    ancestor: &Checkpoint,
    descendant: &Checkpoint,
    descendant_header: &BlockHeader,
) -> bool {
    if ancestor.slot >= descendant.slot {
        // Equal slot: a checkpoint is its own ancestor only if the roots match.
        // Greater: the ancestor cannot sit below the descendant in the chain.
        return ancestor.slot == descendant.slot && ancestor.root == descendant.root;
    }

    // The descendant header is already in hand, so begin the walk at its parent.
    let mut current_root = descendant_header.parent_root;
    while let Some(current_header) = store
        .get_block_header(&current_root)
        .expect("parent block exists")
    {
        if current_header.slot == ancestor.slot {
            return current_root == ancestor.root;
        }
        if current_header.slot < ancestor.slot {
            return false;
        }
        current_root = current_header.parent_root;
    }

    false
}

/// Validate incoming attestation before processing.
///
/// Ensures the vote respects the basic laws of time and topology:
///     1. The blocks voted for must exist in our store.
///     2. A vote cannot span backwards in time (source > target).
///     3. The head must be at least as recent as source and target.
///     4. Checkpoint slots must match the actual block slots.
///     5. Source, target, and head must lie on one parent chain.
///     6. The vote's slot cannot precede the slot of the head it claims to have seen.
///     7. The vote's slot must have started locally (a small disparity margin is allowed).
fn validate_attestation_data(store: &Store, data: &AttestationData) -> Result<(), StoreError> {
    let _timing = metrics::time_attestation_validation();

    // Availability Check - We cannot count a vote if we haven't seen the blocks involved.
    let source_header = store
        .get_block_header(&data.source.root)
        .expect("source block exists")
        .ok_or(StoreError::UnknownSourceBlock(data.source.root))?;
    let target_header = store
        .get_block_header(&data.target.root)
        .expect("target block exists")
        .ok_or(StoreError::UnknownTargetBlock(data.target.root))?;

    let head_header = store
        .get_block_header(&data.head.root)
        .expect("head block exists")
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

    // Ancestry Check - Source, target, and head must lie on one parent chain.
    //
    // Fork-choice weight accrues to every ancestor of the attested head. A sibling
    // head would steer that weight onto a non-canonical branch, so reject a vote
    // whose checkpoints are slot-ordered but not actually on the same chain.
    if !checkpoint_is_ancestor(store, &data.source, &data.target, &target_header) {
        return Err(StoreError::SourceNotAncestorOfTarget);
    }
    if !checkpoint_is_ancestor(store, &data.target, &data.head, &head_header) {
        return Err(StoreError::TargetNotAncestorOfHead);
    }

    // Finalized-Ancestor Check - Fork choice only ever descends from the latest
    // finalized block, so a vote whose head sits on a branch orphaned by
    // finalization carries no weight. Rejecting it here stops a stale vote from
    // re-entering the pools after finalization pruning has dropped it. This is
    // sound because the store's finalized checkpoint is re-derived from the head
    // on each update, so it is always an ancestor of the head. See leanSpec #1179.
    let finalized = store
        .latest_finalized()
        .expect("latest finalized checkpoint exists");
    if !checkpoint_is_ancestor(store, &finalized, &data.head, &head_header) {
        return Err(StoreError::HeadNotDescendantOfFinalized {
            head_root: data.head.root,
            head_slot: data.head.slot,
            finalized_root: finalized.root,
            finalized_slot: finalized.slot,
        });
    }

    // Head Consistency Check - A vote cannot have observed its head before that
    // head existed, so the vote's slot must not precede the head block's slot.
    if data.slot < data.head.slot {
        return Err(StoreError::AttestationSlotBeforeHead {
            attestation_slot: data.slot,
            head_slot: data.head.slot,
        });
    }

    // Time Check - Honest validators emit votes only after their slot has begun.
    // Allow a small disparity margin for clock skew between peers.
    //
    // The bound is in intervals, not slots: a whole-slot margin would let an
    // adversary pre-publish next-slot aggregates ahead of any honest validator.
    let attestation_start_interval = data.slot.saturating_mul(INTERVALS_PER_SLOT);
    if attestation_start_interval > store.time().unwrap() + GOSSIP_DISPARITY_INTERVALS {
        return Err(StoreError::AttestationTooFarInFuture {
            attestation_slot: data.slot,
            store_time: store.time().unwrap(),
        });
    }

    Ok(())
}

/// Process a tick event.
///
/// `store.time()` represents interval-count-since-genesis: each increment is one
/// [`MILLISECONDS_PER_INTERVAL`] interval. Slot and interval-within-slot are
/// derived as:
///   slot     = store.time() / INTERVALS_PER_SLOT
///   interval = store.time() % INTERVALS_PER_SLOT
pub fn on_tick(store: &mut Store, timestamp_ms: u64, has_proposal: bool) {
    // Convert UNIX timestamp (ms) to interval count since genesis
    let genesis_time_ms = store.config().unwrap().genesis_time * 1000;
    let time_delta_ms = timestamp_ms.saturating_sub(genesis_time_ms);
    let time = time_delta_ms / MILLISECONDS_PER_INTERVAL;

    // If we're more than a slot behind, fast-forward to a slot before.
    // Operations are idempotent, so this should be fine.
    if time.saturating_sub(store.time().unwrap()) > INTERVALS_PER_SLOT {
        store
            .set_time(time - INTERVALS_PER_SLOT)
            .expect("set_time should succeed");
    }

    while store.time().unwrap() < time {
        store
            .set_time(store.time().unwrap() + 1)
            .expect("set_time should succeed");

        let slot = store.time().unwrap() / INTERVALS_PER_SLOT;
        let interval = SlotInterval::from_intervals_since_genesis(store.time().unwrap());

        trace!(%slot, ?interval, "processing tick");

        // has_proposal is only signaled for the final tick (matching Python spec behavior)
        let is_final_tick = store.time().unwrap() == time;
        let should_signal_proposal = has_proposal && is_final_tick;

        // NOTE: here we assume on_tick never skips intervals.
        // Committee-signature aggregation is not handled here: the blockchain
        // actor orchestrates the aggregation worker directly so the actor's
        // message loop stays unblocked during the expensive XMSS proofs. See
        // `BlockChainServer::start_aggregation_session` in `lib.rs`.
        match interval {
            SlotInterval::BlockPublication => {
                // Start of slot - process attestations if proposal exists
                if should_signal_proposal {
                    accept_new_attestations(store);
                }
            }
            SlotInterval::AttestationProduction => {
                // Vote propagation — no action
            }
            SlotInterval::SafeTargetUpdate => {
                // Update safe target for validators
                update_safe_target(store);
            }
            SlotInterval::HeadUpdate => {
                // Recompute the tree base from the RLMD window, then the fast
                // head on top of it, before promoting this slot's payloads and
                // logging the resulting tree.
                update_lagging_head(store);
                let update = accept_new_attestations(store);
                log_fork_choice_tree(store, &update);
            }
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
        .expect("target state exists")
        .ok_or(StoreError::MissingTargetState(target.root))?;
    if validator_id >= target_state.validators.len() as u64 {
        return Err(StoreError::InvalidValidatorIndex);
    }
    let validator_pubkey = ValidatorPublicKey::from_bytes(
        &target_state.validators[validator_id as usize].attestation_pubkey,
    )
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

    metrics::inc_attestations_valid();

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

/// Process a vote received on the global heartbeat topic.
///
/// Validation, in order:
///
/// 1. The existing topology / time / availability checks on the data.
/// 2. XMSS verification against the validator's attestation pubkey in the state
///    at `data.slot`.
/// 3. Committee membership at `data.slot`. Without this the topic is an
///    unmetered global attestation firehose.
/// 4. `data.slot == current_slot` (within the gossip disparity margin).
///    Heartbeat votes are only useful in-slot; older ones arrive via blocks.
///
/// On acceptance both the `AttestationData` and the raw signature are stored
/// **unconditionally** — not gated on `is_aggregator`. A proposer that is not a
/// committee aggregator still has to fold these signatures into its block, and it
/// is at most `K'` signatures per slot.
pub fn on_gossip_heartbeat_attestation(
    store: &mut Store,
    signed_attestation: &SignedAttestation,
) -> Result<(), StoreError> {
    let validator_id = signed_attestation.validator_id;
    let data = signed_attestation.data.clone();

    validate_attestation_data(store, &data).inspect_err(|_| metrics::inc_attestations_invalid())?;

    // Heartbeat votes are in-slot only. Reject anything not for the current slot,
    // allowing the same one-interval skew margin the data time check uses.
    let current_slot = store.current_slot();
    let slot_start_interval = data.slot.saturating_mul(INTERVALS_PER_SLOT);
    let too_old = data.slot < current_slot;
    let too_new = slot_start_interval > store.time().unwrap() + GOSSIP_DISPARITY_INTERVALS;
    if too_old || too_new {
        metrics::inc_attestations_invalid();
        return Err(StoreError::HeartbeatVoteOutOfSlot {
            attestation_slot: data.slot,
            current_slot,
        });
    }

    let hashed = HashedAttestationData::new(data.clone());
    let data_root = hashed.root();

    // The state at the vote's own slot decides both the pubkey and the committee,
    // so both reads agree by construction. `target.root`'s state is the closest
    // available state at or before `data.slot`; only empty slots can lie between,
    // so the registry is identical.
    let target_state = store
        .get_state(&data.target.root)
        .expect("target state exists")
        .ok_or(StoreError::MissingTargetState(data.target.root))?;
    let num_validators = target_state.validators.len() as u64;
    if validator_id >= num_validators {
        return Err(StoreError::InvalidValidatorIndex);
    }

    if !is_heartbeat_committee_member(
        validator_id,
        data.slot,
        num_validators,
        store.heartbeat_committee_size(),
    ) {
        metrics::inc_attestations_invalid();
        return Err(StoreError::NotHeartbeatCommitteeMember {
            validator_id,
            slot: data.slot,
        });
    }

    let validator_pubkey = ValidatorPublicKey::from_bytes(
        &target_state.validators[validator_id as usize].attestation_pubkey,
    )
    .map_err(|_| StoreError::PubkeyDecodingFailed(validator_id))?;

    let slot_u32: u32 = data.slot.try_into().expect("slot exceeds u32");
    let signature = ValidatorSignature::from_bytes(&signed_attestation.signature)
        .map_err(|_| StoreError::SignatureDecodingFailed)?;
    let is_valid = {
        let _timing = metrics::time_pq_sig_attestation_verification();
        signature.is_valid(&validator_pubkey, slot_u32, &data_root)
    };
    if !is_valid {
        metrics::inc_pq_sig_attestation_signatures_invalid();
        return Err(StoreError::SignatureVerificationFailed);
    }
    metrics::inc_pq_sig_attestation_signatures_valid();

    store.insert_heartbeat_vote(validator_id, data.clone());
    store.insert_heartbeat_signature(data.slot, data_root, validator_id, signature);
    metrics::inc_heartbeat_votes_received(metrics::HeartbeatVoteSource::Gossip);
    metrics::update_heartbeat_committee_participation(
        store.heartbeat_voter_count_at(data.slot) as u64
    );

    info!(
        slot = data.slot,
        validator = validator_id,
        target_slot = data.target.slot,
        target_root = %ShortRoot(&data.target.root.0),
        source_slot = data.source.slot,
        source_root = %ShortRoot(&data.source.root.0),
        "Heartbeat attestation processed"
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
    on_gossip_aggregated_attestation_core(store, aggregated, true)
}

/// Process a gossiped aggregated attestation WITHOUT verifying its proof.
///
/// Only for spec tests whose fixtures carry mocked (placeholder) proofs
/// (`proofSetting == 0`); production paths must use
/// [`on_gossip_aggregated_attestation`].
pub fn on_gossip_aggregated_attestation_without_verification(
    store: &mut Store,
    aggregated: SignedAggregatedAttestation,
) -> Result<(), StoreError> {
    on_gossip_aggregated_attestation_core(store, aggregated, false)
}

fn on_gossip_aggregated_attestation_core(
    store: &mut Store,
    aggregated: SignedAggregatedAttestation,
    verify: bool,
) -> Result<(), StoreError> {
    validate_attestation_data(store, &aggregated.data)
        .inspect_err(|_| metrics::inc_attestations_invalid())?;

    let target_state = store
        .get_state(&aggregated.data.target.root)
        .expect("target state exists")
        .ok_or(StoreError::MissingTargetState(aggregated.data.target.root))?;
    let validators = &target_state.validators;
    let num_validators = validators.len() as u64;

    let participant_indices: Vec<u64> = aggregated.proof.participant_indices().collect();
    if participant_indices.is_empty() {
        return Err(StoreError::EmptyAggregationBits);
    }
    if participant_indices.iter().any(|&vid| vid >= num_validators) {
        return Err(StoreError::InvalidValidatorIndex);
    }

    let pubkeys: Vec<_> = participant_indices
        .iter()
        .map(|&vid| {
            ValidatorPublicKey::from_bytes(&validators[vid as usize].attestation_pubkey)
                .map_err(|_| StoreError::PubkeyDecodingFailed(vid))
        })
        .collect::<Result<_, _>>()?;

    let hashed = HashedAttestationData::new(aggregated.data.clone());
    let data_root = hashed.root();
    let slot: u32 = aggregated.data.slot.try_into().expect("slot exceeds u32");

    if verify {
        let _timing = metrics::time_pq_sig_aggregated_signatures_verification();
        ethlambda_crypto::verify_aggregated_signature(
            &aggregated.proof.proof,
            pubkeys,
            &data_root,
            slot,
        )
        .map_err(StoreError::AggregateVerificationFailed)?;
    }

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

    metrics::inc_attestations_valid();

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
/// When `verify` is true, cryptographic signatures are verified.
/// When false, all signature checks are skipped.
fn on_block_core(
    store: &mut Store,
    signed_block: SignedBlock,
    verify: bool,
) -> Result<(), StoreError> {
    let timing = metrics::time_fork_choice_block_processing();
    let block_start = std::time::Instant::now();

    let block = &signed_block.message;
    let block_root = block.hash_tree_root();
    let slot = block.slot;

    // Skip duplicate blocks (idempotent operation)
    if store
        .has_state(&block_root)
        .expect("DB read should succeed")
    {
        timing.discard();
        return Ok(());
    }

    // Verify parent state is available
    // Note: Parent block existence is checked by the caller before calling this function.
    // This check ensures the state has been computed for the parent block.
    let parent_state = store
        .get_state(&block.parent_root)
        .expect("DB read should succeed")
        .ok_or(StoreError::MissingParentState {
            parent_root: block.parent_root,
            slot,
        })?;

    // Bound the block's slot before the state transition runs (leanSpec #1182).
    //
    // The transition advances the state one slot at a time from the parent up to
    // `block.slot`, so a block far beyond its parent, or far in the future, would
    // drive that walk unboundedly. Both guards live here at the untrusted-input
    // boundary and run before the expensive signature verification, so a crafted
    // block is rejected cheaply.
    let slot_gap = slot.saturating_sub(parent_state.slot);
    if slot_gap > HISTORICAL_ROOTS_LIMIT as u64 {
        return Err(StoreError::BlockSlotGapTooLarge {
            gap: slot_gap,
            max: HISTORICAL_ROOTS_LIMIT as u64,
        });
    }
    // Horizon is the current slot plus one whole slot of margin, so an intended
    // early block still imports (mirrors the attestation future-slot guard, but
    // with a whole-slot rather than one-interval margin).
    let current_slot = store.time().expect("DB read should succeed") / INTERVALS_PER_SLOT;
    if slot > current_slot + 1 {
        return Err(StoreError::BlockTooFarInFuture {
            block_slot: slot,
            current_slot,
        });
    }

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

    // Registry size as of the committee's own slot. The parent state is the
    // closest state at or before `block.slot - 1`, and only empty slots can lie
    // between them, so the registry cannot have changed in the gap. Captured
    // before `parent_state` is consumed by the state transition.
    let cttee_num_validators = parent_state.validators.len() as u64;

    // Execute state transition function to compute post-block state
    let state_transition_start = std::time::Instant::now();
    let mut post_state = parent_state;
    ethlambda_state_transition::state_transition(&mut post_state, &block)?;
    let state_transition = state_transition_start.elapsed();

    // Cache the state root in the latest block header
    let state_root = block.state_root;
    post_state.latest_block_header.state_root = state_root;

    // Advance the justified checkpoint when the post-state names a higher one
    // (leanSpec `advance_to`: monotonic by slot). Finalized is intentionally not
    // latched here; it is recomputed from the head's chain in `update_head`.
    let justified = (post_state.latest_justified.slot > store.latest_justified().unwrap().slot)
        .then_some(post_state.latest_justified);

    if let Some(justified) = justified {
        store
            .update_checkpoints(ForkCheckpoints::new(
                store.head().unwrap(),
                Some(justified),
                None,
            ))
            .expect("update_checkpoints should succeed");
    }

    // Store signed block and state
    store
        .insert_signed_block(block_root, signed_block.clone())
        .expect("DB insert should succeed");
    store
        .insert_state(block_root, post_state)
        .expect("DB insert should succeed");

    // Block-included attestations are intentionally not counted here.
    // `lean_attestations_valid_total` tracks the gossip validation pipeline
    // (symmetric with `inc_attestations_invalid`), matching leanSpec. Votes
    // arriving inside a block are counted by
    // `lean_state_transition_attestations_processed_total` instead.

    // View-merge: fold the block's slot-(T-1) committee bits into the heartbeat
    // vote set before fork choice reads it. After the STF (so a rejected block
    // never contributes) and before `update_head` (so this slot's fast head sees
    // the payload the proposer just delivered).
    merge_heartbeat_votes(store, &block.body, slot, cttee_num_validators);

    // Update forkchoice head based on new block and attestations
    update_head(store);

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
        store.latest_justified().unwrap(),
        store.latest_finalized().unwrap(),
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
/// post-state justified for the clamping guard.
pub fn get_attestation_target_with_checkpoints(
    store: &Store,
    justified: Checkpoint,
    // Unused under the simple BFT finality condition: every slot is justifiable
    // now, so the target no longer needs a justifiability walk-back. Kept on the
    // signature because callers resolve both checkpoints from the same
    // post-state and the pair reads as one unit.
    _finalized: Checkpoint,
) -> Checkpoint {
    // Start from current head
    let mut target_block_root = store.head().unwrap();
    let mut target_header = store
        .get_block_header(&target_block_root)
        .expect("head block exists")
        .unwrap();

    let safe_target_block_slot = store
        .get_block_header(&store.safe_target().unwrap())
        .expect("safe target exists")
        .unwrap()
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
                .expect("parent block exists")
                .unwrap();
        } else {
            break;
        }
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
/// The source is the **head state's** latest justified checkpoint, which always
/// lies on the head's own chain. This deliberately diverges from leanSpec, which
/// sources from the store's global `latest_justified` (see
/// <https://github.com/leanEthereum/leanSpec/pull/595>).
///
/// The store's justified is a highest-slot-wins maximum that can latch onto an
/// off-head sibling justified by a minority fork. Voting with such an off-chain
/// source makes every head-chain target fail `is_valid_vote` (the target no
/// longer descends from the source), so the head can never re-justify and block
/// production stalls. Sourcing from the head state keeps the source and target
/// on the same chain, letting justification advance again.
///
/// The target walk-back is fed the same head-state justified so its clamp guard
/// stays consistent with the source we emit.
///
/// Matches leanSpec PR #1166, including its genesis handling: the raw genesis
/// state carries a zero-root justified placeholder that the state transition
/// rebases to the real genesis root on the first block. A vote cast directly on
/// the genesis head normalizes the placeholder the same way, so the source
/// always names a real block (otherwise `validate_attestation_data` rejects it
/// with `UnknownSourceBlock`).
pub fn produce_attestation_data(store: &Store, slot: u64) -> AttestationData {
    let head_root = store.head().unwrap();
    let mut source = store
        .get_state(&head_root)
        .expect("head state exists")
        .unwrap()
        .latest_justified;

    // Replace the placeholder genesis root with the real (head) one. This only
    // fires on the genesis head, whose state still holds the zero-root
    // placeholder; after the first block the root is already rebased.
    if source.root == H256::ZERO {
        source.root = head_root;
    }

    let head_checkpoint = Checkpoint {
        root: head_root,
        slot: store
            .get_block_header(&head_root)
            .expect("head block exists")
            .unwrap()
            .slot,
    };

    let target_checkpoint = get_attestation_target(store);

    AttestationData {
        slot,
        head: head_checkpoint,
        target: target_checkpoint,
        source,
    }
}

/// Get the head for block proposal at the given slot.
///
/// Ensures store is up-to-date and processes any pending attestations
/// before returning the canonical head.
fn get_proposal_head(store: &mut Store, slot: u64) -> H256 {
    // Calculate time corresponding to this slot
    let slot_time_ms =
        store.config().expect("config exists").genesis_time * 1000 + slot * MILLISECONDS_PER_SLOT;

    // Advance time to current slot (ticking intervals)
    on_tick(store, slot_time_ms, true);

    // Process any pending attestations before proposal
    accept_new_attestations(store);

    store.head().expect("store head exists")
}

/// Produce a block and per-aggregated-attestation signature payloads for the target slot.
///
/// Returns the finalized block and attestation signature payloads aligned
/// with `block.body.attestations`.
pub fn produce_block_with_signatures(
    store: &mut Store,
    slot: u64,
    validator_index: u64,
    config: ProposerConfig,
) -> Result<(Block, Vec<SingleMessageAggregate>, PostBlockCheckpoints), StoreError> {
    // Get parent block and state to build upon
    let head_root = get_proposal_head(store, slot);
    let head_state = store
        .get_state(&head_root)
        .expect("head state exists")
        .ok_or(StoreError::MissingParentState {
            parent_root: head_root,
            slot,
        })?;

    // Validate proposer authorization for this slot
    let num_validators = head_state.validators.len() as u64;
    if !is_proposer(validator_index, slot, num_validators) {
        return Err(StoreError::NotProposer {
            validator_index,
            slot,
        });
    }

    // Get known aggregated payloads: data_root -> (AttestationData, Vec<proof>)
    //
    // The heartbeat-folded aggregate needs no special handling here: the fold runs
    // as an ordinary interval-2 aggregation job, so its result was inserted into
    // `new_payloads` at the interval-2 boundary and promoted to `known_payloads`
    // by the promote above. It reaches the builder as one candidate among many,
    // and `Tier::Heartbeat` is what makes it win.
    let aggregated_payloads = store.known_aggregated_payloads();

    let known_block_roots = store.get_block_roots().unwrap();

    let (block, signatures, post_checkpoints) = {
        let _timing = metrics::time_block_building_payload_aggregation();
        build_block(
            BlockTarget {
                head_state: &head_state,
                slot,
                proposer_index: validator_index,
                parent_root: head_root,
                known_block_roots: &known_block_roots,
                heartbeat_committee_size: store.heartbeat_committee_size(),
            },
            &aggregated_payloads,
            config,
        )?
    };

    // leanSpec #595: ideally the produced block should not lag the store's
    // justified checkpoint, since peers processing it would not see
    // justification advance, degrading liveness. The fixed-point loop in
    // `build_block` is expected to incorporate pool attestations that close any
    // divergence inherited from a minority fork, but it may not always
    // converge. We still publish the block in that case (halting block
    // production freezes the chain, which is worse) and only log the divergence.
    let store_justified_slot = store
        .latest_justified()
        .expect("latest finalized checkpoint exists")
        .slot;
    if post_checkpoints.justified.slot < store_justified_slot {
        warn!(
            %slot,
            proposer = validator_index,
            block_justified_slot = post_checkpoints.justified.slot,
            store_justified_slot,
            "Produced block justified slot is behind store justified slot; \
             fixed-point attestation loop did not converge"
        );
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

    #[error("Source checkpoint must be ancestor of target")]
    SourceNotAncestorOfTarget,

    #[error("Target checkpoint must be ancestor of head")]
    TargetNotAncestorOfHead,

    #[error(
        "Head checkpoint {head_root} at slot {head_slot} does not descend from finalized block {finalized_root} at slot {finalized_slot}"
    )]
    HeadNotDescendantOfFinalized {
        head_root: H256,
        head_slot: u64,
        finalized_root: H256,
        finalized_slot: u64,
    },

    #[error("Attestation slot {attestation_slot} precedes head block slot {head_slot}")]
    AttestationSlotBeforeHead {
        attestation_slot: u64,
        head_slot: u64,
    },

    #[error(
        "Attestation slot {attestation_slot} is too far in future (store time: {store_time} intervals)"
    )]
    AttestationTooFarInFuture {
        attestation_slot: u64,
        store_time: u64,
    },

    #[error(
        "heartbeat vote for slot {attestation_slot} is not for the current slot {current_slot}"
    )]
    HeartbeatVoteOutOfSlot {
        attestation_slot: u64,
        current_slot: u64,
    },

    #[error("validator {validator_id} is not in the heartbeat committee for slot {slot}")]
    NotHeartbeatCommitteeMember { validator_id: u64, slot: u64 },

    #[error("Aggregated signature verification failed: {0}")]
    AggregateVerificationFailed(ethlambda_crypto::VerificationError),

    #[error("Signature aggregation failed: {0}")]
    SignatureAggregationFailed(ethlambda_crypto::AggregationError),

    #[error("Missing target state for block: {0}")]
    MissingTargetState(H256),

    #[error("Aggregated attestation references no participants")]
    EmptyAggregationBits,

    #[error("Validator {validator_index} is not the proposer for slot {slot}")]
    NotProposer { validator_index: u64, slot: u64 },

    #[error(
        "Block contains duplicate AttestationData entries: {count} entries but only {unique} unique"
    )]
    DuplicateAttestationData { count: usize, unique: usize },

    #[error("Block contains {count} distinct AttestationData entries; maximum is {max}")]
    TooManyAttestationData { count: usize, max: usize },

    #[error("Block slot gap {gap} beyond parent exceeds historical roots limit {max}")]
    BlockSlotGapTooLarge { gap: u64, max: u64 },

    #[error("Block slot {block_slot} is beyond the future horizon (current slot: {current_slot})")]
    BlockTooFarInFuture { block_slot: u64, current_slot: u64 },
}

/// Full verification of a signed block's merged multi-message aggregate proof.
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

    // Resolve pubkeys per multi-message aggregate component for verify_type_2 and rederive the
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
            let pk = ValidatorPublicKey::from_bytes(&validator.attestation_pubkey)
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
    let proposer_pubkey = ValidatorPublicKey::from_bytes(&proposer_validator.proposal_pubkey)
        .map_err(|_| StoreError::PubkeyDecodingFailed(block.proposer_index))?;
    pubkeys_per_component.push(vec![proposer_pubkey]);
    let block_slot_u32 =
        u32::try_from(block.slot).map_err(|_| StoreError::SlotOutOfRange(block.slot))?;
    expected_bindings.push((block_root, block_slot_u32));

    let merged_bytes = signed_block.proof.proof_bytes();

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
        "Block multi-message aggregate proof verified"
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

    let old_head_header = store
        .get_block_header(&old_head)
        .expect("old head header exists")?;
    let new_head_header = store
        .get_block_header(&new_head)
        .expect("new head header exists")?;

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
    while let Ok(Some(current_header)) = store.get_block_header(&current_root) {
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
            AggregatedAttestations, BlockBody, MultiMessageAggregate, SignedBlock,
            SingleMessageAggregate,
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
        _attestation_proofs: Vec<SingleMessageAggregate>,
    ) -> MultiMessageAggregate {
        MultiMessageAggregate::default()
    }

    fn make_bits(indices: &[usize]) -> AggregationBits {
        let max = indices.iter().copied().max().unwrap_or(0);
        let mut bits = AggregationBits::with_length(max + 1).unwrap();
        for &i in indices {
            bits.set(i, true).unwrap();
        }
        bits
    }

    // ============ Heartbeat Vote Extraction Tests ============

    /// `n = 8, K = 4`, so the committee for slot 7 is `{7, 0, 1, 2}` and the
    /// committee for slot 6 is `{6, 7, 0, 1}`.
    const HB_VALIDATORS: u64 = 8;
    const HB_COMMITTEE: u64 = 4;

    fn hb_data(slot: u64, target_marker: u8) -> AttestationData {
        AttestationData {
            slot,
            head: Checkpoint::default(),
            target: Checkpoint {
                root: H256([target_marker; 32]),
                slot,
            },
            source: Checkpoint::default(),
        }
    }

    /// A body carrying one entry per `(slot, signers, target_marker)` triple.
    fn hb_body(entries: &[(u64, &[usize], u8)]) -> BlockBody {
        let attestations: Vec<AggregatedAttestation> = entries
            .iter()
            .map(|(slot, signers, marker)| AggregatedAttestation {
                aggregation_bits: make_bits(signers),
                data: hb_data(*slot, *marker),
            })
            .collect();
        BlockBody {
            attestations: AggregatedAttestations::try_from(attestations).unwrap(),
        }
    }

    #[test]
    fn extraction_keeps_committee_members_and_drops_outsiders() {
        // Block slot 8 -> committee slot 7 -> committee {7, 0, 1, 2}.
        // Signers 3, 4, 5 are outsiders.
        let body = hb_body(&[(7, &[0, 1, 3, 4, 7], 0xAA)]);
        let votes = extract_heartbeat_votes(&body, 8, HB_VALIDATORS, HB_COMMITTEE);

        let mut extracted: Vec<u64> = votes.iter().map(|(vid, _)| *vid).collect();
        extracted.sort_unstable();
        assert_eq!(extracted, vec![0, 1, 7], "outsider bits must be ignored");
    }

    #[test]
    fn extraction_gate_is_strictly_the_previous_slot() {
        // Entries for slot 6 and slot 8 must both be ignored by a slot-8 block:
        // only slot 7 is the committee slot. This is the exact mirror of the
        // packer's `Tier::Heartbeat` gate.
        let body = hb_body(&[(6, &[6, 7, 0], 0xAA), (7, &[7, 0], 0xBB), (8, &[0], 0xCC)]);
        let votes = extract_heartbeat_votes(&body, 8, HB_VALIDATORS, HB_COMMITTEE);

        assert_eq!(votes.len(), 2);
        assert!(
            votes.iter().all(|(_, data)| data.slot == 7),
            "only the committee slot's entries are heartbeat votes"
        );
    }

    #[test]
    fn extraction_survives_a_skipped_slot_without_widening() {
        // A block at slot 12 built after slots 8..11 were skipped still gates on
        // exactly 11, carrying nothing rather than reaching back for evidence.
        // Degrading on a missed slot is the fast head's job, not the packer's.
        let body = hb_body(&[(7, &[7, 0, 1], 0xAA)]);
        assert!(
            extract_heartbeat_votes(&body, 12, HB_VALIDATORS, HB_COMMITTEE).is_empty(),
            "no window and no fallback"
        );
    }

    #[test]
    fn extraction_ignores_genesis_adjacent_blocks() {
        let body = hb_body(&[(0, &[0], 0xAA)]);
        assert!(extract_heartbeat_votes(&body, 0, HB_VALIDATORS, HB_COMMITTEE).is_empty());
    }

    #[test]
    fn extraction_does_not_apply_the_reaggregate_filters() {
        // `reaggregate::select_candidates` drops attestations whose target is
        // already justified, skips participants already covered locally, and
        // truncates to a per-block maximum. Those filters are right for deciding
        // what is worth a SNARK split and wrong here: the fast head needs the
        // `head` field of every committee vote regardless. Extraction is a plain
        // read of the body, so a target at slot 0 (trivially justified) and a
        // large entry count both come through untouched.
        let body = hb_body(&[(7, &[7, 0, 1, 2], 0)]);
        let votes = extract_heartbeat_votes(&body, 8, HB_VALIDATORS, HB_COMMITTEE);
        assert_eq!(
            votes.len(),
            4,
            "an already-justified target must still be extracted"
        );

        // Many distinct datas for the same committee slot: no cap is applied.
        let many: Vec<(u64, &[usize], u8)> = (0..32).map(|i| (7, &[7, 0][..], i as u8)).collect();
        let body = hb_body(&many);
        let votes = extract_heartbeat_votes(&body, 8, HB_VALIDATORS, HB_COMMITTEE);
        assert_eq!(votes.len(), 64, "no truncation on the fork-choice path");
    }

    #[test]
    fn block_votes_union_with_gossip_and_win_on_conflict() {
        use ethlambda_storage::backend::InMemoryBackend;
        use std::sync::Arc;

        let genesis_state = State::from_genesis(1000, vec![]);
        let store = Store::from_anchor_state(Arc::new(InMemoryBackend::new()), genesis_state);

        // Gossip delivered validator 0 (conflicting data) and validator 1 (which
        // the block will not mention at all).
        store.insert_heartbeat_vote(0, hb_data(7, 0x11));
        store.insert_heartbeat_vote(1, hb_data(7, 0x11));

        // The block carries validators 0 and 7 with different data.
        let body = hb_body(&[(7, &[0, 7], 0x22)]);
        merge_heartbeat_votes(&store, &body, 8, HB_VALIDATORS);

        let votes = store.heartbeat_votes_at(7);
        assert_eq!(votes.len(), 3, "union, not replacement");
        assert_eq!(
            votes[&0].target.root,
            H256([0x22; 32]),
            "block wins the conflict"
        );
        assert_eq!(
            votes[&1].target.root,
            H256([0x11; 32]),
            "a gossip-only validator keeps its vote, so a byzantine proposer \
             cannot blank the fast head's evidence"
        );
        assert_eq!(votes[&7].target.root, H256([0x22; 32]));
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

        let head_root = store.head().expect("store head exists");
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
                SingleMessageAggregate::empty(bits_a),
                SingleMessageAggregate::empty(bits_b),
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

    /// Insert a header-only block at `root` with the given slot and parent.
    ///
    /// Empty body means `get_block_header` resolves it without a body row, which
    /// is all `validate_attestation_data` needs for the ancestry walk.
    fn insert_test_block(store: &mut Store, root: H256, slot: u64, parent_root: H256) {
        let signed_block = SignedBlock {
            message: Block {
                slot,
                proposer_index: 0,
                parent_root,
                state_root: H256::ZERO,
                body: BlockBody::default(),
            },
            proof: make_signed_block_proof(0, vec![]),
        };
        store
            .insert_signed_block(root, signed_block)
            .expect("insert test block should succeed");
    }

    fn new_test_store() -> Store {
        use ethlambda_storage::backend::InMemoryBackend;
        use std::sync::Arc;
        let genesis_state = State::from_genesis(1000, vec![]);
        let backend = Arc::new(InMemoryBackend::new());
        Store::from_anchor_state(backend, genesis_state)
    }

    /// The produced attestation source must track the head state's justified
    /// checkpoint, not the store's global `latest_justified`. When the store's
    /// justified has latched onto a higher, off-head sibling (a minority fork),
    /// sourcing from it would put the vote's source off the head chain and stall
    /// re-justification; sourcing from the head state keeps it on-chain.
    #[test]
    fn produce_attestation_data_sources_from_head_state_not_store() {
        let mut store = new_test_store();
        let genesis = store.head().expect("store head exists");

        // Head chain: genesis(0) <- a(1) <- b(2), with `b` as head.
        let a = H256([1u8; 32]);
        let b = H256([2u8; 32]);
        insert_test_block(&mut store, a, 1, genesis);
        insert_test_block(&mut store, b, 2, a);

        // Head state justified `a` (slot 1), which lies on the head's chain.
        let head_justified = Checkpoint { root: a, slot: 1 };
        // Persist `b`'s post-state via the diff API, diffed against the genesis
        // anchor. Build it as a valid direct child of genesis (the STF appends the
        // parent block root to historical_block_hashes), with the head's justified
        // checkpoint set; `insert_state` reads the base from
        // `latest_block_header.parent_root`, and `get_state(b)` then returns it
        // from the cache.
        let genesis_state = store.get_state(&genesis).expect("genesis state").unwrap();
        let mut head_state = genesis_state.clone();
        head_state.slot = genesis_state.slot + 1;
        head_state.latest_justified = head_justified;
        head_state.latest_block_header.parent_root = genesis;
        let mut hbh = genesis_state.historical_block_hashes.to_vec();
        hbh.push(genesis);
        head_state.historical_block_hashes = hbh.try_into().expect("within limit");
        store
            .insert_state(b, head_state)
            .expect("insert head state should succeed");

        // Store's global justified latched onto a higher, off-head checkpoint,
        // as it would after a minority fork justified a slot the head never saw.
        let off_head_justified = Checkpoint {
            root: H256([9u8; 32]),
            slot: 5,
        };
        store
            .update_checkpoints(ForkCheckpoints::new(b, Some(off_head_justified), None))
            .expect("update_checkpoints should succeed");
        store
            .set_time(2 * INTERVALS_PER_SLOT)
            .expect("set_time should succeed");

        let data = produce_attestation_data(&store, 2);

        assert_eq!(
            data.source, head_justified,
            "source should follow the head state's justified checkpoint"
        );
        assert_ne!(
            data.source,
            store.latest_justified().expect("store has justified"),
            "source must not be the store's off-head global justified"
        );
    }

    /// leanSpec #833: a vote whose head sits on a sibling fork of the target
    /// must be rejected by gossip validation, even though every slot and
    /// availability check passes.
    #[test]
    fn validate_attestation_rejects_head_on_sibling_fork() {
        let mut store = new_test_store();
        let genesis = store.head().expect("store head exists");

        let base = H256([1u8; 32]);
        let fork_left = H256([2u8; 32]);
        let fork_right = H256([3u8; 32]);
        insert_test_block(&mut store, base, 1, genesis);
        insert_test_block(&mut store, fork_left, 2, base);
        insert_test_block(&mut store, fork_right, 3, base);
        store
            .set_time(3 * INTERVALS_PER_SLOT)
            .expect("set_time should succeed");

        // source=base, target=fork_left, head=fork_right: target and head share a
        // parent (base) but neither is an ancestor of the other.
        let data = AttestationData {
            slot: 3,
            source: Checkpoint {
                root: base,
                slot: 1,
            },
            target: Checkpoint {
                root: fork_left,
                slot: 2,
            },
            head: Checkpoint {
                root: fork_right,
                slot: 3,
            },
        };

        let result = validate_attestation_data(&store, &data);
        assert!(
            matches!(result, Err(StoreError::TargetNotAncestorOfHead)),
            "Expected TargetNotAncestorOfHead, got: {result:?}"
        );
    }

    /// leanSpec #833: a vote whose source sits on a sibling fork of the target
    /// must be rejected, even though `source.slot < target.slot`.
    #[test]
    fn validate_attestation_rejects_source_on_sibling_fork() {
        let mut store = new_test_store();
        let genesis = store.head().expect("store head exists");

        let base = H256([1u8; 32]);
        let fork_left = H256([2u8; 32]);
        let fork_right = H256([3u8; 32]);
        let fork_right_head = H256([4u8; 32]);
        insert_test_block(&mut store, base, 1, genesis);
        insert_test_block(&mut store, fork_left, 2, base);
        insert_test_block(&mut store, fork_right, 3, base);
        insert_test_block(&mut store, fork_right_head, 4, fork_right);
        store
            .set_time(4 * INTERVALS_PER_SLOT)
            .expect("set_time should succeed");

        // source=fork_left (abandoned branch), target=head=fork_right_head:
        // source precedes target in slot but lies off the target's chain.
        let data = AttestationData {
            slot: 4,
            source: Checkpoint {
                root: fork_left,
                slot: 2,
            },
            target: Checkpoint {
                root: fork_right_head,
                slot: 4,
            },
            head: Checkpoint {
                root: fork_right_head,
                slot: 4,
            },
        };

        let result = validate_attestation_data(&store, &data);
        assert!(
            matches!(result, Err(StoreError::SourceNotAncestorOfTarget)),
            "Expected SourceNotAncestorOfTarget, got: {result:?}"
        );
    }

    /// leanSpec #1020: a vote whose slot precedes the slot of the head block it
    /// claims to have seen must be rejected. The vote cannot have observed its
    /// head before that head existed.
    #[test]
    fn validate_attestation_rejects_slot_before_head() {
        let mut store = new_test_store();
        let genesis = store.head().expect("store head exists");

        let b1 = H256([1u8; 32]);
        let b2 = H256([2u8; 32]);
        let b3 = H256([3u8; 32]);
        insert_test_block(&mut store, b1, 1, genesis);
        insert_test_block(&mut store, b2, 2, b1);
        insert_test_block(&mut store, b3, 3, b2);
        store
            .set_time(3 * INTERVALS_PER_SLOT)
            .expect("set_time should succeed");

        // head=b3 at slot 3, but the vote's own slot is 2: it claims to have seen
        // a head that did not yet exist when the vote was cast.
        let data = AttestationData {
            slot: 2,
            source: Checkpoint {
                root: genesis,
                slot: 0,
            },
            target: Checkpoint { root: b2, slot: 2 },
            head: Checkpoint { root: b3, slot: 3 },
        };

        let result = validate_attestation_data(&store, &data);
        assert!(
            matches!(
                result,
                Err(StoreError::AttestationSlotBeforeHead {
                    attestation_slot: 2,
                    head_slot: 3,
                })
            ),
            "Expected AttestationSlotBeforeHead, got: {result:?}"
        );
    }

    /// leanSpec #1020: a vote whose slot sits at the unsigned 64-bit ceiling must
    /// be rejected cleanly as too-far-in-future, without overflowing the
    /// slot-to-interval multiplication. `saturating_mul` clamps the product at
    /// `u64::MAX` rather than panicking on overflow.
    #[test]
    fn validate_attestation_rejects_ceiling_slot_without_overflow() {
        let mut store = new_test_store();
        let genesis = store.head().expect("store head exists");

        let b1 = H256([1u8; 32]);
        let b2 = H256([2u8; 32]);
        insert_test_block(&mut store, b1, 1, genesis);
        insert_test_block(&mut store, b2, 2, b1);
        store
            .set_time(2 * INTERVALS_PER_SLOT)
            .expect("set_time should succeed");

        // A crafted gossip vote with a near-`u64::MAX` slot. The head-consistency
        // check passes (slot >= head.slot), so this exercises the time check.
        let data = AttestationData {
            slot: u64::MAX,
            source: Checkpoint {
                root: genesis,
                slot: 0,
            },
            target: Checkpoint { root: b1, slot: 1 },
            head: Checkpoint { root: b2, slot: 2 },
        };

        let result = validate_attestation_data(&store, &data);
        assert!(
            matches!(result, Err(StoreError::AttestationTooFarInFuture { .. })),
            "Expected AttestationTooFarInFuture, got: {result:?}"
        );
    }

    /// A vote whose source, target, and head form one parent chain validates.
    #[test]
    fn validate_attestation_accepts_proper_ancestor_chain() {
        let mut store = new_test_store();
        let genesis = store.head().expect("store head exists");

        let b1 = H256([1u8; 32]);
        let b2 = H256([2u8; 32]);
        insert_test_block(&mut store, b1, 1, genesis);
        insert_test_block(&mut store, b2, 2, b1);
        store
            .set_time(2 * INTERVALS_PER_SLOT)
            .expect("set_time should succeed");

        let data = AttestationData {
            slot: 2,
            source: Checkpoint {
                root: genesis,
                slot: 0,
            },
            target: Checkpoint { root: b1, slot: 1 },
            head: Checkpoint { root: b2, slot: 2 },
        };

        assert!(
            validate_attestation_data(&store, &data).is_ok(),
            "fully canonical vote must validate"
        );
    }

    /// leanSpec #1179: a vote whose head sits on a branch orphaned by
    /// finalization must be rejected. The vote is admissible while finalization
    /// still sits below the fork point, but once a sibling block finalizes a slot
    /// the orphaned head does not descend from, fork choice can no longer count
    /// it: re-gossiping the same vote must be rejected, not re-admitted.
    #[test]
    fn validate_attestation_rejects_head_off_finalized_branch() {
        let mut store = new_test_store();
        let genesis = store.head().expect("store head exists");

        // Canonical chain: genesis(0) <- block_1(1) <- block_2(2).
        // Orphan branch off block_1: block_1(1) <- orph_2(2) <- orph_3(3).
        let block_1 = H256([1u8; 32]);
        let block_2 = H256([2u8; 32]);
        let orph_2 = H256([3u8; 32]);
        let orph_3 = H256([4u8; 32]);
        insert_test_block(&mut store, block_1, 1, genesis);
        insert_test_block(&mut store, block_2, 2, block_1);
        insert_test_block(&mut store, orph_2, 2, block_1);
        insert_test_block(&mut store, orph_3, 3, orph_2);
        store
            .set_time(3 * INTERVALS_PER_SLOT)
            .expect("set_time should succeed");

        // Vote entirely on the orphan branch: source=block_1, target=orph_2,
        // head=orph_3. Source/target/head form one parent chain, so every
        // topology and ancestry check below the finalized check passes.
        let data = AttestationData {
            slot: 3,
            source: Checkpoint {
                root: block_1,
                slot: 1,
            },
            target: Checkpoint {
                root: orph_2,
                slot: 2,
            },
            head: Checkpoint {
                root: orph_3,
                slot: 3,
            },
        };

        // While finalization still sits at genesis (below the block_1 fork point),
        // the orphan head descends from finalized, so the vote is admissible.
        assert!(
            validate_attestation_data(&store, &data).is_ok(),
            "vote must validate while finalized sits below the fork point"
        );

        // block_2 finalizes slot 2 on the canonical branch. orph_3 does not
        // descend from block_2, so the vote must now be rejected.
        let finalized = Checkpoint {
            root: block_2,
            slot: 2,
        };
        store
            .update_checkpoints(ForkCheckpoints::new(block_2, None, Some(finalized)))
            .expect("update_checkpoints should succeed");

        let result = validate_attestation_data(&store, &data);
        assert!(
            matches!(
                result,
                Err(StoreError::HeadNotDescendantOfFinalized {
                    head_root,
                    head_slot: 3,
                    finalized_root,
                    finalized_slot: 2,
                }) if head_root == orph_3 && finalized_root == block_2
            ),
            "Expected HeadNotDescendantOfFinalized, got: {result:?}"
        );
    }

    /// leanSpec #1182: a block whose slot is more than one slot past the store
    /// clock is rejected before the state transition (and before signature
    /// verification), keeping far-future blocks out of the store.
    #[test]
    fn on_block_rejects_block_too_far_in_future() {
        use ethlambda_storage::backend::InMemoryBackend;
        use std::sync::Arc;

        let genesis_state = State::from_genesis(1000, vec![]);
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::from_anchor_state(backend, genesis_state);
        store.set_time(0).expect("set_time should succeed");

        // current_slot = 0, so the horizon is slot 1; a slot-2 block overshoots it.
        let block = Block {
            slot: 2,
            proposer_index: 0,
            parent_root: store.head().expect("store head exists"),
            state_root: H256::ZERO,
            body: BlockBody::default(),
        };
        let signed_block = SignedBlock {
            message: block,
            proof: MultiMessageAggregate::default(),
        };

        let result = on_block_without_verification(&mut store, signed_block);
        assert!(
            matches!(
                result,
                Err(StoreError::BlockTooFarInFuture {
                    block_slot: 2,
                    current_slot: 0,
                })
            ),
            "Expected BlockTooFarInFuture, got: {result:?}"
        );
    }

    /// leanSpec #1182: a block whose slot runs more than HISTORICAL_ROOTS_LIMIT
    /// beyond its parent is rejected up front, so the transition never walks the
    /// empty-slot loop over an unbounded range. The gap guard runs before the
    /// future-horizon guard, so it fires even with the clock at genesis.
    #[test]
    fn on_block_rejects_block_slot_gap_too_large() {
        use ethlambda_storage::backend::InMemoryBackend;
        use std::sync::Arc;

        let genesis_state = State::from_genesis(1000, vec![]);
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::from_anchor_state(backend, genesis_state);
        store.set_time(0).expect("set_time should succeed");

        // Parent (genesis) sits at slot 0, so a slot one past the limit overshoots.
        let gap_slot = HISTORICAL_ROOTS_LIMIT as u64 + 1;
        let block = Block {
            slot: gap_slot,
            proposer_index: 0,
            parent_root: store.head().expect("store head exists"),
            state_root: H256::ZERO,
            body: BlockBody::default(),
        };
        let signed_block = SignedBlock {
            message: block,
            proof: MultiMessageAggregate::default(),
        };

        let result = on_block_without_verification(&mut store, signed_block);
        assert!(
            matches!(
                result,
                Err(StoreError::BlockSlotGapTooLarge { gap, max })
                    if gap == gap_slot && max == HISTORICAL_ROOTS_LIMIT as u64
            ),
            "Expected BlockSlotGapTooLarge, got: {result:?}"
        );
    }
}
