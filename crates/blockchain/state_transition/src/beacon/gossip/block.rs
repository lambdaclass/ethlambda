//! `beacon_block` gossip validation: fulu's `validate_beacon_block_gossip`
//! (`specs/fulu/p2p-interface.md`) and gloas's modified one
//! (`specs/gloas/p2p-interface.md`), with the deviations the design spec lists.

use ethlambda_storage::CacheKey;
use tracing::warn;

use super::{
    IgnoreReason, Outcome, QueueReason, RejectReason, SeenBlocks, execution_requests_within_limits,
    finalized_ancestry, finalized_start_slot, is_future_slot,
};
use crate::beacon::containers::{BeaconState, SignedBeaconBlock, gloas};
use crate::beacon::fork_choice::{self, Store};
use crate::beacon::helpers::misc::compute_epoch_at_slot;
use crate::beacon::lean_boundary::{lean_block_unreachable, lean_state_unreachable};
use crate::beacon::precheck::{self, PrecheckError, Reference, precheck_block};
use crate::beacon::preset;
use crate::beacon::primitives::{ExecutionBlockHash, Root};
use crate::beacon::stf::bellatrix::compute_timestamp_at_slot;

/// The rules that read only the block, the clock and the store's metadata.
///
/// `Err` carries the verdict; `Ok` sends the block on to [`stateful_checks`].
/// A gloas block runs [`cheap_checks_gloas`] instead.
pub fn cheap_checks(
    seen: &SeenBlocks,
    store: &Store,
    block: &SignedBeaconBlock,
    now_ms: u64,
) -> Result<(), Outcome> {
    if let Some(gloas_block) = as_gloas(block, "block::cheap_checks") {
        return cheap_checks_gloas(seen, store, gloas_block, now_ms);
    }
    let config = store.config();
    let slot = block.slot();
    // [IGNORE] The block is not from a future slot.
    if is_future_slot(&config, slot, now_ms) {
        return Err(Outcome::Ignore(IgnoreReason::FutureSlot));
    }
    // [REJECT] The number of blob commitments is within the epoch's limit.
    let max_blobs = config.max_blobs_per_block(compute_epoch_at_slot(slot));
    if block.blob_kzg_commitment_count() as u64 > max_blobs {
        return Err(Outcome::Reject(RejectReason::TooManyBlobs));
    }
    // [IGNORE] The block is from a slot greater than the latest finalized slot.
    if slot <= finalized_start_slot(store) {
        return Err(Outcome::Ignore(IgnoreReason::Finalized));
    }
    // [IGNORE] The block is the first with a valid signature for its slot and
    // proposer.
    if seen.contains(slot, block.proposer_index()) {
        return Err(Outcome::Ignore(IgnoreReason::AlreadySeen));
    }
    Ok(())
}

/// `block` as a gloas block, or `None` for every earlier fork.
///
/// Spelled out arm by arm so that a new fork breaks this match rather than
/// silently taking fulu's rules.
fn as_gloas<'a>(
    block: &'a SignedBeaconBlock,
    function: &str,
) -> Option<&'a gloas::SignedBeaconBlock> {
    match block {
        SignedBeaconBlock::Gloas(block) => Some(block),
        SignedBeaconBlock::Phase0(_)
        | SignedBeaconBlock::Altair(_)
        | SignedBeaconBlock::Bellatrix(_)
        | SignedBeaconBlock::Capella(_)
        | SignedBeaconBlock::Deneb(_)
        | SignedBeaconBlock::Electra(_)
        | SignedBeaconBlock::Fulu(_) => None,
        SignedBeaconBlock::Lean(_) => lean_block_unreachable(function),
    }
}

/// The gloas rules that read only the block, the clock and the store's
/// metadata: the first half of gloas's modified `validate_beacon_block_gossip`
/// (`specs/gloas/p2p-interface.md`), in the specification's order.
///
/// The blob-count rule sits later in the specification, after the parent
/// lookups, but reads only the bid; it runs here for the reason fulu's does,
/// so a block with too many commitments is refused before any state is read.
fn cheap_checks_gloas(
    seen: &SeenBlocks,
    store: &Store,
    signed_block: &gloas::SignedBeaconBlock,
    now_ms: u64,
) -> Result<(), Outcome> {
    let config = store.config();
    let block = &signed_block.message;
    // [IGNORE] The block is the first with a valid signature for its slot and
    // proposer.
    if seen.contains(block.slot, block.proposer_index) {
        return Err(Outcome::Ignore(IgnoreReason::AlreadySeen));
    }
    // [IGNORE] The block is not from a future slot.
    if is_future_slot(&config, block.slot, now_ms) {
        return Err(Outcome::Ignore(IgnoreReason::FutureSlot));
    }
    // [IGNORE] The block is from a slot greater than the latest finalized slot.
    if block.slot <= finalized_start_slot(store) {
        return Err(Outcome::Ignore(IgnoreReason::Finalized));
    }
    // [REJECT] The body's operation counts, and the parent execution
    // requests' counts, are within their limits.
    if !body_operations_within_limits(&block.body)
        || !execution_requests_within_limits(&block.body.parent_execution_requests)
    {
        return Err(Outcome::Reject(RejectReason::OperationLimit));
    }
    // [REJECT] The bid's blob KZG commitment count is within the per-epoch
    // limit.
    let bid = &block.body.signed_execution_payload_bid.message;
    let max_blobs = config.max_blobs_per_block(compute_epoch_at_slot(block.slot));
    if bid.blob_kzg_commitments.len() as u64 > max_blobs {
        return Err(Outcome::Reject(RejectReason::TooManyBlobs));
    }
    Ok(())
}

/// `verify_block_body_operation_limits` (`specs/gloas/p2p-interface.md`).
///
/// Gloas's operation lists are progressive, so unlike every earlier fork's
/// they carry no bound of their own and decoding does not enforce it.
fn body_operations_within_limits(body: &gloas::BeaconBlockBody) -> bool {
    body.proposer_slashings.len() <= preset::MAX_PROPOSER_SLASHINGS
        && body.attester_slashings.len() <= preset::MAX_ATTESTER_SLASHINGS_ELECTRA
        && body.attestations.len() <= preset::MAX_ATTESTATIONS_ELECTRA
        && body.deposits.is_empty()
        && body.voluntary_exits.len() <= preset::MAX_VOLUNTARY_EXITS
        && body.bls_to_execution_changes.len() <= preset::MAX_BLS_TO_EXECUTION_CHANGES
        && body.payload_attestations.len() as u64 <= preset::MAX_PAYLOAD_ATTESTATIONS
}

/// The rules that need the parent's post-state. Runs on a blocking thread.
///
/// Reads states only through [`Store::cached_state`]: a miss would otherwise
/// rebuild the state from diffs, which is far too slow for a verdict that
/// gossipsub waits on. A miss queues the block instead.
pub fn stateful_checks(store: &Store, block: &SignedBeaconBlock, block_root: Root) -> Outcome {
    let gloas_block = as_gloas(block, "block::stateful_checks");
    let config = store.config();
    let parent_root = block.parent_root();
    let parent_known = store.has_block(&parent_root);
    let parent_state = if parent_known {
        store.cached_state(CacheKey::BlockState(parent_root))
    } else {
        None
    };
    // [IGNORE] The parent has been seen and passed validation (MAY queue).
    // A parent without a post-state may have failed, which the specification
    // rejects; without a bad-block cache this cannot tell failed from not yet
    // imported, so it queues. See the design spec's deviations.
    let Some(parent_state) = parent_state else {
        let reason = if parent_known {
            QueueReason::ParentNotReady
        } else {
            QueueReason::ParentUnknown
        };
        return queue_unless_forged(store, block, block_root, reason);
    };
    // [REJECT] After its parent, expected proposer (when the parent's
    // lookahead can answer), known proposer, valid signature.
    if let Err(err) = precheck_block(block, block_root, Reference::Parent(&parent_state), &config) {
        return Outcome::Reject(err.into());
    }
    // [IGNORE] (gloas) If the parent block is full, the parent payload is
    // valid. The specification checks this between the signature and the
    // slot-order rule, but the slot-order and expected-proposer rules are both
    // inside `precheck_block` here, so a block that fails either is rejected
    // even with an unverified parent payload. The parent's fullness is read
    // once: it decodes the parent block, which the bounded validation pool
    // should not do twice.
    let parent_full = if gloas_block.is_some() {
        match fork_choice::is_parent_node_full(store, block) {
            Ok(full) => full,
            Err(err) => {
                warn!(%err, "Could not read a gloas block's parent payload status");
                return Outcome::Ignore(IgnoreReason::Internal);
            }
        }
    } else {
        true
    };
    if gloas_block.is_some() && parent_full && !fork_choice::is_payload_verified(store, parent_root)
    {
        return Outcome::Ignore(IgnoreReason::ParentPayloadUnverified);
    }
    // [REJECT] The finalized checkpoint is an ancestor of the block.
    if let Err(outcome) = finalized_ancestry(store, parent_root).verdict() {
        return outcome;
    }
    // A gloas block has no payload to time; earlier forks: [REJECT] the
    // execution payload's timestamp is the slot's.
    if let Some(gloas_block) = gloas_block {
        // [REJECT] The bid's parent equals the block's parent.
        let bid = &gloas_block
            .message
            .body
            .signed_execution_payload_bid
            .message;
        if bid.parent_block_root != gloas_block.message.parent_root {
            return Outcome::Reject(RejectReason::BidParentMismatch);
        }
        // [REJECT] If the parent is not full, the bid builds on the parent's
        // execution head. `process_slots` leaves `latest_block_hash` alone,
        // so the parent's post-state answers for the advanced one.
        if !parent_full && latest_block_hash(&parent_state) != Some(bid.parent_block_hash) {
            return Outcome::Reject(RejectReason::BidNotOnParentHead);
        }
    } else if let Some(timestamp) = block.execution_payload_timestamp()
        && timestamp != compute_timestamp_at_slot(&parent_state, block.slot(), &config)
    {
        return Outcome::Reject(RejectReason::PayloadTimestamp);
    }
    // [REJECT] Proposed by the expected proposer; when the parent's lookahead
    // cannot place the slot, `precheck_block` above already checked the
    // signature against the parent's key, so this only queues rather than
    // rejecting.
    if precheck::fixed_proposer(&parent_state, block.slot()).is_none() {
        return Outcome::Queue(QueueReason::ShufflingUnavailable);
    }
    Outcome::Accept
}

/// `state.latest_block_hash`, for a gloas state. `None` for an earlier fork,
/// which has none: its parent counts as full, so no caller asks.
fn latest_block_hash(state: &BeaconState) -> Option<ExecutionBlockHash> {
    match state {
        BeaconState::Gloas(state) => Some(state.latest_block_hash),
        BeaconState::Phase0(_)
        | BeaconState::Altair(_)
        | BeaconState::Bellatrix(_)
        | BeaconState::Capella(_)
        | BeaconState::Deneb(_)
        | BeaconState::Electra(_)
        | BeaconState::Fulu(_) => None,
        BeaconState::Lean(_) => lean_state_unreachable("block::latest_block_hash"),
    }
}

/// `cheap_checks` then `stateful_checks`, the order the p2p actor runs them in.
/// For callers that have no reason to split them, such as the spec vectors.
pub fn validate(
    seen: &SeenBlocks,
    store: &Store,
    block: &SignedBeaconBlock,
    now_ms: u64,
) -> Outcome {
    if let Err(outcome) = cheap_checks(seen, store, block, now_ms) {
        return outcome;
    }
    stateful_checks(store, block, block.message_hash_tree_root())
}

/// `Queue(reason)`, unless the head state already shows the signature is forged.
///
/// A block that cannot be judged against its parent yet can still be judged
/// on its signature: validator indices never move, so the head state's key for
/// the proposer is the one the block was signed with. Prysm does the same
/// before queueing.
fn queue_unless_forged(
    store: &Store,
    block: &SignedBeaconBlock,
    block_root: Root,
    reason: QueueReason,
) -> Outcome {
    let head_state = store
        .head()
        .ok()
        .and_then(|head| store.cached_state(CacheKey::BlockState(head)));
    let Some(head_state) = head_state else {
        return Outcome::Queue(reason);
    };
    match precheck_block(
        block,
        block_root,
        Reference::Recent(&head_state),
        &store.config(),
    ) {
        Err(PrecheckError::BadSignature) => Outcome::Reject(RejectReason::BadSignature),
        _ => Outcome::Queue(reason),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::beacon::bls;
    use crate::beacon::config::Config;
    use crate::beacon::constants::{
        DEPOSIT_CONTRACT_TREE_DEPTH, DOMAIN_BEACON_PROPOSER,
        MAXIMUM_GOSSIP_CLOCK_DISPARITY as DISPARITY,
    };
    use crate::beacon::containers::{BeaconState, electra};
    use crate::beacon::fork_choice;
    use crate::beacon::gossip::test_support::{
        PastAFork, fulu_parent, seen_blocks, slot_start_ms, store, store_finalized_past_a_fork,
    };
    use crate::beacon::gossip::{IgnoreReason, Outcome, RejectReason};
    use crate::beacon::helpers::misc::{
        compute_domain, compute_epoch_at_slot, compute_signing_root, compute_start_slot_at_epoch,
    };
    use crate::beacon::helpers::test_state::secret_key_for;
    use crate::beacon::preset;
    use crate::beacon::primitives::{BlsSignature, KzgCommitment, Root, Slot, ValidatorIndex};

    fn fulu_block(slot: Slot, proposer: ValidatorIndex, commitments: usize) -> SignedBeaconBlock {
        let mut body = electra::BeaconBlockBody::empty();
        body.blob_kzg_commitments = vec![KzgCommitment::default(); commitments]
            .try_into()
            .expect("within MAX_BLOB_COMMITMENTS_PER_BLOCK");
        SignedBeaconBlock::Fulu(electra::SignedBeaconBlock {
            message: electra::BeaconBlock {
                slot,
                proposer_index: proposer,
                parent_root: Root::ZERO,
                state_root: Root::ZERO,
                body,
            },
            signature: Default::default(),
        })
    }

    /// [`fulu_parent`], repositioned to `slot` rather than the one
    /// `with_validators_at` places it at.
    fn fulu_parent_at(proposer: ValidatorIndex, slot: Slot) -> BeaconState {
        let mut state = fulu_parent(proposer);
        if let BeaconState::Fulu(fulu_state) = &mut state {
            fulu_state.slot = slot;
        }
        state
    }

    /// Signs `block` under `config`'s domain for its own slot's epoch, with
    /// `signer`'s test key, over `state`'s genesis validators root. Mirrors
    /// `column.rs`'s own `signed` helper.
    fn sign_block(
        mut block: SignedBeaconBlock,
        state: &BeaconState,
        config: &Config,
        signer: ValidatorIndex,
    ) -> SignedBeaconBlock {
        let root = block.message_hash_tree_root();
        let fork_version =
            config.fork_version(config.fork_at_epoch(compute_epoch_at_slot(block.slot())));
        let domain = compute_domain(
            DOMAIN_BEACON_PROPOSER,
            fork_version,
            state.genesis_validators_root(),
        );
        let signing_root = compute_signing_root(root, domain);
        let signature =
            secret_key_for(signer as usize).sign(signing_root.as_slice(), bls::DST, &[]);
        let SignedBeaconBlock::Fulu(inner) = &mut block else {
            unreachable!("fulu_block builds a fulu block");
        };
        inner.signature = BlsSignature(signature.to_bytes());
        block
    }

    /// A block one slot after `parent`, under `parent_root`, signed by
    /// `proposer` and carrying the payload timestamp `parent` expects: every
    /// rule [`stateful_checks`] runs passes, save finalized ancestry.
    fn signed_child(
        parent: &BeaconState,
        parent_root: Root,
        proposer: ValidatorIndex,
        config: &Config,
    ) -> SignedBeaconBlock {
        let slot = parent.slot() + 1;
        let SignedBeaconBlock::Fulu(mut inner) = fulu_block(slot, proposer, 0) else {
            unreachable!("fulu_block builds a fulu block");
        };
        inner.message.parent_root = parent_root;
        inner.message.body.execution_payload.timestamp =
            compute_timestamp_at_slot(parent, slot, config);
        sign_block(SignedBeaconBlock::Fulu(inner), parent, config, proposer)
    }

    #[test]
    fn a_gloas_body_is_limited_per_operation_and_carries_no_deposits() {
        let body = gloas::BeaconBlockBody::default();
        assert!(body_operations_within_limits(&body));

        let mut with_deposit = body.clone();
        let deposit = crate::beacon::containers::Deposit {
            proof: vec![Root::ZERO; DEPOSIT_CONTRACT_TREE_DEPTH + 1]
                .try_into()
                .expect("a deposit proof has the contract tree's depth plus one roots"),
            data: Default::default(),
        };
        with_deposit.deposits = vec![deposit]
            .try_into()
            .expect("progressive lists are unbounded");
        assert!(!body_operations_within_limits(&with_deposit));

        let mut too_many_exits = body;
        too_many_exits.voluntary_exits = vec![Default::default(); preset::MAX_VOLUNTARY_EXITS + 1]
            .try_into()
            .expect("progressive lists are unbounded");
        assert!(!body_operations_within_limits(&too_many_exits));
    }

    #[test]
    fn deposit_requests_are_not_limited_by_gossip() {
        let request = crate::beacon::containers::electra::DepositRequest {
            pubkey: Default::default(),
            withdrawal_credentials: Default::default(),
            amount: 0,
            signature: Default::default(),
            index: 0,
        };
        let requests = gloas::ExecutionRequests {
            deposits: vec![request; preset::MAX_DEPOSIT_REQUESTS_PER_PAYLOAD + 1]
                .try_into()
                .expect("progressive lists are unbounded"),
            ..Default::default()
        };
        assert!(execution_requests_within_limits(&requests));
    }

    #[test]
    fn gloas_execution_requests_are_limited_per_list() {
        let requests = gloas::ExecutionRequests::default();
        assert!(execution_requests_within_limits(&requests));

        let mut too_many = requests;
        too_many.builder_exits =
            vec![Default::default(); preset::MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD as usize + 1]
                .try_into()
                .expect("progressive lists are unbounded");
        assert!(!execution_requests_within_limits(&too_many));
    }

    #[test]
    fn a_block_within_the_clock_disparity_passes() {
        let store = store(0);
        let now = slot_start_ms(&store, 5) - (DISPARITY - 100);
        assert_eq!(
            cheap_checks(&seen_blocks(), &store, &fulu_block(5, 1, 0), now),
            Ok(())
        );
    }

    #[test]
    fn a_block_beyond_the_clock_disparity_is_ignored() {
        let store = store(0);
        let now = slot_start_ms(&store, 5) - (DISPARITY + 100);
        assert_eq!(
            cheap_checks(&seen_blocks(), &store, &fulu_block(5, 1, 0), now),
            Err(Outcome::Ignore(IgnoreReason::FutureSlot))
        );
    }

    #[test]
    fn too_many_blob_commitments_are_rejected() {
        let store = store(0);
        let max = store.config().max_blobs_per_block(compute_epoch_at_slot(5)) as usize;
        let now = slot_start_ms(&store, 5);
        assert_eq!(
            cheap_checks(&seen_blocks(), &store, &fulu_block(5, 1, max), now),
            Ok(())
        );
        assert_eq!(
            cheap_checks(&seen_blocks(), &store, &fulu_block(5, 1, max + 1), now),
            Err(Outcome::Reject(RejectReason::TooManyBlobs))
        );
    }

    #[test]
    fn a_block_at_or_below_the_finalized_epoch_start_is_ignored() {
        // Finalized at the start of epoch 1: slot 32 itself is no longer new.
        let store = store(32);
        let now = slot_start_ms(&store, 40);
        assert_eq!(
            cheap_checks(&seen_blocks(), &store, &fulu_block(32, 1, 0), now),
            Err(Outcome::Ignore(IgnoreReason::Finalized))
        );
        assert_eq!(
            cheap_checks(&seen_blocks(), &store, &fulu_block(33, 1, 0), now),
            Ok(())
        );
    }

    #[test]
    fn a_second_block_for_a_seen_slot_and_proposer_is_ignored() {
        let store = store(0);
        let now = slot_start_ms(&store, 5);
        let mut seen = seen_blocks();
        seen.record(5, 1, Root::repeat_byte(9));
        assert_eq!(
            cheap_checks(&seen, &store, &fulu_block(5, 1, 0), now),
            Err(Outcome::Ignore(IgnoreReason::AlreadySeen))
        );
        assert_eq!(
            cheap_checks(&seen, &store, &fulu_block(5, 2, 0), now),
            Ok(())
        );
    }

    #[test]
    fn a_block_whose_parent_was_never_seen_is_queued() {
        let store = store(0);
        let SignedBeaconBlock::Fulu(mut orphan) = fulu_block(5, 1, 0) else {
            unreachable!("fulu_block builds a fulu block");
        };
        orphan.message.parent_root = Root::repeat_byte(0x11);
        let orphan = SignedBeaconBlock::Fulu(orphan);
        // No head state is cached either, so the signature cannot be judged
        // and the block is queued as it is.
        assert_eq!(
            stateful_checks(&store, &orphan, Root::repeat_byte(5)),
            Outcome::Queue(QueueReason::ParentUnknown)
        );
    }

    #[test]
    fn an_unknown_parent_with_a_cached_head_state_is_judged_on_its_signature() {
        let store = store(0);
        let config = store.config();
        let proposer: ValidatorIndex = 3;
        // `store()` sets the head to `Root::ZERO`, the same root
        // `queue_unless_forged` reads through `Store::head`.
        let head_state = fulu_parent(proposer);
        store.cache_state(
            CacheKey::BlockState(Root::ZERO),
            Arc::new(head_state.clone()),
        );

        let SignedBeaconBlock::Fulu(mut orphan) = fulu_block(5, proposer, 0) else {
            unreachable!("fulu_block builds a fulu block");
        };
        orphan.message.parent_root = Root::repeat_byte(0x11);
        let orphan = SignedBeaconBlock::Fulu(orphan);

        // The default signature verifies against nobody.
        assert_eq!(
            stateful_checks(&store, &orphan, orphan.message_hash_tree_root()),
            Outcome::Reject(RejectReason::BadSignature)
        );

        // The same block, properly signed by the head state's proposer.
        let signed = sign_block(orphan, &head_state, &config, proposer);
        assert_eq!(
            stateful_checks(&store, &signed, signed.message_hash_tree_root()),
            Outcome::Queue(QueueReason::ParentUnknown)
        );
    }

    #[test]
    fn a_slot_past_the_lookahead_is_queued_only_once_verified() {
        let mut store = store(0);
        let config = store.config();
        let proposer: ValidatorIndex = 3;
        let parent = fulu_parent(proposer);
        let parent_root = Root::repeat_byte(0x22);

        // A `BlockHeaders` row and a cached state, plus a `LiveChain` chain
        // back to the finalized root, so the finalized-ancestry walk
        // succeeds and this test reaches the lookahead gate rather than
        // `Queue(ParentNotReady)`.
        store
            .insert_pending_block(parent_root, fulu_block(parent.slot(), proposer, 0))
            .expect("insert pending parent");
        store.cache_state(CacheKey::BlockState(parent_root), Arc::new(parent.clone()));
        store.insert_live_chain_entry(parent.slot(), parent_root, Root::ZERO);
        store.insert_live_chain_entry(0, Root::ZERO, Root::ZERO);

        let window_start = compute_start_slot_at_epoch(compute_epoch_at_slot(parent.slot()));
        let beyond = window_start + preset::PROPOSER_LOOKAHEAD_LENGTH as Slot;
        assert_eq!(precheck::fixed_proposer(&parent, beyond), None);

        let SignedBeaconBlock::Fulu(mut inner) = fulu_block(beyond, proposer, 0) else {
            unreachable!("fulu_block builds a fulu block");
        };
        inner.message.parent_root = parent_root;
        // Outside the lookahead window the proposer rule is skipped, but the
        // payload-timestamp rule still runs before it, so it must match.
        inner.message.body.execution_payload.timestamp =
            compute_timestamp_at_slot(&parent, beyond, &config);
        let unsigned = SignedBeaconBlock::Fulu(inner);

        let good = sign_block(unsigned.clone(), &parent, &config, proposer);
        assert_eq!(
            stateful_checks(&store, &good, good.message_hash_tree_root()),
            Outcome::Queue(QueueReason::ShufflingUnavailable)
        );

        // The default (forged) signature is rejected before the lookahead is
        // ever consulted.
        assert_eq!(
            stateful_checks(&store, &unsigned, unsigned.message_hash_tree_root()),
            Outcome::Reject(RejectReason::BadSignature)
        );
    }

    #[test]
    fn a_slot_the_lookahead_cannot_place_still_fails_on_slot_order() {
        // Pins that `precheck_block`'s not-after-parent check runs before the
        // lookahead gate: a slot the lookahead cannot place at all must still
        // surface the spec's REJECT for a slot not after the parent's, rather
        // than `Queue(ShufflingUnavailable)` masking it.
        let mut store = store(0);
        let config = store.config();
        let proposer: ValidatorIndex = 3;
        let parent_slot: Slot = 40;
        let parent = fulu_parent_at(proposer, parent_slot);
        let parent_root = Root::repeat_byte(0x33);

        // Only a `BlockHeaders` row is needed: `precheck_block`'s
        // not-after-parent check returns before the finalized-ancestry walk
        // is ever reached, so no `LiveChain` row is set up for it.
        store
            .insert_pending_block(parent_root, fulu_block(parent_slot, proposer, 0))
            .expect("insert pending parent");
        store.cache_state(CacheKey::BlockState(parent_root), Arc::new(parent.clone()));

        let slot: Slot = 31;
        assert!(slot < parent_slot);
        assert_eq!(precheck::fixed_proposer(&parent, slot), None);

        let SignedBeaconBlock::Fulu(mut inner) = fulu_block(slot, proposer, 0) else {
            unreachable!("fulu_block builds a fulu block");
        };
        inner.message.parent_root = parent_root;
        let unsigned = SignedBeaconBlock::Fulu(inner);
        let block = sign_block(unsigned, &parent, &config, proposer);

        assert_eq!(
            stateful_checks(&store, &block, block.message_hash_tree_root()),
            Outcome::Reject(RejectReason::NotAfterParent)
        );
    }

    #[test]
    fn a_failed_finalized_ancestry_walk_queues_rather_than_rejects() {
        let mut store = store(0);
        let config = store.config();
        let proposer: ValidatorIndex = 3;
        let parent = fulu_parent(proposer);
        let parent_root = Root::repeat_byte(0x44);

        // A `BlockHeaders` row and a cached state for the parent, but no
        // `LiveChain` row for it: the finalized-ancestry walk cannot finish.
        store
            .insert_pending_block(parent_root, fulu_block(parent.slot(), proposer, 0))
            .expect("insert pending parent");
        store.cache_state(CacheKey::BlockState(parent_root), Arc::new(parent.clone()));

        // Inside the lookahead window, so `precheck_block` fully verifies the
        // proposer and signature before the ancestry walk is ever reached.
        let slot = parent.slot() + 1;
        let SignedBeaconBlock::Fulu(mut inner) = fulu_block(slot, proposer, 0) else {
            unreachable!("fulu_block builds a fulu block");
        };
        inner.message.parent_root = parent_root;
        let unsigned = SignedBeaconBlock::Fulu(inner);
        let block = sign_block(unsigned, &parent, &config, proposer);

        assert_eq!(
            stateful_checks(&store, &block, block.message_hash_tree_root()),
            Outcome::Queue(QueueReason::ParentNotReady)
        );
    }

    /// A parent on a fork that split off below the finalized block, once
    /// finality has pruned `LiveChain` below that block's own slot: the walk
    /// from the parent falls off the pruned tree, and that must still be the
    /// specification's REJECT rather than the IGNORE a missing row gets
    /// above the finalized block.
    #[test]
    fn a_block_on_a_fork_from_below_the_finalized_block_is_rejected() {
        let PastAFork {
            store, fork_tip, ..
        } = store_finalized_past_a_fork();
        let config = store.config();
        let proposer: ValidatorIndex = 3;
        let (parent_slot, _) = store.block_entry(&fork_tip).expect("stored parent");
        let parent = fulu_parent_at(proposer, parent_slot);
        store.cache_state(CacheKey::BlockState(fork_tip), Arc::new(parent.clone()));

        let block = signed_child(&parent, fork_tip, proposer, &config);
        assert_eq!(
            stateful_checks(&store, &block, block.message_hash_tree_root()),
            Outcome::Reject(RejectReason::FinalizedNotAncestor)
        );
    }

    /// The late-invalidation case the IGNORE exists for, on a store where
    /// pruning has run too: the parent descends from the finalized block but
    /// `invalidate_subtree` has since deleted its `LiveChain` row, above the
    /// slot pruning reaches.
    #[test]
    fn a_child_of_a_parent_invalidated_above_the_finalized_block_is_queued() {
        let PastAFork {
            mut store,
            descendant,
            ..
        } = store_finalized_past_a_fork();
        let config = store.config();
        let proposer: ValidatorIndex = 3;
        let (parent_slot, _) = store.block_entry(&descendant).expect("stored parent");
        let parent = fulu_parent_at(proposer, parent_slot);
        store.cache_state(CacheKey::BlockState(descendant), Arc::new(parent.clone()));

        let block = signed_child(&parent, descendant, proposer, &config);
        let block_root = block.message_hash_tree_root();
        // With the parent's row in place, the same block passes outright.
        assert_eq!(stateful_checks(&store, &block, block_root), Outcome::Accept);

        assert_eq!(fork_choice::invalidate_subtree(&mut store, descendant), 1);
        assert_eq!(
            stateful_checks(&store, &block, block_root),
            Outcome::Queue(QueueReason::ParentNotReady)
        );
    }
}
