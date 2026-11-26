//! Gossip validation for the gloas `execution_payload` topic: a builder's
//! `SignedExecutionPayloadEnvelope`, revealing the payload its bid committed to.
//!
//! The rules are the specification's `validate_execution_payload_envelope_gossip`
//! (`specs/gloas/p2p-interface.md`), split the way [`super::column`]'s are:
//! [`cheap_checks`] reads only the message, the seen cache and the store's
//! finalized checkpoint, so the p2p actor runs it inline; [`stateful_checks`]
//! reads the envelope's block and its post-state and verifies the signature, so
//! it runs on a blocking thread.
//!
//! Deliberate departures from the specification:
//!
//! - A block seen without a post-state is [`Outcome::Queue`] where the
//!   specification rejects it, the same deviation every other topic makes until
//!   a bad-block cache exists. A block never seen is `Queue` too (the
//!   specification's "MAY be queued"), and so is a block whose post-state
//!   exists but is not cached, since the chain actor verifies the signature
//!   itself.
//! - The block-independent limits (withdrawal and request counts) run in
//!   [`cheap_checks`], so a message that no block could make valid is never
//!   queued.
//! - The finalized-slot `IGNORE` runs in [`cheap_checks`], ahead of the block
//!   lookups the specification places before it. Both outcomes are `IGNORE`, so
//!   only the metric label can differ, and an envelope too old to matter is
//!   not parked waiting for its block.
//! - [`cheap_checks`] rejects a payload that is not the container its slot
//!   calls for: the specification's before `HEZE_FORK_EPOCH`, the one with
//!   `dependency_witnesses` from that epoch on, and the one with
//!   `dependency_proof` from `ISTAR_FORK_EPOCH` on. It also rejects one
//!   whose list holds an item of any length but
//!   [`LEAN_SPHINCS_SIGNATURE_SIZE`]. The specification's payload has
//!   neither field, so it has no rule for them. The proof is not looked at,
//!   and its size bound is the container's: a payload over it does not
//!   decode.

use std::num::NonZeroUsize;

use ethlambda_storage::CacheKey;
use lru::LruCache;

use super::column::judgeable_block_gloas;
use super::{
    IgnoreReason, Outcome, QueueReason, RejectReason, execution_requests_within_limits,
    finalized_start_slot,
};
use crate::beacon::containers::gloas::BuilderIndex;
use crate::beacon::containers::{SignedBeaconBlock, gloas};
use crate::beacon::fork_choice::Store;
use crate::beacon::helpers::misc::compute_epoch_at_slot;
use crate::beacon::lean_boundary::lean_block_unreachable;
use crate::beacon::preset;
use crate::beacon::primitives::{HashTreeRoot as _, Root};
use crate::beacon::stf::gloas::verify_execution_payload_envelope_signature;

/// The length in bytes of a leanSPHINCS signature, which is what each of a
/// payload's dependency witnesses is.
///
/// Only the length is judged here: the execution client verifies the
/// signatures themselves when it is asked about the payload.
pub const LEAN_SPHINCS_SIGNATURE_SIZE: usize = 7_740;

/// The first valid envelope per `(block root, builder index)`: the
/// specification's `seen.execution_payload_envelopes`.
///
/// Bounded by capacity rather than pruned on finality, like [`super::SeenBlocks`].
pub struct SeenEnvelopes(LruCache<(Root, BuilderIndex), ()>);

impl SeenEnvelopes {
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self(LruCache::new(capacity))
    }

    pub fn contains(&self, block_root: Root, builder_index: BuilderIndex) -> bool {
        self.0.contains(&(block_root, builder_index))
    }

    /// Record the first valid envelope for its key. Returns `false`, changing
    /// nothing, when one is already recorded.
    pub fn record(&mut self, block_root: Root, builder_index: BuilderIndex) -> bool {
        if self.0.contains(&(block_root, builder_index)) {
            return false;
        }
        self.0.put((block_root, builder_index), ());
        true
    }
}

/// The rules that read only the message, the seen cache and the store's
/// finalized checkpoint. The caller records the envelope in `seen` once the
/// whole rule answers [`Outcome::Accept`].
pub fn cheap_checks(
    seen: &SeenEnvelopes,
    store: &Store,
    envelope: &gloas::SignedExecutionPayloadEnvelope,
) -> Result<(), Outcome> {
    let message = &envelope.message;
    // [IGNORE] The node has not seen another valid envelope for this block root
    // from this builder.
    if seen.contains(message.beacon_block_root, message.builder_index) {
        return Err(Outcome::Ignore(IgnoreReason::AlreadySeen));
    }
    // [IGNORE] The envelope is from a slot greater than or equal to the latest
    // finalized slot. See the module documentation for its position.
    if message.payload.slot_number < finalized_start_slot(store) {
        return Err(Outcome::Ignore(IgnoreReason::Finalized));
    }
    // [REJECT] The number of withdrawals is within the limit, and [REJECT] the
    // execution request counts are within theirs. Neither depends on the
    // block, so both run before anything can be queued: the lists are
    // progressive, and without this only the gossip size cap would bound what
    // a parked envelope holds. The specification checks them after the block
    // lookups; an envelope invalid under every block is rejected either way.
    if message.payload.withdrawals.len() > preset::max_withdrawals_per_payload() {
        return Err(Outcome::Reject(RejectReason::TooManyWithdrawals));
    }
    if !execution_requests_within_limits(&message.execution_requests) {
        return Err(Outcome::Reject(RejectReason::OperationLimit));
    }
    // [REJECT] The payload is the container its slot calls for: it has the
    // dependency witnesses field exactly from `HEZE_FORK_EPOCH` up to
    // `ISTAR_FORK_EPOCH`, and the dependency proof field exactly from the
    // latter on. The payload names its own slot, so this needs no block
    // either. The proof itself is the execution client's to read.
    let witnesses = &message.payload.dependency_witnesses;
    let payload_epoch = compute_epoch_at_slot(message.payload.slot_number);
    if message.payload.container() != Some(store.config().payload_container(payload_epoch)) {
        return Err(Outcome::Reject(RejectReason::PayloadContainer));
    }
    // [REJECT] Every dependency witness is exactly one leanSPHINCS signature
    // long. No block can make a witness of another length valid, so, like the
    // limits above, this runs before anything can be queued, and before the
    // execution client is asked to verify the signatures.
    if witnesses
        .iter()
        .flatten()
        .any(|witness| witness.len() != LEAN_SPHINCS_SIGNATURE_SIZE)
    {
        return Err(Outcome::Reject(RejectReason::DependencyWitnessSize));
    }
    Ok(())
}

/// The rules that need the envelope's block and its post-state, then the
/// signature. Runs on a blocking thread.
///
/// A block that is known and has a post-state, but whose state is not in the
/// cache this reads, is [`Outcome::Queue`] ([`QueueReason::StateNotCached`]),
/// not an ignore. The state is never rebuilt here, since a miss would stall
/// the verdict gossipsub waits on, and a block imported moments ago is
/// exactly when it is missing. The chain actor fully verifies every envelope
/// it receives (bid consistency, the builder's signature against the block's
/// post-state before parking it, then `verify_execution_payload_envelope`),
/// so forwarding it without propagating is safe, whereas dropping it stalls
/// sync: a fetched envelope for a block the actor is holding would be lost
/// until the next per-slot re-ask.
pub fn stateful_checks(store: &Store, envelope: &gloas::SignedExecutionPayloadEnvelope) -> Outcome {
    let message = &envelope.message;
    let payload = &message.payload;
    // [IGNORE] The envelope's block has been seen (MAY queue), and [REJECT] it
    // passes validation: see the module documentation for the latter.
    let block = match judgeable_block_gloas(store, &message.beacon_block_root) {
        Ok(block) => block,
        Err(outcome) => return outcome,
    };
    let block = match &block {
        SignedBeaconBlock::Gloas(block) => &block.message,
        // A block of any other fork carries no bid, so no envelope is valid
        // for it.
        SignedBeaconBlock::Phase0(_)
        | SignedBeaconBlock::Altair(_)
        | SignedBeaconBlock::Bellatrix(_)
        | SignedBeaconBlock::Capella(_)
        | SignedBeaconBlock::Deneb(_)
        | SignedBeaconBlock::Electra(_)
        | SignedBeaconBlock::Fulu(_) => return Outcome::Reject(RejectReason::BlockNotGloas),
        SignedBeaconBlock::Lean(_) => lean_block_unreachable("envelope::stateful_checks"),
    };
    let bid = &block.body.signed_execution_payload_bid.message;

    // [REJECT] The block's slot matches the payload's slot number.
    if block.slot != payload.slot_number {
        return Outcome::Reject(RejectReason::SlotMismatch);
    }
    // [REJECT] The envelope is from the builder committed to by the bid.
    if message.builder_index != bid.builder_index {
        return Outcome::Reject(RejectReason::BuilderIndexMismatch);
    }
    // [REJECT] The payload's block hash matches the bid's block hash.
    if payload.block_hash != bid.block_hash {
        return Outcome::Reject(RejectReason::BlockHashMismatch);
    }
    // [REJECT] The execution requests root matches the bid's.
    if message.execution_requests.hash_tree_root() != bid.execution_requests_root {
        return Outcome::Reject(RejectReason::ExecutionRequestsRootMismatch);
    }
    // The request-count and withdrawal-count limits ran in `cheap_checks`.
    // [REJECT] The envelope signature is valid. Read off the block's cached
    // post-state, never rebuilt: a miss would stall the verdict gossipsub
    // waits on.
    let Some(state) = store.cached_state(CacheKey::BlockState(message.beacon_block_root)) else {
        return Outcome::Queue(QueueReason::StateNotCached);
    };
    // An error (a builder the state has no entry for) is a signature that
    // cannot be valid.
    if !matches!(
        verify_execution_payload_envelope_signature(&state, envelope),
        Ok(true)
    ) {
        return Outcome::Reject(RejectReason::BadSignature);
    }
    Outcome::Accept
}

/// [`cheap_checks`] then [`stateful_checks`], for callers with no reason to
/// split them, such as the spec vectors: the specification's
/// `validate_execution_payload_envelope_gossip`. The caller records the
/// envelope in `seen` on [`Outcome::Accept`].
pub fn validate(
    seen: &SeenEnvelopes,
    store: &Store,
    envelope: &gloas::SignedExecutionPayloadEnvelope,
) -> Outcome {
    if let Err(outcome) = cheap_checks(seen, store, envelope) {
        return outcome;
    }
    stateful_checks(store, envelope)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::beacon::containers::electra;
    use crate::beacon::gossip::test_support::{fulu_parent, seen_envelopes, store};
    use crate::beacon::primitives::Slot;

    /// A fulu block at `slot`: a block of the wrong fork for either topic.
    fn fulu_block(slot: Slot) -> SignedBeaconBlock {
        SignedBeaconBlock::Fulu(electra::SignedBeaconBlock {
            message: electra::BeaconBlock {
                slot,
                proposer_index: 0,
                parent_root: Root::ZERO,
                state_root: Root::ZERO,
                body: electra::BeaconBlockBody::empty(),
            },
            signature: Default::default(),
        })
    }

    const BLOCK_ROOT: Root = Root::repeat_byte(7);

    fn withdrawal() -> crate::beacon::containers::capella::Withdrawal {
        crate::beacon::containers::capella::Withdrawal {
            index: 0,
            validator_index: 0,
            address: Default::default(),
            amount: 0,
        }
    }

    /// An envelope naming `BLOCK_ROOT`, with `withdrawals` withdrawals in its
    /// payload. Nothing else in it is meant to be valid.
    fn envelope(slot: Slot, withdrawals: usize) -> gloas::SignedExecutionPayloadEnvelope {
        let payload = gloas::ExecutionPayload {
            parent_hash: Default::default(),
            fee_recipient: Default::default(),
            state_root: Default::default(),
            receipts_root: Default::default(),
            logs_bloom: vec![0u8; preset::BYTES_PER_LOGS_BLOOM]
                .try_into()
                .expect("an exact-length bloom"),
            prev_randao: Default::default(),
            block_number: 0,
            gas_limit: 0,
            gas_used: 0,
            timestamp: 0,
            extra_data: Default::default(),
            base_fee_per_gas: Default::default(),
            block_hash: Default::default(),
            transactions: Default::default(),
            withdrawals: vec![withdrawal(); withdrawals]
                .try_into()
                .expect("progressive lists are unbounded"),
            blob_gas_used: 0,
            excess_blob_gas: 0,
            block_access_list: Default::default(),
            slot_number: slot,
            dependency_witnesses: Default::default(),
            dependency_proof: Default::default(),
        };
        gloas::SignedExecutionPayloadEnvelope {
            message: gloas::ExecutionPayloadEnvelope {
                payload,
                execution_requests: Default::default(),
                builder_index: 0,
                beacon_block_root: BLOCK_ROOT,
                parent_beacon_block_root: Root::ZERO,
            },
            signature: Default::default(),
        }
    }

    #[test]
    fn too_many_withdrawals_are_rejected_before_any_block_lookup() {
        let store = store(0);
        let envelope = envelope(5, preset::max_withdrawals_per_payload() + 1);
        assert_eq!(
            cheap_checks(&seen_envelopes(), &store, &envelope),
            Err(Outcome::Reject(RejectReason::TooManyWithdrawals))
        );
        // The block is unknown, which would queue a well-formed envelope.
        assert_eq!(
            validate(&seen_envelopes(), &store, &envelope),
            Outcome::Reject(RejectReason::TooManyWithdrawals)
        );
    }

    #[test]
    fn too_many_requests_are_rejected_before_any_block_lookup() {
        let store = store(0);
        let mut envelope = envelope(5, 0);
        envelope.message.execution_requests.builder_exits =
            vec![Default::default(); preset::MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD as usize + 1]
                .try_into()
                .expect("progressive lists are unbounded");
        assert_eq!(
            validate(&seen_envelopes(), &store, &envelope),
            Outcome::Reject(RejectReason::OperationLimit)
        );
    }

    /// `store(0)` with payloads carrying dependency witnesses from genesis.
    fn store_with_dependency_witnesses() -> Store {
        let mut store = store(0);
        let mut config = (*store.config()).clone();
        config.heze_fork_epoch = 0;
        store.replace_config(config);
        store
    }

    #[test]
    fn a_payload_with_the_dependency_witnesses_field_is_rejected_before_its_epoch() {
        // `store(0)` schedules no epoch for the field, so no payload has it.
        let store = store(0);
        let mut envelope = envelope(5, 0);
        envelope.message.payload.dependency_witnesses = Some(Default::default());
        assert_eq!(
            cheap_checks(&seen_envelopes(), &store, &envelope),
            Err(Outcome::Reject(RejectReason::PayloadContainer)),
        );
        // The block is unknown, which would queue a well-formed envelope.
        assert_eq!(
            validate(&seen_envelopes(), &store, &envelope),
            Outcome::Reject(RejectReason::PayloadContainer)
        );
    }

    #[test]
    fn a_payload_without_the_dependency_witnesses_field_is_rejected_from_its_epoch() {
        let store = store_with_dependency_witnesses();
        let envelope = envelope(5, 0);
        assert_eq!(envelope.message.payload.dependency_witnesses, None);
        assert_eq!(
            cheap_checks(&seen_envelopes(), &store, &envelope),
            Err(Outcome::Reject(RejectReason::PayloadContainer)),
        );
    }

    #[test]
    fn the_dependency_witnesses_field_is_judged_by_the_payloads_own_slot() {
        let mut store = store(0);
        let mut config = (*store.config()).clone();
        config.heze_fork_epoch = 1;
        store.replace_config(config);
        let first_slot_with_the_field = preset::slots_per_epoch();

        let mut before = envelope(first_slot_with_the_field - 1, 0);
        assert_eq!(cheap_checks(&seen_envelopes(), &store, &before), Ok(()));
        before.message.payload.dependency_witnesses = Some(Default::default());
        assert_eq!(
            cheap_checks(&seen_envelopes(), &store, &before),
            Err(Outcome::Reject(RejectReason::PayloadContainer)),
        );

        let mut from = envelope(first_slot_with_the_field, 0);
        assert_eq!(
            cheap_checks(&seen_envelopes(), &store, &from),
            Err(Outcome::Reject(RejectReason::PayloadContainer)),
        );
        from.message.payload.dependency_witnesses = Some(Default::default());
        assert_eq!(cheap_checks(&seen_envelopes(), &store, &from), Ok(()));
    }

    /// `store(0)` with payloads carrying dependency witnesses from genesis
    /// and a dependency proof from epoch 1.
    fn store_with_a_dependency_proof_from_epoch_one() -> Store {
        let mut store = store(0);
        let mut config = (*store.config()).clone();
        config.heze_fork_epoch = 0;
        config.istar_fork_epoch = 1;
        store.replace_config(config);
        store
    }

    #[test]
    fn a_payload_is_the_container_with_the_proof_exactly_from_its_epoch() {
        let store = store_with_a_dependency_proof_from_epoch_one();
        let first_slot_with_the_proof = preset::slots_per_epoch();
        let with_proof = |slot| {
            let mut envelope = envelope(slot, 0);
            envelope.message.payload.dependency_proof = Some(Default::default());
            envelope
        };
        let with_witnesses = |slot| {
            let mut envelope = envelope(slot, 0);
            envelope.message.payload.dependency_witnesses = Some(Default::default());
            envelope
        };
        let checked = |envelope| cheap_checks(&seen_envelopes(), &store, &envelope);
        let wrong_container = Err(Outcome::Reject(RejectReason::PayloadContainer));

        // Before the epoch: the witness list, and no proof.
        let before = first_slot_with_the_proof - 1;
        assert_eq!(checked(with_witnesses(before)), Ok(()));
        assert_eq!(checked(with_proof(before)), wrong_container);

        // From it on: the proof, and neither of the earlier containers.
        let from = first_slot_with_the_proof;
        assert_eq!(checked(with_proof(from)), Ok(()));
        assert_eq!(checked(with_witnesses(from)), wrong_container);
        assert_eq!(checked(envelope(from, 0)), wrong_container);
    }

    #[test]
    fn a_payload_with_both_witnesses_and_a_proof_is_rejected() {
        let store = store_with_a_dependency_proof_from_epoch_one();
        let wrong_container = Err(Outcome::Reject(RejectReason::PayloadContainer));
        // At a slot of either epoch: no container has both fields.
        for slot in [0, preset::slots_per_epoch()] {
            let mut envelope = envelope(slot, 0);
            envelope.message.payload.dependency_witnesses = Some(Default::default());
            envelope.message.payload.dependency_proof = Some(Default::default());
            assert_eq!(
                cheap_checks(&seen_envelopes(), &store, &envelope),
                wrong_container
            );
        }
    }

    #[test]
    fn a_dependency_proof_is_not_parsed_by_the_cheap_checks() {
        let store = store_with_a_dependency_proof_from_epoch_one();
        // Nothing a prover would write: bytes within the bound pass whatever
        // they are.
        for proof in [vec![], vec![0xff], vec![0x00; 7_741]] {
            let mut envelope = envelope(preset::slots_per_epoch(), 0);
            envelope.message.payload.dependency_proof =
                Some(proof.try_into().expect("within the bound"));
            assert_eq!(cheap_checks(&seen_envelopes(), &store, &envelope), Ok(()));
            assert_eq!(
                validate(&seen_envelopes(), &store, &envelope),
                Outcome::Queue(QueueReason::BlockUnknown)
            );
        }
    }

    #[test]
    fn a_dependency_witness_of_the_wrong_size_is_rejected_before_any_block_lookup() {
        let store = store_with_dependency_witnesses();
        let well_sized = gloas::DependencyWitness::from(vec![0u8; LEAN_SPHINCS_SIGNATURE_SIZE]);
        for wrong_size in [
            0,
            LEAN_SPHINCS_SIGNATURE_SIZE - 1,
            LEAN_SPHINCS_SIGNATURE_SIZE + 1,
        ] {
            // The wrong-sized witness is the second of two, so one good item
            // does not vouch for the list.
            let mut envelope = envelope(5, 0);
            envelope.message.payload.dependency_witnesses =
                Some(vec![well_sized.clone(), vec![0u8; wrong_size].into()].into());
            assert_eq!(
                cheap_checks(&seen_envelopes(), &store, &envelope),
                Err(Outcome::Reject(RejectReason::DependencyWitnessSize)),
                "a witness of {wrong_size} bytes"
            );
            // The block is unknown, which would queue a well-formed envelope.
            assert_eq!(
                validate(&seen_envelopes(), &store, &envelope),
                Outcome::Reject(RejectReason::DependencyWitnessSize)
            );
        }
    }

    #[test]
    fn dependency_witnesses_of_the_signature_size_pass_the_cheap_checks() {
        let store = store_with_dependency_witnesses();
        let mut envelope = envelope(5, 0);
        envelope.message.payload.dependency_witnesses = Some(
            vec![gloas::DependencyWitness::from(vec![0u8; LEAN_SPHINCS_SIGNATURE_SIZE]); 2].into(),
        );
        assert_eq!(cheap_checks(&seen_envelopes(), &store, &envelope), Ok(()));
        assert_eq!(
            validate(&seen_envelopes(), &store, &envelope),
            Outcome::Queue(QueueReason::BlockUnknown)
        );
    }

    #[test]
    fn an_envelope_within_the_limits_for_an_unseen_block_is_queued() {
        let store = store(0);
        let envelope = envelope(5, preset::max_withdrawals_per_payload());
        assert_eq!(
            validate(&seen_envelopes(), &store, &envelope),
            Outcome::Queue(QueueReason::BlockUnknown)
        );
    }

    #[test]
    fn an_envelope_whose_block_has_no_post_state_is_queued_not_rejected() {
        let mut store = store(0);
        store
            .insert_pending_block(BLOCK_ROOT, fulu_block(5))
            .expect("insert pending block");
        assert_eq!(
            validate(&seen_envelopes(), &store, &envelope(5, 0)),
            Outcome::Queue(QueueReason::BlockNotReady)
        );
    }

    /// A known gloas block with a post-state on disk, but with that state
    /// evicted from the cache the checks read, must be forwarded (queued), not
    /// dropped: the observed stall was a fetched envelope lost this way.
    #[test]
    fn an_envelope_whose_block_state_is_not_cached_is_queued_not_ignored() {
        let envelope = envelope(5, 0);
        let mut block = gloas::SignedBeaconBlock::default();
        block.message.slot = 5;
        block
            .message
            .body
            .signed_execution_payload_bid
            .message
            .execution_requests_root = envelope.message.execution_requests.hash_tree_root();
        let mut store = store(0);
        store
            .insert_pending_block(BLOCK_ROOT, SignedBeaconBlock::Gloas(block))
            .expect("insert the block");
        // The block's post-state names the block in its header, and the store
        // keys a state's row by that header's slot: a state for the slot-5
        // block must say slot 5 there, or a read after the writer flushes it
        // looks under another key.
        let mut state = fulu_parent(3);
        if let crate::beacon::containers::BeaconState::Fulu(inner) = &mut state {
            inner.latest_block_header.slot = 5;
        }
        store
            .insert_state(BLOCK_ROOT, state.clone())
            .expect("insert the state");
        // Churn the cache past its capacity with other keys until the block's
        // state is evicted; the pending-state buffer still answers `has_state`.
        let filler = Arc::new(state);
        for epoch in 0..1024 {
            store.cache_state(
                CacheKey::CheckpointState {
                    epoch,
                    root: Root::ZERO,
                },
                filler.clone(),
            );
        }
        assert!(
            store
                .cached_state(CacheKey::BlockState(BLOCK_ROOT))
                .is_none()
        );
        assert_eq!(
            validate(&seen_envelopes(), &store, &envelope),
            Outcome::Queue(QueueReason::StateNotCached)
        );
    }

    #[test]
    fn an_envelope_naming_a_non_gloas_block_is_rejected() {
        let mut store = store(0);
        store
            .insert_pending_block(BLOCK_ROOT, fulu_block(5))
            .expect("insert the block");
        store
            .insert_state(BLOCK_ROOT, fulu_parent(3))
            .expect("insert the state");
        assert_eq!(
            validate(&seen_envelopes(), &store, &envelope(5, 0)),
            Outcome::Reject(RejectReason::BlockNotGloas)
        );
    }

    #[test]
    fn an_envelope_key_records_once_per_root_and_builder() {
        let mut seen = SeenEnvelopes::new(NonZeroUsize::new(4).expect("non-zero"));
        let root = Root::repeat_byte(1);
        assert!(!seen.contains(root, 7));
        assert!(seen.record(root, 7));
        assert!(seen.contains(root, 7));
        assert!(!seen.record(root, 7));
        assert!(seen.record(root, 8));
        assert!(seen.record(Root::repeat_byte(2), 7));
    }

    #[test]
    fn the_seen_envelopes_forget_their_oldest_entry_past_capacity() {
        let mut seen = SeenEnvelopes::new(NonZeroUsize::new(1).expect("non-zero"));
        seen.record(Root::repeat_byte(1), 0);
        seen.record(Root::repeat_byte(2), 0);
        assert!(!seen.contains(Root::repeat_byte(1), 0));
    }
}
