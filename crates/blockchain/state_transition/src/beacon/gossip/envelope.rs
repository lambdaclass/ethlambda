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
//!   specification's "MAY be queued").
//! - The finalized-slot `IGNORE` runs in [`cheap_checks`], ahead of the block
//!   lookups the specification places before it. Both outcomes are `IGNORE`, so
//!   only the metric label can differ, and an envelope too old to matter is
//!   not parked waiting for its block.

use std::num::NonZeroUsize;

use ethlambda_storage::CacheKey;
use lru::LruCache;

use super::column::judgeable_block_gloas;
use super::{
    IgnoreReason, Outcome, RejectReason, execution_requests_within_limits, finalized_start_slot,
};
use crate::beacon::containers::{SignedBeaconBlock, gloas};
use crate::beacon::fork_choice::Store;
use crate::beacon::lean_boundary::lean_block_unreachable;
use crate::beacon::preset;
use crate::beacon::primitives::{HashTreeRoot as _, Root};
use crate::beacon::stf::gloas::verify_execution_payload_envelope_signature;

/// The first valid envelope per `(block root, builder index)`: the
/// specification's `seen.execution_payload_envelopes`.
///
/// Bounded by capacity rather than pruned on finality, like [`super::SeenBlocks`].
pub struct SeenEnvelopes(LruCache<(Root, u64), ()>);

impl SeenEnvelopes {
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self(LruCache::new(capacity))
    }

    pub fn contains(&self, block_root: Root, builder_index: u64) -> bool {
        self.0.contains(&(block_root, builder_index))
    }

    /// Record the first valid envelope for its key. Returns `false`, changing
    /// nothing, when one is already recorded.
    pub fn record(&mut self, block_root: Root, builder_index: u64) -> bool {
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
    Ok(())
}

/// The rules that need the envelope's block and its post-state, then the
/// signature. Runs on a blocking thread.
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
    // [REJECT] The execution request counts are within their limits.
    if !execution_requests_within_limits(&message.execution_requests) {
        return Outcome::Reject(RejectReason::OperationLimit);
    }
    // [REJECT] The number of withdrawals is within the limit.
    if payload.withdrawals.len() > preset::MAX_WITHDRAWALS_PER_PAYLOAD {
        return Outcome::Reject(RejectReason::TooManyWithdrawals);
    }
    // [REJECT] The envelope signature is valid. Read off the block's cached
    // post-state, never rebuilt: a miss would stall the verdict gossipsub
    // waits on.
    let Some(state) = store.cached_state(CacheKey::BlockState(message.beacon_block_root)) else {
        return Outcome::Ignore(IgnoreReason::StateUnavailable);
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
    use super::*;

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
