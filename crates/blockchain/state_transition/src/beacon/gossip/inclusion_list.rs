//! Gossip validation for the heze `inclusion_list` topic: an inclusion list
//! committee member's `SignedInclusionList` (EIP-7805).
//!
//! The rules are the specification's `validate_inclusion_list_gossip`
//! (`specs/heze/p2p-interface.md`), split like [`super::proposer_preferences`]:
//! [`cheap_checks`] reads the message, the clock and the seen counts;
//! [`stateful_checks`] reads the dependent block and a state for the
//! committee, then verifies the signature. The caller records the list in
//! `seen` and stores it with `InclusionListStore::process_inclusion_list` on
//! `Accept`.
//!
//! Deliberate departures from the specification, the ones
//! `proposer_preferences` makes for the same reasons:
//!
//! - Never queues: an unseen dependent block is IGNORE.
//! - The committee's state is read from caches, never rebuilt from disk (see
//!   `inclusion_list::committee_state`); a miss is IGNORE.

use std::num::NonZeroUsize;

use lru::LruCache;

use super::proposer_preferences::is_valid_dependent_root;
use super::{IgnoreReason, Outcome, RejectReason, is_current_slot};
use crate::beacon::containers::heze::SignedInclusionList;
use crate::beacon::fork_choice::{Store, compute_shuffling_dependent_slot};
use crate::beacon::helpers::misc::compute_epoch_at_slot;
use crate::beacon::inclusion_list::{
    committee_state, get_inclusion_list_committee, is_valid_inclusion_list_signature,
    transactions_size,
};
use crate::beacon::primitives::{Root, Slot, ValidatorIndex};

/// The most valid lists the topic forwards per `(slot, dependent_root,
/// validator)`: a second, different one is what reveals an equivocator.
const MAX_LISTS_PER_MEMBER: u8 = 2;

/// How many valid lists each `(slot, dependent_root, validator)` has sent:
/// the specification's `seen.inclusion_list_counts`.
///
/// Bounded the same way as [`super::SeenBlocks`].
pub struct SeenInclusionLists(LruCache<(Slot, Root, ValidatorIndex), u8>);

impl SeenInclusionLists {
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self(LruCache::new(capacity))
    }

    pub fn count(&self, slot: Slot, dependent_root: Root, validator_index: ValidatorIndex) -> u8 {
        self.0
            .peek(&(slot, dependent_root, validator_index))
            .copied()
            .unwrap_or(0)
    }

    /// Counts one more valid list for its key.
    pub fn record(&mut self, signed: &SignedInclusionList) {
        let message = &signed.message;
        let key = (
            message.slot,
            message.dependent_root,
            message.validator_index,
        );
        let count = self.0.get(&key).copied().unwrap_or(0);
        self.0.put(key, count.saturating_add(1));
    }
}

/// The rules that read only the message, the clock and the seen counts.
pub fn cheap_checks(
    seen: &SeenInclusionLists,
    store: &Store,
    signed: &SignedInclusionList,
    now_ms: u64,
) -> Result<(), Outcome> {
    let config = store.config();
    let inclusion_list = &signed.message;
    // [IGNORE] This is the first or second valid message from this validator.
    let count = seen.count(
        inclusion_list.slot,
        inclusion_list.dependent_root,
        inclusion_list.validator_index,
    );
    if count >= MAX_LISTS_PER_MEMBER {
        return Err(Outcome::Ignore(IgnoreReason::AlreadySeen));
    }
    // [IGNORE] The inclusion list's slot is for the current slot.
    if !is_current_slot(&config, inclusion_list.slot, now_ms) {
        return Err(Outcome::Ignore(IgnoreReason::NotCurrentSlot));
    }
    let size = transactions_size(inclusion_list);
    // [IGNORE] The size of inclusion list transactions must be non-empty.
    if size == 0 {
        return Err(Outcome::Ignore(IgnoreReason::EmptyInclusionList));
    }
    // [REJECT] The size of inclusion list transactions must not exceed the
    // maximum size.
    if size > config.max_transactions_bytes_per_inclusion_list {
        return Err(Outcome::Reject(RejectReason::InclusionListTooLarge));
    }
    // [REJECT] Every transaction must be non-empty.
    if inclusion_list.transactions.iter().any(|tx| tx.is_empty()) {
        return Err(Outcome::Reject(RejectReason::EmptyTransaction));
    }
    Ok(())
}

/// The rules that need the dependent block and a state, then the signature.
/// Runs on a blocking thread.
pub fn stateful_checks(store: &Store, signed: &SignedInclusionList) -> Outcome {
    match stateful_rules(store, signed) {
        Ok(()) => Outcome::Accept,
        Err(outcome) => outcome,
    }
}

fn stateful_rules(store: &Store, signed: &SignedInclusionList) -> Result<(), Outcome> {
    let inclusion_list = &signed.message;
    let dependent_root = inclusion_list.dependent_root;
    // [IGNORE] The dependent block has been seen (never queued).
    let (block_slot, _) = store
        .block_entry(&dependent_root)
        .ok_or(Outcome::Ignore(IgnoreReason::UnknownBlock))?;
    // [IGNORE] The dependent block passes validation, i.e. has a post-state.
    if !store.has_state(&dependent_root).unwrap_or(false) {
        return Err(Outcome::Ignore(IgnoreReason::StateUnavailable));
    }
    // [REJECT] The dependent block's slot is not after the shuffling
    // dependent slot.
    let epoch = compute_epoch_at_slot(inclusion_list.slot);
    let dependent_slot = compute_shuffling_dependent_slot(epoch);
    if block_slot > dependent_slot {
        return Err(Outcome::Reject(RejectReason::DependentRootTooLate));
    }
    // [IGNORE] The dependent block is a possible dependent block for the
    // committee lookahead.
    if !is_valid_dependent_root(store, dependent_root, dependent_slot) {
        return Err(Outcome::Ignore(IgnoreReason::ImpossibleDependentRoot));
    }

    let state = committee_state(store, inclusion_list.slot, dependent_root)
        .ok_or(Outcome::Ignore(IgnoreReason::StateUnavailable))?;
    // [REJECT] The includer is a member of the committee.
    let committee =
        get_inclusion_list_committee(&state, inclusion_list.slot, &*store.committee_cache())
            .map_err(|_| Outcome::Ignore(IgnoreReason::StateUnavailable))?;
    if !committee.contains(&inclusion_list.validator_index) {
        return Err(Outcome::Reject(RejectReason::NotInInclusionListCommittee));
    }
    // [REJECT] The signature is valid.
    if !is_valid_inclusion_list_signature(&state, signed) {
        return Err(Outcome::Reject(RejectReason::BadSignature));
    }
    Ok(())
}

/// [`cheap_checks`] then [`stateful_checks`]: the specification's
/// `validate_inclusion_list_gossip`. The caller records the list in `seen`
/// and the inclusion list store on [`Outcome::Accept`].
pub fn validate(
    seen: &SeenInclusionLists,
    store: &Store,
    signed: &SignedInclusionList,
    now_ms: u64,
) -> Outcome {
    if let Err(outcome) = cheap_checks(seen, store, signed, now_ms) {
        return outcome;
    }
    stateful_checks(store, signed)
}
