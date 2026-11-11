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
    let config = store.config();
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
    let committee = get_inclusion_list_committee(
        &config,
        &state,
        inclusion_list.slot,
        &*store.committee_cache(),
    )
    .map_err(|_| Outcome::Ignore(IgnoreReason::StateUnavailable))?;
    if !committee.contains(&inclusion_list.validator_index) {
        return Err(Outcome::Reject(RejectReason::NotInInclusionListCommittee));
    }
    // [REJECT] The signature is valid.
    if !is_valid_inclusion_list_signature(&config, &state, signed) {
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ethlambda_storage::ForkCheckpoints;
    use ethlambda_storage::backend::InMemoryBackend;
    use ethlambda_types::checkpoint::Checkpoint;

    use super::*;
    use crate::beacon::config::Config;
    use crate::beacon::constants::FAR_FUTURE_EPOCH;
    use crate::beacon::containers::BeaconState;
    use crate::beacon::containers::gloas::Transaction;
    use crate::beacon::containers::heze::InclusionList;
    use crate::beacon::fork::ForkName;
    use crate::beacon::gossip::test_support::{GENESIS_TIME, empty_block};
    use crate::beacon::helpers::misc::compute_start_slot_at_epoch;
    use crate::beacon::helpers::test_state::{sign_for, with_signing_validators_at};
    use crate::beacon::inclusion_list::inclusion_list_signing_root;
    use crate::beacon::preset::SLOTS_PER_EPOCH;

    const HEAD: Root = Root::repeat_byte(0x50);
    /// The shuffling dependent block of the fork's first epoch: the head's
    /// parent, at the slot below the head's epoch.
    const DEPENDENT: Root = Root::repeat_byte(0x31);
    const FORK_EPOCH: u64 = 2;

    /// A heze chain one epoch before `EIP8453_FORK_EPOCH`: its head opens
    /// epoch 1, and the head's parent is the dependent block of epoch 2's
    /// committees. The head's post-state, with real keys, is what
    /// `committee_state` hands a list of epoch 2 until a fork block imports.
    fn heze_head_before_the_fork() -> (Store, BeaconState) {
        let mut config = Config::active();
        for fork in [
            ForkName::Altair,
            ForkName::Bellatrix,
            ForkName::Capella,
            ForkName::Deneb,
            ForkName::Electra,
            ForkName::Fulu,
            ForkName::Gloas,
            ForkName::Heze,
        ] {
            config = config.with_fork_epoch(fork, 0);
        }
        let config = config.with_fork_epoch(ForkName::Eip8453, FORK_EPOCH);
        let head_slot = SLOTS_PER_EPOCH;
        let mut state = with_signing_validators_at(ForkName::Heze, 256);
        let BeaconState::Heze(inner) = &mut state else {
            unreachable!("built as heze")
        };
        assert_eq!(inner.slot, head_slot);
        inner.block_roots[(head_slot - 1) as usize] = DEPENDENT;
        inner.latest_block_header.slot = head_slot;
        state.apply_pending_mutations();

        let mut store = Store::init_beacon(
            Arc::new(InMemoryBackend::new()),
            GENESIS_TIME,
            config,
            HEAD,
            Checkpoint {
                root: HEAD,
                slot: head_slot,
            },
            head_slot,
        );
        store
            .insert_pending_block(DEPENDENT, empty_block(0, Root::ZERO))
            .expect("insert the dependent block");
        store
            .insert_signed_block(HEAD, empty_block(head_slot, DEPENDENT))
            .expect("insert the head");
        store
            .insert_state(HEAD, state.clone())
            .expect("insert the head state");
        store
            .update_checkpoints(ForkCheckpoints::head_only(HEAD))
            .expect("move the head");
        let mut dependent_state = state.clone();
        *dependent_state.slot_mut() = 0;
        dependent_state.latest_block_header_mut().slot = 0;
        store
            .insert_state(DEPENDENT, dependent_state)
            .expect("insert the dependent state");
        (store, state)
    }

    /// A list of the fork's first slot, from a member of EIP-8453's committee
    /// for it (a uniform draw) who is not on heze's, judged while the head is
    /// still the heze block before the fork: accepted, as by a node whose
    /// head is the fork's first block (an EIP-8453 state, which answers the
    /// uniform draw).
    #[test]
    fn a_fork_epoch_list_is_judged_by_the_eip8453_committee_under_a_heze_head() {
        let (store, state) = heze_head_before_the_fork();
        let config = store.config();
        let slot = compute_start_slot_at_epoch(FORK_EPOCH);
        let committees = store.committee_cache();
        let eip8453_committee =
            crate::beacon::helpers::eip8453::get_inclusion_list_committee(&state, slot).unwrap();
        let heze_config = (*config)
            .clone()
            .with_fork_epoch(ForkName::Eip8453, FAR_FUTURE_EPOCH);
        let heze_committee =
            get_inclusion_list_committee(&heze_config, &state, slot, &*committees).unwrap();
        let member = *eip8453_committee
            .iter()
            .find(|member| !heze_committee.contains(member))
            .expect("the uniform draw names someone heze's committee does not");

        let message = InclusionList {
            slot,
            validator_index: member,
            dependent_root: DEPENDENT,
            transactions: vec![Transaction::from(vec![1u8])].into(),
        };
        let root = inclusion_list_signing_root(&config, &state, &message);
        let signed = SignedInclusionList {
            message,
            signature: sign_for(member as usize, root),
        };
        assert_eq!(stateful_checks(&store, &signed), Outcome::Accept);
    }
}
