//! `beacon_attestation_{subnet_id}` gossip validation: electra's modified
//! `validate_beacon_attestation_gossip` (`specs/electra/p2p-interface.md`),
//! which fulu (what mainnet runs) inherits unchanged.
//!
//! EIP-7549 replaced the wire type for this topic with [`SingleAttestation`]:
//! one attester's vote, with its committee named explicitly
//! (`committee_index`) rather than inferred from the bit position in a
//! committee-scoped bitfield. This module, like the specification's own
//! modified function, only ever sees that shape; a pre-electra,
//! phase0-shaped attestation on this topic is not this module's problem; see
//! the design spec's split for where that answers `Ignore(NoConsumer)`
//! instead.
//!
//! # Deviations from the specification
//!
//! Both are shared with [`super::aggregate`], which explains them in more
//! depth:
//!
//! - **"Block passes validation" becomes "post-state is cached"**: an
//!   uncached vote-block state is [`IgnoreReason::StateUnavailable`], not
//!   the specification's `REJECT`. The vector this cannot satisfy
//!   (`reject_block_failed_validation`) is skipped, not forced to pass.
//! - **The attester's signature is checked before any committee
//!   derivation.** The specification checks committee membership first;
//!   this checks the pubkey-only signature first instead, so a forged
//!   attestation cannot force [`store.committee_cache()`](crate::beacon::fork_choice::Store::committee_cache)
//!   to derive a shuffling it did not need to.
//! - **Ancestry through the vote state's own `block_roots`**
//!   ([`super::ancestor_at`]), not a `Store::block_index` scan: the vote
//!   state's own history already reaches back to both checkpoints in
//!   question.
//!
//! # Seen state
//!
//! [`SeenAttestations`] is this module's copy of the specification's
//! `Seen.attestation_validator_epochs`: bounded by capacity like every other
//! seen cache in this crate (see [`super::SeenBlocks`]), rather than pruned
//! on finality.

use std::num::NonZeroUsize;

use lru::LruCache;

use super::{
    IgnoreReason, Outcome, RejectReason, ancestor_at, is_current_or_previous_epoch, is_future_slot,
};
use crate::beacon::bls;
use crate::beacon::config::Config;
use crate::beacon::constants::DOMAIN_BEACON_ATTESTER;
use crate::beacon::containers::electra::SingleAttestation;
use crate::beacon::fork_choice::Store;
use crate::beacon::helpers::accessors::CommitteeCacheExt;
use crate::beacon::helpers::accessors::get_domain;
use crate::beacon::helpers::misc::{
    compute_epoch_at_slot, compute_signing_root, compute_start_slot_at_epoch,
};
use crate::beacon::preset;
use crate::beacon::primitives::{CommitteeIndex, Epoch, HashTreeRoot as _, Slot, ValidatorIndex};
use ethlambda_storage::CacheKey;

/// Accepted subnet attestations by `(target_epoch, attester_index)`.
///
/// Bounded by capacity, like [`super::SeenBlocks`], rather than pruned on
/// finality: the capacity is the caller's (`ethlambda-p2p` defines the
/// constant, next to its other seen-cache sizes).
pub struct SeenAttestations(LruCache<(Epoch, ValidatorIndex), ()>);

impl SeenAttestations {
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self(LruCache::new(capacity))
    }

    /// Read-only ([`LruCache::contains`] does not touch recency), so
    /// [`cheap_checks`] can use it without mutating anything on a message
    /// that turns out invalid.
    fn contains(&self, target_epoch: Epoch, attester_index: ValidatorIndex) -> bool {
        self.0.contains(&(target_epoch, attester_index))
    }

    /// Record an accepted attestation. Returns `false`, recording nothing,
    /// when its attester is already recorded for the target epoch: the same
    /// race [`super::aggregate::SeenAggregates::record`] documents can land
    /// two racing `Accept`s here too, and this settles the second as
    /// `Ignore(AlreadySeen)` rather than double-recording.
    pub fn record(&mut self, attestation: &SingleAttestation) -> bool {
        let key = (attestation.data.target.epoch, attestation.attester_index);
        if self.0.contains(&key) {
            return false;
        }
        self.0.put(key, ());
        true
    }
}

/// `validator.md`'s `compute_subnet_for_attestation`, kept here rather than
/// imported from `ethlambda-p2p` (which has its own copy, used for a
/// validator's own gossip publication): the dependency between the two
/// crates only runs one way, `ethlambda-p2p` depends on
/// `ethlambda-state-transition`, so this side cannot reach across to reuse
/// it.
///
/// `committees_per_slot` is the caller's, since it is a function of the
/// state at the attestation's epoch and this function holds no state.
pub(crate) fn compute_subnet_for_attestation(
    committees_per_slot: u64,
    slot: Slot,
    committee_index: CommitteeIndex,
    config: &Config,
) -> u64 {
    let slots_since_epoch_start = slot % preset::SLOTS_PER_EPOCH;
    let committees_since_epoch_start = committees_per_slot.saturating_mul(slots_since_epoch_start);
    committees_since_epoch_start.saturating_add(committee_index) % config.attestation_subnet_count
}

/// The conditions that read only the message, the clock and the seen cache.
///
/// `Err` carries the verdict; `Ok` sends the attestation on to
/// [`stateful_checks`].
pub fn cheap_checks(
    seen: &SeenAttestations,
    store: &Store,
    attestation: &SingleAttestation,
    now_ms: u64,
) -> Result<(), Outcome> {
    let config = store.config();
    let data = &attestation.data;
    let target_epoch = data.target.epoch;

    // [Modified in Electra:EIP7549] [IGNORE] No other valid attestation seen
    // for this target epoch and validator.
    if seen.contains(target_epoch, attestation.attester_index) {
        return Err(Outcome::Ignore(IgnoreReason::AlreadySeen));
    }
    // [New in Electra:EIP7549] [REJECT] `data.index` is zero: the committee
    // now travels in `committee_index` instead.
    if data.index != 0 {
        return Err(Outcome::Reject(RejectReason::NonZeroDataIndex));
    }
    // [IGNORE] Not from a future slot.
    if is_future_slot(&config, data.slot, now_ms) {
        return Err(Outcome::Ignore(IgnoreReason::FutureSlot));
    }
    // [IGNORE] The current or the previous epoch.
    let attestation_epoch = compute_epoch_at_slot(data.slot);
    if !is_current_or_previous_epoch(&config, attestation_epoch, now_ms) {
        return Err(Outcome::Ignore(IgnoreReason::OutsideEpochWindow));
    }
    // [REJECT] The epoch matches its target.
    if target_epoch != attestation_epoch {
        return Err(Outcome::Reject(RejectReason::EpochMismatch));
    }
    Ok(())
}

/// The conditions that need the voted block's state. Runs on a blocking
/// thread. See [`super::aggregate::stateful_checks`] for why this reads the
/// vote block's own cached post-state rather than the head's, and why the
/// pubkey-only signature check runs before any committee derivation.
pub fn stateful_checks(store: &Store, attestation: &SingleAttestation, subnet_id: u64) -> Outcome {
    let data = &attestation.data;
    let beacon_block_root = data.beacon_block_root;

    // [IGNORE] The block being voted for has been seen.
    if !store.has_block(&beacon_block_root) {
        return Outcome::Ignore(IgnoreReason::UnknownBlock);
    }
    let Some(state) = store.cached_state(CacheKey::BlockState(beacon_block_root)) else {
        return Outcome::Ignore(IgnoreReason::StateUnavailable);
    };

    let target_epoch = data.target.epoch;

    // The pubkey-only signature, before any committee derivation.
    let Ok(attester) = state.validator(attestation.attester_index) else {
        return Outcome::Reject(RejectReason::UnknownValidator);
    };
    let domain = get_domain(&state, DOMAIN_BEACON_ATTESTER, Some(target_epoch));
    let signing_root = compute_signing_root(data.hash_tree_root(), domain);
    if !bls::verify(&attester.pubkey, signing_root, &attestation.signature) {
        return Outcome::Reject(RejectReason::BadSignature);
    }

    // Committees for the target epoch, through the shared cache.
    let committees = store.committee_cache();
    let epoch_committees = committees.committees(&state, target_epoch);
    // [REJECT] The committee index is within range.
    if attestation.committee_index >= epoch_committees.committees_per_slot() {
        return Outcome::Reject(RejectReason::CommitteeIndex);
    }
    // [New in Electra:EIP7549] [REJECT] The correct subnet.
    let config = store.config();
    let expected_subnet = compute_subnet_for_attestation(
        epoch_committees.committees_per_slot(),
        data.slot,
        attestation.committee_index,
        &config,
    );
    if expected_subnet != subnet_id {
        return Outcome::Reject(RejectReason::WrongSubnet);
    }
    let Ok(committee) = epoch_committees.committee(data.slot, attestation.committee_index) else {
        // `committee_index` and `data.slot`'s epoch were both just checked
        // against this same `epoch_committees`, so this cannot fail.
        return Outcome::Ignore(IgnoreReason::Internal);
    };
    // [New in Electra:EIP7549] [REJECT] The attester is a member of the
    // named committee.
    if !committee.contains(&attestation.attester_index) {
        return Outcome::Reject(RejectReason::NotInCommittee);
    }

    // Ancestry, via the vote state's own history.
    let target_start_slot = compute_start_slot_at_epoch(target_epoch);
    // [REJECT] The target is the vote block's ancestor at the target epoch.
    let Some(checkpoint_block) = ancestor_at(&state, beacon_block_root, target_start_slot) else {
        return Outcome::Ignore(IgnoreReason::AncestryUnknown);
    };
    if checkpoint_block != data.target.root {
        return Outcome::Reject(RejectReason::TargetNotAncestor);
    }
    // [IGNORE] The finalized checkpoint is an ancestor of the vote block.
    let finalized = store.beacon_finalized_checkpoint();
    let finalized_start_slot = compute_start_slot_at_epoch(finalized.epoch);
    let Some(finalized_block) = ancestor_at(&state, beacon_block_root, finalized_start_slot) else {
        return Outcome::Ignore(IgnoreReason::AncestryUnknown);
    };
    if finalized_block != finalized.root {
        return Outcome::Ignore(IgnoreReason::FinalizedNotAncestor);
    }

    Outcome::Accept
}

/// `cheap_checks` then `stateful_checks`, for callers with no reason to
/// split them, such as the spec vectors.
pub fn validate(
    seen: &SeenAttestations,
    store: &Store,
    attestation: &SingleAttestation,
    subnet_id: u64,
    now_ms: u64,
) -> Outcome {
    if let Err(outcome) = cheap_checks(seen, store, attestation, now_ms) {
        return outcome;
    }
    stateful_checks(store, attestation, subnet_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::gossip::test_support::{seen_attestations, slot_start_ms, store};
    use crate::beacon::primitives::Root;

    fn capacity(n: usize) -> NonZeroUsize {
        NonZeroUsize::new(n).expect("non-zero")
    }

    fn attestation_at(
        target_epoch: Epoch,
        attester_index: ValidatorIndex,
        committee_index: CommitteeIndex,
    ) -> SingleAttestation {
        SingleAttestation {
            committee_index,
            attester_index,
            data: crate::beacon::containers::shared::AttestationData {
                slot: compute_start_slot_at_epoch(target_epoch),
                index: 0,
                beacon_block_root: Root::repeat_byte(1),
                source: Default::default(),
                target: crate::beacon::containers::shared::Checkpoint {
                    epoch: target_epoch,
                    root: Root::repeat_byte(2),
                },
            },
            signature: Default::default(),
        }
    }

    // -- SeenAttestations ----------------------------------------------------

    #[test]
    fn the_first_attestation_for_an_epoch_and_attester_is_recorded_once() {
        let mut seen = seen_attestations();
        let first = attestation_at(3, 7, 0);
        assert!(!seen.contains(3, 7));
        assert!(seen.record(&first));
        assert!(seen.contains(3, 7));
        // A second attestation from the same attester and epoch, even with
        // different data, is already seen.
        let second = attestation_at(3, 7, 1);
        assert!(!seen.record(&second));
    }

    #[test]
    fn a_different_attester_or_epoch_is_recorded_independently() {
        let mut seen = seen_attestations();
        assert!(seen.record(&attestation_at(3, 1, 0)));
        assert!(seen.record(&attestation_at(3, 2, 0)));
        assert!(seen.record(&attestation_at(4, 1, 0)));
    }

    #[test]
    fn the_cache_forgets_its_oldest_entry_past_capacity() {
        let mut seen = SeenAttestations::new(capacity(2));
        seen.record(&attestation_at(1, 1, 0));
        seen.record(&attestation_at(1, 2, 0));
        seen.record(&attestation_at(1, 3, 0));
        assert!(!seen.contains(1, 1));
        assert!(seen.contains(1, 3));
    }

    // -- compute_subnet_for_attestation --------------------------------------

    #[test]
    fn an_attestation_maps_to_its_subnet() {
        let config = Config::mainnet();
        assert_eq!(compute_subnet_for_attestation(4, 0, 0, &config), 0);
        assert_eq!(compute_subnet_for_attestation(4, 0, 2, &config), 2);
        assert_eq!(compute_subnet_for_attestation(4, 1, 0, &config), 4);
        assert_eq!(compute_subnet_for_attestation(4, 1, 3, &config), 7);
    }

    #[test]
    fn the_subnet_mapping_wraps_at_the_subnet_count() {
        let config = Config::mainnet();
        let count = config.attestation_subnet_count;
        assert_eq!(compute_subnet_for_attestation(count, 1, 0, &config), 0);
    }

    // -- cheap_checks --------------------------------------------------------

    #[test]
    fn an_already_seen_attester_and_epoch_is_ignored() {
        let store = store(0);
        let mut seen = seen_attestations();
        let attestation = attestation_at(0, 1, 0);
        seen.record(&attestation);
        let now = slot_start_ms(&store, 0);
        assert_eq!(
            cheap_checks(&seen, &store, &attestation, now),
            Err(Outcome::Ignore(IgnoreReason::AlreadySeen))
        );
    }

    #[test]
    fn a_nonzero_data_index_is_rejected() {
        let store = store(0);
        let seen = seen_attestations();
        let mut attestation = attestation_at(0, 1, 0);
        attestation.data.index = 1;
        let now = slot_start_ms(&store, 0);
        assert_eq!(
            cheap_checks(&seen, &store, &attestation, now),
            Err(Outcome::Reject(RejectReason::NonZeroDataIndex))
        );
    }

    #[test]
    fn a_future_slot_is_ignored() {
        let store = store(0);
        let seen = seen_attestations();
        let target_epoch = 5;
        let attestation = attestation_at(target_epoch, 1, 0);
        let slot = compute_start_slot_at_epoch(target_epoch);
        let too_early = slot_start_ms(&store, slot)
            - (crate::beacon::constants::MAXIMUM_GOSSIP_CLOCK_DISPARITY + 100);
        assert_eq!(
            cheap_checks(&seen, &store, &attestation, too_early),
            Err(Outcome::Ignore(IgnoreReason::FutureSlot))
        );
    }

    #[test]
    fn an_epoch_far_from_current_is_ignored() {
        let store = store(0);
        let seen = seen_attestations();
        // The attestation names a stale epoch; its own slot is safely in the
        // past (not a future slot), but the clock has since moved many
        // epochs ahead, so the epoch itself is no longer current or previous.
        let stale_epoch = 0;
        let attestation = attestation_at(stale_epoch, 1, 0);
        let now_epoch = 10;
        let now = slot_start_ms(&store, compute_start_slot_at_epoch(now_epoch));
        assert_eq!(
            cheap_checks(&seen, &store, &attestation, now),
            Err(Outcome::Ignore(IgnoreReason::OutsideEpochWindow))
        );
    }

    #[test]
    fn an_epoch_mismatched_with_the_slot_is_rejected() {
        let store = store(0);
        let seen = seen_attestations();
        let mut attestation = attestation_at(0, 1, 0);
        attestation.data.slot = crate::beacon::preset::SLOTS_PER_EPOCH;
        let now = slot_start_ms(&store, crate::beacon::preset::SLOTS_PER_EPOCH);
        assert_eq!(
            cheap_checks(&seen, &store, &attestation, now),
            Err(Outcome::Reject(RejectReason::EpochMismatch))
        );
    }

    // -- stateful_checks -------------------------------------------------

    #[test]
    fn a_vote_for_an_unseen_block_is_ignored() {
        let store = store(0);
        let attestation = attestation_at(0, 1, 0);
        assert_eq!(
            stateful_checks(&store, &attestation, 0),
            Outcome::Ignore(IgnoreReason::UnknownBlock)
        );
    }
}
