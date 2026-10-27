//! `beacon_attestation_{subnet_id}` gossip validation: electra's modified
//! `validate_beacon_attestation_gossip` (`specs/electra/p2p-interface.md`),
//! which fulu inherits unchanged, and gloas's modification of it
//! (`specs/gloas/p2p-interface.md`), picked by the attestation's slot since
//! gloas keeps [`SingleAttestation`].
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
    is_gloas_slot, verify_attestation_payload_status,
};
use crate::beacon::bls;
use crate::beacon::config::Config;
use crate::beacon::constants::DOMAIN_BEACON_ATTESTER;
use crate::beacon::containers::electra::SingleAttestation;
use crate::beacon::fork_choice::Store;
use crate::beacon::helpers::accessors::CommitteeCacheExt;
use crate::beacon::helpers::accessors::get_domain_from_schedule;
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
///
/// Public for the Beacon API, which computes the subnet of each attestation a
/// validator client submits before publishing it.
pub fn compute_subnet_for_attestation(
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
    if is_gloas_slot(&config, data.slot) {
        // [New in Gloas:EIP7732] [REJECT] `data.index` is 0 or 1: it is the
        // payload-present flag now.
        if data.index > 1 {
            return Err(Outcome::Reject(RejectReason::DataIndexOutOfRange));
        }
    } else if data.index != 0 {
        // [New in Electra:EIP7549] [REJECT] `data.index` is zero: the committee
        // now travels in `committee_index` instead.
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
    let config = store.config();

    // The pubkey-only signature, before any committee derivation, under the
    // schedule's domain: the voted block's state may predate the target's fork.
    let Ok(attester) = state.validator(attestation.attester_index) else {
        return Outcome::Reject(RejectReason::UnknownValidator);
    };
    let domain = get_domain_from_schedule(&config, &state, DOMAIN_BEACON_ATTESTER, target_epoch);
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

    // [New in Gloas:EIP7732] The attested payload status is consistent with the
    // block's execution payload.
    if is_gloas_slot(&store.config(), data.slot)
        && let Err(outcome) = verify_attestation_payload_status(store, data)
    {
        return outcome;
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

    /// A vote cast in a fork's first slot while that slot has no block: the
    /// voted block, and so the state it is checked against, is still the
    /// previous fork's, but the vote is signed under the new fork's version.
    #[test]
    fn a_vote_across_a_fork_boundary_verifies_under_the_new_forks_version() {
        use crate::beacon::containers::shared::{AttestationData, Checkpoint, Fork};
        use crate::beacon::containers::{SignedBeaconBlock, electra};
        use crate::beacon::fork::ForkName;
        use crate::beacon::gossip::test_support::store_with_config;
        use crate::beacon::helpers::accessors::get_beacon_committee;
        use crate::beacon::helpers::misc::compute_domain;
        use crate::beacon::helpers::test_state::{sign_for, with_signing_validators_at};

        let fulu_epoch = 2;
        let config = Config::mainnet()
            .with_fork_epoch(ForkName::Electra, 0)
            .with_fork_epoch(ForkName::Fulu, fulu_epoch);
        let mut state = with_signing_validators_at(ForkName::Electra, 64);
        let pre_fork_slot = compute_start_slot_at_epoch(fulu_epoch) - 1;
        *state.slot_mut() = pre_fork_slot;
        *state.fork_mut() = Fork {
            previous_version: config.deneb_fork_version,
            current_version: config.electra_fork_version,
            epoch: 0,
        };
        state.apply_pending_mutations();

        let mut store = store_with_config(0, config.clone());
        let block_root = Root::repeat_byte(7);
        let block = SignedBeaconBlock::Electra(electra::SignedBeaconBlock {
            message: electra::BeaconBlock {
                slot: pre_fork_slot,
                proposer_index: 0,
                parent_root: Root::ZERO,
                state_root: Root::ZERO,
                body: electra::BeaconBlockBody::empty(),
            },
            signature: Default::default(),
        });
        store
            .insert_pending_block(block_root, block)
            .expect("insert the voted block");
        store.cache_state(
            CacheKey::BlockState(block_root),
            std::sync::Arc::new(state.clone()),
        );

        let slot = compute_start_slot_at_epoch(fulu_epoch);
        let committee = get_beacon_committee(&state, slot, 0).expect("committee");
        let attester_index = committee[0];
        let data = AttestationData {
            slot,
            index: 0,
            beacon_block_root: block_root,
            source: Default::default(),
            target: Checkpoint {
                epoch: fulu_epoch,
                root: block_root,
            },
        };
        let domain = compute_domain(
            DOMAIN_BEACON_ATTESTER,
            config.fulu_fork_version,
            state.genesis_validators_root(),
        );
        let attestation = SingleAttestation {
            committee_index: 0,
            attester_index,
            signature: sign_for(
                attester_index as usize,
                compute_signing_root(data.hash_tree_root(), domain),
            ),
            data,
        };
        let committees_per_slot = store
            .committee_cache()
            .committees(&state, fulu_epoch)
            .committees_per_slot();
        let subnet_id = compute_subnet_for_attestation(committees_per_slot, slot, 0, &config);

        assert_eq!(
            stateful_checks(&store, &attestation, subnet_id),
            Outcome::Accept
        );
    }
}
