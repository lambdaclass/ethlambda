//! Gossip validation for the gloas `payload_attestation_message` topic: a
//! payload timeliness committee member's vote on whether a block's payload
//! arrived in time.
//!
//! The rules are the specification's `validate_payload_attestation_message_gossip`
//! (`specs/gloas/p2p-interface.md`), split like [`super::envelope`]'s:
//! [`cheap_checks`] reads the message, the clock, the seen cache and the
//! config; [`stateful_checks`] reads the voted block and the head state's
//! committee and verifies the signature.
//!
//! Deliberate departures from the specification:
//!
//! - A voted block seen without a post-state is `IGNORE` where the
//!   specification rejects it, until a bad-block cache exists. An unseen block
//!   is `IGNORE` as the specification says; nothing is queued, since the vote
//!   is only valid within its own slot.
//! - The head state is read from the state cache, never rebuilt. A miss is
//!   `IGNORE`, like the other topics' uncached states.

use std::num::NonZeroUsize;

use ethlambda_storage::CacheKey;
use lru::LruCache;

use super::{IgnoreReason, Outcome, RejectReason, is_current_slot};
use crate::beacon::bls;
use crate::beacon::constants::DOMAIN_PTC_ATTESTER;
use crate::beacon::containers::gloas;
use crate::beacon::fork_choice::Store;
use crate::beacon::helpers::accessors::get_domain;
use crate::beacon::helpers::gloas::get_ptc;
use crate::beacon::helpers::misc::{compute_epoch_at_slot, compute_signing_root};
use crate::beacon::primitives::{HashTreeRoot as _, Slot, ValidatorIndex};

/// The first valid payload attestation per `(slot, validator index)`: the
/// specification's `seen.payload_attestation_validators`.
///
/// Bounded the same way as [`super::SeenBlocks`].
pub struct SeenPayloadAttestations(LruCache<(Slot, ValidatorIndex), ()>);

impl SeenPayloadAttestations {
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self(LruCache::new(capacity))
    }

    pub fn contains(&self, slot: Slot, validator_index: ValidatorIndex) -> bool {
        self.0.contains(&(slot, validator_index))
    }

    /// Record the first valid attestation for its key. Returns `false`,
    /// changing nothing, when one is already recorded.
    pub fn record(&mut self, slot: Slot, validator_index: ValidatorIndex) -> bool {
        if self.0.contains(&(slot, validator_index)) {
            return false;
        }
        self.0.put((slot, validator_index), ());
        true
    }
}

/// The rules that read only the message, the clock, the seen cache and the
/// config. The caller records the message in `seen` once the whole rule
/// answers [`Outcome::Accept`].
pub fn cheap_checks(
    seen: &SeenPayloadAttestations,
    store: &Store,
    message: &gloas::PayloadAttestationMessage,
    now_ms: u64,
) -> Result<(), Outcome> {
    let config = store.config();
    let slot = message.data.slot;
    // [REJECT] The payload attestation's slot is at or after the gloas fork.
    if compute_epoch_at_slot(slot) < config.gloas_fork_epoch {
        return Err(Outcome::Reject(RejectReason::PreGloasSlot));
    }
    // [IGNORE] This is the first valid payload attestation from this validator.
    if seen.contains(slot, message.validator_index) {
        return Err(Outcome::Ignore(IgnoreReason::AlreadySeen));
    }
    // [IGNORE] The payload attestation's slot is the current slot.
    if !is_current_slot(&config, slot, now_ms) {
        return Err(Outcome::Ignore(IgnoreReason::NotCurrentSlot));
    }
    Ok(())
}

/// The rules that need the voted block and the head state. Runs on a blocking
/// thread.
pub fn stateful_checks(store: &Store, message: &gloas::PayloadAttestationMessage) -> Outcome {
    let data = &message.data;
    let validator_index = message.validator_index;
    // [IGNORE] The voted block has been seen.
    let Some((block_slot, _)) = store.block_slot_and_state_root(&data.beacon_block_root) else {
        return Outcome::Ignore(IgnoreReason::UnknownBlock);
    };
    // [REJECT] The voted block passes validation: see the module documentation.
    match store.has_state(&data.beacon_block_root) {
        Ok(true) => {}
        Ok(false) => return Outcome::Ignore(IgnoreReason::StateUnavailable),
        Err(_) => return Outcome::Ignore(IgnoreReason::Internal),
    }
    // [IGNORE] The voted block is at the assigned slot.
    if block_slot != data.slot {
        return Outcome::Ignore(IgnoreReason::BlockNotAtSlot);
    }

    // The committee is read off the head state, as the specification says.
    // `head` is the root alone: `beacon_head` would decode the whole head block
    // for a slot nothing here reads.
    let Ok(head_root) = store.head() else {
        return Outcome::Ignore(IgnoreReason::Internal);
    };
    let Some(state) = store.cached_state(CacheKey::BlockState(head_root)) else {
        return Outcome::Ignore(IgnoreReason::StateUnavailable);
    };
    // [REJECT] The validator index is valid.
    let Ok(validator) = state.validator(validator_index) else {
        return Outcome::Reject(RejectReason::UnknownValidator);
    };
    // [REJECT] The validator is a member of the payload timeliness committee.
    // A slot the head's committee window cannot answer is not the sender's fault.
    let Ok(ptc) = get_ptc(&state, data.slot, &store.config()) else {
        return Outcome::Ignore(IgnoreReason::PtcUnavailable);
    };
    if !ptc.contains(&validator_index) {
        return Outcome::Reject(RejectReason::NotInPtc);
    }
    // [REJECT] The signature is valid.
    let domain = get_domain(
        &state,
        DOMAIN_PTC_ATTESTER,
        Some(compute_epoch_at_slot(data.slot)),
    );
    let signing_root = compute_signing_root(data.hash_tree_root(), domain);
    if !bls::verify(&validator.pubkey, signing_root, &message.signature) {
        return Outcome::Reject(RejectReason::BadSignature);
    }
    Outcome::Accept
}

/// [`cheap_checks`] then [`stateful_checks`], for callers with no reason to
/// split them, such as the spec vectors: the specification's
/// `validate_payload_attestation_message_gossip`. The caller records the
/// message in `seen` on [`Outcome::Accept`].
pub fn validate(
    seen: &SeenPayloadAttestations,
    store: &Store,
    message: &gloas::PayloadAttestationMessage,
    now_ms: u64,
) -> Outcome {
    if let Err(outcome) = cheap_checks(seen, store, message, now_ms) {
        return outcome;
    }
    stateful_checks(store, message)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ethlambda_storage::backend::InMemoryBackend;
    use ethlambda_types::checkpoint::Checkpoint;

    use super::*;
    use crate::beacon::config::Config;
    use crate::beacon::containers::{SignedBeaconBlock, electra};
    use crate::beacon::fork::ForkName;
    use crate::beacon::gossip::test_support::{GENESIS_TIME, store};
    use crate::beacon::helpers::test_state::with_validators_at;
    use crate::beacon::preset;
    use crate::beacon::primitives::Root;

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

    fn message(slot: Slot) -> gloas::PayloadAttestationMessage {
        gloas::PayloadAttestationMessage {
            validator_index: 0,
            data: gloas::PayloadAttestationData {
                beacon_block_root: BLOCK_ROOT,
                slot,
                payload_present: true,
                blob_data_available: true,
            },
            signature: Default::default(),
        }
    }

    /// A store that is gloas from genesis, so the committee lookup is reached.
    fn gloas_store() -> Store {
        Store::init_beacon(
            Arc::new(InMemoryBackend::new()),
            GENESIS_TIME,
            Config::mainnet()
                .with_fork_epoch(ForkName::Fulu, 0)
                .with_fork_epoch(ForkName::Gloas, 0),
            Root::ZERO,
            Checkpoint {
                root: Root::ZERO,
                slot: 0,
            },
            0,
        )
    }

    #[test]
    fn a_vote_for_an_unseen_block_is_ignored() {
        let store = store(0);
        assert_eq!(
            stateful_checks(&store, &message(5)),
            Outcome::Ignore(IgnoreReason::UnknownBlock)
        );
    }

    #[test]
    fn a_vote_for_a_block_without_a_post_state_is_ignored_not_rejected() {
        let mut store = store(0);
        store
            .insert_pending_block(BLOCK_ROOT, fulu_block(5))
            .expect("insert pending block");
        assert_eq!(
            stateful_checks(&store, &message(5)),
            Outcome::Ignore(IgnoreReason::StateUnavailable)
        );
    }

    #[test]
    fn a_vote_is_ignored_when_the_head_state_is_not_cached() {
        let mut store = store(0);
        store
            .insert_pending_block(BLOCK_ROOT, fulu_block(5))
            .expect("insert the block");
        // Only the voted block has a state; the head (the anchor root) has none.
        store
            .insert_state(BLOCK_ROOT, with_validators_at(ForkName::Gloas, 8))
            .expect("insert the state");
        assert_eq!(
            stateful_checks(&store, &message(5)),
            Outcome::Ignore(IgnoreReason::StateUnavailable)
        );
    }

    #[test]
    fn a_vote_outside_the_head_states_committee_window_is_ignored_with_its_own_reason() {
        let mut store = gloas_store();
        let slot = 10 * preset::SLOTS_PER_EPOCH;
        store
            .insert_pending_block(BLOCK_ROOT, fulu_block(slot))
            .expect("insert the block");
        store
            .insert_state(BLOCK_ROOT, with_validators_at(ForkName::Gloas, 8))
            .expect("insert the voted block's state");
        let head = store.head().expect("head root");
        store
            .insert_state(head, with_validators_at(ForkName::Gloas, 8))
            .expect("insert the head state");
        assert_eq!(
            stateful_checks(&store, &message(slot)),
            Outcome::Ignore(IgnoreReason::PtcUnavailable)
        );
    }

    #[test]
    fn a_validator_the_head_state_lacks_is_rejected() {
        let mut store = gloas_store();
        store
            .insert_pending_block(BLOCK_ROOT, fulu_block(5))
            .expect("insert the block");
        store
            .insert_state(BLOCK_ROOT, with_validators_at(ForkName::Gloas, 8))
            .expect("insert the voted block's state");
        let head = store.head().expect("head root");
        store
            .insert_state(head, with_validators_at(ForkName::Gloas, 8))
            .expect("insert the head state");
        let mut message = message(5);
        message.validator_index = 8;
        assert_eq!(
            stateful_checks(&store, &message),
            Outcome::Reject(RejectReason::UnknownValidator)
        );
    }

    #[test]
    fn a_payload_attestation_key_records_once_per_slot_and_validator() {
        let mut seen = SeenPayloadAttestations::new(NonZeroUsize::new(4).expect("non-zero"));
        assert!(!seen.contains(5, 9));
        assert!(seen.record(5, 9));
        assert!(seen.contains(5, 9));
        assert!(!seen.record(5, 9));
        assert!(seen.record(5, 10));
        assert!(seen.record(6, 9));
    }
}
