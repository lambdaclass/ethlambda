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
    let Some((_, head_root)) = store.beacon_head() else {
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
        return Outcome::Ignore(IgnoreReason::StateUnavailable);
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
    use super::*;

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
