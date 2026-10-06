//! Gossip validation for the altair `sync_committee_{subnet_id}` and
//! `sync_committee_contribution_and_proof` topics.
//!
//! The rules are the specification's `validate_sync_committee_message_gossip`
//! and the contribution-and-proof section of `specs/altair/p2p-interface.md`,
//! split by cost like [`super::payload_attestation`]'s: the `*_cheap_checks`
//! read the message, the clock and the seen caches; the `*_stateful_checks`
//! read the head state and verify signatures. Neither fulu nor gloas changes
//! the rules.
//!
//! Deliberate departures from the specification:
//!
//! - The committee is chosen by the message's slot and the signing domain by
//!   the config's fork schedule (see [`crate::beacon::helpers::sync_committee`]),
//!   not by `state.slot + 1` and `state.fork`. A head that lags across a period
//!   or fork boundary would otherwise reject honest messages.
//! - The head state is read from the state cache, never rebuilt. A miss is
//!   `IGNORE`, like the other topics' uncached states, and so is a period the
//!   head state's committees cannot answer for ([`IgnoreReason::SyncCommitteeUnavailable`]).

use std::num::NonZeroUsize;

use ethlambda_storage::CacheKey;
use lru::LruCache;

use super::{IgnoreReason, Outcome, RejectReason, is_current_slot};
use crate::beacon::bls;
use crate::beacon::config::Config;
use crate::beacon::constants::SYNC_COMMITTEE_SUBNET_COUNT;
use crate::beacon::containers::BeaconState;
use crate::beacon::containers::altair::{
    SYNC_SUBCOMMITTEE_SIZE, SignedContributionAndProof, SyncCommitteeMessage,
};
use crate::beacon::fork_choice::Store;
use crate::beacon::helpers::sync_committee::{
    contribution_and_proof_signing_root, get_sync_subcommittee_pubkeys,
    is_sync_committee_aggregator, sync_committee_for_slot, sync_committee_message_signing_root,
    sync_committee_seats, sync_selection_proof_signing_root,
};
use crate::beacon::primitives::{Root, Slot, ValidatorIndex};

/// The first valid message per `(slot, validator index, subnet)`: the
/// specification's `seen.sync_message_validator_slots`. Bounded by capacity,
/// like [`super::SeenPayloadAttestations`].
pub struct SeenSyncCommitteeMessages(LruCache<(Slot, ValidatorIndex, u64), ()>);

impl SeenSyncCommitteeMessages {
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self(LruCache::new(capacity))
    }

    pub fn contains(&self, slot: Slot, validator_index: ValidatorIndex, subnet_id: u64) -> bool {
        self.0.contains(&(slot, validator_index, subnet_id))
    }

    /// Record the first valid message for its key. Returns `false`, changing
    /// nothing, when one is already recorded.
    pub fn record(&mut self, slot: Slot, validator_index: ValidatorIndex, subnet_id: u64) -> bool {
        if self.0.contains(&(slot, validator_index, subnet_id)) {
            return false;
        }
        self.0.put((slot, validator_index, subnet_id), ());
        true
    }
}

/// A subcommittee's aggregation bits, packed into one word.
fn pack_bits(signed: &SignedContributionAndProof) -> u128 {
    let bits = &signed.message.contribution.aggregation_bits;
    (0..SYNC_SUBCOMMITTEE_SIZE)
        .filter(|&index| bits.get(index).unwrap_or(false))
        .fold(0u128, |packed, index| packed | (1 << index))
}

/// Accepted contributions, keyed the way the specification's `Seen` keys them:
/// `sync_contribution_aggregator_slots` and `sync_contribution_data`.
///
/// Both are bounded by capacity. See [`super::SeenAggregates`] for why that
/// beats pruning on finality, and for the race [`Self::record`] closes.
pub struct SeenSyncContributions {
    aggregators: LruCache<(Slot, ValidatorIndex, u64), ()>,
    data: LruCache<(Slot, Root, u64), Vec<u128>>,
}

impl SeenSyncContributions {
    pub fn new(aggregators: NonZeroUsize, data: NonZeroUsize) -> Self {
        Self {
            aggregators: LruCache::new(aggregators),
            data: LruCache::new(data),
        }
    }

    /// The two seen verdicts, in the specification's order: a superset already
    /// accepted for the same data, then an aggregator already accepted for the
    /// slot and subcommittee. Read-only.
    fn verdict(&self, signed: &SignedContributionAndProof) -> Result<(), Outcome> {
        let contribution = &signed.message.contribution;
        let bits = pack_bits(signed);
        let covered = self
            .data
            .peek(&(
                contribution.slot,
                contribution.beacon_block_root,
                contribution.subcommittee_index,
            ))
            .is_some_and(|seen| seen.iter().any(|prior| bits & !prior == 0));
        if covered {
            return Err(Outcome::Ignore(IgnoreReason::CoveredBits));
        }
        let aggregator_seen = self.aggregators.contains(&(
            contribution.slot,
            signed.message.aggregator_index,
            contribution.subcommittee_index,
        ));
        if aggregator_seen {
            return Err(Outcome::Ignore(IgnoreReason::AlreadySeen));
        }
        Ok(())
    }

    /// Record an accepted contribution. Re-runs both seen verdicts, so of two
    /// validation tasks that both passed [`contribution_cheap_checks`] before
    /// either settled, only the first records. Returns `false`, recording
    /// nothing, for the second.
    pub fn record(&mut self, signed: &SignedContributionAndProof) -> bool {
        if self.verdict(signed).is_err() {
            return false;
        }
        let contribution = &signed.message.contribution;
        self.aggregators.put(
            (
                contribution.slot,
                signed.message.aggregator_index,
                contribution.subcommittee_index,
            ),
            (),
        );
        let key = (
            contribution.slot,
            contribution.beacon_block_root,
            contribution.subcommittee_index,
        );
        let bits = pack_bits(signed);
        match self.data.get_mut(&key) {
            Some(existing) => existing.push(bits),
            None => {
                self.data.put(key, vec![bits]);
            }
        }
        true
    }
}

// --- sync_committee_{subnet_id} -------------------------------------------

/// The rules that read only the message, the clock and the seen cache. The
/// caller records the message in `seen` once the whole rule answers
/// [`Outcome::Accept`].
pub fn message_cheap_checks(
    seen: &SeenSyncCommitteeMessages,
    store: &Store,
    message: &SyncCommitteeMessage,
    subnet_id: u64,
    now_ms: u64,
) -> Result<(), Outcome> {
    // [REJECT] The subnet exists. Defensive: the topic parser never yields one
    // that does not.
    if subnet_id >= SYNC_COMMITTEE_SUBNET_COUNT as u64 {
        return Err(Outcome::Reject(RejectReason::WrongSubnet));
    }
    // [IGNORE] This is the first valid message from this validator for this
    // slot and subnet.
    if seen.contains(message.slot, message.validator_index, subnet_id) {
        return Err(Outcome::Ignore(IgnoreReason::AlreadySeen));
    }
    // [IGNORE] The message's slot is the current slot.
    if !is_current_slot(&store.config(), message.slot, now_ms) {
        return Err(Outcome::Ignore(IgnoreReason::NotCurrentSlot));
    }
    Ok(())
}

/// The cached head state, or the verdict that says it is unavailable.
fn head_state(store: &Store) -> Result<std::sync::Arc<BeaconState>, Outcome> {
    // `head` is the root alone: `beacon_head` would decode the whole head block
    // for a slot nothing here reads.
    let Ok(head_root) = store.head() else {
        return Err(Outcome::Ignore(IgnoreReason::Internal));
    };
    store
        .cached_state(CacheKey::BlockState(head_root))
        .ok_or(Outcome::Ignore(IgnoreReason::StateUnavailable))
}

/// The rules that read the head state and verify the signature. Runs on a
/// blocking thread. Returns the `(subcommittee, position)` seats the message
/// covers on `subnet_id`.
pub fn message_stateful_checks(
    store: &Store,
    message: &SyncCommitteeMessage,
    subnet_id: u64,
) -> Result<Vec<(u64, usize)>, Outcome> {
    let state = head_state(store)?;
    check_message(&state, &store.config(), message, Some(subnet_id))
}

/// The state-dependent rules for one message. With `subnet_id`, the seats kept
/// are those on that subnet; without one (the Beacon API, which accepts a
/// message for every subnet its validator sits on), all of them.
pub fn check_message(
    state: &BeaconState,
    config: &Config,
    message: &SyncCommitteeMessage,
    subnet_id: Option<u64>,
) -> Result<Vec<(u64, usize)>, Outcome> {
    // [REJECT] The validator index is valid.
    let Ok(validator) = state.validator(message.validator_index) else {
        return Err(Outcome::Reject(RejectReason::UnknownValidator));
    };
    // A period the head state's committees cannot answer for is not the
    // sender's fault.
    let Ok(committee) = sync_committee_for_slot(state, message.slot) else {
        return Err(Outcome::Ignore(IgnoreReason::SyncCommitteeUnavailable));
    };
    let mut seats = sync_committee_seats(committee, &validator.pubkey);
    match subnet_id {
        Some(subnet) => {
            seats.retain(|&(seat_subnet, _)| seat_subnet == subnet);
            // [REJECT] The validator is in the subcommittee of this subnet.
            if seats.is_empty() {
                return Err(Outcome::Reject(RejectReason::WrongSubnet));
            }
        }
        None => {
            // [REJECT] The validator is in the sync committee.
            if seats.is_empty() {
                return Err(Outcome::Reject(RejectReason::NotInCommittee));
            }
        }
    }
    // [REJECT] The signature is valid.
    let signing_root = sync_committee_message_signing_root(
        config,
        state.genesis_validators_root(),
        message.slot,
        message.beacon_block_root,
    );
    if !bls::verify(&validator.pubkey, signing_root, &message.signature) {
        return Err(Outcome::Reject(RejectReason::BadSignature));
    }
    Ok(seats)
}

/// The rules for a message submitted through the Beacon API: the clock, then
/// [`check_message`] over every subnet, so the signature is checked once.
pub fn check_submitted_message(
    state: &BeaconState,
    config: &Config,
    message: &SyncCommitteeMessage,
    now_ms: u64,
) -> Result<Vec<(u64, usize)>, Outcome> {
    // [IGNORE] The message's slot is the current slot.
    if !is_current_slot(config, message.slot, now_ms) {
        return Err(Outcome::Ignore(IgnoreReason::NotCurrentSlot));
    }
    check_message(state, config, message, None)
}

/// [`message_cheap_checks`] then [`message_stateful_checks`], for callers with
/// no reason to split them, such as the spec vectors. The caller records the
/// message in `seen` on success.
pub fn validate_message(
    seen: &SeenSyncCommitteeMessages,
    store: &Store,
    message: &SyncCommitteeMessage,
    subnet_id: u64,
    now_ms: u64,
) -> Result<Vec<(u64, usize)>, Outcome> {
    message_cheap_checks(seen, store, message, subnet_id, now_ms)?;
    message_stateful_checks(store, message, subnet_id)
}

// --- sync_committee_contribution_and_proof --------------------------------

/// The rules that read only the message, the clock and the seen caches, in the
/// specification's order.
pub fn contribution_cheap_checks(
    seen: &SeenSyncContributions,
    store: &Store,
    signed: &SignedContributionAndProof,
    now_ms: u64,
) -> Result<(), Outcome> {
    let contribution = &signed.message.contribution;
    // [IGNORE] A superset was already seen; [IGNORE] this aggregator was.
    seen.verdict(signed)?;
    // [IGNORE] The contribution's slot is the current slot.
    if !is_current_slot(&store.config(), contribution.slot, now_ms) {
        return Err(Outcome::Ignore(IgnoreReason::NotCurrentSlot));
    }
    // [REJECT] The subcommittee index is in range.
    if contribution.subcommittee_index >= SYNC_COMMITTEE_SUBNET_COUNT as u64 {
        return Err(Outcome::Reject(RejectReason::SubcommitteeIndex));
    }
    // [REJECT] The contribution has at least one participant.
    if contribution.aggregation_bits.count_ones() == 0 {
        return Err(Outcome::Reject(RejectReason::NoParticipants));
    }
    // [REJECT] The selection proof selects the aggregator.
    if !is_sync_committee_aggregator(&signed.message.selection_proof) {
        return Err(Outcome::Reject(RejectReason::NotAggregator));
    }
    Ok(())
}

/// The rules that read the head state and verify three signatures. Runs on a
/// blocking thread.
pub fn contribution_stateful_checks(store: &Store, signed: &SignedContributionAndProof) -> Outcome {
    match head_state(store) {
        Ok(state) => check_contribution(&state, &store.config(), signed),
        Err(outcome) => outcome,
    }
}

/// The state-dependent rules for one contribution.
pub fn check_contribution(
    state: &BeaconState,
    config: &Config,
    signed: &SignedContributionAndProof,
) -> Outcome {
    let message = &signed.message;
    let contribution = &message.contribution;
    let gvr = state.genesis_validators_root();
    // [REJECT] The aggregator's validator index is valid.
    let Ok(aggregator) = state.validator(message.aggregator_index) else {
        return Outcome::Reject(RejectReason::UnknownValidator);
    };
    if contribution.subcommittee_index >= SYNC_COMMITTEE_SUBNET_COUNT as u64 {
        return Outcome::Reject(RejectReason::SubcommitteeIndex);
    }
    let Ok(pubkeys) =
        get_sync_subcommittee_pubkeys(state, contribution.slot, contribution.subcommittee_index)
    else {
        return Outcome::Ignore(IgnoreReason::SyncCommitteeUnavailable);
    };
    // [REJECT] The aggregator is in the subcommittee.
    if !pubkeys.contains(&aggregator.pubkey) {
        return Outcome::Reject(RejectReason::NotInCommittee);
    }
    // [REJECT] The selection proof is valid.
    let selection_root = sync_selection_proof_signing_root(
        config,
        gvr,
        contribution.slot,
        contribution.subcommittee_index,
    );
    if !bls::verify(&aggregator.pubkey, selection_root, &message.selection_proof) {
        return Outcome::Reject(RejectReason::SelectionProof);
    }
    // [REJECT] The aggregator's signature over the envelope is valid.
    let envelope_root = contribution_and_proof_signing_root(config, gvr, message);
    if !bls::verify(&aggregator.pubkey, envelope_root, &signed.signature) {
        return Outcome::Reject(RejectReason::AggregatorSignature);
    }
    // [REJECT] The aggregate signature is valid over the participants.
    let participants: Vec<_> = pubkeys
        .iter()
        .enumerate()
        .filter(|(index, _)| contribution.aggregation_bits.get(*index).unwrap_or(false))
        .map(|(_, pubkey)| *pubkey)
        .collect();
    let signing_root = sync_committee_message_signing_root(
        config,
        gvr,
        contribution.slot,
        contribution.beacon_block_root,
    );
    if !bls::eth_fast_aggregate_verify(&participants, signing_root, &contribution.signature) {
        return Outcome::Reject(RejectReason::AggregateSignature);
    }
    Outcome::Accept
}

/// [`contribution_cheap_checks`] then [`contribution_stateful_checks`], for
/// callers with no reason to split them. The caller records the contribution in
/// `seen` on [`Outcome::Accept`].
pub fn validate_contribution(
    seen: &SeenSyncContributions,
    store: &Store,
    signed: &SignedContributionAndProof,
    now_ms: u64,
) -> Outcome {
    if let Err(outcome) = contribution_cheap_checks(seen, store, signed, now_ms) {
        return outcome;
    }
    contribution_stateful_checks(store, signed)
}

#[cfg(test)]
mod tests {
    use ethlambda_types::beacon::containers::altair::{
        ContributionAndProof, SyncCommitteeContribution,
    };
    use ethlambda_types::beacon::primitives::BlsSignature;

    use super::*;
    use crate::beacon::gossip::test_support::{slot_start_ms, store};
    use crate::beacon::helpers::sync_committee::tests::state_with_committees;
    use crate::beacon::helpers::test_state::sign_for;
    use crate::beacon::preset;

    const SLOT: Slot = 5;
    const VALIDATORS: usize = preset::SYNC_COMMITTEE_SIZE;

    fn root() -> Root {
        Root::repeat_byte(4)
    }

    fn caches() -> (SeenSyncCommitteeMessages, SeenSyncContributions) {
        let capacity = NonZeroUsize::new(8).expect("non-zero");
        (
            SeenSyncCommitteeMessages::new(capacity),
            SeenSyncContributions::new(capacity, capacity),
        )
    }

    /// A store whose head state is the committee state, cached.
    fn store_with_head() -> (Store, std::sync::Arc<BeaconState>) {
        let mut store = store(0);
        let state = state_with_committees(VALIDATORS);
        let head = store.head().expect("head root");
        store.insert_state(head, state).expect("insert head state");
        let cached = store
            .cached_state(CacheKey::BlockState(head))
            .expect("the head state is cached");
        (store, cached)
    }

    /// Validator `index` is at position `index` of the current committee.
    fn message_from(index: u64, signer: usize) -> SyncCommitteeMessage {
        let signing_root = sync_committee_message_signing_root(
            &Config::mainnet().with_fork_epoch(crate::beacon::ForkName::Fulu, 0),
            Root::ZERO,
            SLOT,
            root(),
        );
        SyncCommitteeMessage {
            slot: SLOT,
            beacon_block_root: root(),
            validator_index: index,
            signature: sign_for(signer, signing_root),
        }
    }

    fn subnet_of(index: u64) -> u64 {
        index / SYNC_SUBCOMMITTEE_SIZE as u64
    }

    #[test]
    fn the_message_seen_cache_records_once_per_slot_validator_and_subnet() {
        let (mut seen, _) = caches();
        assert!(!seen.contains(5, 9, 1));
        assert!(seen.record(5, 9, 1));
        assert!(seen.contains(5, 9, 1));
        assert!(!seen.record(5, 9, 1));
        assert!(seen.record(5, 9, 2));
    }

    #[test]
    fn a_message_outside_the_current_slot_is_ignored() {
        let (store, _) = store_with_head();
        let (seen, _) = caches();
        let message = message_from(0, 0);
        let later = slot_start_ms(&store, SLOT + 3);
        assert_eq!(
            message_cheap_checks(&seen, &store, &message, 0, later),
            Err(Outcome::Ignore(IgnoreReason::NotCurrentSlot))
        );
        let now = slot_start_ms(&store, SLOT);
        assert_eq!(
            message_cheap_checks(&seen, &store, &message, 0, now),
            Ok(())
        );
        assert_eq!(
            message_cheap_checks(&seen, &store, &message, 4, now),
            Err(Outcome::Reject(RejectReason::WrongSubnet))
        );
    }

    #[test]
    fn a_duplicate_is_ignored_on_the_same_subnet_and_not_on_another() {
        let (store, _) = store_with_head();
        let (mut seen, _) = caches();
        let message = message_from(0, 0);
        let now = slot_start_ms(&store, SLOT);
        seen.record(SLOT, 0, 0);
        assert_eq!(
            message_cheap_checks(&seen, &store, &message, 0, now),
            Err(Outcome::Ignore(IgnoreReason::AlreadySeen))
        );
        assert_eq!(
            message_cheap_checks(&seen, &store, &message, 1, now),
            Ok(())
        );
    }

    #[test]
    fn a_valid_message_returns_exactly_its_seats() {
        let (store, _) = store_with_head();
        let message = message_from(1, 1);
        assert_eq!(
            message_stateful_checks(&store, &message, subnet_of(1)),
            Ok(vec![(subnet_of(1), 1 % SYNC_SUBCOMMITTEE_SIZE)])
        );
    }

    #[test]
    fn the_wrong_subnet_a_non_member_and_a_bad_signature_are_rejected() {
        let (store, state) = store_with_head();
        let config = store.config();
        let message = message_from(1, 1);
        assert_eq!(
            message_stateful_checks(&store, &message, (subnet_of(1) + 1) % 4),
            Err(Outcome::Reject(RejectReason::WrongSubnet))
        );
        // A validator the registry has but the committee lacks: add one.
        let mut forged = message_from(1, 2);
        assert_eq!(
            check_message(&state, &config, &forged, None),
            Err(Outcome::Reject(RejectReason::BadSignature))
        );
        forged.validator_index = 100_000;
        assert_eq!(
            check_message(&state, &config, &forged, None),
            Err(Outcome::Reject(RejectReason::UnknownValidator))
        );
        // With fewer validators than seats a committee still has non-members
        // only when the registry is larger than the committee.
        let big = state_with_committees(VALIDATORS + 1);
        let outsider = VALIDATORS as u64;
        big.validator(outsider).expect("the outsider is registered");
        let outsider_message = message_from(outsider, VALIDATORS);
        assert_eq!(
            check_message(&big, &config, &outsider_message, None),
            Err(Outcome::Reject(RejectReason::NotInCommittee))
        );
    }

    #[test]
    fn an_uncached_head_state_is_ignored() {
        let store = store(0);
        assert_eq!(
            message_stateful_checks(&store, &message_from(0, 0), 0),
            Err(Outcome::Ignore(IgnoreReason::StateUnavailable))
        );
    }

    #[test]
    fn a_period_the_head_cannot_answer_is_ignored() {
        let (store, state) = store_with_head();
        let mut message = message_from(0, 0);
        message.slot = 3 * preset::SLOTS_PER_EPOCH * preset::EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
        assert_eq!(
            check_message(&state, &store.config(), &message, None),
            Err(Outcome::Ignore(IgnoreReason::SyncCommitteeUnavailable))
        );
    }

    // --- contributions ----------------------------------------------------

    /// Searches for an aggregator among the subcommittee's first members: a
    /// selection proof only selects one in `modulo` of them.
    fn contribution_from(
        config: &Config,
        subcommittee: u64,
        participants: &[usize],
    ) -> SignedContributionAndProof {
        let base = subcommittee as usize * SYNC_SUBCOMMITTEE_SIZE;
        let signing_root = sync_committee_message_signing_root(config, Root::ZERO, SLOT, root());
        let signatures: Vec<BlsSignature> = participants
            .iter()
            .map(|&position| sign_for(base + position, signing_root))
            .collect();
        let mut bits = <SyncCommitteeContribution as Clone>::clone(&SyncCommitteeContribution {
            slot: SLOT,
            beacon_block_root: root(),
            subcommittee_index: subcommittee,
            aggregation_bits: Default::default(),
            signature: BlsSignature::default(),
        });
        for &position in participants {
            bits.aggregation_bits.set(position, true).unwrap();
        }
        bits.signature = bls::aggregate(&signatures).unwrap();
        let selection_root =
            sync_selection_proof_signing_root(config, Root::ZERO, SLOT, subcommittee);
        // The first member whose selection proof selects it.
        let (aggregator, selection_proof) = (0..SYNC_SUBCOMMITTEE_SIZE)
            .map(|position| (base + position, sign_for(base + position, selection_root)))
            .find(|(_, proof)| is_sync_committee_aggregator(proof))
            .expect("some member of the subcommittee is selected");
        let message = ContributionAndProof {
            aggregator_index: aggregator as u64,
            contribution: bits,
            selection_proof,
        };
        let envelope = contribution_and_proof_signing_root(config, Root::ZERO, &message);
        SignedContributionAndProof {
            signature: sign_for(aggregator, envelope),
            message,
        }
    }

    fn mainnet_fulu() -> Config {
        Config::mainnet().with_fork_epoch(crate::beacon::ForkName::Fulu, 0)
    }

    #[test]
    fn a_valid_contribution_is_accepted() {
        let (store, state) = store_with_head();
        let signed = contribution_from(&mainnet_fulu(), 1, &[0, 3]);
        assert_eq!(
            check_contribution(&state, &store.config(), &signed),
            Outcome::Accept
        );
        let (_, seen) = caches();
        let now = slot_start_ms(&store, SLOT);
        assert_eq!(
            validate_contribution(&seen, &store, &signed, now),
            Outcome::Accept
        );
    }

    #[test]
    fn forged_signatures_are_each_rejected() {
        let (store, state) = store_with_head();
        let config = store.config();
        let good = contribution_from(&mainnet_fulu(), 1, &[0, 3]);

        let mut bad = good.clone();
        bad.message.selection_proof = sign_for(0, Root::repeat_byte(1));
        // Either not selected, or a forged proof: only the latter reaches the signature.
        if is_sync_committee_aggregator(&bad.message.selection_proof) {
            assert_eq!(
                check_contribution(&state, &config, &bad),
                Outcome::Reject(RejectReason::SelectionProof)
            );
        }

        let mut bad = good.clone();
        bad.signature = sign_for(0, Root::repeat_byte(1));
        assert_eq!(
            check_contribution(&state, &config, &bad),
            Outcome::Reject(RejectReason::AggregatorSignature)
        );

        let mut bad = good.clone();
        bad.message.contribution.signature = sign_for(0, Root::repeat_byte(1));
        // Re-sign the envelope so only the aggregate is wrong.
        let aggregator = bad.message.aggregator_index as usize;
        let envelope = contribution_and_proof_signing_root(&config, Root::ZERO, &bad.message);
        bad.signature = sign_for(aggregator, envelope);
        assert_eq!(
            check_contribution(&state, &config, &bad),
            Outcome::Reject(RejectReason::AggregateSignature)
        );
    }

    #[test]
    fn a_forged_selection_proof_is_rejected() {
        let (store, state) = store_with_head();
        let config = store.config();
        let good = contribution_from(&mainnet_fulu(), 1, &[0]);
        // Another member's proof for the same data is validly signed, but not by this aggregator.
        let selection_root = sync_selection_proof_signing_root(&config, Root::ZERO, SLOT, 1);
        let impostor = (0..SYNC_SUBCOMMITTEE_SIZE * 4)
            .map(|index| sign_for(index, selection_root))
            .find(|proof| {
                is_sync_committee_aggregator(proof) && *proof != good.message.selection_proof
            })
            .expect("another selected signature exists");
        let mut bad = good;
        bad.message.selection_proof = impostor;
        assert_eq!(
            check_contribution(&state, &config, &bad),
            Outcome::Reject(RejectReason::SelectionProof)
        );
    }

    #[test]
    fn contribution_cheap_checks_cover_each_rule() {
        let (store, _) = store_with_head();
        let (_, mut seen) = caches();
        let now = slot_start_ms(&store, SLOT);
        let good = contribution_from(&mainnet_fulu(), 1, &[0, 3]);
        assert_eq!(contribution_cheap_checks(&seen, &store, &good, now), Ok(()));

        // Not the current slot.
        let later = slot_start_ms(&store, SLOT + 3);
        assert_eq!(
            contribution_cheap_checks(&seen, &store, &good, later),
            Err(Outcome::Ignore(IgnoreReason::NotCurrentSlot))
        );
        // Subcommittee out of range.
        let mut bad = good.clone();
        bad.message.contribution.subcommittee_index = 4;
        assert_eq!(
            contribution_cheap_checks(&seen, &store, &bad, now),
            Err(Outcome::Reject(RejectReason::SubcommitteeIndex))
        );
        // No participants.
        let mut bad = good.clone();
        bad.message.contribution.aggregation_bits = Default::default();
        assert_eq!(
            contribution_cheap_checks(&seen, &store, &bad, now),
            Err(Outcome::Reject(RejectReason::NoParticipants))
        );
        // Not selected.
        let mut bad = good.clone();
        bad.message.selection_proof = (0u8..=255)
            .map(|byte| BlsSignature([byte; 96]))
            .find(|proof| !is_sync_committee_aggregator(proof))
            .expect("an unselected value exists");
        assert_eq!(
            contribution_cheap_checks(&seen, &store, &bad, now),
            Err(Outcome::Reject(RejectReason::NotAggregator))
        );

        // Seen: the same aggregator, then a covered subset from another.
        assert!(seen.record(&good));
        assert_eq!(
            contribution_cheap_checks(&seen, &store, &good, now),
            Err(Outcome::Ignore(IgnoreReason::CoveredBits))
        );
        let mut other_aggregator = good.clone();
        other_aggregator.message.contribution.aggregation_bits = Default::default();
        other_aggregator
            .message
            .contribution
            .aggregation_bits
            .set(0, true)
            .unwrap();
        other_aggregator.message.aggregator_index += 1;
        assert_eq!(
            contribution_cheap_checks(&seen, &store, &other_aggregator, now),
            Err(Outcome::Ignore(IgnoreReason::CoveredBits))
        );
        // The same aggregator with a bit the data lacks is still AlreadySeen.
        let mut same_aggregator = good.clone();
        same_aggregator
            .message
            .contribution
            .aggregation_bits
            .set(5, true)
            .unwrap();
        assert_eq!(
            contribution_cheap_checks(&seen, &store, &same_aggregator, now),
            Err(Outcome::Ignore(IgnoreReason::AlreadySeen))
        );
    }

    #[test]
    fn recording_a_contribution_twice_reports_the_second_as_lost() {
        let (_, mut seen) = caches();
        let good = contribution_from(&mainnet_fulu(), 1, &[0, 3]);
        assert!(seen.record(&good));
        assert!(!seen.record(&good));
    }
}
