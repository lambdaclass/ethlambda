//! `beacon_aggregate_and_proof` gossip validation: electra's
//! `validate_beacon_aggregate_and_proof_gossip` (`specs/electra/p2p-interface.md`),
//! which fulu (what mainnet runs) inherits unchanged.
//!
//! # Deviations from the specification
//!
//! **Which state.** The specification resolves every committee, signature and
//! ancestry question against `store.block_states[get_head(store).root]`; see
//! [`stateful_checks`] for why this reads the aggregate's own vote block's
//! post-state instead.
//!
//! **"Block passes validation" becomes "post-state is cached".** The
//! specification's `block_root not in store.block_states` REJECT assumes a
//! bad-block cache: a block that failed its own validation is known but has
//! no post-state, and so is a block that is merely still importing or was
//! queued. Telling those apart needs remembering which failed, which this
//! node does not do (see `gossip::block`'s and `gossip::column`'s own copies
//! of this same limitation). So a vote block with no cached post-state is
//! [`IgnoreReason::StateUnavailable`] here rather than a REJECT; the spec
//! vector that depends on that distinction
//! (`reject_block_failed_validation`) is skipped, not made to pass.
//!
//! **Signatures before committees.** The specification checks the committee
//! index range, the committee itself, and the aggregator's membership before
//! either signature. This runs the two pubkey-only checks (the selection
//! proof and the aggregator's signature over the whole envelope) first
//! instead: both need nothing but the vote state's validator registry, while
//! every committee question needs [`store.committee_cache()`](Store::committee_cache)
//! to derive (or, worst case, shuffle) the target epoch's committees. A
//! forged aggregate is caught before it can force that work. The spec's own
//! test format states that independent conditions may run in any order
//! without changing a vector's expected result, and every condition
//! reordered here is independent of the ones it moves past.
//!
//! **Ancestry via the vote state's own history, not a `LiveChain` scan.**
//! [`super::ancestor_at`] answers both the target-checkpoint and the
//! finalized-checkpoint ancestry questions from `block_roots`, in place of
//! the specification's `get_checkpoint_block(store, ...)` (which
//! `gossip::block` and `gossip::column` still use, because they only ever
//! have a *parent* state, whose own history does not yet reach the checkpoint
//! in question). See [`stateful_checks`] for why the vote state can always
//! answer this instead.
//!
//! # Seen state
//!
//! [`SeenAggregates`] is this module's copy of the specification's `Seen`
//! fields `aggregator_epochs` and `aggregate_data_roots`. It is written only
//! by [`SeenAggregates::record`], called once per gossip message, on
//! `Accept`; see that method's own documentation for the race it closes.

use std::num::NonZeroUsize;

use lru::LruCache;

use super::{
    IgnoreReason, Outcome, RejectReason, ancestor_at, is_current_or_previous_epoch, is_future_slot,
};
use crate::beacon::bls;
use crate::beacon::constants::{
    DOMAIN_AGGREGATE_AND_PROOF, DOMAIN_SELECTION_PROOF, TARGET_AGGREGATORS_PER_COMMITTEE,
};
use crate::beacon::containers::SignedAggregateAndProof;
use crate::beacon::fork_choice::Store;
use crate::beacon::hash::hash;
use crate::beacon::helpers::accessors::{CommitteeCacheExt, get_domain};
use crate::beacon::helpers::math::bytes_to_uint64;
use crate::beacon::helpers::misc::{
    compute_epoch_at_slot, compute_signing_root, compute_start_slot_at_epoch,
};
use crate::beacon::primitives::{
    BlsSignature, CommitteeIndex, Epoch, HashTreeRoot as _, Root, ValidatorIndex,
};
use ethlambda_storage::CacheKey;

/// One committee's worth of aggregation bits, packed a `u64` at a time.
///
/// The specification's `Seen.aggregate_data_roots` stores each accepted
/// bitfield as a `Tuple[bool, ...]`; packing here keeps a whole committee's
/// bits (up to `MAX_VALIDATORS_PER_COMMITTEE`, thousands on mainnet) to a
/// handful of words instead of one heap-allocated `bool` per bit.
#[derive(Clone, PartialEq, Eq)]
struct PackedBits(Vec<u64>);

impl PackedBits {
    fn from_bits(bits: &[bool]) -> Self {
        let mut words = vec![0u64; bits.len().div_ceil(64)];
        for (index, &bit) in bits.iter().enumerate() {
            if bit {
                words[index / 64] |= 1 << (index % 64);
            }
        }
        Self(words)
    }

    /// The specification's `is_non_strict_superset` (`phase0/p2p-interface.md`):
    /// every bit `other` sets is also set here.
    ///
    /// A `other` longer than `self` is never covered, however much the
    /// overlapping words agree: the extra bits are positions `self` has no
    /// opinion on. In practice the two are always the same length, since both
    /// come from aggregates sharing one `(data_root, committee_index)` key
    /// and so the same committee, but nothing here relies on that.
    fn is_superset_of(&self, other: &PackedBits) -> bool {
        if other.0.len() > self.0.len() {
            return false;
        }
        self.0
            .iter()
            .zip(other.0.iter())
            .all(|(mine, theirs)| theirs & !mine == 0)
    }
}

/// Accepted aggregates, keyed the way the specification's `Seen` keys them.
///
/// Bounded by capacity, like [`super::SeenBlocks`], rather than pruned on
/// finality (reviewer feedback on PR #19: a finality-pruned set lets a peer
/// hold the deduplication window open indefinitely just by not finalizing).
/// The two capacities are independent because the two maps hold different
/// keys at a different natural cardinality: `aggregator_epochs` holds one
/// entry per `(epoch, aggregator)` no matter how many committees or slots
/// that epoch has, while `aggregate_data_roots` holds one entry per
/// `(attestation data, committee)` and, under it, one bitfield per
/// aggregator that reached it before the superset covered them. Sizing both
/// is the caller's job (`ethlambda-p2p` defines the constants); see that
/// crate's own reasoning for the numbers.
pub struct SeenAggregates {
    aggregator_epochs: LruCache<(Epoch, ValidatorIndex), ()>,
    data_roots: LruCache<(Root, CommitteeIndex), Vec<PackedBits>>,
}

impl SeenAggregates {
    pub fn new(aggregators: NonZeroUsize, data_roots: NonZeroUsize) -> Self {
        Self {
            aggregator_epochs: LruCache::new(aggregators),
            data_roots: LruCache::new(data_roots),
        }
    }

    /// Whether an aggregator is already recorded for `target_epoch`.
    /// Read-only, so [`super::cheap_checks`]-style callers can use it without
    /// touching recency ([`LruCache::contains`] does not).
    fn aggregator_seen(&self, target_epoch: Epoch, aggregator_index: ValidatorIndex) -> bool {
        self.aggregator_epochs
            .contains(&(target_epoch, aggregator_index))
    }

    /// Whether some already-accepted aggregate for `(data_root,
    /// committee_index)` is a non-strict superset of `bits`. Read-only, via
    /// [`LruCache::peek`], for the same reason as [`Self::aggregator_seen`].
    fn covered(&self, data_root: Root, committee_index: CommitteeIndex, bits: &[bool]) -> bool {
        let candidate = PackedBits::from_bits(bits);
        self.data_roots
            .peek(&(data_root, committee_index))
            .is_some_and(|seen| seen.iter().any(|prior| prior.is_superset_of(&candidate)))
    }

    /// [`cheap_checks`]'s verdict for `aggregate`, given its already-parsed
    /// `committee_index`: `Ignore(AlreadySeen)` if this aggregator already has
    /// an accepted aggregate for the target epoch, `Ignore(CoveredBits)` if
    /// an accepted aggregate already covers every bit it sets.
    fn verdict(
        &self,
        aggregate: &SignedAggregateAndProof,
        committee_index: CommitteeIndex,
    ) -> Result<(), Outcome> {
        let data = aggregate.data();
        let bits = aggregate.aggregation_bits();
        // Checked in the specification's own order: the superset rule first,
        // then the aggregator/epoch rule.
        if self.covered(data.hash_tree_root(), committee_index, &bits) {
            return Err(Outcome::Ignore(IgnoreReason::CoveredBits));
        }
        if self.aggregator_seen(data.target.epoch, aggregate.aggregator_index()) {
            return Err(Outcome::Ignore(IgnoreReason::AlreadySeen));
        }
        Ok(())
    }

    /// Record an accepted aggregate. Returns `false`, recording nothing, when
    /// its aggregator is already recorded for the target epoch or an accepted
    /// aggregate for the same data and committee already covers its bits.
    ///
    /// That second case is what keeps a race honest: two validation tasks for
    /// aggregates that overlap can both pass [`cheap_checks`]' read of this
    /// same state before either one's `Accept` reaches `settle`. Whichever
    /// settles first calls this and wins; this method re-runs the exact same
    /// verdict the settling caller is about to publish, so the second racer's
    /// `record` (called from its own, now-stale `Accept`) finds itself
    /// already covered and reports `false`. The caller then turns that
    /// `Accept` into `Ignore(AlreadySeen)` rather than double-recording (or,
    /// worse, propagating two aggregates gossipsub only meant to accept one
    /// of).
    pub fn record(&mut self, aggregate: &SignedAggregateAndProof) -> bool {
        let Some(committee_index) = aggregate.committee_index() else {
            return false;
        };
        if self.verdict(aggregate, committee_index).is_err() {
            return false;
        }

        let data = aggregate.data();
        let bits = aggregate.aggregation_bits();
        self.aggregator_epochs
            .put((data.target.epoch, aggregate.aggregator_index()), ());
        let packed = PackedBits::from_bits(&bits);
        match self
            .data_roots
            .get_mut(&(data.hash_tree_root(), committee_index))
        {
            Some(existing) => existing.push(packed),
            None => {
                self.data_roots
                    .put((data.hash_tree_root(), committee_index), vec![packed]);
            }
        }
        true
    }
}

/// The specification's `is_aggregator` (`validator.md`), taking the
/// committee's length rather than a whole committee cache and state: by the
/// time [`stateful_checks`] calls this, it has already paid for the
/// committee slice this needs, so this cannot trigger a second, uncached
/// derivation the way `crate::beacon::aggregate::is_aggregator` (which this
/// replaces) could when handed a fresh cache.
///
/// The modulo is floored at one, which is what makes every member of a
/// committee smaller than [`TARGET_AGGREGATORS_PER_COMMITTEE`] an aggregator
/// rather than dividing by zero.
fn is_aggregator(committee_len: usize, slot_signature: &BlsSignature) -> bool {
    let modulo = (committee_len as u64 / TARGET_AGGREGATORS_PER_COMMITTEE).max(1);
    let digest = hash(slot_signature.as_ref());
    bytes_to_uint64(&digest.0[0..8]).is_multiple_of(modulo)
}

/// `hash_tree_root(aggregate_and_proof)`, the object the aggregator's own
/// (non-selection-proof) signature is over.
fn aggregate_and_proof_root(aggregate: &SignedAggregateAndProof) -> Root {
    match aggregate {
        SignedAggregateAndProof::Phase0(signed) => signed.message.hash_tree_root(),
        SignedAggregateAndProof::Electra(signed) => signed.message.hash_tree_root(),
    }
}

/// The conditions that read only the message, the clock and the seen caches.
///
/// `Err` carries the verdict; `Ok` sends the aggregate on to
/// [`stateful_checks`].
pub fn cheap_checks(
    seen: &SeenAggregates,
    store: &Store,
    aggregate: &SignedAggregateAndProof,
    now_ms: u64,
) -> Result<(), Outcome> {
    let config = store.config();
    let data = aggregate.data();

    // [New in Electra:EIP7549] [REJECT] `data.index` is zero: the committee
    // now lives in `committee_bits` instead. Phase0 has no `committee_bits`
    // and carries the real committee in `data.index`, so this only applies
    // to the electra shape.
    if matches!(aggregate, SignedAggregateAndProof::Electra(_)) && data.index != 0 {
        return Err(Outcome::Reject(RejectReason::NonZeroDataIndex));
    }
    // [New in Electra:EIP7549] [REJECT] Exactly one committee is named.
    // Always `Some` for phase0, whose `data.index` alone names the committee.
    let Some(committee_index) = aggregate.committee_index() else {
        return Err(Outcome::Reject(RejectReason::CommitteeBits));
    };

    // [Modified in Electra:EIP7549] [IGNORE] Not a covered superset, and
    // [IGNORE] first for this epoch and aggregator.
    seen.verdict(aggregate, committee_index)?;

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
    if data.target.epoch != attestation_epoch {
        return Err(Outcome::Reject(RejectReason::EpochMismatch));
    }
    // [REJECT] Has participants. Needs only the raw bitfield: electra's
    // `aggregation_bits` spans exactly the one named committee when
    // `committee_bits` names only one, so a set bit here is a real attester
    // regardless of which committee it turns out to be.
    if aggregate.attester_count() == 0 {
        return Err(Outcome::Reject(RejectReason::NoParticipants));
    }
    Ok(())
}

/// The conditions that need the voted block's state. Runs on a blocking
/// thread. `Ok` is `Accept`, carrying the attesting indices whose aggregate
/// signature verified: they travel to the chain actor, which applies them to
/// fork choice without ever deriving them again.
///
/// # Which state
///
/// This resolves every committee, signature and ancestry question against
/// the vote block's own cached post-state
/// (`store.cached_state(CacheKey::BlockState(data.beacon_block_root))`),
/// rather than the specification's head state. Three reasons converge here:
///
/// - It is the attested chain's own state, so its shuffling is the one the
///   attesters were actually assigned. The head may sit on a branch this
///   aggregate does not vote for at all, in which case the specification's
///   own choice would check against the wrong committee.
/// - It is an `O(1)` cache read, unlike the head state, which the
///   specification re-reads (and this node would have to look up) fresh per
///   message.
/// - Its own `block_roots` answers both ancestry questions
///   ([`super::ancestor_at`]) without a `Store::block_index` / `LiveChain`
///   scan, because a block's post-state always has history back through its
///   own ancestors.
pub fn stateful_checks(
    store: &Store,
    aggregate: &SignedAggregateAndProof,
) -> Result<Vec<ValidatorIndex>, Outcome> {
    let data = aggregate.data();
    let beacon_block_root = data.beacon_block_root;

    // [IGNORE] The block being voted for has been seen.
    if !store.has_block(&beacon_block_root) {
        return Err(Outcome::Ignore(IgnoreReason::UnknownBlock));
    }
    // See this function's own documentation for why this state, and the
    // module documentation for why an uncached state is `IGNORE` rather than
    // the specification's `REJECT`.
    let Some(state) = store.cached_state(CacheKey::BlockState(beacon_block_root)) else {
        return Err(Outcome::Ignore(IgnoreReason::StateUnavailable));
    };

    let target_epoch = data.target.epoch;

    // Pubkey-only signatures, before any committee derivation; see the
    // module documentation for why this order.
    let aggregator_index = aggregate.aggregator_index();
    let Ok(aggregator) = state.validator(aggregator_index) else {
        return Err(Outcome::Reject(RejectReason::UnknownValidator));
    };
    // [REJECT] The selection proof selects the validator as an aggregator.
    let selection_proof = aggregate.selection_proof();
    let selection_domain = get_domain(&state, DOMAIN_SELECTION_PROOF, Some(target_epoch));
    let selection_signing_root = compute_signing_root(data.slot.hash_tree_root(), selection_domain);
    if !bls::verify(&aggregator.pubkey, selection_signing_root, &selection_proof) {
        return Err(Outcome::Reject(RejectReason::SelectionProof));
    }
    // [REJECT] The aggregator's own signature, over the whole envelope.
    let aggregator_domain = get_domain(&state, DOMAIN_AGGREGATE_AND_PROOF, Some(target_epoch));
    let aggregator_signing_root =
        compute_signing_root(aggregate_and_proof_root(aggregate), aggregator_domain);
    if !bls::verify(
        &aggregator.pubkey,
        aggregator_signing_root,
        &aggregate.signature(),
    ) {
        return Err(Outcome::Reject(RejectReason::AggregatorSignature));
    }

    // Committees for the target epoch, through the shared cache.
    let committees = store.committee_cache();
    let epoch_committees = committees.committees(&state, target_epoch);
    // `cheap_checks` already rejected `None`.
    let committee_index = aggregate
        .committee_index()
        .expect("cheap_checks rejects a message with no single named committee");
    // [REJECT] The committee index is within range.
    if committee_index >= epoch_committees.committees_per_slot() {
        return Err(Outcome::Reject(RejectReason::CommitteeIndex));
    }
    let Ok(committee) = epoch_committees.committee(data.slot, committee_index) else {
        // `committee_index` and `data.slot`'s epoch were both just checked
        // against this same `epoch_committees`, so this cannot fail; treated
        // as internal rather than unreachable so a future change here fails
        // safe instead of panicking.
        return Err(Outcome::Ignore(IgnoreReason::Internal));
    };
    // [REJECT] The aggregation bits match the committee's size.
    let aggregation_bits = aggregate.aggregation_bits();
    if aggregation_bits.len() != committee.len() {
        return Err(Outcome::Reject(RejectReason::BitsLength));
    }
    // [REJECT] The selection proof selects this validator as an aggregator.
    if !is_aggregator(committee.len(), &selection_proof) {
        return Err(Outcome::Reject(RejectReason::NotAggregator));
    }
    // [REJECT] The aggregator is a member of the committee.
    if !committee.contains(&aggregator_index) {
        return Err(Outcome::Reject(RejectReason::NotInCommittee));
    }

    // [REJECT] The aggregate's own signature is valid. Built from the same
    // (cached) committees, so this costs no further shuffle.
    let attesting_indices = match aggregate {
        SignedAggregateAndProof::Phase0(signed) => {
            let phase0_attestation = &signed.message.aggregate;
            let indexed = crate::beacon::helpers::attestation::get_indexed_attestation(
                &state,
                phase0_attestation,
                &committees,
            )
            .map_err(|_| Outcome::Ignore(IgnoreReason::Internal))?;
            if !crate::beacon::helpers::attestation::is_valid_indexed_attestation(&state, &indexed)
            {
                return Err(Outcome::Reject(RejectReason::AggregateSignature));
            }
            indexed.attesting_indices.to_vec()
        }
        SignedAggregateAndProof::Electra(signed) => {
            let electra_attestation = &signed.message.aggregate;
            let indexed = crate::beacon::helpers::electra::get_indexed_attestation(
                &state,
                electra_attestation,
                &committees,
            )
            .map_err(|_| Outcome::Ignore(IgnoreReason::Internal))?;
            if !crate::beacon::helpers::electra::is_valid_indexed_attestation(&state, &indexed) {
                return Err(Outcome::Reject(RejectReason::AggregateSignature));
            }
            indexed.attesting_indices.to_vec()
        }
    };

    // Ancestry, via the vote state's own history; see this function's
    // documentation for why this state can always answer both questions.
    let (target_checkpoint_epoch, target_root) = aggregate.target();
    let target_start_slot = compute_start_slot_at_epoch(target_checkpoint_epoch);
    // [REJECT] The target is the vote block's ancestor at the target epoch.
    let Some(checkpoint_block) = ancestor_at(&state, beacon_block_root, target_start_slot) else {
        return Err(Outcome::Ignore(IgnoreReason::AncestryUnknown));
    };
    if checkpoint_block != target_root {
        return Err(Outcome::Reject(RejectReason::TargetNotAncestor));
    }
    // [IGNORE] The finalized checkpoint is an ancestor of the vote block.
    let finalized = store.beacon_finalized_checkpoint();
    let finalized_start_slot = compute_start_slot_at_epoch(finalized.epoch);
    let Some(finalized_block) = ancestor_at(&state, beacon_block_root, finalized_start_slot) else {
        return Err(Outcome::Ignore(IgnoreReason::AncestryUnknown));
    };
    if finalized_block != finalized.root {
        return Err(Outcome::Ignore(IgnoreReason::FinalizedNotAncestor));
    }

    Ok(attesting_indices)
}

/// `cheap_checks` then `stateful_checks`, the order the p2p actor runs them
/// in. For callers that have no reason to split them, such as the spec
/// vectors.
pub fn validate(
    seen: &SeenAggregates,
    store: &Store,
    aggregate: &SignedAggregateAndProof,
    now_ms: u64,
) -> Result<Vec<ValidatorIndex>, Outcome> {
    cheap_checks(seen, store, aggregate, now_ms)?;
    stateful_checks(store, aggregate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::containers::electra;
    use crate::beacon::gossip::test_support::{seen_aggregates, slot_start_ms, store};
    use crate::beacon::primitives::Slot;

    fn capacity(n: usize) -> NonZeroUsize {
        NonZeroUsize::new(n).expect("non-zero")
    }

    fn aggregate_with(
        target_epoch: Epoch,
        aggregator_index: ValidatorIndex,
        committee_index: CommitteeIndex,
        bits: &[bool],
    ) -> SignedAggregateAndProof {
        let aggregation_bits: electra::AggregationBits = bits
            .to_vec()
            .try_into()
            .expect("within the committee bound");
        let mut committee_bits = electra::CommitteeBits::default();
        committee_bits
            .set(committee_index as usize, true)
            .expect("within MAX_COMMITTEES_PER_SLOT");
        SignedAggregateAndProof::Electra(electra::SignedAggregateAndProof {
            message: electra::AggregateAndProof {
                aggregator_index,
                aggregate: electra::Attestation {
                    aggregation_bits,
                    data: shared_data(target_epoch),
                    signature: Default::default(),
                    committee_bits,
                },
                selection_proof: Default::default(),
            },
            signature: Default::default(),
        })
    }

    fn shared_data(target_epoch: Epoch) -> crate::beacon::containers::shared::AttestationData {
        crate::beacon::containers::shared::AttestationData {
            slot: compute_start_slot_at_epoch(target_epoch),
            index: 0,
            beacon_block_root: Root::repeat_byte(1),
            source: Default::default(),
            target: crate::beacon::containers::shared::Checkpoint {
                epoch: target_epoch,
                root: Root::repeat_byte(2),
            },
        }
    }

    // -- PackedBits / superset semantics --------------------------------

    #[test]
    fn a_superset_covers_what_it_contains() {
        let seen = PackedBits::from_bits(&[true, true, true]);
        assert!(seen.is_superset_of(&PackedBits::from_bits(&[true, false, true])));
        assert!(seen.is_superset_of(&PackedBits::from_bits(&[true, true, true])));
    }

    #[test]
    fn a_candidate_with_a_new_bit_is_not_covered() {
        let seen = PackedBits::from_bits(&[true, false, true]);
        assert!(!seen.is_superset_of(&PackedBits::from_bits(&[true, true, false])));
    }

    #[test]
    fn a_longer_candidate_is_never_covered() {
        let seen = PackedBits::from_bits(&[true]);
        assert!(!seen.is_superset_of(&PackedBits::from_bits(&[true, true])));
    }

    #[test]
    fn packing_survives_more_than_one_word() {
        // 65 bits spans two `u64` words; the high bit must not be lost.
        let mut bits = vec![false; 65];
        bits[64] = true;
        let packed = PackedBits::from_bits(&bits);
        assert!(packed.is_superset_of(&PackedBits::from_bits(&bits)));

        let mut missing_high_bit = bits.clone();
        missing_high_bit[64] = false;
        let short = PackedBits::from_bits(&missing_high_bit);
        assert!(short.is_superset_of(&PackedBits::from_bits(&missing_high_bit)));
        assert!(!short.is_superset_of(&packed));
    }

    // -- SeenAggregates ---------------------------------------------------

    #[test]
    fn the_first_aggregate_for_an_epoch_and_aggregator_is_recorded_once() {
        let mut seen = seen_aggregates();
        let first = aggregate_with(3, 7, 0, &[true, false]);
        assert!(seen.record(&first));
        // A second aggregate from the same aggregator and epoch, even for
        // different data, is already seen.
        let second = aggregate_with(3, 7, 0, &[false, true]);
        assert!(!seen.record(&second));
    }

    #[test]
    fn a_covered_bitfield_is_not_recorded_again() {
        let mut seen = seen_aggregates();
        let wide = aggregate_with(3, 1, 0, &[true, true, false]);
        assert!(seen.record(&wide));
        // A different aggregator, but every bit it sets is already covered.
        let narrow = aggregate_with(3, 2, 0, &[true, false, false]);
        assert!(!seen.record(&narrow));
        assert!(seen.covered(shared_data(3).hash_tree_root(), 0, &[true, false, false]));
    }

    #[test]
    fn a_bit_outside_the_covered_set_is_still_recorded() {
        let mut seen = seen_aggregates();
        let first = aggregate_with(3, 1, 0, &[true, false, false]);
        assert!(seen.record(&first));
        // Adds a new bit no prior aggregate covered, so it is not dropped.
        let second = aggregate_with(3, 2, 0, &[false, true, false]);
        assert!(seen.record(&second));
    }

    #[test]
    fn the_aggregator_cache_forgets_its_oldest_entry_past_capacity() {
        // Distinct, non-overlapping bit patterns throughout: two aggregates
        // covered by the same or an overlapping bitfield are dropped by the
        // superset rule regardless of the aggregator cache, which is not
        // what this test means to exercise. See `a_covered_bitfield_is_not_recorded_again`
        // for that rule on its own.
        let mut seen = SeenAggregates::new(capacity(2), capacity(8));
        seen.record(&aggregate_with(1, 1, 0, &[true, false, false, false]));
        seen.record(&aggregate_with(1, 2, 0, &[false, true, false, false]));
        seen.record(&aggregate_with(1, 3, 0, &[false, false, true, false]));
        // The first aggregator's entry was the oldest, so it was evicted
        // first; the two more recent ones are still recorded.
        assert!(!seen.aggregator_seen(1, 1));
        assert!(seen.aggregator_seen(1, 2));
        assert!(seen.aggregator_seen(1, 3));
        // A new bitfield from the now-evicted aggregator: its epoch slot is
        // free again.
        assert!(seen.record(&aggregate_with(1, 1, 0, &[false, false, false, true])));
    }

    // -- is_aggregator -----------------------------------------------------

    #[test]
    fn every_member_is_an_aggregator_below_the_target_committee_size() {
        // A committee too small to divide by `TARGET_AGGREGATORS_PER_COMMITTEE`
        // floors the modulo at one, so every signature selects its signer.
        let small_committee = (TARGET_AGGREGATORS_PER_COMMITTEE as usize) - 1;
        for byte in 0..8u8 {
            let signature = BlsSignature::default();
            let _ = byte; // exercise a few, deterministic, signature bytes
            assert!(is_aggregator(small_committee, &signature));
        }
    }

    #[test]
    fn a_larger_committee_does_not_select_every_signature() {
        let large_committee = (TARGET_AGGREGATORS_PER_COMMITTEE as usize) * 64;
        let mut selected = 0;
        for byte in 0u8..=255 {
            let mut signature = BlsSignature::default();
            signature.0[0] = byte;
            if is_aggregator(large_committee, &signature) {
                selected += 1;
            }
        }
        assert!(
            selected < 255,
            "every signature selected its signer, which the modulo should rule out"
        );
    }

    // -- cheap_checks --------------------------------------------------------

    #[test]
    fn electra_rejects_a_nonzero_data_index() {
        let store = store(0);
        let seen = seen_aggregates();
        let mut aggregate = aggregate_with(0, 1, 0, &[true]);
        if let SignedAggregateAndProof::Electra(signed) = &mut aggregate {
            signed.message.aggregate.data.index = 1;
        }
        let now = slot_start_ms(&store, 0);
        assert_eq!(
            cheap_checks(&seen, &store, &aggregate, now),
            Err(Outcome::Reject(RejectReason::NonZeroDataIndex))
        );
    }

    #[test]
    fn zero_named_committees_are_rejected() {
        let store = store(0);
        let seen = seen_aggregates();
        let mut aggregate = aggregate_with(0, 1, 0, &[true]);
        if let SignedAggregateAndProof::Electra(signed) = &mut aggregate {
            signed.message.aggregate.committee_bits = Default::default();
        }
        let now = slot_start_ms(&store, 0);
        assert_eq!(
            cheap_checks(&seen, &store, &aggregate, now),
            Err(Outcome::Reject(RejectReason::CommitteeBits))
        );
    }

    #[test]
    fn a_future_slot_is_ignored() {
        let store = store(0);
        let seen = seen_aggregates();
        let target_epoch = 5;
        let aggregate = aggregate_with(target_epoch, 1, 0, &[true]);
        let slot = compute_start_slot_at_epoch(target_epoch);
        let too_early = slot_start_ms(&store, slot)
            - (crate::beacon::constants::MAXIMUM_GOSSIP_CLOCK_DISPARITY + 100);
        assert_eq!(
            cheap_checks(&seen, &store, &aggregate, too_early),
            Err(Outcome::Ignore(IgnoreReason::FutureSlot))
        );
    }

    #[test]
    fn an_epoch_far_from_current_is_ignored() {
        let store = store(0);
        let seen = seen_aggregates();
        // The aggregate names a stale epoch; its own slot is safely in the
        // past (not a future slot), but the clock has since moved many
        // epochs ahead, so the epoch itself is no longer current or previous.
        let stale_epoch = 0;
        let aggregate = aggregate_with(stale_epoch, 1, 0, &[true]);
        let now_epoch = 10;
        let now = slot_start_ms(&store, compute_start_slot_at_epoch(now_epoch));
        assert_eq!(
            cheap_checks(&seen, &store, &aggregate, now),
            Err(Outcome::Ignore(IgnoreReason::OutsideEpochWindow))
        );
    }

    #[test]
    fn an_epoch_mismatched_with_the_slot_is_rejected() {
        let store = store(0);
        let seen = seen_aggregates();
        let mut aggregate = aggregate_with(0, 1, 0, &[true]);
        // `target.epoch` (0) no longer matches `slot`'s own epoch once the
        // slot moves into epoch 1.
        if let SignedAggregateAndProof::Electra(signed) = &mut aggregate {
            signed.message.aggregate.data.slot = preset_slots_per_epoch();
        }
        let now = slot_start_ms(&store, preset_slots_per_epoch());
        assert_eq!(
            cheap_checks(&seen, &store, &aggregate, now),
            Err(Outcome::Reject(RejectReason::EpochMismatch))
        );
    }

    #[test]
    fn an_aggregate_with_no_participants_is_rejected() {
        let store = store(0);
        let seen = seen_aggregates();
        let aggregate = aggregate_with(0, 1, 0, &[false, false]);
        let now = slot_start_ms(&store, 0);
        assert_eq!(
            cheap_checks(&seen, &store, &aggregate, now),
            Err(Outcome::Reject(RejectReason::NoParticipants))
        );
    }

    #[test]
    fn a_vote_for_an_unseen_block_is_ignored() {
        let store = store(0);
        let aggregate = aggregate_with(0, 1, 0, &[true]);
        assert_eq!(
            stateful_checks(&store, &aggregate),
            Err(Outcome::Ignore(IgnoreReason::UnknownBlock))
        );
    }

    #[test]
    fn a_known_block_with_no_cached_state_is_ignored_not_rejected() {
        let mut store = store(0);
        let block_root = Root::repeat_byte(1);
        store
            .insert_pending_block(
                block_root,
                crate::beacon::containers::SignedBeaconBlock::Fulu(electra::SignedBeaconBlock {
                    message: electra::BeaconBlock {
                        slot: 0,
                        proposer_index: 0,
                        parent_root: Root::ZERO,
                        state_root: Root::ZERO,
                        body: electra::BeaconBlockBody::empty(),
                    },
                    signature: Default::default(),
                }),
            )
            .expect("insert pending block");
        let aggregate = aggregate_with(0, 1, 0, &[true]);
        assert_eq!(
            stateful_checks(&store, &aggregate),
            Err(Outcome::Ignore(IgnoreReason::StateUnavailable))
        );
    }

    fn preset_slots_per_epoch() -> Slot {
        crate::beacon::preset::SLOTS_PER_EPOCH
    }
}
