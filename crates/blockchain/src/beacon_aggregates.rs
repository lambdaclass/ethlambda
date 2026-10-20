//! The chain actor's state for `beacon_aggregate_and_proof`.
//!
//! Two things that have to live beside the store rather than in the p2p
//! layer, and one reason each.
//!
//! **The applied-bits gate**, a running union of the aggregation bits this
//! actor has already applied to fork choice per `(target_epoch,
//! hash_tree_root(data), committee_index)`. `ethlambda-p2p`'s gossip
//! validation owns the specification's own `Seen` sets now (a garbage
//! aggregate can no longer censor a genuine one, since gossip only records a
//! key once its signatures verify), so this gate is not about spec conformance
//! at all: it is what keeps a committee's other aggregators, each carrying the
//! same votes and each individually accepted by gossip, from paying
//! [`fork_choice::apply_verified_aggregate`]'s own work more than once.
//!
//! **The deferral queue**, because `validate_on_attestation` requires
//! `get_current_slot(store) >= attestation.data.slot + 1` and aggregates are
//! published two thirds of the way through the slot they vote for. Every
//! aggregate therefore arrives one slot too early to be applied. Without a
//! queue this topic would contribute nothing at all, which is why the queue is
//! not an optimization: it is the difference between the feature working and
//! not. The specification licenses it directly ("consider scheduling it for
//! later processing in such case"), and lighthouse does the same thing in
//! `process_attestation_queue`.
//!
//! # What bounds this
//!
//! A slot carries at most
//! [`aggregate::MAX_AGGREGATES_PER_SLOT`](ethlambda_state_transition::beacon::aggregate::MAX_AGGREGATES_PER_SLOT)
//! aggregates, so the queue is capped at a small multiple of that. The
//! applied-bits gate is pruned by the store's own clock, not by finality: see
//! [`AggregateGossip::prune`].

use std::collections::{HashMap, VecDeque};

use ethlambda_state_transition::beacon::aggregate::{
    MAX_AGGREGATES_PER_SLOT, is_non_strict_superset,
};
use ethlambda_types::beacon::containers::SignedAggregateAndProof;
use ethlambda_types::beacon::primitives::{
    CommitteeIndex, Epoch, HashTreeRoot as _, Root, Slot, ValidatorIndex,
};

/// How many slots' worth of aggregates the deferral queue may hold.
///
/// Two rather than one: an aggregate for slot N becomes applicable at slot
/// N+1, so a queue draining once per slot holds one slot's worth in the steady
/// state and needs room for a second while the first is still being drained.
/// Anything past that is a backlog the next drain would not clear either.
const DEFERRED_SLOTS: u64 = 2;

/// The deferral queue's hard cap.
const MAX_DEFERRED: usize = (MAX_AGGREGATES_PER_SLOT * DEFERRED_SLOTS) as usize;

/// One aggregate held for a slot that has not passed yet.
pub(crate) struct Deferred {
    pub aggregate: Box<SignedAggregateAndProof>,
    /// The attesting indices gossip validation resolved for this aggregate;
    /// carried alongside it so a drain has no state left to rebuild before
    /// calling [`fork_choice::apply_verified_aggregate`].
    pub attesting_indices: Vec<ValidatorIndex>,
    /// The slot this becomes applicable at: the aggregate's own slot plus one,
    /// cached so a drain compares numbers rather than reaching back into the
    /// container.
    pub applicable_at: Slot,
}

/// Why an aggregate was not applied, for the metric that counts outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dropped {
    /// A valid aggregate whose bits are already covered for this
    /// `(AttestationData, committee)`.
    KnownSubset,
    /// The queue was full when this arrived.
    QueueFull,
}

impl Dropped {
    /// The label this outcome is counted under.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::KnownSubset => "known_subset",
            Self::QueueFull => "queue_full",
        }
    }
}

/// The actor's `beacon_aggregate_and_proof` state. Always empty on lean, which
/// subscribes to no such topic.
#[derive(Default)]
pub(crate) struct AggregateGossip {
    /// The union of aggregation bits applied for each
    /// `(hash_tree_root(data), committee_index)`, by target epoch.
    ///
    /// A running union rather than every bitfield seen, which is what makes
    /// the superset test one comparison and the memory one bitfield per
    /// distinct attestation rather than one per aggregate. EIP-7549 keys this
    /// by committee as well as by data root, because electra's
    /// `aggregation_bits` is only meaningful against the committee it covers.
    seen_bits: HashMap<Epoch, HashMap<(Root, CommitteeIndex), Vec<bool>>>,
    /// Aggregates waiting for their own slot to pass.
    deferred: VecDeque<Deferred>,
}

impl AggregateGossip {
    /// Whether this aggregate adds nothing that has not already been applied.
    ///
    /// Read before [`fork_choice::apply_verified_aggregate`] and written only
    /// after it succeeds; see the module documentation. The specification's
    /// own `[IGNORE]` for this condition is gossip's to answer now (p2p's
    /// `SeenAggregates` records it before this aggregate is even forwarded),
    /// so a caller here treats a `Some` purely as "this would cost work with
    /// no effect", not as misbehaviour.
    pub(crate) fn already_covered(&self, aggregate: &SignedAggregateAndProof) -> Option<Dropped> {
        let data = aggregate.data();
        let epoch = data.target.epoch;

        // An aggregate naming no single committee is rejected downstream by
        // the gossip conditions; there is no key to look it up under here, so
        // it simply is not covered.
        let committee_index = aggregate.committee_index()?;
        let key = (data.hash_tree_root(), committee_index);
        let seen = self.seen_bits.get(&epoch)?.get(&key)?;
        is_non_strict_superset(seen, &aggregate.aggregation_bits()).then_some(Dropped::KnownSubset)
    }

    /// Record an aggregate that was applied, so a later one covering no more
    /// is dropped before it reaches fork choice at all.
    pub(crate) fn record(&mut self, aggregate: &SignedAggregateAndProof) {
        let data = aggregate.data();
        let epoch = data.target.epoch;

        let Some(committee_index) = aggregate.committee_index() else {
            return;
        };
        let bits = aggregate.aggregation_bits();
        let union = self
            .seen_bits
            .entry(epoch)
            .or_default()
            .entry((data.hash_tree_root(), committee_index))
            .or_insert_with(|| vec![false; bits.len()]);
        // A later aggregate for the same committee has the same width, but a
        // malformed one that reached here would not, so grow rather than
        // index out of bounds.
        if union.len() < bits.len() {
            union.resize(bits.len(), false);
        }
        for (slot, bit) in union.iter_mut().zip(bits.iter()) {
            *slot |= *bit;
        }
    }

    /// Hold an aggregate whose own slot has not passed yet.
    ///
    /// Returns [`Dropped::QueueFull`] if the queue is at its cap, which is
    /// what keeps a peer from choosing how much memory this costs. The oldest
    /// entry is the one refused rather than evicted: an entry already in the
    /// queue is closer to being applicable than one just arriving, so
    /// dropping it to make room would trade a nearly-ready vote for a newer
    /// one that still has to wait.
    pub(crate) fn defer(
        &mut self,
        aggregate: Box<SignedAggregateAndProof>,
        attesting_indices: Vec<ValidatorIndex>,
    ) -> Option<Dropped> {
        if self.deferred.len() >= MAX_DEFERRED {
            return Some(Dropped::QueueFull);
        }
        let applicable_at = aggregate.slot().saturating_add(1);
        self.deferred.push_back(Deferred {
            aggregate,
            attesting_indices,
            applicable_at,
        });
        None
    }

    /// Take every held aggregate whose slot has now passed.
    ///
    /// Drains the whole queue and puts back what is still early, rather than
    /// draining a prefix: arrivals are not ordered by slot, since a peer may
    /// send an aggregate for an older slot at any time.
    pub(crate) fn take_ready(&mut self, current_slot: Slot) -> Vec<Deferred> {
        let mut ready = Vec::new();
        let mut still_early = VecDeque::with_capacity(self.deferred.len());
        for entry in self.deferred.drain(..) {
            if current_slot >= entry.applicable_at {
                ready.push(entry);
            } else {
                still_early.push_back(entry);
            }
        }
        self.deferred = still_early;
        ready
    }

    /// How many aggregates are held, for the gauge that makes a backlog
    /// visible.
    pub(crate) fn deferred_len(&self) -> usize {
        self.deferred.len()
    }

    /// Drop the applied-bits gate's entries for any epoch but the current and
    /// the previous one, and any held aggregate for a finalized slot.
    ///
    /// Driven by the store's own clock (`current_epoch`), not by finality
    /// (`finalized_slot` still prunes the deferral queue, which is a
    /// different bound): the gossip conditions this gate backs only ever ask
    /// about the current or the previous epoch
    /// (`is_current_or_previous_epoch`), and finality can stall for far longer
    /// than that window while gossip keeps arriving, which is exactly the
    /// unbounded growth a peer must not get to cause.
    pub(crate) fn prune(&mut self, current_epoch: Epoch, finalized_slot: Slot) {
        let floor = current_epoch.saturating_sub(1);
        self.seen_bits.retain(|epoch, _| *epoch >= floor);
        // A held aggregate for a finalized slot can no longer change the head,
        // and nothing else would ever remove it: its slot has passed, so a
        // drain would take it, but a drain only runs while the actor ticks.
        self.deferred
            .retain(|entry| entry.aggregate.slot() > finalized_slot);
    }
}

#[cfg(test)]
mod tests {
    use ethlambda_types::beacon::containers::phase0;
    use ethlambda_types::beacon::containers::{AttestationData, Checkpoint};
    use libssz_types::SszBitlist;

    use super::*;

    /// An aggregate at `slot` from `aggregator`, covering `bits` of a
    /// four-member committee. Only the fields the seen-sets and the queue read
    /// are meaningful; nothing here is signature-valid.
    fn aggregate(
        slot: Slot,
        aggregator: ValidatorIndex,
        bits: [bool; 4],
    ) -> SignedAggregateAndProof {
        let mut aggregation_bits: SszBitlist<2048> = SszBitlist::with_length(4).unwrap();
        for (index, bit) in bits.iter().enumerate() {
            aggregation_bits.set(index, *bit).unwrap();
        }
        SignedAggregateAndProof::Phase0(phase0::SignedAggregateAndProof {
            message: phase0::AggregateAndProof {
                aggregator_index: aggregator,
                aggregate: phase0::Attestation {
                    aggregation_bits,
                    data: AttestationData {
                        slot,
                        index: 0,
                        beacon_block_root: Root::ZERO,
                        source: Checkpoint::default(),
                        target: Checkpoint {
                            epoch: slot / 32,
                            root: Root::ZERO,
                        },
                    },
                    signature: Default::default(),
                },
                selection_proof: Default::default(),
            },
            signature: Default::default(),
        })
    }

    #[test]
    fn an_unseen_aggregate_is_not_covered() {
        let gossip = AggregateGossip::default();
        assert_eq!(
            gossip.already_covered(&aggregate(0, 1, [true, false, false, false])),
            None
        );
    }

    /// The gate that actually pays for itself: a committee's other aggregators
    /// publish the same votes, and once the union covers them their aggregates
    /// cost no signature verification at all.
    #[test]
    fn an_aggregate_adding_no_bits_is_dropped() {
        let mut gossip = AggregateGossip::default();
        gossip.record(&aggregate(0, 1, [true, true, true, false]));
        // A different aggregator, same data, a subset of the bits.
        assert_eq!(
            gossip.already_covered(&aggregate(0, 2, [true, false, true, false])),
            Some(Dropped::KnownSubset)
        );
    }

    #[test]
    fn an_aggregate_adding_a_bit_is_kept() {
        let mut gossip = AggregateGossip::default();
        gossip.record(&aggregate(0, 1, [true, true, false, false]));
        // Position 3 is new, so this carries a vote the union does not have.
        assert_eq!(
            gossip.already_covered(&aggregate(0, 2, [true, false, false, true])),
            None
        );
    }

    /// Two aggregators' partial coverage has to accumulate, or the third
    /// aggregate covering their union would be applied again.
    #[test]
    fn coverage_accumulates_across_aggregates() {
        let mut gossip = AggregateGossip::default();
        gossip.record(&aggregate(0, 1, [true, true, false, false]));
        gossip.record(&aggregate(0, 2, [false, false, true, true]));
        assert_eq!(
            gossip.already_covered(&aggregate(0, 3, [true, false, true, false])),
            Some(Dropped::KnownSubset)
        );
    }

    #[test]
    fn a_held_aggregate_is_taken_once_its_slot_has_passed() {
        let mut gossip = AggregateGossip::default();
        assert_eq!(
            gossip.defer(Box::new(aggregate(5, 1, [true; 4])), vec![1]),
            None
        );
        // Still slot 5: the aggregate votes at 5 and needs 6.
        assert!(gossip.take_ready(5).is_empty());
        assert_eq!(gossip.deferred_len(), 1);
        let ready = gossip.take_ready(6);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].attesting_indices, vec![1]);
        assert_eq!(gossip.deferred_len(), 0);
    }

    /// Arrivals are not ordered by slot, so a drain has to consider the whole
    /// queue rather than a prefix of it.
    #[test]
    fn a_drain_takes_ready_entries_from_anywhere_in_the_queue() {
        let mut gossip = AggregateGossip::default();
        gossip.defer(Box::new(aggregate(9, 1, [true; 4])), vec![]);
        gossip.defer(Box::new(aggregate(2, 2, [true; 4])), vec![]);
        gossip.defer(Box::new(aggregate(9, 3, [true; 4])), vec![]);

        let ready = gossip.take_ready(5);
        assert_eq!(ready.len(), 1, "only the slot-2 aggregate is applicable");
        assert_eq!(ready[0].aggregate.slot(), 2);
        assert_eq!(gossip.deferred_len(), 2);
    }

    #[test]
    fn the_queue_refuses_rather_than_growing_without_bound() {
        let mut gossip = AggregateGossip::default();
        for index in 0..MAX_DEFERRED {
            assert_eq!(
                gossip.defer(Box::new(aggregate(9, index as u64, [true; 4])), vec![]),
                None
            );
        }
        assert_eq!(
            gossip.defer(Box::new(aggregate(9, 0, [true; 4])), vec![]),
            Some(Dropped::QueueFull)
        );
        assert_eq!(gossip.deferred_len(), MAX_DEFERRED);
    }

    #[test]
    fn pruning_drops_old_epochs_and_finalized_holds() {
        let mut gossip = AggregateGossip::default();
        // Epoch 0, via slot 0.
        gossip.record(&aggregate(0, 1, [true; 4]));
        // Epoch 10, via slot 320.
        gossip.record(&aggregate(320, 2, [true; 4]));
        gossip.defer(Box::new(aggregate(100, 3, [true; 4])), vec![]);

        // Current epoch 10: the window keeps only epochs 9 and 10.
        gossip.prune(10, 200);

        // Epoch 0 is outside the current-or-previous-epoch window.
        assert_eq!(
            gossip.already_covered(&aggregate(0, 1, [true; 4])),
            None,
            "the old epoch's coverage should have been forgotten"
        );
        // Epoch 10 is still within the window.
        assert_eq!(
            gossip.already_covered(&aggregate(320, 2, [true; 4])),
            Some(Dropped::KnownSubset)
        );
        // The held aggregate votes at slot 100, below the finalized slot.
        assert_eq!(gossip.deferred_len(), 0);
    }

    /// The applied-bits window follows the store's clock, not finality: a
    /// finality stall must not let coverage from an old epoch keep costing an
    /// LRU-free `HashMap` entry forever.
    #[test]
    fn pruning_follows_the_current_epoch_even_when_finality_has_not_moved() {
        let mut gossip = AggregateGossip::default();
        gossip.record(&aggregate(0, 1, [true; 4]));

        // Finality is still at slot 0, but the clock has moved to epoch 50.
        gossip.prune(50, 0);

        assert_eq!(
            gossip.already_covered(&aggregate(0, 1, [true; 4])),
            None,
            "coverage far behind the current epoch must not survive finality stalling"
        );
    }
}
