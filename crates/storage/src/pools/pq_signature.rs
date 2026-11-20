//! The XMSS signatures this node's PQ aggregators prove aggregates from.
//!
//! A PQ aggregator is a member of its committee's aggregation committee
//! (PQ `validator.md`, "Aggregation selection") and proves its committee's
//! signatures with an `AttestationProof` instead of aggregating them. The
//! validator client names the committees it aggregates for through
//! `beacon_committee_subscriptions`; this pool keeps the signatures of
//! validated single attestations for those committees only, hands what it
//! has collected to the prover at each of its aggregators' cutoffs, and holds
//! what the node proved from them for the aggregate endpoint to answer with.
//!
//! The aggregators of a committee are staggered (`get_aggregation_cutoff_ms`),
//! so a slot's signatures are read more than once and its collection ends at
//! the last cutoff ([`PqSignaturePool::seal`]). The pool also records the
//! attesters of every aggregate broadcast for those committees, gossip's and
//! this node's own, which is what `should_broadcast_aggregate` compares an
//! aggregate against before it is broadcast.
//!
//! In memory only, and a few slots deep: an aggregate is published within its
//! own slot.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use ethlambda_types::{
    beacon::{
        containers::{pq::SingleAttestation, shared::AttestationData},
        preset,
        primitives::{Root, Slot, ValidatorIndex, XmssSignature},
    },
    primitives::HashTreeRoot as _,
};

use super::PooledPqAggregate;

/// How many slots below the current one the pool keeps anything for.
const RETAINED_SLOTS: Slot = 3;

/// How many distinct `(AttestationData, committee)` groups one slot may hold:
/// four votes per committee leaves room for honest disagreement and bounds
/// what a peer can make the node store.
const MAX_GROUPS_PER_SLOT: usize = preset::MAX_COMMITTEES_PER_SLOT_PQ * 4;

/// How many broadcast aggregates' attester sets the pool keeps per
/// `(AttestationData, committee)`. Gossip accepts one aggregate per
/// aggregator and epoch, and only one no earlier aggregate covers, so a
/// committee's `AGGREGATORS_PER_COMMITTEE` aggregators fill at most that
/// many; twice that leaves room without letting a peer grow the record.
const MAX_BROADCAST_SETS: usize = 8;

/// `(slot, data root, committee index)`.
type Key = (Slot, Root, u64);

/// One committee's collected votes on one `AttestationData`.
#[derive(Debug, Clone)]
pub struct CommitteeSignatures {
    pub data: AttestationData,
    pub committee_index: u64,
    /// By attester. Positions in the committee are resolved when proving,
    /// against the state the proof is made for.
    pub signatures: BTreeMap<ValidatorIndex, XmssSignature>,
}

/// Signatures awaiting proof and the aggregates proved from them.
#[derive(Debug, Default)]
pub struct PqSignaturePool {
    /// The validators of this node that aggregate for each `(slot,
    /// committee)`.
    subscriptions: BTreeMap<(Slot, u64), BTreeSet<ValidatorIndex>>,
    raw: BTreeMap<Key, CommitteeSignatures>,
    proven: BTreeMap<Key, Arc<PooledPqAggregate>>,
    /// The attesters, sorted, of each aggregate broadcast for a subscribed
    /// committee: the ones gossip accepted and the ones this node published.
    broadcast: BTreeMap<Key, Vec<Vec<ValidatorIndex>>>,
    /// The latest slot whose collection ended: later signatures for it are
    /// not collected.
    sealed_slot: Option<Slot>,
}

impl PqSignaturePool {
    fn prune(&mut self, now: Slot) {
        let earliest = now.saturating_sub(RETAINED_SLOTS - 1);
        self.raw.retain(|(slot, _, _), _| *slot >= earliest);
        self.proven.retain(|(slot, _, _), _| *slot >= earliest);
        self.broadcast.retain(|(slot, _, _), _| *slot >= earliest);
        self.subscriptions.retain(|(slot, _), _| *slot >= now);
    }

    /// Collect `committee`'s signatures at `slot`, which `validator`, one of
    /// this node's, aggregates for. Refused for a past slot, one more than two
    /// epochs ahead, or a committee index PQ cannot have.
    pub fn subscribe(
        &mut self,
        now: Slot,
        slot: Slot,
        committee: u64,
        validator: ValidatorIndex,
    ) -> bool {
        self.prune(now);
        let accepted = slot >= now
            && slot <= now.saturating_add(2 * preset::SLOTS_PER_EPOCH)
            && committee < preset::MAX_COMMITTEES_PER_SLOT_PQ as u64;
        if accepted {
            let aggregators = self.subscriptions.entry((slot, committee)).or_default();
            // A committee has `AGGREGATORS_PER_COMMITTEE` aggregators; more
            // names than a committee has members is a caller's mistake, and
            // the bound keeps the record from growing with it.
            if aggregators.len() < preset::MAX_VALIDATORS_PER_COMMITTEE {
                aggregators.insert(validator);
            }
        }
        accepted
    }

    /// Whether this node collects `committee`'s signatures at `slot`.
    pub fn is_subscribed(&self, slot: Slot, committee: u64) -> bool {
        self.subscriptions.contains_key(&(slot, committee))
    }

    /// The committees of `slot` this node aggregates for, each with its
    /// aggregators among this node's validators.
    pub fn aggregators(&self, slot: Slot) -> Vec<(u64, Vec<ValidatorIndex>)> {
        self.subscriptions
            .range((slot, 0)..=(slot, u64::MAX))
            .map(|(&(_, committee), validators)| (committee, validators.iter().copied().collect()))
            .collect()
    }

    /// Keep a validated attestation's signature, if its committee is one this
    /// node aggregates for and its slot is neither past nor sealed. The first
    /// signature per attester wins. Returns whether it was kept.
    pub fn insert(&mut self, now: Slot, attestation: &SingleAttestation) -> bool {
        self.prune(now);
        let slot = attestation.data.slot;
        let committee = attestation.committee_index;
        if slot < now
            || self.sealed_slot.is_some_and(|sealed| slot <= sealed)
            || !self.subscriptions.contains_key(&(slot, committee))
        {
            return false;
        }
        let key = (slot, attestation.data.hash_tree_root(), committee);
        if !self.raw.contains_key(&key) {
            let groups = self
                .raw
                .range((slot, Root::ZERO, 0)..)
                .take_while(|((held, _, _), _)| *held == slot)
                .count();
            if groups >= MAX_GROUPS_PER_SLOT {
                return false;
            }
        }
        let group = self.raw.entry(key).or_insert_with(|| CommitteeSignatures {
            data: attestation.data,
            committee_index: committee,
            signatures: BTreeMap::new(),
        });
        let mut kept = false;
        group
            .signatures
            .entry(attestation.attester_index)
            .or_insert_with(|| {
                kept = true;
                attestation.signature.clone()
            });
        kept
    }

    /// What `slot` has collected so far for `committees`, for an aggregator
    /// whose cutoff has come. Collection goes on for the aggregators after
    /// it, until [`Self::seal`].
    pub fn collected(&self, slot: Slot, committees: &[u64]) -> Vec<CommitteeSignatures> {
        self.raw
            .range((slot, Root::ZERO, 0)..)
            .take_while(|((held, _, _), _)| *held == slot)
            .filter(|((_, _, committee), _)| committees.contains(committee))
            .map(|(_, group)| group.clone())
            .collect()
    }

    /// End `slot`'s collection, once its last aggregator's cutoff has passed:
    /// its signatures are dropped and none arriving afterwards is kept.
    pub fn seal(&mut self, slot: Slot) {
        self.prune(slot);
        if self.sealed_slot.is_some_and(|sealed| slot <= sealed) {
            return;
        }
        self.sealed_slot = Some(slot);
        self.raw = self.raw.split_off(&(slot + 1, Root::ZERO, 0));
    }

    /// Hold an aggregate this node proved, for the aggregate endpoint.
    ///
    /// A later seat proves from more signatures than an earlier one, so the
    /// aggregate covering more attesters is the one kept.
    pub fn insert_proven(&mut self, aggregate: Arc<PooledPqAggregate>) {
        let data = &aggregate.attestation.data;
        let key = (data.slot, data.hash_tree_root(), aggregate.committee_index);
        let better = self
            .proven
            .get(&key)
            .is_none_or(|held| aggregate.attesting_indices.len() > held.attesting_indices.len());
        if better {
            self.proven.insert(key, aggregate);
        }
    }

    /// The aggregate this node proved for `committee`'s vote on the data
    /// whose root is `data_root` at `slot`.
    pub fn proven(
        &self,
        slot: Slot,
        data_root: Root,
        committee: u64,
    ) -> Option<Arc<PooledPqAggregate>> {
        self.proven.get(&(slot, data_root, committee)).cloned()
    }

    /// Whether `slot`'s collection has ended.
    pub fn is_sealed(&self, slot: Slot) -> bool {
        self.sealed_slot.is_some_and(|sealed| slot <= sealed)
    }

    /// Record an aggregate broadcast for `committee`'s vote on `data`, with
    /// the attesters it covers: one gossip accepted, or one this node
    /// published. Kept only for committees this node aggregates for.
    pub fn note_broadcast(
        &mut self,
        data: &AttestationData,
        committee: u64,
        attesting_indices: &[ValidatorIndex],
    ) {
        if !self.subscriptions.contains_key(&(data.slot, committee)) {
            return;
        }
        let mut attesters = attesting_indices.to_vec();
        attesters.sort_unstable();
        attesters.dedup();
        let sets = self
            .broadcast
            .entry((data.slot, data.hash_tree_root(), committee))
            .or_default();
        if sets.iter().any(|held| is_superset(held, &attesters)) {
            return;
        }
        sets.retain(|held| !is_superset(&attesters, held));
        if sets.len() < MAX_BROADCAST_SETS {
            sets.push(attesters);
        }
    }

    /// Whether an aggregate already broadcast for the same data and committee
    /// includes all of `attesting_indices`: the negation of PQ
    /// `validator.md`'s `should_broadcast_aggregate`. Each broadcast
    /// aggregate is compared on its own, since a proposer includes one per
    /// committee: two that only together cover the attesters do not make an
    /// aggregate redundant. An identical one does.
    pub fn is_covered(
        &self,
        slot: Slot,
        data_root: Root,
        committee: u64,
        attesting_indices: &[ValidatorIndex],
    ) -> bool {
        let mut attesters = attesting_indices.to_vec();
        attesters.sort_unstable();
        self.broadcast
            .get(&(slot, data_root, committee))
            .is_some_and(|sets| sets.iter().any(|held| is_superset(held, &attesters)))
    }
}

/// Whether sorted `held` includes every element of `wanted`.
fn is_superset(held: &[ValidatorIndex], wanted: &[ValidatorIndex]) -> bool {
    wanted
        .iter()
        .all(|validator| held.binary_search(validator).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vote(slot: Slot, committee: u64, attester: ValidatorIndex, root: u8) -> SingleAttestation {
        SingleAttestation {
            committee_index: committee,
            attester_index: attester,
            data: AttestationData {
                slot,
                beacon_block_root: Root::repeat_byte(root),
                ..Default::default()
            },
            signature: XmssSignature::default(),
        }
    }

    #[test]
    fn signatures_need_a_subscription_and_are_read_until_the_slot_seals() {
        let mut pool = PqSignaturePool::default();
        assert!(!pool.insert(3, &vote(3, 0, 7, 1)));
        assert!(pool.subscribe(3, 3, 0, 7));
        assert!(pool.insert(3, &vote(3, 0, 7, 1)));
        // The first signature per attester wins.
        assert!(!pool.insert(3, &vote(3, 0, 7, 1)));
        // Another committee of the slot is not subscribed.
        assert!(!pool.insert(3, &vote(3, 1, 9, 1)));

        // The first aggregator's cutoff reads what there is, and collection
        // goes on for the next one.
        let attesters = |pool: &PqSignaturePool| -> Vec<Vec<ValidatorIndex>> {
            pool.collected(3, &[0])
                .iter()
                .map(|group| group.signatures.keys().copied().collect())
                .collect()
        };
        assert_eq!(attesters(&pool), vec![vec![7]]);
        assert!(pool.insert(3, &vote(3, 0, 8, 1)));
        assert_eq!(attesters(&pool), vec![vec![7, 8]]);
        // Only the committees asked for are read.
        assert!(pool.collected(3, &[1]).is_empty());
        assert!(pool.collected(4, &[0]).is_empty());

        // Nothing more is collected for a sealed slot.
        pool.seal(3);
        assert!(pool.is_sealed(3));
        assert!(pool.collected(3, &[0]).is_empty());
        assert!(!pool.insert(3, &vote(3, 0, 10, 1)));
    }

    #[test]
    fn sealing_a_slot_keeps_the_next_ones_signatures() {
        let mut pool = PqSignaturePool::default();
        pool.subscribe(3, 3, 0, 7);
        pool.subscribe(3, 4, 0, 7);
        pool.insert(3, &vote(3, 0, 7, 1));
        pool.insert(3, &vote(4, 0, 7, 1));
        pool.seal(3);
        assert_eq!(pool.collected(4, &[0]).len(), 1);
    }

    #[test]
    fn a_slot_holds_a_bounded_number_of_groups() {
        let mut pool = PqSignaturePool::default();
        pool.subscribe(3, 3, 0, 7);
        for root in 0..=MAX_GROUPS_PER_SLOT as u8 {
            pool.insert(3, &vote(3, 0, root as u64, root));
        }
        assert_eq!(pool.collected(3, &[0]).len(), MAX_GROUPS_PER_SLOT);
    }

    #[test]
    fn subscriptions_are_bounded_in_time_and_committee() {
        let mut pool = PqSignaturePool::default();
        assert!(!pool.subscribe(10, 9, 0, 1));
        assert!(!pool.subscribe(10, 10 + 2 * preset::SLOTS_PER_EPOCH + 1, 0, 1));
        assert!(!pool.subscribe(10, 10, preset::MAX_COMMITTEES_PER_SLOT_PQ as u64, 1));
        assert!(pool.subscribe(10, 12, 1, 1));
        assert!(pool.is_subscribed(12, 1));
    }

    #[test]
    fn a_committees_aggregators_are_the_validators_that_subscribed() {
        let mut pool = PqSignaturePool::default();
        pool.subscribe(10, 12, 1, 40);
        pool.subscribe(10, 12, 1, 30);
        pool.subscribe(10, 12, 1, 40);
        pool.subscribe(10, 12, 3, 50);
        pool.subscribe(10, 13, 0, 60);
        assert_eq!(pool.aggregators(12), vec![(1, vec![30, 40]), (3, vec![50])]);
        assert!(pool.aggregators(11).is_empty());
    }

    /// PQ `validator.md`'s table for `should_broadcast_aggregate`: whether an
    /// aggregator in a committee of four broadcasts an aggregate with
    /// attesters 0 and 1, given the aggregates already broadcast.
    #[test]
    fn an_aggregate_is_redundant_only_when_one_broadcast_covers_it() {
        let data = vote(3, 0, 0, 1).data;
        let root = data.hash_tree_root();
        let covered_given = |broadcast: &[&[ValidatorIndex]]| {
            let mut pool = PqSignaturePool::default();
            pool.subscribe(3, 3, 0, 0);
            for attesters in broadcast {
                pool.note_broadcast(&data, 0, attesters);
            }
            pool.is_covered(3, root, 0, &[0, 1])
        };
        // Nothing to compare against.
        assert!(!covered_given(&[]));
        // `1000` lacks attester 1.
        assert!(!covered_given(&[&[0]]));
        // `1110` has attesters 0 and 1.
        assert!(covered_given(&[&[0, 1, 2]]));
        // `1100`: an identical aggregate counts as a superset.
        assert!(covered_given(&[&[1, 0]]));
        // `1000` and `0100`: neither has both.
        assert!(!covered_given(&[&[0], &[1]]));
        // `0011` has neither.
        assert!(!covered_given(&[&[2, 3]]));
    }

    #[test]
    fn broadcasts_are_kept_per_vote_and_committee_and_only_when_subscribed() {
        let data = vote(3, 0, 0, 1).data;
        let other = vote(3, 0, 0, 2).data;
        let mut pool = PqSignaturePool::default();
        // Not a committee this node aggregates for: nothing is kept.
        pool.note_broadcast(&data, 0, &[0, 1]);
        assert!(!pool.is_covered(3, data.hash_tree_root(), 0, &[0]));

        pool.subscribe(3, 3, 0, 0);
        pool.subscribe(3, 3, 1, 0);
        pool.note_broadcast(&data, 0, &[0, 1]);
        assert!(pool.is_covered(3, data.hash_tree_root(), 0, &[0]));
        // Another vote of the committee, and another committee's same vote.
        assert!(!pool.is_covered(3, other.hash_tree_root(), 0, &[0]));
        assert!(!pool.is_covered(3, data.hash_tree_root(), 1, &[0]));

        // A set a later one covers is dropped, so the record stays small.
        for extra in 2..40 {
            let attesters: Vec<ValidatorIndex> = (0..=extra).collect();
            pool.note_broadcast(&data, 0, &attesters);
        }
        let key = (3, data.hash_tree_root(), 0);
        assert_eq!(pool.broadcast[&key].len(), 1);
        // Disjoint sets are capped.
        for attester in 100..140 {
            pool.note_broadcast(&data, 0, &[attester]);
        }
        assert_eq!(pool.broadcast[&key].len(), MAX_BROADCAST_SETS);
    }
}
