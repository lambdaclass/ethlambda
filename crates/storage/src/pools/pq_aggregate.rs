//! PQ network aggregates this node has validated, held until a block packs
//! them.
//!
//! A PQ attestation carries no signature: each network aggregate covers one
//! committee and travels with an `AttestationProof` of its attesters'
//! signatures, and a proposer merges the proofs of the aggregates it packs
//! into the block's single `proof` (PQ `validator.md`, "Attestations" and
//! "Proof"). A proof proves an exact set of signers, so two aggregates for
//! one committee cannot be combined the way BLS aggregates are. The pool
//! keeps the one covering the most attesters per `(AttestationData,
//! committee)` instead.
//!
//! Only aggregates that passed gossip validation go in, and each keeps the
//! attesting indices it was validated with, so a proposer on another branch
//! can tell whether the committee it read still names the same signers. In
//! memory only.

use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use ethlambda_types::{
    beacon::{
        containers::pq::{Attestation, AttestationProof},
        preset,
        primitives::{Root, Slot, ValidatorIndex},
    },
    primitives::HashTreeRoot as _,
};

/// How many slots of aggregates the pool holds below the newest one it has
/// seen: an attestation is includable through the end of the epoch after its
/// own, so two epochs cover every one a block could still pack.
fn retained_slots() -> Slot {
    2 * preset::slots_per_epoch()
}

/// One validated network aggregate.
#[derive(Debug, Clone)]
pub struct PooledPqAggregate {
    /// Covers exactly one committee.
    pub attestation: Attestation,
    pub committee_index: u64,
    /// The attesters the aggregate was validated with, sorted.
    pub attesting_indices: Vec<ValidatorIndex>,
    /// The proof of their signatures over the attestation's message.
    pub proof: AttestationProof,
}

/// Validated PQ aggregates by slot, then by `(data root, committee)`.
#[derive(Debug, Default)]
pub struct PqAggregatePool {
    by_slot: BTreeMap<Slot, HashMap<(Root, u64), Arc<PooledPqAggregate>>>,
}

impl PqAggregatePool {
    /// Hold `aggregate` unless the pool already has one for its data and
    /// committee covering at least as many attesters. Returns whether it was
    /// kept. Drops everything more than [`retained_slots`] below the newest
    /// slot held.
    pub fn insert(&mut self, mut aggregate: PooledPqAggregate) -> bool {
        aggregate.attesting_indices.sort_unstable();
        let slot = aggregate.attestation.data.slot;
        let newest = self
            .by_slot
            .last_key_value()
            .map_or(slot, |(&newest, _)| newest.max(slot));
        let floor = newest.saturating_sub(retained_slots());
        if slot < floor {
            return false;
        }
        self.by_slot = self.by_slot.split_off(&floor);
        let key = (
            aggregate.attestation.data.hash_tree_root(),
            aggregate.committee_index,
        );
        let held = self.by_slot.entry(slot).or_default();
        let better = held.get(&key).is_none_or(|current| {
            aggregate.attesting_indices.len() > current.attesting_indices.len()
        });
        if better {
            held.insert(key, Arc::new(aggregate));
        }
        better
    }

    /// Every aggregate held for a slot at or below `latest_slot`.
    pub fn candidates(&self, latest_slot: Slot) -> Vec<Arc<PooledPqAggregate>> {
        self.by_slot
            .range(..=latest_slot)
            .flat_map(|(_, held)| held.values().cloned())
            .collect()
    }

    /// How many aggregates the pool holds.
    pub fn len(&self) -> usize {
        self.by_slot.values().map(HashMap::len).sum()
    }

    /// Whether the pool holds nothing.
    pub fn is_empty(&self) -> bool {
        self.by_slot.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_types::beacon::containers::{pq::AggregationBits, shared::AttestationData};

    fn aggregate(slot: Slot, committee: u64, attesters: &[ValidatorIndex]) -> PooledPqAggregate {
        PooledPqAggregate {
            attestation: Attestation {
                aggregation_bits: AggregationBits::default(),
                data: AttestationData {
                    slot,
                    ..Default::default()
                },
                committee_bits: Default::default(),
            },
            committee_index: committee,
            attesting_indices: attesters.to_vec(),
            proof: AttestationProof::default(),
        }
    }

    #[test]
    fn the_aggregate_covering_more_attesters_wins_its_committee() {
        let mut pool = PqAggregatePool::default();
        assert!(pool.insert(aggregate(5, 0, &[3])));
        assert!(pool.insert(aggregate(5, 0, &[3, 1])));
        assert!(!pool.insert(aggregate(5, 0, &[2])));
        assert!(!pool.insert(aggregate(5, 0, &[4, 2])));
        // Another committee of the same data is kept beside it.
        assert!(pool.insert(aggregate(5, 1, &[9])));

        let held = pool.candidates(5);
        assert_eq!(held.len(), 2);
        let committee_zero = held.iter().find(|held| held.committee_index == 0).unwrap();
        assert_eq!(committee_zero.attesting_indices, vec![1, 3]);
    }

    #[test]
    fn candidates_stop_at_the_latest_slot() {
        let mut pool = PqAggregatePool::default();
        pool.insert(aggregate(3, 0, &[1]));
        pool.insert(aggregate(4, 0, &[2]));
        pool.insert(aggregate(6, 0, &[3]));
        let slots: Vec<Slot> = pool
            .candidates(4)
            .iter()
            .map(|held| held.attestation.data.slot)
            .collect();
        assert_eq!(slots.len(), 2);
        assert!(slots.iter().all(|&slot| slot <= 4));
    }

    #[test]
    fn slots_two_epochs_below_the_newest_are_dropped() {
        let mut pool = PqAggregatePool::default();
        pool.insert(aggregate(1, 0, &[1]));
        pool.insert(aggregate(1 + retained_slots(), 0, &[2]));
        assert_eq!(pool.len(), 2);
        pool.insert(aggregate(2 + retained_slots(), 0, &[3]));
        assert_eq!(pool.len(), 2);
        assert!(!pool.insert(aggregate(1, 0, &[4, 5])));
    }
}
