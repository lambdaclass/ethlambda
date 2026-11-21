//! The XMSS signatures this node's PQ aggregators prove aggregates from.
//!
//! A PQ aggregator is a member of its committee's aggregation committee
//! (PQ `validator.md`, "Aggregation selection") and proves its committee's
//! signatures with an `AttestationProof` instead of aggregating them. The
//! validator client names the committees it aggregates for through
//! `beacon_committee_subscriptions`; this pool keeps the signatures of
//! validated single attestations for those committees only, seals each slot's
//! once its collection window closes, and holds what the node proved from
//! them for the aggregate endpoint to answer with.
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
fn max_groups_per_slot() -> usize {
    preset::max_committees_per_slot_pq() * 4
}

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
    /// `(slot, committee)` this node's validators aggregate for.
    subscriptions: BTreeSet<(Slot, u64)>,
    raw: BTreeMap<Key, CommitteeSignatures>,
    proven: BTreeMap<Key, Arc<PooledPqAggregate>>,
    /// The latest slot whose signatures were handed to the prover: later
    /// signatures for it are not collected.
    sealed_slot: Option<Slot>,
}

impl PqSignaturePool {
    fn prune(&mut self, now: Slot) {
        let earliest = now.saturating_sub(RETAINED_SLOTS - 1);
        self.raw.retain(|(slot, _, _), _| *slot >= earliest);
        self.proven.retain(|(slot, _, _), _| *slot >= earliest);
        self.subscriptions.retain(|(slot, _)| *slot >= now);
    }

    /// Collect `committee`'s signatures at `slot`, which one of this node's
    /// validators aggregates for. Refused for a past slot, one more than two
    /// epochs ahead, or a committee index PQ cannot have.
    pub fn subscribe(&mut self, now: Slot, slot: Slot, committee: u64) -> bool {
        self.prune(now);
        let accepted = slot >= now
            && slot <= now.saturating_add(2 * preset::slots_per_epoch())
            && committee < preset::max_committees_per_slot_pq() as u64;
        if accepted {
            self.subscriptions.insert((slot, committee));
        }
        accepted
    }

    /// Whether this node collects `committee`'s signatures at `slot`.
    pub fn is_subscribed(&self, slot: Slot, committee: u64) -> bool {
        self.subscriptions.contains(&(slot, committee))
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
            || !self.subscriptions.contains(&(slot, committee))
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
            if groups >= max_groups_per_slot() {
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

    /// Hand `slot`'s collected signatures to the prover, at most once per
    /// slot. Signatures arriving for it afterwards are not collected.
    pub fn seal(&mut self, slot: Slot) -> Vec<CommitteeSignatures> {
        self.prune(slot);
        if self.sealed_slot.is_some_and(|sealed| slot <= sealed) {
            return Vec::new();
        }
        self.sealed_slot = Some(slot);
        let later = self.raw.split_off(&(slot + 1, Root::ZERO, 0));
        std::mem::replace(&mut self.raw, later)
            .into_iter()
            .filter(|((held, _, _), _)| *held == slot)
            .map(|(_, group)| group)
            .collect()
    }

    /// Hold an aggregate this node proved, for the aggregate endpoint.
    pub fn insert_proven(&mut self, aggregate: Arc<PooledPqAggregate>) {
        let data = &aggregate.attestation.data;
        let key = (data.slot, data.hash_tree_root(), aggregate.committee_index);
        self.proven.insert(key, aggregate);
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

    /// Whether `slot`'s signatures were already handed to the prover.
    pub fn is_sealed(&self, slot: Slot) -> bool {
        self.sealed_slot.is_some_and(|sealed| slot <= sealed)
    }
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
    fn signatures_need_a_subscription_and_a_slot_seals_once() {
        let mut pool = PqSignaturePool::default();
        assert!(!pool.insert(3, &vote(3, 0, 7, 1)));
        assert!(pool.subscribe(3, 3, 0));
        assert!(pool.insert(3, &vote(3, 0, 7, 1)));
        // The first signature per attester wins.
        assert!(!pool.insert(3, &vote(3, 0, 7, 1)));
        assert!(pool.insert(3, &vote(3, 0, 8, 1)));
        // Another committee of the slot is not subscribed.
        assert!(!pool.insert(3, &vote(3, 1, 9, 1)));

        let sealed = pool.seal(3);
        let [group] = sealed.as_slice() else {
            panic!("one group to prove");
        };
        assert_eq!(
            group.signatures.keys().copied().collect::<Vec<_>>(),
            vec![7, 8]
        );
        // Nothing more is collected for a sealed slot, nor sealed twice.
        assert!(!pool.insert(3, &vote(3, 0, 10, 1)));
        assert!(pool.seal(3).is_empty());
    }

    #[test]
    fn a_slot_holds_a_bounded_number_of_groups() {
        let mut pool = PqSignaturePool::default();
        pool.subscribe(3, 3, 0);
        for root in 0..=max_groups_per_slot() as u8 {
            pool.insert(3, &vote(3, 0, root as u64, root));
        }
        assert_eq!(pool.seal(3).len(), max_groups_per_slot());
    }

    #[test]
    fn subscriptions_are_bounded_in_time_and_committee() {
        let mut pool = PqSignaturePool::default();
        assert!(!pool.subscribe(10, 9, 0));
        assert!(!pool.subscribe(10, 10 + 2 * preset::slots_per_epoch() + 1, 0));
        assert!(!pool.subscribe(10, 10, preset::max_committees_per_slot_pq() as u64));
        assert!(pool.subscribe(10, 12, 1));
        assert!(pool.is_subscribed(12, 1));
    }
}
