//! Heze's inclusion list store (EIP-7805, `specs/heze/inclusion-list.md`):
//! every valid inclusion list this node has seen, keyed by
//! `(slot, dependent_root)`, with each list's timeliness and the committee
//! members caught publishing two different ones.
//!
//! Only lists that already passed gossip validation or `on_inclusion_list`
//! go in, so this is pure data: it never checks a signature or a committee
//! seat. What it answers is the specification's helpers over that data:
//! [`InclusionListStore::transactions`] (`get_inclusion_list_transactions`),
//! [`InclusionListStore::bits`] (`get_inclusion_list_bits`) and
//! [`InclusionListStore::is_bits_inclusive`]
//! (`is_inclusion_list_bits_inclusive`).
//!
//! Retention is [`RETENTION_SLOTS`] behind the newest slot inserted, well past
//! the specification's floor of `MIN_SLOTS_FOR_INCLUSION_LISTS_REQUESTS`: a
//! payload's satisfaction is judged against the previous slot's lists when its
//! envelope arrives, and an envelope can arrive late.

use std::collections::{BTreeMap, HashMap, HashSet};

use ethlambda_types::beacon::{
    containers::{
        gloas::Transaction,
        heze::{InclusionListBits, SignedInclusionList},
    },
    primitives::{Root, Slot, ValidatorIndex},
};

/// How many slots behind the newest list inserted the store keeps lists for.
pub const RETENTION_SLOTS: u64 = 64;

/// One stored list: the specification's `InclusionListEntry`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionListEntry {
    pub signed_inclusion_list: SignedInclusionList,
    /// Whether the list arrived in its own slot before
    /// `get_inclusion_list_due_ms()`.
    pub timely: bool,
}

/// The specification's `InclusionListStore`.
#[derive(Debug, Default)]
pub struct InclusionListStore {
    inclusion_lists: BTreeMap<(Slot, Root), HashMap<ValidatorIndex, InclusionListEntry>>,
    equivocators: BTreeMap<(Slot, Root), HashSet<ValidatorIndex>>,
}

impl InclusionListStore {
    /// The specification's `process_inclusion_list`: stores the first list
    /// from a committee member under its key, and marks the member an
    /// equivocator when a later one differs. A list identical to the stored
    /// one changes nothing. Returns whether the list was stored.
    pub fn process_inclusion_list(
        &mut self,
        signed_inclusion_list: SignedInclusionList,
        timely: bool,
    ) -> bool {
        let inclusion_list = &signed_inclusion_list.message;
        let validator_index = inclusion_list.validator_index;
        let key = (inclusion_list.slot, inclusion_list.dependent_root);

        let lists = self.inclusion_lists.entry(key).or_default();
        if let Some(stored) = lists.get(&validator_index) {
            // Mark the validator as an equivocator if it published a
            // different inclusion list.
            if stored.signed_inclusion_list.message != *inclusion_list {
                self.equivocators
                    .entry(key)
                    .or_default()
                    .insert(validator_index);
            }
            // Ignore an inclusion list that has already been processed.
            return false;
        }
        lists.insert(
            validator_index,
            InclusionListEntry {
                signed_inclusion_list,
                timely,
            },
        );
        self.prune(key.0);
        true
    }

    /// The entries counted for `(slot, dependent_root)`: every stored list
    /// whose member has not equivocated, timely ones only when `only_timely`.
    fn counted(
        &self,
        slot: Slot,
        dependent_root: Root,
        only_timely: bool,
    ) -> impl Iterator<Item = (ValidatorIndex, &InclusionListEntry)> {
        let key = (slot, dependent_root);
        let equivocators = self.equivocators.get(&key);
        self.inclusion_lists
            .get(&key)
            .into_iter()
            .flat_map(|lists| lists.iter())
            .filter(move |(validator_index, _)| {
                equivocators.is_none_or(|set| !set.contains(validator_index))
            })
            .filter(move |(_, entry)| !only_timely || entry.timely)
            .map(|(validator_index, entry)| (*validator_index, entry))
    }

    /// The specification's `get_inclusion_list_transactions`: the distinct
    /// transactions of every counted list, in no particular order.
    pub fn transactions(
        &self,
        slot: Slot,
        dependent_root: Root,
        only_timely: bool,
    ) -> Vec<Transaction> {
        let mut seen: HashSet<&[u8]> = HashSet::new();
        let mut transactions = Vec::new();
        for (_, entry) in self.counted(slot, dependent_root, only_timely) {
            for transaction in entry.signed_inclusion_list.message.transactions.iter() {
                if seen.insert(transaction.as_ref()) {
                    transactions.push(transaction.clone());
                }
            }
        }
        transactions
    }

    /// The specification's `get_inclusion_list_bits`: bit `i` set when
    /// `committee[i]` has a counted list.
    pub fn bits(
        &self,
        committee: &[ValidatorIndex],
        slot: Slot,
        dependent_root: Root,
        only_timely: bool,
    ) -> InclusionListBits {
        let members: HashSet<ValidatorIndex> = self
            .counted(slot, dependent_root, only_timely)
            .map(|(validator_index, _)| validator_index)
            .collect();
        let mut bits = InclusionListBits::new();
        for (position, validator_index) in committee.iter().enumerate() {
            if members.contains(validator_index) {
                bits.set(position, true)
                    .expect("the committee has INCLUSION_LIST_COMMITTEE_SIZE members");
            }
        }
        bits
    }

    /// The specification's `is_inclusion_list_bits_inclusive`: every bit this
    /// store would set is set in `inclusion_list_bits` too.
    pub fn is_bits_inclusive(
        &self,
        committee: &[ValidatorIndex],
        slot: Slot,
        dependent_root: Root,
        inclusion_list_bits: &InclusionListBits,
        only_timely: bool,
    ) -> bool {
        let local = self.bits(committee, slot, dependent_root, only_timely);
        (0..local.len())
            .all(|i| !local.get(i).unwrap_or(false) || inclusion_list_bits.get(i).unwrap_or(false))
    }

    /// The lists `InclusionListsByIndices` asks for: `committee[i]`'s for
    /// every set bit `i` of `indices`, skipping members with no list and
    /// equivocators (whose lists the specification says not to serve).
    pub fn lists_for(
        &self,
        committee: &[ValidatorIndex],
        slot: Slot,
        dependent_root: Root,
        indices: &InclusionListBits,
    ) -> Vec<SignedInclusionList> {
        let key = (slot, dependent_root);
        let Some(lists) = self.inclusion_lists.get(&key) else {
            return Vec::new();
        };
        let equivocators = self.equivocators.get(&key);
        committee
            .iter()
            .enumerate()
            .filter(|(position, _)| indices.get(*position).unwrap_or(false))
            .filter(|(_, validator_index)| {
                equivocators.is_none_or(|set| !set.contains(validator_index))
            })
            .filter_map(|(_, validator_index)| lists.get(validator_index))
            .map(|entry| entry.signed_inclusion_list.clone())
            .collect()
    }

    /// How many lists are stored for `(slot, dependent_root)`, equivocators
    /// included. For logs and metrics.
    pub fn count(&self, slot: Slot, dependent_root: Root) -> usize {
        self.inclusion_lists
            .get(&(slot, dependent_root))
            .map_or(0, HashMap::len)
    }

    /// Drops every key more than [`RETENTION_SLOTS`] behind `newest_slot`.
    fn prune(&mut self, newest_slot: Slot) {
        let floor = newest_slot.saturating_sub(RETENTION_SLOTS);
        self.inclusion_lists = self.inclusion_lists.split_off(&(floor, Root::ZERO));
        self.equivocators = self.equivocators.split_off(&(floor, Root::ZERO));
    }
}

#[cfg(test)]
mod tests {
    use ethlambda_types::beacon::containers::heze::InclusionList;

    use super::*;

    fn list(
        slot: Slot,
        validator_index: ValidatorIndex,
        transactions: &[&[u8]],
    ) -> SignedInclusionList {
        let transactions: Vec<Transaction> = transactions
            .iter()
            .map(|bytes| bytes.to_vec().into())
            .collect();
        SignedInclusionList {
            message: InclusionList {
                slot,
                validator_index,
                dependent_root: Root::repeat_byte(1),
                transactions: transactions.into(),
            },
            signature: Default::default(),
        }
    }

    const ROOT: Root = Root::repeat_byte(1);

    #[test]
    fn transactions_are_deduplicated_across_members() {
        let mut store = InclusionListStore::default();
        assert!(store.process_inclusion_list(list(5, 1, &[b"a", b"b"]), true));
        assert!(store.process_inclusion_list(list(5, 2, &[b"b", b"c"]), true));
        let mut transactions: Vec<Vec<u8>> = store
            .transactions(5, ROOT, true)
            .into_iter()
            .map(|tx| tx.to_vec())
            .collect();
        transactions.sort();
        assert_eq!(
            transactions,
            vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]
        );
    }

    #[test]
    fn an_equivocator_is_no_longer_counted() {
        let mut store = InclusionListStore::default();
        store.process_inclusion_list(list(5, 1, &[b"a"]), true);
        // The same list again changes nothing.
        assert!(!store.process_inclusion_list(list(5, 1, &[b"a"]), true));
        assert_eq!(store.transactions(5, ROOT, true).len(), 1);
        // A different one marks the member an equivocator.
        assert!(!store.process_inclusion_list(list(5, 1, &[b"z"]), true));
        assert!(store.transactions(5, ROOT, true).is_empty());
        let committee = [1; 16];
        assert!(store.lists_for(&committee, 5, ROOT, &all_bits()).is_empty());
    }

    #[test]
    fn untimely_lists_count_only_when_asked() {
        let mut store = InclusionListStore::default();
        store.process_inclusion_list(list(5, 1, &[b"a"]), false);
        assert!(store.transactions(5, ROOT, true).is_empty());
        assert_eq!(store.transactions(5, ROOT, false).len(), 1);
    }

    fn all_bits() -> InclusionListBits {
        let mut bits = InclusionListBits::new();
        for i in 0..bits.len() {
            bits.set(i, true).unwrap();
        }
        bits
    }

    #[test]
    fn bits_follow_the_committee_order_and_check_inclusiveness() {
        let mut store = InclusionListStore::default();
        store.process_inclusion_list(list(5, 7, &[b"a"]), true);
        let mut committee = [0; 16];
        committee[3] = 7;
        let bits = store.bits(&committee, 5, ROOT, true);
        assert_eq!(bits.get(3), Some(true));
        assert_eq!((0..16).filter(|i| bits.get(*i).unwrap()).count(), 1);

        assert!(store.is_bits_inclusive(&committee, 5, ROOT, &bits, true));
        assert!(store.is_bits_inclusive(&committee, 5, ROOT, &all_bits(), true));
        assert!(!store.is_bits_inclusive(&committee, 5, ROOT, &InclusionListBits::new(), true));
    }

    #[test]
    fn old_slots_are_pruned() {
        let mut store = InclusionListStore::default();
        store.process_inclusion_list(list(1, 1, &[b"a"]), true);
        store.process_inclusion_list(list(1 + RETENTION_SLOTS + 1, 1, &[b"a"]), true);
        assert_eq!(store.count(1, ROOT), 0);
        assert_eq!(store.count(1 + RETENTION_SLOTS + 1, ROOT), 1);
    }
}
