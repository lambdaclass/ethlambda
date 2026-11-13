//! Per-block unslashed TIMELY_TARGET balances, kept so a block's pulled-up tip
//! does not rescan the validator registry.
//!
//! Fork choice's `compute_pulled_up_tip` needs, for every imported block, the
//! balance that cast a timely target vote in the previous and current epoch of
//! the block's post-state. Summing it is one pass over every validator, which
//! is the dominant per-block cost at mainnet scale. Within one epoch the sum
//! only grows by what a block adds (effective balances change only at the
//! epoch boundary), so the child's totals are its parent's plus the block's
//! own delta. This is Lighthouse's `ProgressiveBalancesCache`; it cannot live
//! on the state here (the per-fork state structs derive SSZ), so it is held by
//! the `Store` beside [`crate::ActiveBalanceCache`], keyed by block root.
//!
//! A block root identifies the post-state it produced, so an entry is never
//! stale: there is nothing to invalidate, only to bound. This module knows
//! nothing about a `BeaconState`; `ethlambda-state-transition`'s
//! `beacon::helpers::target_balances` derives the values and decides when a
//! parent's entry may be extended.
//!
//! # Bound
//!
//! An entry is a root plus three words. [`TARGET_BALANCE_CACHE_CAPACITY`]
//! caps the table; an insert into a full table drops the entry with the lowest
//! epoch. [`TargetBalanceCache::prune_below`] additionally drops every entry
//! older than the finalized epoch, which no later import can read: a block's
//! parent is only consulted when it shares the block's epoch. A dropped entry
//! costs one full registry scan on the next import that needed it, never a
//! wrong answer.

use std::collections::HashMap;
use std::sync::Mutex;

use ethlambda_types::beacon::primitives::{Epoch, Gwei, Root};

/// How many block roots stay resident.
///
/// Sized for several epochs of the unfinalized window across forks; the cost of
/// exceeding it is a rescan, so it only has to keep a long-lived store from
/// growing the table without limit while finality stalls.
const TARGET_BALANCE_CACHE_CAPACITY: usize = 4096;

/// The unslashed balance with the TIMELY_TARGET flag set, for the previous and
/// current epoch of one block's post-state.
///
/// Raw sums: the consumer applies the one-increment floor the specification's
/// `get_total_balance` does, which is not additive and so cannot be stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetBalances {
    /// The current epoch of the post-state the sums belong to.
    pub epoch: Epoch,
    /// Previous epoch's unslashed participating balance.
    pub previous: Gwei,
    /// Current epoch's unslashed participating balance.
    pub current: Gwei,
}

/// Target balances by block root. Internally synchronized, so every method
/// takes `&self`; the lock is never held while anything is computed.
#[derive(Debug, Default)]
pub struct TargetBalanceCache {
    entries: Mutex<HashMap<Root, TargetBalances>>,
}

impl TargetBalanceCache {
    /// The resident totals for `root`'s post-state, if any.
    pub fn get(&self, root: &Root) -> Option<TargetBalances> {
        self.entries.lock().unwrap().get(root).copied()
    }

    /// Records `root`'s totals, evicting the lowest-epoch entry when full.
    pub fn insert(&self, root: Root, totals: TargetBalances) {
        let mut entries = self.entries.lock().unwrap();
        if entries.len() >= TARGET_BALANCE_CACHE_CAPACITY && !entries.contains_key(&root) {
            let victim = entries
                .iter()
                .min_by_key(|(_, entry)| entry.epoch)
                .map(|(root, _)| *root);
            if let Some(victim) = victim {
                entries.remove(&victim);
            }
        }
        entries.insert(root, totals);
    }

    /// Drops every entry whose epoch is below `epoch`; called at finalization.
    pub fn prune_below(&self, epoch: Epoch) {
        self.entries
            .lock()
            .unwrap()
            .retain(|_, entry| entry.epoch >= epoch);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn totals(epoch: Epoch) -> TargetBalances {
        TargetBalances {
            epoch,
            previous: 1,
            current: 2,
        }
    }

    #[test]
    fn an_inserted_entry_is_returned() {
        let cache = TargetBalanceCache::default();
        let root = Root::repeat_byte(1);
        assert_eq!(cache.get(&root), None);
        cache.insert(root, totals(5));
        assert_eq!(cache.get(&root), Some(totals(5)));
    }

    #[test]
    fn a_full_cache_evicts_the_lowest_epoch() {
        let cache = TargetBalanceCache::default();
        let mut roots = Vec::new();
        for i in 0..TARGET_BALANCE_CACHE_CAPACITY {
            let mut root = Root::ZERO;
            root.0[..8].copy_from_slice(&(i as u64).to_be_bytes());
            roots.push(root);
            // Epochs fall as insertions rise, so insertion order and epoch
            // disagree about which entry is oldest.
            cache.insert(root, totals((TARGET_BALANCE_CACHE_CAPACITY - i) as Epoch));
        }
        let newest = Root::repeat_byte(0xff);
        cache.insert(newest, totals(10_000));

        assert_eq!(
            cache.entries.lock().unwrap().len(),
            TARGET_BALANCE_CACHE_CAPACITY
        );
        assert_eq!(cache.get(&newest), Some(totals(10_000)));
        let last = roots.last().unwrap();
        assert_eq!(cache.get(last), None, "the lowest epoch is the victim");
        assert!(cache.get(&roots[0]).is_some());
    }

    #[test]
    fn prune_below_keeps_the_boundary_epoch() {
        let cache = TargetBalanceCache::default();
        cache.insert(Root::repeat_byte(1), totals(3));
        cache.insert(Root::repeat_byte(2), totals(4));
        cache.prune_below(4);
        assert_eq!(cache.get(&Root::repeat_byte(1)), None);
        assert_eq!(cache.get(&Root::repeat_byte(2)), Some(totals(4)));
    }
}
