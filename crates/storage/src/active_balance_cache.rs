//! The total-active-balance cache: one [`Gwei`] per epoch, shared across every
//! caller asking the same epoch's total of a state that agrees on the block
//! that fixes it.
//!
//! A sibling of [`crate::committee_cache::CommitteeCache`], held by the
//! `Store` for the same reasons (see that module's documentation): one table
//! shared by the chain actor's state transition and fork choice, and by any
//! other task that holds the store. A caller with no `Store` of its own (a
//! spec runner, a one-off lookup, a unit test, block production's scratch
//! state) holds a fresh [`ActiveBalanceCache::default`] for as long as that
//! work lasts instead.
//!
//! This module knows nothing about a `BeaconState`: it is handed an
//! [`ActiveBalanceKey`] and, on a miss, runs a closure that returns the total.
//! The consensus logic that derives the key from a state, and the one-pass
//! sum that computes the value, lives in `ethlambda-state-transition`'s
//! `beacon::helpers::accessors`, in the `ActiveBalanceCacheExt` trait this
//! type implements there; that crate depends on this one, not the other way
//! around.
//!
//! Unlike the committee cache there is no single-flight machinery: the value
//! is one registry pass, cheap next to a whole-epoch shuffle, so two callers
//! racing on the same missing key may both compute it. They compute the same
//! number (the key fixes it), so the second insert is a no-op.

use std::sync::Mutex;

use ethlambda_types::beacon::primitives::{Epoch, Gwei, Root};

pub use crate::committee_cache::Lookup;

/// What pins the total active balance a state names for an epoch: the epoch
/// itself, and the last block root that could still have changed it.
///
/// Opaque to this module: `epoch` and `decision_root` are read only for
/// equality and, for eviction, ordering by `epoch`.
/// `ethlambda-state-transition`'s `beacon::helpers::accessors::active_balance_key`
/// derives one from a state and documents why that root is sound; note that
/// it is the last slot of `epoch - 1`, one epoch later than a
/// [`crate::ShufflingKey`]'s, so the two key types are kept apart rather than
/// shared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveBalanceKey {
    pub epoch: Epoch,
    pub decision_root: Root,
}

/// How many distinct totals stay resident in an [`ActiveBalanceCache`].
///
/// A block asks for one epoch's total; fork choice and sibling branches ask
/// for a few more. Entries are 8 bytes of value plus a 40 byte key, so room
/// for many concurrent forks and several epochs each costs next to nothing,
/// and the bound is only there so a long-lived store cannot grow the table
/// without limit.
const ACTIVE_BALANCE_CACHE_CAPACITY: usize = 32;

/// Totals shared across the calls asking for the same epoch's total active
/// balance, so a block derives it once instead of once per attestation.
///
/// Internally synchronized, so every method takes `&self`. The lock is held
/// only for the table lookup or insert, never while the value is computed.
///
/// # Eviction
///
/// A miss on a full table drops the entry for the lowest epoch (the earliest
/// inserted among equals): an older epoch's total is less likely to be asked
/// for again than a newer one's, whichever branch either belongs to. Every
/// lookup is counted in `lean_beacon_total_active_balance_lookups_total`.
#[derive(Debug, Default)]
pub struct ActiveBalanceCache {
    entries: Mutex<Vec<(ActiveBalanceKey, Gwei)>>,
}

impl ActiveBalanceCache {
    /// `key`'s total, running `compute` on a miss and remembering the result.
    ///
    /// `compute` runs outside the lock. Concurrent misses on one key may each
    /// run it; see the module documentation for why that is acceptable.
    pub fn get_or_compute(
        &self,
        key: ActiveBalanceKey,
        compute: impl FnOnce() -> Gwei,
    ) -> (Gwei, Lookup) {
        if let Some(total) = self.get(key) {
            return (total, Lookup::Hit);
        }
        let total = compute();
        let mut entries = self.entries.lock().unwrap();
        if !entries.iter().any(|(entry_key, _)| *entry_key == key) {
            if entries.len() >= ACTIVE_BALANCE_CACHE_CAPACITY {
                let victim = entries
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, (entry_key, _))| entry_key.epoch)
                    .map(|(position, _)| position);
                if let Some(position) = victim {
                    entries.remove(position);
                }
            }
            entries.push((key, total));
        }
        (total, Lookup::Miss)
    }

    /// The resident total for `key`, if any.
    pub fn get(&self, key: ActiveBalanceKey) -> Option<Gwei> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .find(|(entry_key, _)| *entry_key == key)
            .map(|(_, total)| *total)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    fn key(epoch: Epoch, decision_root: u8) -> ActiveBalanceKey {
        ActiveBalanceKey {
            epoch,
            decision_root: Root::repeat_byte(decision_root),
        }
    }

    #[test]
    fn a_repeat_lookup_is_served_from_the_cache() {
        let cache = ActiveBalanceCache::default();
        let (first, first_lookup) = cache.get_or_compute(key(1, 0), || 7);
        let (second, second_lookup) = cache.get_or_compute(key(1, 0), || panic!("rebuilt"));
        assert_eq!((first, first_lookup), (7, Lookup::Miss));
        assert_eq!((second, second_lookup), (7, Lookup::Hit));
    }

    #[test]
    fn keys_with_different_roots_or_epochs_are_distinct_entries() {
        let cache = ActiveBalanceCache::default();
        cache.get_or_compute(key(1, 1), || 10);
        let computed = Cell::new(0);
        for (k, value) in [(key(1, 2), 20), (key(2, 1), 30)] {
            let (total, lookup) = cache.get_or_compute(k, || {
                computed.set(computed.get() + 1);
                value
            });
            assert_eq!((total, lookup), (value, Lookup::Miss));
        }
        assert_eq!(computed.get(), 2);
        assert_eq!(cache.get(key(1, 1)), Some(10));
    }

    #[test]
    fn a_miss_on_a_full_cache_evicts_the_lowest_epoch() {
        let cache = ActiveBalanceCache::default();
        // Newest first, so eviction by epoch and by insertion order disagree.
        for epoch in (0..ACTIVE_BALANCE_CACHE_CAPACITY as Epoch).rev() {
            cache.get_or_compute(key(epoch, 0), || epoch);
        }
        cache.get_or_compute(key(1000, 0), || 1000);

        assert_eq!(cache.get(key(0, 0)), None);
        assert_eq!(cache.get(key(1, 0)), Some(1));
        assert_eq!(cache.get(key(1000, 0)), Some(1000));
        assert_eq!(
            cache.entries.lock().unwrap().len(),
            ACTIVE_BALANCE_CACHE_CAPACITY
        );
    }
}
