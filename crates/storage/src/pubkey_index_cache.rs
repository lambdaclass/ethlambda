//! The pubkey to validator-index cache: a compact table answering "which
//! registry position holds this pubkey?" without walking the registry.
//!
//! A sibling of [`crate::active_balance_cache::ActiveBalanceCache`], held by
//! the `Store` for the same reasons (one table shared by the chain actor's
//! state transition and anything else holding a `Store` clone). A caller with
//! no `Store` of its own (a spec runner, a unit test, block production's
//! scratch state) holds a fresh [`PubkeyIndexCache::default`] for as long as
//! that work lasts.
//!
//! This module knows nothing about a `BeaconState`. It stores positions it is
//! told about and answers *candidates*; the consensus logic that feeds it a
//! state's registry and verifies a candidate against that state lives in
//! `ethlambda-state-transition`'s `beacon::helpers::accessors`, in the
//! `PubkeyIndexCacheExt` trait this type implements there.
//!
//! # Why a candidate, not an answer
//!
//! The table is process-wide, so it is fed by whichever state asked first. The
//! registry is append-only along one chain, so a pubkey's index never changes
//! there; across forks an unfinalized index may differ between branches, and
//! two keys can share a [`PubkeyIndexCache::key_of`] prefix. Both only ever
//! make a candidate wrong, never make a right one disappear, so the caller
//! checks every candidate against its own state and falls back to a scan when
//! none passes. A missing or wrong entry is a slower lookup, never a wrong
//! validator.
//!
//! # Layout
//!
//! A pubkey is keyed by eight bytes of itself ([`PubkeyIndexCache::key_of`]),
//! not all 48: that is 12 bytes per validator in the sorted base (an 8 byte
//! key and a 4 byte index) instead of 52, and eight bytes taken from the
//! uniformly distributed part of a compressed point make a collision between
//! two real keys negligible.
//!
//! Entries live in a sorted base (two parallel arrays, binary searched) plus
//! a small hash map holding positions appended since the base was last built.
//! The registry grows by a handful of validators a block at most, so the tail
//! absorbs that growth cheaply; when it reaches [`TAIL_MERGE_THRESHOLD`] it is
//! merged into the base in one linear pass.

use std::collections::HashMap;
use std::sync::RwLock;

use ethlambda_types::beacon::primitives::BlsPubkey;

/// How many appended entries the hash map tail holds before it is merged into
/// the sorted base.
///
/// A merge is linear in the whole table, so it must be rare: this many appends
/// is on the order of the validators a mainnet day adds. It is also small
/// enough that the tail's per-entry cost (a hash map slot, several times a
/// base entry) stays a rounding error next to the base.
pub const TAIL_MERGE_THRESHOLD: usize = 8192;

/// Pubkey-prefix to validator-index table. See the module documentation.
///
/// Internally synchronized, so every method takes `&self`. The write lock is
/// held only to splice entries in, never while a state is scanned: callers
/// collect a state's tail into a buffer first and hand it over.
#[derive(Debug, Default)]
pub struct PubkeyIndexCache {
    inner: RwLock<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    /// Sorted ascending by `(key, index)`; `indices[i]` belongs to `keys[i]`.
    /// Equal keys (a prefix collision, or one pubkey seen at two indices on
    /// two forks) sit next to each other and are all returned as candidates.
    keys: Vec<u64>,
    indices: Vec<u32>,
    /// Positions appended since the base was built. First writer wins for a
    /// key; a second candidate for the same key just costs the caller a scan.
    tail: HashMap<u64, u32>,
    /// How many registry positions have been ingested: positions
    /// `0..covered_len` of some chain's registry, in order.
    covered_len: usize,
}

impl PubkeyIndexCache {
    /// The table key for `pubkey`: bytes `1..9` as a big-endian integer.
    ///
    /// Byte 0 carries the compressed-point flag bits, which are the same for
    /// nearly every key, so it is skipped; the next eight bytes are uniformly
    /// distributed.
    pub fn key_of(pubkey: &BlsPubkey) -> u64 {
        let mut prefix = [0u8; 8];
        prefix.copy_from_slice(&pubkey.0[1..9]);
        u64::from_be_bytes(prefix)
    }

    /// How many registry positions have been ingested.
    pub fn covered_len(&self) -> usize {
        self.inner.read().unwrap().covered_len
    }

    /// The indices recorded under `pubkey`'s key: usually one, empty for a
    /// pubkey the table has never seen. Each must be verified against the
    /// caller's own registry.
    pub fn candidates(&self, pubkey: &BlsPubkey) -> Vec<u64> {
        let key = Self::key_of(pubkey);
        let inner = self.inner.read().unwrap();
        let start = inner.keys.partition_point(|candidate| *candidate < key);
        let mut found: Vec<u64> = inner.keys[start..]
            .iter()
            .zip(&inner.indices[start..])
            .take_while(|(candidate, _)| **candidate == key)
            .map(|(_, index)| u64::from(*index))
            .collect();
        if let Some(index) = inner.tail.get(&key) {
            found.push(u64::from(*index));
        }
        found
    }

    /// Records the pubkeys of registry positions `start..start + keys.len()`,
    /// where `keys` are [`Self::key_of`] values in position order.
    ///
    /// Positions already covered are skipped, so two callers that both saw the
    /// table short and both scanned the same tail do not double-insert. A
    /// `start` past `covered_len` would leave a gap that nothing could later
    /// fill in order, so it is refused (returns `false`); callers pass the
    /// `covered_len` they read, which only grows.
    ///
    /// A position whose index does not fit the table's `u32` is counted as
    /// covered but not stored: such a lookup finds no candidate and takes the
    /// caller's scan, which is correct and unreachable in practice.
    pub fn extend(&self, start: usize, keys: &[u64]) -> bool {
        let mut inner = self.inner.write().unwrap();
        if start > inner.covered_len {
            return false;
        }
        let skip = (inner.covered_len - start).min(keys.len());
        let fresh = &keys[skip..];
        let first_position = inner.covered_len;
        let entries = fresh.iter().enumerate().filter_map(|(offset, key)| {
            u32::try_from(first_position + offset)
                .ok()
                .map(|index| (*key, index))
        });

        if fresh.len() >= TAIL_MERGE_THRESHOLD {
            // A bulk load (the first ingest of a whole registry): sorting it
            // directly beats funnelling millions of entries through the map.
            let mut batch: Vec<(u64, u32)> = entries.collect();
            batch.extend(inner.tail.drain());
            inner.merge(batch);
        } else {
            for (key, index) in entries {
                inner.tail.entry(key).or_insert(index);
            }
            if inner.tail.len() >= TAIL_MERGE_THRESHOLD {
                let batch: Vec<(u64, u32)> = inner.tail.drain().collect();
                inner.merge(batch);
            }
        }
        inner.covered_len += fresh.len();
        true
    }

    /// Heap bytes held by the table: capacity of the base arrays plus the
    /// tail's slots.
    pub fn heap_bytes(&self) -> usize {
        let inner = self.inner.read().unwrap();
        inner.keys.capacity() * size_of::<u64>()
            + inner.indices.capacity() * size_of::<u32>()
            + inner.tail.capacity() * (size_of::<u64>() + size_of::<u32>())
    }
}

impl Inner {
    /// Merges `batch` into the sorted base, ordering ties by index so the
    /// earlier registry position is returned first.
    fn merge(&mut self, mut batch: Vec<(u64, u32)>) {
        batch.sort_unstable();
        let total = self.keys.len() + batch.len();
        let mut keys = Vec::with_capacity(total);
        let mut indices = Vec::with_capacity(total);
        let (mut base, mut fresh) = (0, 0);
        while base < self.keys.len() || fresh < batch.len() {
            let take_base = fresh == batch.len()
                || (base < self.keys.len()
                    && (self.keys[base], self.indices[base]) <= batch[fresh]);
            if take_base {
                keys.push(self.keys[base]);
                indices.push(self.indices[base]);
                base += 1;
            } else {
                keys.push(batch[fresh].0);
                indices.push(batch[fresh].1);
                fresh += 1;
            }
        }
        self.keys = keys;
        self.indices = indices;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pubkey(seed: u64) -> BlsPubkey {
        let mut bytes = [0u8; 48];
        bytes[0] = 0x80;
        bytes[1..9].copy_from_slice(&seed.to_be_bytes());
        BlsPubkey(bytes)
    }

    fn keys(seeds: std::ops::Range<u64>) -> Vec<u64> {
        seeds
            .map(|seed| PubkeyIndexCache::key_of(&pubkey(seed)))
            .collect()
    }

    #[test]
    fn a_small_extend_is_served_from_the_tail() {
        let cache = PubkeyIndexCache::default();
        assert!(cache.extend(0, &keys(10..20)));
        assert_eq!(cache.covered_len(), 10);
        assert_eq!(cache.candidates(&pubkey(13)), vec![3]);
        assert!(cache.candidates(&pubkey(99)).is_empty());
    }

    #[test]
    fn a_bulk_extend_and_a_later_tail_both_resolve() {
        let cache = PubkeyIndexCache::default();
        let bulk = TAIL_MERGE_THRESHOLD as u64 * 2;
        assert!(cache.extend(0, &keys(1..bulk + 1)));
        assert!(cache.extend(bulk as usize, &keys(bulk + 1..bulk + 4)));
        assert_eq!(cache.covered_len(), bulk as usize + 3);
        assert_eq!(cache.candidates(&pubkey(1)), vec![0]);
        assert_eq!(cache.candidates(&pubkey(bulk)), vec![bulk - 1]);
        assert_eq!(cache.candidates(&pubkey(bulk + 2)), vec![bulk + 1]);
    }

    #[test]
    fn a_tail_reaching_the_threshold_merges_into_the_base() {
        let cache = PubkeyIndexCache::default();
        let step = TAIL_MERGE_THRESHOLD as u64 - 1;
        assert!(cache.extend(0, &keys(0..step)));
        assert_eq!(cache.inner.read().unwrap().keys.len(), 0);
        assert!(cache.extend(step as usize, &keys(step..step + 5)));
        {
            let inner = cache.inner.read().unwrap();
            assert_eq!(inner.keys.len(), step as usize + 5);
            assert!(inner.tail.is_empty());
            assert!(inner.keys.is_sorted());
        }
        assert_eq!(cache.candidates(&pubkey(step + 4)), vec![step + 4]);
    }

    #[test]
    fn already_covered_positions_are_skipped_and_gaps_refused() {
        let cache = PubkeyIndexCache::default();
        assert!(cache.extend(0, &keys(0..5)));
        // A second caller that scanned the same tail.
        assert!(cache.extend(3, &keys(3..8)));
        assert_eq!(cache.covered_len(), 8);
        assert_eq!(cache.candidates(&pubkey(4)), vec![4]);
        assert!(!cache.extend(20, &keys(20..22)));
        assert_eq!(cache.covered_len(), 8);
    }

    #[test]
    fn equal_keys_return_every_candidate_in_index_order() {
        let cache = PubkeyIndexCache::default();
        let bulk = TAIL_MERGE_THRESHOLD as u64;
        let mut all = keys(100..100 + bulk);
        all[7] = all[2];
        assert!(cache.extend(0, &all));
        assert_eq!(cache.candidates(&pubkey(102)), vec![2, 7]);
    }

    #[test]
    fn the_base_costs_twelve_bytes_an_entry() {
        let cache = PubkeyIndexCache::default();
        let count = TAIL_MERGE_THRESHOLD as u64 * 4;
        assert!(cache.extend(0, &keys(0..count)));
        assert_eq!(cache.heap_bytes(), count as usize * 12);
    }

    /// Sizing check for a mainnet-scale registry; prints, asserts nothing
    /// about time. Run with `-- --ignored --nocapture`.
    #[test]
    #[ignore = "measurement, not a check"]
    fn a_mainnet_scale_ingest_measured() {
        const COUNT: u64 = 2_400_000;
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let keys: Vec<u64> = (0..COUNT)
            .map(|_| {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                state
            })
            .collect();
        let cache = PubkeyIndexCache::default();
        let started = std::time::Instant::now();
        cache.extend(0, &keys);
        let ingest = started.elapsed();
        let started = std::time::Instant::now();
        let hits = (0..COUNT as usize)
            .step_by(1000)
            .filter(|position| {
                let key = keys[*position];
                let inner = cache.inner.read().unwrap();
                inner.keys.binary_search(&key).is_ok()
            })
            .count();
        println!(
            "ingest {COUNT} keys: {ingest:?}; {hits} lookups: {:?}; heap {} bytes",
            started.elapsed(),
            cache.heap_bytes()
        );
    }
}
