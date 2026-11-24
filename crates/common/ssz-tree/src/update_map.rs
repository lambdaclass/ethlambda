//! Where a [`List`](crate::List) or [`Vector`](crate::Vector) buffers writes
//! until `apply_updates` folds them into its tree.

use std::collections::BTreeMap;
use std::collections::hash_map::{self, HashMap};
use std::hash::{BuildHasherDefault, Hasher};

/// Pending writes, keyed by element index.
///
/// Three implementations with different costs: [`BTreeMap`] is sparse and
/// ordered, suited to rare, scattered writes of large elements (the validator
/// registry); [`SparseMap`] is sparse and hashed, suited to a few hundred to
/// a few tens of thousands of scattered writes per block into a list of
/// millions (balances, participation); [`VecMap`] is dense, suited to writing
/// most of a list at once. The map is a type parameter of each list, so the
/// choice can be benchmarked per field.
pub trait UpdateMap<T>: Default + Clone + Send + Sync {
    /// The pending value at `index`, if any.
    fn get(&self, index: usize) -> Option<&T>;

    /// A mutable handle to the pending value at `index`, if any.
    fn get_mut(&mut self, index: usize) -> Option<&mut T>;

    /// Sets the pending value at `index`, replacing any earlier one.
    fn insert(&mut self, index: usize, value: T);

    /// The pending value at `index`, first set to `value()` if there is none.
    ///
    /// What a first write to an element costs: one lookup where `get`,
    /// `insert` and `get_mut` would make three.
    fn get_or_insert_with(&mut self, index: usize, value: impl FnOnce() -> T) -> &mut T {
        if self.get(index).is_none() {
            self.insert(index, value());
        }
        self.get_mut(index).expect("inserted just above")
    }

    /// Number of pending writes.
    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Every pending write, in ascending index order.
    fn into_sorted_vec(self) -> Vec<(usize, T)>;

    /// Every pending write, in ascending index order, by reference: what an
    /// in-order pass over the list merges in, so that it needs no lookup per
    /// element.
    fn sorted_refs(&self) -> Vec<(usize, &T)>;
}

impl<T: Clone + Send + Sync> UpdateMap<T> for BTreeMap<usize, T> {
    fn get(&self, index: usize) -> Option<&T> {
        BTreeMap::get(self, &index)
    }

    fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        BTreeMap::get_mut(self, &index)
    }

    fn insert(&mut self, index: usize, value: T) {
        BTreeMap::insert(self, index, value);
    }

    fn get_or_insert_with(&mut self, index: usize, value: impl FnOnce() -> T) -> &mut T {
        self.entry(index).or_insert_with(value)
    }

    fn len(&self) -> usize {
        BTreeMap::len(self)
    }

    fn into_sorted_vec(self) -> Vec<(usize, T)> {
        self.into_iter().collect()
    }

    fn sorted_refs(&self) -> Vec<(usize, &T)> {
        self.iter().map(|(&index, value)| (index, value)).collect()
    }
}

/// A dense map: one slot per index, up to the highest index written.
///
/// Growing to the highest written index is the price of O(1) access: one
/// write near the end of a 2.4M-element list allocates 2.4M slots. Lighthouse
/// pays the same price for its balances.
#[derive(Debug, Clone)]
pub struct VecMap<T> {
    slots: Vec<Option<T>>,
    len: usize,
}

impl<T> Default for VecMap<T> {
    fn default() -> Self {
        Self {
            slots: Vec::new(),
            len: 0,
        }
    }
}

impl<T: Clone + Send + Sync> UpdateMap<T> for VecMap<T> {
    fn get(&self, index: usize) -> Option<&T> {
        self.slots.get(index)?.as_ref()
    }

    fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        self.slots.get_mut(index)?.as_mut()
    }

    fn insert(&mut self, index: usize, value: T) {
        if index >= self.slots.len() {
            self.slots.resize_with(index + 1, || None);
        }
        if self.slots[index].replace(value).is_none() {
            self.len += 1;
        }
    }

    fn get_or_insert_with(&mut self, index: usize, value: impl FnOnce() -> T) -> &mut T {
        if index >= self.slots.len() {
            self.slots.resize_with(index + 1, || None);
        }
        let slot = &mut self.slots[index];
        if slot.is_none() {
            self.len += 1;
        }
        slot.get_or_insert_with(value)
    }

    fn len(&self) -> usize {
        self.len
    }

    fn into_sorted_vec(self) -> Vec<(usize, T)> {
        self.slots
            .into_iter()
            .enumerate()
            .filter_map(|(index, slot)| slot.map(|value| (index, value)))
            .collect()
    }

    fn sorted_refs(&self) -> Vec<(usize, &T)> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| slot.as_ref().map(|value| (index, value)))
            .collect()
    }
}

/// A sparse map: a hash table from index to pending value.
///
/// What it costs follows the writes, not the list: no slot per element, nothing
/// to scan, and draining it sorts only what was written. That suits a list of
/// millions that a block writes a few hundred times (balances: rewards to the
/// sync committee and the proposer) or a few tens of thousands of times
/// (participation flags), where a [`VecMap`] allocates, fills and scans a slot
/// for every element. A pass that writes most of a list should go through the
/// write cursor (`iter_cow`) instead, which buffers nothing.
#[derive(Debug, Clone)]
pub struct SparseMap<T> {
    entries: HashMap<usize, T, BuildHasherDefault<IndexHasher>>,
}

impl<T> Default for SparseMap<T> {
    fn default() -> Self {
        Self {
            entries: HashMap::default(),
        }
    }
}

impl<T: Clone + Send + Sync> UpdateMap<T> for SparseMap<T> {
    fn get(&self, index: usize) -> Option<&T> {
        self.entries.get(&index)
    }

    fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        self.entries.get_mut(&index)
    }

    fn insert(&mut self, index: usize, value: T) {
        self.entries.insert(index, value);
    }

    fn get_or_insert_with(&mut self, index: usize, value: impl FnOnce() -> T) -> &mut T {
        match self.entries.entry(index) {
            hash_map::Entry::Occupied(entry) => entry.into_mut(),
            hash_map::Entry::Vacant(entry) => entry.insert(value()),
        }
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn into_sorted_vec(self) -> Vec<(usize, T)> {
        let mut entries: Vec<(usize, T)> = self.entries.into_iter().collect();
        // Every index appears once, so an unstable sort loses nothing.
        entries.sort_unstable_by_key(|&(index, _)| index);
        entries
    }

    fn sorted_refs(&self) -> Vec<(usize, &T)> {
        let mut entries: Vec<(usize, &T)> = self
            .entries
            .iter()
            .map(|(&index, value)| (index, value))
            .collect();
        entries.sort_unstable_by_key(|&(index, _)| index);
        entries
    }
}

/// Hashes an element index with one multiply.
///
/// Indices are not adversarial (they are positions in a list whose length the
/// consensus rules bound), so SipHash's resistance to chosen keys buys nothing
/// here and costs most of a lookup. The multiply spreads the index over the
/// high bits, which the table's control bytes read; folding them back down
/// spreads it over the low bits too, which pick the bucket, so indices that
/// share their low bits (a stride) still land apart.
#[derive(Default, Clone, Copy)]
struct IndexHasher(u64);

impl Hasher for IndexHasher {
    fn write(&mut self, bytes: &[u8]) {
        // Only reached by a key type other than `usize`, which no map here has.
        for &byte in bytes {
            self.write_u64(u64::from(byte));
        }
    }

    fn write_u64(&mut self, value: u64) {
        let mixed = (self.0 ^ value).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        self.0 = mixed ^ (mixed >> 32);
    }

    fn write_usize(&mut self, value: usize) {
        self.write_u64(value as u64);
    }

    fn finish(&self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn buffers_writes<M: UpdateMap<u64>>() {
        let mut map = M::default();
        assert!(map.is_empty());
        map.insert(5, 50);
        map.insert(2, 20);
        map.insert(5, 55);
        assert_eq!(map.len(), 2);
        assert_eq!(map.get(5), Some(&55));
        assert_eq!(map.get(3), None);
        assert_eq!(map.get(99), None);
        *map.get_mut(2).unwrap() += 1;
        *map.get_or_insert_with(7, || 70) += 1;
        *map.get_or_insert_with(5, || unreachable!("5 is pending")) += 1;
        assert_eq!(map.len(), 3);
        assert_eq!(map.sorted_refs(), vec![(2, &21), (5, &56), (7, &71)]);
        assert_eq!(map.into_sorted_vec(), vec![(2, 21), (5, 56), (7, 71)]);
    }

    #[test]
    fn btree_map_buffers_writes() {
        buffers_writes::<BTreeMap<usize, u64>>();
    }

    #[test]
    fn vec_map_buffers_writes() {
        buffers_writes::<VecMap<u64>>();
    }

    #[test]
    fn sparse_map_buffers_writes() {
        buffers_writes::<SparseMap<u64>>();
    }
}
