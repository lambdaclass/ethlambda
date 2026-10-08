//! Where a [`List`](crate::List) or [`Vector`](crate::Vector) buffers writes
//! until `apply_updates` folds them into its tree.

use std::collections::BTreeMap;

/// Pending writes, keyed by element index.
///
/// Two implementations with different costs: [`BTreeMap`] is sparse, suited
/// to rare, scattered writes of large elements (the validator registry);
/// [`VecMap`] is dense, suited to writing most of a list at once (balances at
/// an epoch boundary). The map is a type parameter of each list, so the choice
/// can be benchmarked per field.
pub trait UpdateMap<T>: Default + Clone + Send + Sync {
    /// The pending value at `index`, if any.
    fn get(&self, index: usize) -> Option<&T>;

    /// A mutable handle to the pending value at `index`, if any.
    fn get_mut(&mut self, index: usize) -> Option<&mut T>;

    /// Sets the pending value at `index`, replacing any earlier one.
    fn insert(&mut self, index: usize, value: T);

    /// Number of pending writes.
    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Every pending write, in ascending index order.
    fn into_sorted_vec(self) -> Vec<(usize, T)>;
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

    fn len(&self) -> usize {
        BTreeMap::len(self)
    }

    fn into_sorted_vec(self) -> Vec<(usize, T)> {
        self.into_iter().collect()
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
        assert_eq!(map.into_sorted_vec(), vec![(2, 21), (5, 55)]);
    }

    #[test]
    fn btree_map_buffers_writes() {
        buffers_writes::<BTreeMap<usize, u64>>();
    }

    #[test]
    fn vec_map_buffers_writes() {
        buffers_writes::<VecMap<u64>>();
    }
}
