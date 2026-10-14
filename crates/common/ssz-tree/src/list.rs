//! [`List`]: an SSZ `List[T, N]` kept in a persistent Merkle tree.

use std::fmt;
use std::ops::{Index, IndexMut};

use libssz::{DecodeError, SszDecode, SszEncode};
use libssz_merkle::{HashTreeRoot, Sha2Hasher, Sha256Hasher, mix_in_length};
use libssz_types::TypeError;

use crate::cursor::{ElemCow, IterCow};
use crate::interface::Interface;
use crate::iter::Iter;
use crate::update_map::{UpdateMap, VecMap};
use crate::{Hash256, Value, tree_depth};

/// An SSZ list of at most `N` elements, kept in a persistent Merkle tree.
///
/// Stands in for `libssz_types::SszList<T, N>` in a derived container: the
/// same SSZ encoding, the same `hash_tree_root`, and the same element API
/// (`len`, `get`, `get_mut`, `push`, `iter`, `[i]`), minus slice access, since
/// the elements are not contiguous.
///
/// A clone is O(1) and shares the whole tree. Writes are buffered in `U` (see
/// [`UpdateMap`]) until [`List::apply_updates`].
#[derive(Clone)]
pub struct List<T, const N: usize, U = VecMap<T>> {
    interface: Interface<T, U>,
}

impl<T: Value, const N: usize, U: UpdateMap<T>> List<T, N, U> {
    fn depth() -> usize {
        tree_depth::<T>(N)
    }

    /// An empty list.
    pub fn empty() -> Self {
        Self {
            interface: Interface::from_values(std::iter::empty(), Self::depth()),
        }
    }

    /// The number of elements, pending pushes included.
    pub fn len(&self) -> usize {
        self.interface.len()
    }

    /// Whether the list holds no elements.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The type's element limit, `N`.
    pub fn max_capacity(&self) -> usize {
        N
    }

    /// The element at `index`, or `None` past the end.
    pub fn get(&self, index: usize) -> Option<&T> {
        self.interface.get(index)
    }

    /// The element at `index`, to be written. The write is buffered until
    /// [`List::apply_updates`].
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        self.interface.get_mut(index)
    }

    /// Appends `value`, buffered until [`List::apply_updates`].
    pub fn push(&mut self, value: T) -> Result<(), TypeError> {
        if self.len() >= N {
            return Err(TypeError::OverCapacity {
                max: N,
                got: self.len() + 1,
            });
        }
        self.interface.push(value);
        Ok(())
    }

    /// An in-order pass that can rewrite any element, for updating most of the
    /// list at once. Applies pending writes first; the pass's writes reach the
    /// tree when it is dropped, so an early return or a panic keeps the writes
    /// made so far.
    pub fn iter_cow(&mut self) -> IterCow<'_, T> {
        self.interface.iter_cow()
    }

    /// Runs `f` on every element in order, stopping at the first error and
    /// keeping the writes made before it. See [`List::iter_cow`].
    pub fn try_update_each<E>(
        &mut self,
        mut f: impl FnMut(&mut ElemCow<'_, T>) -> Result<(), E>,
    ) -> Result<(), E> {
        let mut pass = self.iter_cow();
        while let Some(mut element) = pass.next_cow() {
            f(&mut element)?;
        }
        Ok(())
    }

    /// The elements in order, pending writes included.
    pub fn iter(&self) -> Iter<'_, T, U> {
        self.interface.iter_from(0)
    }

    /// The elements from `index` on; empty if `index` is past the end.
    pub fn iter_from(&self, index: usize) -> Iter<'_, T, U> {
        self.interface.iter_from(index)
    }

    /// A `Vec` copy of the elements, pending writes included.
    pub fn to_vec(&self) -> Vec<T> {
        self.iter().cloned().collect()
    }

    /// Folds every buffered write into the tree, rebuilding the touched paths
    /// once.
    pub fn apply_updates(&mut self) {
        self.interface.apply_updates();
    }

    /// Whether any write is buffered and not yet folded into the tree.
    pub fn has_pending_updates(&self) -> bool {
        self.interface.has_pending_updates()
    }

    /// Makes this list share every unchanged subtree with `base`, after
    /// applying its own pending writes. The contents do not change.
    pub fn rebase_on(&mut self, base: &Self) {
        self.interface.rebase_on(&base.interface);
    }

    /// Whether both lists' committed trees are the same allocation: a cheap
    /// check of sharing, not of equality.
    pub fn ptr_eq(&self, other: &Self) -> bool {
        self.interface.ptr_eq(&other.interface)
    }
}

impl<T: Value, const N: usize, U: UpdateMap<T>> Default for List<T, N, U> {
    fn default() -> Self {
        Self::empty()
    }
}

impl<T: Value, const N: usize, U: UpdateMap<T>> TryFrom<Vec<T>> for List<T, N, U> {
    type Error = TypeError;

    fn try_from(values: Vec<T>) -> Result<Self, TypeError> {
        if values.len() > N {
            return Err(TypeError::OverCapacity {
                max: N,
                got: values.len(),
            });
        }
        Ok(Self {
            interface: Interface::from_values(values, Self::depth()),
        })
    }
}

impl<T: Value, const N: usize, U: UpdateMap<T>> Index<usize> for List<T, N, U> {
    type Output = T;

    fn index(&self, index: usize) -> &T {
        let len = self.len();
        self.get(index)
            .unwrap_or_else(|| panic!("index {index} out of bounds for a list of length {len}"))
    }
}

impl<T: Value, const N: usize, U: UpdateMap<T>> IndexMut<usize> for List<T, N, U> {
    fn index_mut(&mut self, index: usize) -> &mut T {
        let len = self.len();
        self.get_mut(index)
            .unwrap_or_else(|| panic!("index {index} out of bounds for a list of length {len}"))
    }
}

impl<T: Value, const N: usize, U: UpdateMap<T>> PartialEq for List<T, N, U> {
    fn eq(&self, other: &Self) -> bool {
        if self.len() != other.len() {
            return false;
        }
        let nothing_pending = !self.has_pending_updates() && !other.has_pending_updates();
        (nothing_pending && self.ptr_eq(other)) || self.iter().eq(other.iter())
    }
}

impl<T: Value + Eq, const N: usize, U: UpdateMap<T>> Eq for List<T, N, U> {}

impl<T: Value + fmt::Debug, const N: usize, U: UpdateMap<T>> fmt::Debug for List<T, N, U> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl<'a, T: Value, const N: usize, U: UpdateMap<T>> IntoIterator for &'a List<T, N, U> {
    type Item = &'a T;
    type IntoIter = Iter<'a, T, U>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<T: Value, const N: usize, U: UpdateMap<T>> SszEncode for List<T, N, U> {
    fn is_fixed_size() -> bool {
        false
    }

    fn fixed_size() -> usize {
        0
    }

    fn encoded_len(&self) -> usize {
        self.interface.encoded_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.interface.ssz_append(buf);
    }
}

impl<T: Value, const N: usize, U: UpdateMap<T>> SszDecode for List<T, N, U> {
    fn is_fixed_size() -> bool {
        false
    }

    fn fixed_size() -> usize {
        0
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self {
            interface: Interface::from_ssz_bytes(bytes, N, Self::depth())?,
        })
    }
}

impl<T: Value, const N: usize, U: UpdateMap<T>> HashTreeRoot for List<T, N, U> {
    /// Ignores `hasher` and uses SHA-256: see the crate docs.
    fn hash_tree_root(&self, _hasher: &impl Sha256Hasher) -> Hash256 {
        mix_in_length(&Sha2Hasher, &self.interface.root(), self.len())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
    use libssz_types::SszList;

    use super::*;

    #[derive(Debug, Clone, Default, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
    struct Item {
        id: u64,
        data: [u8; 32],
    }

    fn item(id: u64) -> Item {
        Item {
            id,
            data: [id as u8; 32],
        }
    }

    fn root<L: HashTreeRoot>(list: &L) -> Hash256 {
        HashTreeRoot::hash_tree_root(list, &Sha2Hasher)
    }

    fn model<T: Value, const N: usize>(values: &[T]) -> SszList<T, N> {
        values.to_vec().try_into().expect("within the limit")
    }

    type Balances = List<u64, 1024>;
    type Items = List<Item, 100, BTreeMap<usize, Item>>;

    #[test]
    fn an_empty_list_hashes_like_an_empty_ssz_list() {
        assert_eq!(root(&Balances::empty()), root(&model::<u64, 1024>(&[])));
        assert_eq!(root(&Items::default()), root(&model::<Item, 100>(&[])));
    }

    #[test]
    fn a_built_list_matches_ssz_list_at_every_length() {
        for len in [1u64, 3, 4, 5, 8, 9, 255, 256, 257] {
            let values: Vec<u64> = (0..len).map(|i| i * 7 + 1).collect();
            let list = Balances::try_from(values.clone()).unwrap();
            assert_eq!(list.len(), values.len());
            assert_eq!(list.to_vec(), values);
            assert_eq!(root(&list), root(&model::<u64, 1024>(&values)), "len {len}");
        }
    }

    #[test]
    fn a_registry_sized_limit_hashes_like_ssz_list() {
        let values: Vec<u64> = (0..10).collect();
        let list = List::<u64, { 1 << 40 }>::try_from(values.clone()).unwrap();
        assert_eq!(root(&list), root(&model::<u64, { 1 << 40 }>(&values)));
    }

    #[test]
    fn writes_are_visible_before_they_are_applied() {
        let mut list = Items::try_from(vec![item(0), item(1)]).unwrap();
        list.get_mut(1).unwrap().id = 11;
        list.push(item(2)).unwrap();
        assert!(list.has_pending_updates());
        assert_eq!(list.len(), 3);
        assert_eq!(list[1].id, 11);
        assert_eq!(list.get(2), Some(&item(2)));
        assert_eq!(list.get(3), None);
        let collected: Vec<u64> = list.iter().map(|item| item.id).collect();
        assert_eq!(collected, vec![0, 11, 2]);
    }

    #[test]
    fn applied_writes_hash_like_the_same_ssz_list() {
        let mut list = Balances::try_from((0..10).collect::<Vec<u64>>()).unwrap();
        list[3] = 300;
        list.push(10).unwrap();
        list.push(11).unwrap();
        let expected: Vec<u64> = (0..12).map(|i| if i == 3 { 300 } else { i }).collect();

        // Hashing with writes pending is correct and leaves them pending.
        assert_eq!(root(&list), root(&model::<u64, 1024>(&expected)));
        assert!(list.has_pending_updates());

        list.apply_updates();
        assert!(!list.has_pending_updates());
        assert_eq!(list.to_vec(), expected);
        assert_eq!(root(&list), root(&model::<u64, 1024>(&expected)));
    }

    #[test]
    fn a_clone_does_not_see_later_writes() {
        let mut original = Items::try_from(vec![item(0), item(1)]).unwrap();
        let snapshot = original.clone();
        original[0].id = 99;
        original.apply_updates();
        original.push(item(2)).unwrap();
        assert_eq!(snapshot.to_vec(), vec![item(0), item(1)]);
        assert_eq!(original.len(), 3);
    }

    #[test]
    fn pushing_past_the_limit_is_an_error() {
        let mut list = List::<u64, 2>::empty();
        list.push(1).unwrap();
        list.push(2).unwrap();
        assert_eq!(
            list.push(3),
            Err(TypeError::OverCapacity { max: 2, got: 3 })
        );
        assert_eq!(
            List::<u64, 2>::try_from(vec![1, 2, 3]),
            Err(TypeError::OverCapacity { max: 2, got: 3 })
        );
    }

    #[test]
    fn get_mut_past_the_end_is_none() {
        let mut list = Balances::try_from(vec![1, 2]).unwrap();
        assert!(list.get_mut(2).is_none());
        assert!(!list.has_pending_updates());
    }

    #[test]
    #[should_panic(expected = "out of bounds")]
    fn indexing_past_the_end_panics() {
        let list = Balances::try_from(vec![1, 2]).unwrap();
        let _ = list[2];
    }

    #[test]
    fn equality_is_by_contents_not_by_history() {
        let built = Balances::try_from(vec![1, 2, 3]).unwrap();
        let mut pushed = Balances::empty();
        for value in [1, 2, 3] {
            pushed.push(value).unwrap();
        }
        assert_eq!(built, pushed);
        pushed.apply_updates();
        assert_eq!(built, pushed);
        pushed[0] = 5;
        assert_ne!(built, pushed);
    }

    #[test]
    fn a_write_breaks_equality_even_while_the_tree_is_still_shared() {
        let b = Balances::try_from(vec![1, 2, 3]).unwrap();
        let mut a = b.clone();
        assert!(a.ptr_eq(&b));
        a[0] = 100;
        // `a` still shares `b`'s tree (the write is only buffered), so the
        // `ptr_eq` fast path in `PartialEq` must not fire here.
        assert!(a.ptr_eq(&b));
        assert_ne!(a, b);
        a.apply_updates();
        assert_ne!(a, b);
    }

    #[test]
    fn clones_with_the_same_pending_write_are_equal() {
        let base = Balances::try_from(vec![1, 2, 3]).unwrap();
        let mut a = base.clone();
        let mut b = base.clone();
        a[0] = 42;
        b[0] = 42;
        assert!(a.ptr_eq(&b));
        assert_eq!(a, b);
    }

    #[test]
    fn cloning_after_a_write_carries_the_pending_write_to_both_copies() {
        let mut a = Balances::try_from(vec![1, 2, 3]).unwrap();
        a[0] = 42;
        let b = a.clone();
        a.apply_updates();
        assert!(!a.has_pending_updates());
        assert!(b.has_pending_updates());
        assert_eq!(a, b);
        assert_eq!(b[0], 42);
    }

    #[test]
    fn pushing_on_a_clone_makes_the_lists_unequal() {
        let a = Balances::try_from(vec![1, 2, 3]).unwrap();
        let mut b = a.clone();
        b.push(4).unwrap();
        // Same tree, different length: `len` must be checked before `ptr_eq`.
        assert!(a.ptr_eq(&b));
        assert_ne!(a, b);
    }

    #[test]
    fn iter_from_starts_at_the_given_index() {
        let list = Balances::try_from((0..9).collect::<Vec<u64>>()).unwrap();
        let tail: Vec<u64> = list.iter_from(6).copied().collect();
        assert_eq!(tail, vec![6, 7, 8]);
        assert_eq!(list.iter_from(9).count(), 0);
        assert_eq!(list.iter_from(50).count(), 0);
        assert_eq!(list.iter().len(), 9);
    }

    /// A variable-size element (an `SszList` itself), like the beacon
    /// `Blob` type: exercises the offset-table encode/decode path rather
    /// than the fixed-size one.
    type VarElem = SszList<u8, 64>;
    type VarList = List<VarElem, 4>;
    type VarModel = SszList<VarElem, 4>;

    fn var_elem(bytes: &[u8]) -> VarElem {
        bytes.to_vec().try_into().expect("within the limit")
    }

    #[test]
    fn fixed_size_elements_round_trip_like_ssz_list() {
        for len in [0usize, 1, 3, 255, 1024] {
            let values: Vec<u64> = (0..len as u64).map(|i| i * 7 + 1).collect();
            let list = Balances::try_from(values.clone()).unwrap();
            let model = model::<u64, 1024>(&values);
            let encoded = list.to_ssz();
            assert_eq!(encoded, model.to_ssz(), "len {len}");
            assert_eq!(
                Balances::from_ssz_bytes(&encoded).unwrap(),
                list,
                "len {len}"
            );
        }
    }

    #[test]
    fn composite_fixed_size_elements_round_trip_like_ssz_list() {
        for len in [0usize, 1, 3, 100] {
            let values: Vec<Item> = (0..len as u64).map(item).collect();
            let list = Items::try_from(values.clone()).unwrap();
            let model = model::<Item, 100>(&values);
            let encoded = list.to_ssz();
            assert_eq!(encoded, model.to_ssz(), "len {len}");
            assert_eq!(Items::from_ssz_bytes(&encoded).unwrap(), list, "len {len}");
        }
    }

    #[test]
    fn variable_size_elements_round_trip_like_ssz_list() {
        let cases: [Vec<VarElem>; 2] = [
            vec![],
            vec![
                var_elem(&[]),
                var_elem(&[1, 2, 3]),
                var_elem(&(0..64).collect::<Vec<u8>>()),
                var_elem(&[9]),
            ],
        ];
        for values in cases {
            let list = VarList::try_from(values.clone()).unwrap();
            let model: VarModel = values.clone().try_into().unwrap();
            let encoded = list.to_ssz();
            assert_eq!(encoded, model.to_ssz(), "len {}", values.len());
            assert_eq!(
                VarList::from_ssz_bytes(&encoded).unwrap(),
                list,
                "len {}",
                values.len()
            );
        }
    }

    #[test]
    fn encoding_with_pending_writes_matches_encoding_after_apply_updates() {
        let mut list = Balances::try_from(vec![1, 2, 3]).unwrap();
        list[0] = 99;
        list.push(4).unwrap();
        assert!(list.has_pending_updates());
        let pending_bytes = list.to_ssz();

        let mut applied = list.clone();
        applied.apply_updates();
        assert_eq!(pending_bytes, applied.to_ssz());
    }

    #[test]
    fn decoding_too_many_fixed_size_elements_is_rejected_like_ssz_list() {
        let values: Vec<u64> = (0..5).collect();
        let encoded = model::<u64, 10>(&values).to_ssz();
        let list_err = List::<u64, 3>::from_ssz_bytes(&encoded).unwrap_err();
        let ssz_err = SszList::<u64, 3>::from_ssz_bytes(&encoded).unwrap_err();
        assert_eq!(list_err, ssz_err);
    }

    #[test]
    fn decoding_a_length_not_a_multiple_of_the_element_size_is_rejected_like_ssz_list() {
        let bytes = vec![0u8; 7]; // u64 is 8 bytes wide; 7 does not divide evenly.
        let list_err = List::<u64, 10>::from_ssz_bytes(&bytes).unwrap_err();
        let ssz_err = SszList::<u64, 10>::from_ssz_bytes(&bytes).unwrap_err();
        assert_eq!(list_err, ssz_err);
    }

    #[test]
    fn decoding_a_first_offset_that_is_not_a_multiple_of_four_is_rejected_like_ssz_list() {
        let bytes = vec![5, 0, 0, 0, 0]; // first offset = 5, not a multiple of 4.
        let list_err = VarList::from_ssz_bytes(&bytes).unwrap_err();
        let ssz_err = VarModel::from_ssz_bytes(&bytes).unwrap_err();
        assert_eq!(list_err, ssz_err);
    }

    #[test]
    fn decoding_a_decreasing_offset_is_rejected_like_ssz_list() {
        // Two items: offset table says item 0 starts at 8, item 1 at 4 (before
        // item 0), which is not monotonically increasing.
        let bytes = vec![8, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0];
        let list_err = VarList::from_ssz_bytes(&bytes).unwrap_err();
        let ssz_err = VarModel::from_ssz_bytes(&bytes).unwrap_err();
        assert_eq!(list_err, ssz_err);
    }

    #[test]
    fn decoding_an_offset_past_the_end_is_rejected_like_ssz_list() {
        let bytes = vec![8, 0, 0, 0]; // claims an item starts at byte 8 of a 4-byte input.
        let list_err = VarList::from_ssz_bytes(&bytes).unwrap_err();
        let ssz_err = VarModel::from_ssz_bytes(&bytes).unwrap_err();
        assert_eq!(list_err, ssz_err);
    }

    #[test]
    fn rebasing_a_rebuilt_list_shares_the_base_and_keeps_its_writes() {
        let values: Vec<u64> = (0..1000).collect();
        let base = Balances::try_from(values.clone()).unwrap();
        root(&base);

        let mut rebuilt = Balances::try_from(values.clone()).unwrap();
        assert!(!rebuilt.ptr_eq(&base));
        rebuilt.rebase_on(&base);
        assert!(rebuilt.ptr_eq(&base));

        // Pending writes are applied first, so they survive the rebase.
        rebuilt[7] = 70_000;
        rebuilt.rebase_on(&base);
        assert!(!rebuilt.has_pending_updates());
        assert_eq!(rebuilt[7], 70_000);
        let mut expected = values;
        expected[7] = 70_000;
        assert_eq!(root(&rebuilt), root(&model::<u64, 1024>(&expected)));
    }
}
