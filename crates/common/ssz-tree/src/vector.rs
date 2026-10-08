//! [`Vector`]: an SSZ `Vector[T, N]` kept in a persistent Merkle tree.

use std::fmt;
use std::ops::{Index, IndexMut};

use libssz::{DecodeError, SszDecode, SszEncode};
use libssz_merkle::{HashTreeRoot, Sha256Hasher};
use libssz_types::TypeError;

use crate::interface::Interface;
use crate::iter::Iter;
use crate::update_map::{UpdateMap, VecMap};
use crate::{Hash256, Value, tree_depth};

/// An SSZ vector of exactly `N` elements, kept in a persistent Merkle tree.
///
/// The fixed-length counterpart of [`List`](crate::List): the same tree,
/// buffered writes and O(1) clone, with no `push` and no length mix-in in the
/// root. Stands in for `libssz_types::SszVector<T, N>` in a derived container.
#[derive(Clone)]
pub struct Vector<T, const N: usize, U = VecMap<T>> {
    interface: Interface<T, U>,
}

impl<T: Value, const N: usize, U: UpdateMap<T>> Vector<T, N, U> {
    fn depth() -> usize {
        tree_depth::<T>(N)
    }

    /// The number of elements: always `N`.
    pub fn len(&self) -> usize {
        N
    }

    /// Whether `N` is zero.
    pub fn is_empty(&self) -> bool {
        N == 0
    }

    /// The element at `index`, or `None` past the end.
    pub fn get(&self, index: usize) -> Option<&T> {
        self.interface.get(index)
    }

    /// The element at `index`, to be written. The write is buffered until
    /// [`Vector::apply_updates`].
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        self.interface.get_mut(index)
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

    /// Makes this vector share every unchanged subtree with `base`, after
    /// applying its own pending writes. The contents do not change.
    pub fn rebase_on(&mut self, base: &Self) {
        self.interface.rebase_on(&base.interface);
    }

    /// Whether both vectors' committed trees are the same allocation: a cheap
    /// check of sharing, not of equality.
    pub fn ptr_eq(&self, other: &Self) -> bool {
        self.interface.ptr_eq(&other.interface)
    }
}

impl<T: Value + Default, const N: usize, U: UpdateMap<T>> Default for Vector<T, N, U> {
    /// A vector of `N` default-valued elements.
    fn default() -> Self {
        let values = std::iter::repeat_with(T::default).take(N);
        Self {
            interface: Interface::from_values(values, Self::depth()),
        }
    }
}

impl<T: Value, const N: usize, U: UpdateMap<T>> TryFrom<Vec<T>> for Vector<T, N, U> {
    type Error = TypeError;

    fn try_from(values: Vec<T>) -> Result<Self, TypeError> {
        if values.len() != N {
            return Err(TypeError::InvalidLength {
                expected: N,
                got: values.len(),
            });
        }
        Ok(Self {
            interface: Interface::from_values(values, Self::depth()),
        })
    }
}

impl<T: Value, const N: usize, U: UpdateMap<T>> Index<usize> for Vector<T, N, U> {
    type Output = T;

    fn index(&self, index: usize) -> &T {
        self.get(index)
            .unwrap_or_else(|| panic!("index {index} out of bounds for a vector of length {N}"))
    }
}

impl<T: Value, const N: usize, U: UpdateMap<T>> IndexMut<usize> for Vector<T, N, U> {
    fn index_mut(&mut self, index: usize) -> &mut T {
        self.get_mut(index)
            .unwrap_or_else(|| panic!("index {index} out of bounds for a vector of length {N}"))
    }
}

impl<T: Value, const N: usize, U: UpdateMap<T>> PartialEq for Vector<T, N, U> {
    fn eq(&self, other: &Self) -> bool {
        let nothing_pending = !self.has_pending_updates() && !other.has_pending_updates();
        (nothing_pending && self.ptr_eq(other)) || self.iter().eq(other.iter())
    }
}

impl<T: Value + Eq, const N: usize, U: UpdateMap<T>> Eq for Vector<T, N, U> {}

impl<T: Value + fmt::Debug, const N: usize, U: UpdateMap<T>> fmt::Debug for Vector<T, N, U> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl<'a, T: Value, const N: usize, U: UpdateMap<T>> IntoIterator for &'a Vector<T, N, U> {
    type Item = &'a T;
    type IntoIter = Iter<'a, T, U>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<T: Value, const N: usize, U: UpdateMap<T>> SszEncode for Vector<T, N, U> {
    fn is_fixed_size() -> bool {
        <T as SszEncode>::is_fixed_size()
    }

    fn fixed_size() -> usize {
        if <T as SszEncode>::is_fixed_size() {
            <T as SszEncode>::fixed_size() * N
        } else {
            0
        }
    }

    fn encoded_len(&self) -> usize {
        self.interface.encoded_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.interface.ssz_append(buf);
    }
}

impl<T: Value, const N: usize, U: UpdateMap<T>> SszDecode for Vector<T, N, U> {
    fn is_fixed_size() -> bool {
        <T as SszDecode>::is_fixed_size()
    }

    fn fixed_size() -> usize {
        if <T as SszDecode>::is_fixed_size() {
            <T as SszDecode>::fixed_size() * N
        } else {
            0
        }
    }

    /// Rejects what `SszVector` rejects, with the same error.
    ///
    /// `SszVector` decodes without a cap and checks the count afterwards,
    /// while the shared decoder caps at `N` like a list and would report too
    /// many fixed-size elements as `InvalidByteLength`. Checking the count of
    /// a fixed-size `T` first reports it as `InvalidFixedLength`, as
    /// `SszVector` does. A variable-size `T` accepts and rejects the same
    /// inputs, but too many elements may still get a different error.
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if <T as SszDecode>::is_fixed_size() {
            let size = <T as SszDecode>::fixed_size();
            if size != 0 && bytes.len().is_multiple_of(size) {
                let count = bytes.len() / size;
                if count != N {
                    return Err(DecodeError::InvalidFixedLength {
                        expected: N,
                        got: count,
                    });
                }
            }
        }
        let interface = Interface::from_ssz_bytes(bytes, N, Self::depth())?;
        if interface.len() != N {
            return Err(DecodeError::InvalidFixedLength {
                expected: N,
                got: interface.len(),
            });
        }
        Ok(Self { interface })
    }
}

impl<T: Value, const N: usize, U: UpdateMap<T>> HashTreeRoot for Vector<T, N, U> {
    /// Ignores `hasher` and uses SHA-256: see the crate docs.
    fn hash_tree_root(&self, _hasher: &impl Sha256Hasher) -> Hash256 {
        self.interface.root()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use libssz_derive::{HashTreeRoot, SszDecode, SszEncode};
    use libssz_merkle::Sha2Hasher;
    use libssz_types::SszVector;

    use super::*;

    /// A composite element with a `Default`, which `[u8; 48]` lacks.
    #[derive(Debug, Clone, Default, PartialEq, Eq, SszEncode, SszDecode, HashTreeRoot)]
    struct Pair {
        a: u64,
        b: u64,
    }

    fn root<V: HashTreeRoot>(vector: &V) -> Hash256 {
        HashTreeRoot::hash_tree_root(vector, &Sha2Hasher)
    }

    fn model<T: Value, const N: usize>(values: &[T]) -> SszVector<T, N> {
        values.to_vec().try_into().expect("exactly N values")
    }

    #[test]
    fn a_default_vector_hashes_like_an_all_default_ssz_vector() {
        assert_eq!(
            root(&Vector::<u64, 37>::default()),
            root(&model::<u64, 37>(&[0; 37]))
        );
        assert_eq!(
            root(&Vector::<Pair, 5, BTreeMap<usize, Pair>>::default()),
            root(&model::<Pair, 5>(&vec![Pair::default(); 5]))
        );
    }

    #[test]
    fn writes_hash_like_the_same_ssz_vector() {
        let mut values: Vec<u64> = (0..37).collect();
        let mut vector = Vector::<u64, 37>::try_from(values.clone()).unwrap();
        vector[36] = 1000;
        *vector.get_mut(0).unwrap() = 5;
        values[36] = 1000;
        values[0] = 5;
        assert_eq!(root(&vector), root(&model::<u64, 37>(&values)));
        vector.apply_updates();
        assert_eq!(vector.to_vec(), values);
        assert_eq!(root(&vector), root(&model::<u64, 37>(&values)));
    }

    #[test]
    fn a_vector_needs_exactly_n_values() {
        assert_eq!(
            Vector::<u64, 3>::try_from(vec![1, 2]),
            Err(TypeError::InvalidLength {
                expected: 3,
                got: 2
            })
        );
        assert!(Vector::<u64, 3>::try_from(vec![1, 2, 3]).is_ok());
    }

    #[test]
    fn a_vector_of_fixed_size_elements_is_fixed_size() {
        assert!(<Vector<u64, 3> as SszEncode>::is_fixed_size());
        assert_eq!(<Vector<u64, 3> as SszEncode>::fixed_size(), 24);
        assert!(<Vector<u64, 3> as SszDecode>::is_fixed_size());
        assert_eq!(<Vector<u64, 3> as SszDecode>::fixed_size(), 24);
    }

    #[test]
    fn ssz_bytes_match_ssz_vector_and_round_trip() {
        let values: Vec<u64> = (10..47).collect();
        let vector = Vector::<u64, 37>::try_from(values.clone()).unwrap();
        let bytes = vector.to_ssz();
        assert_eq!(bytes, model::<u64, 37>(&values).to_ssz());
        let decoded = Vector::<u64, 37>::from_ssz_bytes(&bytes).unwrap();
        assert_eq!(decoded, vector);
    }

    #[test]
    fn decoding_the_wrong_count_is_an_error() {
        assert!(Vector::<u64, 3>::from_ssz_bytes(&[0u8; 16]).is_err());
        assert!(Vector::<u64, 3>::from_ssz_bytes(&[0u8; 32]).is_err());
        assert!(Vector::<u64, 3>::from_ssz_bytes(&[0u8; 23]).is_err());
    }

    /// `Interface::from_ssz_bytes` treats empty input as an empty result (to
    /// match `libssz`'s list decoding), so a fixed-size `Vector` must reject
    /// it itself, through the same count check as any other wrong length.
    #[test]
    fn decoding_empty_bytes_is_rejected_like_ssz_vector() {
        let vector_err = Vector::<u64, 4>::from_ssz_bytes(&[]).unwrap_err();
        let ssz_err = SszVector::<u64, 4>::from_ssz_bytes(&[]).unwrap_err();
        assert_eq!(vector_err, ssz_err);
    }

    /// Minimized case from the `model.rs` decode-parity property: 7 zero
    /// `u64`s (56 bytes) into a `Vector<u64, 6>`. Before the pre-check in
    /// `from_ssz_bytes`, this came back as `InvalidByteLength` here (the
    /// shared decoder's own list-style cap) but `InvalidFixedLength` from
    /// `SszVector` (which decodes uncapped, then checks the count).
    #[test]
    fn decoding_too_many_fixed_size_elements_matches_ssz_vector() {
        let bytes = vec![0u8; 56];
        let vector_err = Vector::<u64, 6>::from_ssz_bytes(&bytes).unwrap_err();
        let ssz_err = SszVector::<u64, 6>::from_ssz_bytes(&bytes).unwrap_err();
        assert_eq!(vector_err, ssz_err);
        assert_eq!(
            vector_err,
            DecodeError::InvalidFixedLength {
                expected: 6,
                got: 7
            }
        );
    }

    /// Encoding, decoding and hashing agree with `SszVector` for both a
    /// packed element type (`u64`) and a composite one (`Pair`).
    #[test]
    fn ssz_bytes_and_root_match_ssz_vector_for_packed_and_composite_elements() {
        let packed_values: Vec<u64> = (0..37).collect();
        let packed = Vector::<u64, 37>::try_from(packed_values.clone()).unwrap();
        let packed_model = model::<u64, 37>(&packed_values);
        assert_eq!(packed.to_ssz(), packed_model.to_ssz());
        assert_eq!(root(&packed), root(&packed_model));
        assert_eq!(
            Vector::<u64, 37>::from_ssz_bytes(&packed.to_ssz()).unwrap(),
            packed
        );

        let composite_values: Vec<Pair> = (0..5).map(|i| Pair { a: i, b: i * 2 }).collect();
        let composite =
            Vector::<Pair, 5, BTreeMap<usize, Pair>>::try_from(composite_values.clone()).unwrap();
        let composite_model = model::<Pair, 5>(&composite_values);
        assert_eq!(composite.to_ssz(), composite_model.to_ssz());
        assert_eq!(root(&composite), root(&composite_model));
        assert_eq!(
            Vector::<Pair, 5, BTreeMap<usize, Pair>>::from_ssz_bytes(&composite.to_ssz()).unwrap(),
            composite
        );
    }
}
