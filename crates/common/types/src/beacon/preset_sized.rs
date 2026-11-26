//! SSZ lists, vectors and bitfields whose bound is a preset value.
//!
//! `libssz_types`' `SszList<T, N>`, `SszVector<T, N>`, `SszBitlist<N>` and
//! `SszBitvector<N>` take their bound as a const generic, fixed when the code
//! is compiled. The preset is chosen when the process starts
//! ([`Preset::active`](crate::beacon::preset::Preset::active)), so a container
//! bound by a value the two presets disagree on (`SYNC_COMMITTEE_SIZE`,
//! `MAX_COMMITTEES_PER_SLOT`, ...) needs a bound read at runtime instead.
//! These four types are that: the same storage, API, SSZ encoding and
//! `hash_tree_root` as their libssz counterparts, with `N` replaced by
//! `L::get()` for a [`Length`] marker such as
//! [`preset::SyncCommitteeSize`](crate::beacon::preset::SyncCommitteeSize).
//!
//! Bounds both presets agree on stay const generics on the libssz types, and
//! the large state vectors (`block_roots`, `randao_mixes`, ...) use the
//! persistent trees in `ethlambda_ssz_tree`, which take a [`Length`] as well.
//!
//! The merkleization below is libssz's (`ssz-types/src/hash_tree_root.rs`)
//! with that one substitution; the spec fixtures' `ssz_static` cases are what
//! check that the two agree, under both presets.

use core::marker::PhantomData;
use core::ops::{Deref, DerefMut, Index, IndexMut};

use libssz::{DecodeError, SszDecode, SszEncode, decode_list_with_max};
use libssz_merkle::{HashTreeRoot, Node, Sha256Hasher, merkleize, mix_in_length, pack, pack_bits};
use libssz_types::{IndexError, TypeError};
use smallvec::SmallVec;

use crate::beacon::preset::Length;

/// A bitfield's bytes, inline up to 512 bits like libssz's own bitfields, so
/// decoding or cloning an attestation's committee or aggregation bits does not
/// allocate.
type Bytes = SmallVec<[u8; 64]>;

/// `SszList<T, N>` with `N = L::get()`.
pub struct PresetList<T, L> {
    items: Vec<T>,
    length: PhantomData<fn() -> L>,
}

/// `SszVector<T, N>` with `N = L::get()`.
pub struct PresetVector<T, L> {
    items: Vec<T>,
    length: PhantomData<fn() -> L>,
}

/// `SszBitlist<N>` with `N = L::get()`.
pub struct PresetBitlist<L> {
    /// The data bits, LSB-first, without the delimiter.
    bytes: Bytes,
    len: usize,
    length: PhantomData<fn() -> L>,
}

/// `SszBitvector<N>` with `N = L::get()`.
pub struct PresetBitvector<L> {
    bytes: Bytes,
    length: PhantomData<fn() -> L>,
}

// ── The derivable traits, by hand ──
//
// A derive would bound each impl on `L` too, and `L` is a marker that is never
// instantiated, so these spell out the bounds on the element type alone.

macro_rules! by_hand {
    ($ty:ident < $($param:ident),* > { $($field:ident),* }) => {
        impl<$($param: Clone,)* L> Clone for $ty<$($param,)* L> {
            fn clone(&self) -> Self {
                Self { $($field: self.$field.clone(),)* length: PhantomData }
            }
        }

        impl<$($param: PartialEq,)* L> PartialEq for $ty<$($param,)* L> {
            fn eq(&self, other: &Self) -> bool {
                true $(&& self.$field == other.$field)*
            }
        }

        impl<$($param: Eq,)* L> Eq for $ty<$($param,)* L> {}

        impl<$($param: core::hash::Hash,)* L> core::hash::Hash for $ty<$($param,)* L> {
            fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
                $(self.$field.hash(state);)*
            }
        }
    };
}

by_hand!(PresetList<T> { items });
by_hand!(PresetVector<T> { items });
by_hand!(PresetBitlist<> { bytes, len });
by_hand!(PresetBitvector<> { bytes });

impl<T: core::fmt::Debug, L> core::fmt::Debug for PresetList<T, L> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("PresetList").field(&self.items).finish()
    }
}

impl<T: core::fmt::Debug, L> core::fmt::Debug for PresetVector<T, L> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("PresetVector").field(&self.items).finish()
    }
}

impl<L> core::fmt::Debug for PresetBitlist<L> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PresetBitlist")
            .field("bytes", &self.bytes)
            .field("len", &self.len)
            .finish()
    }
}

impl<L> core::fmt::Debug for PresetBitvector<L> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PresetBitvector")
            .field("bytes", &self.bytes)
            .finish()
    }
}

// ── Lists and vectors: element access ──

macro_rules! sequence_access {
    ($ty:ident) => {
        impl<T, L> Deref for $ty<T, L> {
            type Target = [T];

            fn deref(&self) -> &[T] {
                &self.items
            }
        }

        /// Mutable access to the elements, but not to the length: a `&mut [T]`
        /// cannot grow or shrink, so the bound still holds.
        impl<T, L> DerefMut for $ty<T, L> {
            fn deref_mut(&mut self) -> &mut [T] {
                &mut self.items
            }
        }

        impl<T, L, I: core::slice::SliceIndex<[T]>> Index<I> for $ty<T, L> {
            type Output = I::Output;

            fn index(&self, index: I) -> &Self::Output {
                &self.items[index]
            }
        }

        impl<T, L, I: core::slice::SliceIndex<[T]>> IndexMut<I> for $ty<T, L> {
            fn index_mut(&mut self, index: I) -> &mut Self::Output {
                &mut self.items[index]
            }
        }

        impl<T, L> IntoIterator for $ty<T, L> {
            type Item = T;
            type IntoIter = std::vec::IntoIter<T>;

            fn into_iter(self) -> Self::IntoIter {
                self.items.into_iter()
            }
        }

        impl<'a, T, L> IntoIterator for &'a $ty<T, L> {
            type Item = &'a T;
            type IntoIter = core::slice::Iter<'a, T>;

            fn into_iter(self) -> Self::IntoIter {
                self.items.iter()
            }
        }

        impl<'a, T, L> IntoIterator for &'a mut $ty<T, L> {
            type Item = &'a mut T;
            type IntoIter = core::slice::IterMut<'a, T>;

            fn into_iter(self) -> Self::IntoIter {
                self.items.iter_mut()
            }
        }
    };
}

sequence_access!(PresetList);
sequence_access!(PresetVector);

// ── PresetList ──

impl<T, L: Length> PresetList<T, L> {
    /// An empty list.
    pub fn new() -> Self {
        Self {
            items: Vec::new(),
            length: PhantomData,
        }
    }

    /// The maximum number of elements, `L::get()`.
    pub fn max_capacity(&self) -> usize {
        L::get()
    }

    /// The number of elements.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the list holds no elements.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Appends `value`, failing when the list is at its bound.
    pub fn push(&mut self, value: T) -> Result<(), TypeError> {
        if self.items.len() >= L::get() {
            return Err(TypeError::OverCapacity {
                max: L::get(),
                got: self.items.len() + 1,
            });
        }
        self.items.push(value);
        Ok(())
    }

    /// The elements, as a `Vec`.
    pub fn into_inner(self) -> Vec<T> {
        self.items
    }
}

impl<T, L: Length> Default for PresetList<T, L> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, L: Length> TryFrom<Vec<T>> for PresetList<T, L> {
    type Error = TypeError;

    fn try_from(items: Vec<T>) -> Result<Self, Self::Error> {
        if items.len() > L::get() {
            return Err(TypeError::OverCapacity {
                max: L::get(),
                got: items.len(),
            });
        }
        Ok(Self {
            items,
            length: PhantomData,
        })
    }
}

impl<T: SszEncode, L> SszEncode for PresetList<T, L> {
    fn is_fixed_size() -> bool {
        false
    }

    fn fixed_size() -> usize {
        0
    }

    fn encoded_len(&self) -> usize {
        self.items.encoded_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.items.ssz_append(buf);
    }
}

impl<T: SszDecode, L: Length> SszDecode for PresetList<T, L> {
    fn is_fixed_size() -> bool {
        false
    }

    fn fixed_size() -> usize {
        0
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode_list_with_max(bytes, L::get()).map(|items| Self {
            items,
            length: PhantomData,
        })
    }
}

impl<T: HashTreeRoot + SszEncode, L: Length> HashTreeRoot for PresetList<T, L> {
    fn hash_tree_root(&self, hasher: &impl Sha256Hasher) -> Node {
        let root = merkleize_elements(hasher, &self.items, L::get());
        mix_in_length(hasher, &root, self.items.len())
    }
}

// ── PresetVector ──

impl<T, L: Length> PresetVector<T, L> {
    /// The number of elements: always `L::get()`.
    pub fn len(&self) -> usize {
        L::get()
    }

    /// Whether the bound is zero.
    pub fn is_empty(&self) -> bool {
        L::get() == 0
    }

    /// The elements, as a `Vec`.
    pub fn into_inner(self) -> Vec<T> {
        self.items
    }
}

impl<T, L: Length> TryFrom<Vec<T>> for PresetVector<T, L> {
    type Error = TypeError;

    fn try_from(items: Vec<T>) -> Result<Self, Self::Error> {
        if items.len() != L::get() {
            return Err(TypeError::InvalidLength {
                expected: L::get(),
                got: items.len(),
            });
        }
        Ok(Self {
            items,
            length: PhantomData,
        })
    }
}

impl<T: SszEncode, L: Length> SszEncode for PresetVector<T, L> {
    fn is_fixed_size() -> bool {
        T::is_fixed_size()
    }

    fn fixed_size() -> usize {
        if T::is_fixed_size() {
            T::fixed_size() * L::get()
        } else {
            0
        }
    }

    fn encoded_len(&self) -> usize {
        self.items.encoded_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.items.ssz_append(buf);
    }
}

impl<T: SszDecode, L: Length> SszDecode for PresetVector<T, L> {
    fn is_fixed_size() -> bool {
        T::is_fixed_size()
    }

    fn fixed_size() -> usize {
        if T::is_fixed_size() {
            T::fixed_size() * L::get()
        } else {
            0
        }
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let items = Vec::<T>::from_ssz_bytes(bytes)?;
        if items.len() != L::get() {
            return Err(DecodeError::InvalidFixedLength {
                expected: L::get(),
                got: items.len(),
            });
        }
        Ok(Self {
            items,
            length: PhantomData,
        })
    }
}

impl<T: HashTreeRoot + SszEncode, L: Length> HashTreeRoot for PresetVector<T, L> {
    fn hash_tree_root(&self, hasher: &impl Sha256Hasher) -> Node {
        merkleize_elements(hasher, &self.items, L::get())
    }
}

/// The root of `items` padded to `limit` elements: packed chunks for a basic
/// element type, one root per element otherwise. A list mixes its length in
/// on top; a vector does not.
fn merkleize_elements<T: HashTreeRoot + SszEncode>(
    hasher: &impl Sha256Hasher,
    items: &[T],
    limit: usize,
) -> Node {
    if T::is_basic_type() {
        let mut serialized = Vec::new();
        for item in items {
            item.ssz_append(&mut serialized);
        }
        let chunks = pack(&serialized);
        let max_chunks = (limit * T::fixed_size()).div_ceil(32);
        merkleize(hasher, &chunks, Some(max_chunks))
    } else {
        let roots: Vec<Node> = items
            .iter()
            .map(|item| item.hash_tree_root(hasher))
            .collect();
        merkleize(hasher, &roots, Some(limit))
    }
}

// ── PresetBitlist ──

impl<L: Length> PresetBitlist<L> {
    /// An empty bitlist.
    pub fn new() -> Self {
        Self {
            bytes: Bytes::new(),
            len: 0,
            length: PhantomData,
        }
    }

    /// `len` zero bits, failing past the bound.
    pub fn with_length(len: usize) -> Result<Self, TypeError> {
        if len > L::get() {
            return Err(TypeError::OverCapacity {
                max: L::get(),
                got: len,
            });
        }
        Ok(Self {
            bytes: Bytes::from_elem(0, len.div_ceil(8)),
            len,
            length: PhantomData,
        })
    }

    /// The maximum number of bits, `L::get()`.
    pub fn max_capacity(&self) -> usize {
        L::get()
    }

    /// The number of bits.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the bitlist has no bits.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The bit at `index` (LSB-first), or `None` past the end.
    pub fn get(&self, index: usize) -> Option<bool> {
        if index >= self.len {
            return None;
        }
        Some((self.bytes[index / 8] >> (index % 8)) & 1 == 1)
    }

    /// Sets the bit at `index`, returning its previous value.
    pub fn set(&mut self, index: usize, value: bool) -> Result<bool, IndexError> {
        if index >= self.len {
            return Err(IndexError {
                index,
                len: self.len,
            });
        }
        Ok(set_bit(&mut self.bytes, index, value))
    }

    /// The data bytes, without the delimiter bit.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The number of set bits.
    pub fn count_ones(&self) -> usize {
        count_ones(&self.bytes)
    }

    /// Appends a bit, failing at the bound.
    pub fn push(&mut self, value: bool) -> Result<(), TypeError> {
        if self.len >= L::get() {
            return Err(TypeError::OverCapacity {
                max: L::get(),
                got: self.len + 1,
            });
        }
        if self.len / 8 >= self.bytes.len() {
            self.bytes.push(0);
        }
        if value {
            self.bytes[self.len / 8] |= 1 << (self.len % 8);
        }
        self.len += 1;
        Ok(())
    }
}

impl<L: Length> Default for PresetBitlist<L> {
    fn default() -> Self {
        Self::new()
    }
}

impl<L: Length> TryFrom<Vec<bool>> for PresetBitlist<L> {
    type Error = TypeError;

    fn try_from(bits: Vec<bool>) -> Result<Self, Self::Error> {
        let mut bitlist = Self::with_length(bits.len())?;
        for (index, bit) in bits.into_iter().enumerate() {
            set_bit(&mut bitlist.bytes, index, bit);
        }
        Ok(bitlist)
    }
}

impl<L> SszEncode for PresetBitlist<L> {
    fn is_fixed_size() -> bool {
        false
    }

    fn fixed_size() -> usize {
        0
    }

    fn encoded_len(&self) -> usize {
        // The data bits plus the delimiter bit.
        (self.len + 1).div_ceil(8)
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let start = buf.len();
        buf.extend_from_slice(&self.bytes);
        buf.resize(start + self.encoded_len(), 0);
        buf[start + self.len / 8] |= 1 << (self.len % 8);
    }
}

impl<L: Length> SszDecode for PresetBitlist<L> {
    fn is_fixed_size() -> bool {
        false
    }

    fn fixed_size() -> usize {
        0
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let Some(&last) = bytes.last() else {
            return Err(DecodeError::MissingDelimiterBit);
        };
        if last == 0 {
            return Err(DecodeError::MissingDelimiterBit);
        }
        // The delimiter is the highest set bit of the last byte, so nothing
        // above it can be set: no excess-bits check is needed.
        let highest_bit = 7 - last.leading_zeros() as usize;
        let bit_len = (bytes.len() - 1) * 8 + highest_bit;
        if bit_len > L::get() {
            return Err(DecodeError::InvalidByteLength {
                expected: L::get(),
                got: bit_len,
            });
        }
        let mut data = Bytes::from_slice(bytes);
        data[bytes.len() - 1] &= !(1 << highest_bit);
        data.truncate(bit_len.div_ceil(8));
        Ok(Self {
            bytes: data,
            len: bit_len,
            length: PhantomData,
        })
    }
}

impl<L: Length> HashTreeRoot for PresetBitlist<L> {
    fn hash_tree_root(&self, hasher: &impl Sha256Hasher) -> Node {
        let chunks = pack_bits(&self.bytes, self.len);
        let root = merkleize(hasher, &chunks, Some(L::get().div_ceil(256)));
        mix_in_length(hasher, &root, self.len)
    }
}

// ── PresetBitvector ──

impl<L: Length> PresetBitvector<L> {
    fn byte_len() -> usize {
        L::get().div_ceil(8)
    }

    /// `L::get()` zero bits.
    pub fn new() -> Self {
        Self {
            bytes: Bytes::from_elem(0, Self::byte_len()),
            length: PhantomData,
        }
    }

    /// The number of bits: always `L::get()`.
    pub fn len(&self) -> usize {
        L::get()
    }

    /// Whether the bound is zero.
    pub fn is_empty(&self) -> bool {
        L::get() == 0
    }

    /// The bit at `index` (LSB-first), or `None` past the end.
    pub fn get(&self, index: usize) -> Option<bool> {
        if index >= L::get() {
            return None;
        }
        Some((self.bytes[index / 8] >> (index % 8)) & 1 == 1)
    }

    /// Sets the bit at `index`, returning its previous value.
    pub fn set(&mut self, index: usize, value: bool) -> Result<bool, IndexError> {
        if index >= L::get() {
            return Err(IndexError {
                index,
                len: L::get(),
            });
        }
        Ok(set_bit(&mut self.bytes, index, value))
    }

    /// The encoded bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The number of set bits.
    pub fn count_ones(&self) -> usize {
        count_ones(&self.bytes)
    }
}

impl<L: Length> Default for PresetBitvector<L> {
    fn default() -> Self {
        Self::new()
    }
}

impl<L: Length> SszEncode for PresetBitvector<L> {
    fn is_fixed_size() -> bool {
        true
    }

    fn fixed_size() -> usize {
        Self::byte_len()
    }

    fn encoded_len(&self) -> usize {
        Self::byte_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.bytes);
    }
}

impl<L: Length> SszDecode for PresetBitvector<L> {
    fn is_fixed_size() -> bool {
        true
    }

    fn fixed_size() -> usize {
        Self::byte_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != Self::byte_len() {
            return Err(DecodeError::InvalidFixedLength {
                expected: Self::byte_len(),
                got: bytes.len(),
            });
        }
        let excess = L::get() % 8;
        if excess != 0 && bytes[bytes.len() - 1] & !((1u8 << excess) - 1) != 0 {
            return Err(DecodeError::ExcessBitsNotZero);
        }
        Ok(Self {
            bytes: Bytes::from_slice(bytes),
            length: PhantomData,
        })
    }
}

impl<L: Length> HashTreeRoot for PresetBitvector<L> {
    fn hash_tree_root(&self, hasher: &impl Sha256Hasher) -> Node {
        let chunks = pack_bits(&self.bytes, L::get());
        merkleize(hasher, &chunks, Some(L::get().div_ceil(256)))
    }
}

fn set_bit(bytes: &mut [u8], index: usize, value: bool) -> bool {
    let mask = 1 << (index % 8);
    let byte = &mut bytes[index / 8];
    let previous = *byte & mask != 0;
    if value {
        *byte |= mask;
    } else {
        *byte &= !mask;
    }
    previous
}

fn count_ones(bytes: &[u8]) -> usize {
    bytes.iter().map(|byte| byte.count_ones() as usize).sum()
}

#[cfg(test)]
mod tests {
    use libssz_merkle::Sha2Hasher;
    use libssz_types::{SszBitlist, SszBitvector, SszList, SszVector};

    use super::*;
    use crate::beacon::preset::Const;

    fn root(value: &impl HashTreeRoot) -> Node {
        value.hash_tree_root(&Sha2Hasher)
    }

    /// Each type against its libssz counterpart at the same bound: the same
    /// bytes, the same root, and the same decode, for a packed and a
    /// composite element type and a bound that is not a power of two.
    #[test]
    fn every_type_matches_its_libssz_counterpart() {
        let values: Vec<u64> = (0..37).map(|i| i * 3 + 1).collect();
        let list = PresetList::<u64, Const<100>>::try_from(values.clone()).unwrap();
        let model = SszList::<u64, 100>::try_from(values.clone()).unwrap();
        assert_eq!(list.to_ssz(), model.to_ssz());
        assert_eq!(root(&list), root(&model));
        assert_eq!(
            PresetList::<u64, Const<100>>::from_ssz_bytes(&model.to_ssz()).unwrap(),
            list
        );

        let nested: Vec<SszList<u8, 10>> = (0..5u8)
            .map(|i| vec![i; i as usize].try_into().unwrap())
            .collect();
        let vector = PresetVector::<SszList<u8, 10>, Const<5>>::try_from(nested.clone()).unwrap();
        let model = SszVector::<SszList<u8, 10>, 5>::try_from(nested).unwrap();
        assert_eq!(vector.to_ssz(), model.to_ssz());
        assert_eq!(root(&vector), root(&model));
        assert_eq!(
            PresetVector::<SszList<u8, 10>, Const<5>>::from_ssz_bytes(&model.to_ssz()).unwrap(),
            vector
        );

        for len in [0usize, 1, 7, 8, 9, 300] {
            let bits: Vec<bool> = (0..len).map(|i| i % 3 == 0).collect();
            let bitlist = PresetBitlist::<Const<2048>>::try_from(bits.clone()).unwrap();
            let model = SszBitlist::<2048>::try_from(bits).unwrap();
            assert_eq!(bitlist.to_ssz(), model.to_ssz(), "length {len}");
            assert_eq!(root(&bitlist), root(&model), "length {len}");
            assert_eq!(
                PresetBitlist::<Const<2048>>::from_ssz_bytes(&model.to_ssz()).unwrap(),
                bitlist
            );
        }

        let mut bitvector = PresetBitvector::<Const<12>>::new();
        let mut model = SszBitvector::<12>::new();
        for index in [0, 5, 11] {
            bitvector.set(index, true).unwrap();
            model.set(index, true).unwrap();
        }
        assert_eq!(bitvector.to_ssz(), model.to_ssz());
        assert_eq!(root(&bitvector), root(&model));
        assert_eq!(
            PresetBitvector::<Const<12>>::from_ssz_bytes(&model.to_ssz()).unwrap(),
            bitvector
        );
        assert_eq!(
            PresetBitvector::<Const<12>>::from_ssz_bytes(&[0, 0x10]),
            Err(DecodeError::ExcessBitsNotZero)
        );
    }

    #[test]
    fn bounds_are_enforced() {
        assert!(PresetList::<u64, Const<2>>::try_from(vec![1, 2, 3]).is_err());
        assert!(PresetVector::<u64, Const<2>>::try_from(vec![1]).is_err());
        assert!(PresetBitlist::<Const<4>>::with_length(5).is_err());
        let mut list = PresetList::<u64, Const<1>>::new();
        list.push(1).unwrap();
        assert!(list.push(2).is_err());
        assert!(PresetVector::<u64, Const<2>>::from_ssz_bytes(&[0; 24]).is_err());
        assert!(PresetBitlist::<Const<4>>::from_ssz_bytes(&[0b0010_0000]).is_err());
    }
}
