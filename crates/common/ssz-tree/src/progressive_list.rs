//! [`ProgressiveList`]: an SSZ `ProgressiveList[T]` (EIP-7916) kept in
//! persistent Merkle trees.

use std::fmt;
use std::iter::FusedIterator;
use std::ops::{Index, IndexMut};

use libssz::{BYTES_PER_LENGTH_OFFSET, DecodeError, SszDecode, SszEncode};
use libssz_merkle::{HashTreeRoot, Sha2Hasher, Sha256Hasher, hash_nodes, mix_in_length};
use libssz_types::TypeError;

use crate::cursor::{ElemCow, IterCow};
use crate::interface::Interface;
use crate::iter::Iter;
use crate::update_map::{UpdateMap, VecMap};
use crate::{Hash256, Value, packing_factor};

/// An SSZ progressive list: no length limit, merkleized as a chain of
/// balanced subtrees holding 1, 4, 16, ... chunks (EIP-7916).
///
/// Stands in for `libssz_types::ProgressiveList<T>` in a derived container the
/// way [`List`](crate::List) stands in for `SszList`: same encoding, same
/// root, same element API, and a mirror of `List`'s method set (including
/// `push -> Result`, which never fails here) so code written against one
/// reads the same against the other.
///
/// Subtree `k` is a tree of height `2k`, so every write, cache and rebase
/// rule `List` has holds per subtree. The chain above them, one hash per
/// subtree, is recomputed on every root.
#[derive(Clone)]
pub struct ProgressiveList<T, U = VecMap<T>> {
    /// Subtree `k` holds the next `capacity(k)` elements. Every subtree but
    /// the last is full, and none is empty.
    subtrees: Vec<Interface<T, U>>,
}

impl<T: Value, U: UpdateMap<T>> ProgressiveList<T, U> {
    /// Elements subtree `k` holds when full: `4^k` chunks.
    fn capacity(k: usize) -> usize {
        packing_factor::<T>() << (2 * k)
    }

    /// Height of subtree `k`, which has `4^k` leaves.
    fn height(k: usize) -> usize {
        2 * k
    }

    /// Streams `values` into subtrees, filling each before opening the next.
    fn from_values(values: impl IntoIterator<Item = T>) -> Self {
        let mut values = values.into_iter().peekable();
        let mut subtrees = Vec::new();
        while values.peek().is_some() {
            let k = subtrees.len();
            let chunk = values.by_ref().take(Self::capacity(k));
            subtrees.push(Interface::from_values(chunk, Self::height(k)));
        }
        Self { subtrees }
    }

    /// The subtree holding element `index`, and the index within it.
    fn locate(&self, mut index: usize) -> Option<(usize, usize)> {
        for (k, subtree) in self.subtrees.iter().enumerate() {
            if index < subtree.len() {
                return Some((k, index));
            }
            index -= subtree.len();
        }
        None
    }

    /// An empty list.
    pub fn empty() -> Self {
        Self {
            subtrees: Vec::new(),
        }
    }

    /// The number of elements, pending pushes included.
    pub fn len(&self) -> usize {
        self.subtrees.iter().map(Interface::len).sum()
    }

    /// Whether the list holds no elements.
    pub fn is_empty(&self) -> bool {
        self.subtrees.is_empty()
    }

    /// The element at `index`, or `None` past the end.
    pub fn get(&self, index: usize) -> Option<&T> {
        let (k, offset) = self.locate(index)?;
        self.subtrees[k].get(offset)
    }

    /// A pending copy of the element at `index`, or `None` past the end.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        let (k, offset) = self.locate(index)?;
        self.subtrees[k].get_mut(offset)
    }

    /// Buffers `value` as the new last element.
    ///
    /// Returns a `Result` only to mirror [`List::push`](crate::List::push);
    /// a progressive list has no limit, so this never fails.
    pub fn push(&mut self, value: T) -> Result<(), TypeError> {
        let k = self.subtrees.len();
        match self.subtrees.last_mut() {
            Some(last) if last.len() < Self::capacity(k - 1) => last.push(value),
            _ => {
                let mut subtree = Interface::from_values(std::iter::empty(), Self::height(k));
                subtree.push(value);
                self.subtrees.push(subtree);
            }
        }
        Ok(())
    }

    /// Every element, in order, pending writes included.
    pub fn iter(&self) -> ProgressiveIter<'_, T, U> {
        self.iter_from(0)
    }

    /// The elements from `start` on.
    pub fn iter_from(&self, start: usize) -> ProgressiveIter<'_, T, U> {
        let len = self.len();
        let start = start.min(len);
        let (k, offset) = self.locate(start).unwrap_or((self.subtrees.len(), 0));
        let mut subtrees = self.subtrees[k..].iter();
        let current = subtrees.next().map(|subtree| subtree.iter_from(offset));
        ProgressiveIter {
            subtrees,
            current,
            remaining: len - start,
        }
    }

    /// An in-order pass that can rewrite any element, subtree after subtree.
    /// See [`List::iter_cow`](crate::List::iter_cow): pending writes are
    /// applied first, and each subtree's changed leaves reach it when the
    /// pass leaves that subtree or is dropped.
    pub fn iter_cow(&mut self) -> ProgressiveIterCow<'_, T, U> {
        self.apply_updates();
        ProgressiveIterCow {
            subtrees: self.subtrees.iter_mut(),
            current: None,
            base: 0,
        }
    }

    /// Runs `f` on every element in order, stopping at the first error and
    /// keeping the writes made before it.
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

    /// The elements, copied out.
    pub fn to_vec(&self) -> Vec<T> {
        self.iter().cloned().collect()
    }

    /// Folds every pending write into the trees.
    pub fn apply_updates(&mut self) {
        self.subtrees.iter_mut().for_each(Interface::apply_updates);
    }

    /// Whether any write is still buffered.
    pub fn has_pending_updates(&self) -> bool {
        self.subtrees.iter().any(Interface::has_pending_updates)
    }

    /// Applies pending writes, then shares every subtree equal to `base`'s.
    ///
    /// Subtree `k` of both lists has the same shape, so they rebase
    /// pairwise; subtrees past `base`'s last have nothing to share.
    pub fn rebase_on(&mut self, base: &Self) {
        self.apply_updates();
        for (own, base) in self.subtrees.iter_mut().zip(&base.subtrees) {
            own.rebase_on(base);
        }
    }

    /// Whether every committed subtree is the same allocation as `other`'s.
    pub fn ptr_eq(&self, other: &Self) -> bool {
        self.subtrees.len() == other.subtrees.len()
            && self
                .subtrees
                .iter()
                .zip(&other.subtrees)
                .all(|(a, b)| a.ptr_eq(b))
    }

    /// The chain root, before the length mix-in: `hash(sub_0, hash(sub_1,
    /// ... hash(sub_last, 0)))`.
    fn chain_root(&self) -> Hash256 {
        self.subtrees.iter().rev().fold([0u8; 32], |rest, subtree| {
            hash_nodes(&Sha2Hasher, &subtree.root(), &rest)
        })
    }
}

/// An in-order rewriting pass over a [`ProgressiveList`], made by
/// [`ProgressiveList::iter_cow`]: one [`IterCow`] per subtree, in turn.
pub struct ProgressiveIterCow<'a, T: Value, U> {
    subtrees: std::slice::IterMut<'a, Interface<T, U>>,
    current: Option<IterCow<'a, T>>,
    /// Elements in the subtrees already started.
    base: usize,
}

impl<T: Value, U: UpdateMap<T>> ProgressiveIterCow<'_, T, U> {
    /// The next element, to read or to write, or `None` after the last.
    pub fn next_cow(&mut self) -> Option<ElemCow<'_, T>> {
        loop {
            if self.current.as_mut().is_some_and(IterCow::advance) {
                return self.current.as_mut().map(IterCow::take);
            }
            // Dropping the spent pass swaps its changed leaves into its subtree.
            self.current = None;
            let subtree = self.subtrees.next()?;
            let len = subtree.len();
            self.current = Some(subtree.iter_cow().with_base(self.base));
            self.base += len;
        }
    }
}

impl<T: Value, U: UpdateMap<T>> Default for ProgressiveList<T, U> {
    fn default() -> Self {
        Self::empty()
    }
}

impl<T: Value, U: UpdateMap<T>> From<Vec<T>> for ProgressiveList<T, U> {
    fn from(values: Vec<T>) -> Self {
        Self::from_values(values)
    }
}

impl<T: Value, U: UpdateMap<T>> Index<usize> for ProgressiveList<T, U> {
    type Output = T;
    fn index(&self, index: usize) -> &T {
        // `len` sums over every subtree, unlike `List`'s O(1) field read, so
        // it is computed only on the panic path, not on every access.
        self.get(index).unwrap_or_else(|| {
            panic!(
                "index {index} out of bounds for a list of length {}",
                self.len()
            )
        })
    }
}

impl<T: Value, U: UpdateMap<T>> IndexMut<usize> for ProgressiveList<T, U> {
    fn index_mut(&mut self, index: usize) -> &mut T {
        // Locate once and index the subtree directly, rather than through
        // `get`/`get_mut` (each of which re-locates on its own): `len`,
        // needed only for the panic message, still costs nothing on the
        // common, in-bounds path.
        let Some((k, offset)) = self.locate(index) else {
            panic!(
                "index {index} out of bounds for a list of length {}",
                self.len()
            );
        };
        self.subtrees[k]
            .get_mut(offset)
            .expect("locate returned an in-bounds offset")
    }
}

impl<T: Value, U: UpdateMap<T>> PartialEq for ProgressiveList<T, U> {
    fn eq(&self, other: &Self) -> bool {
        if self.len() != other.len() {
            return false;
        }
        let nothing_pending = !self.has_pending_updates() && !other.has_pending_updates();
        (nothing_pending && self.ptr_eq(other)) || self.iter().eq(other.iter())
    }
}

impl<T: Value + Eq, U: UpdateMap<T>> Eq for ProgressiveList<T, U> {}

impl<T: Value + fmt::Debug, U: UpdateMap<T>> fmt::Debug for ProgressiveList<T, U> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl<'a, T: Value, U: UpdateMap<T>> IntoIterator for &'a ProgressiveList<T, U> {
    type Item = &'a T;
    type IntoIter = ProgressiveIter<'a, T, U>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<T: Value, U: UpdateMap<T>> SszEncode for ProgressiveList<T, U> {
    fn is_fixed_size() -> bool {
        false
    }

    fn fixed_size() -> usize {
        0
    }

    fn encoded_len(&self) -> usize {
        self.subtrees.iter().map(Interface::encoded_len).sum()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        if <T as SszEncode>::is_fixed_size() {
            for subtree in &self.subtrees {
                subtree.ssz_append(buf);
            }
            return;
        }
        // Offsets are relative to the start of the whole list, so the
        // offset table cannot be written subtree by subtree.
        let len = self.len();
        let start = buf.len();
        buf.resize(start + len * BYTES_PER_LENGTH_OFFSET, 0);
        for (index, value) in self.iter().enumerate() {
            let offset = (buf.len() - start) as u32;
            let position = start + index * BYTES_PER_LENGTH_OFFSET;
            buf[position..position + BYTES_PER_LENGTH_OFFSET]
                .copy_from_slice(&offset.to_le_bytes());
            value.ssz_append(buf);
        }
    }
}

impl<T: Value, U: UpdateMap<T>> SszDecode for ProgressiveList<T, U> {
    fn is_fixed_size() -> bool {
        false
    }

    fn fixed_size() -> usize {
        0
    }

    /// Matches `libssz_types::ProgressiveList`, which decodes as a plain
    /// `Vec<T>` with no length limit. Fixed-size elements stream straight
    /// into the subtrees, as `Interface::from_ssz_bytes` does.
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.is_empty() {
            return Ok(Self::empty());
        }
        if !<T as SszDecode>::is_fixed_size() {
            let values = libssz::decode_list_with_max::<T>(bytes, usize::MAX)?;
            return Ok(Self::from_values(values));
        }
        let size = <T as SszDecode>::fixed_size();
        if size == 0 || !bytes.len().is_multiple_of(size) {
            return Err(DecodeError::InvalidByteLength {
                expected: size,
                got: bytes.len(),
            });
        }
        let mut error = None;
        // `.fuse()` matters here: `map_while` alone is not a fused iterator,
        // so once its closure returns `None` for a bad chunk, the
        // `Peekable` in `from_values` would call it again on the *next*
        // chunk rather than stopping, silently skipping the bad one and
        // letting `error` end up holding the last failure instead of the
        // first.
        let values = bytes
            .chunks_exact(size)
            .map_while(|chunk| {
                T::from_ssz_bytes(chunk)
                    .map_err(|err| error = Some(err))
                    .ok()
            })
            .fuse();
        let list = Self::from_values(values);
        match error {
            Some(err) => Err(err),
            None => Ok(list),
        }
    }
}

impl<T: Value, U: UpdateMap<T>> HashTreeRoot for ProgressiveList<T, U> {
    /// Ignores `hasher` and uses SHA-256: see the crate docs.
    fn hash_tree_root(&self, _hasher: &impl Sha256Hasher) -> Hash256 {
        mix_in_length(&Sha2Hasher, &self.chain_root(), self.len())
    }
}

/// An iterator over a [`ProgressiveList`], pending writes included.
pub struct ProgressiveIter<'a, T, U> {
    subtrees: std::slice::Iter<'a, Interface<T, U>>,
    current: Option<Iter<'a, T, U>>,
    remaining: usize,
}

impl<'a, T: Value, U: UpdateMap<T>> Iterator for ProgressiveIter<'a, T, U> {
    type Item = &'a T;

    fn next(&mut self) -> Option<&'a T> {
        loop {
            if let Some(value) = self.current.as_mut().and_then(Iterator::next) {
                self.remaining -= 1;
                return Some(value);
            }
            self.current = Some(self.subtrees.next()?.iter_from(0));
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<T: Value, U: UpdateMap<T>> ExactSizeIterator for ProgressiveIter<'_, T, U> {}

impl<T: Value, U: UpdateMap<T>> FusedIterator for ProgressiveIter<'_, T, U> {}
