//! The tree-plus-pending-writes core that [`List`](crate::List) and
//! [`Vector`](crate::Vector) share, including their SSZ codec.

use std::sync::Arc;

use libssz::{BYTES_PER_LENGTH_OFFSET, DecodeError, SszDecode, SszEncode};

use crate::cursor::IterCow;
use crate::iter::{Iter, TreeIter};
use crate::tree::Tree;
use crate::update_map::UpdateMap;
use crate::{Hash256, Value};

/// A committed tree plus the writes not yet folded into it.
#[derive(Clone)]
pub(crate) struct Interface<T, U> {
    tree: Arc<Tree<T>>,
    depth: usize,
    /// Elements in `tree`.
    committed_len: usize,
    /// Elements including pending pushes, which sit in `updates` at
    /// `committed_len..len`.
    len: usize,
    updates: U,
}

impl<T: Value, U: UpdateMap<T>> Interface<T, U> {
    /// `values` in a new tree of height `depth`, with nothing pending. The
    /// caller checks the type's limit.
    pub(crate) fn from_values(values: impl IntoIterator<Item = T>, depth: usize) -> Self {
        let (tree, len) = Tree::from_values(values, depth);
        Self {
            tree,
            depth,
            committed_len: len,
            len,
            updates: U::default(),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn get(&self, index: usize) -> Option<&T> {
        if index >= self.len {
            return None;
        }
        self.updates
            .get(index)
            .or_else(|| self.tree.get(index, self.depth))
    }

    /// A pending copy of the element at `index`, made on first access.
    pub(crate) fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        if index >= self.len {
            return None;
        }
        if self.updates.get(index).is_none() {
            // Pending pushes are always in `updates`, so this is a committed
            // element.
            let value = self
                .tree
                .get(index, self.depth)
                .expect("an index below the committed length is in the tree")
                .clone();
            self.updates.insert(index, value);
        }
        self.updates.get_mut(index)
    }

    /// Buffers `value` as the new last element. The caller checks the limit.
    pub(crate) fn push(&mut self, value: T) {
        self.updates.insert(self.len, value);
        self.len += 1;
    }

    pub(crate) fn has_pending_updates(&self) -> bool {
        !self.updates.is_empty()
    }

    /// Folds every pending write into the tree, in one pass.
    ///
    /// Cannot fail: every pending index was bounds-checked when it was
    /// written.
    pub(crate) fn apply_updates(&mut self) {
        if self.updates.is_empty() {
            return;
        }
        let updates = std::mem::take(&mut self.updates).into_sorted_vec();
        let mut updates = updates.into_iter().peekable();
        self.tree = Tree::with_updated_leaves(&self.tree, self.depth, 0, &mut updates);
        debug_assert!(updates.next().is_none(), "every pending write is in range");
        self.committed_len = self.len;
    }

    /// Applies pending writes, then starts an in-order pass whose writes reach
    /// the tree when it is dropped, bypassing the pending-write map.
    ///
    /// Applying first keeps the pass simple: it reads the tree alone, so a
    /// write made earlier is never hidden by (or lost to) the pass.
    pub(crate) fn iter_cow(&mut self) -> IterCow<'_, T> {
        self.apply_updates();
        IterCow::new(&mut self.tree, self.depth)
    }

    pub(crate) fn iter_from(&self, start: usize) -> Iter<'_, T, U> {
        let start = start.min(self.len);
        Iter {
            tree: TreeIter::new(&self.tree, self.depth, start),
            updates: &self.updates,
            no_updates: self.updates.is_empty(),
            index: start,
            committed_len: self.committed_len,
            end: self.len,
        }
    }

    /// The data root (before any length mix-in), pending writes included.
    ///
    /// With writes pending, the root is computed on a copy with them applied,
    /// so it is right but the hashes computed for the new paths are thrown
    /// away. Subtrees the copy shares with `self` do keep what is computed for
    /// them.
    pub(crate) fn root(&self) -> Hash256 {
        if !self.has_pending_updates() {
            return self.tree.hash(self.depth);
        }
        let mut applied = self.clone();
        applied.apply_updates();
        applied.tree.hash(applied.depth)
    }

    /// Whether both committed trees are the same allocation: a cheap check of
    /// sharing, not of equality.
    pub(crate) fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.tree, &other.tree)
    }

    /// Applies pending writes, then swaps every subtree equal to `base`'s at
    /// the same position for `base`'s own. `base`'s pending writes are
    /// ignored: its committed tree is still a valid base.
    pub(crate) fn rebase_on(&mut self, base: &Self) {
        self.apply_updates();
        let shared_prefix = self.committed_len.min(base.committed_len);
        self.tree = Tree::rebase_on(&self.tree, &base.tree, self.depth, 0, shared_prefix);
    }

    /// The SSZ length of the elements, as a list or vector body.
    pub(crate) fn encoded_len(&self) -> usize {
        if <T as SszEncode>::is_fixed_size() {
            return <T as SszEncode>::fixed_size() * self.len;
        }
        self.iter_from(0)
            .map(|value| BYTES_PER_LENGTH_OFFSET + value.encoded_len())
            .sum()
    }

    /// Appends the elements' SSZ encoding: back to back for fixed-size
    /// elements, or an offset table followed by the bodies, as `SszList`
    /// writes it.
    pub(crate) fn ssz_append(&self, buf: &mut Vec<u8>) {
        if <T as SszEncode>::is_fixed_size() {
            buf.reserve(<T as SszEncode>::fixed_size() * self.len);
            for value in self.iter_from(0) {
                value.ssz_append(buf);
            }
            return;
        }
        let start = buf.len();
        buf.resize(start + self.len * BYTES_PER_LENGTH_OFFSET, 0);
        for (index, value) in self.iter_from(0).enumerate() {
            let offset = (buf.len() - start) as u32;
            let position = start + index * BYTES_PER_LENGTH_OFFSET;
            buf[position..position + BYTES_PER_LENGTH_OFFSET]
                .copy_from_slice(&offset.to_le_bytes());
            value.ssz_append(buf);
        }
    }

    /// Decodes at most `max_len` elements from `bytes` into a tree of height
    /// `depth`.
    ///
    /// Fixed-size elements are decoded straight into the tree, so decoding
    /// never holds a `Vec` of every element next to the tree built from it.
    pub(crate) fn from_ssz_bytes(
        bytes: &[u8],
        max_len: usize,
        depth: usize,
    ) -> Result<Self, DecodeError> {
        // Matches `libssz::decode_list_with_max`: an empty input is an empty
        // list regardless of the element type, checked before any fixed-size
        // arithmetic (which would divide by a zero-sized element).
        if bytes.is_empty() {
            return Ok(Self::from_values(std::iter::empty(), depth));
        }
        if !<T as SszDecode>::is_fixed_size() {
            let values = libssz::decode_list_with_max::<T>(bytes, max_len)?;
            return Ok(Self::from_values(values, depth));
        }
        let size = <T as SszDecode>::fixed_size();
        if size == 0 || !bytes.len().is_multiple_of(size) {
            return Err(DecodeError::InvalidByteLength {
                expected: size,
                got: bytes.len(),
            });
        }
        let count = bytes.len() / size;
        if count > max_len {
            return Err(DecodeError::InvalidByteLength {
                expected: max_len,
                got: count,
            });
        }
        let mut error = None;
        let values = bytes.chunks_exact(size).map_while(|chunk| {
            T::from_ssz_bytes(chunk)
                .map_err(|err| error = Some(err))
                .ok()
        });
        let interface = Self::from_values(values, depth);
        match error {
            Some(err) => Err(err),
            None => Ok(interface),
        }
    }
}
