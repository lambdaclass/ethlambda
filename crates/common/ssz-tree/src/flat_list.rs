//! [`FlatList`]: an SSZ `List[T, N]` of a packed type whose Merkle tree is
//! kept level by level in flat arrays, as `silver_state_hashing` keeps its
//! lists.
//!
//! [`List`](crate::List) is a tree of nodes: a write rebuilds the leaf it
//! lands in and the inner nodes above it, and hashing walks down to the
//! rebuilt ones. That suits a list whose writes touch a few places. A list
//! written all over at every block, as current epoch participation is (about
//! 27k flags a mainnet block, in nearly every 4 KiB of the list), pays the
//! walk and the rebuild everywhere, and rehashes whole leaves, which keep no
//! hashes inside them.
//!
//! Here every level of the tree above the chunks is stored, so a root rehashes
//! only the paths of the chunks written since the last one: the dirty chunks'
//! parents, then theirs, one level at a time. Each level's pairs are gathered
//! into one buffer and hashed in one call (see [`hash_pairs_into`]), wide
//! enough for multi-message SHA-256 kernels. Values and levels live in 4 KiB
//! pages shared through `Arc`, so a clone copies only page pointers, and a
//! write copies only the pages it changes.

use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;

use libssz_merkle::{Sha2Hasher, ZERO_HASHES, mix_in_length};
use libssz_types::TypeError;
use rayon::prelude::*;

use crate::batch::hash_pairs_into;
use crate::{Const, Hash256, Length, Value, is_packed, packing_factor, tree_depth};

/// Nodes per level page, and chunks' worth of values per value page: 4 KiB
/// of nodes. Even, so a pair of chunks never straddles two value pages.
const PAGE_NODES: usize = 128;

/// One page of a level.
type NodePage = [Hash256; PAGE_NODES];

/// At or above this many pairs in one level, the pairs are hashed on rayon.
const PARALLEL_PAIRS: usize = 4096;

/// Pairs per rayon task when a level is hashed in parallel.
const PARALLEL_BLOCK: usize = 1024;

/// An SSZ list of at most `L::get()` elements of a packed type, every level
/// of its Merkle tree kept flat. See the module documentation.
pub struct FlatListOf<T, L> {
    len: usize,
    /// The values, `PAGE_NODES` chunks' worth per page; every page but the
    /// last is full.
    values: Vec<Arc<Vec<T>>>,
    /// `levels[k - 1]` is level `k` above the chunks: `chunks.div_ceil(2^k)`
    /// nodes, in pages, a missing right sibling taken as the zero subtree of
    /// its height. The last level has one node, the data's root. Nodes past a
    /// level's size are unused.
    levels: Vec<Vec<Arc<NodePage>>>,
    /// One bit per chunk written since the last root.
    dirty: Vec<u64>,
    /// The list's root, length mixed in; `None` while chunks are dirty.
    root: Option<Hash256>,
    limit: PhantomData<L>,
}

/// A [`FlatListOf`] whose bound is fixed when the code is compiled.
pub type FlatList<T, const N: usize> = FlatListOf<T, Const<N>>;

impl<T: Value, L: Length> FlatListOf<T, L> {
    /// Values per value page.
    fn per_page() -> usize {
        PAGE_NODES * packing_factor::<T>()
    }

    /// The height of the type's Merkle tree, before the length is mixed in.
    fn depth() -> usize {
        tree_depth::<T>(L::get())
    }

    /// The number of chunks `len` values fill.
    fn chunks(len: usize) -> usize {
        len.div_ceil(packing_factor::<T>())
    }

    /// How many levels sit above `chunks` chunks, up to the data's root.
    fn height(chunks: usize) -> usize {
        chunks.next_power_of_two().trailing_zeros() as usize
    }

    fn empty() -> Self {
        assert!(is_packed::<T>(), "a flat list holds a packed type");
        Self {
            len: 0,
            values: Vec::new(),
            levels: Vec::new(),
            dirty: Vec::new(),
            root: None,
            limit: PhantomData,
        }
    }

    /// `len` copies of `T::default()`, which must encode as zero bytes, built
    /// without hashing: every node of an all-zero tree is the zero hash of its
    /// height, so each level is one shared page of it.
    pub fn zeros(len: usize) -> Result<Self, TypeError>
    where
        T: Default,
    {
        check_capacity(len, L::get())?;
        let zero = T::default();
        debug_assert!(
            zero.to_ssz().iter().all(|&byte| byte == 0),
            "the default value encodes as zeros"
        );
        let mut list = Self::empty();
        let per_page = Self::per_page();
        let full = Arc::new(vec![zero.clone(); per_page]);
        list.values = vec![full; len / per_page];
        if !len.is_multiple_of(per_page) {
            list.values.push(Arc::new(vec![zero; len % per_page]));
        }
        let mut size = Self::chunks(len);
        for zero_hash in &ZERO_HASHES[1..=Self::height(size)] {
            size = size.div_ceil(2);
            let page = Arc::new([*zero_hash; PAGE_NODES]);
            list.levels.push(vec![page; size.div_ceil(PAGE_NODES)]);
        }
        list.len = len;
        list.root = Some(mix_in_length(&Sha2Hasher, &ZERO_HASHES[Self::depth()], len));
        Ok(list)
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn get(&self, index: usize) -> Option<&T> {
        if index >= self.len {
            return None;
        }
        let per_page = Self::per_page();
        Some(&self.values[index / per_page][index % per_page])
    }

    /// Overwrites element `index`, copying its page if another version shares
    /// it.
    ///
    /// # Panics
    ///
    /// If `index` is out of bounds.
    pub fn set(&mut self, index: usize, value: T) {
        assert!(
            index < self.len,
            "index {index} out of bounds ({})",
            self.len
        );
        let per_page = Self::per_page();
        Arc::make_mut(&mut self.values[index / per_page])[index % per_page] = value;
        self.mark(index / packing_factor::<T>());
    }

    pub fn push(&mut self, value: T) -> Result<(), TypeError> {
        check_capacity(self.len + 1, L::get())?;
        if self.len.is_multiple_of(Self::per_page()) {
            self.values
                .push(Arc::new(Vec::with_capacity(Self::per_page())));
        }
        let page = self.values.last_mut().expect("pushed above if missing");
        Arc::make_mut(page).push(value);
        self.mark(self.len / packing_factor::<T>());
        self.len += 1;
        Ok(())
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> + '_ {
        self.values.iter().flat_map(|page| page.iter())
    }

    fn mark(&mut self, chunk: usize) {
        let word = chunk / 64;
        if word >= self.dirty.len() {
            self.dirty.resize(word + 1, 0);
        }
        self.dirty[word] |= 1 << (chunk % 64);
        self.root = None;
    }

    /// The list's root, rehashing the paths of the chunks written since the
    /// last one.
    pub fn commit(&mut self) -> Hash256 {
        if let Some(root) = self.root {
            return root;
        }
        let root = self.rehash();
        self.root = Some(root);
        root
    }

    /// The root, if nothing was written since it was computed.
    pub fn cached_root(&self) -> Option<Hash256> {
        self.root
    }

    fn rehash(&mut self) -> Hash256 {
        let chunks = Self::chunks(self.len);
        let height = Self::height(chunks);
        let mut dirty = take_dirty(&mut self.dirty, chunks);
        self.grow_levels(chunks, height);

        let mut pairs: Vec<Hash256> = Vec::new();
        let mut hashes: Vec<Hash256> = Vec::new();
        let mut size = chunks;
        for level in 1..=height {
            // The parents of the dirty nodes one level down, ascending.
            for node in &mut dirty {
                *node /= 2;
            }
            dirty.dedup();
            pairs.clear();
            if level == 1 {
                self.gather_chunk_pairs(&dirty, &mut pairs);
            } else {
                let below = &self.levels[level - 2];
                let zero = ZERO_HASHES[level - 1];
                for &parent in &dirty {
                    pairs.push(node_at(below, 2 * parent));
                    let right = 2 * parent + 1;
                    pairs.push(if right < size {
                        node_at(below, right)
                    } else {
                        zero
                    });
                }
            }
            hashes.clear();
            hashes.resize(dirty.len(), [0; 32]);
            hash_pairs(&pairs, &mut hashes);
            scatter(&mut self.levels[level - 1], &dirty, &hashes);
            size = size.div_ceil(2);
        }

        let mut root = match height {
            // An empty list's data is the zero tree; a one-chunk list's is
            // that chunk.
            0 if chunks == 0 => ZERO_HASHES[0],
            0 => {
                let mut chunk = Vec::with_capacity(32);
                T::ssz_append_fixed_slice(&self.values[0], &mut chunk);
                chunk.resize(32, 0);
                chunk.try_into().expect("32 bytes")
            }
            _ => self.levels[height - 1][0][0],
        };
        for zero in &ZERO_HASHES[height..Self::depth()] {
            let mut parent = [[0u8; 32]];
            hash_pairs_into(&[root, *zero], &mut parent);
            root = parent[0];
        }
        mix_in_length(&Sha2Hasher, &root, self.len)
    }

    /// Makes room in every level for `chunks` chunks: pushes add nodes, and
    /// the tree a level when the chunks pass a power of two. The new nodes are
    /// all on dirty paths, so the rehash fills them.
    fn grow_levels(&mut self, chunks: usize, height: usize) {
        if self.levels.len() < height {
            self.levels.resize_with(height, Vec::new);
        }
        let mut size = chunks;
        for level in &mut self.levels[..height] {
            size = size.div_ceil(2);
            let pages = size.div_ceil(PAGE_NODES);
            while level.len() < pages {
                level.push(Arc::new([[0; 32]; PAGE_NODES]));
            }
        }
    }

    /// The chunk pairs under the level-1 nodes `parents`, as 64 bytes each,
    /// zero-padded past the data.
    fn gather_chunk_pairs(&self, parents: &[usize], pairs: &mut Vec<Hash256>) {
        let per_pair = 2 * packing_factor::<T>();
        let per_page = Self::per_page();
        let mut bytes = Vec::with_capacity(64 * parents.len());
        for &parent in parents {
            let first = parent * per_pair;
            let page = &self.values[first / per_page];
            let start = first % per_page;
            let end = (start + per_pair).min(page.len());
            let at = bytes.len();
            T::ssz_append_fixed_slice(&page[start..end], &mut bytes);
            bytes.resize(at + 64, 0);
        }
        let (nodes, rest) = bytes.as_chunks::<32>();
        debug_assert!(rest.is_empty());
        pairs.extend_from_slice(nodes);
    }
}

fn check_capacity(len: usize, max: usize) -> Result<(), TypeError> {
    if len > max {
        return Err(TypeError::OverCapacity { max, got: len });
    }
    Ok(())
}

fn node_at(level: &[Arc<NodePage>], index: usize) -> Hash256 {
    level[index / PAGE_NODES][index % PAGE_NODES]
}

/// The set bits of `dirty` below `chunks`, ascending, clearing them all.
fn take_dirty(dirty: &mut Vec<u64>, chunks: usize) -> Vec<usize> {
    let mut indices = Vec::new();
    for (word_index, word) in dirty.iter().enumerate() {
        let mut bits = *word;
        while bits != 0 {
            let index = word_index * 64 + bits.trailing_zeros() as usize;
            bits &= bits - 1;
            if index < chunks {
                indices.push(index);
            }
        }
    }
    // Dropped rather than zeroed, so a clone of the committed list copies no
    // bitset.
    *dirty = Vec::new();
    indices
}

/// Hashes the pairs, on rayon when there are many.
fn hash_pairs(pairs: &[Hash256], hashes: &mut [Hash256]) {
    if hashes.len() >= PARALLEL_PAIRS && rayon::current_num_threads() > 1 {
        pairs
            .par_chunks(2 * PARALLEL_BLOCK)
            .zip(hashes.par_chunks_mut(PARALLEL_BLOCK))
            .for_each(|(pairs, hashes)| hash_pairs_into(pairs, hashes));
    } else {
        hash_pairs_into(pairs, hashes);
    }
}

/// Writes `hashes[i]` to node `nodes[i]` of `level`, copying each page that
/// another version shares once.
fn scatter(level: &mut [Arc<NodePage>], nodes: &[usize], hashes: &[Hash256]) {
    let mut i = 0;
    while i < nodes.len() {
        let page_index = nodes[i] / PAGE_NODES;
        let page = Arc::make_mut(&mut level[page_index]);
        while i < nodes.len() && nodes[i] / PAGE_NODES == page_index {
            page[nodes[i] % PAGE_NODES] = hashes[i];
            i += 1;
        }
    }
}

impl<T: Value, L: Length> TryFrom<Vec<T>> for FlatListOf<T, L> {
    type Error = TypeError;

    /// Builds the list and hashes every level.
    fn try_from(values: Vec<T>) -> Result<Self, TypeError> {
        check_capacity(values.len(), L::get())?;
        let mut list = Self::empty();
        list.len = values.len();
        list.values = values
            .chunks(Self::per_page())
            .map(|page| Arc::new(page.to_vec()))
            .collect();
        let chunks = Self::chunks(list.len);
        list.dirty = vec![u64::MAX; chunks.div_ceil(64)];
        list.commit();
        Ok(list)
    }
}

impl<T, L> Clone for FlatListOf<T, L> {
    fn clone(&self) -> Self {
        Self {
            len: self.len,
            values: self.values.clone(),
            levels: self.levels.clone(),
            dirty: self.dirty.clone(),
            root: self.root,
            limit: PhantomData,
        }
    }
}

impl<T, L> fmt::Debug for FlatListOf<T, L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlatList")
            .field("len", &self.len)
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use libssz_merkle::HashTreeRoot;
    use proptest::prelude::*;

    use super::*;
    use crate::List;

    const LIMIT: usize = 1 << 40;

    fn tree_root<T: Value>(values: &[T]) -> Hash256 {
        let list = List::<T, LIMIT>::try_from(values.to_vec()).unwrap();
        HashTreeRoot::hash_tree_root(&list, &Sha2Hasher)
    }

    #[test]
    fn a_built_list_hashes_like_the_tree() {
        for len in [0usize, 1, 31, 32, 33, 64, 4095, 4096, 4097, 8192, 70_001] {
            let values: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let mut flat = FlatList::<u8, LIMIT>::try_from(values.clone()).unwrap();
            assert_eq!(flat.commit(), tree_root(&values), "len {len}");
        }
    }

    #[test]
    fn zeros_hash_like_the_tree_without_hashing() {
        for len in [0usize, 1, 32, 33, 4096, 4097, 100_000] {
            let mut flat = FlatList::<u8, LIMIT>::zeros(len).unwrap();
            assert!(flat.cached_root().is_some());
            assert_eq!(flat.commit(), tree_root(&vec![0u8; len]), "len {len}");
            // The shared zero levels rehash right once written.
            if len > 0 {
                flat.set(len - 1, 9);
                let mut values = vec![0u8; len];
                values[len - 1] = 9;
                assert_eq!(flat.commit(), tree_root(&values), "len {len}, written");
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Rounds of writes and pushes, each followed by a root, against the
        /// tree built from the same values; a clone taken each round keeps its
        /// own root while the original moves on.
        #[test]
        fn writes_and_pushes_hash_like_the_tree(
            start in 0usize..20_000,
            rounds in prop::collection::vec(
                (prop::collection::vec((any::<usize>(), any::<u8>()), 0..300), 0usize..300),
                1..6,
            ),
        ) {
            let mut values: Vec<u8> = (0..start).map(|i| (i % 251) as u8).collect();
            let mut flat = FlatList::<u8, LIMIT>::try_from(values.clone()).unwrap();
            let mut kept = Vec::new();
            for (writes, pushes) in rounds {
                for (index, value) in writes {
                    if values.is_empty() { break; }
                    let index = index % values.len();
                    values[index] = value;
                    flat.set(index, value);
                }
                for i in 0..pushes {
                    values.push(i as u8);
                    flat.push(i as u8).unwrap();
                }
                prop_assert_eq!(flat.commit(), tree_root(&values));
                kept.push((flat.clone(), tree_root(&values)));
            }
            for (mut old, root) in kept {
                prop_assert_eq!(old.commit(), root);
            }
        }

        #[test]
        fn u64_writes_hash_like_the_tree(
            start in 0usize..3_000,
            writes in prop::collection::vec((any::<usize>(), any::<u64>()), 0..200),
            pushes in 0usize..100,
        ) {
            let mut values: Vec<u64> = (0..start as u64).collect();
            let mut flat = FlatList::<u64, LIMIT>::try_from(values.clone()).unwrap();
            for (index, value) in writes {
                if values.is_empty() { break; }
                let index = index % values.len();
                values[index] = value;
                flat.set(index, value);
            }
            for i in 0..pushes as u64 {
                values.push(i);
                flat.push(i).unwrap();
            }
            prop_assert_eq!(flat.commit(), tree_root(&values));
        }
    }
}
