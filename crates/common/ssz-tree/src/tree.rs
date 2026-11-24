//! The persistent Merkle tree behind [`List`](crate::List) and
//! [`Vector`](crate::Vector).

use std::iter::Peekable;
use std::sync::{Arc, OnceLock};

use libssz::SszEncode;
use libssz_merkle::{HashTreeRoot, Sha2Hasher, ZERO_HASHES, pack};
use rayon::prelude::*;

use crate::batch::{hash_layer, hash_pairs_into, merkleize};
use crate::{
    Hash256, NODE_LEVELS, Value, child_height, is_packed, leaf_height, max_leaf_height,
    packing_factor,
};

/// Height at or above which a node with no cached hash hashes its children in
/// parallel.
///
/// Below it a subtree has fewer than 2^12 chunks, few enough that handing parts
/// of it to other threads costs more than hashing it on this one. A starting
/// value, measured by the `tree_bench` benchmark in `ethlambda-types`.
const PARALLEL_HASH_HEIGHT: usize = 12;

/// A Merkle tree with the shape of the SSZ one, whose nodes cache their own
/// hash.
///
/// Nodes are shared through `Arc` and never modified once built. An update
/// builds new nodes along the paths it touches and reuses the rest, so two
/// versions of a list share every subtree they have in common, cached hash
/// included.
///
/// Heights count SSZ chunks: a node at height `h` covers `2^h` chunks, the
/// subtree SSZ merkleization would build there. Every [`Tree::Leaf`] sits at the
/// same height, [`leaf_height`] of the tree's depth, and holds that whole
/// subtree's elements in one run. Above the leaves, each [`Tree::Node`] stands
/// for [`NODE_LEVELS`] binary levels at once (the root for fewer, see
/// [`child_height`]), so its children are the SSZ subtrees at the bottom of
/// those levels. Subtrees past the end of the data are [`Tree::Zero`] or, below
/// an inner node, simply absent, and are never materialized.
#[derive(Debug)]
pub(crate) enum Tree<T> {
    /// A subtree of the given height whose chunks are all zero: its hash is
    /// `ZERO_HASHES[height]`, looked up rather than computed.
    ///
    /// Only ever past the end of the data. An in-range element always sits in
    /// a [`Tree::Leaf`], even when it is zero, and the reads count on that:
    /// [`Self::get`] and [`Self::leaf_run`] answer `None` at a `Zero`, which
    /// means "past the end". Collapsing all-zero in-range leaves into a `Zero`
    /// would make both lose elements.
    Zero(usize),
    /// The elements of one leaf-height subtree, in order.
    Leaf(Leaf<T>),
    /// An inner node, above the leaf height.
    Node(Node<T>),
}

/// An inner node: the non-empty subtrees at its bottom level, left to right.
///
/// The data is a prefix of the list, so every child past the last one here
/// is a zero subtree, and every child before the last one is full.
#[derive(Debug)]
pub(crate) struct Node<T> {
    /// The root of the node's subtree.
    pub(crate) hash: OnceLock<Hash256>,
    /// Every binary level from the children's roots up to this node's root,
    /// bottom first (see [`fold_levels`]), kept once the node is hashed. A node
    /// rebuilt from this one starts from them and rehashes only the paths of
    /// the children it replaced, rather than all of a node's binary levels for
    /// one changed child (511 hashes for a full node).
    pub(crate) levels: OnceLock<Arc<[Hash256]>>,
    /// Set on a node rebuilt from a hashed one with as many children: see
    /// [`Base`].
    pub(crate) base: Option<Base>,
    pub(crate) children: Vec<Arc<Tree<T>>>,
}

/// What a rebuilt node needs to rehash only what changed: the levels of the
/// node it was rebuilt from, which had as many children, and the slots of
/// the children that differ from that node's.
#[derive(Debug)]
pub(crate) struct Base {
    pub(crate) levels: Arc<[Hash256]>,
    /// Ascending and unique.
    pub(crate) changed: Vec<usize>,
}

/// A leaf's run of elements and its cached hashes.
///
/// Holds up to `packing_factor << height` elements: every element of its
/// subtree, or fewer at the right edge of the data, where the missing chunks
/// are zero padding.
#[derive(Debug)]
pub(crate) struct Leaf<T> {
    /// The root of the leaf's subtree.
    pub(crate) hash: OnceLock<Hash256>,
    /// Each element's own root, in the order of `values`, for a composite type.
    /// Never set for a packed type, whose chunks are the values' bytes.
    ///
    /// Kept so that rebuilding a leaf around a few changed elements rehashes
    /// only those: see [`Tree::updated_leaf`].
    pub(crate) roots: OnceLock<Box<[Hash256]>>,
    pub(crate) values: Vec<T>,
}

impl<T> Tree<T> {
    pub(crate) fn node(children: Vec<Arc<Self>>) -> Self {
        Self::rebuilt_node(children, None)
    }

    /// An inner node with `base` to rehash from, if it was rebuilt from a
    /// hashed node with as many children.
    pub(crate) fn rebuilt_node(children: Vec<Arc<Self>>, base: Option<Base>) -> Self {
        debug_assert!(!children.is_empty(), "an empty subtree is a Tree::Zero");
        Tree::Node(Node {
            hash: OnceLock::new(),
            levels: OnceLock::new(),
            base,
            children,
        })
    }

    pub(crate) fn leaf(values: Vec<T>, roots: Option<Box<[Hash256]>>) -> Self {
        Tree::Leaf(Leaf {
            hash: OnceLock::new(),
            roots: roots.map(OnceLock::from).unwrap_or_default(),
            values,
        })
    }
}

impl<T: Value> Leaf<T> {
    /// The root of this leaf's subtree, which has height `height`.
    fn root(&self, height: usize) -> Hash256 {
        let chunks = 1 << height;
        if is_packed::<T>() {
            // In bulk: a memcpy for the integer types on a little-endian host,
            // where appending element by element was a call per byte of a
            // participation leaf.
            let mut bytes = Vec::with_capacity(self.values.len() * <T as SszEncode>::fixed_size());
            T::ssz_append_fixed_slice(&self.values, &mut bytes);
            return merkleize(&pack(&bytes), chunks);
        }
        merkleize(self.element_roots(), chunks)
    }

    /// Each element's root, computed and kept on first use.
    ///
    /// `get` and `set` rather than `get_or_init`, for the reason [`cached`]
    /// gives: an element's `hash_tree_root` may itself run on rayon.
    fn element_roots(&self) -> &[Hash256] {
        if let Some(roots) = self.roots.get() {
            return roots;
        }
        let roots: Box<[Hash256]> = self.values.iter().map(element_root).collect();
        // A racing worker may have stored the same roots first.
        let _ = self.roots.set(roots);
        self.roots.get().expect("set just above")
    }
}

impl<T: Value> Tree<T> {
    /// Builds a tree of height `depth` holding `values` in order.
    ///
    /// Returns the tree and how many values it holds.
    ///
    /// # Panics
    ///
    /// If there are more values than a tree of height `depth` holds. Callers
    /// check the type's limit first.
    pub(crate) fn from_values(
        values: impl IntoIterator<Item = T>,
        depth: usize,
    ) -> (Arc<Self>, usize) {
        let leaf_height = leaf_height::<T>(depth);
        let per_leaf = packing_factor::<T>() << leaf_height;
        let mut len = 0;
        let mut leaves = Vec::new();
        let mut run = Vec::with_capacity(per_leaf);
        for value in values {
            len += 1;
            run.push(value);
            if run.len() == per_leaf {
                let full = std::mem::replace(&mut run, Vec::with_capacity(per_leaf));
                leaves.push(Arc::new(Self::leaf(full, None)));
            }
        }
        if !run.is_empty() {
            run.shrink_to_fit();
            leaves.push(Arc::new(Self::leaf(run, None)));
        }
        let levels = depth - leaf_height;
        assert!(
            levels >= usize::BITS as usize || leaves.len() <= 1 << levels,
            "{len} values do not fit in a tree of depth {depth}"
        );
        (Self::from_leaves(leaves, leaf_height, depth), len)
    }

    /// Builds a tree of height `depth` holding `len` copies of `value`,
    /// sharing every identical subtree instead of building it again.
    ///
    /// All full leaves are one allocation, and so are all the full inner nodes
    /// at each level, each caching its hash once for every place it appears.
    /// Building and hashing is therefore proportional to the tree's height
    /// plus the partial leaf at the right edge, not to `len`. The nodes are
    /// immutable and every write copies the path it touches, so the sharing is
    /// never observable.
    ///
    /// # Panics
    ///
    /// If `len` elements do not fit in a tree of height `depth`. Callers check
    /// the type's limit first.
    pub(crate) fn repeat(value: &T, len: usize, depth: usize) -> Arc<Self> {
        if len == 0 {
            return Arc::new(Tree::Zero(depth));
        }
        let leaf_height = leaf_height::<T>(depth);
        let per_leaf = packing_factor::<T>() << leaf_height;
        let mut full_count = len / per_leaf;
        let tail_len = len % per_leaf;
        let levels = depth - leaf_height;
        assert!(
            levels >= usize::BITS as usize || full_count + usize::from(tail_len > 0) <= 1 << levels,
            "{len} values do not fit in a tree of depth {depth}"
        );
        // The shared full node of the level being built, if it has any.
        let mut full =
            (full_count > 0).then(|| Arc::new(Self::leaf(vec![value.clone(); per_leaf], None)));
        // The one partial node at the right edge of the level, if any.
        let mut tail =
            (tail_len > 0).then(|| Arc::new(Self::leaf(vec![value.clone(); tail_len], None)));
        let mut height = leaf_height;
        while height < depth {
            let parent = (height + NODE_LEVELS).min(depth);
            debug_assert_eq!(child_height::<T>(parent), height);
            let fan_out = 1 << (parent - height);
            let rest = full_count % fan_out;
            let tail_children: Vec<Arc<Self>> = full
                .iter()
                .flat_map(|full| std::iter::repeat_n(Arc::clone(full), rest))
                .chain(tail.take())
                .collect();
            let next_full = full
                .as_ref()
                .filter(|_| full_count >= fan_out)
                .map(|full| Arc::new(Self::node(vec![Arc::clone(full); fan_out])));
            tail = (!tail_children.is_empty()).then(|| Arc::new(Self::node(tail_children)));
            full_count /= fan_out;
            full = next_full;
            height = parent;
        }
        match (full, tail) {
            (Some(root), None) if full_count == 1 => root,
            (None, Some(root)) => root,
            _ => unreachable!("a tree that fits groups up into one root"),
        }
    }

    /// Groups `level`, left to right, from `leaf_height` up into a tree of
    /// height `depth`, [`NODE_LEVELS`] binary levels per inner node.
    fn from_leaves(mut level: Vec<Arc<Self>>, leaf_height: usize, depth: usize) -> Arc<Self> {
        if level.is_empty() {
            return Arc::new(Tree::Zero(depth));
        }
        let mut height = leaf_height;
        while height < depth {
            let parent = (height + NODE_LEVELS).min(depth);
            debug_assert_eq!(child_height::<T>(parent), height);
            let fan_out = 1 << (parent - height);
            let mut nodes = level.into_iter().peekable();
            let mut next = Vec::with_capacity(nodes.len().div_ceil(fan_out));
            while nodes.peek().is_some() {
                let children: Vec<_> = nodes.by_ref().take(fan_out).collect();
                next.push(Arc::new(Self::node(children)));
            }
            level = next;
            height = parent;
        }
        level
            .pop()
            .expect("a non-empty level groups up into one root")
    }

    /// The element at `index` of a tree of height `depth`, or `None` past the
    /// end of the data.
    ///
    /// `index` must be below the type's limit: bits of the chunk index above
    /// `depth` are not looked at.
    pub(crate) fn get(&self, index: usize, depth: usize) -> Option<&T> {
        let packing = packing_factor::<T>();
        debug_assert!(
            index < packing << depth,
            "index {index} is past the tree's capacity at depth {depth}"
        );
        let chunk_index = index / packing;
        let mut node = self;
        let mut height = depth;
        loop {
            match node {
                Tree::Node(inner) => {
                    let below = child_height::<T>(height);
                    let slot = (chunk_index >> below) & ((1 << (height - below)) - 1);
                    node = inner.children.get(slot)?;
                    height = below;
                }
                // The leaf covers an aligned run of `packing << height`
                // elements, so the low bits of `index` are the offset in it.
                Tree::Leaf(leaf) => return leaf.values.get(index & ((packing << height) - 1)),
                Tree::Zero(_) => return None,
            }
        }
    }

    /// The leaf holding element `index` of a tree of height `depth`, as the
    /// index of its first element and its run of elements, or `None` past the
    /// end of the data. The element itself is `run.get(index - first)`: a
    /// partial last leaf is shorter than the span it covers.
    pub(crate) fn leaf_run(&self, index: usize, depth: usize) -> Option<(usize, &[T])> {
        let packing = packing_factor::<T>();
        let chunk_index = index / packing;
        let mut node = self;
        let mut height = depth;
        loop {
            match node {
                Tree::Node(inner) => {
                    let below = child_height::<T>(height);
                    let slot = (chunk_index >> below) & ((1 << (height - below)) - 1);
                    node = inner.children.get(slot)?;
                    height = below;
                }
                Tree::Leaf(leaf) => {
                    let first = index & !((packing << height) - 1);
                    return Some((first, &leaf.values));
                }
                Tree::Zero(_) => return None,
            }
        }
    }

    /// This subtree's root, computing and caching whatever is not cached yet.
    ///
    /// `height` is this node's height. An inner node folds its children's
    /// roots up its binary levels, hashing the children in parallel at or
    /// above [`PARALLEL_HASH_HEIGHT`].
    pub(crate) fn hash(&self, height: usize) -> Hash256 {
        match self {
            Tree::Zero(zero_height) => ZERO_HASHES[*zero_height],
            Tree::Leaf(leaf) => cached(&leaf.hash, || leaf.root(height)),
            Tree::Node(inner) => cached(&inner.hash, || {
                let below = child_height::<T>(height);
                let levels = match &inner.base {
                    Some(base) => inner.rehash_changed(base, below, height),
                    None => {
                        let all: Vec<usize> = (0..inner.children.len()).collect();
                        fold_levels(inner.child_roots(&all, below, height), below, height)
                    }
                };
                let root = *levels.last().expect("a node has a root level");
                let _ = inner.levels.set(levels.into());
                root
            }),
        }
    }

    /// The hash this node already has, if any. A [`Tree::Zero`] always has one.
    pub(crate) fn cached_hash(&self) -> Option<Hash256> {
        match self {
            Tree::Zero(height) => Some(ZERO_HASHES[*height]),
            Tree::Leaf(leaf) => leaf.hash.get().copied(),
            Tree::Node(inner) => inner.hash.get().copied(),
        }
    }

    /// A copy of `node` with `updates` applied, sharing every child that no
    /// update touches.
    ///
    /// `node` has height `height` and covers the elements from `first` up to
    /// `first + (packing << height)`. `updates` yields `(index, value)` in
    /// strictly ascending index order; this consumes the ones inside that
    /// range and leaves the rest for the caller.
    pub(crate) fn with_updated_leaves<I>(
        node: &Arc<Self>,
        height: usize,
        first: usize,
        updates: &mut Peekable<I>,
    ) -> Arc<Self>
    where
        I: Iterator<Item = (usize, T)>,
    {
        Self::with_rebuilt_leaves(node, height, first, &mut ElementUpdates(updates))
    }

    /// A copy of `node` whose leaves are rebuilt by `source`, sharing every
    /// child the source does not touch.
    ///
    /// The descent behind [`Tree::with_updated_leaves`], generalized over what
    /// happens at a leaf: `source` names, in ascending order, the next index it
    /// has work for, and builds the new leaf. Everything above the leaves is
    /// rebuilt only along those paths.
    pub(crate) fn with_rebuilt_leaves<S: LeafSource<T>>(
        node: &Arc<Self>,
        height: usize,
        first: usize,
        source: &mut S,
    ) -> Arc<Self> {
        let packing = packing_factor::<T>();
        let end = first + (packing << height);
        match source.peek() {
            Some(index) if index < end => {}
            _ => return Arc::clone(node),
        }
        // A tree shorter than a leaf is one leaf, at its root; otherwise the
        // walk meets the leaves at the leaf height itself.
        if height <= max_leaf_height::<T>() {
            return source.leaf(node, first, end);
        }
        let below = child_height::<T>(height);
        let span = packing << below;
        let (mut children, levels) = match &**node {
            Tree::Node(inner) => (inner.children.clone(), inner.levels.get().cloned()),
            Tree::Zero(_) => (Vec::new(), None),
            Tree::Leaf(_) => unreachable!("a leaf above the leaf height"),
        };
        let len = children.len();
        let mut changed = Vec::new();
        while let Some(index) = source.peek() {
            if index >= end {
                break;
            }
            let slot = (index - first) / span;
            let child_first = first + slot * span;
            if let Some(child) = children.get(slot) {
                children[slot] = Self::with_rebuilt_leaves(child, below, child_first, source);
                // The source consumed everything below this child, so the next
                // slot is a later one.
                changed.push(slot);
            } else {
                // The data is a prefix, so a child past the last one only
                // appears as the next one, grown from nothing by pushes.
                assert_eq!(slot, children.len(), "a new child follows the last one");
                let empty = Arc::new(Tree::Zero(below));
                children.push(Self::with_rebuilt_leaves(
                    &empty,
                    below,
                    child_first,
                    source,
                ));
            }
        }
        // Rehashing from the old levels needs them to describe as many
        // children; a push that added one falls back to the full fold.
        let base = levels
            .filter(|_| children.len() == len)
            .map(|levels| Base { levels, changed });
        Arc::new(Self::rebuilt_node(children, base))
    }

    /// The leaf at this position once the updates for elements `first..end`
    /// are applied.
    ///
    /// Copies the run and writes the updates into it. For a composite type
    /// whose element roots this leaf already has, the new leaf gets them too,
    /// with each updated element's root computed here, so hashing it later
    /// only folds roots rather than rehashing every element in the run.
    fn updated_leaf<I>(&self, first: usize, end: usize, updates: &mut Peekable<I>) -> Self
    where
        I: Iterator<Item = (usize, T)>,
    {
        let (mut values, mut roots) = match self {
            Tree::Leaf(leaf) => (
                leaf.values.clone(),
                leaf.roots.get().map(|roots| roots.to_vec()),
            ),
            Tree::Zero(_) => (Vec::new(), None),
            Tree::Node(_) => unreachable!("an inner node at the leaf height"),
        };
        while let Some((index, value)) = updates.next_if(|(index, _)| *index < end) {
            let offset = index - first;
            if let Some(roots) = roots.as_mut() {
                let root = element_root(&value);
                if offset < roots.len() {
                    roots[offset] = root;
                } else {
                    roots.push(root);
                }
            }
            if offset < values.len() {
                values[offset] = value;
            } else {
                // Pushes are buffered in order with no gaps, so a value past the
                // end of the leaf is always the next one.
                assert_eq!(offset, values.len(), "a pushed value follows the last one");
                values.push(value);
            }
        }
        Self::leaf(values, roots.map(Vec::into_boxed_slice))
    }
}

/// What a descent does at the leaves it reaches: see
/// [`Tree::with_rebuilt_leaves`].
pub(crate) trait LeafSource<T> {
    /// The index of the next element or leaf this source has work for, in
    /// strictly ascending order, or `None` when it is done.
    fn peek(&mut self) -> Option<usize>;

    /// The replacement for `node`, the leaf covering elements `first..end`,
    /// consuming the work inside that range.
    fn leaf(&mut self, node: &Arc<Tree<T>>, first: usize, end: usize) -> Arc<Tree<T>>;
}

/// Element-level writes, folded into each leaf they land in.
struct ElementUpdates<'a, I: Iterator>(&'a mut Peekable<I>);

impl<T: Value, I: Iterator<Item = (usize, T)>> LeafSource<T> for ElementUpdates<'_, I> {
    fn peek(&mut self) -> Option<usize> {
        self.0.peek().map(|&(index, _)| index)
    }

    fn leaf(&mut self, node: &Arc<Tree<T>>, first: usize, end: usize) -> Arc<Tree<T>> {
        Arc::new(node.updated_leaf(first, end, self.0))
    }
}

/// Whole leaves built elsewhere, to swap in: `(first index, new leaf)` in
/// ascending order.
pub(crate) struct LeafReplacements<T>(Peekable<std::vec::IntoIter<(usize, Arc<Tree<T>>)>>);

impl<T> LeafReplacements<T> {
    pub(crate) fn new(replacements: Vec<(usize, Arc<Tree<T>>)>) -> Self {
        Self(replacements.into_iter().peekable())
    }
}

impl<T> LeafSource<T> for LeafReplacements<T> {
    fn peek(&mut self) -> Option<usize> {
        self.0.peek().map(|&(first, _)| first)
    }

    fn leaf(&mut self, _node: &Arc<Tree<T>>, first: usize, _end: usize) -> Arc<Tree<T>> {
        let (at, leaf) = self.0.next().expect("peeked just before");
        debug_assert_eq!(at, first, "a replacement leaf sits at its own position");
        leaf
    }
}

impl<T: Value> Node<T> {
    /// The roots of the children in `slots`, in that order: on rayon for a
    /// node high enough that its children are large subtrees.
    fn child_roots(&self, slots: &[usize], below: usize, height: usize) -> Vec<Hash256> {
        if height >= PARALLEL_HASH_HEIGHT && slots.len() > 1 {
            slots
                .par_iter()
                .map(|&slot| self.children[slot].hash(below))
                .collect()
        } else {
            slots
                .iter()
                .map(|&slot| self.children[slot].hash(below))
                .collect()
        }
    }

    /// This node's levels: `base`'s, with the paths of the changed children
    /// rehashed, one hash per changed pair per level rather than a full fold.
    fn rehash_changed(&self, base: &Base, below: usize, height: usize) -> Vec<Hash256> {
        let mut levels = base.levels.to_vec();
        debug_assert_eq!(
            levels.len(),
            levels_len(self.children.len(), height - below),
            "the base describes as many children"
        );
        let roots = self.child_roots(&base.changed, below, height);
        for (&slot, root) in base.changed.iter().zip(roots) {
            levels[slot] = root;
        }
        let mut dirty = base.changed.clone();
        let (mut start, mut size) = (0, self.children.len());
        let mut pairs = Vec::with_capacity(2 * dirty.len());
        let mut parents = Vec::with_capacity(dirty.len());
        for zero in &ZERO_HASHES[below..height] {
            dirty.iter_mut().for_each(|slot| *slot /= 2);
            dirty.dedup();
            pairs.clear();
            for &parent in &dirty {
                pairs.push(levels[start + 2 * parent]);
                let right = 2 * parent + 1;
                pairs.push(if right < size {
                    levels[start + right]
                } else {
                    *zero
                });
            }
            parents.clear();
            parents.resize(dirty.len(), [0; 32]);
            hash_pairs_into(&pairs, &mut parents);
            let next = start + size;
            for (&parent, &hash) in dirty.iter().zip(&parents) {
                levels[next + parent] = hash;
            }
            (start, size) = (next, size.div_ceil(2));
        }
        levels
    }
}

/// How many hashes [`fold_levels`] keeps for `children` roots folded up
/// `levels` levels: each level half the one below, rounded up, down to the
/// root.
fn levels_len(children: usize, levels: usize) -> usize {
    let mut size = children;
    let mut total = size;
    for _ in 0..levels {
        size = size.div_ceil(2);
        total += size;
    }
    total
}

/// Every level of the fold from `roots`, which sit at height `below`, up to
/// the root at height `height`, bottom first: `roots` themselves, then each
/// level above, with a missing right sibling taken as the zero subtree of its
/// height. The last hash is the root.
///
/// Not `merkleize`: that pads with the zero hashes of chunk-level subtrees,
/// right only for chunks, while a missing child here is a zero subtree of the
/// children's own height, and one level up of that height plus one.
fn fold_levels(roots: Vec<Hash256>, below: usize, height: usize) -> Vec<Hash256> {
    debug_assert!(roots.len() <= 1 << (height - below));
    if roots.is_empty() {
        return vec![ZERO_HASHES[height]];
    }
    let mut levels = Vec::with_capacity(levels_len(roots.len(), height - below));
    levels.extend_from_slice(&roots);
    let mut layer = roots;
    for zero in &ZERO_HASHES[below..height] {
        hash_layer(&mut layer, zero);
        levels.extend_from_slice(&layer);
    }
    levels
}

/// A composite element's own root, as a leaf keeps it.
pub(crate) fn element_root<T: Value>(value: &T) -> Hash256 {
    HashTreeRoot::hash_tree_root(value, &Sha2Hasher)
}

/// The hash in `cell`, computing and storing it first if the cell is empty.
///
/// Uses `get` and `set` rather than `OnceLock::get_or_init`. `get_or_init`
/// holds the cell's lock while `compute` runs, and `compute` hashes the
/// children on rayon: a worker blocked on a cell another worker
/// is filling may be the very worker that one's parallel hash waits on, which
/// deadlocks. Racing workers here are safe: each may end up rehashing the
/// whole uncached subtree below this node rather than just this one cell, and
/// more than two workers can race on it, but every racer computes the same
/// value, so the cost is wasted work, never a wrong hash.
fn cached(cell: &OnceLock<Hash256>, compute: impl FnOnce() -> Hash256) -> Hash256 {
    if let Some(hash) = cell.get() {
        return *hash;
    }
    let hash = compute();
    // A racing worker may have stored the same value first.
    let _ = cell.set(hash);
    hash
}

#[cfg(test)]
mod tests {
    use libssz::SszEncode;
    use libssz_merkle::{merkleize, pack};

    use super::*;

    /// The root libssz computes for `values` packed and padded to `2^depth`
    /// chunks.
    fn expected_root(values: &[u64], depth: usize) -> Hash256 {
        let mut bytes = Vec::new();
        for value in values {
            value.ssz_append(&mut bytes);
        }
        merkleize(&Sha2Hasher, &pack(&bytes), Some(1 << depth))
    }

    #[test]
    fn a_built_tree_hashes_like_merkleize() {
        for len in [0usize, 1, 3, 4, 5, 8, 9, 31, 32, 33] {
            let values: Vec<u64> = (0..len as u64).map(|i| i * 3 + 1).collect();
            let (tree, count) = Tree::from_values(values.clone(), 4);
            assert_eq!(count, len);
            assert_eq!(tree.hash(4), expected_root(&values, 4), "len {len}");
        }
    }

    #[test]
    fn get_finds_every_value_and_nothing_past_the_end() {
        let values: Vec<u64> = (100..137).collect();
        let (tree, _) = Tree::from_values(values.clone(), 4);
        for (index, value) in values.iter().enumerate() {
            assert_eq!(tree.get(index, 4), Some(value));
        }
        assert_eq!(tree.get(values.len(), 4), None);
        assert_eq!(tree.get(63, 4), None);
    }

    /// An inner node's children.
    fn children<T>(tree: &Tree<T>) -> &[Arc<Tree<T>>] {
        match tree {
            Tree::Node(inner) => &inner.children,
            _ => panic!("not an inner node"),
        }
    }

    /// Elements in one u64 leaf.
    fn per_leaf() -> usize {
        crate::packing_factor::<u64>() << crate::max_leaf_height::<u64>()
    }

    /// Leaf height of `u64` plus two: one inner node of four leaves.
    fn four_u64_leaves() -> usize {
        crate::max_leaf_height::<u64>() + 2
    }

    #[test]
    fn updating_leaves_rebuilds_only_their_paths() {
        let values: Vec<u64> = (0..4 * per_leaf() as u64).collect();
        let (tree, _) = Tree::from_values(values.clone(), four_u64_leaves());
        assert_eq!(
            tree.hash(four_u64_leaves()),
            expected_root(&values, four_u64_leaves())
        );

        // Both writes land in the first leaf.
        let updates = vec![(1usize, 1000u64), (2, 2000)];
        let updated = Tree::with_updated_leaves(
            &tree,
            four_u64_leaves(),
            0,
            &mut updates.into_iter().peekable(),
        );

        let mut expected = values.clone();
        expected[1] = 1000;
        expected[2] = 2000;
        assert_eq!(
            updated.hash(four_u64_leaves()),
            expected_root(&expected, four_u64_leaves())
        );

        // Every element past the first leaf was untouched, so the root's other
        // three leaves
        // are the same nodes; only the first was rebuilt.
        let (old, new) = (children(&tree), children(&updated));
        assert_eq!((old.len(), new.len()), (4, 4));
        assert!(!Arc::ptr_eq(&old[0], &new[0]));
        for slot in 1..4 {
            assert!(Arc::ptr_eq(&old[slot], &new[slot]), "leaf {slot}");
        }

        // The original tree is unchanged.
        assert_eq!(tree.get(1, four_u64_leaves()), Some(&1));
    }

    #[test]
    fn a_tree_of_several_leaves_hashes_like_merkleize() {
        // Around each leaf boundary, and a full tree.
        let leaf = per_leaf();
        for len in [
            0,
            1,
            leaf - 1,
            leaf,
            leaf + 1,
            2 * leaf,
            3 * leaf - 5,
            4 * leaf,
        ] {
            let values: Vec<u64> = (0..len as u64).map(|i| i * 3 + 1).collect();
            let (tree, count) = Tree::from_values(values.clone(), four_u64_leaves());
            assert_eq!(count, len);
            assert_eq!(
                tree.hash(four_u64_leaves()),
                expected_root(&values, four_u64_leaves()),
                "len {len}"
            );
            for (index, value) in values.iter().enumerate() {
                assert_eq!(tree.get(index, four_u64_leaves()), Some(value), "len {len}");
            }
            // `get` takes an index below the capacity, so a full tree has no
            // "one past the end" to ask about.
            if len < 4 * leaf {
                assert_eq!(tree.get(len, four_u64_leaves()), None);
            }
        }
    }

    /// 200 composite elements, 64 to a leaf, in a tree of 256 chunks: three
    /// full leaves and a partial one.
    fn composite_values() -> Vec<[u8; 48]> {
        (0..200u16).map(|i| [(i % 251) as u8; 48]).collect()
    }

    fn composite_root(values: &[[u8; 48]], depth: usize) -> Hash256 {
        let roots: Vec<Hash256> = values.iter().map(element_root).collect();
        merkleize(&Sha2Hasher, &roots, Some(1 << depth))
    }

    #[test]
    fn a_composite_tree_of_several_leaves_hashes_and_finds_every_value() {
        let values = composite_values();
        let (tree, _) = Tree::from_values(values.clone(), 8);
        assert_eq!(tree.hash(8), composite_root(&values, 8));
        for (index, value) in values.iter().enumerate() {
            assert_eq!(tree.get(index, 8), Some(value));
        }
        assert_eq!(tree.get(values.len(), 8), None);
    }

    #[test]
    fn a_rebuilt_leaf_keeps_the_element_roots_it_already_had() {
        let values = composite_values();
        let (tree, _) = Tree::from_values(values.clone(), 8);
        tree.hash(8);

        // Element 70 is in the second leaf; 199 is pushed after the last.
        let updates = vec![(70usize, [7u8; 48]), (200, [9u8; 48])];
        let updated = Tree::with_updated_leaves(&tree, 8, 0, &mut updates.into_iter().peekable());

        let mut expected = values.clone();
        expected[70] = [7u8; 48];
        expected.push([9u8; 48]);

        // The second leaf holds elements 64..128, the root's second child.
        let Tree::Leaf(leaf) = &*children(&updated)[1] else {
            panic!("height 6 is the leaf height of a 48-byte element");
        };
        let carried = leaf.roots.get().expect("carried over from the hashed leaf");
        let fresh: Vec<Hash256> = expected[64..128].iter().map(element_root).collect();
        assert_eq!(&carried[..], &fresh[..]);

        // The last leaf was hashed too, so the pushed value's root is carried
        // in with it, and the whole tree still hashes like merkleize.
        assert_eq!(updated.hash(8), composite_root(&expected, 8));
    }

    #[test]
    fn updates_past_the_end_extend_the_tree() {
        let (tree, _) = Tree::from_values(vec![7u64, 8, 9], 4);
        let updates = vec![(3usize, 10u64), (4, 11), (5, 12)];
        let updated = Tree::with_updated_leaves(&tree, 4, 0, &mut updates.into_iter().peekable());
        assert_eq!(updated.hash(4), expected_root(&[7, 8, 9, 10, 11, 12], 4));
        assert_eq!(updated.get(5, 4), Some(&12));
    }

    #[test]
    fn composite_leaves_hash_like_merkleize_of_their_roots() {
        let values: Vec<[u8; 48]> = (0..5u8).map(|i| [i; 48]).collect();
        let (tree, _) = Tree::from_values(values.clone(), 3);
        let roots: Vec<Hash256> = values
            .iter()
            .map(|value| HashTreeRoot::hash_tree_root(value, &Sha2Hasher))
            .collect();
        assert_eq!(tree.hash(3), merkleize(&Sha2Hasher, &roots, Some(8)));
    }

    /// More than one bottom inner node's worth of u64 leaves (512 leaves), at
    /// the registry limit's depth: two levels of inner nodes over the leaves,
    /// plus the root spanning what is left.
    #[test]
    fn a_registry_depth_tree_of_two_inner_levels_reads_writes_and_hashes() {
        const DEPTH: usize = 38;
        const LEN: usize = 300_000;
        let values: Vec<u64> = (0..LEN as u64).map(|i| i ^ 0x5555).collect();
        let (tree, _) = Tree::from_values(values.clone(), DEPTH);
        assert_eq!(tree.hash(DEPTH), expected_root(&values, DEPTH));

        // Around the boundary between the first two bottom inner nodes.
        let boundary = 512 * per_leaf();
        assert!(
            LEN > boundary + per_leaf(),
            "the tree spans two bottom nodes"
        );
        let leaf = per_leaf();
        for index in [
            0,
            leaf - 1,
            leaf,
            boundary - 1,
            boundary,
            boundary + 1,
            LEN - 1,
        ] {
            assert_eq!(
                tree.get(index, DEPTH),
                Some(&values[index]),
                "index {index}"
            );
        }
        assert_eq!(tree.get(LEN, DEPTH), None);
        for start in [boundary - 1, boundary, LEN - 3] {
            let got: Vec<u64> = crate::iter::TreeIter::new(&tree, DEPTH, start)
                .copied()
                .collect();
            assert_eq!(got, values[start..], "start {start}");
        }

        // One write in each bottom node, and a push after the last value.
        let updates = vec![(7usize, 1u64), (boundary + 9, 2), (LEN, 3)];
        let updated =
            Tree::with_updated_leaves(&tree, DEPTH, 0, &mut updates.into_iter().peekable());
        let mut expected = values;
        expected[7] = 1;
        expected[boundary + 9] = 2;
        expected.push(3);
        assert_eq!(updated.hash(DEPTH), expected_root(&expected, DEPTH));
        assert_eq!(updated.get(LEN, DEPTH), Some(&3));
    }

    #[test]
    fn a_tall_tree_hashes_in_parallel_to_the_same_root() {
        // Height 14 is above PARALLEL_HASH_HEIGHT, so the top levels go
        // through rayon::join.
        let values: Vec<u64> = (0..40_000).collect();
        let (tree, _) = Tree::from_values(values.clone(), 14);
        assert_eq!(tree.hash(14), expected_root(&values, 14));
    }

    #[test]
    fn pushing_into_an_empty_tree_above_height_zero_hashes_correctly() {
        // n = 5 crosses the leaf 0 / leaf 1 boundary (u64 packs 4 to a leaf);
        // n = 100 lands deep in the right half of a height-5 (32-leaf) tree.
        for n in [1usize, 4, 5, 20, 100] {
            let (tree, count) = Tree::<u64>::from_values(vec![], 5);
            assert_eq!(count, 0);
            let values: Vec<u64> = (0..n as u64).collect();
            let updates: Vec<(usize, u64)> = values.iter().copied().enumerate().collect();
            let updated =
                Tree::with_updated_leaves(&tree, 5, 0, &mut updates.into_iter().peekable());
            assert_eq!(updated.hash(5), expected_root(&values, 5), "n {n}");
        }
    }

    #[test]
    fn updating_composite_leaves_overwrites_and_pushes() {
        let values: Vec<[u8; 48]> = (0..5u8).map(|i| [i; 48]).collect();
        let (tree, _) = Tree::from_values(values.clone(), 3);

        // Overwrite element 2, push a new element 5 (past the end).
        let overwritten = [99u8; 48];
        let pushed = [100u8; 48];
        let updates = vec![(2usize, overwritten), (5, pushed)];
        let updated = Tree::with_updated_leaves(&tree, 3, 0, &mut updates.into_iter().peekable());

        let mut expected = values;
        expected[2] = overwritten;
        expected.push(pushed);
        let roots: Vec<Hash256> = expected
            .iter()
            .map(|value| HashTreeRoot::hash_tree_root(value, &Sha2Hasher))
            .collect();
        assert_eq!(updated.hash(3), merkleize(&Sha2Hasher, &roots, Some(8)));
        assert_eq!(updated.get(2, 3), Some(&overwritten));
        assert_eq!(updated.get(5, 3), Some(&pushed));
    }

    /// A node rebuilt from a hashed one rehashes only its changed children's
    /// paths. Its root must equal a fresh fold of the same values at the
    /// widths real lists have (hundreds of children, a partial last one, two
    /// levels of inner nodes), over rounds of scattered writes, pushes that add
    /// a child (the full fold again), and rounds left unhashed, after which
    /// the next rebuild has no levels to start from.
    #[test]
    fn rehashing_changed_paths_matches_a_fresh_fold() {
        let next = |x: u64| {
            let x = x ^ (x << 13);
            let x = x ^ (x >> 7);
            x ^ (x << 17)
        };
        for (depth, len) in [
            (12, 512 * 5),
            (16, 512 * 300 + 17),
            (16, 512 * 512),
            (19, 512 * 700 + 3),
        ] {
            let mut values: Vec<u64> = (0..len as u64).map(|i| i.wrapping_mul(0x9e37)).collect();
            let (mut tree, _) = Tree::from_values(values.clone(), depth);
            assert_eq!(tree.hash(depth), expected_root(&values, depth));
            let mut seed = 0x1234_5678 + depth as u64;
            let mut hashed = true;
            for round in 0..8usize {
                let mut updates = Vec::new();
                for _ in 0..1 + round * 37 {
                    seed = next(seed);
                    let index = (seed % values.len() as u64) as usize;
                    updates.push((index, seed));
                }
                updates.sort_by_key(|&(index, _)| index);
                updates.dedup_by_key(|&mut (index, _)| index);
                // Every third round also pushes 512 values, while the tree has
                // room: new leaves, so no base for their parent.
                let grows = round % 3 == 2 && values.len() + 512 <= 4 << depth;
                for &(index, value) in &updates {
                    values[index] = value;
                }
                if grows {
                    for offset in 0..512 {
                        updates.push((values.len(), offset));
                        values.push(offset);
                    }
                }
                let before = children(&tree).len();
                tree =
                    Tree::with_updated_leaves(&tree, depth, 0, &mut updates.into_iter().peekable());
                let Tree::Node(inner) = &*tree else {
                    panic!("every case is taller than a leaf");
                };
                assert_eq!(
                    inner.base.is_some(),
                    hashed && inner.children.len() == before,
                    "depth {depth} round {round}: a base exactly when the old root was hashed \
                     and kept its number of children"
                );
                // Odd rounds stay unhashed.
                hashed = round % 2 == 0;
                if hashed {
                    assert_eq!(
                        tree.hash(depth),
                        expected_root(&values, depth),
                        "depth {depth} len {len} round {round}"
                    );
                }
            }
            assert_eq!(tree.hash(depth), expected_root(&values, depth));
        }
    }

    #[test]
    fn a_tree_of_depth_zero_builds_updates_and_hashes() {
        let (tree, count) = Tree::from_values(vec![42u64], 0);
        assert_eq!(count, 1);
        assert_eq!(tree.hash(0), expected_root(&[42], 0));
        assert_eq!(tree.get(0, 0), Some(&42));

        let updates = vec![(0usize, 100u64)];
        let updated = Tree::with_updated_leaves(&tree, 0, 0, &mut updates.into_iter().peekable());
        assert_eq!(updated.hash(0), expected_root(&[100], 0));
        assert_eq!(updated.get(0, 0), Some(&100));
    }
}
