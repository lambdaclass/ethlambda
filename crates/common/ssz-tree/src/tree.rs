//! The persistent Merkle tree behind [`List`](crate::List) and
//! [`Vector`](crate::Vector).

use std::collections::HashSet;
use std::iter::Peekable;
use std::sync::{Arc, OnceLock};

use libssz_merkle::{HashTreeRoot, Sha2Hasher, ZERO_HASHES};
use rayon::prelude::*;

use crate::batch::hash_pairs;
use crate::{
    Hash256, NODE_LEVELS, Value, child_height, is_packed, leaf_height, max_leaf_height,
    packing_factor,
};

/// Height at or above which a node hashes its changed child subtrees in
/// parallel (see [`Tree::hash`]). Below it a subtree has fewer than 2^12
/// chunks, few enough that handing parts of it to other threads costs more
/// than hashing it on this one.
const PARALLEL_HASH_HEIGHT: usize = 12;

/// At most this many bottom-level nodes per group of subtrees hashed together
/// (see [`Tree::hash`]), so a group's buffers stay in cache.
const GROUP_NODES: usize = 8192;

/// At least this many leaves per group, so even a group's top level, one
/// pair per leaf, fills a 16-message SHA-256 call. Inner nodes have no such
/// floor: a block dirties a few dozen, each with several changed paths, and
/// spreading them over the threads gains more than wider top levels.
const MIN_LEAF_GROUP: usize = 16;

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
    /// bottom first (see [`Job`]), kept once the node is hashed. A node
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
    /// The bottom level of this leaf's subtree: its chunks for a packed type
    /// (the last one zero-padded), its elements' roots for a composite.
    fn chunks(&self, bytes: &mut Vec<u8>) -> Vec<Hash256> {
        if !is_packed::<T>() {
            return self.element_roots().to_vec();
        }
        // In bulk: a memcpy for the integer types on a little-endian host,
        // where appending element by element was a call per byte of a
        // participation leaf.
        bytes.clear();
        T::ssz_append_fixed_slice(&self.values, bytes);
        let mut chunks = vec![[0u8; 32]; bytes.len().div_ceil(32)];
        chunks.as_flattened_mut()[..bytes.len()].copy_from_slice(bytes);
        chunks
    }

    /// Each element's root, computed and kept on first use.
    ///
    /// `get` and `set` rather than `get_or_init`, which would hold the cell's
    /// lock while computing: an element's `hash_tree_root` may itself run on
    /// rayon, and a worker blocked on a cell another worker is filling may be
    /// the very worker that one waits on. Racing workers each compute the same
    /// roots, so the cost of a race is wasted work, never a wrong root.
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
    /// `height` is this node's height. Above the bottom inner nodes (those
    /// whose children are leaves), a node hashes its changed children first,
    /// in parallel at or above [`PARALLEL_HASH_HEIGHT`], then itself: each
    /// subtree is a task of its own, with no barrier between them. A bottom
    /// node and its leaves are hashed together instead, level by level, as a
    /// flat array of levels would be: every unhashed leaf, one binary level at
    /// a time, each level's pairs in one call, then the node. Each call is then
    /// wide enough for multi-message SHA-256 kernels, where one leaf at a time
    /// was a handful of pairs. A node rebuilt from a hashed one rehashes only
    /// the paths of the children it replaced (see [`Base`]).
    pub(crate) fn hash(&self, height: usize) -> Hash256 {
        if let Some(hash) = self.cached_hash() {
            return hash;
        }
        match self {
            Tree::Node(inner) if child_height::<T>(height) > max_leaf_height::<T>() => {
                let below = child_height::<T>(height);
                let all: Vec<usize>;
                let slots = match &inner.base {
                    Some(base) => &base.changed,
                    None => {
                        all = (0..inner.children.len()).collect();
                        &all
                    }
                };
                let hash_child = |&slot: &usize| {
                    inner.children[slot].hash(below);
                };
                if height >= PARALLEL_HASH_HEIGHT && slots.len() > 1 {
                    slots.par_iter().for_each(hash_child);
                } else {
                    slots.iter().for_each(hash_child);
                }
                hash_nodes(&[inner], height);
            }
            _ => {
                let mut work = Work::default();
                work.collect(self, height);
                work.run();
            }
        }
        self.cached_hash()
            .expect("the subtree was hashed just above")
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

/// Every leaf and inner node of a subtree still to be hashed.
struct Work<'a, T> {
    /// Shared subtrees (a [`Tree::repeat`] reuses one node many times) are
    /// collected once.
    seen: HashSet<usize>,
    /// Unhashed leaves and their heights.
    leaves: Vec<(&'a Leaf<T>, usize)>,
    /// Unhashed inner nodes and their heights.
    nodes: Vec<(&'a Node<T>, usize)>,
}

impl<T> Default for Work<'_, T> {
    fn default() -> Self {
        Self {
            seen: HashSet::new(),
            leaves: Vec::new(),
            nodes: Vec::new(),
        }
    }
}

impl<'a, T: Value> Work<'a, T> {
    fn collect(&mut self, tree: &'a Tree<T>, height: usize) {
        match tree {
            Tree::Zero(_) => {}
            Tree::Leaf(leaf) => {
                if leaf.hash.get().is_none() && self.seen.insert(std::ptr::from_ref(leaf).addr()) {
                    self.leaves.push((leaf, height));
                }
            }
            Tree::Node(inner) => {
                if inner.hash.get().is_some() || !self.seen.insert(std::ptr::from_ref(inner).addr())
                {
                    return;
                }
                let below = child_height::<T>(height);
                // A rebuilt node's unchanged children are the hashed node's,
                // whose roots its base already holds.
                match &inner.base {
                    Some(base) => {
                        for &slot in &base.changed {
                            self.collect(&inner.children[slot], below);
                        }
                    }
                    None => {
                        for child in &inner.children {
                            self.collect(child, below);
                        }
                    }
                }
                self.nodes.push((inner, height));
            }
        }
    }

    /// Hashes the leaves, then the inner nodes from the lowest height up, so
    /// every node finds its changed children hashed.
    fn run(mut self) {
        self.leaves.sort_by_key(|&(_, height)| height);
        for group in self.leaves.chunk_by(|a, b| a.1 == b.1) {
            let height = group[0].1;
            let leaves: Vec<&Leaf<T>> = group.iter().map(|&(leaf, _)| leaf).collect();
            hash_leaves(&leaves, height);
        }
        self.nodes.sort_by_key(|&(_, height)| height);
        for group in self.nodes.chunk_by(|a, b| a.1 == b.1) {
            let height = group[0].1;
            let nodes: Vec<&Node<T>> = group.iter().map(|&(node, _)| node).collect();
            hash_nodes(&nodes, height);
        }
    }
}

/// Splits `items`, subtrees of `width` bottom-level nodes each, into groups
/// and runs `f` on each, on rayon when there are several.
///
/// A group is a share of the items per thread, so a block's few hundred
/// dirty leaves still spread over every thread, but no fewer than `least`
/// items and no more than [`GROUP_NODES`] bottom nodes.
fn in_groups<I: Sync>(items: &[I], width: usize, least: usize, f: impl Fn(&[I]) + Sync + Send) {
    let threads = rayon::current_num_threads();
    let most = (GROUP_NODES / width.max(1)).max(least);
    let per_group = items.len().div_ceil(threads).clamp(least, most);
    if items.len() > per_group && threads > 1 {
        items.par_chunks(per_group).for_each(f);
    } else {
        items.chunks(per_group).for_each(f);
    }
}

/// Hashes leaves of height `height` together, level by level, and caches
/// each leaf's root.
fn hash_leaves<T: Value>(leaves: &[&Leaf<T>], height: usize) {
    in_groups(leaves, 1 << height, MIN_LEAF_GROUP, |group| {
        let mut bytes = Vec::new();
        let mut jobs: Vec<Job> = group
            .iter()
            .map(|leaf| Job::full(leaf.chunks(&mut bytes), height))
            .collect();
        fold(&mut jobs, 0, height);
        for (leaf, job) in group.iter().zip(jobs) {
            let _ = leaf.hash.set(job.root());
        }
    });
}

/// Hashes inner nodes at height `height` together, level by level, keeping
/// each node's levels for the nodes that will be rebuilt from it.
fn hash_nodes<T: Value>(nodes: &[&Node<T>], height: usize) {
    let below = child_height::<T>(height);
    let span = height - below;
    let root_of = |child: &Arc<Tree<T>>| {
        child
            .cached_hash()
            .expect("a node's changed children are hashed before it")
    };
    in_groups(nodes, 1 << span, 1, |group| {
        let mut jobs: Vec<Job> = group
            .iter()
            .map(|node| match &node.base {
                Some(base) => {
                    debug_assert_eq!(
                        base.levels.len(),
                        levels_len(node.children.len(), span),
                        "the base describes as many children"
                    );
                    let mut levels = base.levels.to_vec();
                    for &slot in &base.changed {
                        levels[slot] = root_of(&node.children[slot]);
                    }
                    Job {
                        levels,
                        dirty: Dirty::Some(base.changed.clone()),
                        start: 0,
                        size: node.children.len(),
                    }
                }
                None => Job::full(node.children.iter().map(root_of).collect(), span),
            })
            .collect();
        fold(&mut jobs, below, span);
        for (node, job) in group.iter().zip(jobs) {
            let root = job.root();
            let _ = node.levels.set(job.levels.into());
            let _ = node.hash.set(root);
        }
    });
}

/// One subtree being hashed: every level of it from the bottom nodes up to
/// its root, bottom first, each level half the one below rounded up, a
/// missing right sibling taken as the zero subtree of its height.
struct Job {
    levels: Vec<Hash256>,
    /// The nodes of the current level that changed, whose parents the next
    /// level rehashes.
    dirty: Dirty,
    /// Where the current level starts in `levels`, and its size.
    start: usize,
    size: usize,
}

enum Dirty {
    All,
    /// Ascending and unique.
    Some(Vec<usize>),
}

impl Job {
    /// A subtree with no levels to start from: every node is new.
    fn full(mut bottom: Vec<Hash256>, span: usize) -> Self {
        let size = bottom.len();
        bottom.resize(levels_len(size, span), [0; 32]);
        Self {
            levels: bottom,
            dirty: Dirty::All,
            start: 0,
            size,
        }
    }

    fn root(&self) -> Hash256 {
        *self.levels.last().expect("a subtree has a root level")
    }

    /// Moves `dirty` up to the parents and appends their child pairs to
    /// `pairs`, `zero` standing in for a missing right child.
    fn push_pairs(&mut self, pairs: &mut Vec<Hash256>, zero: &Hash256) {
        let (start, size) = (self.start, self.size);
        let mut push = |parent: usize| {
            pairs.push(self.levels[start + 2 * parent]);
            let right = 2 * parent + 1;
            pairs.push(if right < size {
                self.levels[start + right]
            } else {
                *zero
            });
        };
        match &mut self.dirty {
            Dirty::All => (0..size.div_ceil(2)).for_each(&mut push),
            Dirty::Some(nodes) => {
                for node in nodes.iter_mut() {
                    *node /= 2;
                }
                nodes.dedup();
                nodes.iter().copied().for_each(push);
            }
        }
    }

    /// Writes the parents' hashes, taken from the front of `hashes`, into the
    /// next level and moves up to it. Returns how many hashes it took.
    fn take_parents(&mut self, hashes: &[Hash256]) -> usize {
        let next = self.start + self.size;
        let taken = match &self.dirty {
            Dirty::All => {
                let count = self.size.div_ceil(2);
                self.levels[next..next + count].copy_from_slice(&hashes[..count]);
                count
            }
            Dirty::Some(parents) => {
                for (&parent, hash) in parents.iter().zip(hashes) {
                    self.levels[next + parent] = *hash;
                }
                parents.len()
            }
        };
        self.start = next;
        self.size = self.size.div_ceil(2);
        taken
    }
}

/// Rehashes `jobs` up `span` levels from height `below`: each level's pairs
/// from every job gathered into one call.
fn fold(jobs: &mut [Job], below: usize, span: usize) {
    let mut pairs = Vec::new();
    let mut hashes = Vec::new();
    for zero in &ZERO_HASHES[below..below + span] {
        pairs.clear();
        for job in jobs.iter_mut() {
            job.push_pairs(&mut pairs, zero);
        }
        hashes.clear();
        hashes.resize(pairs.len() / 2, [0; 32]);
        hash_pairs(&pairs, &mut hashes);
        let mut at = 0;
        for job in jobs.iter_mut() {
            at += job.take_parents(&hashes[at..]);
        }
    }
}

/// How many hashes a [`Job`] keeps for `children` bottom nodes folded up
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

/// A composite element's own root, as a leaf keeps it.
pub(crate) fn element_root<T: Value>(value: &T) -> Hash256 {
    HashTreeRoot::hash_tree_root(value, &Sha2Hasher)
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
