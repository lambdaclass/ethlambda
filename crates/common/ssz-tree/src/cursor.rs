//! A lazy copy-on-write cursor: one in-order pass that can rewrite any element.
//!
//! Writing most of a list through `get_mut` pays for a pending-write map (an
//! entry per element, then a sorted copy of it) and for a descent per element,
//! only to rebuild each touched leaf in the end. The cursor skips the map. It
//! walks the leaves left to right and copies a leaf only when an element in it
//! is first written; when it leaves the leaf it compares what was written with
//! the original, and keeps the original (its `Arc` and its cached hash) if
//! nothing differs. The leaves that did change are swapped into the tree in
//! one descent when the cursor is dropped, which rebuilds only the paths to
//! them.
//!
//! The tree is never modified while the pass runs, so nothing is buffered
//! between elements: an early return or a panic still leaves a consistent
//! list holding the writes made so far.

use std::ops::Deref;
use std::sync::Arc;

use crate::Value;
use crate::tree::{LeafReplacements, Tree, element_root};

/// The leaf the cursor is in: the original, plus a copy made on the first
/// write.
struct LeafState<T> {
    /// The original leaf, always a [`Tree::Leaf`] while set.
    leaf: Option<Arc<Tree<T>>>,
    /// Index of the leaf's first element.
    first: usize,
    /// Elements in the leaf.
    len: usize,
    /// Offset of the next element to hand out.
    next: usize,
    /// The leaf's elements with this pass's writes, made on first write.
    copy: Option<Vec<T>>,
    /// One bit per offset that `make_mut` handed out, so the end-of-leaf
    /// comparison looks only at those. All zero whenever `copy` is `None`.
    touched: Vec<u64>,
}

impl<T: Value> LeafState<T> {
    fn empty() -> Self {
        Self {
            leaf: None,
            first: 0,
            len: 0,
            next: 0,
            copy: None,
            touched: Vec::new(),
        }
    }

    fn original(&self) -> &[T] {
        match self.leaf.as_deref() {
            Some(Tree::Leaf(leaf)) => &leaf.values,
            _ => &[],
        }
    }

    /// The leaf's elements as the pass sees them: the copy once there is one.
    fn current(&self) -> &[T] {
        self.copy.as_deref().unwrap_or_else(|| self.original())
    }

    fn load(&mut self, leaf: Arc<Tree<T>>, first: usize) {
        let Tree::Leaf(inner) = &*leaf else {
            unreachable!("the walk yields leaves")
        };
        self.len = inner.values.len();
        self.leaf = Some(leaf);
        self.first = first;
        self.next = 0;
    }

    fn make_mut(&mut self, offset: usize) -> &mut T {
        if self.copy.is_none() {
            self.copy = Some(self.original().to_vec());
            self.touched.resize(self.len.div_ceil(64), 0);
        }
        self.touched[offset / 64] |= 1 << (offset % 64);
        &mut self.copy.as_mut().expect("made just above")[offset]
    }

    /// Leaves the current leaf behind: the replacement to swap into the tree,
    /// or `None` if the pass left it as it was.
    ///
    /// A kept original and a carried element root both follow a comparison
    /// here, never an assumption that a write changed (or did not change)
    /// something.
    fn finish(&mut self) -> Option<(usize, Arc<Tree<T>>)> {
        let copy = self.copy.take()?;
        let touched = std::mem::take(&mut self.touched);
        let Some(Tree::Leaf(original)) = self.leaf.as_deref() else {
            unreachable!("a copy is only made of a loaded leaf")
        };
        // The element roots the original already has: the copy carries them
        // over, with the changed elements' recomputed. Only a composite leaf
        // that was hashed has any.
        let mut roots = original.roots.get().map(|roots| roots.to_vec());
        let mut changed = false;
        for (word_index, &word) in touched.iter().enumerate() {
            let mut bits = word;
            while bits != 0 {
                let offset = word_index * 64 + bits.trailing_zeros() as usize;
                bits &= bits - 1;
                if copy[offset] == original.values[offset] {
                    continue;
                }
                changed = true;
                if let Some(roots) = roots.as_mut() {
                    roots[offset] = element_root(&copy[offset]);
                }
            }
        }
        // Hand the zeroed bitset back for the next copy.
        self.touched = touched;
        self.touched.fill(0);
        if !changed {
            return None;
        }
        let leaf = Tree::leaf(copy, roots.map(Vec::into_boxed_slice));
        Some((self.first, Arc::new(leaf)))
    }
}

/// An in-order pass over a [`List`](crate::List) or [`Vector`](crate::Vector)
/// that can rewrite any element, made by `iter_cow`.
///
/// It is lending: [`IterCow::next_cow`] returns an [`ElemCow`] that borrows
/// the pass until the next call, so it is used in a `while let` loop rather
/// than a `for`. The writes reach the list when the pass is dropped, which
/// also happens on an early return or a panic.
pub struct IterCow<'a, T: Value> {
    tree: &'a mut Arc<Tree<T>>,
    depth: usize,
    /// For each inner node on the path to the next leaf, the index of its next
    /// child to visit.
    stack: Vec<(Arc<Tree<T>>, usize)>,
    /// A tree no taller than a leaf is one, yielded first.
    root_leaf: Option<Arc<Tree<T>>>,
    /// Index of the first element of the next leaf to visit.
    next_first: usize,
    state: LeafState<T>,
    /// Leaves that changed, in order, with their first index.
    replaced: Vec<(usize, Arc<Tree<T>>)>,
}

impl<'a, T: Value> IterCow<'a, T> {
    /// A pass over the tree of height `depth`. The caller has applied every
    /// pending write, so the tree is the whole list.
    pub(crate) fn new(tree: &'a mut Arc<Tree<T>>, depth: usize) -> Self {
        let root = Arc::clone(tree);
        let mut stack = Vec::new();
        let mut root_leaf = None;
        match &*root {
            Tree::Node(_) => stack.push((root, 0)),
            Tree::Leaf(_) => root_leaf = Some(root),
            Tree::Zero(_) => {}
        }
        Self {
            tree,
            depth,
            stack,
            root_leaf,
            next_first: 0,
            state: LeafState::empty(),
            replaced: Vec::new(),
        }
    }

    /// The next element, to read or to write, or `None` after the last.
    pub fn next_cow(&mut self) -> Option<ElemCow<'_, T>> {
        loop {
            if self.state.next < self.state.len {
                let offset = self.state.next;
                self.state.next += 1;
                let index = self.state.first + offset;
                return Some(ElemCow {
                    state: &mut self.state,
                    offset,
                    index,
                });
            }
            self.finish_leaf();
            let leaf = self.next_leaf()?;
            let first = self.next_first;
            self.next_first += crate::packing_factor::<T>() << crate::leaf_height::<T>(self.depth);
            self.state.load(leaf, first);
        }
    }

    fn finish_leaf(&mut self) {
        if let Some(replacement) = self.state.finish() {
            self.replaced.push(replacement);
        }
        self.state.len = 0;
        self.state.next = 0;
    }

    /// The next leaf in order, or `None` when the data ends.
    fn next_leaf(&mut self) -> Option<Arc<Tree<T>>> {
        if let Some(leaf) = self.root_leaf.take() {
            return Some(leaf);
        }
        loop {
            let (node, slot) = self.stack.last_mut()?;
            let Tree::Node(inner) = &**node else {
                unreachable!("only inner nodes are on the stack")
            };
            let Some(child) = inner.children.get(*slot).map(Arc::clone) else {
                self.stack.pop();
                continue;
            };
            *slot += 1;
            match &*child {
                Tree::Node(_) => self.stack.push((child, 0)),
                Tree::Leaf(_) => return Some(child),
                // The data is a prefix: everything from here on is padding.
                Tree::Zero(_) => {
                    self.stack.clear();
                    return None;
                }
            }
        }
    }
}

impl<T: Value> Drop for IterCow<'_, T> {
    /// Finishes the current leaf and swaps the changed leaves into the tree,
    /// rebuilding only the paths to them.
    fn drop(&mut self) {
        self.finish_leaf();
        if self.replaced.is_empty() {
            return;
        }
        let replaced = std::mem::take(&mut self.replaced);
        let mut source = LeafReplacements::new(replaced);
        *self.tree = Tree::with_rebuilt_leaves(&*self.tree, self.depth, 0, &mut source);
    }
}

/// One element of an [`IterCow`] pass.
///
/// Dereferences to the element, with this pass's writes to it. The leaf holding
/// it is copied only by the first [`make_mut`](ElemCow::make_mut) or changing
/// [`set`](ElemCow::set) on any element in it.
pub struct ElemCow<'c, T: Value> {
    state: &'c mut LeafState<T>,
    offset: usize,
    index: usize,
}

impl<T: Value> Deref for ElemCow<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.state.current()[self.offset]
    }
}

impl<T: Value> ElemCow<'_, T> {
    /// The element's index in the list.
    pub fn index(&self) -> usize {
        self.index
    }

    /// The element, to be written. Copies its leaf on the first write to the
    /// leaf in this pass; the leaf is kept as it was if the writes in the end
    /// leave every element equal.
    ///
    /// Prefer [`set`](ElemCow::set), or check first, when most writes change
    /// nothing: the copy is paid on the first call whether or not the value
    /// ends up different.
    pub fn make_mut(&mut self) -> &mut T {
        self.state.make_mut(self.offset)
    }

    /// Writes `value` if it differs from the element, so a write of the same
    /// value copies nothing.
    pub fn set(&mut self, value: T) {
        if **self != value {
            *self.make_mut() = value;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use libssz_merkle::{HashTreeRoot, Sha2Hasher, merkleize, pack};

    use super::*;
    use crate::{Hash256, List};

    fn children<T>(tree: &Tree<T>) -> &[Arc<Tree<T>>] {
        match tree {
            Tree::Node(inner) => &inner.children,
            _ => panic!("not an inner node"),
        }
    }

    fn u64_root(values: &[u64], depth: usize) -> Hash256 {
        let bytes: Vec<u8> = values.iter().flat_map(|v| v.to_le_bytes()).collect();
        merkleize(&Sha2Hasher, &pack(&bytes), Some(1 << depth))
    }

    fn list_root<V: HashTreeRoot>(value: &V) -> [u8; 32] {
        HashTreeRoot::hash_tree_root(value, &Sha2Hasher)
    }

    /// A tree of four u64 leaves (512 to a leaf) under one inner node.
    const DEPTH: usize = 9;

    #[test]
    fn only_the_changed_leafs_path_is_new() {
        let values: Vec<u64> = (0..2048).collect();
        let (mut tree, _) = Tree::from_values(values.clone(), DEPTH);
        let before = Arc::clone(&tree);
        before.hash(DEPTH);
        {
            let mut pass = IterCow::new(&mut tree, DEPTH);
            while let Some(mut element) = pass.next_cow() {
                match element.index() {
                    // Changes leaf 1.
                    600 => element.set(0),
                    // Touches leaf 2 without changing it.
                    1100 => *element.make_mut() = 1100,
                    // Sets the same value in leaf 3.
                    1600 => element.set(1600),
                    _ => {}
                }
            }
        }
        let (old, new) = (children(&before), children(&tree));
        assert!(Arc::ptr_eq(&old[0], &new[0]));
        assert!(!Arc::ptr_eq(&old[1], &new[1]));
        assert!(Arc::ptr_eq(&old[2], &new[2]));
        assert!(Arc::ptr_eq(&old[3], &new[3]));
        // The kept leaves keep their cached hash; the new one has none yet.
        assert!(new[0].cached_hash().is_some());
        assert!(new[1].cached_hash().is_none());

        let mut expected = values;
        expected[600] = 0;
        assert_eq!(tree.hash(DEPTH), u64_root(&expected, DEPTH));
        // The original is untouched.
        assert_eq!(before.get(600, DEPTH), Some(&600));
    }

    #[test]
    fn a_pass_that_changes_nothing_keeps_the_root_node() {
        let (mut tree, _) = Tree::from_values((0..2048u64).collect::<Vec<_>>(), DEPTH);
        let before = Arc::clone(&tree);
        {
            let mut pass = IterCow::new(&mut tree, DEPTH);
            while let Some(mut element) = pass.next_cow() {
                let same = *element;
                element.set(same);
                *element.make_mut() = same;
            }
        }
        assert!(Arc::ptr_eq(&before, &tree));
    }

    fn composite(n: u8) -> [u8; 48] {
        [n; 48]
    }

    #[test]
    fn carried_element_roots_equal_fresh_ones() {
        let values: Vec<[u8; 48]> = (0..200u8).map(composite).collect();
        let (mut tree, _) = Tree::from_values(values.clone(), 8);
        tree.hash(8);
        {
            let mut pass = IterCow::new(&mut tree, 8);
            while let Some(mut element) = pass.next_cow() {
                match element.index() {
                    70 => element.set(composite(250)),
                    // Touched but equal: its root must stay the old one.
                    71 => *element.make_mut() = composite(71),
                    _ => {}
                }
            }
        }
        let mut expected = values;
        expected[70] = composite(250);
        let Tree::Leaf(leaf) = &*children(&tree)[1] else {
            panic!("a 48-byte element's leaf height is 6");
        };
        let carried = leaf.roots.get().expect("carried from the hashed leaf");
        let fresh: Vec<Hash256> = expected[64..128].iter().map(element_root).collect();
        assert_eq!(&carried[..], &fresh[..]);
        let roots: Vec<Hash256> = expected.iter().map(element_root).collect();
        assert_eq!(tree.hash(8), merkleize(&Sha2Hasher, &roots, Some(256)));
    }

    #[test]
    fn a_leaf_without_roots_gets_none_and_hashes_correctly() {
        let values: Vec<[u8; 48]> = (0..70u8).map(composite).collect();
        let (mut tree, _) = Tree::from_values(values.clone(), 8);
        {
            let mut pass = IterCow::new(&mut tree, 8);
            while let Some(mut element) = pass.next_cow() {
                if element.index() == 3 {
                    element.set(composite(200));
                }
            }
        }
        let Tree::Leaf(leaf) = &*children(&tree)[0] else {
            panic!("expected a leaf");
        };
        assert!(leaf.roots.get().is_none());
        let mut expected = values;
        expected[3] = composite(200);
        let roots: Vec<Hash256> = expected.iter().map(element_root).collect();
        assert_eq!(tree.hash(8), merkleize(&Sha2Hasher, &roots, Some(256)));
    }

    #[test]
    fn an_early_return_keeps_the_writes_made_so_far() {
        let mut list = List::<u64, 4096>::try_from((0..1500u64).collect::<Vec<_>>()).unwrap();
        let result = list.try_update_each(|element| {
            if element.index() == 700 {
                return Err("stop");
            }
            element.set(element.index() as u64 + 1);
            Ok(())
        });
        assert_eq!(result, Err("stop"));
        let expected: Vec<u64> = (0..1500u64)
            .map(|i| if i < 700 { i + 1 } else { i })
            .collect();
        assert_eq!(list.to_vec(), expected);
        let reference = List::<u64, 4096>::try_from(expected).unwrap();
        assert_eq!(list_root(&list), list_root(&reference));
    }

    #[test]
    fn a_panic_mid_pass_leaves_a_consistent_list() {
        let mut list = List::<u64, 4096>::try_from((0..1500u64).collect::<Vec<_>>()).unwrap();
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let mut pass = list.iter_cow();
            while let Some(mut element) = pass.next_cow() {
                if element.index() == 800 {
                    *element.make_mut() = 9999;
                    panic!("mid-pass");
                }
                element.set(element.index() as u64 + 1);
            }
        }));
        assert!(outcome.is_err());
        let expected: Vec<u64> = (0..1500u64)
            .map(|i| match i {
                800 => 9999,
                i if i < 800 => i + 1,
                i => i,
            })
            .collect();
        assert_eq!(list.to_vec(), expected);
        let reference = List::<u64, 4096>::try_from(expected).unwrap();
        assert_eq!(list_root(&list), list_root(&reference));
    }

    #[test]
    fn empty_lists_and_partial_last_leaves() {
        let mut empty = List::<u64, 64>::empty();
        assert!(empty.iter_cow().next_cow().is_none());
        empty
            .try_update_each(|_| -> Result<(), ()> { unreachable!("no elements") })
            .unwrap();

        // 513 u64s: a full leaf and a one-element leaf.
        let mut list = List::<u64, 4096>::try_from((0..513u64).collect::<Vec<_>>()).unwrap();
        list.try_update_each(|e| -> Result<(), ()> {
            e.set(**e + 1);
            Ok(())
        })
        .unwrap();
        assert_eq!(list.to_vec(), (1..514u64).collect::<Vec<_>>());
    }

    #[test]
    fn a_registry_depth_list_updates_across_inner_nodes() {
        let boundary = 512 * 512;
        let len = boundary + 1000;
        let values: Vec<u64> = (0..len as u64).collect();
        let mut list = List::<u64, { 1 << 40 }>::try_from(values.clone()).unwrap();
        list.try_update_each(|e| -> Result<(), ()> {
            let index = e.index();
            if index == 5 || index == boundary - 1 || index == boundary || index == len - 1 {
                e.set(0);
            }
            Ok(())
        })
        .unwrap();
        let mut expected = values;
        for index in [5, boundary - 1, boundary, len - 1] {
            expected[index] = 0;
        }
        let reference = List::<u64, { 1 << 40 }>::try_from(expected.clone()).unwrap();
        assert_eq!(list_root(&list), list_root(&reference));
        assert_eq!(list.to_vec(), expected);
    }

    #[test]
    fn pending_writes_are_applied_before_the_pass() {
        let mut list = List::<u64, 4096>::try_from((0..1000u64).collect::<Vec<_>>()).unwrap();
        list.push(1000).unwrap();
        *list.get_mut(3).unwrap() = 77;
        list.try_update_each(|e| -> Result<(), ()> {
            if e.index() == 3 {
                assert_eq!(**e, 77);
            }
            if e.index() == 1000 {
                e.set(5);
            }
            Ok(())
        })
        .unwrap();
        assert!(!list.has_pending_updates());
        assert_eq!(list[3], 77);
        assert_eq!(list[1000], 5);
        assert_eq!(list.len(), 1001);
    }
}
