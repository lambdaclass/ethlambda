//! In-order iteration over a tree, and over a tree plus its pending writes.

use std::iter::FusedIterator;
use std::sync::Arc;

use crate::tree::Tree;
use crate::update_map::UpdateMap;
use crate::{Value, child_height, packing_factor};

/// Walks a tree's elements left to right from a given index.
pub(crate) struct TreeIter<'a, T> {
    /// For each inner node on the path to the current leaf, its children still
    /// to visit; the innermost node's on top.
    stack: Vec<std::slice::Iter<'a, Arc<Tree<T>>>>,
    /// What is left of the current leaf.
    leaf: std::slice::Iter<'a, T>,
}

impl<'a, T: Value> TreeIter<'a, T> {
    /// An iterator at element `start` of `tree`, a tree of height `depth`.
    pub(crate) fn new(tree: &'a Tree<T>, depth: usize, start: usize) -> Self {
        let packing = packing_factor::<T>();
        let chunk_index = start / packing;
        let mut stack = Vec::new();
        let mut node = tree;
        let mut height = depth;
        let leaf = loop {
            match node {
                // As in `Tree::get`, but deferring the children right of the
                // path, which come after `start`.
                Tree::Node(inner) => {
                    let below = child_height::<T>(height);
                    let slot = (chunk_index >> below) & ((1 << (height - below)) - 1);
                    let Some(child) = inner.children.get(slot) else {
                        // `start` is past the data.
                        break std::slice::Iter::default();
                    };
                    stack.push(inner.children[slot + 1..].iter());
                    node = child;
                    height = below;
                }
                // The low bits of `start` are its offset in the leaf's aligned
                // run.
                Tree::Leaf(leaf) => {
                    let offset = start & ((packing << height) - 1);
                    break leaf.values.get(offset..).unwrap_or(&[]).iter();
                }
                Tree::Zero(_) => break std::slice::Iter::default(),
            }
        };
        Self { stack, leaf }
    }
}

impl<'a, T> Iterator for TreeIter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<&'a T> {
        loop {
            if let Some(value) = self.leaf.next() {
                return Some(value);
            }
            // The next unvisited child of the innermost node that has one.
            let mut node = loop {
                match self.stack.last_mut()?.next() {
                    Some(child) => break &**child,
                    None => {
                        self.stack.pop();
                    }
                }
            };
            // Descend to its leftmost leaf, deferring the other children of
            // each node on the way down.
            self.leaf = loop {
                match node {
                    Tree::Node(inner) => {
                        let mut children = inner.children.iter();
                        let Some(first) = children.next() else {
                            self.stack.clear();
                            return None;
                        };
                        self.stack.push(children);
                        node = first;
                    }
                    Tree::Leaf(leaf) => break leaf.values.iter(),
                    // The data is a prefix of the tree, so everything from the
                    // first zero subtree on is padding.
                    Tree::Zero(_) => {
                        self.stack.clear();
                        return None;
                    }
                }
            };
        }
    }
}

/// An iterator over the elements of a [`List`](crate::List) or
/// [`Vector`](crate::Vector), pending writes included.
pub struct Iter<'a, T, U> {
    pub(crate) tree: TreeIter<'a, T>,
    pub(crate) updates: &'a U,
    /// Whether `updates` is empty, so the common case skips a lookup per
    /// element.
    pub(crate) no_updates: bool,
    pub(crate) index: usize,
    /// Elements the tree holds; the rest up to `end` are pending pushes.
    pub(crate) committed_len: usize,
    pub(crate) end: usize,
}

impl<'a, T: Value, U: UpdateMap<T>> Iterator for Iter<'a, T, U> {
    type Item = &'a T;

    fn next(&mut self) -> Option<&'a T> {
        if self.index >= self.end {
            return None;
        }
        let index = self.index;
        self.index += 1;
        // Advance the tree walk even when a pending write overrides this
        // element, so the two stay aligned.
        let committed = if index < self.committed_len {
            self.tree.next()
        } else {
            None
        };
        if self.no_updates {
            return committed;
        }
        self.updates.get(index).or(committed)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.end - self.index;
        (remaining, Some(remaining))
    }
}

impl<T: Value, U: UpdateMap<T>> ExactSizeIterator for Iter<'_, T, U> {}

impl<T: Value, U: UpdateMap<T>> FusedIterator for Iter<'_, T, U> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_iter_yields_every_value_from_any_start() {
        let values: Vec<u64> = (0..37).collect();
        let (tree, _) = Tree::from_values(values.clone(), 4);
        for start in 0..=values.len() {
            let got: Vec<u64> = TreeIter::new(&tree, 4, start).copied().collect();
            assert_eq!(got, values[start..], "start {start}");
        }
    }

    #[test]
    fn tree_iter_walks_composite_leaves() {
        let values: Vec<[u8; 48]> = (0..6u8).map(|i| [i; 48]).collect();
        let (tree, _) = Tree::from_values(values.clone(), 3);
        let got: Vec<[u8; 48]> = TreeIter::new(&tree, 3, 2).copied().collect();
        assert_eq!(got, values[2..]);
    }

    #[test]
    fn tree_iter_crosses_leaf_boundaries_from_any_start() {
        // 512 u64s to a leaf: three leaves, the last partial.
        let values: Vec<u64> = (0..1300).collect();
        let (tree, _) = Tree::from_values(values.clone(), 9);
        for start in [0usize, 1, 511, 512, 513, 1023, 1024, 1299, 1300] {
            let got: Vec<u64> = TreeIter::new(&tree, 9, start).copied().collect();
            assert_eq!(got, values[start..], "start {start}");
        }
    }

    #[test]
    fn tree_iter_over_an_empty_tree_is_empty() {
        let (tree, _) = Tree::<u64>::from_values(Vec::new(), 4);
        assert_eq!(TreeIter::new(&tree, 4, 0).count(), 0);
    }
}
