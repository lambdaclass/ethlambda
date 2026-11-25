//! Sharing subtrees between two versions of a list that were built apart,
//! such as a state decoded from storage and a resident relative of it.

use std::sync::{Arc, OnceLock};

use crate::tree::{Node, Tree};
use crate::{Value, child_height, packing_factor};

impl<T: Value> Tree<T> {
    /// A tree equal to `orig` that reuses `base`'s node wherever the two
    /// subtrees at the same position hold the same elements.
    ///
    /// `orig` and `base` have height `height` and cover elements from `first`
    /// on. `shared_prefix` is how many elements both lists hold. A subtree
    /// wholly inside that prefix holds the same number of elements in both
    /// trees, so there equal cached hashes prove equal contents and end the
    /// walk. At the boundary a shorter list can hash the same as a longer one
    /// (a trailing zero value looks like padding), so there only comparing
    /// values counts.
    ///
    /// When `orig` has no cached hashes (it was just decoded) the walk
    /// compares values all the way down: O(n), with no hashing. Every leaf it
    /// swaps for `base`'s arrives with `base`'s cached hash.
    pub(crate) fn rebase_on(
        orig: &Arc<Self>,
        base: &Arc<Self>,
        height: usize,
        first: usize,
        shared_prefix: usize,
    ) -> Arc<Self> {
        if Arc::ptr_eq(orig, base) {
            return Arc::clone(base);
        }
        match (&**orig, &**base) {
            (Tree::Leaf(a), Tree::Leaf(b)) if a.values == b.values => Arc::clone(base),
            (Tree::Zero(a), Tree::Zero(b)) if a == b => Arc::clone(base),
            (Tree::Node(orig_node), Tree::Node(base_node)) => {
                let packing = packing_factor::<T>();
                let end = first + (packing << height);
                let hashes_prove_equal = end <= shared_prefix
                    && orig.cached_hash().is_some()
                    && orig.cached_hash() == base.cached_hash();
                if hashes_prove_equal {
                    return Arc::clone(base);
                }
                let below = child_height::<T>(height);
                let span = packing << below;
                // Children pair up by slot; one orig has past base's last
                // child has nothing to share with.
                let children: Vec<Arc<Self>> = orig_node
                    .children
                    .iter()
                    .enumerate()
                    .map(|(slot, child)| match base_node.children.get(slot) {
                        Some(base_child) => Self::rebase_on(
                            child,
                            base_child,
                            below,
                            first + slot * span,
                            shared_prefix,
                        ),
                        None => Arc::clone(child),
                    })
                    .collect();
                let all_base = children.len() == base_node.children.len()
                    && children
                        .iter()
                        .zip(&base_node.children)
                        .all(|(child, base_child)| Arc::ptr_eq(child, base_child));
                if all_base {
                    // Every element below matched, so the whole subtree does.
                    return Arc::clone(base);
                }
                let all_orig = children
                    .iter()
                    .zip(&orig_node.children)
                    .all(|(child, orig_child)| Arc::ptr_eq(child, orig_child));
                if all_orig {
                    return Arc::clone(orig);
                }
                // The contents are still orig's, so orig's hash and levels (if
                // any) hold.
                let hash = orig.cached_hash().map(OnceLock::from).unwrap_or_default();
                let levels = orig_node.levels.get().cloned().map(OnceLock::from);
                Arc::new(Tree::Node(Node {
                    hash,
                    levels: levels.unwrap_or_default(),
                    base: None,
                    children,
                }))
            }
            _ => Arc::clone(orig),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn children<T>(tree: &Tree<T>) -> &[Arc<Tree<T>>] {
        match tree {
            Tree::Node(inner) => &inner.children,
            _ => panic!("not an inner node"),
        }
    }

    #[test]
    fn only_the_changed_path_stays_unshared() {
        // Four u64 leaves under one inner node; the change is in the second.
        let per_leaf = crate::packing_factor::<u64>() << crate::max_leaf_height::<u64>();
        let depth = crate::max_leaf_height::<u64>() + 2;
        let len = 4 * per_leaf;
        let changed = per_leaf + 88;
        let base_values: Vec<u64> = (0..len as u64).collect();
        let mut orig_values = base_values.clone();
        orig_values[changed] = 99;
        let (base, _) = Tree::from_values(base_values, depth);
        let (orig, _) = Tree::from_values(orig_values, depth);
        base.hash(depth);

        let rebased = Tree::rebase_on(&orig, &base, depth, 0, len);

        // One inner node over the four leaves. The second leaf holds the
        // change, so that leaf is orig's and the root is new...
        let (rebased_leaves, base_leaves) = (children(&rebased), children(&base));
        assert!(!Arc::ptr_eq(&rebased, &base));
        assert!(!Arc::ptr_eq(&rebased_leaves[1], &base_leaves[1]));
        // ...but every unchanged leaf is base's.
        for slot in [0, 2, 3] {
            assert!(
                Arc::ptr_eq(&rebased_leaves[slot], &base_leaves[slot]),
                "leaf {slot}"
            );
        }
        // And the contents are orig's.
        assert_eq!(rebased.hash(depth), orig.hash(depth));
        assert_eq!(rebased.get(changed, depth), Some(&99));
    }

    #[test]
    fn an_identical_rebuilt_tree_becomes_the_base() {
        let values: Vec<u64> = (0..16).collect();
        let (base, _) = Tree::from_values(values.clone(), 2);
        let (orig, _) = Tree::from_values(values, 2);
        let rebased = Tree::rebase_on(&orig, &base, 2, 0, 16);
        assert!(Arc::ptr_eq(&rebased, &base));
    }

    #[test]
    fn a_trailing_zero_is_not_mistaken_for_padding() {
        // [1, 2, 3, 0] and [1, 2, 3] pack into the same chunk, so the leaves and
        // roots hash the same, but they are different lists.
        let (base, _) = Tree::<u64>::from_values(vec![1, 2, 3, 0], 1);
        let (orig, _) = Tree::<u64>::from_values(vec![1, 2, 3], 1);
        assert_eq!(base.hash(1), orig.hash(1));

        let rebased = Tree::rebase_on(&orig, &base, 1, 0, 3);
        assert!(!Arc::ptr_eq(&rebased, &base));
        assert_eq!(rebased.get(3, 1), None);
    }
}
