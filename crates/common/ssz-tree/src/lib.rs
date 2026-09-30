//! Persistent binary Merkle trees for SSZ lists and vectors.
//!
//! [`List`] and [`Vector`] keep their elements in a tree instead of a
//! `Vec`. The tree has the shape of the type's SSZ Merkle tree, so every node
//! caches its own hash, and a clone shares every node with the original
//! through `Arc`. After a write, only the nodes on the paths to the changed
//! leaves are rebuilt and rehashed; the rest are shared with the previous
//! version, cached hashes included.
//!
//! # Leaves hold a run of elements
//!
//! A leaf is not one SSZ chunk but a whole subtree's worth of elements, about
//! `LEAF_BYTES` of them, stored contiguously. The Merkle shape is still the
//! SSZ one: a leaf hashes its elements up to its own height, so the root is
//! unchanged, but there are far fewer nodes to walk and allocate. A lookup
//! descends to the leaf and indexes into it, and iteration walks each leaf as
//! a slice. The cost is on writes: a rebuilt leaf copies its run and rehashes
//! its own subtree, so a composite leaf keeps each element's root to rehash
//! only the elements that changed.
//!
//! Inner nodes are wide in the same way: each holds about `NODE_BYTES` of
//! child pointers and spans that many binary levels at once, so a lookup
//! crosses a handful of nodes. A rebuilt inner node rehashes its binary levels
//! from its children's cached roots.
//!
//! The result is shaped much like a B+-tree over indices: page-sized nodes
//! with a high fan-out, and every element in the leaves. Unlike one, it has no
//! keys to search and never splits or rebalances. An index's bits pick the
//! child at each node, the shape is fixed by the SSZ depth, and a write copies
//! the path to its leaf rather than updating in place.
//!
//! Modeled on Sigma Prime's milhouse (the tree lighthouse keeps its
//! `BeaconState` lists in), but implementing the libssz traits this workspace
//! derives, so a [`List`] can replace a `libssz_types::SszList` field of a
//! derived container.
//!
//! # Buffered writes
//!
//! `get_mut`, `push` and `IndexMut` leave the tree alone. They write into an
//! [`UpdateMap`], and `apply_updates` later folds every pending write into the
//! tree in one pass, so N writes rebuild their paths once rather than N times.
//! Reads check the pending writes first, so a write is visible as soon as it
//! is made.
//!
//! Hashing with writes still pending gives the right root, but computes it on
//! a throwaway copy, so none of the new hashes are kept. Call `apply_updates`
//! before hashing on a hot path.
//!
//! # The hasher argument
//!
//! `HashTreeRoot::hash_tree_root` takes a hasher; these types ignore it and
//! always use SHA-256 (`libssz_merkle::Sha2Hasher`). A cached hash is only
//! valid for the function that produced it, and SHA-256 is the only one the
//! consensus specs use.

mod interface;
mod iter;
mod list;
mod rebase;
mod tree;
mod update_map;
mod vector;

pub use iter::Iter;
pub use list::List;
pub use update_map::{UpdateMap, VecMap};
pub use vector::Vector;

use libssz::{SszDecode, SszEncode};
use libssz_merkle::HashTreeRoot;

/// A 32-byte Merkle node.
pub(crate) type Hash256 = libssz_merkle::Node;

/// Bytes in one Merkle chunk.
const BYTES_PER_CHUNK: usize = 32;

/// What a tree can hold: anything SSZ-encodable and merkleizable that can
/// be shared across threads.
pub trait Value:
    SszEncode + SszDecode + HashTreeRoot + Clone + PartialEq + Send + Sync + 'static
{
}

impl<T> Value for T where
    T: SszEncode + SszDecode + HashTreeRoot + Clone + PartialEq + Send + Sync + 'static
{
}

/// Whether `T` is packed several to a chunk (an SSZ basic type) rather than
/// stored one per leaf (a composite).
pub(crate) fn is_packed<T: Value>() -> bool {
    T::is_basic_type()
}

/// Elements per leaf: `32 / size` for a packed type, 1 for a composite.
///
/// # Panics
///
/// On a basic type whose size does not divide 32, such as a 20-byte address.
/// `libssz_types::SszList` packs those across chunk boundaries, which a tree
/// with one chunk per leaf cannot reproduce, so accepting one would silently
/// produce a different root.
pub(crate) fn packing_factor<T: Value>() -> usize {
    if !is_packed::<T>() {
        return 1;
    }
    let size = <T as SszEncode>::fixed_size();
    assert!(
        size > 0 && BYTES_PER_CHUNK.is_multiple_of(size),
        "a packed element's size must divide {BYTES_PER_CHUNK}, got {size}"
    );
    BYTES_PER_CHUNK / size
}

/// Height of the tree for a type holding at most `limit` elements: the
/// smallest `d` with `2^d` chunks holding `limit` elements, which is the depth
/// SSZ merkleization pads the type to.
pub(crate) fn tree_depth<T: Value>(limit: usize) -> usize {
    let chunks = limit.div_ceil(packing_factor::<T>());
    chunks.next_power_of_two().trailing_zeros() as usize
}

/// Roughly how many bytes of elements one leaf holds: a page, so a lookup ends
/// in one contiguous run and iteration walks few nodes.
pub(crate) const LEAF_BYTES: usize = 4096;

/// The height of `T`'s leaves in a tree tall enough to hold them: the largest
/// power-of-two run of elements whose in-memory size fits in [`LEAF_BYTES`],
/// counted in chunks. At least one chunk, so a leaf is never below height 0.
pub(crate) fn max_leaf_height<T: Value>() -> usize {
    let fits = (LEAF_BYTES / size_of::<T>().max(1)).max(1);
    let elements = 1usize << fits.ilog2();
    let chunks = (elements / packing_factor::<T>()).max(1);
    chunks.ilog2() as usize
}

/// The height of the leaves in a tree of height `depth`: [`max_leaf_height`],
/// or the whole tree if it is shorter than that, in which case the root is
/// the only leaf.
pub(crate) fn leaf_height<T: Value>(depth: usize) -> usize {
    max_leaf_height::<T>().min(depth)
}

/// Roughly how many bytes of child pointers one inner node holds, so a lookup
/// crosses a handful of nodes rather than one per binary level.
pub(crate) const NODE_BYTES: usize = 4096;

/// How many binary levels one inner node spans: it has up to `2^NODE_LEVELS`
/// children, each one `Arc` wide.
pub(crate) const NODE_LEVELS: usize =
    (NODE_BYTES / size_of::<std::sync::Arc<()>>()).ilog2() as usize;

/// The height of the children of the inner node at `height`.
///
/// Inner nodes sit every [`NODE_LEVELS`] levels above the leaves, counted up
/// from [`max_leaf_height`], so only the root can span fewer levels than that.
/// Only meaningful above the leaf height: a tree no taller than a leaf has no
/// inner nodes.
pub(crate) fn child_height<T: Value>(height: usize) -> usize {
    let leaf = max_leaf_height::<T>();
    debug_assert!(height > leaf, "no inner node at height {height}");
    leaf + NODE_LEVELS * ((height - leaf - 1) / NODE_LEVELS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_types_pack_to_a_chunk_and_composites_do_not() {
        assert_eq!(packing_factor::<u8>(), 32);
        assert_eq!(packing_factor::<u64>(), 4);
        assert_eq!(packing_factor::<[u8; 32]>(), 1);
        // Longer than a chunk, so not an SSZ basic type.
        assert_eq!(packing_factor::<[u8; 48]>(), 1);
    }

    #[test]
    fn depth_is_the_ssz_padding_depth() {
        assert_eq!(tree_depth::<u64>(0), 0);
        assert_eq!(tree_depth::<u64>(4), 0);
        assert_eq!(tree_depth::<u64>(5), 1);
        assert_eq!(tree_depth::<u64>(1 << 40), 38);
        assert_eq!(tree_depth::<[u8; 48]>(5), 3);
        assert_eq!(tree_depth::<[u8; 48]>(1 << 40), 40);
    }

    #[test]
    fn a_leaf_holds_about_a_page_of_elements() {
        // 512 u64s = 128 chunks.
        assert_eq!(max_leaf_height::<u64>(), 7);
        // 4096 u8s = 128 chunks.
        assert_eq!(max_leaf_height::<u8>(), 7);
        // 128 roots, one chunk each.
        assert_eq!(max_leaf_height::<[u8; 32]>(), 7);
        // 4096 / 48 = 85, rounded down to 64.
        assert_eq!(max_leaf_height::<[u8; 48]>(), 6);
        // Wider than a page: one element per leaf.
        assert_eq!(max_leaf_height::<[u8; 5000]>(), 0);
    }

    #[test]
    fn an_inner_node_holds_about_a_page_of_children() {
        assert_eq!(NODE_LEVELS, 9);
        // u64 leaves sit at height 7: nodes at 16, 25, 34, and the root at 38.
        assert_eq!(child_height::<u64>(8), 7);
        assert_eq!(child_height::<u64>(16), 7);
        assert_eq!(child_height::<u64>(17), 16);
        assert_eq!(child_height::<u64>(25), 16);
        assert_eq!(child_height::<u64>(38), 34);
    }

    #[test]
    fn a_tree_shorter_than_a_leaf_is_one_leaf() {
        assert_eq!(leaf_height::<u64>(3), 3);
        assert_eq!(leaf_height::<u64>(38), 7);
    }

    #[test]
    #[should_panic(expected = "must divide 32")]
    fn a_basic_type_that_straddles_chunks_is_refused() {
        packing_factor::<[u8; 20]>();
    }
}
