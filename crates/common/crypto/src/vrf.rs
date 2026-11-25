//! The Beacon Chain PQ fork's VRF tree (consensus-specs
//! `specs/_features/pq/{beacon-chain,validator}.md`, on the `pq` branch at
//! `b5d422b255db80c9bbc48f515370655ecc8bf6e5`).
//!
//! XMSS signatures are not unique, so a proposer could grind a signature-based
//! RANDAO reveal. A validator instead has a secret for each slot, derived from
//! its VRF seed, and registers as its VRF root the root of a Merkle tree of
//! depth [`VRF_TREE_DEPTH`], hashed with Keccak-256, whose leaf for a slot
//! commits to that slot's secret. Its reveal is the secret followed by the
//! leaf's branch (a `VRFProof`). The branch holds only commitments, so
//! proposing at one slot reveals no other slot's secret.
//!
//! The verifying half ([`compute_vrf_leaf`], [`fold_vrf_branch`]) is the
//! state transition's `is_valid_vrf_proof`. The deriving half
//! ([`compute_vrf_secret`], [`compute_vrf_node`], [`VrfTree`]) is the
//! validator's.
//!
//! # Cost
//!
//! A leaf commits to its index as well as its secret, so no two leaves are
//! equal and nothing but hashing all `2^31` of them yields the root: three
//! Keccak-256 calls a leaf, about 6.4 billion a tree. [`VrfTree::build`] runs
//! them across cores and keeps the `2^15` nodes [`SUBTREE_DEPTH`] levels
//! above the leaves (1 MiB), from which a proof rebuilds one `2^16`-leaf
//! subtree. [`VrfTree::to_bytes`] and [`VrfTree::from_bytes`] carry those
//! nodes, so a tree is hashed once per seed, not once per start. On an Apple
//! M4 Max's 14 cores a tree takes about 100 seconds and a proof 30 ms.

use ethlambda_types::beacon::constants::{VRF_LEAF_DOMAIN, VRF_TREE_DEPTH};
use rayon::prelude::*;

/// The specification's `VRF_SECRET_DOMAIN` (`validator.md`).
pub const VRF_SECRET_DOMAIN: &[u8] = b"VRF_SECRET";

/// How many levels above the leaves the nodes a [`VrfTree`] keeps are: a
/// proof rebuilds one subtree of this depth, about 200,000 hashes.
const SUBTREE_DEPTH: usize = 16;

/// The size of one record of ethereum-package's `vrf_state_url` file: the
/// root, four zero bytes, then the branch of leaf 0, bottom-up. See
/// [`VrfTree::from_state_record`].
pub const STATE_RECORD_SIZE: usize = 32 + 4 + 32 * VRF_TREE_DEPTH;

/// A node of the tree, a secret, or a seed.
pub type Node = [u8; 32];

/// Keccak-256's rate: the bytes one permutation absorbs.
const KECCAK_RATE: usize = 136;

/// The specification's `keccak256`, over the concatenation of `parts`.
///
/// Every input the tree hashes (a secret's preimage, a leaf's, a pair of
/// nodes) is at most 64 bytes, under one block, so this pads it into a
/// single block and runs the permutation once rather than going through a
/// streaming hasher, which the full tree's billions of calls notice.
///
/// # Panics
///
/// If the parts add up to [`KECCAK_RATE`] bytes or more.
fn keccak256(parts: &[&[u8]]) -> Node {
    let mut block = [0u8; KECCAK_RATE];
    let mut len = 0;
    for part in parts {
        block[len..len + part.len()].copy_from_slice(part);
        len += part.len();
    }
    // Keccak's own padding (`pad10*1` with the `0x01` domain byte), not
    // SHA-3's `0x06`.
    block[len] ^= 0x01;
    block[KECCAK_RATE - 1] ^= 0x80;
    let mut state = [0u64; 25];
    for (lane, chunk) in state.iter_mut().zip(block.chunks_exact(8)) {
        *lane = u64::from_le_bytes(chunk.try_into().expect("chunks of 8 bytes"));
    }
    keccak::f1600(&mut state);
    let mut out = [0u8; 32];
    for (chunk, lane) in out.chunks_exact_mut(8).zip(state.iter()) {
        chunk.copy_from_slice(&lane.to_le_bytes());
    }
    out
}

fn hash_pair(left: &Node, right: &Node) -> Node {
    keccak256(&[left, right])
}

/// `compute_vrf_secret`: the secret for `index` of the VRF tree derived from
/// `vrf_seed`.
pub fn compute_vrf_secret(vrf_seed: &Node, index: u64) -> Node {
    keccak256(&[VRF_SECRET_DOMAIN, vrf_seed, &index.to_le_bytes()])
}

/// `compute_vrf_leaf`: the leaf at `index` of a VRF tree, which commits to
/// `secret`.
pub fn compute_vrf_leaf(secret: &Node, index: u64) -> Node {
    keccak256(&[VRF_LEAF_DOMAIN, secret, &index.to_le_bytes()])
}

/// `compute_vrf_node`: the node at `index` among the nodes `height` levels
/// above the leaves of the VRF tree derived from `vrf_seed`.
///
/// The specification recurses; this walks the node's `2^height` leaves left to
/// right, keeping one finished node per level, so it allocates `height` nodes
/// rather than a level's worth.
///
/// # Panics
///
/// If the node is outside a tree of depth [`VRF_TREE_DEPTH`].
pub fn compute_vrf_node(vrf_seed: &Node, height: usize, index: u64) -> Node {
    assert!(
        height <= VRF_TREE_DEPTH && index >> (VRF_TREE_DEPTH - height) == 0,
        "node {index} at height {height} is outside the VRF tree"
    );
    let first_leaf = index << height;
    let mut finished: Vec<Node> = Vec::with_capacity(height + 1);
    for offset in 0..1u64 << height {
        let leaf_index = first_leaf + offset;
        let mut node = compute_vrf_leaf(&compute_vrf_secret(vrf_seed, leaf_index), leaf_index);
        // Each trailing one bit of `offset` is a level whose left sibling is
        // already finished.
        for _ in 0..offset.trailing_ones() {
            let left = finished.pop().expect("a left sibling per trailing one");
            node = hash_pair(&left, &node);
        }
        finished.push(node);
    }
    finished.pop().expect("the last leaf folds up to the node")
}

/// The root a `VRFProof` folds to at `slot`: the leaf committing to `secret`
/// at index `slot`, hashed up through `branch` (siblings bottom-up) on the
/// side each bit of `slot` gives. `is_valid_vrf_proof` is this compared with
/// the proposer's registered VRF root.
pub fn fold_vrf_branch<'a>(
    secret: &Node,
    branch: impl IntoIterator<Item = &'a Node>,
    slot: u64,
) -> Node {
    let mut value = compute_vrf_leaf(secret, slot);
    for (height, sibling) in branch.into_iter().enumerate() {
        value = if (slot >> height) & 1 == 1 {
            hash_pair(sibling, &value)
        } else {
            hash_pair(&value, sibling)
        };
    }
    value
}

/// Why [`VrfTree::from_bytes`] refused its input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VrfTreeError {
    #[error("{actual} bytes, where the nodes of a VRF tree take {expected}")]
    Length { expected: usize, actual: usize },
    #[error("the nodes are not those of the tree this seed derives")]
    WrongSeed,
    #[error("the nodes do not fold to the root stored with them")]
    Corrupt,
    #[error("the state is for leaf {0}, where only leaf 0's is read")]
    StateIndex(u32),
}

/// A validator's VRF tree: its seed, and what it keeps of the nodes.
pub struct VrfTree {
    seed: Node,
    depth: usize,
    kept: Kept,
}

/// What a [`VrfTree`] keeps beside its seed.
enum Kept {
    /// Every node [`SUBTREE_DEPTH`] levels above the leaves, left to right:
    /// a tree hashed in full. One node, the root, for a tree no deeper than
    /// [`SUBTREE_DEPTH`].
    Subtrees(Vec<Node>),
    /// The root and the branch of leaf 0, bottom-up: the compact state
    /// ethereum-package publishes for its genesis validators. A slot below
    /// `2^k` shares its ancestors from level `k` up with leaf 0, whose
    /// siblings there `branch` holds, so its proof hashes only the first
    /// `2^k` leaves: a few milliseconds on a young chain, and still seconds
    /// a decade in.
    Leftmost { root: Node, branch: Vec<Node> },
}

impl VrfTree {
    /// The tree the specification derives from `vrf_seed`, over all `2^31`
    /// leaves (`compute_vrf_root`'s tree). Minutes of every core: see the
    /// module doc. Blocking, and parallel over rayon's pool.
    pub fn build(vrf_seed: Node) -> Self {
        Self::with_depth(vrf_seed, VRF_TREE_DEPTH)
    }

    /// The tree over the first `2^depth` leaves only: the leftmost node
    /// `depth` levels above the leaves of [`Self::build`]'s tree, as a tree of
    /// its own. Its root is not the validator's VRF root unless `depth` is
    /// [`VRF_TREE_DEPTH`], so its proofs verify nowhere: for tests, which
    /// cannot hash a whole tree.
    ///
    /// # Panics
    ///
    /// If `depth` exceeds [`VRF_TREE_DEPTH`].
    pub fn with_depth(vrf_seed: Node, depth: usize) -> Self {
        assert!(depth <= VRF_TREE_DEPTH, "a VRF tree is at most 31 deep");
        let subtree_depth = depth.min(SUBTREE_DEPTH);
        let subtree_roots = (0..1u64 << (depth - subtree_depth))
            .into_par_iter()
            .map(|index| compute_vrf_node(&vrf_seed, subtree_depth, index))
            .collect();
        Self {
            seed: vrf_seed,
            depth,
            kept: Kept::Subtrees(subtree_roots),
        }
    }

    /// The tree of `vrf_seed` from its root and the branch of leaf 0
    /// (bottom-up, one sibling per level), without hashing it: the
    /// branch must fold leaf 0, recomputed from the seed, to the root, which
    /// ties both to this seed. Its depth is the branch's length.
    ///
    /// Proofs then hash the leaves below the slot's highest set bit (see
    /// [`Kept::Leftmost`]) instead of one `2^16`-leaf subtree.
    pub fn from_compact_state(
        vrf_seed: Node,
        root: Node,
        branch: Vec<Node>,
    ) -> Result<Self, VrfTreeError> {
        if branch.len() > VRF_TREE_DEPTH {
            return Err(VrfTreeError::Length {
                expected: 32 * VRF_TREE_DEPTH,
                actual: 32 * branch.len(),
            });
        }
        if fold_vrf_branch(&compute_vrf_secret(&vrf_seed, 0), &branch, 0) != root {
            return Err(VrfTreeError::WrongSeed);
        }
        Ok(Self {
            seed: vrf_seed,
            depth: branch.len(),
            kept: Kept::Leftmost { root, branch },
        })
    }

    /// The root and the branch of leaf 0, which
    /// [`Self::from_compact_state`] restores the tree from.
    pub fn compact_state(&self) -> (Node, Vec<Node>) {
        match &self.kept {
            Kept::Leftmost { root, branch } => (*root, branch.clone()),
            Kept::Subtrees(_) => {
                let mut proof = self.proof(0).expect("leaf 0 is in every tree");
                proof.remove(0);
                (self.root(), proof)
            }
        }
    }

    /// The tree of `vrf_seed` from one record of ethereum-package's
    /// `vrf_state_url` file ([`STATE_RECORD_SIZE`] bytes): the root, four
    /// zero bytes, then leaf 0's branch, the layout the package's README
    /// gives and its published file has. Checked as
    /// [`Self::from_compact_state`] checks.
    pub fn from_state_record(vrf_seed: Node, record: &[u8]) -> Result<Self, VrfTreeError> {
        if record.len() != STATE_RECORD_SIZE {
            return Err(VrfTreeError::Length {
                expected: STATE_RECORD_SIZE,
                actual: record.len(),
            });
        }
        let root: Node = record[..32].try_into().expect("32 bytes");
        let leaf = u32::from_le_bytes(record[32..36].try_into().expect("4 bytes"));
        if leaf != 0 {
            return Err(VrfTreeError::StateIndex(leaf));
        }
        let branch = record[36..]
            .chunks_exact(32)
            .map(|node| node.try_into().expect("chunks of 32 bytes"))
            .collect();
        Self::from_compact_state(vrf_seed, root, branch)
    }

    /// This tree as one record of a `vrf_state_url` file, which
    /// [`Self::from_state_record`] reads.
    ///
    /// # Panics
    ///
    /// If the tree is not [`VRF_TREE_DEPTH`] deep.
    pub fn to_state_record(&self) -> Vec<u8> {
        assert_eq!(
            self.depth, VRF_TREE_DEPTH,
            "a state record is a whole tree's"
        );
        let (root, branch) = self.compact_state();
        let mut record = Vec::with_capacity(STATE_RECORD_SIZE);
        record.extend_from_slice(&root);
        record.extend_from_slice(&0u32.to_le_bytes());
        record.extend_from_slice(&branch.concat());
        record
    }

    fn subtree_depth(&self) -> usize {
        self.depth.min(SUBTREE_DEPTH)
    }

    /// `compute_vrf_root`: the tree's root, which a validator registers as its
    /// `vrf_root`.
    pub fn root(&self) -> Node {
        match &self.kept {
            Kept::Subtrees(subtree_roots) => {
                let mut nodes = subtree_roots.clone();
                reduce(&mut nodes, 0, &mut Vec::new());
                nodes[0]
            }
            Kept::Leftmost { root, .. } => *root,
        }
    }

    /// `compute_vrf_proof`: the secret for `slot`, then the branch of the leaf
    /// at index `slot`, siblings bottom-up. `None` for a slot past the tree's
    /// last leaf, which no proof exists for.
    pub fn proof(&self, slot: u64) -> Option<Vec<Node>> {
        if slot >> self.depth != 0 {
            return None;
        }
        let subtree_depth = self.subtree_depth();
        let subtree = slot >> subtree_depth;
        let first_leaf = subtree << subtree_depth;
        let mut proof = Vec::with_capacity(self.depth + 1);
        proof.push(compute_vrf_secret(&self.seed, slot));
        let mut nodes: Vec<Node> = (first_leaf..first_leaf + (1 << subtree_depth))
            .map(|index| compute_vrf_leaf(&compute_vrf_secret(&self.seed, index), index))
            .collect();
        reduce(&mut nodes, (slot - first_leaf) as usize, &mut proof);
        match &self.kept {
            Kept::Subtrees(subtree_roots) => {
                let mut roots = subtree_roots.clone();
                reduce(&mut roots, subtree as usize, &mut proof);
            }
            Kept::Leftmost { branch, .. } => {
                // The slot's ancestors from `span` levels up are leaf 0's, so
                // only the subtrees below them are hashed.
                let span =
                    ((u64::BITS - slot.leading_zeros()) as usize).clamp(subtree_depth, self.depth);
                let mut roots: Vec<Node> = (0..1u64 << (span - subtree_depth))
                    .into_par_iter()
                    .map(|index| compute_vrf_node(&self.seed, subtree_depth, index))
                    .collect();
                reduce(&mut roots, subtree as usize, &mut proof);
                proof.extend_from_slice(&branch[span..]);
            }
        }
        Some(proof)
    }

    /// What the tree keeps, then its root: everything [`Self::from_bytes`]
    /// needs beside the seed. A tree hashed in full keeps its nodes
    /// [`SUBTREE_DEPTH`] levels up (1 MiB), one restored from a compact
    /// state keeps leaf 0's branch (1 KiB). They are commitments, so the
    /// bytes reveal no secret.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = match &self.kept {
            Kept::Subtrees(subtree_roots) => subtree_roots.concat(),
            Kept::Leftmost { branch, .. } => branch.concat(),
        };
        bytes.extend_from_slice(&self.root());
        bytes
    }

    /// The full-depth tree of `vrf_seed` from the bytes [`Self::to_bytes`]
    /// gave, without hashing it again, told apart by their length.
    ///
    /// For kept subtree nodes two checks stand in for the hashing: the first
    /// node is recomputed from the seed (one subtree), which refuses another
    /// seed's nodes, and the nodes must fold to the root stored after them,
    /// which refuses damaged ones. About 230,000 hashes. A compact state is
    /// checked as [`Self::from_compact_state`] checks it.
    pub fn from_bytes(vrf_seed: Node, bytes: &[u8]) -> Result<Self, VrfTreeError> {
        let mut nodes: Vec<Node> = bytes
            .chunks_exact(32)
            .map(|node| node.try_into().expect("chunks of 32 bytes"))
            .collect();
        let node_count = 1usize << (VRF_TREE_DEPTH - SUBTREE_DEPTH);
        let expected = 32 * (node_count + 1);
        if bytes.len() == 32 * (VRF_TREE_DEPTH + 1) {
            let root = nodes.pop().expect("the root follows the branch");
            return Self::from_compact_state(vrf_seed, root, nodes);
        }
        if bytes.len() != expected {
            return Err(VrfTreeError::Length {
                expected,
                actual: bytes.len(),
            });
        }
        let stored_root = nodes.pop().expect("the root follows the nodes");
        if nodes[0] != compute_vrf_node(&vrf_seed, SUBTREE_DEPTH, 0) {
            return Err(VrfTreeError::WrongSeed);
        }
        let tree = Self {
            seed: vrf_seed,
            depth: VRF_TREE_DEPTH,
            kept: Kept::Subtrees(nodes),
        };
        if tree.root() != stored_root {
            return Err(VrfTreeError::Corrupt);
        }
        Ok(tree)
    }
}

/// Folds `nodes` (a power-of-two layer) to its root in `nodes[0]`, pushing
/// the sibling of the node at `index` at every level onto `branch`.
fn reduce(nodes: &mut Vec<Node>, mut index: usize, branch: &mut Vec<Node>) {
    while nodes.len() > 1 {
        branch.push(nodes[index ^ 1]);
        let next: Vec<Node> = nodes
            .chunks_exact(2)
            .map(|pair| hash_pair(&pair[0], &pair[1]))
            .collect();
        *nodes = next;
        index /= 2;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest as _;

    fn hex32(text: &str) -> Node {
        hex::decode(text).unwrap().try_into().unwrap()
    }

    /// The seed `00 01 .. 1f`.
    fn seed() -> Node {
        std::array::from_fn(|index| index as u8)
    }

    /// The specification's `compute_vrf_node`, as it is written.
    fn recursive_node(vrf_seed: &Node, height: usize, index: u64) -> Node {
        if height == 0 {
            return compute_vrf_leaf(&compute_vrf_secret(vrf_seed, index), index);
        }
        let left = recursive_node(vrf_seed, height - 1, 2 * index);
        let right = recursive_node(vrf_seed, height - 1, 2 * index + 1);
        hash_pair(&left, &right)
    }

    #[test]
    fn keccak256_is_not_sha3() {
        // Keccak-256 of the empty string, which SHA3-256 hashes to a7ffc6f8...
        assert_eq!(
            keccak256(&[]),
            hex32("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        );
    }

    #[test]
    fn nodes_match_the_specifications_recursion() {
        let seed = seed();
        for (height, index) in [(0, 0), (0, 5), (1, 3), (5, 0), (5, 9), (9, 2)] {
            assert_eq!(
                compute_vrf_node(&seed, height, index),
                recursive_node(&seed, height, index),
                "height {height}, index {index}"
            );
        }
        // The last node of a level, at the tree's edge.
        let last = (1 << (VRF_TREE_DEPTH - 3)) - 1;
        assert_eq!(
            compute_vrf_node(&seed, 3, last),
            recursive_node(&seed, 3, last)
        );
    }

    #[test]
    fn a_shallow_tree_is_the_full_trees_leftmost_node() {
        let seed = seed();
        // Below, at and above the depth of a kept subtree.
        for depth in [0, 3, SUBTREE_DEPTH, SUBTREE_DEPTH + 2] {
            let tree = VrfTree::with_depth(seed, depth);
            assert_eq!(
                tree.root(),
                compute_vrf_node(&seed, depth, 0),
                "depth {depth}"
            );
        }
    }

    #[test]
    fn a_proof_reveals_its_slots_secret_and_folds_to_the_root() {
        let seed = seed();
        let depth = SUBTREE_DEPTH + 2;
        let tree = VrfTree::with_depth(seed, depth);
        let root = tree.root();
        let last = (1 << depth) - 1;
        for slot in [0, 1, 5, (1 << SUBTREE_DEPTH) - 1, 1 << SUBTREE_DEPTH, last] {
            let proof = tree.proof(slot).unwrap();
            assert_eq!(proof.len(), depth + 1);
            assert_eq!(proof[0], compute_vrf_secret(&seed, slot), "slot {slot}");
            assert_eq!(
                fold_vrf_branch(&proof[0], &proof[1..], slot),
                root,
                "slot {slot}"
            );
            // The leaf commits to its index: the same secret and branch do not
            // open the neighbouring leaf, nor does another secret this one.
            assert_ne!(fold_vrf_branch(&proof[0], &proof[1..], slot ^ 1), root);
            assert_ne!(fold_vrf_branch(&[1; 32], &proof[1..], slot), root);
        }
        assert!(tree.proof(last + 1).is_none());
    }

    /// A proof's branch holds commitments only: no node of it is a secret of
    /// the tree, in particular not the neighbouring slot's, which the leaf
    /// sibling was before leaves committed to secrets.
    #[test]
    fn a_proof_reveals_no_other_secret() {
        let seed = seed();
        let tree = VrfTree::with_depth(seed, 4);
        let proof = tree.proof(6).unwrap();
        let secrets: Vec<Node> = (0..16)
            .map(|index| compute_vrf_secret(&seed, index))
            .collect();
        assert!(proof[1..].iter().all(|node| !secrets.contains(node)));
        assert_eq!(proof[1], compute_vrf_leaf(&secrets[7], 7));
    }

    /// Known answers from a transcription of the specification's functions
    /// over an independent Keccak-256, for the seed `00 01 .. 1f`: the domain
    /// tags, the little-endian index and the order of every concatenation.
    #[test]
    fn known_answers() {
        let seed = seed();
        let secret = compute_vrf_secret(&seed, 0);
        assert_eq!(
            secret,
            hex32("568e22331e25e613a84a6a86df3f442e2f7f994ccce0b746088fb737c2bc0e20")
        );
        assert_eq!(
            compute_vrf_secret(&seed, (1 << 31) - 1),
            hex32("7d65715bc75677b7ae70b0e3a287a883b6424dbdc7fe12476e14a2a28e5f4a72")
        );
        assert_eq!(
            compute_vrf_leaf(&secret, 0),
            hex32("7858a2fe40f519a1db8508fba150a5d89a2f8e6e5c784eb6b5c36728a4364af2")
        );
        assert_eq!(
            compute_vrf_node(&seed, 4, 5),
            hex32("e216d7728aa69ed5ff228641a373039fb56c1bdda676edf8e012443af726e8c6")
        );
        assert_eq!(
            compute_vrf_node(&seed, 3, (1 << 28) - 1),
            hex32("c70649c366c4690b4d9977254f45cef88aa2cb4f0b0a0b08e8d42a6f95a5020e")
        );

        // A depth-10 tree's proofs are the first eleven nodes of the full
        // tree's `compute_vrf_proof`. SHA-256 fingerprints their bytes.
        let tree = VrfTree::with_depth(seed, 10);
        assert_eq!(
            tree.root(),
            hex32("e2fd22f54650f9bb431288d5632b94b406024a411db4fef773eacec0fae253bb")
        );
        for (slot, fingerprint) in [
            (
                0,
                "53b437b21a44e9def0f0a202bf515f0182f652a758a0446318262d9d612687db",
            ),
            (
                5,
                "f22b4ec50f24ae2754eddd04eefd08e52d63b1c13aa863f6b9c4df064afaf9f8",
            ),
            (
                1023,
                "dc21b0ac18f3119cc77117d501050a2c4fa90299aa285bb5e9cd8b90bd575d07",
            ),
        ] {
            let proof = tree.proof(slot).unwrap().concat();
            let digest: Node = sha2::Sha256::digest(proof).into();
            assert_eq!(digest, hex32(fingerprint), "slot {slot}");
        }
    }

    #[test]
    fn the_kept_nodes_restore_the_tree_for_their_seed_only() {
        let seed = seed();
        // A full-depth tree is too slow to hash here, so the nodes past the
        // first are arbitrary: restoring never rehashes the leaves under them.
        let mut nodes = vec![[7u8; 32]; 1 << (VRF_TREE_DEPTH - SUBTREE_DEPTH)];
        nodes[0] = compute_vrf_node(&seed, SUBTREE_DEPTH, 0);
        let tree = VrfTree {
            seed,
            depth: VRF_TREE_DEPTH,
            kept: Kept::Subtrees(nodes),
        };
        let bytes = tree.to_bytes();

        let restored = VrfTree::from_bytes(seed, &bytes).unwrap();
        assert_eq!(restored.to_bytes(), bytes);
        let proof = restored.proof(9).unwrap();
        assert_eq!(proof.len(), VRF_TREE_DEPTH + 1);
        assert_eq!(fold_vrf_branch(&proof[0], &proof[1..], 9), tree.root());
        assert!(restored.proof(1 << VRF_TREE_DEPTH).is_none());

        assert_eq!(
            VrfTree::from_bytes([9; 32], &bytes).err(),
            Some(VrfTreeError::WrongSeed)
        );
        assert_eq!(
            VrfTree::from_bytes(seed, &bytes[32..]).err(),
            Some(VrfTreeError::Length {
                expected: bytes.len(),
                actual: bytes.len() - 32,
            })
        );
        // One flipped bit in a node past the first, and one in the root.
        for position in [32 * 1000, bytes.len() - 1] {
            let mut damaged = bytes.clone();
            damaged[position] ^= 1;
            assert_eq!(
                VrfTree::from_bytes(seed, &damaged).err(),
                Some(VrfTreeError::Corrupt)
            );
        }
    }

    /// A tree restored from its root and leaf 0's branch proves exactly as
    /// the tree hashed in full does, on both sides of every power of two the
    /// restored tree's hashing span changes at.
    #[test]
    fn a_compact_state_proves_as_the_full_tree_does() {
        let seed = seed();
        let depth = 20;
        let full = VrfTree::with_depth(seed, depth);
        let (root, branch) = full.compact_state();
        assert_eq!(branch.len(), depth);
        assert_eq!(root, full.root());
        let compact = VrfTree::from_compact_state(seed, root, branch.clone()).unwrap();
        assert_eq!(compact.root(), root);
        let last = (1u64 << depth) - 1;
        for slot in [
            0,
            1,
            2,
            65_535,
            65_536,
            65_537,
            131_071,
            131_072,
            1 << 19,
            last,
        ] {
            let proof = compact.proof(slot).unwrap();
            assert_eq!(proof, full.proof(slot).unwrap(), "slot {slot}");
            assert_eq!(fold_vrf_branch(&proof[0], &proof[1..], slot), root);
        }
        assert!(compact.proof(last + 1).is_none());

        // The branch must fold this seed's leaf 0 to the root.
        assert_eq!(
            VrfTree::from_compact_state([9; 32], root, branch.clone()).err(),
            Some(VrfTreeError::WrongSeed)
        );
        let mut damaged = branch;
        damaged[7][0] ^= 1;
        assert_eq!(
            VrfTree::from_compact_state(seed, root, damaged).err(),
            Some(VrfTreeError::WrongSeed)
        );
    }

    /// A full-depth compact state, which is too slow to hash here, built
    /// from leaf 0's true branch in the first subtree and arbitrary siblings
    /// above it: the record and byte forms restore it, and a slot in the
    /// first subtree proves against its root.
    #[test]
    fn a_state_record_restores_the_tree_for_its_seed_only() {
        let seed = seed();
        let mut branch = VrfTree::with_depth(seed, SUBTREE_DEPTH).compact_state().1;
        branch.extend((SUBTREE_DEPTH..VRF_TREE_DEPTH).map(|height| [height as u8; 32]));
        let root = fold_vrf_branch(&compute_vrf_secret(&seed, 0), &branch, 0);
        let tree = VrfTree::from_compact_state(seed, root, branch).unwrap();

        let record = tree.to_state_record();
        assert_eq!(record.len(), STATE_RECORD_SIZE);
        assert_eq!(&record[..32], &root);
        assert_eq!(&record[32..36], &[0; 4]);
        let restored = VrfTree::from_state_record(seed, &record).unwrap();
        let reloaded = VrfTree::from_bytes(seed, &tree.to_bytes()).unwrap();
        for slot in [0, 9, 65_535] {
            let proof = restored.proof(slot).unwrap();
            assert_eq!(fold_vrf_branch(&proof[0], &proof[1..], slot), root);
            assert_eq!(reloaded.proof(slot).unwrap(), proof);
        }

        assert_eq!(
            VrfTree::from_state_record([9; 32], &record).err(),
            Some(VrfTreeError::WrongSeed)
        );
        let mut other_leaf = record.clone();
        other_leaf[32] = 1;
        assert_eq!(
            VrfTree::from_state_record(seed, &other_leaf).err(),
            Some(VrfTreeError::StateIndex(1))
        );
        assert_eq!(
            VrfTree::from_state_record(seed, &record[1..]).err(),
            Some(VrfTreeError::Length {
                expected: STATE_RECORD_SIZE,
                actual: STATE_RECORD_SIZE - 1,
            })
        );
    }

    /// The tree `compute_vrf_root` defines, hashed whole: about 100 seconds
    /// of every core, so not part of an ordinary run.
    #[test]
    #[ignore = "hashes all 2^31 leaves: minutes of every core"]
    fn the_whole_tree_proves_at_both_ends_and_survives_its_byte_form() {
        let seed = seed();
        let tree = VrfTree::build(seed);
        let root = tree.root();
        // The root is the fold of the two halves, each a node of its own.
        let Kept::Subtrees(subtree_roots) = &tree.kept else {
            panic!("a hashed tree keeps its subtrees");
        };
        assert_eq!(compute_vrf_node(&seed, SUBTREE_DEPTH, 0), subtree_roots[0]);
        let last = (1u64 << VRF_TREE_DEPTH) - 1;
        let restored = VrfTree::from_bytes(seed, &tree.to_bytes()).unwrap();
        let compact = VrfTree::from_state_record(seed, &tree.to_state_record()).unwrap();
        assert_eq!(restored.root(), root);
        assert_eq!(compact.root(), root);
        for slot in [0, 1, 70_000, 123_456_789, last] {
            let proof = restored.proof(slot).unwrap();
            assert_eq!(proof.len(), VRF_TREE_DEPTH + 1);
            assert_eq!(
                fold_vrf_branch(&proof[0], &proof[1..], slot),
                root,
                "slot {slot}"
            );
            if slot < 1 << 24 {
                assert_eq!(compact.proof(slot).unwrap(), proof, "slot {slot}");
            }
        }
        assert!(restored.proof(last + 1).is_none());
        println!("root {}", hex::encode(root));
    }
}
