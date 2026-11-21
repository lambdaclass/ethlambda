//! The Beacon Chain PQ fork's VRF tree (consensus-specs
//! `specs/_features/pq/{beacon-chain,validator}.md`, on the `pq` branch at
//! `2f43bc0f989f47af81df390a90bc1f78e2436323`, the pq-devnet-0 spec).
//!
//! XMSS signatures are not unique, so a proposer could grind a signature-based
//! RANDAO reveal. A validator instead registers as its VRF root the root of a
//! Merkle tree of depth [`VRF_TREE_DEPTH`], hashed with Keccak-256, whose leaf
//! for a slot is `keccak256(vrf_seed || le64(slot))`. Its reveal is the leaf
//! followed by the leaf's branch (a `VRFProof`).
//!
//! The verifying half ([`fold_vrf_branch`]) is the state transition's
//! `is_valid_vrf_proof`. The deriving half ([`compute_vrf_leaf`],
//! [`compute_vrf_node`], [`VrfTree`]) is the validator's.
//!
//! # Cost
//!
//! A leaf hashes its index with the seed, so no two leaves are equal and
//! nothing but hashing all `2^31` of them yields the root: about two
//! Keccak-256 calls a leaf, 4.3 billion a tree. [`VrfTree::build`] runs them
//! across cores and keeps the `2^15` nodes [`SUBTREE_DEPTH`] levels above the
//! leaves (1 MiB), from which a proof rebuilds one `2^16`-leaf subtree.
//! [`VrfTree::to_bytes`] and [`VrfTree::from_bytes`] carry those nodes, so a
//! tree is hashed once per seed, not once per start. ethereum-package
//! publishes each genesis validator's root and leaf 0's branch, from which
//! [`VrfTree::from_state_record`] proves without hashing the tree.

use ethlambda_types::beacon::constants::VRF_TREE_DEPTH;
use rayon::prelude::*;

/// How many levels above the leaves the nodes a [`VrfTree`] keeps are: a
/// proof rebuilds one subtree of this depth, about 200,000 hashes.
const SUBTREE_DEPTH: usize = 16;

/// The size of one record of ethereum-package's `vrf_state_url` file: the
/// root, four zero bytes, then the branch of leaf 0, bottom-up. See
/// [`VrfTree::from_state_record`].
pub const STATE_RECORD_SIZE: usize = 32 + 4 + 32 * VRF_TREE_DEPTH;

/// A node of the tree, or a seed.
pub type Node = [u8; 32];

/// Keccak-256's rate: the bytes one permutation absorbs.
const KECCAK_RATE: usize = 136;

/// The specification's `keccak256`, over the concatenation of `parts`.
///
/// Every input the tree hashes (a leaf's preimage, a pair of nodes) is at
/// most 64 bytes, under one block, so this pads it into a
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

/// `compute_vrf_leaf`: the leaf at `index` of the VRF tree derived from
/// `vrf_seed`, `keccak256(vrf_seed || uint_to_bytes(index))`.
pub fn compute_vrf_leaf(vrf_seed: &Node, index: u64) -> Node {
    keccak256(&[vrf_seed, &index.to_le_bytes()])
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
        let mut node = compute_vrf_leaf(vrf_seed, leaf_index);
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

/// The root a `VRFProof` folds to at `slot`: its revealed `leaf`, hashed up
/// through `branch` (siblings bottom-up) on the side each bit of `slot`
/// gives. `is_valid_vrf_proof` is this compared with the proposer's
/// registered VRF root.
pub fn fold_vrf_branch<'a>(
    leaf: &Node,
    branch: impl IntoIterator<Item = &'a Node>,
    slot: u64,
) -> Node {
    let mut value = *leaf;
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
        if fold_vrf_branch(&compute_vrf_leaf(&vrf_seed, 0), &branch, 0) != root {
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

    /// `compute_vrf_proof`: the leaf at index `slot`, then its branch,
    /// siblings bottom-up. `None` for a slot past the tree's last leaf, which
    /// no proof exists for.
    pub fn proof(&self, slot: u64) -> Option<Vec<Node>> {
        if slot >> self.depth != 0 {
            return None;
        }
        let subtree_depth = self.subtree_depth();
        let subtree = slot >> subtree_depth;
        let first_leaf = subtree << subtree_depth;
        let mut proof = Vec::with_capacity(self.depth + 1);
        proof.push(compute_vrf_leaf(&self.seed, slot));
        let mut nodes: Vec<Node> = (first_leaf..first_leaf + (1 << subtree_depth))
            .map(|index| compute_vrf_leaf(&self.seed, index))
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
    /// state keeps leaf 0's branch (1 KiB).
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
            return compute_vrf_leaf(vrf_seed, index);
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
    fn a_proof_reveals_its_slots_leaf_and_folds_to_the_root() {
        let seed = seed();
        let depth = SUBTREE_DEPTH + 2;
        let tree = VrfTree::with_depth(seed, depth);
        let root = tree.root();
        let last = (1 << depth) - 1;
        for slot in [0, 1, 5, (1 << SUBTREE_DEPTH) - 1, 1 << SUBTREE_DEPTH, last] {
            let proof = tree.proof(slot).unwrap();
            assert_eq!(proof.len(), depth + 1);
            assert_eq!(proof[0], compute_vrf_leaf(&seed, slot), "slot {slot}");
            assert_eq!(
                fold_vrf_branch(&proof[0], &proof[1..], slot),
                root,
                "slot {slot}"
            );
            // The branch opens this leaf only: not at the neighbouring index,
            // and not another leaf at this one.
            assert_ne!(fold_vrf_branch(&proof[0], &proof[1..], slot ^ 1), root);
            assert_ne!(fold_vrf_branch(&[1; 32], &proof[1..], slot), root);
        }
        assert!(tree.proof(last + 1).is_none());
    }

    /// Validator 0 of ethereum-package's default mnemonic: its VRF root and
    /// leaf 0's branch as the package publishes them
    /// (`static_files/xmss-keys/b9dec4e1daa17dfe.vrf`, record 0, from
    /// eth-beacon-genesis, an independent implementation), and the VRF seed
    /// its signing key derives.
    const PUBLISHED_ROOT: &str = "2c8d6a710d3a22803be6490fef9c9247e30ac68793bffb7cbc151d17f8313cb0";
    const PUBLISHED_BRANCH: [&str; VRF_TREE_DEPTH] = [
        "3b553e1e307ad6190a1c81579244b4cc5ef3689bb306e406c286df6f149f3385",
        "bdff49fdadccf691e8463ad83c9144bb1f1dd3be2cc65d61cb65194a11d44778",
        "b3188264c7dbdfc2097fef24d373f8f0fdde3700f1c7dda868d4d1dfff3ea735",
        "bc747d9befb30d217afb5ef24b2130b3939a18cbb12e8ff9cad8ea43d666f328",
        "2826365c053905094470eb39f801babe15bb56dfede5d3d89c60f94bec94c6cc",
        "b054a7ce37d45e7dc9574b25815b33ef9d5d02dfba2c5867c15c6ce6ce4f87e0",
        "8d48edeef8615159f8e9a5c3ff7d59dc13063cb5a246dec9caf01573514257d9",
        "410a426beda2a00182b63294eac078460157987ce4f7c8d16008d6a82970b278",
        "c01def0ca03beffc51029b7e13f50e39169df10c82f7130d5f7b9c5e8f876d28",
        "5a29cca22a1043e0724dc105e1204f0c2f1956e4d634b7fda4f124f0f3dbe7ae",
        "cd69bff80485b514887c3282ba6e7411e745928f4d253a12b1cc6b658b362a87",
        "f79eb3ba9c7015ff12e965a793f36930aa667af852669424018c1e652742ec76",
        "7b577ddefc00fab0447df555c5d59f76e4e49656fb0f6e565969cccae4ce7dcc",
        "a82515f2a8c036495e924da314d087473d1d7d4acc6a97ec767bcf16e97292f2",
        "36d25a6b0464f79c531d9338e6645fb0559816f66aa3ea7616c5194cc0da924a",
        "438ab193ca00bdf0e5b75855f94bb32e778fbffe85d370284b878b8835968dd6",
        "1305124c8db86859bcf9110c72a2231bce1bc2bf44443032775d90d1e76b3667",
        "ece380acfc342142a937a48d3ea84e3397421f3db74a9122bcea245a4fceb43e",
        "a8e932e0dd6ec363635fdb0b30ea60d24cc1a861904c879e236c0e77f9efa562",
        "123e8cef55f55b0dd4f3d0758fd52aa270c53d3f230393112a404216fc10743f",
        "760a6fcab9db4b616b94ad3882dea4d434a849f6d1a03fa507c648d904ec641d",
        "32a9196616c33e77daecac4d5fbafd131b0968899e1a440cb4f05d868a0deb7f",
        "0a9cf6b998c2736cc5c5a137b335261b1ee68671345b1c9a17f208026f4146a5",
        "cb310e30dc647396390e107f0ec081689d9b84c965b340b7d6949b4be00fe461",
        "fc097343ba9eed74f88793de989d6f250eb852eacb7d70a76f65ffbbbde906ee",
        "1d7fd2ea64087c2a054a78558ed0e578047c06c2fa033dd0cbc3c2a33b88b06e",
        "44d7360b2aacc44b9c969859104c1ecfa4d8da6c410fab927969d28bf6335e38",
        "d8af842dfc83814f0291c4ad67ce2b74e83cefbddf870d1a7352793d027abc6f",
        "6de1e6d637d9a2965eff8b036c0a8c37dcdd85f95f4327a87821b1c10f1eefeb",
        "1b4c477849c185cb826bd541d5a31d83cc5d603b8d5b5d137de2babe4535705d",
        "d1ed2b30f968fa3b5daac6544cf01bb549ad0c70b50a2f56057e89dbbf4e7d72",
    ];

    fn published_seed() -> Node {
        crate::pq_keys::vrf_seed(&hex32(
            "0dce41fa73ae9f6bdfd51df4d422d75eee174553dba5fd450c4437e4ed3fc903",
        ))
    }

    /// The leaf rule, the little-endian index and the fold's order, against
    /// what ethPandaOps' genesis tooling registered: the branch's lower
    /// levels are this seed's nodes, and leaf 0 folds through the whole
    /// branch to the published root, so the published state restores.
    #[test]
    fn matches_ethereum_packages_published_state() {
        let seed = published_seed();
        let branch: Vec<Node> = PUBLISHED_BRANCH.iter().map(|node| hex32(node)).collect();
        for (height, sibling) in branch.iter().enumerate().take(11) {
            assert_eq!(
                compute_vrf_node(&seed, height, 1),
                *sibling,
                "height {height}"
            );
        }
        let root = hex32(PUBLISHED_ROOT);
        assert_eq!(
            fold_vrf_branch(&compute_vrf_leaf(&seed, 0), &branch, 0),
            root
        );
        let tree = VrfTree::from_compact_state(seed, root, branch).unwrap();
        let proof = tree.proof(9).unwrap();
        assert_eq!(proof[0], compute_vrf_leaf(&seed, 9));
        assert_eq!(fold_vrf_branch(&proof[0], &proof[1..], 9), root);
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
        let root = fold_vrf_branch(&compute_vrf_leaf(&seed, 0), &branch, 0);
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
