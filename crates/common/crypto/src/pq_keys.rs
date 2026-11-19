//! A validator's PQ-fork key material, derived from its BLS signing key the
//! way ethPandaOps' PQ genesis tooling (eth-beacon-genesis `284025a0`) and
//! Lighthouse's PQ branch derive it, so a validator's keystore is all it
//! needs on a network whose genesis that tooling built:
//!
//! - the leanXMSS key grows from `sha256("leanxmss-seed" || sk)`;
//! - the VRF tree's seed is `sha256("vrf-seed" || sk)`.
//!
//! `sk` is the 32-byte big-endian BLS secret key a keystore holds. The
//! specification leaves the derivation to the validator (`pq/validator.md`,
//! "XMSS public key" and "VRF tree"); this is the devnet's convention, not the
//! specification's.
//!
//! The VRF tree is the specification's: depth `VRF_TREE_DEPTH` (31), its leaf
//! at index `slot` the proposer's RANDAO reveal for that slot. The tooling
//! populates the first 2^20 leaves, each `sha256(seed || le64(index))`, and
//! leaves the rest zero. Holding the whole populated tree costs 64 MiB a key,
//! so [`VrfTree`] keeps the roots of its 2^10-leaf subtrees (32 KiB) and
//! rebuilds one subtree per proof, as Lighthouse does.

use sha2::{Digest, Sha256};

use crate::lean_xmss;

/// The depth of the VRF tree (the specification's `VRF_TREE_DEPTH`).
pub const VRF_TREE_DEPTH: usize = 31;
const POPULATED_DEPTH: usize = 20;
const POPULATED_LEAVES: u64 = 1 << POPULATED_DEPTH;
const SUBTREE_DEPTH: usize = 10;
const SUBTREE_LEAVES: u64 = 1 << SUBTREE_DEPTH;

type Node = [u8; 32];

fn sha256_concat(prefix: &[u8], body: &[u8]) -> Node {
    let mut hasher = Sha256::new();
    hasher.update(prefix);
    hasher.update(body);
    hasher.finalize().into()
}

/// The seed a validator's leanXMSS key grows from.
pub fn xmss_seed(bls_secret_key: &[u8; 32]) -> lean_xmss::Seed {
    sha256_concat(b"leanxmss-seed", bls_secret_key)
}

/// The seed of a validator's VRF tree.
pub fn vrf_seed(bls_secret_key: &[u8; 32]) -> Node {
    sha256_concat(b"vrf-seed", bls_secret_key)
}

/// A validator's leanXMSS key. Generating it builds the key's whole top tree:
/// about a second and a half across cores.
pub fn xmss_key(bls_secret_key: &[u8; 32]) -> lean_xmss::SecretKey {
    lean_xmss::key_gen(&xmss_seed(bls_secret_key))
}

/// A validator's VRF tree, holding the roots of its populated subtrees.
pub struct VrfTree {
    seed: Node,
    subtree_roots: Vec<Node>,
}

impl VrfTree {
    pub fn from_bls(bls_secret_key: &[u8; 32]) -> Self {
        Self::from_seed(vrf_seed(bls_secret_key))
    }

    /// Hashes every populated leaf once: about two million SHA-256s.
    pub fn from_seed(seed: Node) -> Self {
        let subtree_roots = (0..POPULATED_LEAVES)
            .step_by(SUBTREE_LEAVES as usize)
            .map(|start| {
                let mut nodes = populated_subtree(&seed, start);
                reduce(&mut nodes, 0, &mut Vec::new());
                nodes[0]
            })
            .collect();
        Self {
            seed,
            subtree_roots,
        }
    }

    /// The tree's root, which a validator registers as its `vrf_root`.
    pub fn root(&self) -> Node {
        let mut nodes = self.subtree_roots.clone();
        reduce(&mut nodes, 0, &mut Vec::new());
        let zeros = zero_hashes();
        (POPULATED_DEPTH..VRF_TREE_DEPTH)
            .fold(nodes[0], |node, level| hash_pair(&node, &zeros[level]))
    }

    /// The proof for `slot`: the leaf at index `slot`, then its branch,
    /// siblings bottom-up (`VRF_TREE_DEPTH + 1` nodes), the specification's
    /// `VRFProof`.
    pub fn proof(&self, slot: u64) -> Vec<Node> {
        let index = slot & ((1 << VRF_TREE_DEPTH) - 1);
        let zeros = zero_hashes();
        let mut proof = Vec::with_capacity(VRF_TREE_DEPTH + 1);
        if index < POPULATED_LEAVES {
            let start = index & !(SUBTREE_LEAVES - 1);
            let mut nodes = populated_subtree(&self.seed, start);
            proof.push(vrf_leaf(&self.seed, index));
            reduce(&mut nodes, (index % SUBTREE_LEAVES) as usize, &mut proof);
            let mut roots = self.subtree_roots.clone();
            reduce(&mut roots, (index / SUBTREE_LEAVES) as usize, &mut proof);
            proof.extend_from_slice(&zeros[POPULATED_DEPTH..VRF_TREE_DEPTH]);
        } else {
            // A zero leaf in the empty part of the tree: the populated
            // subtree is the one non-zero sibling on the way up.
            let joined_depth = index.ilog2() as usize;
            let mut roots = self.subtree_roots.clone();
            reduce(&mut roots, 0, &mut Vec::new());
            let mut populated = roots[0];
            proof.push([0; 32]);
            for (level, zero) in zeros.iter().enumerate() {
                proof.push(if level == joined_depth {
                    populated
                } else {
                    *zero
                });
                if (POPULATED_DEPTH..joined_depth).contains(&level) {
                    populated = hash_pair(&populated, zero);
                }
            }
        }
        proof
    }
}

fn populated_subtree(seed: &Node, start: u64) -> Vec<Node> {
    (0..SUBTREE_LEAVES)
        .map(|offset| vrf_leaf(seed, start + offset))
        .collect()
}

fn vrf_leaf(seed: &Node, index: u64) -> Node {
    sha256_concat(seed, &index.to_le_bytes())
}

fn hash_pair(left: &Node, right: &Node) -> Node {
    sha256_concat(left, right)
}

fn zero_hashes() -> [Node; VRF_TREE_DEPTH] {
    let mut previous = [0; 32];
    std::array::from_fn(|_| {
        let zero = previous;
        previous = hash_pair(&zero, &zero);
        zero
    })
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

    fn hex32(text: &str) -> [u8; 32] {
        hex::decode(text.trim_start_matches("0x"))
            .unwrap()
            .try_into()
            .unwrap()
    }

    /// The specification's `is_valid_merkle_branch` for a VRF proof.
    fn verifies(proof: &[Node], slot: u64, root: &Node) -> bool {
        let mut node = proof[0];
        for (level, sibling) in proof[1..].iter().enumerate() {
            node = if (slot >> level) & 1 == 1 {
                hash_pair(sibling, &node)
            } else {
                hash_pair(&node, sibling)
            };
        }
        &node == root
    }

    /// Validator 0 of ethereum-package's default mnemonic: the second 32 bytes
    /// of `static_files/xmss-keys/e383db4eb96b6f02.bin` are its VRF root.
    #[test]
    fn ethereum_package_validator_zero_vrf_root() {
        let sk = hex32("0dce41fa73ae9f6bdfd51df4d422d75eee174553dba5fd450c4437e4ed3fc903");
        let tree = VrfTree::from_bls(&sk);
        assert_eq!(
            tree.root(),
            hex32("b1e3a6168d285a532e0dd3c6e1b5588b3bc68c27b45af71ee60ad5243600d281")
        );
    }

    /// Lighthouse's `pq_ethpandaops_keys_and_vrf_tree_boundaries`: its key and
    /// VRF root, and proofs at the boundaries of the populated part.
    #[test]
    fn lighthouse_known_answer_and_boundary_proofs() {
        let sk = hex32("2892f3ba475c3640a67fe730798ad9c4eed3a6d934db85f91c41cfc837ce8834");
        let tree = VrfTree::from_bls(&sk);
        let root = tree.root();
        assert_eq!(
            root,
            hex32("0fc00857fdae6d29c18f54563c64e166b1fff1c6d943bb2c43e8b096bb60585e")
        );
        assert_eq!(
            xmss_key(&sk).public_key().to_bytes(),
            hex32("155a29b971da2b771fdf52c768af63fa03f78f25487e3e0ed03d012b7039d88b")
        );
        for slot in [
            0,
            5,
            POPULATED_LEAVES - 1,
            POPULATED_LEAVES,
            (1 << VRF_TREE_DEPTH) - 1,
        ] {
            let proof = tree.proof(slot);
            assert_eq!(proof.len(), VRF_TREE_DEPTH + 1);
            assert_eq!(proof[0] == [0; 32], slot >= POPULATED_LEAVES, "slot {slot}");
            assert!(verifies(&proof, slot, &root), "slot {slot}");
            assert!(!verifies(&proof, slot, &[0; 32]), "slot {slot}");
        }
    }
}
