use std::collections::HashMap;

use ethlambda_types::{
    attestation::{AttestationData, SignedAttestation},
    block::Block,
    primitives::H256,
};

/// Compute the LMD GHOST head of the chain, given a starting root, a set of blocks,
/// a set of attestations, and a minimum score threshold.
///
/// This is the same implementation from leanSpec
// TODO: add proto-array implementation
pub fn compute_lmd_ghost_head(
    mut start_root: H256,
    blocks: &HashMap<H256, Block>,
    attestations: &HashMap<u64, AttestationData>,
    min_score: u64,
) -> H256 {
    if blocks.is_empty() {
        return start_root;
    }
    if start_root.is_zero() {
        start_root = *blocks
            .iter()
            .min_by_key(|(_, block)| block.slot)
            .map(|(root, _)| root)
            .expect("we already checked blocks is non-empty");
    }
    let start_slot = blocks[&start_root].slot;
    let mut weights: HashMap<H256, u64> = HashMap::new();

    for attestation_data in attestations.values() {
        let mut current_root = attestation_data.head.root;
        while let Some(block) = blocks.get(&current_root)
            && block.slot > start_slot
        {
            *weights.entry(current_root).or_default() += 1;
            current_root = block.parent_root;
        }
    }

    let mut children_map: HashMap<H256, Vec<H256>> = HashMap::new();

    for (root, block) in blocks {
        if block.parent_root.is_zero() {
            continue;
        }
        if min_score > 0 && *weights.get(root).unwrap_or(&0) < min_score {
            continue;
        }
        children_map
            .entry(block.parent_root)
            .or_default()
            .push(*root);
    }

    let mut head = start_root;

    while let Some(children) = children_map.get(&head)
        && !children.is_empty()
    {
        // Choose best child: most attestations, then lexicographically highest hash
        head = *children
            .into_iter()
            .max_by_key(|root| (weights.get(root).copied().unwrap_or(0), root))
            .expect("checked it's not empty");
    }

    head
}
