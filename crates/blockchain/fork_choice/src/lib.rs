use std::collections::HashMap;

use ethlambda_types::{attestation::AttestationData, primitives::H256};

/// Compute per-block attestation weights for the fork choice tree.
///
/// For each validator attestation, walks backward from the attestation's head
/// through the parent chain, incrementing weight for each block above start_slot.
pub fn compute_block_weights(
    start_slot: u64,
    blocks: &HashMap<H256, (u64, H256)>,
    attestations: &HashMap<u64, AttestationData>,
) -> HashMap<H256, u64> {
    let mut weights: HashMap<H256, u64> = HashMap::new();

    for attestation_data in attestations.values() {
        let mut current_root = attestation_data.head.root;
        while let Some(&(slot, parent_root)) = blocks.get(&current_root)
            && slot > start_slot
        {
            *weights.entry(current_root).or_default() += 1;
            current_root = parent_root;
        }
    }

    weights
}

/// Compute the LMD GHOST head of the chain, given a starting root, a set of blocks,
/// a set of attestations, and a minimum score threshold.
///
/// This is the same implementation from leanSpec
// TODO: add proto-array implementation
pub fn compute_lmd_ghost_head(
    mut start_root: H256,
    blocks: &HashMap<H256, (u64, H256)>,
    attestations: &HashMap<u64, AttestationData>,
    min_score: u64,
) -> H256 {
    if blocks.is_empty() {
        return start_root;
    }
    if start_root.is_zero() {
        start_root = *blocks
            .iter()
            .min_by_key(|(_, (slot, _))| slot)
            .map(|(root, _)| root)
            .expect("we already checked blocks is non-empty");
    }
    let Some(&(start_slot, _)) = blocks.get(&start_root) else {
        return start_root;
    };
    let weights = compute_block_weights(start_slot, blocks, attestations);

    let mut children_map: HashMap<H256, Vec<H256>> = HashMap::new();

    for (root, &(_, parent_root)) in blocks {
        if parent_root.is_zero() {
            continue;
        }
        if min_score > 0 && *weights.get(root).unwrap_or(&0) < min_score {
            continue;
        }
        children_map.entry(parent_root).or_default().push(*root);
    }

    let mut head = start_root;

    while let Some(children) = children_map.get(&head)
        && !children.is_empty()
    {
        // Choose best child: most attestations, then lexicographically highest hash
        head = *children
            .iter()
            .max_by_key(|root| (weights.get(*root).copied().unwrap_or(0), *root))
            .expect("checked it's not empty");
    }

    head
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_types::state::Checkpoint;

    fn make_attestation(head_root: H256, slot: u64) -> AttestationData {
        AttestationData {
            slot,
            head: Checkpoint {
                root: head_root,
                slot,
            },
            target: Checkpoint::default(),
            source: Checkpoint::default(),
        }
    }

    #[test]
    fn test_compute_block_weights() {
        // Chain: root_a (slot 0) -> root_b (slot 1) -> root_c (slot 2)
        let root_a = H256::from([1u8; 32]);
        let root_b = H256::from([2u8; 32]);
        let root_c = H256::from([3u8; 32]);

        let mut blocks = HashMap::new();
        blocks.insert(root_a, (0, H256::ZERO));
        blocks.insert(root_b, (1, root_a));
        blocks.insert(root_c, (2, root_b));

        // Two validators: one attests to root_c, one attests to root_b
        let mut attestations = HashMap::new();
        attestations.insert(0, make_attestation(root_c, 2));
        attestations.insert(1, make_attestation(root_b, 1));

        let weights = compute_block_weights(0, &blocks, &attestations);

        // root_c: 1 vote (validator 0)
        assert_eq!(weights.get(&root_c).copied().unwrap_or(0), 1);
        // root_b: 2 votes (validator 0 walks through it + validator 1 attests directly)
        assert_eq!(weights.get(&root_b).copied().unwrap_or(0), 2);
        // root_a: at slot 0 = start_slot, so not counted
        assert_eq!(weights.get(&root_a).copied().unwrap_or(0), 0);
    }

    #[test]
    fn test_compute_block_weights_empty() {
        let blocks = HashMap::new();
        let attestations = HashMap::new();

        let weights = compute_block_weights(0, &blocks, &attestations);
        assert!(weights.is_empty());
    }
}
