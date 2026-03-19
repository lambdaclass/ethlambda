use std::collections::HashMap;

use ethlambda_types::{attestation::AttestationData, primitives::H256};

/// A node in the proto-array fork choice tree.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ProtoNode {
    root: H256,
    parent: Option<usize>,
    slot: u64,
    /// Subtree weight: direct votes on this node + all descendant votes.
    weight: i64,
    /// Index of the heaviest direct child (used for O(depth) head lookup).
    best_child: Option<usize>,
}

/// Incremental fork choice structure that maintains the block tree and
/// propagates vote weight changes via a single backward pass.
///
/// Nodes are append-only (sorted by insertion order, which respects slot ordering).
/// Iterating backward guarantees children are always processed before parents.
#[derive(Debug, Clone, Default)]
pub struct ProtoArray {
    nodes: Vec<ProtoNode>,
    indices: HashMap<H256, usize>,
}

impl ProtoArray {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new block in the tree. O(1) append.
    ///
    /// The parent must already exist in the array (or be absent for the anchor block).
    pub fn on_block(&mut self, root: H256, parent_root: H256, slot: u64) {
        if self.indices.contains_key(&root) {
            return;
        }

        let parent_index = self.indices.get(&parent_root).copied();
        let index = self.nodes.len();

        self.nodes.push(ProtoNode {
            root,
            parent: parent_index,
            slot,
            weight: 0,
            best_child: None,
        });
        self.indices.insert(root, index);
    }

    /// Apply score deltas and propagate weights upward in a single backward pass.
    ///
    /// After this call, each node's `weight` reflects the total votes for its subtree,
    /// and `best_child` pointers are updated.
    pub fn apply_score_changes(&mut self, deltas: &mut [i64]) {
        for i in (0..self.nodes.len()).rev() {
            if i < deltas.len() {
                self.nodes[i].weight += deltas[i];
            }

            let Some(parent_idx) = self.nodes[i].parent else {
                continue;
            };

            // Propagate this node's delta to parent
            if i < deltas.len() && parent_idx < deltas.len() {
                deltas[parent_idx] += deltas[i];
            }

            // Update best_child: pick the child with highest weight, tiebreak by root hash
            self.maybe_update_best_child(parent_idx, i);
        }
    }

    /// Find the head of the chain starting from the justified root.
    ///
    /// Follows `best_child` pointers from the justified root down to a leaf.
    /// Returns the justified root itself if it has no children.
    pub fn find_head(&self, justified_root: H256) -> H256 {
        self.find_head_with_threshold(justified_root, 0)
    }

    /// Find the head with a minimum weight threshold.
    ///
    /// Like `find_head`, but stops descending when the best child's subtree
    /// weight is below `min_score`. Since `best_child` always points to the
    /// heaviest child, if it doesn't meet the threshold, no child can.
    pub fn find_head_with_threshold(&self, justified_root: H256, min_score: i64) -> H256 {
        let Some(&start_idx) = self.indices.get(&justified_root) else {
            return justified_root;
        };

        let mut current_idx = start_idx;
        while let Some(best_child_idx) = self.nodes[current_idx].best_child {
            if self.nodes[best_child_idx].weight < min_score {
                break;
            }
            current_idx = best_child_idx;
        }

        self.nodes[current_idx].root
    }

    /// Rebuild the array keeping only descendants of the finalized root.
    ///
    /// All indices are recomputed. O(nodes).
    pub fn prune(&mut self, finalized_root: H256) {
        let Some(&finalized_idx) = self.indices.get(&finalized_root) else {
            return;
        };

        // Collect indices of nodes to keep: finalized root + all descendants
        let mut keep = vec![false; self.nodes.len()];
        keep[finalized_idx] = true;
        for i in (finalized_idx + 1)..self.nodes.len() {
            if let Some(parent) = self.nodes[i].parent
                && keep[parent]
            {
                keep[i] = true;
            }
        }

        // Build new array with only kept nodes, mapping old indices to new
        let mut old_to_new: HashMap<usize, usize> = HashMap::new();
        let mut new_nodes = Vec::new();
        let mut new_indices = HashMap::new();

        for (old_idx, node) in self.nodes.iter().enumerate() {
            if !keep[old_idx] {
                continue;
            }
            let new_idx = new_nodes.len();
            old_to_new.insert(old_idx, new_idx);
            new_indices.insert(node.root, new_idx);
            new_nodes.push(node.clone());
        }

        // Remap parent and best_child indices
        for node in &mut new_nodes {
            node.parent = node.parent.and_then(|p| old_to_new.get(&p).copied());
            node.best_child = node.best_child.and_then(|c| old_to_new.get(&c).copied());
        }

        self.nodes = new_nodes;
        self.indices = new_indices;
    }

    /// Number of nodes currently in the array.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the array is empty.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Get the index for a block root, if it exists.
    pub fn get_index(&self, root: &H256) -> Option<usize> {
        self.indices.get(root).copied()
    }

    fn maybe_update_best_child(&mut self, parent_idx: usize, child_idx: usize) {
        let child_weight = self.nodes[child_idx].weight;
        let child_root = self.nodes[child_idx].root;

        let dominated = match self.nodes[parent_idx].best_child {
            None => true,
            Some(current_best) => {
                let best_weight = self.nodes[current_best].weight;
                let best_root = self.nodes[current_best].root;
                (child_weight, child_root) > (best_weight, best_root)
            }
        };

        if dominated {
            self.nodes[parent_idx].best_child = Some(child_idx);
        }
    }
}

/// Tracks each validator's latest head vote and computes deltas between updates.
#[derive(Debug, Clone, Default)]
pub struct VoteTracker {
    /// Current head vote per validator. Indexed by validator_id.
    votes: Vec<Option<H256>>,
}

impl VoteTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Compare current votes against new attestations and produce a delta array.
    ///
    /// For each validator whose vote changed:
    /// - old vote's node gets -1
    /// - new vote's node gets +1
    ///
    /// After computing deltas, internal state is updated to reflect new votes.
    pub fn compute_deltas(
        &mut self,
        new_attestations: &HashMap<u64, AttestationData>,
        proto_array: &ProtoArray,
    ) -> Vec<i64> {
        let mut deltas = vec![0i64; proto_array.len()];

        for (&validator_id, attestation) in new_attestations {
            let new_root = attestation.head.root;
            let id = validator_id as usize;

            // Grow votes vec if needed
            if id >= self.votes.len() {
                self.votes.resize(id + 1, None);
            }

            let old_root = self.votes[id];

            // Skip if vote hasn't changed
            if old_root == Some(new_root) {
                continue;
            }

            // Remove weight from old vote
            if let Some(old) = old_root
                && let Some(idx) = proto_array.get_index(&old)
            {
                deltas[idx] -= 1;
            }

            // Add weight to new vote
            if let Some(idx) = proto_array.get_index(&new_root) {
                deltas[idx] += 1;
            }

            self.votes[id] = Some(new_root);
        }

        deltas
    }

    /// Reset vote tracker state. Used after pruning when votes may reference
    /// nodes that no longer exist.
    pub fn reset(&mut self) {
        self.votes.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_types::checkpoint::Checkpoint;

    fn h(byte: u8) -> H256 {
        H256::from([byte; 32])
    }

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

    // ==================== ProtoArray tests ====================

    #[test]
    fn linear_chain_head() {
        // anchor(0) -> a(1) -> b(2) -> c(3)
        let mut pa = ProtoArray::new();
        pa.on_block(h(0), H256::ZERO, 0);
        pa.on_block(h(1), h(0), 1);
        pa.on_block(h(2), h(1), 2);
        pa.on_block(h(3), h(2), 3);

        // One validator votes for c
        let mut attestations = HashMap::new();
        attestations.insert(0, make_attestation(h(3), 3));

        let mut vt = VoteTracker::new();
        let mut deltas = vt.compute_deltas(&attestations, &pa);
        pa.apply_score_changes(&mut deltas);

        assert_eq!(pa.find_head(h(0)), h(3));
    }

    #[test]
    fn fork_heavier_branch_wins() {
        //          anchor(0)
        //          /       \
        //        a(1)      b(1)
        // 2 votes for a, 1 vote for b → head = a
        let mut pa = ProtoArray::new();
        pa.on_block(h(0), H256::ZERO, 0);
        pa.on_block(h(1), h(0), 1); // a
        pa.on_block(h(2), h(0), 1); // b

        let mut attestations = HashMap::new();
        attestations.insert(0, make_attestation(h(1), 1));
        attestations.insert(1, make_attestation(h(1), 1));
        attestations.insert(2, make_attestation(h(2), 1));

        let mut vt = VoteTracker::new();
        let mut deltas = vt.compute_deltas(&attestations, &pa);
        pa.apply_score_changes(&mut deltas);

        assert_eq!(pa.find_head(h(0)), h(1));
    }

    #[test]
    fn fork_tiebreak_by_root_hash() {
        // Equal weight → highest root hash wins
        let mut pa = ProtoArray::new();
        pa.on_block(h(0), H256::ZERO, 0);
        pa.on_block(h(1), h(0), 1);
        pa.on_block(h(2), h(0), 1);

        let mut attestations = HashMap::new();
        attestations.insert(0, make_attestation(h(1), 1));
        attestations.insert(1, make_attestation(h(2), 1));

        let mut vt = VoteTracker::new();
        let mut deltas = vt.compute_deltas(&attestations, &pa);
        pa.apply_score_changes(&mut deltas);

        // h(2) > h(1) lexicographically
        assert_eq!(pa.find_head(h(0)), h(2));
    }

    #[test]
    fn vote_change_shifts_head() {
        // Fork: anchor(0) -> a(1), anchor(0) -> b(1)
        // Initially: 2 votes for a, 1 for b → head = a
        // Then: move 2 votes to b → head = b
        let mut pa = ProtoArray::new();
        pa.on_block(h(0), H256::ZERO, 0);
        pa.on_block(h(1), h(0), 1); // a
        pa.on_block(h(2), h(0), 1); // b

        let mut vt = VoteTracker::new();

        // Round 1: 2 votes a, 1 vote b
        let mut att1 = HashMap::new();
        att1.insert(0, make_attestation(h(1), 1));
        att1.insert(1, make_attestation(h(1), 1));
        att1.insert(2, make_attestation(h(2), 1));
        let mut deltas = vt.compute_deltas(&att1, &pa);
        pa.apply_score_changes(&mut deltas);
        assert_eq!(pa.find_head(h(0)), h(1));

        // Round 2: move validators 0,1 to b
        let mut att2 = HashMap::new();
        att2.insert(0, make_attestation(h(2), 1));
        att2.insert(1, make_attestation(h(2), 1));
        att2.insert(2, make_attestation(h(2), 1));
        let mut deltas = vt.compute_deltas(&att2, &pa);
        pa.apply_score_changes(&mut deltas);
        assert_eq!(pa.find_head(h(0)), h(2));
    }

    #[test]
    fn unchanged_votes_produce_zero_deltas() {
        let mut pa = ProtoArray::new();
        pa.on_block(h(0), H256::ZERO, 0);
        pa.on_block(h(1), h(0), 1);

        let mut vt = VoteTracker::new();
        let mut attestations = HashMap::new();
        attestations.insert(0, make_attestation(h(1), 1));

        // First call establishes the vote
        let mut deltas = vt.compute_deltas(&attestations, &pa);
        pa.apply_score_changes(&mut deltas);

        // Second call with same votes → all deltas should be zero
        let deltas = vt.compute_deltas(&attestations, &pa);
        assert!(deltas.iter().all(|&d| d == 0));
    }

    #[test]
    fn prune_removes_pre_finalized_nodes() {
        // anchor(0) -> a(1) -> b(2) -> c(3)
        // Finalize at b(2) → anchor and a should be pruned
        let mut pa = ProtoArray::new();
        pa.on_block(h(0), H256::ZERO, 0);
        pa.on_block(h(1), h(0), 1);
        pa.on_block(h(2), h(1), 2);
        pa.on_block(h(3), h(2), 3);

        pa.prune(h(2));

        assert_eq!(pa.len(), 2); // b and c remain
        assert!(pa.get_index(&h(0)).is_none());
        assert!(pa.get_index(&h(1)).is_none());
        assert!(pa.get_index(&h(2)).is_some());
        assert!(pa.get_index(&h(3)).is_some());
    }

    #[test]
    fn prune_preserves_fork_descendants() {
        //          anchor(0)
        //             |
        //           a(1)  ← finalize here
        //          /     \
        //        b(2)    c(2)
        let mut pa = ProtoArray::new();
        pa.on_block(h(0), H256::ZERO, 0);
        pa.on_block(h(1), h(0), 1);
        pa.on_block(h(2), h(1), 2);
        pa.on_block(h(3), h(1), 2);

        pa.prune(h(1));

        assert_eq!(pa.len(), 3); // a, b, c
        assert!(pa.get_index(&h(0)).is_none());
        assert!(pa.get_index(&h(1)).is_some());
        assert!(pa.get_index(&h(2)).is_some());
        assert!(pa.get_index(&h(3)).is_some());
    }

    #[test]
    fn find_head_with_deep_chain() {
        // Build a chain of 50 blocks, all votes on the tip
        let mut pa = ProtoArray::new();
        pa.on_block(h(0), H256::ZERO, 0);
        for i in 1..50u8 {
            pa.on_block(h(i), h(i - 1), i as u64);
        }

        let mut attestations = HashMap::new();
        attestations.insert(0, make_attestation(h(49), 49));
        attestations.insert(1, make_attestation(h(49), 49));

        let mut vt = VoteTracker::new();
        let mut deltas = vt.compute_deltas(&attestations, &pa);
        pa.apply_score_changes(&mut deltas);

        assert_eq!(pa.find_head(h(0)), h(49));
    }

    #[test]
    fn duplicate_on_block_is_idempotent() {
        let mut pa = ProtoArray::new();
        pa.on_block(h(0), H256::ZERO, 0);
        pa.on_block(h(1), h(0), 1);
        pa.on_block(h(1), h(0), 1); // duplicate

        assert_eq!(pa.len(), 2);
    }

    #[test]
    fn find_head_no_votes_returns_justified() {
        let mut pa = ProtoArray::new();
        pa.on_block(h(0), H256::ZERO, 0);
        pa.on_block(h(1), h(0), 1);
        pa.on_block(h(2), h(0), 1);

        // No votes → no best_child set → returns justified root
        assert_eq!(pa.find_head(h(0)), h(0));
    }

    #[test]
    fn find_head_unknown_justified_returns_it() {
        let pa = ProtoArray::new();
        assert_eq!(pa.find_head(h(99)), h(99));
    }

    #[test]
    fn weight_propagation_through_chain() {
        // anchor(0) -> a(1) -> b(2)
        // Vote for b should propagate weight to a and anchor
        let mut pa = ProtoArray::new();
        pa.on_block(h(0), H256::ZERO, 0);
        pa.on_block(h(1), h(0), 1);
        pa.on_block(h(2), h(1), 2);

        let mut attestations = HashMap::new();
        attestations.insert(0, make_attestation(h(2), 2));

        let mut vt = VoteTracker::new();
        let mut deltas = vt.compute_deltas(&attestations, &pa);
        pa.apply_score_changes(&mut deltas);

        // best_child chain should lead from anchor through a to b
        assert_eq!(pa.find_head(h(0)), h(2));
        assert_eq!(pa.find_head(h(1)), h(2));
    }

    #[test]
    fn prune_then_new_blocks_and_votes() {
        // anchor(0) -> a(1) -> b(2) -> c(3)
        // Finalize b, then add d(4) as child of c, vote for d
        let mut pa = ProtoArray::new();
        pa.on_block(h(0), H256::ZERO, 0);
        pa.on_block(h(1), h(0), 1);
        pa.on_block(h(2), h(1), 2);
        pa.on_block(h(3), h(2), 3);

        let mut vt = VoteTracker::new();
        let mut att = HashMap::new();
        att.insert(0, make_attestation(h(3), 3));
        let mut deltas = vt.compute_deltas(&att, &pa);
        pa.apply_score_changes(&mut deltas);

        // Prune to b(2), reset votes since indices changed
        pa.prune(h(2));
        vt.reset();

        // Add new block d(4)
        pa.on_block(h(4), h(3), 4);

        // Vote for d
        let mut att2 = HashMap::new();
        att2.insert(0, make_attestation(h(4), 4));
        let mut deltas = vt.compute_deltas(&att2, &pa);
        pa.apply_score_changes(&mut deltas);

        assert_eq!(pa.find_head(h(2)), h(4));
    }

    // ==================== Threshold tests ====================

    #[test]
    fn threshold_stops_at_branch_below_min_score() {
        //          anchor(0)
        //             |
        //           a(1)
        //          /     \
        //        b(2)    c(2)
        // 2 votes for b, 1 vote for c → threshold=2 stops at b, threshold=3 stops at a
        let mut pa = ProtoArray::new();
        pa.on_block(h(0), H256::ZERO, 0);
        pa.on_block(h(1), h(0), 1);
        pa.on_block(h(2), h(1), 2); // b
        pa.on_block(h(3), h(1), 2); // c

        let mut vt = VoteTracker::new();
        let mut att = HashMap::new();
        att.insert(0, make_attestation(h(2), 2));
        att.insert(1, make_attestation(h(2), 2));
        att.insert(2, make_attestation(h(3), 2));
        let mut deltas = vt.compute_deltas(&att, &pa);
        pa.apply_score_changes(&mut deltas);

        // No threshold → follows best_child to b (weight 2 > c weight 1)
        assert_eq!(pa.find_head_with_threshold(h(0), 0), h(2));
        // Threshold=2 → b meets it (weight=2), so head=b
        assert_eq!(pa.find_head_with_threshold(h(0), 2), h(2));
        // Threshold=3 → b doesn't meet it (weight=2 < 3), stop at a
        assert_eq!(pa.find_head_with_threshold(h(0), 3), h(1));
    }

    #[test]
    fn threshold_returns_justified_when_no_child_qualifies() {
        //   anchor(0) -> a(1)
        // 1 vote for a, threshold=2 → stop at anchor
        let mut pa = ProtoArray::new();
        pa.on_block(h(0), H256::ZERO, 0);
        pa.on_block(h(1), h(0), 1);

        let mut vt = VoteTracker::new();
        let mut att = HashMap::new();
        att.insert(0, make_attestation(h(1), 1));
        let mut deltas = vt.compute_deltas(&att, &pa);
        pa.apply_score_changes(&mut deltas);

        assert_eq!(pa.find_head_with_threshold(h(0), 2), h(0));
    }

    #[test]
    fn threshold_walks_deep_chain_until_weight_drops() {
        // anchor(0) -> a(1) -> b(2) -> c(3)
        // 3 votes for c, threshold=3 → walks all the way to c
        // Then move 1 vote to b: c has weight=2, b has weight=3
        // threshold=3 → walks to b but stops before c
        let mut pa = ProtoArray::new();
        pa.on_block(h(0), H256::ZERO, 0);
        pa.on_block(h(1), h(0), 1);
        pa.on_block(h(2), h(1), 2);
        pa.on_block(h(3), h(2), 3);

        let mut vt = VoteTracker::new();
        let mut att = HashMap::new();
        att.insert(0, make_attestation(h(3), 3));
        att.insert(1, make_attestation(h(3), 3));
        att.insert(2, make_attestation(h(3), 3));
        let mut deltas = vt.compute_deltas(&att, &pa);
        pa.apply_score_changes(&mut deltas);

        assert_eq!(pa.find_head_with_threshold(h(0), 3), h(3));

        // Move validator 2 to vote for b instead of c
        let mut att2 = HashMap::new();
        att2.insert(0, make_attestation(h(3), 3));
        att2.insert(1, make_attestation(h(3), 3));
        att2.insert(2, make_attestation(h(2), 2));
        let mut deltas = vt.compute_deltas(&att2, &pa);
        pa.apply_score_changes(&mut deltas);

        // c now has weight=2 (below threshold=3), b has weight=3 (meets threshold)
        assert_eq!(pa.find_head_with_threshold(h(0), 3), h(2));
    }
}
