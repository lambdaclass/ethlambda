use ethlambda_types::{
    attestation::{AttestationData, HashedAttestationData, bits_is_subset},
    block::AggregatedSignatureProof,
    checkpoint::Checkpoint,
    primitives::H256,
    signature::ValidatorSignature,
};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

/// Checkpoints to update in the forkchoice store.
///
/// Used with `Store::update_checkpoints` to update head and optionally
/// update justified/finalized checkpoints (only if higher slot).
pub struct ForkCheckpoints {
    pub(crate) head: H256,
    pub(crate) justified: Option<Checkpoint>,
    pub(crate) finalized: Option<Checkpoint>,
}

impl ForkCheckpoints {
    pub fn head_only(head: H256) -> Self {
        Self {
            head,
            justified: None,
            finalized: None,
        }
    }

    pub fn new(head: H256, justified: Option<Checkpoint>, finalized: Option<Checkpoint>) -> Self {
        Self {
            head,
            justified,
            finalized,
        }
    }
}

/// An entry in the payload buffer: attestation data + set of proofs.
#[derive(Clone)]
pub(crate) struct PayloadEntry {
    pub data: AttestationData,
    pub proofs: Vec<AggregatedSignatureProof>,
}

/// Fixed-size circular buffer for aggregated payloads, keyed by data_root.
/// Entries are evicted FIFO when the buffer reaches capacity.
#[derive(Clone)]
pub(crate) struct PayloadBuffer {
    pub data: HashMap<H256, PayloadEntry>,
    pub order: VecDeque<H256>,
    pub capacity: usize,
    pub total_proofs: usize,
}

impl PayloadBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            data: HashMap::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
            capacity,
            total_proofs: 0,
        }
    }

    /// Insert a proof for an attestation, FIFO-evicting oldest data_roots
    /// when total proofs reach capacity. Also ensures the buffer doesn't
    /// include proofs which are a subset of other proofs for the same
    /// attestation data:
    ///
    /// - If the incoming proof's participants are a subset (incl. equal) of
    ///   any existing proof, the incoming proof is redundant and skipped.
    /// - Otherwise, any existing proof whose participants are a strict subset
    ///   of the incoming proof's is removed before inserting.
    pub fn push(&mut self, hashed: HashedAttestationData, proof: AggregatedSignatureProof) {
        let (data_root, att_data) = hashed.into_parts();

        if let Some(entry) = self.data.get_mut(&data_root) {
            let mut to_remove: Vec<usize> = Vec::new();
            for (i, p) in entry.proofs.iter().enumerate() {
                // Incoming is subsumed by an existing proof (incl. equal). Skip.
                if bits_is_subset(&proof.participants, &p.participants) {
                    return;
                }
                // Existing is a strict subset of incoming. Mark for removal.
                // (Non-strict equality was ruled out by the check above.)
                if bits_is_subset(&p.participants, &proof.participants) {
                    to_remove.push(i);
                }
            }

            // Remove subsumed proofs (reverse order so earlier indices stay valid).
            for i in to_remove.into_iter().rev() {
                entry.proofs.swap_remove(i);
                self.total_proofs -= 1;
            }

            entry.proofs.push(proof);
            self.total_proofs += 1;
        } else {
            self.data.insert(
                data_root,
                PayloadEntry {
                    data: att_data,
                    proofs: vec![proof],
                },
            );
            self.order.push_back(data_root);
            self.total_proofs += 1;
        }
        // Evict oldest data_roots until under capacity
        while self.total_proofs > self.capacity {
            if let Some(evicted) = self.order.pop_front() {
                if let Some(removed) = self.data.remove(&evicted) {
                    self.total_proofs -= removed.proofs.len();
                }
            } else {
                break;
            }
        }
    }

    pub fn push_batch(&mut self, entries: Vec<(HashedAttestationData, AggregatedSignatureProof)>) {
        for (hashed, proof) in entries {
            self.push(hashed, proof);
        }
    }

    /// Take all entries, leaving the buffer empty.
    ///
    /// Drains in insertion order (via `self.order`) so downstream consumers
    /// like `promote_new_aggregated_payloads` re-insert into known_payloads
    /// deterministically. HashMap iteration would be RandomState-seeded and
    /// produce non-deterministic vote ordering for same-slot equivocation.
    pub fn drain(&mut self) -> Vec<(HashedAttestationData, AggregatedSignatureProof)> {
        self.total_proofs = 0;
        let mut result = Vec::with_capacity(self.data.values().map(|e| e.proofs.len()).sum());
        while let Some(data_root) = self.order.pop_front() {
            if let Some(entry) = self.data.remove(&data_root) {
                for proof in entry.proofs {
                    result.push((HashedAttestationData::new(entry.data.clone()), proof));
                }
            }
        }
        result
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn proof_count_for_root(&self, data_root: &H256) -> usize {
        self.data.get(data_root).map_or(0, |e| e.proofs.len())
    }

    pub fn proofs_for_root(&self, data_root: &H256) -> Vec<AggregatedSignatureProof> {
        self.data
            .get(data_root)
            .map_or_else(Vec::new, |e| e.proofs.clone())
    }

    pub fn attestation_data_keys(&self) -> Vec<(H256, AttestationData)> {
        self.data
            .iter()
            .map(|(&root, entry)| (root, entry.data.clone()))
            .collect()
    }

    /// Extract per-validator latest attestations from proofs' participation bits.
    ///
    /// Iterates entries in insertion order (via `self.order`) so that, when two
    /// aggregations carry the same `slot` but disagree on the target (an
    /// equivocation by the shared validators), the first-observed aggregation
    /// wins. The ethrex spec relies on Python dict insertion-order semantics
    /// here; iterating `self.data.values()` would be RandomState-seeded and
    /// fail the equivocation fork-choice tests non-deterministically.
    pub fn extract_latest_attestations(&self) -> HashMap<u64, AttestationData> {
        let mut result: HashMap<u64, AttestationData> = HashMap::new();
        for data_root in &self.order {
            let Some(entry) = self.data.get(data_root) else {
                continue;
            };
            for proof in &entry.proofs {
                for vid in proof.participant_indices() {
                    let should_update = result
                        .get(&vid)
                        .is_none_or(|existing| existing.slot < entry.data.slot);
                    if should_update {
                        result.insert(vid, entry.data.clone());
                    }
                }
            }
        }
        result
    }
}

/// Gossip signatures grouped by attestation data.
///
/// Signatures are stored in a `BTreeMap` keyed by validator_id to guarantee
/// ascending iteration order. XMSS aggregate proofs are order-dependent:
/// verification reconstructs pubkeys from the participation bitfield (low-to-high),
/// so aggregation must produce them in the same ascending order.
pub(crate) struct GossipDataEntry {
    pub data: AttestationData,
    pub signatures: BTreeMap<u64, ValidatorSignature>,
}

/// Gossip signatures snapshot: (hashed_attestation_data, Vec<(validator_id, signature)>).
pub type GossipSignatureSnapshot = Vec<(HashedAttestationData, Vec<(u64, ValidatorSignature)>)>;

/// Bounded buffer for gossip signatures with FIFO eviction.
///
/// Groups signatures by attestation data (via data_root). Each distinct
/// attestation message stores the full `AttestationData` plus individual
/// validator signatures in ascending order (required for XMSS aggregation).
///
/// Entries are evicted FIFO (by insertion order of the data_root) when
/// total_signatures exceeds capacity, matching the `PayloadBuffer` pattern.
pub(crate) struct GossipSignatureBuffer {
    pub data: HashMap<H256, GossipDataEntry>,
    pub order: VecDeque<H256>,
    pub capacity: usize,
    pub total_signatures: usize,
}

impl GossipSignatureBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            data: HashMap::new(),
            order: VecDeque::new(),
            capacity,
            total_signatures: 0,
        }
    }

    /// Insert a gossip signature, FIFO-evicting oldest data_roots when over capacity.
    ///
    /// Last-write-wins: if (validator_id, data_root) already exists, the signature is overwritten.
    pub fn insert(
        &mut self,
        hashed: HashedAttestationData,
        validator_id: u64,
        signature: ValidatorSignature,
    ) {
        let (data_root, att_data) = hashed.into_parts();

        if let Some(entry) = self.data.get_mut(&data_root) {
            let is_new = entry.signatures.insert(validator_id, signature).is_none();
            if is_new {
                self.total_signatures += 1;
            }
        } else {
            let mut signatures = BTreeMap::new();
            signatures.insert(validator_id, signature);
            self.data.insert(
                data_root,
                GossipDataEntry {
                    data: att_data,
                    signatures,
                },
            );
            self.order.push_back(data_root);
            self.total_signatures += 1;
        }

        // Evict oldest data_roots until under capacity
        while self.total_signatures > self.capacity {
            if let Some(evicted) = self.order.pop_front() {
                if let Some(removed) = self.data.remove(&evicted) {
                    self.total_signatures -= removed.signatures.len();
                }
            } else {
                break;
            }
        }
    }

    /// Delete gossip entries for the given (validator_id, data_root) pairs.
    ///
    /// When all signatures for a data_root are removed, the entry is cleaned up.
    /// Collects emptied roots and batch-cleans the VecDeque in one pass.
    pub fn delete(&mut self, keys: &[(u64, H256)]) {
        if keys.is_empty() {
            return;
        }
        let mut emptied_roots: HashSet<H256> = HashSet::new();
        for &(vid, data_root) in keys {
            if let Some(entry) = self.data.get_mut(&data_root) {
                if entry.signatures.remove(&vid).is_some() {
                    self.total_signatures -= 1;
                }
                if entry.signatures.is_empty() {
                    self.data.remove(&data_root);
                    emptied_roots.insert(data_root);
                }
            }
        }
        if !emptied_roots.is_empty() {
            self.order.retain(|r| !emptied_roots.contains(r));
        }
    }

    /// Prune gossip signatures for slots <= finalized_slot.
    ///
    /// Returns the number of data_root entries pruned.
    pub fn prune(&mut self, finalized_slot: u64) -> usize {
        let mut pruned_roots: HashSet<H256> = HashSet::new();
        self.data.retain(|root, entry| {
            if entry.data.slot > finalized_slot {
                true
            } else {
                self.total_signatures -= entry.signatures.len();
                pruned_roots.insert(*root);
                false
            }
        });
        if !pruned_roots.is_empty() {
            self.order.retain(|r| !pruned_roots.contains(r));
        }
        pruned_roots.len()
    }

    pub fn snapshot(&self) -> GossipSignatureSnapshot {
        self.data
            .values()
            .map(|entry| {
                let sigs: Vec<_> = entry
                    .signatures
                    .iter()
                    .map(|(&vid, sig)| (vid, sig.clone()))
                    .collect();
                (HashedAttestationData::new(entry.data.clone()), sigs)
            })
            .collect()
    }

    pub fn total_signatures(&self) -> usize {
        self.total_signatures
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_types::primitives::HashTreeRoot as _;

    fn make_proof() -> AggregatedSignatureProof {
        use ethlambda_types::attestation::AggregationBits;
        AggregatedSignatureProof::empty(AggregationBits::new())
    }

    /// Create a proof with a specific validator bit set (distinct participants).
    fn make_proof_for_validator(vid: usize) -> AggregatedSignatureProof {
        use ethlambda_types::attestation::AggregationBits;
        let mut bits = AggregationBits::with_length(vid + 1).unwrap();
        bits.set(vid, true).unwrap();
        AggregatedSignatureProof::empty(bits)
    }

    /// Create a proof with bits set for every validator in `vids`.
    fn make_proof_for_validators(vids: &[u64]) -> AggregatedSignatureProof {
        use ethlambda_types::attestation::AggregationBits;
        let max = vids.iter().copied().max().unwrap_or(0) as usize;
        let mut bits = AggregationBits::with_length(max + 1).unwrap();
        for &v in vids {
            bits.set(v as usize, true).unwrap();
        }
        AggregatedSignatureProof::empty(bits)
    }

    fn make_att_data(slot: u64) -> AttestationData {
        AttestationData {
            slot,
            head: Checkpoint::default(),
            target: Checkpoint::default(),
            source: Checkpoint::default(),
        }
    }

    #[test]
    fn payload_buffer_fifo_eviction() {
        let mut buf = PayloadBuffer::new(3);

        // Insert 3 distinct attestation data entries (different slots -> different roots)
        for slot in 1..=3u64 {
            let data = make_att_data(slot);
            buf.push(HashedAttestationData::new(data), make_proof());
        }
        assert_eq!(buf.len(), 3);

        // Pushing a 4th should evict the oldest (slot 1)
        let data = make_att_data(4);
        buf.push(HashedAttestationData::new(data), make_proof());
        assert_eq!(buf.len(), 3);

        // The oldest (slot 1) should be gone
        let att_data_1 = make_att_data(1);
        assert!(!buf.data.contains_key(&att_data_1.hash_tree_root()));
    }

    #[test]
    fn payload_buffer_multiple_proofs_per_data() {
        let mut buf = PayloadBuffer::new(10);
        let data = make_att_data(1);
        let data_root = data.hash_tree_root();

        // Insert 3 proofs with distinct participants for the same attestation data
        buf.push(
            HashedAttestationData::new(data.clone()),
            make_proof_for_validator(0),
        );
        buf.push(
            HashedAttestationData::new(data.clone()),
            make_proof_for_validator(1),
        );
        buf.push(
            HashedAttestationData::new(data),
            make_proof_for_validator(2),
        );

        // Should be 1 distinct data entry with 3 proofs
        assert_eq!(buf.len(), 1);
        assert_eq!(buf.data[&data_root].proofs.len(), 3);
    }

    #[test]
    fn payload_buffer_drain_empties_buffer() {
        let mut buf = PayloadBuffer::new(10);
        let data = make_att_data(1);

        buf.push(
            HashedAttestationData::new(data.clone()),
            make_proof_for_validator(0),
        );
        buf.push(
            HashedAttestationData::new(data),
            make_proof_for_validator(1),
        );

        let drained = buf.drain();
        assert_eq!(drained.len(), 2); // 2 proofs flattened
        assert!(buf.data.is_empty());
        assert!(buf.order.is_empty());
    }

    #[test]
    fn payload_buffer_push_superset_removes_strict_subset() {
        let mut buf = PayloadBuffer::new(10);
        let data = make_att_data(1);
        let data_root = data.hash_tree_root();

        buf.push(
            HashedAttestationData::new(data.clone()),
            make_proof_for_validators(&[1, 2]),
        );
        buf.push(
            HashedAttestationData::new(data),
            make_proof_for_validators(&[1, 2, 3]),
        );

        assert_eq!(buf.total_proofs, 1);
        assert_eq!(buf.data[&data_root].proofs.len(), 1);
        let kept: HashSet<u64> = buf.data[&data_root].proofs[0]
            .participant_indices()
            .collect();
        assert_eq!(kept, HashSet::from([1, 2, 3]));
    }

    #[test]
    fn payload_buffer_push_subset_is_skipped() {
        let mut buf = PayloadBuffer::new(10);
        let data = make_att_data(1);
        let data_root = data.hash_tree_root();

        buf.push(
            HashedAttestationData::new(data.clone()),
            make_proof_for_validators(&[1, 2, 3]),
        );
        buf.push(
            HashedAttestationData::new(data),
            make_proof_for_validators(&[1, 2]),
        );

        assert_eq!(buf.total_proofs, 1);
        assert_eq!(buf.data[&data_root].proofs.len(), 1);
        let kept: HashSet<u64> = buf.data[&data_root].proofs[0]
            .participant_indices()
            .collect();
        assert_eq!(kept, HashSet::from([1, 2, 3]));
    }

    #[test]
    fn payload_buffer_push_equal_participants_is_skipped() {
        let mut buf = PayloadBuffer::new(10);
        let data = make_att_data(1);
        let data_root = data.hash_tree_root();

        buf.push(
            HashedAttestationData::new(data.clone()),
            make_proof_for_validators(&[1, 2]),
        );
        buf.push(
            HashedAttestationData::new(data),
            make_proof_for_validators(&[1, 2]),
        );

        assert_eq!(buf.total_proofs, 1);
        assert_eq!(buf.data[&data_root].proofs.len(), 1);
    }

    #[test]
    fn payload_buffer_push_incomparable_proofs_coexist() {
        let mut buf = PayloadBuffer::new(10);
        let data = make_att_data(1);
        let data_root = data.hash_tree_root();

        buf.push(
            HashedAttestationData::new(data.clone()),
            make_proof_for_validators(&[1, 2]),
        );
        buf.push(
            HashedAttestationData::new(data),
            make_proof_for_validators(&[3, 4]),
        );

        assert_eq!(buf.total_proofs, 2);
        assert_eq!(buf.data[&data_root].proofs.len(), 2);
    }

    #[test]
    fn payload_buffer_push_superset_absorbs_multiple_subsets() {
        let mut buf = PayloadBuffer::new(10);
        let data = make_att_data(1);
        let data_root = data.hash_tree_root();

        // Three pairwise-incomparable singletons: all retained.
        buf.push(
            HashedAttestationData::new(data.clone()),
            make_proof_for_validators(&[1]),
        );
        buf.push(
            HashedAttestationData::new(data.clone()),
            make_proof_for_validators(&[2]),
        );
        buf.push(
            HashedAttestationData::new(data.clone()),
            make_proof_for_validators(&[3]),
        );
        assert_eq!(buf.total_proofs, 3);

        // Superset push absorbs all three at once.
        buf.push(
            HashedAttestationData::new(data),
            make_proof_for_validators(&[1, 2, 3]),
        );

        assert_eq!(buf.total_proofs, 1);
        assert_eq!(buf.data[&data_root].proofs.len(), 1);
        // `order` still contains the single entry.
        assert_eq!(buf.order.len(), 1);
        assert_eq!(buf.order.front().copied(), Some(data_root));
    }

    #[test]
    fn payload_buffer_push_mixed_kept_and_removed() {
        let mut buf = PayloadBuffer::new(10);
        let data = make_att_data(1);
        let data_root = data.hash_tree_root();

        buf.push(
            HashedAttestationData::new(data.clone()),
            make_proof_for_validators(&[1, 2]),
        );
        buf.push(
            HashedAttestationData::new(data.clone()),
            make_proof_for_validators(&[5, 6]),
        );
        buf.push(
            HashedAttestationData::new(data),
            make_proof_for_validators(&[1, 2, 3]),
        );

        assert_eq!(buf.total_proofs, 2);

        let sets: HashSet<Vec<u64>> = buf.data[&data_root]
            .proofs
            .iter()
            .map(|p| {
                let mut v: Vec<u64> = p.participant_indices().collect();
                v.sort_unstable();
                v
            })
            .collect();
        assert!(sets.contains(&vec![5, 6]));
        assert!(sets.contains(&vec![1, 2, 3]));
    }

    #[test]
    fn payload_buffer_push_empty_participants_subsumed_by_anything() {
        let mut buf = PayloadBuffer::new(10);
        let data = make_att_data(1);
        let data_root = data.hash_tree_root();

        // Empty-participant proof inserted first: anything that follows absorbs it.
        buf.push(
            HashedAttestationData::new(data.clone()),
            make_proof_for_validators(&[]),
        );
        assert_eq!(buf.total_proofs, 1);
        buf.push(
            HashedAttestationData::new(data.clone()),
            make_proof_for_validators(&[1, 2]),
        );
        assert_eq!(buf.total_proofs, 1);
        assert_eq!(
            buf.data[&data_root].proofs[0]
                .participant_indices()
                .collect::<Vec<u64>>(),
            vec![1, 2]
        );

        // Empty-participant proof pushed against existing non-empty: incoming is subsumed, skipped.
        buf.push(
            HashedAttestationData::new(data),
            make_proof_for_validators(&[]),
        );
        assert_eq!(buf.total_proofs, 1);
    }

    #[test]
    fn payload_buffer_push_cross_data_root_independence() {
        let mut buf = PayloadBuffer::new(10);
        let data_a = make_att_data(1);
        let data_b = make_att_data(2);
        let root_a = data_a.hash_tree_root();
        let root_b = data_b.hash_tree_root();

        buf.push(
            HashedAttestationData::new(data_a),
            make_proof_for_validators(&[1, 2, 3]),
        );
        buf.push(
            HashedAttestationData::new(data_b),
            make_proof_for_validators(&[1, 2]),
        );

        // Different data_roots -> no cross-entry subsumption.
        assert_eq!(buf.total_proofs, 2);
        assert_eq!(buf.data[&root_a].proofs.len(), 1);
        assert_eq!(buf.data[&root_b].proofs.len(), 1);
    }

    #[test]
    fn payload_buffer_push_fifo_eviction_uses_total_proofs() {
        let mut buf = PayloadBuffer::new(2);
        let data_a = make_att_data(1);
        let data_b = make_att_data(2);
        let data_c = make_att_data(3);
        let root_a = data_a.hash_tree_root();
        let root_c = data_c.hash_tree_root();

        buf.push(
            HashedAttestationData::new(data_a),
            make_proof_for_validators(&[1]),
        );
        buf.push(
            HashedAttestationData::new(data_b),
            make_proof_for_validators(&[2, 3]),
        );
        // total_proofs == 3, over capacity -> evict oldest (root_a).
        // Pushing a third distinct data_root triggers eviction via capacity.
        buf.push(
            HashedAttestationData::new(data_c),
            make_proof_for_validators(&[4]),
        );

        assert!(!buf.data.contains_key(&root_a));
        assert!(buf.data.contains_key(&root_c));
        assert_eq!(buf.total_proofs, 2);
    }

    /// Build an attestation message at `slot` whose target points at `target_root`,
    /// distinct from the default zero target so two such datas have different roots.
    fn make_att_data_for_target(slot: u64, target_root: H256) -> AttestationData {
        AttestationData {
            slot,
            head: Checkpoint::default(),
            target: Checkpoint {
                root: target_root,
                slot,
            },
            source: Checkpoint::default(),
        }
    }

    /// When two aggregations share `slot` but disagree on the target
    /// (same-slot equivocation), the *first inserted* aggregation must win for
    /// the validators that participate in both. The fork-choice spec test
    /// `test_same_slot_equivocating_attesters_count_once` depends on this.
    /// HashMap iteration would make this RandomState-seeded and flaky.
    #[test]
    fn extract_latest_attestations_first_inserted_wins_on_slot_tie() {
        let target_a = H256([0xaa; 32]);
        let target_b = H256([0xbb; 32]);
        let data_a = make_att_data_for_target(3, target_a);
        let data_b = make_att_data_for_target(3, target_b);
        assert_ne!(data_a.hash_tree_root(), data_b.hash_tree_root());

        // Order 1: A then B -> validators 0,1 (in both) must see A.
        let mut buf = PayloadBuffer::new(10);
        buf.push(
            HashedAttestationData::new(data_a.clone()),
            make_proof_for_validators(&[0, 1, 2]),
        );
        buf.push(
            HashedAttestationData::new(data_b.clone()),
            make_proof_for_validators(&[0, 1, 3, 4]),
        );
        let extracted = buf.extract_latest_attestations();
        assert_eq!(extracted[&0].target.root, target_a);
        assert_eq!(extracted[&1].target.root, target_a);
        assert_eq!(extracted[&2].target.root, target_a);
        assert_eq!(extracted[&3].target.root, target_b);
        assert_eq!(extracted[&4].target.root, target_b);

        // Order 2: B then A -> validators 0,1 must now see B.
        let mut buf = PayloadBuffer::new(10);
        buf.push(
            HashedAttestationData::new(data_b),
            make_proof_for_validators(&[0, 1, 3, 4]),
        );
        buf.push(
            HashedAttestationData::new(data_a),
            make_proof_for_validators(&[0, 1, 2]),
        );
        let extracted = buf.extract_latest_attestations();
        assert_eq!(extracted[&0].target.root, target_b);
        assert_eq!(extracted[&1].target.root, target_b);
        assert_eq!(extracted[&2].target.root, target_a);
        assert_eq!(extracted[&3].target.root, target_b);
        assert_eq!(extracted[&4].target.root, target_b);
    }

    /// `drain` must hand back entries in insertion order so that
    /// `promote_new_aggregated_payloads` lands them in known_payloads in the
    /// same order, preserving same-slot equivocation semantics through the
    /// new -> known migration.
    #[test]
    fn drain_preserves_insertion_order() {
        let target_a = H256([0xaa; 32]);
        let target_b = H256([0xbb; 32]);
        let target_c = H256([0xcc; 32]);
        let data_a = make_att_data_for_target(1, target_a);
        let data_b = make_att_data_for_target(2, target_b);
        let data_c = make_att_data_for_target(3, target_c);

        let mut buf = PayloadBuffer::new(10);
        buf.push(HashedAttestationData::new(data_a), make_proof());
        buf.push(HashedAttestationData::new(data_b), make_proof());
        buf.push(HashedAttestationData::new(data_c), make_proof());

        let drained = buf.drain();
        let slots: Vec<u64> = drained.iter().map(|(h, _)| h.data().slot).collect();
        assert_eq!(slots, vec![1, 2, 3]);
        assert!(buf.data.is_empty());
        assert!(buf.order.is_empty());
        assert_eq!(buf.total_proofs, 0);
    }

    fn make_dummy_sig() -> ValidatorSignature {
        use ethlambda_types::signature::LeanSignatureScheme;
        use leansig::{serialization::Serializable, signature::SignatureScheme};
        use rand::{SeedableRng, rngs::StdRng};

        static CACHED_SIG: std::sync::LazyLock<Vec<u8>> = std::sync::LazyLock::new(|| {
            let mut rng = StdRng::seed_from_u64(42);
            let lifetime = 1 << 5; // small for speed
            let (_pk, sk) = LeanSignatureScheme::key_gen(&mut rng, 0, lifetime);
            let sig = LeanSignatureScheme::sign(&sk, 0, &[0u8; 32]).unwrap();
            sig.to_bytes()
        });

        ValidatorSignature::from_bytes(&CACHED_SIG).expect("cached test signature")
    }

    #[test]
    fn gossip_buffer_fifo_eviction() {
        // Capacity of 3 signatures total
        let mut buf = GossipSignatureBuffer::new(3);

        // Insert 3 sigs across 3 data_roots (1 sig each)
        for slot in 1..=3u64 {
            let data = make_att_data(slot);
            buf.insert(HashedAttestationData::new(data), 0, make_dummy_sig());
        }
        assert_eq!(buf.total_signatures(), 3);
        assert_eq!(buf.len(), 3);

        // Insert a 4th - should evict the oldest (slot 1)
        let data4 = make_att_data(4);
        buf.insert(HashedAttestationData::new(data4), 0, make_dummy_sig());
        assert_eq!(buf.total_signatures(), 3);
        assert_eq!(buf.len(), 3);

        // Slot 1 should be gone
        let slot1_root = HashedAttestationData::new(make_att_data(1)).root();
        assert!(!buf.data.contains_key(&slot1_root));

        // Slots 2, 3, 4 should remain
        let slot2_root = HashedAttestationData::new(make_att_data(2)).root();
        let slot4_root = HashedAttestationData::new(make_att_data(4)).root();
        assert!(buf.data.contains_key(&slot2_root));
        assert!(buf.data.contains_key(&slot4_root));
    }

    #[test]
    fn gossip_buffer_dedup_last_write_wins() {
        let mut buf = GossipSignatureBuffer::new(100);
        let data = make_att_data(1);
        let hashed = HashedAttestationData::new(data);

        buf.insert(hashed.clone(), 0, make_dummy_sig());
        buf.insert(hashed.clone(), 0, make_dummy_sig());

        // Last-write-wins: overwrites the signature but count stays at 1
        assert_eq!(buf.total_signatures(), 1);
        assert_eq!(buf.len(), 1);
    }

    #[test]
    fn gossip_buffer_multiple_validators_per_root() {
        let mut buf = GossipSignatureBuffer::new(100);
        let data = make_att_data(1);

        buf.insert(
            HashedAttestationData::new(data.clone()),
            0,
            make_dummy_sig(),
        );
        buf.insert(
            HashedAttestationData::new(data.clone()),
            1,
            make_dummy_sig(),
        );
        buf.insert(
            HashedAttestationData::new(data.clone()),
            2,
            make_dummy_sig(),
        );

        assert_eq!(buf.total_signatures(), 3);
        assert_eq!(buf.len(), 1); // One data_root
    }

    #[test]
    fn gossip_buffer_delete_cleans_up() {
        let mut buf = GossipSignatureBuffer::new(100);
        let data = make_att_data(1);
        let root = HashedAttestationData::new(data.clone()).root();

        buf.insert(
            HashedAttestationData::new(data.clone()),
            0,
            make_dummy_sig(),
        );
        buf.insert(
            HashedAttestationData::new(data.clone()),
            1,
            make_dummy_sig(),
        );
        assert_eq!(buf.total_signatures(), 2);

        // Delete one sig - root should remain
        buf.delete(&[(0, root)]);
        assert_eq!(buf.total_signatures(), 1);
        assert_eq!(buf.len(), 1);

        // Delete last sig - root should be fully removed
        buf.delete(&[(1, root)]);
        assert_eq!(buf.total_signatures(), 0);
        assert_eq!(buf.len(), 0);
        assert!(buf.order.is_empty());
    }

    #[test]
    fn gossip_buffer_prune_by_slot() {
        let mut buf = GossipSignatureBuffer::new(100);

        // Insert sigs at slots 1, 2, 3, 4, 5
        for slot in 1..=5u64 {
            buf.insert(
                HashedAttestationData::new(make_att_data(slot)),
                0,
                make_dummy_sig(),
            );
        }
        assert_eq!(buf.total_signatures(), 5);

        // Prune slots <= 3
        let pruned = buf.prune(3);
        assert_eq!(pruned, 3);
        assert_eq!(buf.total_signatures(), 2);
        assert_eq!(buf.len(), 2);
        assert_eq!(buf.order.len(), 2);
    }

    #[test]
    fn gossip_buffer_eviction_removes_whole_root() {
        // Capacity of 4 signatures
        let mut buf = GossipSignatureBuffer::new(4);

        // Slot 1: 3 validators
        let data1 = make_att_data(1);
        buf.insert(
            HashedAttestationData::new(data1.clone()),
            0,
            make_dummy_sig(),
        );
        buf.insert(
            HashedAttestationData::new(data1.clone()),
            1,
            make_dummy_sig(),
        );
        buf.insert(
            HashedAttestationData::new(data1.clone()),
            2,
            make_dummy_sig(),
        );

        // Slot 2: 1 validator
        let data2 = make_att_data(2);
        buf.insert(
            HashedAttestationData::new(data2.clone()),
            0,
            make_dummy_sig(),
        );
        assert_eq!(buf.total_signatures(), 4);

        // Insert slot 3 - should evict slot 1 (3 sigs), now total = 2
        let data3 = make_att_data(3);
        buf.insert(HashedAttestationData::new(data3), 0, make_dummy_sig());

        let slot1_root = HashedAttestationData::new(data1).root();
        assert!(!buf.data.contains_key(&slot1_root));
        assert_eq!(buf.total_signatures(), 2); // slot 2 (1) + slot 3 (1)
        assert_eq!(buf.len(), 2);
    }
}
