//! Per-slot attestation aggregate coverage computation.
//!
//! Mirrors the producer side of [zeam#876](https://github.com/blockblaz/zeam/pull/876)
//! on top of the metrics registered by leanSpec PR #735.
//!
//! All `Coverage` instances are bound to a fixed `(validator_count,
//! committee_count)` pair from genesis state; ethlambda's validator set
//! is immutable across slots, so no resize handling is required.

use ethlambda_storage::Store;
use ethlambda_types::{
    attestation::{AggregationBits, validator_indices},
    block::AggregatedSignatureProof,
    primitives::HashTreeRoot,
};

use crate::metrics;

/// Per-validator and per-subnet presence bitsets for one coverage section.
#[derive(Debug, Clone)]
pub struct Coverage {
    seen: Vec<bool>,
    has_subnet: Vec<bool>,
}

impl Coverage {
    pub fn new(validator_count: usize, committee_count: usize) -> Self {
        Self {
            seen: vec![false; validator_count],
            has_subnet: vec![false; committee_count],
        }
    }

    /// Subnet for validator `vid` matches `crates/net/p2p/src/lib.rs:241`
    /// (`vid % committee_count`).
    pub fn add_bits(&mut self, bits: &AggregationBits) {
        let committee_count = self.has_subnet.len();
        if committee_count == 0 {
            return;
        }
        for vid in validator_indices(bits) {
            let vid = vid as usize;
            if vid < self.seen.len() {
                self.seen[vid] = true;
                self.has_subnet[vid % committee_count] = true;
            }
        }
    }

    /// Convenience: merge all `proofs` for one entry.
    pub fn add_proofs(&mut self, proofs: &[AggregatedSignatureProof]) {
        for proof in proofs {
            self.add_bits(&proof.participants);
        }
    }

    pub fn merge_from(&mut self, other: &Self) {
        for (dst, &src) in self.seen.iter_mut().zip(other.seen.iter()) {
            *dst |= src;
        }
        for (dst, &src) in self.has_subnet.iter_mut().zip(other.has_subnet.iter()) {
            *dst |= src;
        }
    }

    pub fn count_seen(&self) -> usize {
        self.seen.iter().filter(|&&b| b).count()
    }

    pub fn count_subnets(&self) -> usize {
        self.has_subnet.iter().filter(|&&b| b).count()
    }

    pub fn seen(&self) -> &[bool] {
        &self.seen
    }

    /// Mark validator `vid` (and its derived subnet) as covered.
    pub fn mark(&mut self, vid: usize, subnet: usize) {
        if vid < self.seen.len() {
            self.seen[vid] = true;
        }
        if subnet < self.has_subnet.len() {
            self.has_subnet[subnet] = true;
        }
    }
}

/// Symmetric-difference counts: `(a_only, b_only)` validators.
pub fn diff_counts(a: &Coverage, b: &Coverage) -> (usize, usize) {
    let len = a.seen.len().min(b.seen.len());
    let mut a_only = 0;
    let mut b_only = 0;
    for i in 0..len {
        match (a.seen[i], b.seen[i]) {
            (true, false) => a_only += 1,
            (false, true) => b_only += 1,
            _ => {}
        }
    }
    (a_only, b_only)
}

/// Emit `validators{section, subnet="combined"}` + `subnets{section}` for one section.
///
/// Per-subnet (`subnet="subnet_N"`) series intentionally stay at zero until a
/// future PR wires per-subnet emission; this matches zeam's current emission
/// pattern (one series per section).
pub fn record_section(section: &str, coverage: &Coverage) {
    metrics::set_attestation_aggregate_coverage_validators(
        section,
        "combined",
        coverage.count_seen() as i64,
    );
    metrics::set_attestation_aggregate_coverage_subnets(section, coverage.count_subnets() as i64);
}

/// Emit `diff_validators{direction}` for both directions.
pub fn record_diff(block_only: usize, timely_only: usize) {
    metrics::set_attestation_aggregate_coverage_diff_validators("block_only", block_only as i64);
    metrics::set_attestation_aggregate_coverage_diff_validators("timely_only", timely_only as i64);
}

/// Emit the post-block-merge coverage report for `reporting_slot` (the slot
/// that just finished). Reads pre-merge / late / block snapshots from the
/// Store, computes `combined` as their union, and records all 5 metrics.
pub fn emit_post_block_report(store: &Store, committee_count: u64, reporting_slot: u64) {
    let validator_count = store.head_state().validators.len();
    if validator_count == 0 || committee_count == 0 {
        return;
    }
    let cc = committee_count as usize;

    // `timely` — pre-merge snapshot of new_payloads (i.e., "prev_new" in zeam).
    let mut timely = Coverage::new(validator_count, cc);
    if let Some(snap) = store.pre_merge_new_coverage()
        && snap.slot == reporting_slot
    {
        for bits in &snap.participant_bits {
            timely.add_bits(bits);
        }
    }

    // `late` — current new_payloads that match the reporting slot
    // (arrived after the last merge).
    let mut late = Coverage::new(validator_count, cc);
    for (data, proofs) in store.new_aggregated_payloads().values() {
        if data.slot == reporting_slot {
            late.add_proofs(proofs);
        }
    }

    // `block` — participant bits from the most-recently-imported block,
    // if and only if its slot matches.
    let mut block = Coverage::new(validator_count, cc);
    if let Some(snap) = store.last_block_coverage()
        && snap.slot == reporting_slot
    {
        for bits in &snap.participant_bits {
            block.add_bits(bits);
        }
    }

    // `combined` — union of all three sources.
    let mut combined = Coverage::new(validator_count, cc);
    combined.merge_from(&timely);
    combined.merge_from(&late);
    combined.merge_from(&block);

    record_section("timely", &timely);
    record_section("late", &late);
    record_section("block", &block);
    record_section("combined", &combined);

    let (block_only, timely_only) = diff_counts(&block, &timely);
    record_diff(block_only, timely_only);
}

/// Emit `agg_start_new` coverage. Called right before fork-choice aggregation
/// runs (interval 2).
pub fn emit_agg_start_new(store: &Store, committee_count: u64) {
    let validator_count = store.head_state().validators.len();
    if validator_count == 0 || committee_count == 0 {
        return;
    }
    let mut cov = Coverage::new(validator_count, committee_count as usize);
    for (_, proofs) in store.new_aggregated_payloads().values() {
        cov.add_proofs(proofs);
    }
    record_section("agg_start_new", &cov);
}

/// Emit `proposal_payloads`, `proposal_gossip`, `proposal_combined` for a
/// block we are about to publish. We classify validators set in the final
/// block as either covered by an existing known-payload proof for that
/// AttestationData (`payloads`) or as gossip-only (`gossip`).
pub fn emit_proposal_coverage<'a, I>(store: &Store, committee_count: u64, selected: I)
where
    I: IntoIterator<Item = &'a ethlambda_types::attestation::AggregatedAttestation>,
{
    let validator_count = store.head_state().validators.len();
    if validator_count == 0 || committee_count == 0 {
        return;
    }
    let cc = committee_count as usize;

    let mut combined = Coverage::new(validator_count, cc);
    let mut payloads = Coverage::new(validator_count, cc);
    let mut gossip = Coverage::new(validator_count, cc);

    // For each AttestationData in the final block, OR together the known
    // payload proofs for that data — those validators are payload-covered.
    let known = store.known_aggregated_payloads();
    let mut payload_seen = vec![false; validator_count];
    for att in selected {
        combined.add_bits(&att.aggregation_bits);
        let data_root = att.data.hash_tree_root();
        if let Some((_, proofs)) = known.get(&data_root) {
            for proof in proofs {
                for vid in validator_indices(&proof.participants) {
                    let vid = vid as usize;
                    if vid < payload_seen.len() {
                        payload_seen[vid] = true;
                    }
                }
            }
        }
    }

    for (vid, &is_final) in combined.seen().iter().enumerate() {
        if !is_final {
            continue;
        }
        let subnet = vid % cc;
        if payload_seen[vid] {
            payloads.mark(vid, subnet);
        } else {
            gossip.mark(vid, subnet);
        }
    }

    record_section("proposal_payloads", &payloads);
    record_section("proposal_gossip", &gossip);
    record_section("proposal_combined", &combined);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_types::attestation::AggregationBits;

    fn make_bits(len: usize, indices: &[usize]) -> AggregationBits {
        let mut bits = AggregationBits::with_length(len).unwrap();
        for &i in indices {
            bits.set(i, true).unwrap();
        }
        bits
    }

    #[test]
    fn add_bits_marks_validators_and_subnets() {
        // 8 validators, 4 subnets → vid 1 → subnet 1, vid 5 → subnet 1, vid 6 → subnet 2.
        let mut cov = Coverage::new(8, 4);
        cov.add_bits(&make_bits(8, &[1, 5, 6]));

        assert!(!cov.seen()[0]);
        assert!(cov.seen()[1]);
        assert!(cov.seen()[5]);
        assert!(cov.seen()[6]);
        assert_eq!(cov.count_seen(), 3);
        assert_eq!(cov.count_subnets(), 2);
    }

    #[test]
    fn merge_from_is_set_union() {
        let mut a = Coverage::new(8, 4);
        a.add_bits(&make_bits(8, &[0, 1]));
        let mut b = Coverage::new(8, 4);
        b.add_bits(&make_bits(8, &[1, 2]));

        a.merge_from(&b);
        assert_eq!(a.count_seen(), 3);
        assert!(a.seen()[0] && a.seen()[1] && a.seen()[2]);
    }

    #[test]
    fn diff_counts_is_symmetric_difference() {
        let mut block = Coverage::new(8, 4);
        block.add_bits(&make_bits(8, &[0, 1, 2]));
        let mut timely = Coverage::new(8, 4);
        timely.add_bits(&make_bits(8, &[1, 2, 3]));

        let (block_only, timely_only) = diff_counts(&block, &timely);
        assert_eq!(block_only, 1);
        assert_eq!(timely_only, 1);
    }

    #[test]
    fn empty_coverage_counts_zero() {
        let cov = Coverage::new(8, 4);
        assert_eq!(cov.count_seen(), 0);
        assert_eq!(cov.count_subnets(), 0);
    }

    #[test]
    fn zero_committee_count_is_inert() {
        let mut cov = Coverage::new(8, 0);
        cov.add_bits(&make_bits(8, &[0, 1, 2]));
        assert_eq!(cov.count_seen(), 0);
        assert_eq!(cov.count_subnets(), 0);
    }

    #[test]
    fn add_bits_ignores_out_of_range_indices() {
        let mut cov = Coverage::new(4, 2);
        cov.add_bits(&make_bits(8, &[0, 5]));
        assert!(cov.seen()[0]);
        assert_eq!(cov.count_seen(), 1);
        assert_eq!(cov.count_subnets(), 1);
    }
}
