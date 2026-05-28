//! Attestation aggregate coverage emission.
//!
//! Pure observability — nothing here feeds back into fork choice or the state
//! transition. The emitters build `Vec<bool>` locals (`seen` for validators,
//! `has_subnet` for subnets, with subnet = `vid % committee_count`, matching
//! the gossip subnet assignment in `crates/net/p2p/src/lib.rs`) and push the
//! resulting counts to the coverage gauges registered in
//! [`crate::metrics`].

use ethlambda_storage::Store;
use ethlambda_types::attestation::{AggregatedAttestation, AggregationBits, validator_indices};

use crate::metrics;

/// Pre-merge snapshot of `new_payloads` participant bits, used by the
/// attestation aggregate coverage report.
///
/// Each entry is tagged with its attestation `data.slot` (the voting round) so
/// the consumer can filter to a single round at emit time — `new_payloads` may
/// hold entries spanning more than one slot. Holds raw participant bits; the
/// consumer constructs coverage bitsets at emit time using the current
/// validator and committee counts.
#[derive(Debug, Clone)]
pub(crate) struct CoverageSnapshot {
    pub(crate) entries: Vec<(u64, AggregationBits)>,
}

/// Capture the participant bits of every entry in `new_payloads` for the
/// attestation aggregate coverage report. Each entry is tagged with its
/// attestation `data.slot` so the post-block report can filter to a single
/// voting round (`new_payloads` may span multiple slots).
///
/// Returns `None` when `new_payloads` is empty so callers can keep their last
/// non-empty snapshot rather than overwriting it with nothing — a node that
/// missed a round still reports the round it last saw.
pub(crate) fn snapshot_new_payloads(store: &Store) -> Option<CoverageSnapshot> {
    let entries = store.new_aggregated_payload_participants();
    if entries.is_empty() {
        return None;
    }
    Some(CoverageSnapshot { entries })
}

fn cov_add(seen: &mut [bool], has_subnet: &mut [bool], bits: &AggregationBits) {
    let cc = has_subnet.len();
    if cc == 0 {
        return;
    }
    for vid in validator_indices(bits) {
        let vid = vid as usize;
        if vid < seen.len() {
            seen[vid] = true;
            has_subnet[vid % cc] = true;
        }
    }
}

fn cov_record(section: &str, seen: &[bool], has_subnet: &[bool]) {
    // TODO: emit a per-subnet breakdown (subnet=subnet_N) alongside the
    // subnet=combined total. `has_subnet` already tracks which subnets are
    // covered, but we only report the aggregate count here; the per-subnet
    // label is reserved in the metric definition and not yet populated.
    metrics::set_attestation_aggregate_coverage_validators(
        section,
        "combined",
        seen.iter().filter(|&&b| b).count() as i64,
    );
    metrics::set_attestation_aggregate_coverage_subnets(
        section,
        has_subnet.iter().filter(|&&b| b).count() as i64,
    );
}

fn or_into(dst: &mut [bool], src: &[bool]) {
    for (d, &s) in dst.iter_mut().zip(src) {
        *d |= s;
    }
}

/// Post-block coverage report for `reporting_slot`. Emits `timely` / `late` /
/// `block` / `combined` sections plus the `diff_validators` symmetric
/// difference between `block` and `timely`. Called at interval 1 of the
/// next slot.
pub(crate) fn emit_post_block_coverage(
    store: &Store,
    pre_merge_coverage: Option<&CoverageSnapshot>,
    committee_count: u64,
    reporting_slot: u64,
) {
    let validator_count = store.head_state().validators.len();
    if validator_count == 0 || committee_count == 0 {
        return;
    }
    let cc = committee_count as usize;
    let (mut timely_v, mut timely_s) = (vec![false; validator_count], vec![false; cc]);
    let (mut late_v, mut late_s) = (vec![false; validator_count], vec![false; cc]);
    let (mut block_v, mut block_s) = (vec![false; validator_count], vec![false; cc]);

    // Every section is the same cohort: validators whose attestations *for*
    // `reporting_slot` (`data.slot == reporting_slot`) were seen via that
    // channel.

    // `timely`: pre-merge snapshot of `new_payloads`, filtered to this round.
    if let Some(snap) = pre_merge_coverage {
        for (data_slot, bits) in &snap.entries {
            if *data_slot == reporting_slot {
                cov_add(&mut timely_v, &mut timely_s, bits);
            }
        }
    }
    // `late`: current `new_payloads` for this round (arrived after the promote).
    for (data_slot, bits) in store.new_aggregated_payload_participants() {
        if data_slot == reporting_slot {
            cov_add(&mut late_v, &mut late_s, &bits);
        }
    }
    // `block`: attestations included in the canonical head block. At interval 1
    // the head is normally the block proposed at `reporting_slot + 1`, which
    // carries this round's votes; filter by `data.slot` so we count the same
    // cohort even if the head is at a different slot.
    if let Some(block) = store.get_block(&store.head()) {
        for att in block.body.attestations.iter() {
            if att.data.slot == reporting_slot {
                cov_add(&mut block_v, &mut block_s, &att.aggregation_bits);
            }
        }
    }

    let mut combined_v = timely_v.clone();
    let mut combined_s = timely_s.clone();
    or_into(&mut combined_v, &late_v);
    or_into(&mut combined_s, &late_s);
    or_into(&mut combined_v, &block_v);
    or_into(&mut combined_s, &block_s);

    // Only report a round once the canonical head block actually carries its
    // votes (`block_v` non-empty). Gating on `combined` instead would still
    // fire on a missed slot — the `timely` snapshot for the round is populated
    // while `block_v` is all-false — pushing exactly the misleading
    // `block_only=0, timely_only=N` the diff is meant to avoid. When there is
    // no block for the round the gauges retain their previous value.
    if !block_v.iter().any(|&b| b) {
        return;
    }

    cov_record("timely", &timely_v, &timely_s);
    cov_record("late", &late_v, &late_s);
    cov_record("block", &block_v, &block_s);
    cov_record("combined", &combined_v, &combined_s);

    let (block_only, timely_only) =
        block_v
            .iter()
            .zip(timely_v.iter())
            .fold((0i64, 0i64), |(b, t), (bv, tv)| match (bv, tv) {
                (true, false) => (b + 1, t),
                (false, true) => (b, t + 1),
                _ => (b, t),
            });
    metrics::set_attestation_aggregate_coverage_diff_validators("block_only", block_only);
    metrics::set_attestation_aggregate_coverage_diff_validators("timely_only", timely_only);
}

/// `agg_start_new` coverage from `new_payloads`, called right before fork-
/// choice aggregation runs at interval 2.
pub(crate) fn emit_agg_start_new_coverage(store: &Store, committee_count: u64) {
    let validator_count = store.head_state().validators.len();
    if validator_count == 0 || committee_count == 0 {
        return;
    }
    let cc = committee_count as usize;
    let mut seen = vec![false; validator_count];
    let mut has_subnet = vec![false; cc];
    for (_slot, bits) in store.new_aggregated_payload_participants() {
        cov_add(&mut seen, &mut has_subnet, &bits);
    }
    cov_record("agg_start_new", &seen, &has_subnet);
}

/// `proposal_combined` coverage for a block we are about to publish: the full
/// set of validators included across the block's aggregated attestations.
pub(crate) fn emit_proposal_coverage<'a>(
    store: &Store,
    committee_count: u64,
    selected: impl IntoIterator<Item = &'a AggregatedAttestation>,
) {
    let validator_count = store.head_state().validators.len();
    if validator_count == 0 || committee_count == 0 {
        return;
    }
    let cc = committee_count as usize;
    let mut combined_v = vec![false; validator_count];
    let mut combined_s = vec![false; cc];
    for att in selected {
        cov_add(&mut combined_v, &mut combined_s, &att.aggregation_bits);
    }
    cov_record("proposal_combined", &combined_v, &combined_s);
}
