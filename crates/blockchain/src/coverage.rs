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
    metrics::set_attestation_aggregate_coverage_validators(
        section,
        "combined",
        seen.iter().filter(|&&b| b).count() as i64,
    );
    let cc = has_subnet.len();
    if cc > 0 {
        let mut subnet_counts = vec![0i64; cc];
        for (vid, &was_seen) in seen.iter().enumerate() {
            if was_seen {
                subnet_counts[vid % cc] += 1;
            }
        }
        for (i, &count) in subnet_counts.iter().enumerate() {
            metrics::set_attestation_aggregate_coverage_validators(
                section,
                &format!("subnet_{i}"),
                count,
            );
        }
    }
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
    if let Ok(Some(block)) = store.get_block(&store.head().expect("head exists")) {
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

    // Always record the four section gauges, including a genuine all-zero
    // reading. A round can legitimately see no votes for `reporting_slot`
    // (an empty slot, or a proposer that dropped every attestation), and
    // that zero is real information a Grafana reader needs: it renders as a
    // dip on the section's timeseries, distinguishable from a gauge that
    // silently kept its last value. Do not gate these on `block_v` — that
    // guard below is scoped to the diff gauges only.
    cov_record("timely", &timely_v, &timely_s);
    cov_record("late", &late_v, &late_s);
    cov_record("block", &block_v, &block_s);
    cov_record("combined", &combined_v, &combined_s);

    // The `block_only`/`timely_only` diff is only meaningful once the
    // canonical head block has actually reported this round (`block_v`
    // non-empty). Gating on `combined` instead would still fire on a missed
    // slot — the `timely` snapshot for the round is populated while
    // `block_v` is all-false — pushing exactly the misleading
    // `block_only=0, timely_only=N` this guard exists to avoid. Unlike the
    // four sections above, there is no "genuine zero" to fall back on here
    // (the comparison itself is undefined, not merely empty), so when there
    // is no block for the round yet the diff gauges keep their previous
    // value.
    if !block_v.iter().any(|&b| b) {
        return;
    }

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

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use ethlambda_storage::{ForkCheckpoints, Store, backend::InMemoryBackend};
    use ethlambda_types::{
        attestation::AttestationData,
        block::{AggregatedAttestations, Block, BlockBody, MultiMessageAggregate, SignedBlock},
        checkpoint::Checkpoint,
        primitives::H256,
        state::{State, Validator},
    };

    use super::*;

    /// Serializes the tests below: they all read and write the same
    /// process-global Prometheus gauges (`LEAN_ATTESTATION_AGGREGATE_COVERAGE_*`
    /// in `crate::metrics`), and `cargo test` runs unit tests within a binary
    /// concurrently by default.
    static METRICS_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn make_bits(indices: &[usize]) -> AggregationBits {
        let max = indices.iter().copied().max().unwrap_or(0);
        let mut bits = AggregationBits::with_length(max + 1).unwrap();
        for &i in indices {
            bits.set(i, true).unwrap();
        }
        bits
    }

    fn make_validator(index: u64) -> Validator {
        Validator {
            attestation_pubkey: [0u8; 52],
            proposal_pubkey: [0u8; 52],
            index,
        }
    }

    fn new_test_store(validator_count: u64) -> Store {
        let validators = (0..validator_count).map(make_validator).collect();
        let genesis_state = State::from_genesis(1000, validators);
        let backend = Arc::new(InMemoryBackend::new());
        Store::from_anchor_state(backend, genesis_state)
    }

    /// Insert a child block of `genesis` at slot 1, with the given
    /// attestations in its body, and make it the new head. Also inserts the
    /// matching post-state (genesis's, slot-advanced) so `head_state()`
    /// resolves. Returns the new block's root.
    fn insert_head_block(
        store: &mut Store,
        genesis: H256,
        attestations: Vec<AggregatedAttestation>,
    ) -> H256 {
        let body = BlockBody {
            attestations: AggregatedAttestations::try_from(attestations).expect("within limit"),
        };
        let block = Block {
            slot: 1,
            proposer_index: 0,
            parent_root: genesis,
            state_root: H256::ZERO,
            body,
        };
        let root = H256([1u8; 32]);
        let signed_block = SignedBlock {
            message: block,
            proof: MultiMessageAggregate::default(),
        };
        store
            .insert_signed_block(root, signed_block)
            .expect("insert head block should succeed");

        let genesis_state = store
            .get_state(&genesis)
            .expect("get genesis state")
            .expect("genesis state exists");
        let mut head_state = genesis_state.clone();
        head_state.slot = genesis_state.slot + 1;
        head_state.latest_block_header.parent_root = genesis;
        let mut hbh = genesis_state.historical_block_hashes.to_vec();
        hbh.push(genesis);
        head_state.historical_block_hashes = hbh.try_into().expect("within limit");
        store
            .insert_state(root, head_state)
            .expect("insert head state should succeed");

        store
            .update_checkpoints(ForkCheckpoints::head_only(root))
            .expect("update_checkpoints should succeed");
        root
    }

    /// Regression test for the coverage-freeze bug: a round whose canonical
    /// head block carries no votes for it (an empty slot, or a proposer that
    /// dropped every attestation) must still report a genuine zero on the
    /// four section gauges, not silently retain whatever value they held
    /// before. Fails without the fix, since the old early return skipped
    /// every `cov_record` call and left the pre-seeded sentinels untouched.
    #[test]
    fn emit_post_block_coverage_records_zero_when_block_has_no_round_votes() {
        let _guard = METRICS_TEST_LOCK.lock().unwrap();

        let mut store = new_test_store(2);
        let genesis = store.head().expect("genesis head exists");
        insert_head_block(&mut store, genesis, vec![]);

        // Sentinel distinguishable from any real count this call could
        // produce, so a frozen gauge is caught rather than accidentally
        // matching a real zero.
        for section in ["timely", "late", "block", "combined"] {
            metrics::set_attestation_aggregate_coverage_validators(section, "combined", 42);
        }
        metrics::set_attestation_aggregate_coverage_diff_validators("block_only", 42);
        metrics::set_attestation_aggregate_coverage_diff_validators("timely_only", 42);

        emit_post_block_coverage(&store, None, 1, 0);

        for section in ["timely", "late", "block", "combined"] {
            assert_eq!(
                metrics::get_attestation_aggregate_coverage_validators(section, "combined"),
                0,
                "section {section} should report the real (zero) count for a round with \
                 no votes, not a stale value"
            );
        }
        // The block/timely diff is undefined without a reporting block, so it
        // correctly keeps its previous value here rather than guessing.
        assert_eq!(
            metrics::get_attestation_aggregate_coverage_diff_validators("block_only"),
            42
        );
        assert_eq!(
            metrics::get_attestation_aggregate_coverage_diff_validators("timely_only"),
            42
        );
    }

    /// Companion positive case: once the head block does carry a vote for the
    /// round, the section gauges reflect it and the diff gauges are computed
    /// (rather than being permanently disabled by the fix above).
    #[test]
    fn emit_post_block_coverage_records_real_counts_when_block_has_round_votes() {
        let _guard = METRICS_TEST_LOCK.lock().unwrap();

        let mut store = new_test_store(2);
        let genesis = store.head().expect("genesis head exists");

        let att_data = AttestationData {
            slot: 0,
            head: Checkpoint {
                root: genesis,
                slot: 0,
            },
            target: Checkpoint {
                root: genesis,
                slot: 0,
            },
            source: Checkpoint {
                root: genesis,
                slot: 0,
            },
        };
        let attestation = AggregatedAttestation {
            aggregation_bits: make_bits(&[1]),
            data: att_data,
        };
        insert_head_block(&mut store, genesis, vec![attestation]);

        emit_post_block_coverage(&store, None, 1, 0);

        assert_eq!(
            metrics::get_attestation_aggregate_coverage_validators("block", "combined"),
            1
        );
        assert_eq!(
            metrics::get_attestation_aggregate_coverage_validators("combined", "combined"),
            1
        );
        assert_eq!(
            metrics::get_attestation_aggregate_coverage_diff_validators("block_only"),
            1,
            "validator 1 is in the block but absent from the (empty) timely snapshot"
        );
        assert_eq!(
            metrics::get_attestation_aggregate_coverage_diff_validators("timely_only"),
            0
        );
    }
}
