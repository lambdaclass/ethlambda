//! Prometheus metrics for the blockchain module.

use std::time::Duration;

use ethlambda_metrics::*;

// --- Label sets ---

/// Section labels for attestation aggregate coverage gauges. Order matches
/// the names printed in slot/report logs.
///
/// Slot is the X-axis (time series), not a label dimension.
pub const ATTESTATION_AGGREGATE_COVERAGE_SECTIONS: &[&str] = &[
    "timely",
    "late",
    "block",
    "combined",
    "agg_start_new",
    "proposal_combined",
];

/// Validator-coverage delta directions between block payloads and
/// locally-aggregated pre-merge (`timely`) payloads.
pub const ATTESTATION_AGGREGATE_COVERAGE_DIFF_DIRECTIONS: &[&str] = &["block_only", "timely_only"];

/// Phase labels for `lean_block_proposal_attestation_build_phase_seconds`.
///
/// `select_payloads`: greedy per-`AttestationData` proof selection.
/// `compact`: recursive merge of proofs sharing the same `AttestationData`.
/// `stf_simulate`: the single candidate-block state transition that seals the
/// state root. Unlike leanSpec (which re-runs the STF inside a fixed-point
/// loop), ethlambda projects justification/finalization incrementally during
/// `select_payloads` and runs the STF exactly once, so its `stf_simulate`
/// timing is a single observation per build rather than one per loop round.
pub const BLOCK_PROPOSAL_ATTESTATION_BUILD_PHASES: &[&str] =
    &["select_payloads", "compact", "stf_simulate"];

// --- Gauges ---

static LEAN_HEAD_SLOT: std::sync::LazyLock<IntGauge> = std::sync::LazyLock::new(|| {
    register_int_gauge!("lean_head_slot", "Latest slot of the lean chain").unwrap()
});

static LEAN_LATEST_JUSTIFIED_SLOT: std::sync::LazyLock<IntGauge> = std::sync::LazyLock::new(|| {
    register_int_gauge!("lean_latest_justified_slot", "Latest justified slot").unwrap()
});

static LEAN_LATEST_FINALIZED_SLOT: std::sync::LazyLock<IntGauge> = std::sync::LazyLock::new(|| {
    register_int_gauge!("lean_latest_finalized_slot", "Latest finalized slot").unwrap()
});

static LEAN_CURRENT_SLOT: std::sync::LazyLock<IntGauge> = std::sync::LazyLock::new(|| {
    register_int_gauge!("lean_current_slot", "Current slot of the lean chain").unwrap()
});

static LEAN_VALIDATORS_COUNT: std::sync::LazyLock<IntGauge> = std::sync::LazyLock::new(|| {
    register_int_gauge!(
        "lean_validators_count",
        "Number of validators managed by a node"
    )
    .unwrap()
});

static LEAN_SAFE_TARGET_SLOT: std::sync::LazyLock<IntGauge> = std::sync::LazyLock::new(|| {
    register_int_gauge!("lean_safe_target_slot", "Safe target slot").unwrap()
});

static LEAN_NODE_INFO: std::sync::LazyLock<IntGaugeVec> = std::sync::LazyLock::new(|| {
    register_int_gauge_vec!(
        "lean_node_info",
        "Node information (always 1)",
        &["name", "version"]
    )
    .unwrap()
});

static LEAN_NODE_START_TIME_SECONDS: std::sync::LazyLock<IntGauge> =
    std::sync::LazyLock::new(|| {
        register_int_gauge!(
            "lean_node_start_time_seconds",
            "Timestamp when node started"
        )
        .unwrap()
    });

static LEAN_GOSSIP_SIGNATURES: std::sync::LazyLock<IntGauge> = std::sync::LazyLock::new(|| {
    register_int_gauge!(
        "lean_gossip_signatures",
        "Number of gossip signatures in fork-choice store"
    )
    .unwrap()
});

static LEAN_LATEST_NEW_AGGREGATED_PAYLOADS: std::sync::LazyLock<IntGauge> =
    std::sync::LazyLock::new(|| {
        register_int_gauge!(
            "lean_latest_new_aggregated_payloads",
            "Number of new aggregated payload items"
        )
        .unwrap()
    });

static LEAN_LATEST_KNOWN_AGGREGATED_PAYLOADS: std::sync::LazyLock<IntGauge> =
    std::sync::LazyLock::new(|| {
        register_int_gauge!(
            "lean_latest_known_aggregated_payloads",
            "Number of known aggregated payload items"
        )
        .unwrap()
    });

static LEAN_IS_AGGREGATOR: std::sync::LazyLock<IntGauge> = std::sync::LazyLock::new(|| {
    register_int_gauge!(
        "lean_is_aggregator",
        "Validator's is_aggregator status. True=1, False=0"
    )
    .unwrap()
});

static LEAN_ATTESTATION_COMMITTEE_COUNT: std::sync::LazyLock<IntGauge> =
    std::sync::LazyLock::new(|| {
        register_int_gauge!(
            "lean_attestation_committee_count",
            "Number of attestation committees (ATTESTATION_COMMITTEE_COUNT)"
        )
        .unwrap()
    });

static LEAN_TABLE_BYTES: std::sync::LazyLock<IntGaugeVec> = std::sync::LazyLock::new(|| {
    register_int_gauge_vec!(
        "lean_table_bytes",
        "Byte size of a storage table (key + value bytes)",
        &["table"]
    )
    .unwrap()
});

static LEAN_ATTESTATION_AGGREGATE_COVERAGE_VALIDATORS: std::sync::LazyLock<IntGaugeVec> =
    std::sync::LazyLock::new(|| {
        register_int_gauge_vec!(
            "lean_attestation_aggregate_coverage_validators",
            "Validator coverage in attestation aggregate reports, labeled by section and \
             subnet. subnet=combined is the section total; subnet=subnet_N is the count of \
             validators in subnet N that were seen. Updated each slot (slot is the X-axis).",
            &["section", "subnet"]
        )
        .unwrap()
    });

static LEAN_ATTESTATION_AGGREGATE_COVERAGE_SUBNETS: std::sync::LazyLock<IntGaugeVec> =
    std::sync::LazyLock::new(|| {
        register_int_gauge_vec!(
            "lean_attestation_aggregate_coverage_subnets",
            "Number of covered subnets in attestation aggregate reports, labeled by section. \
             Updated each slot (slot is the X-axis).",
            &["section"]
        )
        .unwrap()
    });

static LEAN_ATTESTATION_AGGREGATE_COVERAGE_DIFF_VALIDATORS: std::sync::LazyLock<IntGaugeVec> =
    std::sync::LazyLock::new(|| {
        register_int_gauge_vec!(
            "lean_attestation_aggregate_coverage_diff_validators",
            "Count of validators in the symmetric difference between block-included aggregates \
             and locally-aggregated pre-merge (timely) aggregates for the same slot. \
             direction=block_only: in block but not in local pool. direction=timely_only: in \
             local pool but not in block. Updated each slot (slot is the X-axis).",
            &["direction"]
        )
        .unwrap()
    });

// --- Counters ---

static LEAN_ATTESTATIONS_VALID_TOTAL: std::sync::LazyLock<IntCounter> =
    std::sync::LazyLock::new(|| {
        register_int_counter!(
            "lean_attestations_valid_total",
            "Total number of valid attestations"
        )
        .unwrap()
    });

static LEAN_ATTESTATIONS_INVALID_TOTAL: std::sync::LazyLock<IntCounter> =
    std::sync::LazyLock::new(|| {
        register_int_counter!(
            "lean_attestations_invalid_total",
            "Total number of invalid attestations"
        )
        .unwrap()
    });

static LEAN_FORK_CHOICE_REORGS_TOTAL: std::sync::LazyLock<IntCounter> =
    std::sync::LazyLock::new(|| {
        register_int_counter!(
            "lean_fork_choice_reorgs_total",
            "Count of fork choice reorganizations"
        )
        .unwrap()
    });

static LEAN_PQ_SIG_AGGREGATED_SIGNATURES_TOTAL: std::sync::LazyLock<IntCounter> =
    std::sync::LazyLock::new(|| {
        register_int_counter!(
            "lean_pq_sig_aggregated_signatures_total",
            "Total number of aggregated signatures"
        )
        .unwrap()
    });

static LEAN_PQ_SIG_ATTESTATIONS_IN_AGGREGATED_SIGNATURES_TOTAL: std::sync::LazyLock<IntCounter> =
    std::sync::LazyLock::new(|| {
        register_int_counter!(
            "lean_pq_sig_attestations_in_aggregated_signatures_total",
            "Total number of attestations included into aggregated signatures"
        )
        .unwrap()
    });

static LEAN_PQ_SIG_AGGREGATED_SIGNATURES_VALID_TOTAL: std::sync::LazyLock<IntCounter> =
    std::sync::LazyLock::new(|| {
        register_int_counter!(
            "lean_pq_sig_aggregated_signatures_valid_total",
            "Total number of valid aggregated signatures"
        )
        .unwrap()
    });

static LEAN_PQ_SIG_AGGREGATED_SIGNATURES_INVALID_TOTAL: std::sync::LazyLock<IntCounter> =
    std::sync::LazyLock::new(|| {
        register_int_counter!(
            "lean_pq_sig_aggregated_signatures_invalid_total",
            "Total number of invalid aggregated signatures"
        )
        .unwrap()
    });

static LEAN_PQ_SIG_ATTESTATION_SIGNATURES_TOTAL: std::sync::LazyLock<IntCounter> =
    std::sync::LazyLock::new(|| {
        register_int_counter!(
            "lean_pq_sig_attestation_signatures_total",
            "Total number of individual attestation signatures"
        )
        .unwrap()
    });

static LEAN_PQ_SIG_ATTESTATION_SIGNATURES_VALID_TOTAL: std::sync::LazyLock<IntCounter> =
    std::sync::LazyLock::new(|| {
        register_int_counter!(
            "lean_pq_sig_attestation_signatures_valid_total",
            "Total number of valid individual attestation signatures"
        )
        .unwrap()
    });

static LEAN_PQ_SIG_ATTESTATION_SIGNATURES_INVALID_TOTAL: std::sync::LazyLock<IntCounter> =
    std::sync::LazyLock::new(|| {
        register_int_counter!(
            "lean_pq_sig_attestation_signatures_invalid_total",
            "Total number of invalid individual attestation signatures"
        )
        .unwrap()
    });

// --- Histograms ---

static LEAN_FORK_CHOICE_BLOCK_PROCESSING_TIME_SECONDS: std::sync::LazyLock<Histogram> =
    std::sync::LazyLock::new(|| {
        register_histogram!(
            "lean_fork_choice_block_processing_time_seconds",
            "Duration to process a block",
            vec![0.005, 0.01, 0.025, 0.05, 0.1, 1.0, 1.25, 1.5, 2.0, 4.0]
        )
        .unwrap()
    });

static LEAN_ATTESTATION_VALIDATION_TIME_SECONDS: std::sync::LazyLock<Histogram> =
    std::sync::LazyLock::new(|| {
        register_histogram!(
            "lean_attestation_validation_time_seconds",
            "Duration to validate an attestation",
            vec![0.005, 0.01, 0.025, 0.05, 0.1, 1.0]
        )
        .unwrap()
    });

static LEAN_PQ_SIG_ATTESTATION_SIGNING_TIME_SECONDS: std::sync::LazyLock<Histogram> =
    std::sync::LazyLock::new(|| {
        register_histogram!(
            "lean_pq_sig_attestation_signing_time_seconds",
            "Time taken to sign an attestation",
            vec![0.005, 0.01, 0.025, 0.05, 0.1, 1.0]
        )
        .unwrap()
    });

static LEAN_ATTESTATIONS_PRODUCTION_TIME_SECONDS: std::sync::LazyLock<Histogram> =
    std::sync::LazyLock::new(|| {
        register_histogram!(
            "lean_attestations_production_time_seconds",
            "Time taken to produce attestation",
            vec![0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 0.75, 1.0]
        )
        .unwrap()
    });

static LEAN_PQ_SIG_ATTESTATION_VERIFICATION_TIME_SECONDS: std::sync::LazyLock<Histogram> =
    std::sync::LazyLock::new(|| {
        register_histogram!(
            "lean_pq_sig_attestation_verification_time_seconds",
            "Time taken to verify an attestation signature",
            vec![0.005, 0.01, 0.025, 0.05, 0.1, 1.0]
        )
        .unwrap()
    });

static LEAN_PQ_SIG_AGGREGATED_SIGNATURES_BUILDING_TIME_SECONDS: std::sync::LazyLock<Histogram> =
    std::sync::LazyLock::new(|| {
        register_histogram!(
            "lean_pq_sig_aggregated_signatures_building_time_seconds",
            "Time taken to build an aggregated attestation signature",
            vec![0.1, 0.25, 0.5, 0.75, 1.0, 1.25, 1.5, 2.0, 4.0]
        )
        .unwrap()
    });

static LEAN_PQ_SIG_AGGREGATED_SIGNATURES_VERIFICATION_TIME_SECONDS: std::sync::LazyLock<Histogram> =
    std::sync::LazyLock::new(|| {
        register_histogram!(
            "lean_pq_sig_aggregated_signatures_verification_time_seconds",
            "Time taken to verify an aggregated attestation signature",
            vec![0.1, 0.25, 0.5, 0.75, 1.0, 1.25, 1.5, 2.0, 4.0]
        )
        .unwrap()
    });

static LEAN_AGGREGATED_PROOF_SIZE_BYTES: std::sync::LazyLock<Histogram> =
    std::sync::LazyLock::new(|| {
        register_histogram!(
            "lean_aggregated_proof_size_bytes",
            "Bytes size of an aggregated signature proof's proof_data field",
            vec![
                1024.0,
                4096.0,
                16384.0,
                65536.0,
                131_072.0,
                262_144.0,
                524_288.0,
                1_048_576.0
            ]
        )
        .unwrap()
    });

static LEAN_COMMITTEE_SIGNATURES_AGGREGATION_TIME_SECONDS: std::sync::LazyLock<Histogram> =
    std::sync::LazyLock::new(|| {
        register_histogram!(
            "lean_committee_signatures_aggregation_time_seconds",
            "Time taken to aggregate committee signatures",
            vec![0.05, 0.1, 0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0]
        )
        .unwrap()
    });

static LEAN_FORK_CHOICE_REORG_DEPTH: std::sync::LazyLock<Histogram> =
    std::sync::LazyLock::new(|| {
        register_histogram!(
            "lean_fork_choice_reorg_depth",
            "Depth of fork choice reorgs (in blocks)",
            vec![1.0, 2.0, 3.0, 5.0, 7.0, 10.0, 20.0, 30.0, 50.0, 100.0]
        )
        .unwrap()
    });

static LEAN_TICK_INTERVAL_DURATION_SECONDS: std::sync::LazyLock<Histogram> =
    std::sync::LazyLock::new(|| {
        register_histogram!(
            "lean_tick_interval_duration_seconds",
            "Elapsed time between clock ticks in seconds",
            vec![
                0.4, 0.6, 0.75, 0.8, 0.805, 0.81, 0.815, 0.82, 0.825, 0.85, 0.9, 1.0, 1.2, 1.6
            ]
        )
        .unwrap()
    });

// --- Block Production ---

static LEAN_BLOCK_AGGREGATED_PAYLOADS: std::sync::LazyLock<Histogram> =
    std::sync::LazyLock::new(|| {
        register_histogram!(
            "lean_block_aggregated_payloads",
            "Number of aggregated_payloads in a block",
            vec![1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0]
        )
        .unwrap()
    });

static LEAN_BLOCK_BUILDING_PAYLOAD_AGGREGATION_TIME_SECONDS: std::sync::LazyLock<Histogram> =
    std::sync::LazyLock::new(|| {
        register_histogram!(
            "lean_block_building_payload_aggregation_time_seconds",
            "Time taken to build aggregated_payloads during block building",
            vec![0.1, 0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0]
        )
        .unwrap()
    });

static LEAN_BLOCK_BUILDING_TIME_SECONDS: std::sync::LazyLock<Histogram> =
    std::sync::LazyLock::new(|| {
        register_histogram!(
            "lean_block_building_time_seconds",
            "Time taken to build a block",
            vec![0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 0.75, 1.0]
        )
        .unwrap()
    });

static LEAN_BLOCK_BUILDING_SUCCESS_TOTAL: std::sync::LazyLock<IntCounter> =
    std::sync::LazyLock::new(|| {
        register_int_counter!(
            "lean_block_building_success_total",
            "Successful block builds"
        )
        .unwrap()
    });

static LEAN_BLOCK_BUILDING_FAILURES_TOTAL: std::sync::LazyLock<IntCounter> =
    std::sync::LazyLock::new(|| {
        register_int_counter!("lean_block_building_failures_total", "Failed block builds").unwrap()
    });

// --- Block Proposal Attestation Selection (build_block fixed-point loop) ---

static LEAN_BLOCK_PROPOSAL_ATTESTATION_BUILD_PHASE_SECONDS: std::sync::LazyLock<HistogramVec> =
    std::sync::LazyLock::new(|| {
        register_histogram_vec!(
            "lean_block_proposal_attestation_build_phase_seconds",
            "Phase-level time in block-proposal attestation selection: select_payloads (greedy \
             per-AttestationData proof pick), compact (recursive merge of proofs per \
             AttestationData), stf_simulate (candidate block state transition).",
            &["phase"],
            vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0
            ]
        )
        .unwrap()
    });

static LEAN_BLOCK_PROPOSAL_ATTESTATION_BUILDS_TOTAL: std::sync::LazyLock<IntCounter> =
    std::sync::LazyLock::new(|| {
        register_int_counter!(
            "lean_block_proposal_attestation_builds_total",
            "Completed block-proposal attestation selection runs (one per proposal attempt)."
        )
        .unwrap()
    });

static LEAN_BLOCK_PROPOSAL_CHILD_PAYLOADS_CONSUMED_TOTAL: std::sync::LazyLock<IntCounter> =
    std::sync::LazyLock::new(|| {
        register_int_counter!(
            "lean_block_proposal_child_payloads_consumed_total",
            "Child aggregated payloads selected during greedy proof picking (before compaction)."
        )
        .unwrap()
    });

static LEAN_BLOCK_PROPOSAL_ATTESTATION_DATA_SELECTED: std::sync::LazyLock<Histogram> =
    std::sync::LazyLock::new(|| {
        register_histogram!(
            "lean_block_proposal_attestation_data_selected",
            "Distinct AttestationData entries in the proposal block body",
            vec![0.0, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0]
        )
        .unwrap()
    });

static LEAN_BLOCK_PROPOSAL_AGGREGATES_SELECTED: std::sync::LazyLock<Histogram> =
    std::sync::LazyLock::new(|| {
        register_histogram!(
            "lean_block_proposal_aggregates_selected",
            "Aggregated signature proofs in the proposal result after compaction",
            vec![0.0, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0]
        )
        .unwrap()
    });

// --- Sync Status ---

/// Node synchronization status.
pub enum SyncStatus {
    Idle,
    Syncing,
    Synced,
}

impl SyncStatus {
    fn as_str(&self) -> &'static str {
        match self {
            SyncStatus::Idle => "idle",
            SyncStatus::Syncing => "syncing",
            SyncStatus::Synced => "synced",
        }
    }

    const ALL: &[&str] = &["idle", "syncing", "synced"];
}

static LEAN_NODE_SYNC_STATUS: std::sync::LazyLock<IntGaugeVec> = std::sync::LazyLock::new(|| {
    register_int_gauge_vec!("lean_node_sync_status", "Node sync status", &["status"]).unwrap()
});

// --- Initialization ---

/// Register all metrics with the Prometheus registry so they appear in `/metrics` from startup.
pub fn init() {
    // Gauges
    std::sync::LazyLock::force(&LEAN_HEAD_SLOT);
    std::sync::LazyLock::force(&LEAN_LATEST_JUSTIFIED_SLOT);
    std::sync::LazyLock::force(&LEAN_LATEST_FINALIZED_SLOT);
    std::sync::LazyLock::force(&LEAN_CURRENT_SLOT);
    std::sync::LazyLock::force(&LEAN_VALIDATORS_COUNT);
    std::sync::LazyLock::force(&LEAN_SAFE_TARGET_SLOT);
    std::sync::LazyLock::force(&LEAN_NODE_INFO);
    std::sync::LazyLock::force(&LEAN_NODE_START_TIME_SECONDS);
    std::sync::LazyLock::force(&LEAN_GOSSIP_SIGNATURES);
    std::sync::LazyLock::force(&LEAN_LATEST_NEW_AGGREGATED_PAYLOADS);
    std::sync::LazyLock::force(&LEAN_LATEST_KNOWN_AGGREGATED_PAYLOADS);
    std::sync::LazyLock::force(&LEAN_IS_AGGREGATOR);
    std::sync::LazyLock::force(&LEAN_ATTESTATION_COMMITTEE_COUNT);
    std::sync::LazyLock::force(&LEAN_TABLE_BYTES);
    // Attestation aggregate coverage (leanMetrics: Fork-Choice Metrics).
    // Per upstream leanSpec, seed only the combined-subnet series for each
    // section; per-subnet series appear lazily when instrumentation writes them.
    std::sync::LazyLock::force(&LEAN_ATTESTATION_AGGREGATE_COVERAGE_VALIDATORS);
    std::sync::LazyLock::force(&LEAN_ATTESTATION_AGGREGATE_COVERAGE_SUBNETS);
    std::sync::LazyLock::force(&LEAN_ATTESTATION_AGGREGATE_COVERAGE_DIFF_VALIDATORS);
    for &section in ATTESTATION_AGGREGATE_COVERAGE_SECTIONS {
        LEAN_ATTESTATION_AGGREGATE_COVERAGE_VALIDATORS
            .with_label_values(&[section, "combined"])
            .set(0);
        LEAN_ATTESTATION_AGGREGATE_COVERAGE_SUBNETS
            .with_label_values(&[section])
            .set(0);
    }
    for &direction in ATTESTATION_AGGREGATE_COVERAGE_DIFF_DIRECTIONS {
        LEAN_ATTESTATION_AGGREGATE_COVERAGE_DIFF_VALIDATORS
            .with_label_values(&[direction])
            .set(0);
    }
    // Counters
    std::sync::LazyLock::force(&LEAN_ATTESTATIONS_VALID_TOTAL);
    std::sync::LazyLock::force(&LEAN_ATTESTATIONS_INVALID_TOTAL);
    std::sync::LazyLock::force(&LEAN_FORK_CHOICE_REORGS_TOTAL);
    std::sync::LazyLock::force(&LEAN_PQ_SIG_AGGREGATED_SIGNATURES_TOTAL);
    std::sync::LazyLock::force(&LEAN_PQ_SIG_ATTESTATIONS_IN_AGGREGATED_SIGNATURES_TOTAL);
    std::sync::LazyLock::force(&LEAN_PQ_SIG_AGGREGATED_SIGNATURES_VALID_TOTAL);
    std::sync::LazyLock::force(&LEAN_PQ_SIG_AGGREGATED_SIGNATURES_INVALID_TOTAL);
    std::sync::LazyLock::force(&LEAN_PQ_SIG_ATTESTATION_SIGNATURES_TOTAL);
    std::sync::LazyLock::force(&LEAN_PQ_SIG_ATTESTATION_SIGNATURES_VALID_TOTAL);
    std::sync::LazyLock::force(&LEAN_PQ_SIG_ATTESTATION_SIGNATURES_INVALID_TOTAL);
    // Histograms
    std::sync::LazyLock::force(&LEAN_FORK_CHOICE_BLOCK_PROCESSING_TIME_SECONDS);
    std::sync::LazyLock::force(&LEAN_ATTESTATION_VALIDATION_TIME_SECONDS);
    std::sync::LazyLock::force(&LEAN_PQ_SIG_ATTESTATION_SIGNING_TIME_SECONDS);
    std::sync::LazyLock::force(&LEAN_ATTESTATIONS_PRODUCTION_TIME_SECONDS);
    std::sync::LazyLock::force(&LEAN_PQ_SIG_ATTESTATION_VERIFICATION_TIME_SECONDS);
    std::sync::LazyLock::force(&LEAN_PQ_SIG_AGGREGATED_SIGNATURES_BUILDING_TIME_SECONDS);
    std::sync::LazyLock::force(&LEAN_PQ_SIG_AGGREGATED_SIGNATURES_VERIFICATION_TIME_SECONDS);
    std::sync::LazyLock::force(&LEAN_COMMITTEE_SIGNATURES_AGGREGATION_TIME_SECONDS);
    std::sync::LazyLock::force(&LEAN_AGGREGATED_PROOF_SIZE_BYTES);
    std::sync::LazyLock::force(&LEAN_FORK_CHOICE_REORG_DEPTH);
    std::sync::LazyLock::force(&LEAN_TICK_INTERVAL_DURATION_SECONDS);
    // Block production
    std::sync::LazyLock::force(&LEAN_BLOCK_AGGREGATED_PAYLOADS);
    std::sync::LazyLock::force(&LEAN_BLOCK_BUILDING_PAYLOAD_AGGREGATION_TIME_SECONDS);
    std::sync::LazyLock::force(&LEAN_BLOCK_BUILDING_TIME_SECONDS);
    std::sync::LazyLock::force(&LEAN_BLOCK_BUILDING_SUCCESS_TOTAL);
    std::sync::LazyLock::force(&LEAN_BLOCK_BUILDING_FAILURES_TOTAL);
    // Block proposal attestation selection
    std::sync::LazyLock::force(&LEAN_BLOCK_PROPOSAL_ATTESTATION_BUILD_PHASE_SECONDS);
    std::sync::LazyLock::force(&LEAN_BLOCK_PROPOSAL_ATTESTATION_BUILDS_TOTAL);
    std::sync::LazyLock::force(&LEAN_BLOCK_PROPOSAL_CHILD_PAYLOADS_CONSUMED_TOTAL);
    std::sync::LazyLock::force(&LEAN_BLOCK_PROPOSAL_ATTESTATION_DATA_SELECTED);
    std::sync::LazyLock::force(&LEAN_BLOCK_PROPOSAL_AGGREGATES_SELECTED);
    // Sync status
    std::sync::LazyLock::force(&LEAN_NODE_SYNC_STATUS);
}

// --- Public API ---

pub fn update_head_slot(slot: u64) {
    LEAN_HEAD_SLOT.set(slot.try_into().unwrap());
}

pub fn update_latest_justified_slot(slot: u64) {
    LEAN_LATEST_JUSTIFIED_SLOT.set(slot.try_into().unwrap());
}

pub fn update_latest_finalized_slot(slot: u64) {
    LEAN_LATEST_FINALIZED_SLOT.set(slot.try_into().unwrap());
}

pub fn update_current_slot(slot: u64) {
    LEAN_CURRENT_SLOT.set(slot.try_into().unwrap());
}

pub fn update_validators_count(count: u64) {
    LEAN_VALIDATORS_COUNT.set(count.try_into().unwrap());
}

pub fn update_safe_target_slot(slot: u64) {
    LEAN_SAFE_TARGET_SLOT.set(slot.try_into().unwrap());
}

pub fn set_node_info(name: &str, version: &str) {
    LEAN_NODE_INFO.with_label_values(&[name, version]).set(1);
}

pub fn set_node_start_time() {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    LEAN_NODE_START_TIME_SECONDS.set(timestamp as i64);
}

/// Increment the valid attestations counter.
pub fn inc_attestations_valid(count: u64) {
    LEAN_ATTESTATIONS_VALID_TOTAL.inc_by(count);
}

/// Increment the invalid attestations counter.
pub fn inc_attestations_invalid() {
    LEAN_ATTESTATIONS_INVALID_TOTAL.inc();
}

/// Increment the fork choice reorgs counter.
pub fn inc_fork_choice_reorgs() {
    LEAN_FORK_CHOICE_REORGS_TOTAL.inc();
}

/// Start timing fork choice block processing. Records duration when the guard is dropped.
pub fn time_fork_choice_block_processing() -> TimingGuard {
    TimingGuard::new(&LEAN_FORK_CHOICE_BLOCK_PROCESSING_TIME_SECONDS)
}

/// Start timing attestation validation. Records duration when the guard is dropped.
pub fn time_attestation_validation() -> TimingGuard {
    TimingGuard::new(&LEAN_ATTESTATION_VALIDATION_TIME_SECONDS)
}

/// Increment the PQ aggregated signatures counter.
pub fn inc_pq_sig_aggregated_signatures() {
    LEAN_PQ_SIG_AGGREGATED_SIGNATURES_TOTAL.inc();
}

/// Increment the attestations in aggregated signatures counter.
pub fn inc_pq_sig_attestations_in_aggregated_signatures(count: u64) {
    LEAN_PQ_SIG_ATTESTATIONS_IN_AGGREGATED_SIGNATURES_TOTAL.inc_by(count);
}

/// Increment the valid aggregated signatures counter.
pub fn inc_pq_sig_aggregated_signatures_valid() {
    LEAN_PQ_SIG_AGGREGATED_SIGNATURES_VALID_TOTAL.inc();
}

/// Increment the invalid aggregated signatures counter.
pub fn inc_pq_sig_aggregated_signatures_invalid() {
    LEAN_PQ_SIG_AGGREGATED_SIGNATURES_INVALID_TOTAL.inc();
}

/// Increment the individual attestation signatures counter.
pub fn inc_pq_sig_attestation_signatures() {
    LEAN_PQ_SIG_ATTESTATION_SIGNATURES_TOTAL.inc();
}

/// Increment the valid individual attestation signatures counter.
pub fn inc_pq_sig_attestation_signatures_valid() {
    LEAN_PQ_SIG_ATTESTATION_SIGNATURES_VALID_TOTAL.inc();
}

/// Increment the invalid individual attestation signatures counter.
pub fn inc_pq_sig_attestation_signatures_invalid() {
    LEAN_PQ_SIG_ATTESTATION_SIGNATURES_INVALID_TOTAL.inc();
}

/// Start timing individual attestation signing. Records duration when the guard is dropped.
pub fn time_pq_sig_attestation_signing() -> TimingGuard {
    TimingGuard::new(&LEAN_PQ_SIG_ATTESTATION_SIGNING_TIME_SECONDS)
}

/// Start timing attestation production. Records duration when the guard is dropped.
pub fn time_attestations_production() -> TimingGuard {
    TimingGuard::new(&LEAN_ATTESTATIONS_PRODUCTION_TIME_SECONDS)
}

/// Start timing individual attestation signature verification. Records duration when the guard is dropped.
pub fn time_pq_sig_attestation_verification() -> TimingGuard {
    TimingGuard::new(&LEAN_PQ_SIG_ATTESTATION_VERIFICATION_TIME_SECONDS)
}

/// Start timing aggregated signature building. Records duration when the guard is dropped.
pub fn time_pq_sig_aggregated_signatures_building() -> TimingGuard {
    TimingGuard::new(&LEAN_PQ_SIG_AGGREGATED_SIGNATURES_BUILDING_TIME_SECONDS)
}

/// Start timing aggregated signature verification. Records duration when the guard is dropped.
pub fn time_pq_sig_aggregated_signatures_verification() -> TimingGuard {
    TimingGuard::new(&LEAN_PQ_SIG_AGGREGATED_SIGNATURES_VERIFICATION_TIME_SECONDS)
}

/// Observe the size of an aggregated signature proof's `proof_data` bytes.
pub fn observe_aggregated_proof_size(bytes: usize) {
    LEAN_AGGREGATED_PROOF_SIZE_BYTES.observe(bytes as f64);
}

/// Observe committee-signature aggregation duration. Measured in the
/// off-thread worker and reported back via an `AggregationDone` message, so a
/// drop-guard that crosses the thread boundary is not appropriate here.
pub fn observe_committee_signatures_aggregation(elapsed: std::time::Duration) {
    LEAN_COMMITTEE_SIGNATURES_AGGREGATION_TIME_SECONDS.observe(elapsed.as_secs_f64());
}

/// Update a table byte size gauge.
pub fn update_table_bytes(table_name: &str, bytes: u64) {
    LEAN_TABLE_BYTES
        .with_label_values(&[table_name])
        .set(bytes as i64);
}

/// Update the gossip signatures gauge.
pub fn update_gossip_signatures(count: usize) {
    LEAN_GOSSIP_SIGNATURES.set(count as i64);
}

/// Update the new aggregated payloads gauge.
pub fn update_latest_new_aggregated_payloads(count: usize) {
    LEAN_LATEST_NEW_AGGREGATED_PAYLOADS.set(count as i64);
}

/// Update the known aggregated payloads gauge.
pub fn update_latest_known_aggregated_payloads(count: usize) {
    LEAN_LATEST_KNOWN_AGGREGATED_PAYLOADS.set(count as i64);
}

/// Set the is_aggregator gauge.
pub fn set_is_aggregator(is_aggregator: bool) {
    LEAN_IS_AGGREGATOR.set(i64::from(is_aggregator));
}

/// Set the attestation committee count gauge.
pub fn set_attestation_committee_count(count: u64) {
    LEAN_ATTESTATION_COMMITTEE_COUNT.set(count.try_into().unwrap_or_default());
}

/// Set `lean_attestation_aggregate_coverage_validators{section, subnet}`.
pub fn set_attestation_aggregate_coverage_validators(section: &str, subnet: &str, value: i64) {
    LEAN_ATTESTATION_AGGREGATE_COVERAGE_VALIDATORS
        .with_label_values(&[section, subnet])
        .set(value);
}

/// Set `lean_attestation_aggregate_coverage_subnets{section}`.
pub fn set_attestation_aggregate_coverage_subnets(section: &str, value: i64) {
    LEAN_ATTESTATION_AGGREGATE_COVERAGE_SUBNETS
        .with_label_values(&[section])
        .set(value);
}

/// Set `lean_attestation_aggregate_coverage_diff_validators{direction}`.
pub fn set_attestation_aggregate_coverage_diff_validators(direction: &str, value: i64) {
    LEAN_ATTESTATION_AGGREGATE_COVERAGE_DIFF_VALIDATORS
        .with_label_values(&[direction])
        .set(value);
}

/// Observe the depth of a fork choice reorg.
pub fn observe_fork_choice_reorg_depth(depth: u64) {
    LEAN_FORK_CHOICE_REORG_DEPTH.observe(depth as f64);
}

/// Observe the duration between consecutive tick intervals in seconds.
pub fn observe_tick_interval_duration(duration: Duration) {
    LEAN_TICK_INTERVAL_DURATION_SECONDS.observe(duration.as_secs_f64());
}

/// Observe the number of aggregated payloads in a built block.
pub fn observe_block_aggregated_payloads(count: usize) {
    LEAN_BLOCK_AGGREGATED_PAYLOADS.observe(count as f64);
}

/// Start timing payload aggregation during block building. Records duration when the guard is dropped.
pub fn time_block_building_payload_aggregation() -> TimingGuard {
    TimingGuard::new(&LEAN_BLOCK_BUILDING_PAYLOAD_AGGREGATION_TIME_SECONDS)
}

/// Start timing block building. Records duration when the guard is dropped.
pub fn time_block_building() -> TimingGuard {
    TimingGuard::new(&LEAN_BLOCK_BUILDING_TIME_SECONDS)
}

/// Increment the successful block builds counter.
pub fn inc_block_building_success() {
    LEAN_BLOCK_BUILDING_SUCCESS_TOTAL.inc();
}

/// Increment the failed block builds counter.
pub fn inc_block_building_failures() {
    LEAN_BLOCK_BUILDING_FAILURES_TOTAL.inc();
}

/// Observe the duration of a block-proposal attestation-selection phase.
/// `phase` must be one of [`BLOCK_PROPOSAL_ATTESTATION_BUILD_PHASES`].
pub fn observe_block_proposal_phase(phase: &str, elapsed: Duration) {
    LEAN_BLOCK_PROPOSAL_ATTESTATION_BUILD_PHASE_SECONDS
        .with_label_values(&[phase])
        .observe(elapsed.as_secs_f64());
}

/// Increment the completed block-proposal attestation selection runs counter.
pub fn inc_block_proposal_attestation_builds() {
    LEAN_BLOCK_PROPOSAL_ATTESTATION_BUILDS_TOTAL.inc();
}

/// Increment the greedily-selected child payloads counter (before compaction).
pub fn inc_block_proposal_child_payloads_consumed(count: u64) {
    LEAN_BLOCK_PROPOSAL_CHILD_PAYLOADS_CONSUMED_TOTAL.inc_by(count);
}

/// Observe the number of distinct `AttestationData` entries in the proposal block body.
pub fn observe_block_proposal_attestation_data_selected(count: usize) {
    LEAN_BLOCK_PROPOSAL_ATTESTATION_DATA_SELECTED.observe(count as f64);
}

/// Observe the number of aggregated signature proofs in the proposal result after compaction.
pub fn observe_block_proposal_aggregates_selected(count: usize) {
    LEAN_BLOCK_PROPOSAL_AGGREGATES_SELECTED.observe(count as f64);
}

/// Set the node sync status. Sets the given status label to 1 and all others to 0.
pub fn set_node_sync_status(status: SyncStatus) {
    let active = status.as_str();
    for label in SyncStatus::ALL {
        LEAN_NODE_SYNC_STATUS
            .with_label_values(&[label])
            .set(i64::from(*label == active));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The block-proposal phase metric registers and accepts every label in
    /// `BLOCK_PROPOSAL_ATTESTATION_BUILD_PHASES`, and the companion
    /// counters/histograms are callable. Guards against label drift between the
    /// constant and the strings passed at the `build_block` call sites.
    #[test]
    fn block_proposal_attestation_build_metrics_are_usable() {
        for phase in BLOCK_PROPOSAL_ATTESTATION_BUILD_PHASES {
            observe_block_proposal_phase(phase, Duration::from_millis(1));
            assert_eq!(
                LEAN_BLOCK_PROPOSAL_ATTESTATION_BUILD_PHASE_SECONDS
                    .with_label_values(&[phase])
                    .get_sample_count(),
                1,
                "phase {phase} should have one observation"
            );
        }

        inc_block_proposal_attestation_builds();
        inc_block_proposal_child_payloads_consumed(3);
        observe_block_proposal_attestation_data_selected(4);
        observe_block_proposal_aggregates_selected(4);

        assert_eq!(LEAN_BLOCK_PROPOSAL_ATTESTATION_BUILDS_TOTAL.get(), 1);
        assert_eq!(LEAN_BLOCK_PROPOSAL_CHILD_PAYLOADS_CONSUMED_TOTAL.get(), 3);
        assert_eq!(
            LEAN_BLOCK_PROPOSAL_ATTESTATION_DATA_SELECTED.get_sample_count(),
            1
        );
        assert_eq!(
            LEAN_BLOCK_PROPOSAL_AGGREGATES_SELECTED.get_sample_count(),
            1
        );
    }
}
