//! Prometheus metrics for the blockchain module.

use ethlambda_metrics::*;

static LEAN_ATTESTATIONS_INVALID_TOTAL: std::sync::LazyLock<IntCounter> =
    std::sync::LazyLock::new(|| {
        register_int_counter!(
            "lean_attestations_invalid_total",
            "Total number of invalid attestations"
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

static LEAN_PQ_SIG_ATTESTATION_SIGNATURES_INVALID_TOTAL: std::sync::LazyLock<IntCounter> =
    std::sync::LazyLock::new(|| {
        register_int_counter!(
            "lean_pq_sig_attestation_signatures_invalid_total",
            "Total number of invalid individual attestation signatures"
        )
        .unwrap()
    });

/// Initialize metrics that may never be incremented so they appear in Prometheus with value 0.
/// When adding a new module-scope counter above, add a corresponding `LazyLock::force` call here.
pub fn init() {
    std::sync::LazyLock::force(&LEAN_ATTESTATIONS_INVALID_TOTAL);
    std::sync::LazyLock::force(&LEAN_PQ_SIG_AGGREGATED_SIGNATURES_INVALID_TOTAL);
    std::sync::LazyLock::force(&LEAN_PQ_SIG_ATTESTATION_SIGNATURES_INVALID_TOTAL);
}

pub fn update_head_slot(slot: u64) {
    static LEAN_HEAD_SLOT: std::sync::LazyLock<IntGauge> = std::sync::LazyLock::new(|| {
        register_int_gauge!("lean_head_slot", "Latest slot of the lean chain").unwrap()
    });
    LEAN_HEAD_SLOT.set(slot.try_into().unwrap());
}

pub fn update_latest_justified_slot(slot: u64) {
    static LEAN_LATEST_JUSTIFIED_SLOT: std::sync::LazyLock<IntGauge> =
        std::sync::LazyLock::new(|| {
            register_int_gauge!("lean_latest_justified_slot", "Latest justified slot").unwrap()
        });
    LEAN_LATEST_JUSTIFIED_SLOT.set(slot.try_into().unwrap());
}

pub fn update_latest_finalized_slot(slot: u64) {
    static LEAN_LATEST_FINALIZED_SLOT: std::sync::LazyLock<IntGauge> =
        std::sync::LazyLock::new(|| {
            register_int_gauge!("lean_latest_finalized_slot", "Latest finalized slot").unwrap()
        });
    LEAN_LATEST_FINALIZED_SLOT.set(slot.try_into().unwrap());
}

pub fn update_current_slot(slot: u64) {
    static LEAN_CURRENT_SLOT: std::sync::LazyLock<IntGauge> = std::sync::LazyLock::new(|| {
        register_int_gauge!("lean_current_slot", "Current slot of the lean chain").unwrap()
    });
    LEAN_CURRENT_SLOT.set(slot.try_into().unwrap());
}

pub fn update_validators_count(count: u64) {
    static LEAN_VALIDATORS_COUNT: std::sync::LazyLock<IntGauge> = std::sync::LazyLock::new(|| {
        register_int_gauge!(
            "lean_validators_count",
            "Number of validators managed by a node"
        )
        .unwrap()
    });
    LEAN_VALIDATORS_COUNT.set(count.try_into().unwrap());
}

pub fn update_safe_target_slot(slot: u64) {
    static LEAN_SAFE_TARGET_SLOT: std::sync::LazyLock<IntGauge> = std::sync::LazyLock::new(|| {
        register_int_gauge!("lean_safe_target_slot", "Safe target slot").unwrap()
    });
    LEAN_SAFE_TARGET_SLOT.set(slot.try_into().unwrap());
}

pub fn set_node_info(name: &str, version: &str) {
    static LEAN_NODE_INFO: std::sync::LazyLock<IntGaugeVec> = std::sync::LazyLock::new(|| {
        register_int_gauge_vec!(
            "lean_node_info",
            "Node information (always 1)",
            &["name", "version"]
        )
        .unwrap()
    });
    LEAN_NODE_INFO.with_label_values(&[name, version]).set(1);
}

pub fn set_node_start_time() {
    static LEAN_NODE_START_TIME_SECONDS: std::sync::LazyLock<IntGauge> =
        std::sync::LazyLock::new(|| {
            register_int_gauge!(
                "lean_node_start_time_seconds",
                "Timestamp when node started"
            )
            .unwrap()
        });
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    LEAN_NODE_START_TIME_SECONDS.set(timestamp as i64);
}

/// Increment the valid attestations counter.
pub fn inc_attestations_valid() {
    static LEAN_ATTESTATIONS_VALID_TOTAL: std::sync::LazyLock<IntCounter> =
        std::sync::LazyLock::new(|| {
            register_int_counter!(
                "lean_attestations_valid_total",
                "Total number of valid attestations"
            )
            .unwrap()
        });
    LEAN_ATTESTATIONS_VALID_TOTAL.inc();
}

/// Increment the invalid attestations counter.
pub fn inc_attestations_invalid() {
    LEAN_ATTESTATIONS_INVALID_TOTAL.inc();
}

/// Increment the fork choice reorgs counter.
pub fn inc_fork_choice_reorgs() {
    static LEAN_FORK_CHOICE_REORGS_TOTAL: std::sync::LazyLock<IntCounter> =
        std::sync::LazyLock::new(|| {
            register_int_counter!(
                "lean_fork_choice_reorgs_total",
                "Count of fork choice reorganizations"
            )
            .unwrap()
        });
    LEAN_FORK_CHOICE_REORGS_TOTAL.inc();
}

/// Start timing fork choice block processing. Records duration when the guard is dropped.
pub fn time_fork_choice_block_processing() -> TimingGuard {
    static LEAN_FORK_CHOICE_BLOCK_PROCESSING_TIME_SECONDS: std::sync::LazyLock<Histogram> =
        std::sync::LazyLock::new(|| {
            register_histogram!(
                "lean_fork_choice_block_processing_time_seconds",
                "Duration to process a block",
                vec![0.005, 0.01, 0.025, 0.05, 0.1, 1.0, 1.25, 1.5, 2.0, 4.0]
            )
            .unwrap()
        });
    TimingGuard::new(&LEAN_FORK_CHOICE_BLOCK_PROCESSING_TIME_SECONDS)
}

/// Start timing attestation validation. Records duration when the guard is dropped.
pub fn time_attestation_validation() -> TimingGuard {
    static LEAN_ATTESTATION_VALIDATION_TIME_SECONDS: std::sync::LazyLock<Histogram> =
        std::sync::LazyLock::new(|| {
            register_histogram!(
                "lean_attestation_validation_time_seconds",
                "Duration to validate an attestation",
                vec![0.005, 0.01, 0.025, 0.05, 0.1, 1.0]
            )
            .unwrap()
        });
    TimingGuard::new(&LEAN_ATTESTATION_VALIDATION_TIME_SECONDS)
}

/// Increment the PQ aggregated signatures counter.
pub fn inc_pq_sig_aggregated_signatures() {
    static LEAN_PQ_SIG_AGGREGATED_SIGNATURES_TOTAL: std::sync::LazyLock<IntCounter> =
        std::sync::LazyLock::new(|| {
            register_int_counter!(
                "lean_pq_sig_aggregated_signatures_total",
                "Total number of aggregated signatures"
            )
            .unwrap()
        });
    LEAN_PQ_SIG_AGGREGATED_SIGNATURES_TOTAL.inc();
}

/// Increment the attestations in aggregated signatures counter.
pub fn inc_pq_sig_attestations_in_aggregated_signatures(count: u64) {
    static LEAN_PQ_SIG_ATTESTATIONS_IN_AGGREGATED_SIGNATURES_TOTAL: std::sync::LazyLock<
        IntCounter,
    > = std::sync::LazyLock::new(|| {
        register_int_counter!(
            "lean_pq_sig_attestations_in_aggregated_signatures_total",
            "Total number of attestations included into aggregated signatures"
        )
        .unwrap()
    });
    LEAN_PQ_SIG_ATTESTATIONS_IN_AGGREGATED_SIGNATURES_TOTAL.inc_by(count);
}

/// Increment the valid aggregated signatures counter.
pub fn inc_pq_sig_aggregated_signatures_valid() {
    static LEAN_PQ_SIG_AGGREGATED_SIGNATURES_VALID_TOTAL: std::sync::LazyLock<IntCounter> =
        std::sync::LazyLock::new(|| {
            register_int_counter!(
                "lean_pq_sig_aggregated_signatures_valid_total",
                "Total number of valid aggregated signatures"
            )
            .unwrap()
        });
    LEAN_PQ_SIG_AGGREGATED_SIGNATURES_VALID_TOTAL.inc();
}

/// Increment the invalid aggregated signatures counter.
pub fn inc_pq_sig_aggregated_signatures_invalid() {
    LEAN_PQ_SIG_AGGREGATED_SIGNATURES_INVALID_TOTAL.inc();
}

/// Increment the individual attestation signatures counter.
pub fn inc_pq_sig_attestation_signatures() {
    static LEAN_PQ_SIG_ATTESTATION_SIGNATURES_TOTAL: std::sync::LazyLock<IntCounter> =
        std::sync::LazyLock::new(|| {
            register_int_counter!(
                "lean_pq_sig_attestation_signatures_total",
                "Total number of individual attestation signatures"
            )
            .unwrap()
        });
    LEAN_PQ_SIG_ATTESTATION_SIGNATURES_TOTAL.inc();
}

/// Increment the valid individual attestation signatures counter.
pub fn inc_pq_sig_attestation_signatures_valid() {
    static LEAN_PQ_SIG_ATTESTATION_SIGNATURES_VALID_TOTAL: std::sync::LazyLock<IntCounter> =
        std::sync::LazyLock::new(|| {
            register_int_counter!(
                "lean_pq_sig_attestation_signatures_valid_total",
                "Total number of valid individual attestation signatures"
            )
            .unwrap()
        });
    LEAN_PQ_SIG_ATTESTATION_SIGNATURES_VALID_TOTAL.inc();
}

/// Increment the invalid individual attestation signatures counter.
pub fn inc_pq_sig_attestation_signatures_invalid() {
    LEAN_PQ_SIG_ATTESTATION_SIGNATURES_INVALID_TOTAL.inc();
}

/// Start timing individual attestation signing. Records duration when the guard is dropped.
pub fn time_pq_sig_attestation_signing() -> TimingGuard {
    static LEAN_PQ_SIG_ATTESTATION_SIGNING_TIME_SECONDS: std::sync::LazyLock<Histogram> =
        std::sync::LazyLock::new(|| {
            register_histogram!(
                "lean_pq_sig_attestation_signing_time_seconds",
                "Time taken to sign an attestation",
                vec![0.005, 0.01, 0.025, 0.05, 0.1, 1.0]
            )
            .unwrap()
        });
    TimingGuard::new(&LEAN_PQ_SIG_ATTESTATION_SIGNING_TIME_SECONDS)
}

/// Start timing individual attestation signature verification. Records duration when the guard is dropped.
pub fn time_pq_sig_attestation_verification() -> TimingGuard {
    static LEAN_PQ_SIG_ATTESTATION_VERIFICATION_TIME_SECONDS: std::sync::LazyLock<Histogram> =
        std::sync::LazyLock::new(|| {
            register_histogram!(
                "lean_pq_sig_attestation_verification_time_seconds",
                "Time taken to verify an attestation signature",
                vec![0.005, 0.01, 0.025, 0.05, 0.1, 1.0]
            )
            .unwrap()
        });
    TimingGuard::new(&LEAN_PQ_SIG_ATTESTATION_VERIFICATION_TIME_SECONDS)
}

/// Start timing aggregated signature building. Records duration when the guard is dropped.
pub fn time_pq_sig_aggregated_signatures_building() -> TimingGuard {
    static LEAN_PQ_SIG_AGGREGATED_SIGNATURES_BUILDING_TIME_SECONDS: std::sync::LazyLock<Histogram> =
        std::sync::LazyLock::new(|| {
            register_histogram!(
                "lean_pq_sig_aggregated_signatures_building_time_seconds",
                "Time taken to build an aggregated attestation signature",
                vec![0.1, 0.25, 0.5, 0.75, 1.0, 1.25, 1.5, 2.0, 4.0]
            )
            .unwrap()
        });
    TimingGuard::new(&LEAN_PQ_SIG_AGGREGATED_SIGNATURES_BUILDING_TIME_SECONDS)
}

/// Start timing aggregated signature verification. Records duration when the guard is dropped.
pub fn time_pq_sig_aggregated_signatures_verification() -> TimingGuard {
    static LEAN_PQ_SIG_AGGREGATED_SIGNATURES_VERIFICATION_TIME_SECONDS: std::sync::LazyLock<
        Histogram,
    > = std::sync::LazyLock::new(|| {
        register_histogram!(
            "lean_pq_sig_aggregated_signatures_verification_time_seconds",
            "Time taken to verify an aggregated attestation signature",
            vec![0.1, 0.25, 0.5, 0.75, 1.0, 1.25, 1.5, 2.0, 4.0]
        )
        .unwrap()
    });
    TimingGuard::new(&LEAN_PQ_SIG_AGGREGATED_SIGNATURES_VERIFICATION_TIME_SECONDS)
}

/// Start timing committee signatures aggregation. Records duration when the guard is dropped.
pub fn time_committee_signatures_aggregation() -> TimingGuard {
    static LEAN_COMMITTEE_SIGNATURES_AGGREGATION_TIME_SECONDS: std::sync::LazyLock<Histogram> =
        std::sync::LazyLock::new(|| {
            register_histogram!(
                "lean_committee_signatures_aggregation_time_seconds",
                "Time taken to aggregate committee signatures",
                vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 0.75, 1.0]
            )
            .unwrap()
        });
    TimingGuard::new(&LEAN_COMMITTEE_SIGNATURES_AGGREGATION_TIME_SECONDS)
}

/// Update the gossip signatures gauge.
pub fn update_gossip_signatures(count: usize) {
    static LEAN_GOSSIP_SIGNATURES: std::sync::LazyLock<IntGauge> = std::sync::LazyLock::new(|| {
        register_int_gauge!(
            "lean_gossip_signatures",
            "Number of gossip signatures in fork-choice store"
        )
        .unwrap()
    });
    LEAN_GOSSIP_SIGNATURES.set(count as i64);
}

/// Update the new aggregated payloads gauge.
pub fn update_latest_new_aggregated_payloads(count: usize) {
    static LEAN_LATEST_NEW_AGGREGATED_PAYLOADS: std::sync::LazyLock<IntGauge> =
        std::sync::LazyLock::new(|| {
            register_int_gauge!(
                "lean_latest_new_aggregated_payloads",
                "Number of new aggregated payload items"
            )
            .unwrap()
        });
    LEAN_LATEST_NEW_AGGREGATED_PAYLOADS.set(count as i64);
}

/// Update the known aggregated payloads gauge.
pub fn update_latest_known_aggregated_payloads(count: usize) {
    static LEAN_LATEST_KNOWN_AGGREGATED_PAYLOADS: std::sync::LazyLock<IntGauge> =
        std::sync::LazyLock::new(|| {
            register_int_gauge!(
                "lean_latest_known_aggregated_payloads",
                "Number of known aggregated payload items"
            )
            .unwrap()
        });
    LEAN_LATEST_KNOWN_AGGREGATED_PAYLOADS.set(count as i64);
}

/// Set the is_aggregator gauge.
pub fn set_is_aggregator(is_aggregator: bool) {
    static LEAN_IS_AGGREGATOR: std::sync::LazyLock<IntGauge> = std::sync::LazyLock::new(|| {
        register_int_gauge!(
            "lean_is_aggregator",
            "Validator's is_aggregator status. True=1, False=0"
        )
        .unwrap()
    });
    LEAN_IS_AGGREGATOR.set(i64::from(is_aggregator));
}

/// Set the attestation committee count gauge.
pub fn set_attestation_committee_count(count: u64) {
    static LEAN_ATTESTATION_COMMITTEE_COUNT: std::sync::LazyLock<IntGauge> =
        std::sync::LazyLock::new(|| {
            register_int_gauge!(
                "lean_attestation_committee_count",
                "Number of attestation committees (ATTESTATION_COMMITTEE_COUNT)"
            )
            .unwrap()
        });
    LEAN_ATTESTATION_COMMITTEE_COUNT.set(count.try_into().unwrap_or_default());
}

/// Observe the depth of a fork choice reorg.
pub fn observe_fork_choice_reorg_depth(depth: u64) {
    static LEAN_FORK_CHOICE_REORG_DEPTH: std::sync::LazyLock<Histogram> =
        std::sync::LazyLock::new(|| {
            register_histogram!(
                "lean_fork_choice_reorg_depth",
                "Depth of fork choice reorgs (in blocks)",
                vec![1.0, 2.0, 3.0, 5.0, 7.0, 10.0, 20.0, 30.0, 50.0, 100.0]
            )
            .unwrap()
        });
    LEAN_FORK_CHOICE_REORG_DEPTH.observe(depth as f64);
}
