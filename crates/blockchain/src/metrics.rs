//! Prometheus metrics for the blockchain module.

pub fn update_head_slot(slot: u64) {
    static LEAN_HEAD_SLOT: std::sync::LazyLock<prometheus::IntGauge> =
        std::sync::LazyLock::new(|| {
            prometheus::register_int_gauge!("lean_head_slot", "Latest slot of the lean chain")
                .unwrap()
        });
    LEAN_HEAD_SLOT.set(slot.try_into().unwrap());
}

pub fn update_latest_justified_slot(slot: u64) {
    static LEAN_LATEST_JUSTIFIED_SLOT: std::sync::LazyLock<prometheus::IntGauge> =
        std::sync::LazyLock::new(|| {
            prometheus::register_int_gauge!("lean_latest_justified_slot", "Latest justified slot")
                .unwrap()
        });
    LEAN_LATEST_JUSTIFIED_SLOT.set(slot.try_into().unwrap());
}

pub fn update_latest_finalized_slot(slot: u64) {
    static LEAN_LATEST_FINALIZED_SLOT: std::sync::LazyLock<prometheus::IntGauge> =
        std::sync::LazyLock::new(|| {
            prometheus::register_int_gauge!("lean_latest_finalized_slot", "Latest finalized slot")
                .unwrap()
        });
    LEAN_LATEST_FINALIZED_SLOT.set(slot.try_into().unwrap());
}

pub fn update_current_slot(slot: u64) {
    static LEAN_CURRENT_SLOT: std::sync::LazyLock<prometheus::IntGauge> =
        std::sync::LazyLock::new(|| {
            prometheus::register_int_gauge!("lean_current_slot", "Current slot of the lean chain")
                .unwrap()
        });
    LEAN_CURRENT_SLOT.set(slot.try_into().unwrap());
}

pub fn update_validators_count(count: u64) {
    static LEAN_VALIDATORS_COUNT: std::sync::LazyLock<prometheus::IntGauge> =
        std::sync::LazyLock::new(|| {
            prometheus::register_int_gauge!(
                "lean_validators_count",
                "Number of validators managed by a node"
            )
            .unwrap()
        });
    LEAN_VALIDATORS_COUNT.set(count.try_into().unwrap());
}

pub fn update_safe_target_slot(slot: u64) {
    static LEAN_SAFE_TARGET_SLOT: std::sync::LazyLock<prometheus::IntGauge> =
        std::sync::LazyLock::new(|| {
            prometheus::register_int_gauge!("lean_safe_target_slot", "Safe target slot").unwrap()
        });
    LEAN_SAFE_TARGET_SLOT.set(slot.try_into().unwrap());
}

pub fn set_node_info(name: &str, version: &str) {
    static LEAN_NODE_INFO: std::sync::LazyLock<prometheus::IntGaugeVec> =
        std::sync::LazyLock::new(|| {
            prometheus::register_int_gauge_vec!(
                "lean_node_info",
                "Node information (always 1)",
                &["name", "version"]
            )
            .unwrap()
        });
    LEAN_NODE_INFO.with_label_values(&[name, version]).set(1);
}

pub fn set_node_start_time() {
    static LEAN_NODE_START_TIME_SECONDS: std::sync::LazyLock<prometheus::IntGauge> =
        std::sync::LazyLock::new(|| {
            prometheus::register_int_gauge!(
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
pub fn inc_attestations_valid(source: &str) {
    static LEAN_ATTESTATIONS_VALID_TOTAL: std::sync::LazyLock<prometheus::IntCounterVec> =
        std::sync::LazyLock::new(|| {
            prometheus::register_int_counter_vec!(
                "lean_attestations_valid_total",
                "Count of valid attestations",
                &["source"]
            )
            .unwrap()
        });
    LEAN_ATTESTATIONS_VALID_TOTAL
        .with_label_values(&[source])
        .inc();
}

/// Increment the invalid attestations counter.
pub fn inc_attestations_invalid(source: &str) {
    static LEAN_ATTESTATIONS_INVALID_TOTAL: std::sync::LazyLock<prometheus::IntCounterVec> =
        std::sync::LazyLock::new(|| {
            prometheus::register_int_counter_vec!(
                "lean_attestations_invalid_total",
                "Count of invalid attestations",
                &["source"]
            )
            .unwrap()
        });
    LEAN_ATTESTATIONS_INVALID_TOTAL
        .with_label_values(&[source])
        .inc();
}

/// Increment the fork choice reorgs counter.
pub fn inc_fork_choice_reorgs() {
    static LEAN_FORK_CHOICE_REORGS_TOTAL: std::sync::LazyLock<prometheus::IntCounter> =
        std::sync::LazyLock::new(|| {
            prometheus::register_int_counter!(
                "lean_fork_choice_reorgs_total",
                "Count of fork choice reorganizations"
            )
            .unwrap()
        });
    LEAN_FORK_CHOICE_REORGS_TOTAL.inc();
}

/// Increment the PQ aggregated signatures counter.
pub fn inc_pq_sig_aggregated_signatures() {
    static LEAN_PQ_SIG_AGGREGATED_SIGNATURES_TOTAL: std::sync::LazyLock<prometheus::IntCounter> =
        std::sync::LazyLock::new(|| {
            prometheus::register_int_counter!(
                "lean_pq_sig_aggregated_signatures_total",
                "Count of aggregated signatures created"
            )
            .unwrap()
        });
    LEAN_PQ_SIG_AGGREGATED_SIGNATURES_TOTAL.inc();
}

/// Increment the attestations in aggregated signatures counter.
pub fn inc_pq_sig_attestations_in_aggregated_signatures(count: u64) {
    static LEAN_PQ_SIG_ATTESTATIONS_IN_AGGREGATED_SIGNATURES_TOTAL: std::sync::LazyLock<
        prometheus::IntCounter,
    > = std::sync::LazyLock::new(|| {
        prometheus::register_int_counter!(
            "lean_pq_sig_attestations_in_aggregated_signatures_total",
            "Count of attestations included in aggregated signatures"
        )
        .unwrap()
    });
    LEAN_PQ_SIG_ATTESTATIONS_IN_AGGREGATED_SIGNATURES_TOTAL.inc_by(count);
}

/// Increment the valid aggregated signatures counter.
pub fn inc_pq_sig_aggregated_signatures_valid() {
    static LEAN_PQ_SIG_AGGREGATED_SIGNATURES_VALID_TOTAL: std::sync::LazyLock<
        prometheus::IntCounter,
    > = std::sync::LazyLock::new(|| {
        prometheus::register_int_counter!(
            "lean_pq_sig_aggregated_signatures_valid_total",
            "Count of valid aggregated signatures"
        )
        .unwrap()
    });
    LEAN_PQ_SIG_AGGREGATED_SIGNATURES_VALID_TOTAL.inc();
}

/// Increment the invalid aggregated signatures counter.
pub fn inc_pq_sig_aggregated_signatures_invalid() {
    static LEAN_PQ_SIG_AGGREGATED_SIGNATURES_INVALID_TOTAL: std::sync::LazyLock<
        prometheus::IntCounter,
    > = std::sync::LazyLock::new(|| {
        prometheus::register_int_counter!(
            "lean_pq_sig_aggregated_signatures_invalid_total",
            "Count of invalid aggregated signatures"
        )
        .unwrap()
    });
    LEAN_PQ_SIG_AGGREGATED_SIGNATURES_INVALID_TOTAL.inc();
}
