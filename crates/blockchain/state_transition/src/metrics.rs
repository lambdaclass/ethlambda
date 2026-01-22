//! Prometheus metrics for state transition.

use std::sync::LazyLock;

use prometheus::{IntCounter, IntCounterVec, register_int_counter, register_int_counter_vec};

static LEAN_STATE_TRANSITION_SLOTS_PROCESSED_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "lean_state_transition_slots_processed_total",
        "Count of processed slots"
    )
    .unwrap()
});

static LEAN_STATE_TRANSITION_ATTESTATIONS_PROCESSED_TOTAL: LazyLock<IntCounter> =
    LazyLock::new(|| {
        register_int_counter!(
            "lean_state_transition_attestations_processed_total",
            "Count of processed attestations"
        )
        .unwrap()
    });

static LEAN_FINALIZATIONS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "lean_finalizations_total",
        "Total number of finalization attempts",
        &["result"]
    )
    .unwrap()
});

/// Increment the slots processed counter by the given amount.
pub fn inc_slots_processed(count: u64) {
    LEAN_STATE_TRANSITION_SLOTS_PROCESSED_TOTAL.inc_by(count);
}

/// Increment the attestations processed counter by the given amount.
pub fn inc_attestations_processed(count: u64) {
    LEAN_STATE_TRANSITION_ATTESTATIONS_PROCESSED_TOTAL.inc_by(count);
}

/// Increment the finalization counter with the given result.
pub fn inc_finalizations(result: &str) {
    LEAN_FINALIZATIONS_TOTAL.with_label_values(&[result]).inc();
}

static LEAN_STATE_TRANSITION_TIME_SECONDS: LazyLock<prometheus::Histogram> = LazyLock::new(|| {
    prometheus::register_histogram!(
        "lean_state_transition_time_seconds",
        "Duration of the entire state transition",
        vec![0.25, 0.5, 0.75, 1.0, 1.25, 1.5, 2.0, 2.5, 3.0, 4.0]
    )
    .unwrap()
});

static LEAN_STATE_TRANSITION_SLOTS_PROCESSING_TIME_SECONDS: LazyLock<prometheus::Histogram> =
    LazyLock::new(|| {
        prometheus::register_histogram!(
            "lean_state_transition_slots_processing_time_seconds",
            "Duration to process slots",
            vec![0.005, 0.01, 0.025, 0.05, 0.1, 1.0]
        )
        .unwrap()
    });

static LEAN_STATE_TRANSITION_BLOCK_PROCESSING_TIME_SECONDS: LazyLock<prometheus::Histogram> =
    LazyLock::new(|| {
        prometheus::register_histogram!(
            "lean_state_transition_block_processing_time_seconds",
            "Duration to process a block in state transition",
            vec![0.005, 0.01, 0.025, 0.05, 0.1, 1.0]
        )
        .unwrap()
    });

static LEAN_STATE_TRANSITION_ATTESTATIONS_PROCESSING_TIME_SECONDS: LazyLock<prometheus::Histogram> =
    LazyLock::new(|| {
        prometheus::register_histogram!(
            "lean_state_transition_attestations_processing_time_seconds",
            "Duration to process attestations",
            vec![0.005, 0.01, 0.025, 0.05, 0.1, 1.0]
        )
        .unwrap()
    });

/// Record state transition time in seconds.
pub fn observe_state_transition_time(duration_secs: f64) {
    LEAN_STATE_TRANSITION_TIME_SECONDS.observe(duration_secs);
}

/// Record slots processing time in seconds.
pub fn observe_slots_processing_time(duration_secs: f64) {
    LEAN_STATE_TRANSITION_SLOTS_PROCESSING_TIME_SECONDS.observe(duration_secs);
}

/// Record block processing time in seconds.
pub fn observe_block_processing_time(duration_secs: f64) {
    LEAN_STATE_TRANSITION_BLOCK_PROCESSING_TIME_SECONDS.observe(duration_secs);
}

/// Record attestations processing time in seconds.
pub fn observe_attestations_processing_time(duration_secs: f64) {
    LEAN_STATE_TRANSITION_ATTESTATIONS_PROCESSING_TIME_SECONDS.observe(duration_secs);
}
