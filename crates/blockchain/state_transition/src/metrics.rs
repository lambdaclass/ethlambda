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
