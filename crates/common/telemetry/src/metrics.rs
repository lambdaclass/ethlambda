//! Counters for the telemetry writer, so a node whose rows are not arriving
//! says why on its own `/metrics`.

use std::sync::LazyLock;

use ethlambda_metrics::{
    IntCounter, IntCounterVec, register_int_counter, register_int_counter_vec,
};

static ROWS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "lean_telemetry_rows_total",
        "Telemetry block_events rows, by what became of them",
        &["outcome"]
    )
    .unwrap()
});

static INSERT_FAILURES: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "lean_telemetry_insert_failures_total",
        "Failed ClickHouse insert attempts, refusals included"
    )
    .unwrap()
});

/// Publish every series at zero, so a node whose inserts never succeed shows
/// a rising failure count next to zero rows inserted, rather than no series.
pub(crate) fn init() {
    for outcome in ["inserted", "dropped"] {
        ROWS.with_label_values(&[outcome]);
    }
    LazyLock::force(&INSERT_FAILURES);
}

pub(crate) fn inc_rows_inserted(rows: u64) {
    ROWS.with_label_values(&["inserted"]).inc_by(rows);
}

pub(crate) fn inc_rows_dropped(rows: u64) {
    ROWS.with_label_values(&["dropped"]).inc_by(rows);
}

pub(crate) fn inc_insert_failures() {
    INSERT_FAILURES.inc();
}

/// Count one PQ timing event the export's queue had no room for, by class
/// (`receipt`, `validation`, `work`, `status`). The run's `run.json` counts
/// them too; this is where a running node says its export is falling behind.
pub(crate) fn inc_pq_timing_dropped(class: &str) {
    static DROPPED: LazyLock<IntCounterVec> = LazyLock::new(|| {
        register_int_counter_vec!(
            "lean_beacon_pq_timing_dropped_events_total",
            "PQ timing events the export dropped because its queue was full, by class",
            &["class"]
        )
        .unwrap()
    });
    DROPPED.with_label_values(&[class]).inc();
}
