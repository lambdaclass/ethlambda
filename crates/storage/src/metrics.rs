//! Prometheus metrics for the storage layer.

use std::sync::LazyLock;

use ethlambda_metrics::*;

static LEAN_STATE_WRITE_QUEUE_DEPTH: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "lean_state_write_queue_depth",
        "States handed to the background writer but not yet committed"
    )
    .unwrap()
});

static LEAN_STATE_WRITE_SECONDS: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(
        "lean_state_write_seconds",
        "Time the background writer spends encoding, diffing and committing one state",
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0]
    )
    .unwrap()
});

/// One state was handed to the writer. Call from `insert_state`, and pair
/// with [`dec_state_write_queue_depth`].
///
/// `inc`/`dec` rather than reading `PendingStates::len()` and `set`ting it:
/// the two sides of the handoff run on different threads, so a read-then-set
/// there races the other side's own read-then-set and can latch the gauge one
/// too high, silently, for as long as the node stays quiet afterward.
/// `IntGauge::inc`/`dec` are the atomic increment/decrement themselves, so
/// there is nothing between the read and the write for the other side to
/// land in.
pub(crate) fn inc_state_write_queue_depth() {
    LEAN_STATE_WRITE_QUEUE_DEPTH.inc();
}

/// One state left the writer's queue, its commit having returned. Call after
/// [`PendingStates::remove`](crate::state_writer::PendingStates::remove).
pub(crate) fn dec_state_write_queue_depth() {
    LEAN_STATE_WRITE_QUEUE_DEPTH.dec();
}

/// Time one state write; the guard records on drop.
pub(crate) fn time_state_write() -> TimingGuard {
    TimingGuard::new(&LEAN_STATE_WRITE_SECONDS)
}
