//! Prometheus metrics for the storage layer.

use std::sync::LazyLock;

use ethlambda_metrics::*;

use crate::state_writer::CacheKey;

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

static LEAN_STATE_CACHE_LOOKUPS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "lean_state_cache_lookups_total",
        "State cache lookups, by the Store method that made them, the kind of state asked \
         for, and whether the cache held it",
        &["method", "kind", "result"]
    )
    .unwrap()
});

/// The `Store` method a state-cache lookup was made for.
///
/// A label rather than one series, because the callers' rates mean different
/// things: gossip validation calls `cached_state` once per attestation and
/// aggregate, far more often than a block is imported, so a single rate would
/// be dominated by it and hide the import path's misses.
#[derive(Debug, Clone, Copy)]
pub(crate) enum StateCacheMethod {
    /// `Store::get_state`, and the writer thread's own parent read, which
    /// shares its read path (`state_writer::read_state`). A miss falls back
    /// to the write buffer, then to storage.
    Get,
    /// `Store::has_state`. An existence check, so it peeks rather than
    /// promoting the entry; a miss falls back to the write buffer, then to
    /// key-existence checks against storage.
    Has,
    /// `Store::cached_state`, the memoization lookup fork choice's
    /// `checkpoint_state` and gossip validation use. A miss is the caller's
    /// to handle; nothing here falls back to storage.
    Cached,
}

impl StateCacheMethod {
    fn label(self) -> &'static str {
        match self {
            Self::Get => "get_state",
            Self::Has => "has_state",
            Self::Cached => "cached_state",
        }
    }
}

/// Count one state-cache lookup for `key`, made by `method`.
pub(crate) fn inc_state_cache_lookups(method: StateCacheMethod, key: &CacheKey, hit: bool) {
    let kind = match key {
        CacheKey::BlockState(_) => "block",
        CacheKey::CheckpointState { .. } => "checkpoint",
    };
    let result = if hit { "hit" } else { "miss" };
    LEAN_STATE_CACHE_LOOKUPS_TOTAL
        .with_label_values(&[method.label(), kind, result])
        .inc();
}
