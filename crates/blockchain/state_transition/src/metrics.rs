//! Prometheus metrics for state transition.

use std::sync::LazyLock;

use ethlambda_metrics::*;

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

static LEAN_BEACON_COMMITTEE_CACHE_LOOKUPS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "lean_beacon_committee_cache_lookups_total",
        "Beacon committee shuffling lookups, by whether the committee cache served them",
        &["result"]
    )
    .unwrap()
});

/// Count one `CommitteeCache` lookup: `hit`, `miss` (a whole-epoch shuffle
/// was built and cached), or `unkeyable` (built for one caller, not cached).
pub fn inc_committee_cache_lookups(result: &str) {
    LEAN_BEACON_COMMITTEE_CACHE_LOOKUPS_TOTAL
        .with_label_values(&[result])
        .inc();
}

static LEAN_BEACON_JUSTIFIED_BALANCES_LOOKUPS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(
    || {
        register_int_counter_vec!(
            "lean_beacon_justified_balances_lookups_total",
            "Beacon fork-choice justified-balances snapshot lookups, by whether the cached snapshot served them",
            &["result"]
        )
        .unwrap()
    },
);

/// Count one justified-balances lookup: `hit` (the cached snapshot matched the
/// justified checkpoint) or `miss` (it was rebuilt from the checkpoint state).
pub fn inc_justified_balances_lookups(result: &str) {
    LEAN_BEACON_JUSTIFIED_BALANCES_LOOKUPS_TOTAL
        .with_label_values(&[result])
        .inc();
}

static LEAN_BEACON_JUSTIFIED_BALANCES_BUILD_SECONDS: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(
        "lean_beacon_justified_balances_build_seconds",
        "Duration of one justified-balances snapshot build (one pass over the checkpoint state's registry)",
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
    )
    .unwrap()
});

/// Time one justified-balances snapshot build, excluding the checkpoint state
/// lookup it starts from.
pub fn time_justified_balances_build() -> TimingGuard {
    TimingGuard::new(&LEAN_BEACON_JUSTIFIED_BALANCES_BUILD_SECONDS)
}

static LEAN_STATE_TRANSITION_TIME_SECONDS: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(
        "lean_state_transition_time_seconds",
        "Duration of the entire state transition",
        vec![0.25, 0.5, 0.75, 1.0, 1.25, 1.5, 2.0, 2.5, 3.0, 4.0]
    )
    .unwrap()
});

static LEAN_STATE_TRANSITION_SLOTS_PROCESSING_TIME_SECONDS: LazyLock<Histogram> =
    LazyLock::new(|| {
        register_histogram!(
            "lean_state_transition_slots_processing_time_seconds",
            "Duration to process slots",
            vec![0.005, 0.01, 0.025, 0.05, 0.1, 1.0]
        )
        .unwrap()
    });

static LEAN_STATE_TRANSITION_BLOCK_PROCESSING_TIME_SECONDS: LazyLock<Histogram> =
    LazyLock::new(|| {
        register_histogram!(
            "lean_state_transition_block_processing_time_seconds",
            "Duration to process a block in state transition",
            vec![0.005, 0.01, 0.025, 0.05, 0.1, 1.0]
        )
        .unwrap()
    });

static LEAN_STATE_TRANSITION_ATTESTATIONS_PROCESSING_TIME_SECONDS: LazyLock<Histogram> =
    LazyLock::new(|| {
        register_histogram!(
            "lean_state_transition_attestations_processing_time_seconds",
            "Duration to process attestations",
            vec![0.005, 0.01, 0.025, 0.05, 0.1, 1.0]
        )
        .unwrap()
    });

/// Start timing state transition. Records duration when the guard is dropped.
pub fn time_state_transition() -> TimingGuard {
    TimingGuard::new(&LEAN_STATE_TRANSITION_TIME_SECONDS)
}

/// Start timing slots processing. Records duration when the guard is dropped.
pub fn time_slots_processing() -> TimingGuard {
    TimingGuard::new(&LEAN_STATE_TRANSITION_SLOTS_PROCESSING_TIME_SECONDS)
}

/// Start timing block processing. Records duration when the guard is dropped.
pub fn time_block_processing() -> TimingGuard {
    TimingGuard::new(&LEAN_STATE_TRANSITION_BLOCK_PROCESSING_TIME_SECONDS)
}

/// Start timing attestations processing. Records duration when the guard is dropped.
pub fn time_attestations_processing() -> TimingGuard {
    TimingGuard::new(&LEAN_STATE_TRANSITION_ATTESTATIONS_PROCESSING_TIME_SECONDS)
}

static LEAN_BEACON_PUBKEY_CACHE_LOOKUPS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "lean_beacon_pubkey_cache_lookups_total",
        "BLS public keys resolved for a signature check, by whether the validated-pubkey cache \
         already held them",
        &["result"]
    )
    .unwrap()
});

// The two label values resolved once: a lookup is counted on every signature
// check, and the vector's own label lookup would hash the label every time.
static LEAN_BEACON_PUBKEY_CACHE_HITS: LazyLock<IntCounter> =
    LazyLock::new(|| LEAN_BEACON_PUBKEY_CACHE_LOOKUPS_TOTAL.with_label_values(&["hit"]));
static LEAN_BEACON_PUBKEY_CACHE_MISSES: LazyLock<IntCounter> =
    LazyLock::new(|| LEAN_BEACON_PUBKEY_CACHE_LOOKUPS_TOTAL.with_label_values(&["miss"]));

static LEAN_BEACON_PUBKEY_CACHE_ENTRIES: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "lean_beacon_pubkey_cache_entries",
        "Validated BLS public keys held by the process-wide pubkey cache"
    )
    .unwrap()
});

/// Count one signature check's public keys: `hits` the cache already held,
/// `misses` it had to validate (whether or not they then passed).
pub fn inc_pubkey_cache_lookups(hits: u64, misses: u64) {
    if hits > 0 {
        LEAN_BEACON_PUBKEY_CACHE_HITS.inc_by(hits);
    }
    if misses > 0 {
        LEAN_BEACON_PUBKEY_CACHE_MISSES.inc_by(misses);
    }
}

/// Count one key added to the pubkey cache. The cache never removes one.
pub fn inc_pubkey_cache_entries() {
    LEAN_BEACON_PUBKEY_CACHE_ENTRIES.inc();
}

static LEAN_DATA_COLUMN_KZG_VERIFY_SECONDS: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(
        "lean_data_column_kzg_verify_seconds",
        "Time spent batch-verifying one sidecar's cells against its own commitments",
        vec![0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
    )
    .unwrap()
});

/// Start timing a sidecar's KZG cell-proof batch. Records duration when the
/// guard is dropped.
///
/// Here rather than beside the rest of the column metrics, because the batch
/// runs inside `beacon::gossip::column`'s rules, which both the gossip path
/// and the p2p layer's chain checks call.
pub fn time_data_column_kzg_verify() -> TimingGuard {
    TimingGuard::new(&LEAN_DATA_COLUMN_KZG_VERIFY_SECONDS)
}

/// Register the metrics above that should be visible before their first
/// observation.
pub fn init() {
    LazyLock::force(&LEAN_DATA_COLUMN_KZG_VERIFY_SECONDS);
}
