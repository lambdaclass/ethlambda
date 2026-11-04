//! Prometheus metrics for the BLS wrapper.

use std::sync::LazyLock;

use ethlambda_metrics::*;

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
pub(crate) fn inc_pubkey_cache_lookups(hits: u64, misses: u64) {
    if hits > 0 {
        LEAN_BEACON_PUBKEY_CACHE_HITS.inc_by(hits);
    }
    if misses > 0 {
        LEAN_BEACON_PUBKEY_CACHE_MISSES.inc_by(misses);
    }
}

/// Count one key added to the pubkey cache. The cache never removes one.
pub(crate) fn inc_pubkey_cache_entries() {
    LEAN_BEACON_PUBKEY_CACHE_ENTRIES.inc();
}
