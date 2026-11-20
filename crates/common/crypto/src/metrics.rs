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

static LEAN_BEACON_PUBKEY_CACHE_ENTRIES: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "lean_beacon_pubkey_cache_entries",
        "Validated BLS public keys held by the process-wide pubkey cache, by the structure \
         holding them (a key reached both by index and by bytes is held in both)",
        &["structure"]
    )
    .unwrap()
});

static LEAN_BEACON_PUBKEY_CACHE_MAP_ENTRIES: LazyLock<IntGauge> =
    LazyLock::new(|| LEAN_BEACON_PUBKEY_CACHE_ENTRIES.with_label_values(&["map"]));
static LEAN_BEACON_PUBKEY_CACHE_TABLE_ENTRIES: LazyLock<IntGauge> =
    LazyLock::new(|| LEAN_BEACON_PUBKEY_CACHE_ENTRIES.with_label_values(&["table"]));

static LEAN_BEACON_PUBKEY_CACHE_INDEX_CHUNKS: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "lean_beacon_pubkey_cache_index_chunks",
        "Chunks of the pubkey cache's index table allocated so far; the table's memory follows \
         this, not its entry count"
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

/// Count one key added to the pubkey cache's byte-keyed map. The cache never
/// removes one.
pub(crate) fn inc_pubkey_cache_map_entries() {
    LEAN_BEACON_PUBKEY_CACHE_MAP_ENTRIES.inc();
}

/// Count one key added to the pubkey cache's index table. The cache never
/// removes one.
pub(crate) fn inc_pubkey_cache_table_entries() {
    LEAN_BEACON_PUBKEY_CACHE_TABLE_ENTRIES.inc();
}

/// Count one chunk of the index table allocated. Chunks are never freed.
pub(crate) fn inc_pubkey_cache_index_chunks() {
    LEAN_BEACON_PUBKEY_CACHE_INDEX_CHUNKS.inc();
}
