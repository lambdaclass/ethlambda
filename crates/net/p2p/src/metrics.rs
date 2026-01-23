//! Prometheus metrics for the P2P network layer.

use std::sync::LazyLock;

use prometheus::{IntCounterVec, IntGaugeVec, register_int_counter_vec, register_int_gauge_vec};

static LEAN_CONNECTED_PEERS: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "lean_connected_peers",
        "Number of connected peers",
        &["client"]
    )
    .unwrap()
});

static LEAN_PEER_CONNECTION_EVENTS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "lean_peer_connection_events_total",
        "Total number of peer connection events",
        &["direction", "result"]
    )
    .unwrap()
});

static LEAN_PEER_DISCONNECTION_EVENTS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "lean_peer_disconnection_events_total",
        "Total number of peer disconnection events",
        &["direction", "reason"]
    )
    .unwrap()
});

/// Notify that a peer connection event occurred.
///
/// If `result` is "success", the connected peer count is incremented.
/// The connection event counter is always incremented.
pub fn notify_peer_connected(direction: &str, result: &str) {
    LEAN_PEER_CONNECTION_EVENTS_TOTAL
        .with_label_values(&[direction, result])
        .inc();

    if result == "success" {
        LEAN_CONNECTED_PEERS.with_label_values(&["unknown"]).inc();
    }
}

/// Notify that a peer disconnected.
///
/// Decrements the connected peer count and increments the disconnection event counter.
pub fn notify_peer_disconnected(direction: &str, reason: &str) {
    LEAN_PEER_DISCONNECTION_EVENTS_TOTAL
        .with_label_values(&[direction, reason])
        .inc();

    LEAN_CONNECTED_PEERS.with_label_values(&["unknown"]).dec();
}
