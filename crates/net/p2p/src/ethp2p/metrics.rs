//! Prometheus metrics for the experimental ethp2p broadcast path.
//!
//! These distinguish ethp2p traffic from gossipsub (the plan's
//! observability goal) and expose the size of the configured mesh. All use
//! the `lean_` prefix and register lazily into the global default registry
//! the metrics server gathers.

use std::sync::LazyLock;

use ethlambda_metrics::*;

/// Number of ethp2p mesh peers configured at startup (derived from the
/// static bootnode set). Static for the process lifetime: the transport does
/// emit `PeerDisconnected`, but the engine consumes it internally and this
/// gauge is not yet updated on runtime peer loss (a live health signal is a
/// follow-up).
static LEAN_ETHP2P_MESH_PEERS: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "lean_ethp2p_mesh_peers",
        "Number of ethp2p broadcast mesh peers configured at startup"
    )
    .unwrap()
});

/// Number of live ethp2p broadcast sessions held by the engine. Sampled each
/// time the engine task services an event. It should **plateau** once session
/// GC keeps pace with new messages; a monotonic climb means cleanup is not
/// keeping up (a memory-health signal).
static LEAN_ETHP2P_ACTIVE_SESSIONS: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "lean_ethp2p_active_sessions",
        "Number of live ethp2p broadcast sessions currently held by the engine"
    )
    .unwrap()
});

/// Messages crossing the ethp2p path, by `channel` (block / aggregation /
/// attestation) and `direction` (`published` = teed out by this node,
/// `delivered` = reconstructed from the mesh and injected into consensus).
static LEAN_ETHP2P_MESSAGES_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "lean_ethp2p_messages_total",
        "Total ethp2p broadcast messages, by channel and direction",
        &["channel", "direction"]
    )
    .unwrap()
});

/// Set the configured ethp2p mesh peer gauge.
pub(crate) fn set_mesh_peers(count: usize) {
    LEAN_ETHP2P_MESH_PEERS.set(count.try_into().unwrap_or_default());
}

/// Set the live-session gauge (sampled from the engine each event).
pub(crate) fn set_active_sessions(count: usize) {
    LEAN_ETHP2P_ACTIVE_SESSIONS.set(count.try_into().unwrap_or_default());
}

/// Count a message this node published (teed) onto the ethp2p mesh.
pub(crate) fn inc_published(channel: &str) {
    LEAN_ETHP2P_MESSAGES_TOTAL
        .with_label_values(&[channel, "published"])
        .inc();
}

/// Count a message reconstructed from the ethp2p mesh and delivered into
/// the consensus pipeline.
pub(crate) fn inc_delivered(channel: &str) {
    LEAN_ETHP2P_MESSAGES_TOTAL
        .with_label_values(&[channel, "delivered"])
        .inc();
}
