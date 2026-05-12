//! Prometheus metrics for the P2P network layer.

use std::collections::HashMap;
use std::sync::LazyLock;

use ethlambda_metrics::*;
use libp2p::PeerId;

static LEAN_CONNECTED_PEERS: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "lean_connected_peers",
        "Number of connected peers",
        &["client"]
    )
    .unwrap()
});

static LEAN_GOSSIP_MESH_PEERS: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "lean_gossip_mesh_peers",
        "Number of peers in the gossipsub mesh",
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

// --- Gossip Message Size Histograms ---
//
// `compression` label values:
// - `"raw"`: size of SSZ-encoded payload before snappy compression
// - `"snappy"`: size of the on-wire snappy-compressed payload

static LEAN_GOSSIP_BLOCK_SIZE_BYTES: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        "lean_gossip_block_size_bytes",
        "Bytes size of a gossip block message",
        &["compression"],
        vec![
            10_000.0,
            50_000.0,
            100_000.0,
            250_000.0,
            500_000.0,
            1_000_000.0,
            2_000_000.0,
            5_000_000.0
        ]
    )
    .unwrap()
});

static LEAN_GOSSIP_ATTESTATION_SIZE_BYTES: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        "lean_gossip_attestation_size_bytes",
        "Bytes size of a gossip attestation message",
        &["compression"],
        vec![512.0, 1024.0, 2048.0, 4096.0, 8192.0, 16384.0]
    )
    .unwrap()
});

static LEAN_GOSSIP_AGGREGATION_SIZE_BYTES: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        "lean_gossip_aggregation_size_bytes",
        "Bytes size of a gossip aggregated attestation message",
        &["compression"],
        vec![
            1024.0,
            4096.0,
            16384.0,
            65536.0,
            131_072.0,
            262_144.0,
            524_288.0,
            1_048_576.0
        ]
    )
    .unwrap()
});

/// Observe the size of a gossip block message, recording both the raw SSZ
/// size and the snappy-compressed on-wire size.
pub fn observe_gossip_block_size(raw: usize, snappy: usize) {
    LEAN_GOSSIP_BLOCK_SIZE_BYTES
        .with_label_values(&["raw"])
        .observe(raw as f64);
    LEAN_GOSSIP_BLOCK_SIZE_BYTES
        .with_label_values(&["snappy"])
        .observe(snappy as f64);
}

/// Observe the size of a gossip attestation message, recording both the raw
/// SSZ size and the snappy-compressed on-wire size.
pub fn observe_gossip_attestation_size(raw: usize, snappy: usize) {
    LEAN_GOSSIP_ATTESTATION_SIZE_BYTES
        .with_label_values(&["raw"])
        .observe(raw as f64);
    LEAN_GOSSIP_ATTESTATION_SIZE_BYTES
        .with_label_values(&["snappy"])
        .observe(snappy as f64);
}

/// Observe the size of a gossip aggregated attestation message, recording both
/// the raw SSZ size and the snappy-compressed on-wire size.
pub fn observe_gossip_aggregation_size(raw: usize, snappy: usize) {
    LEAN_GOSSIP_AGGREGATION_SIZE_BYTES
        .with_label_values(&["raw"])
        .observe(raw as f64);
    LEAN_GOSSIP_AGGREGATION_SIZE_BYTES
        .with_label_values(&["snappy"])
        .observe(snappy as f64);
}

// --- Req/Resp Message Size Histograms ---
//
// `protocol` label: `"status"` or `"blocks_by_root"`.
// `compression` label: `"raw"` (SSZ) or `"snappy"` (on-wire, varint-prefixed
// snappy frame bytes only — the response-code byte is not included).

static LEAN_REQRESP_REQUEST_SIZE_BYTES: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        "lean_reqresp_request_size_bytes",
        "Bytes size of a req/resp request",
        &["protocol", "compression"],
        vec![64.0, 128.0, 256.0, 512.0, 1024.0, 4096.0, 16384.0, 65536.0]
    )
    .unwrap()
});

static LEAN_REQRESP_RESPONSE_CHUNK_SIZE_BYTES: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        "lean_reqresp_response_chunk_size_bytes",
        "Bytes size of a single req/resp response chunk",
        &["protocol", "compression"],
        vec![
            128.0,
            1024.0,
            10_000.0,
            100_000.0,
            500_000.0,
            1_000_000.0,
            5_000_000.0,
            10_000_000.0
        ]
    )
    .unwrap()
});

/// Observe the size of a req/resp request, recording both the raw SSZ size
/// and the snappy-compressed on-wire size.
pub fn observe_reqresp_request_size(protocol: &str, raw: usize, snappy: usize) {
    LEAN_REQRESP_REQUEST_SIZE_BYTES
        .with_label_values(&[protocol, "raw"])
        .observe(raw as f64);
    LEAN_REQRESP_REQUEST_SIZE_BYTES
        .with_label_values(&[protocol, "snappy"])
        .observe(snappy as f64);
}

/// Observe the size of a single req/resp response chunk, recording both the
/// raw SSZ size and the snappy-compressed on-wire size.
pub fn observe_reqresp_response_chunk_size(protocol: &str, raw: usize, snappy: usize) {
    LEAN_REQRESP_RESPONSE_CHUNK_SIZE_BYTES
        .with_label_values(&[protocol, "raw"])
        .observe(raw as f64);
    LEAN_REQRESP_RESPONSE_CHUNK_SIZE_BYTES
        .with_label_values(&[protocol, "snappy"])
        .observe(snappy as f64);
}

/// Set the attestation committee subnet gauge.
pub fn set_attestation_committee_subnet(subnet_id: u64) {
    static LEAN_ATTESTATION_COMMITTEE_SUBNET: LazyLock<IntGauge> = LazyLock::new(|| {
        register_int_gauge!(
            "lean_attestation_committee_subnet",
            "Node's attestation committee subnet"
        )
        .unwrap()
    });
    LEAN_ATTESTATION_COMMITTEE_SUBNET.set(subnet_id.try_into().unwrap_or_default());
}

/// Notify that a peer connection event occurred.
///
/// If `result` is "success", the connected peer count is incremented.
/// The connection event counter is always incremented.
pub fn notify_peer_connected(node_name: &str, direction: &str, result: &str) {
    LEAN_PEER_CONNECTION_EVENTS_TOTAL
        .with_label_values(&[direction, result])
        .inc();

    if result == "success" {
        LEAN_CONNECTED_PEERS.with_label_values(&[node_name]).inc();
    }
}

/// Notify that a peer disconnected.
///
/// Decrements the connected peer count and increments the disconnection event counter.
pub fn notify_peer_disconnected(node_name: &str, direction: &str, reason: &str) {
    LEAN_PEER_DISCONNECTION_EVENTS_TOTAL
        .with_label_values(&[direction, reason])
        .inc();

    LEAN_CONNECTED_PEERS.with_label_values(&[node_name]).dec();
}

/// Refresh the gossipsub mesh peers gauge from the current mesh peer set.
pub fn update_gossip_mesh_peers<'a>(
    peers: impl Iterator<Item = &'a PeerId>,
    node_names: &HashMap<PeerId, String>,
) {
    let mut counts: HashMap<String, i64> = HashMap::new();
    for peer_id in peers {
        let name = node_names
            .get(peer_id)
            .map(String::as_str)
            .unwrap_or("unknown");
        *counts.entry(name.to_string()).or_default() += 1;
    }
    // Seed previously-published labels with 0 so departed clients fall to
    // zero in the single set() pass below.
    for family in LEAN_GOSSIP_MESH_PEERS.collect() {
        for metric in family.get_metric() {
            for label in metric.get_label() {
                counts.entry(label.value().to_string()).or_insert(0);
            }
        }
    }
    for (name, count) in counts {
        LEAN_GOSSIP_MESH_PEERS
            .with_label_values(&[&name])
            .set(count);
    }
}
