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

/// Refresh the per-peer gossipsub score gauge.
///
/// Scores only exist once `with_peer_score` has been called; `peer_score`
/// returns `None` for an unscored peer, and those are skipped rather than
/// published as 0.0, so a missing series means scoring is off rather than a
/// peer sitting at neutral.
pub fn update_gossip_peer_scores<'a>(
    scores: impl Iterator<Item = (&'a PeerId, f64)>,
    node_names: &HashMap<PeerId, String>,
) {
    static LEAN_GOSSIP_PEER_SCORE: LazyLock<GaugeVec> = LazyLock::new(|| {
        register_gauge_vec!(
            "lean_gossip_peer_score",
            "Current gossipsub score for each connected peer",
            &["node_name"]
        )
        .unwrap()
    });
    for (peer_id, score) in scores {
        let name = node_names
            .get(peer_id)
            .map(String::as_str)
            .unwrap_or("unknown");
        LEAN_GOSSIP_PEER_SCORE.with_label_values(&[name]).set(score);
    }
}

/// Record a gossipsub `Event::SlowPeer` report.
///
/// The event fires from the gossipsub heartbeat and carries the messages that
/// failed to enqueue for that peer since the previous heartbeat, split by
/// queue. `non_priority` covers Publish, Forward, IHave and IWant, which share
/// one bounded queue sized by `connection_handler_queue_len`; `priority`
/// covers the separate control queue, whose cap is hardcoded in the fork.
pub fn observe_slow_peer(node_name: &str, priority: usize, non_priority: usize) {
    static LEAN_GOSSIP_SLOW_PEER_REPORTS: LazyLock<IntCounterVec> = LazyLock::new(|| {
        register_int_counter_vec!(
            "lean_gossip_slow_peer_reports_total",
            "Gossipsub SlowPeer events, one per heartbeat in which a peer failed to consume",
            &["node_name"]
        )
        .unwrap()
    });
    static LEAN_GOSSIP_FAILED_MESSAGES: LazyLock<IntCounterVec> = LazyLock::new(|| {
        register_int_counter_vec!(
            "lean_gossip_failed_messages_total",
            "Messages that could not be enqueued for a peer, by queue",
            &["node_name", "queue"]
        )
        .unwrap()
    });
    LEAN_GOSSIP_SLOW_PEER_REPORTS
        .with_label_values(&[node_name])
        .inc();
    LEAN_GOSSIP_FAILED_MESSAGES
        .with_label_values(&[node_name, "priority"])
        .inc_by(priority as u64);
    LEAN_GOSSIP_FAILED_MESSAGES
        .with_label_values(&[node_name, "non_priority"])
        .inc_by(non_priority as u64);
}

/// Record a gossipsub publish that never reached the wire.
///
/// Previously these were logged and discarded, so a node losing every publish
/// looked identical to a healthy one in metrics. `reason` is the
/// `PublishError` variant, which distinguishes total loss (`AllQueuesFull`,
/// every recipient's queue was full) from the benign cases.
pub fn inc_gossip_publish_failed(reason: &str) {
    static LEAN_GOSSIP_PUBLISH_FAILED: LazyLock<IntCounterVec> = LazyLock::new(|| {
        register_int_counter_vec!(
            "lean_gossip_publish_failed_total",
            "Gossipsub publishes rejected before reaching the wire, by PublishError variant",
            &["reason"]
        )
        .unwrap()
    });
    LEAN_GOSSIP_PUBLISH_FAILED
        .with_label_values(&[reason])
        .inc();
}
