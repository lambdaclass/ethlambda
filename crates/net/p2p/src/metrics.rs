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

/// Count an established connection against the transport that carried it.
///
/// A separate metric rather than a third label on
/// `lean_peer_connection_events_total`: that one is leanMetrics-specified down
/// to its `direction`/`result` label set, so widening it would put ethlambda
/// off-spec. This is the production-visible answer to "did the TCP fallback
/// actually carry anything", which the `transport` trace field alone cannot give
/// at default verbosity.
///
/// Counts connections, not peers: a peer holding both a QUIC and a TCP
/// connection is counted once per connection, so the total can exceed the
/// `result="success"` count next door, which fires only on a peer's first.
pub fn inc_peer_connection_transport(direction: &str, transport: &str) {
    static LEAN_PEER_CONNECTIONS_BY_TRANSPORT: LazyLock<IntCounterVec> = LazyLock::new(|| {
        register_int_counter_vec!(
            "lean_peer_connections_by_transport_total",
            "Established peer connections by the transport that carried them",
            &["direction", "transport"]
        )
        .unwrap()
    });
    LEAN_PEER_CONNECTIONS_BY_TRANSPORT
        .with_label_values(&[direction, transport])
        .inc();
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

/// Count a closed connection against what actually ended it.
///
/// A separate metric rather than more values on
/// `lean_peer_disconnection_events_total`'s `reason`, for the same reason
/// [`inc_peer_connection_transport`] is separate: that one is leanMetrics-
/// specified down to its label values, so adding to them would put ethlambda
/// off-spec.
///
/// The specified set is `timeout`/`remote_close`/`local_close`/`error`, and on
/// a mainnet follower nine in ten closes land in `error`, which says only that
/// libp2p handed back a cause. This splits that bucket: see
/// [`crate::disconnect_cause`] for the values and what each one means.
pub fn inc_peer_disconnect_cause(direction: &str, cause: &str) {
    static LEAN_PEER_DISCONNECT_CAUSE: LazyLock<IntCounterVec> = LazyLock::new(|| {
        register_int_counter_vec!(
            "lean_peer_disconnect_cause_total",
            "Closed peer connections by the cause libp2p reported for the close",
            &["direction", "cause"]
        )
        .unwrap()
    });
    LEAN_PEER_DISCONNECT_CAUSE
        .with_label_values(&[direction, cause])
        .inc();
}

/// Count a `goodbye/1` received, against the reason the peer gave.
///
/// The only place a peer states *why* it is leaving. Everything else about a
/// disconnect is inferred from how the socket ended, and the two readings that
/// matter most are indistinguishable there: a peer that is merely full closes
/// exactly like one that has scored us badly or banned us.
///
/// One-directional by construction, so there is no `direction` label: this node
/// never sends a `goodbye`, and the protocol is registered inbound-only.
///
/// See [`crate::beacon::messages::Goodbye::reason_label`] for the values, which
/// are bounded there because the wire code is not.
pub fn inc_peer_goodbye(reason: &str) {
    static LEAN_PEER_GOODBYE: LazyLock<IntCounterVec> = LazyLock::new(|| {
        register_int_counter_vec!(
            "lean_peer_goodbye_total",
            "Goodbye messages received, by the reason code the peer sent",
            &["reason"]
        )
        .unwrap()
    });
    LEAN_PEER_GOODBYE.with_label_values(&[reason]).inc();
}

/// Counts dials initiated from discv5 discovery, as opposed to static bootnode
/// dials. Connection outcomes are already covered by the peer connect and
/// disconnect metrics.
pub fn inc_discovered_peers_dialed() {
    static LEAN_DISCOVERED_PEERS_DIALED: LazyLock<IntCounter> = LazyLock::new(|| {
        register_int_counter!(
            "lean_discovered_peers_dialed_total",
            "Peers dialed as a result of discv5 discovery"
        )
        .unwrap()
    });
    LEAN_DISCOVERED_PEERS_DIALED.inc();
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

static LEAN_BEACON_GOSSIP_MESSAGES_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "lean_beacon_gossip_messages_total",
        "Beacon gossip messages received, by topic and decode outcome",
        &["topic", "result"]
    )
    .unwrap()
});

static LEAN_BEACON_STATUS_DIGEST_MISMATCH_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "lean_beacon_status_digest_mismatch_total",
        "Beacon Status requests whose fork digest did not match ours"
    )
    .unwrap()
});

static LEAN_BEACON_FORK_DIGEST: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "lean_beacon_fork_digest",
        "The fork digest this node computed at startup, as a label",
        &["digest"]
    )
    .unwrap()
});

/// Count one gossip message. `result` is `decoded`, `decode_failed`, or
/// `decompress_failed`.
pub fn inc_beacon_gossip(topic: &str, result: &str) {
    LEAN_BEACON_GOSSIP_MESSAGES_TOTAL
        .with_label_values(&[topic, result])
        .inc();
}

static LEAN_BEACON_GOSSIP_VALIDATION_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "lean_beacon_gossip_validation_total",
        "Beacon gossip verdicts, by topic kind, outcome and reason",
        &["kind", "outcome", "reason"]
    )
    .unwrap()
});

static LEAN_BEACON_GOSSIP_VALIDATION_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        "lean_beacon_gossip_validation_seconds",
        "Time from a beacon gossip message's arrival to its verdict",
        &["kind"],
        vec![
            0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0
        ]
    )
    .unwrap()
});

static LEAN_BEACON_GOSSIP_VERDICT_EXPIRED_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "lean_beacon_gossip_verdict_expired_total",
        "Beacon gossip verdicts reported after gossipsub had evicted the message",
        &["kind"]
    )
    .unwrap()
});

/// Every reason `beacon::column_checks` can count a sidecar under: the
/// `Outcome` reason labels `column::chain_checks` drops with, less
/// `already_stored`, which is a duplicate rather than a rejection. Seeded at
/// zero by [`init`], so a reason this node never fires is still visible on a
/// dashboard.
const DATA_COLUMN_REJECT_REASONS: &[&str] = &[
    "malformed",
    "future_slot",
    "finalized",
    "not_after_parent",
    "unknown_proposer",
    "bad_signature",
    "wrong_proposer",
    "finalized_not_ancestor",
    "parent_not_ready",
    "inclusion_proof",
    "kzg",
    "internal",
];

static LEAN_DATA_COLUMNS_REJECTED_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "lean_data_columns_rejected_total",
        "Data column sidecars the chain checks dropped, by reason (gossip verdicts are counted by lean_beacon_gossip_validation_total)",
        &["reason"]
    )
    .unwrap()
});

/// Count one sidecar the chain checks dropped. `reason` is one of
/// [`DATA_COLUMN_REJECT_REASONS`].
pub fn inc_data_column_rejected(reason: &str) {
    LEAN_DATA_COLUMNS_REJECTED_TOTAL
        .with_label_values(&[reason])
        .inc();
}

/// Register the metrics that should be visible before their first
/// observation.
pub fn init() {
    LazyLock::force(&LEAN_DATA_COLUMNS_REJECTED_TOTAL);
    for &reason in DATA_COLUMN_REJECT_REASONS {
        LEAN_DATA_COLUMNS_REJECTED_TOTAL.with_label_values(&[reason]);
    }
}

/// Count one beacon gossip verdict and how long it took from arrival.
pub fn observe_beacon_gossip_verdict(
    kind: &str,
    outcome: &str,
    reason: &str,
    elapsed: std::time::Duration,
) {
    LEAN_BEACON_GOSSIP_VALIDATION_TOTAL
        .with_label_values(&[kind, outcome, reason])
        .inc();
    LEAN_BEACON_GOSSIP_VALIDATION_SECONDS
        .with_label_values(&[kind])
        .observe(elapsed.as_secs_f64());
}

/// Count one verdict gossipsub could no longer act on.
pub fn inc_beacon_gossip_verdict_expired(kind: &str) {
    LEAN_BEACON_GOSSIP_VERDICT_EXPIRED_TOTAL
        .with_label_values(&[kind])
        .inc();
}

pub fn inc_beacon_status_digest_mismatch() {
    LEAN_BEACON_STATUS_DIGEST_MISMATCH_TOTAL.inc();
}

/// Publish the computed fork digest as a label, so a dashboard can tell at a
/// glance whether a node is stranded on a boundary it failed to cross.
pub fn set_beacon_fork_digest(digest: &str) {
    LEAN_BEACON_FORK_DIGEST.with_label_values(&[digest]).set(1);
}

static LEAN_DATA_COLUMN_FETCH_FAILURES_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "lean_data_column_fetch_failures_total",
        "Data column sidecar lookups abandoned, by reason",
        &["reason"]
    )
    .unwrap()
});

/// Count one `DataColumnsByRoot` lookup this node gave up on. `reason` is
/// `"no_peers"` (nothing connected to ask) or `"max_retries"` (the retry
/// ladder ran out).
pub fn inc_data_column_fetch_failure(reason: &str) {
    LEAN_DATA_COLUMN_FETCH_FAILURES_TOTAL
        .with_label_values(&[reason])
        .inc();
}

/// Test-only readback of [`inc_data_column_fetch_failure`]'s counter. The
/// metric otherwise has no consumer inside the crate itself (Prometheus
/// scrapes it), so this is the only way a test can observe that a failure was
/// actually counted rather than merely that the code path returned.
#[cfg(test)]
pub(crate) fn data_column_fetch_failures_total(reason: &str) -> u64 {
    LEAN_DATA_COLUMN_FETCH_FAILURES_TOTAL
        .with_label_values(&[reason])
        .get()
}

// --- Peer composition and custody-column supply ---

/// Connected peers split by which side opened the connection.
///
/// Separate from `lean_connected_peers`, which is labelled by node name and
/// exists to answer "who are we talking to". This one answers "how did we get
/// them", and the difference is operational: inbound supply is unbounded and
/// unchosen, while an outbound peer is one this node picked and is the only
/// kind it can aim at a column it needs. A node pinned at its inbound cap with
/// zero outbound peers looks perfectly healthy on a total peer count and cannot
/// steer its own custody coverage at all.
static LEAN_PEERS_BY_DIRECTION: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "lean_peers_by_direction",
        "Connected peers by the direction the connection was opened in",
        &["direction"]
    )
    .unwrap()
});

/// Established connections as libp2p itself counts them.
///
/// The connection limits are enforced against these, not against
/// [`LEAN_PEERS_BY_DIRECTION`], so publishing both is what makes a leaked
/// connection visible: one the swarm still charges against the cap but that no
/// live peer is using would show up here and nowhere else. The two are not
/// expected to be equal, since this counts connections and the other counts
/// peers, and a peer may hold more than one; what matters is that the gap
/// stays small and does not grow.
static LEAN_SWARM_ESTABLISHED_CONNECTIONS: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "lean_swarm_established_connections",
        "Established connections as counted by the libp2p swarm, which is what \
         the connection limits are enforced against",
        &["direction"]
    )
    .unwrap()
});

/// Connected peers known to custody each column this node samples.
static LEAN_CUSTODY_COLUMN_PEERS: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "lean_custody_column_peers",
        "Connected peers known to custody each data column this node samples",
        &["column"]
    )
    .unwrap()
});

/// Set the peers-by-direction gauges from a full re-count.
pub fn set_peers_by_direction(inbound: usize, outbound: usize) {
    LEAN_PEERS_BY_DIRECTION
        .with_label_values(&["inbound"])
        .set(inbound as i64);
    LEAN_PEERS_BY_DIRECTION
        .with_label_values(&["outbound"])
        .set(outbound as i64);
}

/// Set the swarm's own established-connection gauges.
pub fn set_swarm_established_connections(inbound: u32, outbound: u32) {
    LEAN_SWARM_ESTABLISHED_CONNECTIONS
        .with_label_values(&["inbound"])
        .set(i64::from(inbound));
    LEAN_SWARM_ESTABLISHED_CONNECTIONS
        .with_label_values(&["outbound"])
        .set(i64::from(outbound));
}

/// Set how many connected peers are known to custody `column`.
///
/// A peer counts only once it has answered `metadata/3` or arrived with a
/// usable `cgc`, matching `P2PServer::peer_custody`. That makes this a floor on
/// real supply rather than an estimate of it, which is the right direction for
/// a gauge whose job is to show a column running dry.
pub fn set_custody_column_peers(column: u64, peers: usize) {
    LEAN_CUSTODY_COLUMN_PEERS
        .with_label_values(&[&column.to_string()])
        .set(peers as i64);
}
