//! Prometheus metrics for the P2P network layer.

use std::{
    collections::HashMap,
    sync::{LazyLock, RwLock},
};

use ethlambda_metrics::*;
use ethlambda_types::primitives::H256;
use libp2p::{
    PeerId,
    identity::{Keypair, secp256k1},
};

static NODE_NAME_REGISTRY: LazyLock<RwLock<HashMap<PeerId, &'static str>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

pub fn populate_name_registry(names_and_privkeys: HashMap<String, H256>) {
    let mut registry = NODE_NAME_REGISTRY.write().unwrap();
    *registry = names_and_privkeys
        .into_iter()
        .filter_map(|(name, mut privkey)| {
            let Ok(privkey) = secp256k1::SecretKey::try_from_bytes(&mut privkey.0) else {
                return None;
            };
            let pubkey = Keypair::from(secp256k1::Keypair::from(privkey)).public();
            let peer_id = PeerId::from_public_key(&pubkey);
            // NOTE: we leak the name string to get a 'static lifetime.
            // In reality, the name registry is not expected to be read, so it should be safe
            // to turn these strings to &'static str.
            Some((peer_id, &*name.leak()))
        })
        .collect();
}

fn resolve(peer_id: &Option<PeerId>) -> &'static str {
    let registry = NODE_NAME_REGISTRY.read().unwrap();
    peer_id
        .as_ref()
        .and_then(|peer_id| registry.get(peer_id))
        .unwrap_or(&"unknown")
}

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
pub fn notify_peer_connected(peer_id: &Option<PeerId>, direction: &str, result: &str) {
    LEAN_PEER_CONNECTION_EVENTS_TOTAL
        .with_label_values(&[direction, result])
        .inc();

    if result == "success" {
        let name = resolve(peer_id);
        LEAN_CONNECTED_PEERS.with_label_values(&[name]).inc();
    }
}

static LEAN_GOSSIP_BLOCK_SIZE_BYTES: LazyLock<ethlambda_metrics::Histogram> = LazyLock::new(|| {
    ethlambda_metrics::register_histogram!(
        "lean_gossip_block_size_bytes",
        "Bytes size of a gossip block message",
        vec![
            10000.0, 50000.0, 100000.0, 250000.0, 500000.0, 1000000.0, 2000000.0, 5000000.0
        ]
    )
    .unwrap()
});

static LEAN_GOSSIP_ATTESTATION_SIZE_BYTES: LazyLock<ethlambda_metrics::Histogram> =
    LazyLock::new(|| {
        ethlambda_metrics::register_histogram!(
            "lean_gossip_attestation_size_bytes",
            "Bytes size of a gossip attestation message",
            vec![512.0, 1024.0, 2048.0, 4096.0, 8192.0, 16384.0]
        )
        .unwrap()
    });

static LEAN_GOSSIP_AGGREGATION_SIZE_BYTES: LazyLock<ethlambda_metrics::Histogram> =
    LazyLock::new(|| {
        ethlambda_metrics::register_histogram!(
            "lean_gossip_aggregation_size_bytes",
            "Bytes size of a gossip aggregated attestation message",
            vec![
                1024.0, 4096.0, 16384.0, 65536.0, 131072.0, 262144.0, 524288.0, 1048576.0
            ]
        )
        .unwrap()
    });

/// Observe the compressed size of a gossip block message.
pub fn observe_gossip_block_size(bytes: usize) {
    LEAN_GOSSIP_BLOCK_SIZE_BYTES.observe(bytes as f64);
}

/// Observe the compressed size of a gossip attestation message.
pub fn observe_gossip_attestation_size(bytes: usize) {
    LEAN_GOSSIP_ATTESTATION_SIZE_BYTES.observe(bytes as f64);
}

/// Observe the compressed size of a gossip aggregated attestation message.
pub fn observe_gossip_aggregation_size(bytes: usize) {
    LEAN_GOSSIP_AGGREGATION_SIZE_BYTES.observe(bytes as f64);
}

/// Notify that a peer disconnected.
///
/// Decrements the connected peer count and increments the disconnection event counter.
pub fn notify_peer_disconnected(peer_id: &Option<PeerId>, direction: &str, reason: &str) {
    LEAN_PEER_DISCONNECTION_EVENTS_TOTAL
        .with_label_values(&[direction, reason])
        .inc();

    let name = resolve(peer_id);
    LEAN_CONNECTED_PEERS.with_label_values(&[name]).dec();
}
