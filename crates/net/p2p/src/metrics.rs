//! Prometheus metrics for the P2P network layer.

use std::{
    collections::HashMap,
    sync::{LazyLock, RwLock},
};

use ethlambda_types::primitives::H256;
use libp2p::{
    PeerId,
    identity::{Keypair, secp256k1},
};
use prometheus::{IntCounterVec, IntGaugeVec, register_int_counter_vec, register_int_gauge_vec};

static NODE_NAME_REGISTRY: LazyLock<RwLock<HashMap<PeerId, &'static str>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

pub fn populate_name_registry(names_and_privkeys: HashMap<String, H256>) {
    let mut registry = NODE_NAME_REGISTRY.write().unwrap();
    let name_registry = names_and_privkeys
        .into_iter()
        .filter_map(|(name, mut privkey)| {
            let Ok(privkey) = secp256k1::SecretKey::try_from_bytes(&mut privkey) else {
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
    *registry = name_registry;
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
