//! discv5 peer discovery, built on ethrex's discovery stack.
//!
//! ethrex's `DiscoveryServer` runs discv5-only on its own UDP socket and writes
//! what it finds into an ethrex `PeerTable`. ethlambda's `P2PServer` polls that
//! table, applies the spec checks in [`admission`], and dials the survivors over
//! libp2p QUIC. Static bootnode dialing is untouched.
//!
//! See `docs/discovery.md` for the operator-facing description.

pub mod admission;
pub mod enr;

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ethlambda_types::enr::EnrForkId;
use ethrex_p2p::discovery::{DiscoveryConfig, DiscoveryServer};
use ethrex_p2p::peer_table::{PeerTable, PeerTableServer};
use ethrex_p2p::types::Node;
use ethrex_storage::{EngineType, Store};
use secp256k1::SecretKey;
use tokio::net::UdpSocket;
use tracing::info;

use crate::Bootnode;
use enr::{LocalEnrParams, build_local_enr};

/// How often the dial loop looks for a new peer.
pub const DISCOVERY_DIAL_INTERVAL: Duration = Duration::from_secs(5);

/// Connected-peer count above which discovery stops dialing. Also the peer
/// table's own target.
pub const DISCOVERY_TARGET_PEERS: usize = 16;

/// Candidates drawn from the peer table per refill.
pub const DISCOVERY_CANDIDATE_BATCH: usize = 8;

pub struct DiscoverySpawnConfig {
    pub node_key: SecretKey,
    pub bind_ip: IpAddr,
    pub discovery_port: u16,
    pub quic_port: u16,
    pub subscription_subnets: HashSet<u64>,
    pub attestation_committee_count: u64,
    pub bootnodes: Vec<Bootnode>,
    /// IP address to advertise in the ENR. Defaults to `bind_ip` when unset,
    /// which is undialable if `bind_ip` is the wildcard `0.0.0.0`.
    pub advertise_ip: Option<IpAddr>,
}

/// What the P2P actor needs from a running discovery server.
pub struct DiscoveryHandle {
    pub peer_table: PeerTable,
    /// This node's ENR as an `enr:`-prefixed string, for logs and the RPC
    /// identity endpoint. Reflects startup state; discv5 may bump the sequence
    /// number later if PONG voting changes our external IP.
    pub local_enr: String,
    pub local_fork_id: EnrForkId,
    /// The discv5 socket's actual bound address. Equal to the requested
    /// `discovery_port` unless that was 0, in which case this carries the
    /// port the OS assigned — the same one baked into `local_enr`'s `udp`
    /// entry.
    pub bound_addr: SocketAddr,
}

/// Bind the discv5 socket, build the local ENR, and start ethrex's discovery
/// server with discv4 disabled.
///
/// The socket is bound before the ENR is built so that a `discovery_port: 0`
/// (ask the OS for a free port) still produces an ENR advertising the real
/// bound port rather than the literal 0, which would be undialable.
///
/// Only bootnodes whose ENR advertises a `udp` port can seed discv5; the rest
/// are still dialed statically by `build_swarm`.
pub async fn spawn_discovery(config: DiscoverySpawnConfig) -> Result<DiscoveryHandle, String> {
    let bind_addr = SocketAddr::new(config.bind_ip, config.discovery_port);
    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(|err| format!("failed to bind discovery socket on {bind_addr}: {err}"))?;
    let bound = socket
        .local_addr()
        .map_err(|err| format!("failed to read discovery socket address: {err}"))?;

    let params = LocalEnrParams {
        signer: config.node_key,
        ip: config.advertise_ip.unwrap_or(config.bind_ip),
        discovery_port: bound.port(),
        quic_port: config.quic_port,
        subscription_subnets: config.subscription_subnets,
        attestation_committee_count: config.attestation_committee_count,
    };
    let local_node = params.local_node();
    let local_record = build_local_enr(&params)?;
    let local_enr = local_record
        .enr_url()
        .map_err(|err| format!("failed to encode local ENR: {err}"))?;

    let peer_table = PeerTableServer::spawn_with_requirements(
        local_node.node_id(),
        DISCOVERY_TARGET_PEERS,
        // `PeerTableServer::spawn` would impose ethrex's own requirement, an
        // EIP-2124 `eth` entry compatible with a chain we do not have, which
        // would stamp every lean contact as rejected. Lean imposes nothing at
        // the ENR level here: the spec checks live in [`admission`] and run at
        // dial selection instead.
        Arc::new(admission::AcceptEveryContact),
    );

    let seeds: Vec<Node> = config
        .bootnodes
        .iter()
        .filter_map(|bootnode| bootnode.as_discovery_node())
        .collect();
    info!(
        discovery_addr = %bound,
        seeds = seeds.len(),
        total_bootnodes = config.bootnodes.len(),
        "Starting discv5 discovery"
    );

    // An empty in-memory store, because `spawn` requires one and lean has no
    // execution chain. It is read for exactly one thing, `get_fork_id`, whose
    // result is written into the record ethrex serves; an empty store yields a
    // genesis-less default rather than anything meaningful.
    //
    // KNOWN GAP: `spawn` builds its own local record from `local_node` alone and
    // offers no way to seed the consensus entries, so the record ethrex serves
    // over the wire carries `ip`/`udp`/`secp256k1` but not `eth2`, `attnets` or
    // `quic`. The ENR this node reports (and logs below) is `local_record`,
    // built by `build_local_enr`, and is complete. The consequence is one-sided
    // discovery: we can find and admit lean peers, but a lean peer applying the
    // same admission rules to what ethrex serves would reject us for a missing
    // `quic` entry. Closing this needs a way to hand `spawn` a prepared record.
    let store = Store::new("", EngineType::InMemory)
        .map_err(|err| format!("failed to create the discovery store: {err}"))?;

    DiscoveryServer::spawn(
        store,
        local_node,
        params.signer,
        Arc::new(socket),
        peer_table.clone(),
        seeds,
        DiscoveryConfig {
            discv4_enabled: false,
            discv5_enabled: true,
            ..Default::default()
        },
    )
    .await
    .map_err(|err| format!("failed to start discovery server: {err}"))?;

    info!(enr = %local_enr, "Local ENR");

    Ok(DiscoveryHandle {
        peer_table,
        local_enr,
        local_fork_id: EnrForkId::local(),
        bound_addr: bound,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethrex_p2p::types::NodeRecord;
    use ethrex_rlp::decode::RLPDecode;
    use std::collections::HashSet;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn spawn_binds_the_socket_and_returns_the_local_enr() {
        // Port 0 asks the OS for a free port, so the test cannot collide with a
        // running node or a sibling test.
        let handle = spawn_discovery(DiscoverySpawnConfig {
            node_key: secp256k1::SecretKey::new(&mut rand::rngs::OsRng),
            bind_ip: IpAddr::from(Ipv4Addr::LOCALHOST),
            discovery_port: 0,
            quic_port: 9001,
            subscription_subnets: HashSet::from([0u64]),
            attestation_committee_count: 4,
            bootnodes: Vec::new(),
            advertise_ip: None,
        })
        .await
        .expect("discovery spawns");

        assert!(handle.local_enr.starts_with("enr:"));
        assert_eq!(handle.local_fork_id, EnrForkId::local());

        // With discovery_port: 0 the OS picks the real port. The bound
        // address must reflect that real port, and the published ENR's `udp`
        // entry must match it: were the two out of sync (e.g. the ENR built
        // from the requested port 0 instead of the bound one), the record
        // would advertise an undialable node.
        assert_ne!(handle.bound_addr.port(), 0);
        let record = NodeRecord::decode(&ethrex_common::base64::decode(
            handle
                .local_enr
                .strip_prefix("enr:")
                .expect("enr: prefix")
                .as_bytes(),
        ))
        .expect("local ENR decodes");
        assert_eq!(record.pairs().udp_port, Some(handle.bound_addr.port()));
    }

    #[tokio::test]
    async fn spawn_advertises_a_different_ip_than_it_binds() {
        // Bind the loopback address but advertise a distinct, non-dialable-from-
        // here address, mimicking an operator setting `--discovery.advertise-ip`
        // to their host's public IP while still binding the wildcard/loopback
        // locally. The ENR must reflect the advertised address, not the bind
        // address.
        let advertised = Ipv4Addr::new(203, 0, 113, 7);
        let handle = spawn_discovery(DiscoverySpawnConfig {
            node_key: secp256k1::SecretKey::new(&mut rand::rngs::OsRng),
            bind_ip: IpAddr::from(Ipv4Addr::LOCALHOST),
            discovery_port: 0,
            quic_port: 9001,
            subscription_subnets: HashSet::from([0u64]),
            attestation_committee_count: 4,
            bootnodes: Vec::new(),
            advertise_ip: Some(IpAddr::from(advertised)),
        })
        .await
        .expect("discovery spawns");

        assert_eq!(handle.bound_addr.ip(), IpAddr::from(Ipv4Addr::LOCALHOST));

        let record = NodeRecord::decode(&ethrex_common::base64::decode(
            handle
                .local_enr
                .strip_prefix("enr:")
                .expect("enr: prefix")
                .as_bytes(),
        ))
        .expect("local ENR decodes");
        assert_eq!(record.pairs().ip, Some(advertised));
    }

    #[tokio::test]
    async fn spawn_fails_loudly_on_a_busy_port() {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let busy = socket.local_addr().unwrap().port();

        let result = spawn_discovery(DiscoverySpawnConfig {
            node_key: secp256k1::SecretKey::new(&mut rand::rngs::OsRng),
            bind_ip: IpAddr::from(Ipv4Addr::LOCALHOST),
            discovery_port: busy,
            quic_port: 9001,
            subscription_subnets: HashSet::new(),
            attestation_committee_count: 4,
            bootnodes: Vec::new(),
            advertise_ip: None,
        })
        .await;

        assert!(result.is_err(), "a busy discovery port must not be silent");
    }
}
