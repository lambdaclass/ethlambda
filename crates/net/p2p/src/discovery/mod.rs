//! discv5 peer discovery, built on ethrex's discovery stack.
//!
//! ethrex's `DiscoveryServer` runs discv5-only on its own UDP socket and writes
//! what it finds into an ethrex `PeerTable`. ethlambda's `P2PServer` polls that
//! table, applies the spec checks in [`admission`], and dials the survivors over
//! libp2p QUIC. Static bootnode dialing is untouched.
//!
//! See `docs/discovery.md` for the operator-facing description.

pub mod admission;
pub(crate) mod dial;
pub mod enr;

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ethrex_p2p::discovery::{DiscoveryConfig, DiscoveryServer};
use ethrex_p2p::peer_table::{PeerTable, PeerTableServer};
use ethrex_p2p::types::Node;
use tokio::net::UdpSocket;
use tracing::{info, warn};

use crate::Bootnode;
use admission::LeanFilter;
use enr::{EnrForkId, LocalEnrParams, build_local_enr};

/// How often the dial loop looks for a new peer.
pub const DISCOVERY_DIAL_INTERVAL: Duration = Duration::from_secs(5);

/// Default connected-peer count above which the dial loop stops dialing.
/// Overridable per node via [`DiscoverySpawnConfig::target_peers`].
pub const DEFAULT_DISCOVERY_TARGET_PEERS: usize = 200;

/// The target we hand ethrex's peer table, which is not
/// [`DiscoverySpawnConfig::target_peers`] and deliberately so.
///
/// ethrex's table counts only peers registered through `NewConnectedPeer`, which
/// carries an RLPx `PeerConnection`. ethlambda connects over libp2p and never
/// registers anything, so `peers.len()` is permanently 0 and the table's target
/// cannot mean "how many peers we have". Its one live consumer here is the discv5
/// lookup pacing, which divides by it: passing 0 would yield `0/0 = NaN`, and
/// `NaN as u64` saturates to zero, turning the lookup timer into an unthrottled
/// re-fire loop. Any non-zero value gives the same pacing, so this is 1 with the
/// reason attached rather than a number pretending to be a peer budget.
const PEER_TABLE_TARGET_PEERS: usize = 1;

/// Candidates drawn from the peer table per refill.
pub const DISCOVERY_CANDIDATE_BATCH: usize = 8;

/// Why discovery could not be started. Every variant is fatal at startup.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    #[error("failed to bind discovery socket on {addr}: {source}")]
    BindSocket {
        addr: SocketAddr,
        source: std::io::Error,
    },
    #[error("failed to read discovery socket address: {0}")]
    SocketAddr(std::io::Error),
    #[error("failed to build local ENR: {0}")]
    BuildEnr(ethrex_p2p::types::NodeError),
    #[error("failed to encode local ENR: {0}")]
    EncodeEnr(ethrex_p2p::types::NodeError),
    #[error("failed to start discovery server: {0}")]
    Server(String),
    #[error("node key is not a valid secp256k1 secret key: {0}")]
    NodeKey(secp256k1::Error),
}

pub struct DiscoverySpawnConfig {
    /// Raw 32-byte secp256k1 secret key, the same bytes `SwarmConfig::node_key`
    /// takes, so the binary never needs to name a crypto type.
    pub node_key: Vec<u8>,
    pub bind_ip: IpAddr,
    pub discovery_port: u16,
    pub quic_port: u16,
    pub subscription_subnets: HashSet<u64>,
    pub attestation_committee_count: u64,
    pub bootnodes: Vec<Bootnode>,
    /// IP address to advertise in the ENR. Defaults to `bind_ip` when unset,
    /// which is undialable if `bind_ip` is the wildcard `0.0.0.0`.
    pub advertise_ip: Option<IpAddr>,
    /// Connected-peer count above which the dial loop stops dialing. Defaults to
    /// [`DEFAULT_DISCOVERY_TARGET_PEERS`]; a target of 0 leaves the dial loop
    /// ticking without ever dialing.
    ///
    /// Governs the dial loop only. ethrex's peer table is handed a fixed value
    /// instead, because it counts only peers registered over RLPx and so can
    /// never see ours; see `PEER_TABLE_TARGET_PEERS`.
    pub target_peers: usize,
}

/// What the P2P actor needs from a running discovery server.
pub struct DiscoveryHandle {
    pub peer_table: PeerTable,
    /// This node's ENR as an `enr:`-prefixed string. `spawn_discovery` already
    /// logs it; this copy is what the tests assert the published record against,
    /// and what a future RPC identity endpoint would read. Reflects startup
    /// state; discv5 may bump the sequence number later if PONG voting changes
    /// our external IP.
    pub local_enr: String,
    /// The admission policy the peer table judges records with, kept so the dial
    /// loop can apply the same rules when it turns a contact into a dial target.
    /// See [`LeanFilter`].
    pub filter: LeanFilter,
    /// The configured [`DiscoverySpawnConfig::target_peers`], carried through to
    /// the dial loop, which is the only thing it governs.
    pub target_peers: usize,
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
pub async fn spawn_discovery(
    config: DiscoverySpawnConfig,
) -> Result<DiscoveryHandle, DiscoveryError> {
    let signer =
        secp256k1::SecretKey::from_slice(&config.node_key).map_err(DiscoveryError::NodeKey)?;

    let bind_addr = SocketAddr::new(config.bind_ip, config.discovery_port);
    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(|source| DiscoveryError::BindSocket {
            addr: bind_addr,
            source,
        })?;
    let bound = socket.local_addr().map_err(DiscoveryError::SocketAddr)?;

    let advertise_ip = config.advertise_ip.unwrap_or(config.bind_ip);
    let params = LocalEnrParams {
        signer,
        ip: advertise_ip,
        discovery_port: bound.port(),
        quic_port: config.quic_port,
        subscription_subnets: config.subscription_subnets,
        attestation_committee_count: config.attestation_committee_count,
    };
    let local_node = params.local_node();
    let local_record = build_local_enr(&params)?;
    let local_enr = local_record.enr_url().map_err(DiscoveryError::EncodeEnr)?;

    // `spawn` rather than `spawn_with_filter` would install ethrex's own filter,
    // which wants an EIP-2124 `eth` entry compatible with an execution chain lean
    // does not have and rejects any record without one, so every lean contact
    // would be stamped rejected and never dialed.
    //
    // The peer table owns the filter it runs, so the dial loop keeps a clone
    // rather than sharing one: the two carry the same fork id and committee
    // count, which is what makes their judgments agree.
    let filter = LeanFilter::new(EnrForkId::local(), config.attestation_committee_count);
    let peer_table = PeerTableServer::spawn_with_filter(
        local_node.node_id(),
        PEER_TABLE_TARGET_PEERS,
        filter.clone(),
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

    // The record we hand over is the same one `enr_url` above reported, so what
    // ethrex answers discv5 queries with carries the consensus entries (`eth2`,
    // `attnets`, `quic`) and a lean peer applying our own admission rules to it
    // admits us. ethrex re-signs it under `params.signer` whenever IP voting
    // bumps the sequence number, keeping the extra entries.
    DiscoveryServer::spawn(
        local_node,
        local_record,
        params.signer,
        Arc::new(socket),
        peer_table.clone(),
        seeds,
        DiscoveryConfig {
            discv4_enabled: false,
            discv5_enabled: true,
        },
    )
    .await
    .map_err(|err| DiscoveryError::Server(err.to_string()))?;

    info!(enr = %local_enr, "Local ENR");
    if advertise_ip.is_unspecified() {
        warn!(
            "Local ENR advertises an unspecified IP; peers can still reach us once \
             discv5 IP voting resolves our external address, but this ENR is not \
             directly dialable as published. Set --discovery.advertise-ip to the \
             address peers should reach this node on"
        );
    }

    Ok(DiscoveryHandle {
        peer_table,
        local_enr,
        filter,
        target_peers: config.target_peers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethrex_p2p::peer_filter::PeerFilter;
    use ethrex_p2p::types::NodeRecord;
    use ethrex_rlp::decode::RLPDecode;
    use std::net::Ipv4Addr;

    fn config(discovery_port: u16, advertise_ip: Option<IpAddr>) -> DiscoverySpawnConfig {
        DiscoverySpawnConfig {
            node_key: secp256k1::SecretKey::new(&mut rand::rngs::OsRng)
                .secret_bytes()
                .to_vec(),
            bind_ip: IpAddr::from(Ipv4Addr::LOCALHOST),
            discovery_port,
            quic_port: 9001,
            subscription_subnets: HashSet::from([0u64]),
            attestation_committee_count: 4,
            bootnodes: Vec::new(),
            advertise_ip,
            target_peers: DEFAULT_DISCOVERY_TARGET_PEERS,
        }
    }

    fn decode_enr(local_enr: &str) -> NodeRecord {
        NodeRecord::decode(&ethrex_common::base64::decode(
            local_enr
                .strip_prefix("enr:")
                .expect("enr: prefix")
                .as_bytes(),
        ))
        .expect("local ENR decodes")
    }

    #[tokio::test]
    async fn spawn_binds_the_socket_and_returns_the_local_enr() {
        // Port 0 asks the OS for a free port, so the test cannot collide with a
        // running node or a sibling test.
        let handle = spawn_discovery(config(0, None))
            .await
            .expect("discovery spawns");

        assert!(handle.local_enr.starts_with("enr:"));
        let record = decode_enr(&handle.local_enr);

        // With discovery_port: 0 the OS picks the real port, and the published
        // ENR must advertise that one: were it built from the requested 0
        // instead of the bound port, the record would name an undialable node.
        let advertised_port = record.pairs().udp_port.expect("udp entry");
        assert_ne!(advertised_port, 0);

        // The policy handed to the peer table must admit our own record. A peer
        // running this code applies exactly these rules to what we publish, so a
        // record we would reject ourselves is one nobody dials.
        assert!(handle.filter.accepts(&record));
    }

    #[tokio::test]
    async fn spawn_advertises_a_different_ip_than_it_binds() {
        // Bind the loopback address but advertise a distinct, non-dialable-from-
        // here address, mimicking an operator setting `--discovery.advertise-ip`
        // to their host's public IP while still binding the wildcard/loopback
        // locally. The ENR must reflect the advertised address, not the bind
        // address.
        let advertised = Ipv4Addr::new(203, 0, 113, 7);
        let handle = spawn_discovery(config(0, Some(IpAddr::from(advertised))))
            .await
            .expect("discovery spawns");

        assert_eq!(decode_enr(&handle.local_enr).pairs().ip, Some(advertised));
    }

    #[tokio::test]
    async fn spawn_fails_loudly_on_a_busy_port() {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let busy = socket.local_addr().unwrap().port();

        let result = spawn_discovery(config(busy, None)).await;

        assert!(result.is_err(), "a busy discovery port must not be silent");
    }
}
