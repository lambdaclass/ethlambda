//! discv5 peer discovery, built on ethrex's discovery stack.
//!
//! ethrex's `DiscoveryServer` runs discv5-only on its own UDP socket and keeps
//! what it finds to itself. ethlambda asks it for dial candidates, applies the
//! spec checks in [`admission`] as each ENR arrives, and dials the survivors
//! over libp2p QUIC. Static bootnode dialing is untouched.
//!
//! The traffic across that boundary runs one way, into discovery: a request for
//! the next candidate, and a cast per connection opened or closed. Those casts
//! are what let discovery pace its own lookups, since a libp2p connection is
//! otherwise invisible to it.
//!
//! See `docs/discovery.md` for the operator-facing description.

pub mod admission;
pub(crate) mod dial;
pub mod enr;
pub(crate) mod node_id;

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use ethrex_p2p::discovery::{DiscoveryConfig, DiscoveryHandle, DiscoveryServer};
use ethrex_p2p::types::{LocalNode, Node};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::Bootnode;
use admission::{DialTargets, LeanFilter};
use enr::{EnrForkId, LocalEnrParams, build_local_enr};

/// How often the dial loop looks for a new peer.
pub const DISCOVERY_DIAL_INTERVAL: Duration = Duration::from_secs(5);

/// Default connected-peer count above which the dial loop stops dialing.
/// Overridable per node via [`DiscoverySpawnConfig::target_peers`].
pub const DEFAULT_DISCOVERY_TARGET_PEERS: usize = 200;

/// Candidates drawn from discovery per refill.
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
    /// The same number governs how hard discovery looks: it eases its lookups
    /// off the startup rate as our connected count approaches this, which it can
    /// only do because we report those connections to it.
    pub target_peers: usize,
}

/// What the P2P actor needs from a running discovery server.
pub struct SpawnedDiscovery {
    /// The running server. Three things travel over it: a request for the next
    /// dial candidate, and a report for each connection opened and closed.
    pub handle: DiscoveryHandle,
    /// How to dial the peers the filter admitted; see [`DialTargets`].
    pub(crate) dial_targets: DialTargets,
    /// This node's ENR as an `enr:`-prefixed string. `spawn_discovery` already
    /// logs it; this copy is what the tests assert the published record against,
    /// and what a future RPC identity endpoint would read. Reflects startup
    /// state; discv5 may bump the sequence number later if PONG voting changes
    /// our external IP.
    pub local_enr: String,
    /// The configured [`DiscoverySpawnConfig::target_peers`], carried through to
    /// the dial loop's cutoff. Discovery is handed the same number separately,
    /// for its lookup pacing.
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
) -> Result<SpawnedDiscovery, DiscoveryError> {
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

    // Our own filter rather than ethrex's `EthForkIdFilter`, which wants an
    // EIP-2124 `eth` entry compatible with an execution chain lean does not have
    // and rejects any record without one, so every lean contact would be stamped
    // rejected and never dialed. `AcceptAllFilter` would go the other way and
    // hand us every node on the DHT.
    //
    // Discovery takes the filter by value, so what the dial loop keeps is the
    // map the filter writes into, not a second copy of the policy.
    let filter = LeanFilter::new(EnrForkId::local(), config.attestation_committee_count);
    let dial_targets = filter.dial_targets();

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
    //
    // `shared_local_node` is ethrex's live mirror of that identity, which its RPC
    // layer serves the current record from. Nothing on this side reads it yet, so
    // it is written and dropped; it costs one `Arc`.
    //
    // `fork_id` publishes an EIP-2124 fork id for discovery to stamp on the ENR
    // when the chain crosses a fork. Lean has no fork schedule and its digest
    // lives in `eth2`, not `eth`, so there is nothing to publish: the sender is
    // dropped straight away, which discovery reads as "the publisher is gone" and
    // stops checking.
    let (fork_id_tx, fork_id_rx) = watch::channel(None);
    drop(fork_id_tx);
    let shared_local_node = Arc::new(RwLock::new(LocalNode {
        node: local_node.clone(),
        record: local_record.clone(),
    }));

    let server = DiscoveryServer::spawn(
        local_node,
        local_record,
        params.signer,
        Arc::new(socket),
        Box::new(filter),
        seeds,
        DiscoveryConfig {
            discv4_enabled: false,
            discv5_enabled: true,
            // The real target, unlike the placeholder this replaces: discovery
            // divides our reported connection count by it to decide how hard to
            // keep looking. A target of 0 is answered as "complete" upstream, so
            // it no longer has to be worked around here.
            target_peers: config.target_peers,
            // `--discovery.advertise-ip` is this node's `--nat extip:`: an
            // operator naming the address peers should reach it on. Locking the
            // predictor keeps discv5's PONG voting from overwriting it, which is
            // the whole point of having said it.
            nat_extip_set: config.advertise_ip.is_some(),
        },
        shared_local_node,
        fork_id_rx,
    )
    .await
    .map_err(|err| DiscoveryError::Server(err.to_string()))?;

    // The handle exists to be published once and cloned everywhere, which is how
    // ethrex's own consumer starts discovery after the context that reaches it.
    // We have the running server in hand, so the publish is unconditional and its
    // "already set" answer cannot be anything but true.
    let discovery = DiscoveryHandle::new();
    discovery.set(server);

    info!(enr = %local_enr, "Local ENR");
    if advertise_ip.is_unspecified() {
        warn!(
            "Local ENR advertises an unspecified IP; peers can still reach us once \
             discv5 IP voting resolves our external address, but this ENR is not \
             directly dialable as published. Set --discovery.advertise-ip to the \
             address peers should reach this node on"
        );
    }

    Ok(SpawnedDiscovery {
        handle: discovery,
        dial_targets,
        local_enr,
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

    /// The committee count `config` below spawns with, named so the filter the
    /// self-admission test rebuilds cannot silently drift from it.
    const TEST_COMMITTEE_COUNT: u64 = 4;

    fn config(discovery_port: u16, advertise_ip: Option<IpAddr>) -> DiscoverySpawnConfig {
        DiscoverySpawnConfig {
            node_key: secp256k1::SecretKey::new(&mut rand::rngs::OsRng)
                .secret_bytes()
                .to_vec(),
            bind_ip: IpAddr::from(Ipv4Addr::LOCALHOST),
            discovery_port,
            quic_port: 9001,
            subscription_subnets: HashSet::from([0u64]),
            attestation_committee_count: TEST_COMMITTEE_COUNT,
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

        // The policy handed to discovery must admit our own record. A peer
        // running this code applies exactly these rules to what we publish, so a
        // record we would reject ourselves is one nobody dials. Rebuilt here
        // from the same two values `spawn_discovery` constructs it with, since
        // the filter itself was moved into the discovery server.
        let filter = LeanFilter::new(EnrForkId::local(), TEST_COMMITTEE_COUNT);
        assert!(filter.accepts(&record));
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
