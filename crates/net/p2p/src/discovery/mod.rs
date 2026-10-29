//! discv5 peer discovery, built on ethrex's discovery stack.
//!
//! ethrex's `DiscoveryServer` runs discv5-only on its own UDP socket and keeps
//! what it finds to itself. ethlambda asks it for dial candidates, applies the
//! spec checks in [`admission`] as each ENR arrives, and dials the survivors
//! over libp2p. Both dial paths, discovered peers and static bootnodes alike, hand
//! the swarm every address a peer advertises (`quic` and `tcp`) in one attempt
//! and let libp2p race them.
//!
//! The traffic across that boundary runs one way, into discovery: a request for
//! the next candidate, a cast per connection opened or closed, and the
//! [`subnets`] hunt's predicate queries. The casts are what let discovery pace
//! its own lookups, since a libp2p connection is otherwise invisible to it.
//!
//! This node's ENR lives in one lock-free slot that discovery serves from.
//! discv5's IP voting re-signs it when the address moves, [`LocalEnrWriter`]
//! re-signs it when a fork boundary moves the `eth2` entry, and [`LocalEnr`]
//! reads it for the Beacon API.
//!
//! See `docs/discovery.md` for the operator-facing description.

pub mod admission;
pub(crate) mod dial;
pub mod enr;
pub(crate) mod node_id;
pub(crate) mod subnets;

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ethrex_p2p::discovery::{DiscoveryConfig, DiscoveryHandle, DiscoveryServer};
use ethrex_p2p::types::{LocalNode, Node, SharedLocalNode};
use libssz::SszEncode;
use secp256k1::SecretKey;
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::Bootnode;
use admission::LeanFilter;
use enr::{ETH2_ENR_KEY, EnrForkId, LocalEnrParams, build_local_enr};

/// Dials per second the loop opens when this node has no peers at all.
///
/// A node short of peers is not idling, it is failing. Mainnet beacon nodes sit
/// at their inbound cap and answer `Goodbye(129)`, "too many peers", within a
/// millisecond of the handshake, so landing one with room is a numbers game:
/// measured on the eth-4 follower, 96% of outbound dials never establish. The
/// rate is set high enough that the 4% still arrives quickly, and it is a
/// *starting* rate, not a standing one — see [`DIAL_INTERVAL_AT_TARGET`].
pub const MAX_DIAL_RATE_PER_SECOND: u64 = 50;

/// The gap between dials at [`MAX_DIAL_RATE_PER_SECOND`], which is the floor
/// the pacing curve starts from.
pub const DIAL_INTERVAL_AT_ZERO_PEERS: Duration =
    Duration::from_micros(1_000_000 / MAX_DIAL_RATE_PER_SECOND);

/// The gap between dials as the peer count reaches its target.
///
/// ethrex's `LOOKUP_INTERVAL_MS` itself, which it uses as the ceiling for both
/// discv5 lookups and RLPx dialing, so the two layers slow down together. Its
/// floor is 100ms against this node's 20ms, but the ceiling is worth matching
/// exactly: it is reached while the table is nearly full and peers still churn,
/// and a slower one there means replacing losses at the rate they happen
/// instead of ahead of it. Read from upstream rather than copied, so "exactly"
/// survives a retune there.
///
/// This is not where dialing stops. [`dial::dial_budget`] returns 0 at target
/// and the loop opens nothing at all, so a fast ceiling costs nothing once the
/// table is genuinely full.
pub const DIAL_INTERVAL_AT_TARGET: Duration =
    Duration::from_micros((ethrex_p2p::discovery::LOOKUP_INTERVAL_MS * 1_000.0) as u64);

/// Default connected-peer count above which the dial loop stops dialing.
/// Overridable per node via [`DiscoverySpawnConfig::target_peers`].
pub const DEFAULT_DISCOVERY_TARGET_PEERS: usize = 200;

/// Admitted contacts [`dial::spawn_contact_poll`] keeps buffered ahead of the
/// dial loop, and so the most one refill can draw.
///
/// A bound rather than a batch size, because discovery marks every node tried
/// on the way out: this is how far ahead of the dialing its eligible set may be
/// drawn down. See [`dial::spawn_contact_poll`].
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
    /// Port the libp2p transports are bound to, advertised in the ENR as both
    /// `quic` (UDP) and `tcp`. One number for both: see
    /// [`LocalEnrParams::p2p_port`](enr::LocalEnrParams::p2p_port).
    pub p2p_port: u16,
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
    /// The `eth2` entry to publish and to compare discovered peers against.
    pub fork_id: EnrForkId,
    /// The `cgc` entry to publish, or `None` to omit it.
    pub custody_group_count: Option<u64>,
}

/// What the P2P actor needs from a running discovery server.
pub struct SpawnedDiscovery {
    /// The running server. Over it travel a request for the next dial
    /// candidate, a report for each connection opened and closed, and the
    /// subnet hunt's queries.
    pub handle: DiscoveryHandle,
    /// A clone of the admission policy discovery runs. Clones share their
    /// policy and their [`DialTargets`](admission::DialTargets), so this is
    /// both how a fork boundary moves what discovery admits and how the dial
    /// loop reads what discovery filed.
    pub(crate) filter: LeanFilter,
    /// The ENR discovery serves, read live; see [`LocalEnr`].
    pub local_enr: LocalEnr,
    /// The same record's write side, which a fork boundary republishes `eth2`
    /// through; see [`LocalEnrWriter`].
    pub(crate) local_enr_writer: LocalEnrWriter,
    /// The attestation subnets this node subscribes to, which its ENR's
    /// `attnets` advertises. What the subnet hunt keeps supplied with peers.
    pub(crate) subscription_subnets: HashSet<u64>,
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
/// Only bootnodes whose ENR advertises a `udp` port can seed discv5. That is a
/// separate question from whether `build_swarm` dials one statically, which
/// turns on its `quic`/`tcp` entries: a bootnode can do both, either, or
/// neither.
pub async fn spawn_discovery(
    config: DiscoverySpawnConfig,
) -> Result<SpawnedDiscovery, DiscoveryError> {
    let signer = SecretKey::from_slice(&config.node_key).map_err(DiscoveryError::NodeKey)?;

    let bind_addr = SocketAddr::new(config.bind_ip, config.discovery_port);
    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(|source| DiscoveryError::BindSocket {
            addr: bind_addr,
            source,
        })?;
    let bound = socket.local_addr().map_err(DiscoveryError::SocketAddr)?;

    let advertise_ip = config.advertise_ip.unwrap_or(config.bind_ip);
    let subscription_subnets = config.subscription_subnets.clone();
    let params = LocalEnrParams {
        signer,
        ip: advertise_ip,
        discovery_port: bound.port(),
        p2p_port: config.p2p_port,
        subscription_subnets: config.subscription_subnets,
        attestation_committee_count: config.attestation_committee_count,
        fork_id: config.fork_id,
        custody_group_count: config.custody_group_count,
    };
    let local_node = params.local_node();
    let local_record = build_local_enr(&params)?;
    // Encoded once up front so a record that cannot be is a startup error, not
    // an empty answer from the identity endpoint later. ethrex writes EIP-778's
    // unpadded base64, which lighthouse requires.
    let startup_enr = local_record.enr_url().map_err(DiscoveryError::EncodeEnr)?;

    // Our own filter rather than ethrex's `EthForkIdFilter`, which wants an
    // EIP-2124 `eth` entry compatible with an execution chain we do not judge
    // peers by, and rejects any record without one, so every lean contact would
    // be stamped rejected and never dialed. `AcceptAllFilter` would go the other
    // way and hand us every node on the DHT.
    //
    // Discovery takes the filter by value, so the dial loop keeps a clone: the
    // two share one policy and one map of filed dial targets.
    let filter = LeanFilter::new(config.fork_id, config.attestation_committee_count);

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
    // `attnets`, `quic`) and the `tcp` port of the fallback transport, and a
    // lean peer applying our own admission rules to it admits us. ethrex
    // re-signs it under `params.signer` whenever IP voting bumps the sequence
    // number, keeping the extra entries.
    //
    // `local_node` is the only copy of that identity: discovery serves from it
    // and swaps every re-signed record into it. [`LocalEnr`] and
    // [`LocalEnrWriter`] keep clones, so the identity endpoint reports the
    // record discv5 actually serves and a fork boundary edits that same record.
    //
    // `fork_id` publishes an EIP-2124 fork id for discovery to stamp on the ENR
    // when the chain crosses a fork. Neither chain here keys its peers on an
    // `eth` entry (both carry their digest in `eth2`), so there is nothing to
    // publish: the sender is dropped straight away, which discovery reads as
    // "the publisher is gone" and stops checking.
    let (fork_id_tx, fork_id_rx) = watch::channel(None);
    drop(fork_id_tx);
    let local_node = SharedLocalNode::new(LocalNode {
        node: local_node,
        record: local_record,
    });
    let local_enr = LocalEnr(local_node.clone());
    let local_enr_writer = LocalEnrWriter {
        local_node: local_node.clone(),
        signer: params.signer,
    };

    let server = DiscoveryServer::spawn(
        local_node,
        params.signer,
        Arc::new(socket),
        Box::new(filter.clone()),
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

    info!(enr = %startup_enr, "Local ENR");
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
        filter,
        local_enr,
        local_enr_writer,
        subscription_subnets,
        target_peers: config.target_peers,
    })
}

/// This node's ENR as discovery serves it right now.
///
/// discv5's IP voting re-signs the record at runtime with a new address and a
/// higher `seq`, and so does [`LocalEnrWriter`] at a fork boundary. Both swap
/// the result into the [`SharedLocalNode`] discovery serves from. Reading
/// through that, instead of keeping the string built at startup, is what keeps
/// the Beacon API's `/eth/v1/node/identity` reporting the record peers get over
/// discv5.
///
/// Read-only, and so safe to hand to the RPC server: editing takes the node
/// key, which only [`LocalEnrWriter`] holds.
#[derive(Clone)]
pub struct LocalEnr(SharedLocalNode);

impl LocalEnr {
    /// The served record as an `enr:` string, or `None` if it cannot be
    /// encoded.
    ///
    /// Encoding cannot fail for a record `spawn_discovery` already encoded,
    /// since the edits after it only replace entries it already carried.
    /// Takes no lock: [`SharedLocalNode::load`] is a snapshot.
    pub fn current(&self) -> Option<String> {
        self.0
            .load()
            .record
            .enr_url()
            .inspect_err(|err| warn!(%err, "Could not encode the local ENR"))
            .ok()
    }
}

/// The write side of [`LocalEnr`]: edits the record discovery serves.
///
/// Holds the node key every edit is re-signed with, which is why it is a
/// separate type that stays inside this crate rather than a method on
/// [`LocalEnr`] riding along into the RPC server.
pub(crate) struct LocalEnrWriter {
    local_node: SharedLocalNode,
    signer: SecretKey,
}

impl LocalEnrWriter {
    /// Serve `fork_id` as this node's `eth2` entry.
    ///
    /// Does nothing when the served record already carries it. Every edit bumps
    /// `seq`, and a bumped `seq` sends each peer that next sees our PING or PONG
    /// back for the whole record, so a call that changes nothing must not edit.
    ///
    /// Otherwise the record is re-signed once with `seq` one higher, and peers
    /// that discover this node after a fork boundary read the digest it is on
    /// now. Without this they would read the startup digest and reject the
    /// record, so a long-running node would grow harder to find with every
    /// boundary until it restarted.
    pub(crate) fn publish_fork_id(&self, fork_id: &EnrForkId) {
        let eth2 = fork_id.to_ssz();
        let served = self.local_node.load();
        let unchanged = served
            .record
            .pairs()
            .extra(ETH2_ENR_KEY)
            .is_some_and(|served| served.as_ref() == eth2.as_slice());
        if unchanged {
            return;
        }

        // The edit runs again on a newer record whenever IP voting swaps one in
        // first, so it must come out the same every time: it only replaces the
        // one entry, from bytes computed once above.
        let edited = self.local_node.edit_record(&self.signer, |pairs| {
            let stored = pairs.set_extra(ETH2_ENR_KEY, eth2.clone());
            debug_assert!(stored, "eth2 is outside the ENR dictionary");
        });
        let fork_digest = hex::encode(fork_id.fork_digest);
        let next_fork_epoch = fork_id.next_fork_epoch;
        match edited {
            Ok(local_node) => info!(
                %fork_digest,
                next_fork_epoch,
                enr_seq = local_node.record.seq,
                "Serving a new eth2 entry in the local ENR"
            ),
            Err(err) => warn!(
                %err,
                %fork_digest,
                next_fork_epoch,
                "Could not republish the local ENR's eth2 entry; peers keep reading the old one"
            ),
        }
    }

    /// The record discovery serves right now, for tests outside this module
    /// that hold a `DiscoveryState` rather than a [`LocalEnr`].
    #[cfg(test)]
    pub(crate) fn served_record(&self) -> ethrex_p2p::types::NodeRecord {
        self.local_node.load().record.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethrex_p2p::peer_filter::PeerFilter;
    use ethrex_p2p::types::NodeRecord;
    use ethrex_rlp::decode::RLPDecode;
    use libssz::SszDecode;
    use std::net::Ipv4Addr;

    fn config(discovery_port: u16, advertise_ip: Option<IpAddr>) -> DiscoverySpawnConfig {
        DiscoverySpawnConfig {
            node_key: secp256k1::SecretKey::new(&mut rand::rngs::OsRng)
                .secret_bytes()
                .to_vec(),
            bind_ip: IpAddr::from(Ipv4Addr::LOCALHOST),
            discovery_port,
            p2p_port: 9001,
            subscription_subnets: HashSet::from([0u64]),
            attestation_committee_count: 4,
            bootnodes: Vec::new(),
            advertise_ip,
            target_peers: DEFAULT_DISCOVERY_TARGET_PEERS,
            fork_id: EnrForkId::local(),
            custody_group_count: None,
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

        let local_enr = handle.local_enr.current().expect("the served ENR encodes");
        assert!(local_enr.starts_with("enr:"));
        // EIP-778's text form carries no base64 padding, and lighthouse
        // refuses a record that does.
        assert!(!local_enr.contains('='), "{local_enr}");
        let record = decode_enr(&local_enr);

        // With discovery_port: 0 the OS picks the real port, and the published
        // ENR must advertise that one: were it built from the requested 0
        // instead of the bound port, the record would name an undialable node.
        let advertised_port = record.pairs().udp_port.expect("udp entry");
        assert_ne!(advertised_port, 0);

        // The policy handed to discovery must admit our own record. A peer
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

        let local_enr = handle.local_enr.current().expect("the served ENR encodes");
        assert_eq!(decode_enr(&local_enr).pairs().ip, Some(advertised));
    }

    #[tokio::test]
    async fn a_new_fork_id_is_what_discovery_serves_next() {
        let handle = spawn_discovery(config(0, None))
            .await
            .expect("discovery spawns");
        let before = decode_enr(&handle.local_enr.current().expect("the served ENR encodes"));
        let next = EnrForkId {
            fork_digest: [0x8c, 0x9f, 0x62, 0xfe],
            next_fork_version: [0x06, 0x00, 0x00, 0x00],
            next_fork_epoch: enr::FAR_FUTURE_EPOCH,
        };

        handle.local_enr_writer.publish_fork_id(&next);

        let after = decode_enr(&handle.local_enr.current().expect("the served ENR encodes"));
        let eth2 = after.pairs().extra(ETH2_ENR_KEY).expect("eth2 entry");
        assert_eq!(EnrForkId::from_ssz_bytes(&eth2).unwrap(), next);
        // One edit, one bump: peers learn of the edit from the higher `seq` in
        // our next PING or PONG.
        assert_eq!(after.seq, before.seq + 1);
        assert!(after.verify_signature(), "re-signed with the node key");
        // Nothing else a peer judges us by moved.
        for key in [enr::ATTNETS_ENR_KEY, enr::QUIC_ENR_KEY] {
            assert_eq!(after.pairs().extra(key), before.pairs().extra(key));
        }
        assert_eq!(after.pairs().ip, before.pairs().ip);
        assert_eq!(after.pairs().udp_port, before.pairs().udp_port);
        // A peer already on the new digest admits the record.
        handle.filter.set_fork_id(next, Vec::new());
        assert!(handle.filter.accepts(&after));
    }

    #[tokio::test]
    async fn republishing_the_served_fork_id_leaves_the_record_alone() {
        let handle = spawn_discovery(config(0, None))
            .await
            .expect("discovery spawns");
        let before = handle.local_enr.current().expect("the served ENR encodes");

        // `config` publishes `EnrForkId::local()`, and `transition::apply`
        // offers the entry on every call, boundary or not.
        handle.local_enr_writer.publish_fork_id(&EnrForkId::local());

        let after = handle.local_enr.current().expect("the served ENR encodes");
        assert_eq!(
            after, before,
            "no edit, so no `seq` bump for peers to chase"
        );
    }

    #[tokio::test]
    async fn spawn_fails_loudly_on_a_busy_port() {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let busy = socket.local_addr().unwrap().port();

        let result = spawn_discovery(config(busy, None)).await;

        assert!(result.is_err(), "a busy discovery port must not be silent");
    }
}
