//! Building the swarm `ethlambda beacon` runs on.
//!
//! Everything except the topic set, the protocol set, the `seen_ttl` and the
//! identify protocol version is shared with lean, because those are the only
//! four things the two networks disagree about at the swarm level.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::preset;
use ethlambda_types::beacon::primitives::{ForkDigest, Root};
use libp2p::identity::secp256k1;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::{Multiaddr, request_response};
use tracing::{debug, info};

use super::{BeaconWire, protocols, topics::BeaconTopics};
use crate::{Behaviour, Bootnode, BuiltSwarm, PeerId, Wire, bootnode_dial_addrs, gossipsub_config};

/// How long gossipsub remembers a message id, so a duplicate arriving late is
/// dropped rather than re-forwarded.
///
/// The beacon p2p interface states this as
/// `SLOTS_PER_EPOCH * SECONDS_PER_SLOT * 2`, which is what is written here
/// rather than the number it evaluates to, so it stays correct if either factor
/// moves.
pub fn seen_ttl(config: &Config) -> Duration {
    Duration::from_secs(preset::SLOTS_PER_EPOCH * config.seconds_per_slot * 2)
}

pub struct BeaconSwarmConfig {
    pub node_key: Vec<u8>,
    pub listening_socket: SocketAddr,
    pub fork_digest: ForkDigest,
    pub config: Config,
    pub genesis_time: u64,
    /// Needed by the req/resp codec, which labels each block chunk it writes
    /// with the fork digest of that block's own fork.
    pub genesis_validators_root: Root,
    /// Parsed from the built-in list or from `--bootnodes`. Every published
    /// mainnet record advertises `tcp` (none advertises `quic`), which is
    /// what makes them statically dialable now that the swarm speaks TCP.
    pub bootnodes: Vec<Bootnode>,
}

/// Build the beacon swarm, subscribe to the seven topics, and dial any bootnode
/// that advertises a QUIC port.
pub fn build_beacon_swarm(
    config: BeaconSwarmConfig,
) -> Result<BuiltSwarm, libp2p::gossipsub::SubscriptionError> {
    let gossipsub = libp2p::gossipsub::Behaviour::new(
        libp2p::gossipsub::MessageAuthenticity::Anonymous,
        gossipsub_config(seen_ttl(&config.config)),
    )
    .expect("failed to initiate behaviour");

    // The codec carries the fork schedule and the genesis validators root: a
    // `beacon_blocks_by_*/2` chunk is fork-typed, so decoding one needs the
    // same schedule the digest was computed from, and writing one needs to
    // recompute the digest of the fork each block belongs to.
    let req_resp = request_response::Behaviour::with_codec(
        crate::req_resp::Codec::beacon(config.config.clone(), config.genesis_validators_root),
        protocols::registrations(),
        Default::default(),
    );

    let secret_key =
        secp256k1::SecretKey::try_from_bytes(config.node_key).expect("invalid node key");
    let identity = libp2p::identity::Keypair::from(secp256k1::Keypair::from(secret_key));

    // Lighthouse's identify protocol version. go-libp2p peers gate gossipsub
    // GRAFT on the identify exchange completing, so a peer that does not answer
    // is silently excluded from the mesh.
    let identify = libp2p::identify::Behaviour::new(libp2p::identify::Config::new(
        "eth2/1.0.0".to_owned(),
        identity.public(),
    ));

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default().nodelay(true),
            libp2p::noise::Config::new,
            // mplex is not decoration here: mainnet beacon peers answer `na` to
            // a yamux-only proposal. See `crate::muxers` for the measurement.
            #[allow(deprecated)]
            (
                libp2p::yamux::Config::default,
                libp2p_mplex::MplexConfig::default,
            ),
        )
        .expect("failed to add TCP transport to swarm")
        .with_quic()
        .with_behaviour(|_| {
            Behaviour::new(
                identify,
                gossipsub,
                req_resp,
                crate::beacon_connection_limits(),
            )
        })
        .expect("failed to add behaviour to swarm")
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(u64::MAX)))
        .build();

    let local_peer_id = *swarm.local_peer_id();
    let mut bootnode_addrs = HashMap::new();
    for bootnode in config.bootnodes {
        let peer_id = PeerId::from_public_key(&bootnode.public_key);
        if peer_id == local_peer_id {
            continue;
        }
        let addrs = bootnode_dial_addrs(&bootnode, peer_id);
        if addrs.is_empty() {
            // Discovery-only seed: reachable over discv5, but with no QUIC or
            // TCP port there is nothing for the swarm to dial.
            debug!(%peer_id, ip = %bootnode.ip, "Bootnode advertises no dialable transport, discv5 seed only");
            continue;
        }
        bootnode_addrs.insert(peer_id, addrs.clone());
        swarm
            .dial(DialOpts::peer_id(peer_id).addresses(addrs).build())
            .expect("failed to dial bootnode");
    }

    let quic_listen_addr = Multiaddr::empty()
        .with(config.listening_socket.ip().into())
        .with(Protocol::Udp(config.listening_socket.port()))
        .with(Protocol::QuicV1);
    swarm
        .listen_on(quic_listen_addr)
        .expect("failed to bind gossipsub QUIC listening address");
    // Same port number as the QUIC listener above: TCP and UDP are separate
    // namespaces, so this cannot collide with it.
    let tcp_listen_addr = Multiaddr::empty()
        .with(config.listening_socket.ip().into())
        .with(Protocol::Tcp(config.listening_socket.port()));
    swarm
        .listen_on(tcp_listen_addr)
        .expect("failed to bind gossipsub TCP listening address");

    let beacon_topics = BeaconTopics::new(config.fork_digest);
    for topic in &beacon_topics.topics {
        swarm.behaviour_mut().gossipsub.subscribe(topic)?;
        info!(topic = %topic, "Subscribed to beacon topic");
    }

    info!(
        socket = %config.listening_socket,
        fork_digest = %hex::encode(config.fork_digest),
        topics = beacon_topics.topics.len(),
        "Beacon P2P node started"
    );

    Ok(BuiltSwarm {
        local_peer_id,
        swarm,
        wire: Wire::Beacon(Box::new(BeaconWire {
            fork_digest: config.fork_digest,
            topics: beacon_topics,
            config: config.config,
            genesis_time: config.genesis_time,
            metadata_seq_number: 0,
        })),
        bootnode_addrs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_seen_ttl_is_two_epochs() {
        // The design doc's parenthetical says 385s, which does not match its own
        // formula: 32 * 12 * 2 is 768. The formula is the one the beacon p2p
        // interface states, so it wins, and writing it out keeps it honest if
        // either factor ever moves.
        assert_eq!(seen_ttl(&Config::mainnet()), Duration::from_secs(768));
    }

    #[tokio::test]
    async fn a_beacon_swarm_subscribes_to_seven_topics_and_dials_bootnodes_over_tcp() {
        // Port 0 asks the OS for a free port, so this cannot collide with a
        // running node or a sibling test.
        let mainnet_bootnodes = crate::parse_enrs(
            super::super::bootnodes::MAINNET_BOOTNODES
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
        );
        // Checked directly against the list (see `beacon::bootnodes`'s own
        // test): Teku's two and Nimbus's two advertise `tcp`; the other
        // thirteen advertise neither transport and stay seed-only.
        let tcp_dialable_count = mainnet_bootnodes
            .iter()
            .filter(|b| b.tcp_port.is_some())
            .count();
        let built = build_beacon_swarm(BeaconSwarmConfig {
            node_key: vec![1u8; 32],
            listening_socket: "127.0.0.1:0".parse().expect("valid socket"),
            fork_digest: [0x8c, 0x9f, 0x62, 0xfe],
            config: Config::mainnet(),
            genesis_time: 1_606_824_023,
            genesis_validators_root: Root::zero(),
            bootnodes: mainnet_bootnodes,
        })
        .expect("swarm builds");

        let wire = built.wire.beacon().expect("a beacon wire");
        assert_eq!(wire.topics.topics.len(), 7);
        assert_eq!(wire.fork_digest, [0x8c, 0x9f, 0x62, 0xfe]);
        // No published mainnet bootnode advertises `quic`, but the ones that
        // advertise `tcp` are now dialable, which is the point of adding the
        // transport; the rest are still seed-only, exactly as before.
        assert_eq!(built.bootnode_addrs.len(), tcp_dialable_count);
        for addrs in built.bootnode_addrs.values() {
            assert_eq!(
                addrs.len(),
                1,
                "a quic-less bootnode dial list must carry exactly its tcp address"
            );
            assert!(addrs[0].to_string().contains("/tcp/"));
        }
    }
}
