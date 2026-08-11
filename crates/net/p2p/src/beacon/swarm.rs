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
use ethlambda_types::beacon::primitives::ForkDigest;
use libp2p::identity::secp256k1;
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, request_response};
use tracing::{debug, info};

use super::{BeaconWire, protocols, topics::BeaconTopics};
use crate::{Behaviour, Bootnode, BuiltSwarm, PeerId, Wire, gossipsub_config};

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
    /// Parsed from the built-in list or from `--bootnodes`. Kept only so a
    /// record that does advertise `quic` can still be dialed statically; none
    /// of the published mainnet records does.
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

    let req_resp = request_response::Behaviour::new(protocols::registrations(), Default::default());

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
        .with_quic()
        .with_behaviour(|_| Behaviour::new(identify, gossipsub, req_resp))
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
        let Some(quic_port) = bootnode.quic_port else {
            debug!(%peer_id, ip = %bootnode.ip, "Bootnode advertises no quic port, discv5 seed only");
            continue;
        };
        let addr = Multiaddr::empty()
            .with(bootnode.ip.into())
            .with(Protocol::Udp(quic_port))
            .with(Protocol::QuicV1)
            .with_p2p(peer_id)
            .expect("failed to add peer ID to multiaddr");
        bootnode_addrs.insert(peer_id, addr.clone());
        swarm.dial(addr).expect("failed to dial bootnode");
    }

    let listen_addr = Multiaddr::empty()
        .with(config.listening_socket.ip().into())
        .with(Protocol::Udp(config.listening_socket.port()))
        .with(Protocol::QuicV1);
    swarm
        .listen_on(listen_addr)
        .expect("failed to bind gossipsub listening address");

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
    async fn a_beacon_swarm_subscribes_to_seven_topics_and_dials_nothing() {
        // Port 0 asks the OS for a free port, so this cannot collide with a
        // running node or a sibling test.
        let built = build_beacon_swarm(BeaconSwarmConfig {
            node_key: vec![1u8; 32],
            listening_socket: "127.0.0.1:0".parse().expect("valid socket"),
            fork_digest: [0x8c, 0x9f, 0x62, 0xfe],
            config: Config::mainnet(),
            genesis_time: 1_606_824_023,
            bootnodes: crate::parse_enrs(
                super::super::bootnodes::MAINNET_BOOTNODES
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>(),
            ),
        })
        .expect("swarm builds");

        let wire = built.wire.beacon().expect("a beacon wire");
        assert_eq!(wire.topics.topics.len(), 7);
        assert_eq!(wire.fork_digest, [0x8c, 0x9f, 0x62, 0xfe]);
        assert!(
            built.bootnode_addrs.is_empty(),
            "no published mainnet bootnode advertises quic, so none is dialed"
        );
    }
}
