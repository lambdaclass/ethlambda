//! The beacon half of the swarm configuration.
//!
//! Five things differ from lean at the swarm level: the topic set, the protocol
//! set, the `seen_ttl`, the identify protocol version and the connection limits.
//! [`crate::build_swarm`] resolves all five from the variant it is handed, and
//! every one of them that is a beacon *value* rather than a lean one lives here,
//! so tuning the mainnet numbers never means editing the crate root.

use std::time::Duration;

use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::preset;
use ethlambda_types::beacon::primitives::ForkDigest;

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

/// Lighthouse's identify protocol version. go-libp2p peers gate gossipsub GRAFT
/// on the identify exchange completing, so a peer that does not answer is
/// silently excluded from the mesh.
pub const IDENTIFY_PROTOCOL_VERSION: &str = "eth2/1.0.0";

/// Ceiling on connections the beacon swarm keeps established at once.
///
/// Mainnet dials us far faster than we dial it: a 22-hour run accepted 12,521
/// inbound connections against 235 successful outbound dials, and settled at
/// 371 held peers. Every one of them feeds the same gossip decode path, which
/// competes with block import for the single core that decides how fast the
/// head advances. Left uncapped the peer count is set by how popular we are,
/// not by what we can afford, so it is bounded here by policy.
pub const MAX_CONNECTIONS: u32 = 200;

/// How many of [`MAX_CONNECTIONS`] stay reserved for connections we
/// open ourselves.
///
/// Without a reservation, inbound demand takes every slot and discovery can
/// never dial a peer of its own choosing. That is the eclipse-adjacent case
/// libp2p's own documentation warns about for a total-only limit, and it also
/// costs us the ability to seek out peers that serve the ranges we need.
pub const MAX_OUTBOUND_CONNECTIONS: u32 = 20;

/// Connections a single peer may hold. Two rather than one because the swarm
/// listens on both QUIC and TCP, so a remote is free to establish over each.
pub const MAX_CONNECTIONS_PER_PEER: u32 = 2;

// The inbound allowance below is the ceiling minus the outbound reservation, so
// a reservation at or above the ceiling underflows. Release builds wrap that to
// roughly four billion and silently remove the cap, which is exactly the
// regression a runtime test would be least likely to catch, so it is refused at
// compile time instead.
const _: () = assert!(
    MAX_OUTBOUND_CONNECTIONS < MAX_CONNECTIONS,
    "the outbound reservation has to fit inside the connection ceiling"
);

/// Connection limits for the beacon network, where inbound supply is
/// effectively unbounded. See [`MAX_CONNECTIONS`].
pub fn connection_limits() -> libp2p::connection_limits::Behaviour {
    let limits = libp2p::connection_limits::ConnectionLimits::default()
        .with_max_established(Some(MAX_CONNECTIONS))
        .with_max_established_incoming(Some(MAX_CONNECTIONS - MAX_OUTBOUND_CONNECTIONS))
        .with_max_established_outgoing(Some(MAX_OUTBOUND_CONNECTIONS))
        .with_max_established_per_peer(Some(MAX_CONNECTIONS_PER_PEER));
    libp2p::connection_limits::Behaviour::new(limits)
}

/// The beacon wire's swarm parameters: what [`crate::WireConfig::Beacon`]
/// carries and lean has no equivalent of.
///
/// `config` and `genesis_time` outlive startup on [`crate::beacon::BeaconWire`],
/// because the fork a gossip payload decodes under is derived from its slot and
/// that derivation must use the schedule the fork digest was computed from.
pub struct BeaconWireConfig {
    pub fork_digest: ForkDigest,
    pub config: Config,
    pub genesis_time: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real mainnet bootnode ENRs, two `tcp`-dialable and two seed-only.
    ///
    /// A fixture, not the shipped list: `beacon::MAINNET_BOOTNODES` moved to
    /// the binary, and what these tests need from it is the shape of a mixed
    /// dial set, not its current membership.
    const BOOTNODE_FIXTURE: [&str; 4] = [
        // Teku, 3.147.37.0 | aws-us-east-2-ohio: ip/tcp/udp.
        "enr:-Iu4QLm7bZGdAt9NSeJG0cEnJohWcQTQaI9wFLu3Q7eHIDfrI4cwtzvEW3F3VbG9XdFXlrHyFGeXPn9snTCQJ9bnMRABgmlkgnY0gmlwhAOTJQCJc2VjcDI1NmsxoQIZdZD6tDYpkpEfVo5bgiU8MGRjhcOmHGD2nErK0UKRrIN0Y3CCIyiDdWRwgiMo",
        // Teku, 3.107.124.68 | aws-ap-southeast-2-sydney: ip/tcp/udp.
        "enr:-Iu4QEDJ4Wa_UQNbK8Ay1hFEkXvd8psolVK6OhfTL9irqz3nbXxxWyKwEplPfkju4zduVQj6mMhUCm9R2Lc4YM5jPcIBgmlkgnY0gmlwhANrfESJc2VjcDI1NmsxoQJCYz2-nsqFpeEj6eov9HSi9QssIVIVNr0I89J1vXM9foN0Y3CCIyiDdWRwgiMo",
        // Prylab, 18.223.219.100 | aws-us-east-2-ohio: udp only.
        "enr:-Ku4QImhMc1z8yCiNJ1TyUxdcfNucje3BGwEHzodEZUan8PherEo4sF7pPHPSIB1NNuSg5fZy7qFsjmUKs2ea1Whi0EBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQOVphkDqal4QzPMksc5wnpuC3gvSC8AfbFOnZY_On34wIN1ZHCCIyg",
        // Prylab, 18.223.219.100 | aws-us-east-2-ohio: udp only.
        "enr:-Ku4QP2xDnEtUXIjzJ_DhlCRN9SN99RYQPJL92TMlSv7U5C1YnYLjwOQHgZIUXw6c-BvRg2Yc2QsZxxoS_pPRVe0yK8Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQMeFF5GrS7UZpAH2Ly84aLK-TyvH-dRo0JM1i8yygH50YN1ZHCCJxA",
    ];

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
        // Four real mainnet bootnode ENRs rather than the whole published
        // list, which now lives in the binary's `beacon` module: the subject
        // here is `build_swarm`'s dial set, and what that needs is a mix of
        // records it can and cannot dial. The first two are Teku's, which
        // advertise `tcp`; the last two are Prylab's, which advertise only
        // `udp` and so stay discv5-seed-only. None advertises `quic`, which is
        // true of every published mainnet bootnode.
        let mainnet_bootnodes =
            crate::parse_enrs(BOOTNODE_FIXTURE.iter().map(|s| s.to_string()).collect());
        assert_eq!(mainnet_bootnodes.len(), BOOTNODE_FIXTURE.len());
        let tcp_dialable_count = mainnet_bootnodes
            .iter()
            .filter(|b| b.tcp_port.is_some())
            .count();
        assert_eq!(tcp_dialable_count, 2, "the fixture's premise changed");
        let built = crate::build_swarm(crate::SwarmConfig {
            node_key: vec![1u8; 32],
            listening_socket: "127.0.0.1:0".parse().expect("valid socket"),
            bootnodes: mainnet_bootnodes,
            wire: crate::WireConfig::Beacon(Box::new(BeaconWireConfig {
                fork_digest: [0x8c, 0x9f, 0x62, 0xfe],
                config: Config::mainnet(),
                genesis_time: 1_606_824_023,
            })),
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
