//! The beacon half of the swarm configuration.
//!
//! Five things differ from lean at the swarm level: the topic set, the protocol
//! set, the `seen_ttl`, the identify protocol version and the connection limits.
//! [`crate::build_swarm`] resolves all five from the variant it is handed, and
//! every one of them that is a beacon *value* rather than a lean one lives here,
//! so tuning the mainnet numbers never means editing the crate root.

use std::time::Duration;

use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::preset;
use ethlambda_types::beacon::primitives::{ForkDigest, Root};

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

/// The share of the peer target inbound demand is allowed to hold, as a
/// percentage.
///
/// The remainder is reserved for connections this node opens itself. Without a
/// reservation, inbound demand takes every slot and discovery can never dial a
/// peer of its own choosing: the eclipse-adjacent case libp2p's own
/// documentation warns about for a total-only limit, and the thing that costs
/// us the ability to seek out peers serving the columns we need.
///
/// 70 rather than the 90 a 20-slot reservation worked out to, measured on the
/// mainnet follower: it sat at 178 inbound peers and **zero** outbound ones for
/// two days, while every block waited minutes on custody columns no connected
/// peer held. A reservation only helps if the dial loop is still trying to fill
/// it, so the other half of that fix is in
/// [`crate::discovery::dial::dial_tick`], which now paces itself on the
/// outbound shortfall rather than the total peer count.
pub const MAX_INBOUND_CONNECTION_PERCENT: u32 = 70;

// A share at or above 100 leaves no outbound reservation at all. Exactly 100 is
// the case worth refusing by name: it derives a zero reservation, which every
// other line here then treats as "nothing to reserve" rather than as the
// misconfiguration it is. Zero is refused for the mirror-image reason: it would
// admit no inbound peer at all.
const _: () = assert!(
    MAX_INBOUND_CONNECTION_PERCENT > 0 && MAX_INBOUND_CONNECTION_PERCENT < 100,
    "the inbound share has to leave a non-empty outbound reservation"
);

/// Ceiling on connections the beacon swarm keeps established at once.
///
/// `--discovery.target-peers`, which is the whole of it: the number of peers
/// an operator asks for is the number this node keeps, so the dial loop's
/// cutoff and the swarm's own refusal are one number rather than two that can
/// disagree. A flat ceiling of its own is what let the outbound reservation
/// below be a fixed 60 slots no matter what the operator asked for, so a
/// target of 50 kept dialing to 60 outbound peers and a target of 0, meaning
/// "do not dial", still had a 60-peer shortfall to chase.
///
/// Bounded at all because mainnet dials us far faster than we dial it: a
/// 22-hour run accepted 12,521 inbound connections against 235 successful
/// outbound dials, and settled at 371 held peers. Every one of them feeds the
/// same gossip decode path, which competes with block import for the single
/// core that decides how fast the head advances. Left uncapped the peer count
/// is set by how popular we are, not by what we can afford.
///
/// Counts *connections*, while the target counts peers, and
/// [`MAX_CONNECTIONS_PER_PEER`] lets one peer hold two. A peer on both
/// transports therefore spends two of these, which is the pre-existing reason
/// this ceiling is a bound on the peer count and not an equality.
pub fn max_connections(target_peers: usize) -> u32 {
    u32::try_from(target_peers).unwrap_or(u32::MAX)
}

/// How much of [`max_connections`] inbound demand may hold.
///
/// Rounds down, which is the safe direction: inbound gets slightly less than
/// its nominal share rather than more, and the remainder falls to the
/// reservation. See [`MAX_INBOUND_CONNECTION_PERCENT`].
pub fn max_inbound_connections(target_peers: usize) -> u32 {
    // In `u64` so the share is exact rather than saturating: the product
    // overflows `u32` from a ceiling of about 61 million upward, and a
    // saturated product would silently stop being a percentage.
    let ceiling = u64::from(max_connections(target_peers));
    (ceiling * u64::from(MAX_INBOUND_CONNECTION_PERCENT) / 100) as u32
}

/// How much of [`max_connections`] stays reserved for connections we open
/// ourselves, which is also the shortfall the dial loop chases.
///
/// The remainder rather than its own percentage, so the two allowances add up
/// to the ceiling by construction at every target, including the ones where
/// the division above rounds.
pub fn max_outbound_connections(target_peers: usize) -> u32 {
    max_connections(target_peers) - max_inbound_connections(target_peers)
}

/// Connections a single peer may hold. Two rather than one because the swarm
/// listens on both QUIC and TCP, so a remote is free to establish over each.
pub const MAX_CONNECTIONS_PER_PEER: u32 = 2;

/// Outbound dials allowed in flight at once.
///
/// [`max_connections`] and its two halves bound only *established*
/// connections, and a dial that never establishes is never counted by them.
/// That gap did not matter while the loop dialed 1.6 times a second; at
/// [`crate::discovery::MAX_DIAL_RATE_PER_SECOND`] it does, because 96% of
/// outbound dials to mainnet never establish and the ones that fail by timing
/// out hold a socket for seconds first. Unbounded, the in-flight set is the
/// dial rate times however long the slowest peer takes to not answer.
///
/// Four seconds of dialing at full rate, which is far above what a healthy
/// node has outstanding and still a hard ceiling on the file descriptors this
/// can consume. Denials past it cost a candidate, so it is deliberately not
/// tight enough to be reached in normal operation.
pub const MAX_PENDING_OUTBOUND_CONNECTIONS: u32 =
    crate::discovery::MAX_DIAL_RATE_PER_SECOND as u32 * 4;

/// Connection limits for the beacon network, where inbound supply is
/// effectively unbounded. See [`max_connections`].
///
/// Derived from the same `target_peers` the dial loop reads, so what this node
/// refuses and what it goes looking for are two readings of one number. A
/// target of 0 therefore holds no peers rather than serving from a ceiling
/// nobody asked for.
pub fn connection_limits(target_peers: usize) -> libp2p::connection_limits::Behaviour {
    let limits = libp2p::connection_limits::ConnectionLimits::default()
        .with_max_established(Some(max_connections(target_peers)))
        .with_max_established_incoming(Some(max_inbound_connections(target_peers)))
        .with_max_established_outgoing(Some(max_outbound_connections(target_peers)))
        .with_max_established_per_peer(Some(MAX_CONNECTIONS_PER_PEER))
        .with_max_pending_outgoing(Some(MAX_PENDING_OUTBOUND_CONNECTIONS));
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
    /// The fork `fork_digest` was computed at. See
    /// [`BeaconWire::fork`](crate::beacon::BeaconWire).
    pub fork: ForkName,
    pub config: Config,
    pub genesis_time: u64,
    /// The chain the digests are bound to. See
    /// [`BeaconWire::genesis_validators_root`](crate::beacon::BeaconWire).
    pub genesis_validators_root: Root,
    /// The columns this node custodies, computed once at startup from the
    /// node id. Both the subnet subscription and the availability check read
    /// this, so the node cannot subscribe to one set and require another.
    pub custody_columns: Vec<u64>,
    /// The attestation subnets this node backbones, computed once at startup
    /// from the same node id.
    ///
    /// Carried rather than derived here for the reason `custody_columns` is:
    /// the ENR's `attnets` bits and the gossip subscription have to name one
    /// set, and a peer computes the same set from this node's id, so deriving
    /// it twice is how the two would come to disagree.
    pub attestation_subnets: Vec<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The numbers the default target has always produced, now derived from it
    /// rather than written down beside it.
    #[test]
    fn inbound_is_capped_at_its_share_and_the_rest_is_reserved() {
        assert_eq!(max_connections(200), 200);
        assert_eq!(max_inbound_connections(200), 140);
        assert_eq!(max_outbound_connections(200), 60);
    }

    /// The property the reservation rests on, at every target rather than at
    /// the default alone: inbound may never hold more than its configured
    /// share, and whatever the division rounds off falls to the reservation
    /// rather than going missing.
    #[test]
    fn the_two_allowances_add_up_and_rounding_favours_the_reservation() {
        // 7 and 13 are the interesting ones: neither is a multiple of 100, so
        // the share rounds, which is where an allowance could quietly grow.
        for target in [0usize, 1, 7, 13, 50, 199, 200, 1_000] {
            let inbound = max_inbound_connections(target);
            let outbound = max_outbound_connections(target);
            assert_eq!(
                inbound + outbound,
                max_connections(target),
                "the two allowances have to add up to the ceiling at target {target}"
            );
            assert!(
                u64::from(inbound) * 100
                    <= u64::from(max_connections(target))
                        * u64::from(MAX_INBOUND_CONNECTION_PERCENT),
                "inbound may never hold more than its configured share at target {target}"
            );
        }
    }

    /// `--discovery.target-peers 0` holds no peers at all, which is the whole
    /// of what the flag now means: the dial loop has a zero reservation to
    /// chase and the swarm refuses inbound demand it was never asked to carry.
    #[test]
    fn a_zero_target_reserves_nothing_and_admits_nothing() {
        assert_eq!(max_connections(0), 0);
        assert_eq!(max_inbound_connections(0), 0);
        assert_eq!(max_outbound_connections(0), 0);
    }

    /// Real mainnet bootnode ENRs, two `tcp`-dialable and two seed-only.
    ///
    /// A fixture, not the shipped list (that is the binary's
    /// `assets/mainnet/bootstrap_nodes.yaml`): what these tests need is the
    /// shape of a mixed dial set, not its current membership.
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
    async fn a_beacon_swarm_subscribes_to_its_custody_columns_and_dials_bootnodes_over_tcp() {
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
        // Two arbitrary columns, standing in for whatever a real node id would
        // select: `build_swarm` must subscribe exactly these, not the custody
        // count's-worth of *something*.
        let custody_columns = vec![3u64, 9];
        let built = crate::build_swarm(crate::SwarmConfig {
            node_key: vec![1u8; 32],
            listening_socket: "127.0.0.1:0".parse().expect("valid socket"),
            bootnodes: mainnet_bootnodes,
            target_peers: crate::discovery::DEFAULT_DISCOVERY_TARGET_PEERS,
            agent_version: "ethlambda/test",
            wire: crate::WireConfig::Beacon(Box::new(BeaconWireConfig {
                fork_digest: [0x8c, 0x9f, 0x62, 0xfe],
                fork: ForkName::Fulu,
                config: Config::mainnet(),
                genesis_time: 1_606_824_023,
                genesis_validators_root: Root::ZERO,
                custody_columns: custody_columns.clone(),
                attestation_subnets: Vec::new(),
            })),
        })
        .expect("swarm builds");

        let wire = built.wire.beacon().expect("a beacon wire");
        assert_eq!(
            wire.topics.topics.len(),
            crate::beacon::topics::SUBSCRIBED_TOPIC_KINDS.len() + custody_columns.len()
        );
        assert_eq!(wire.topics.column_topics.len(), custody_columns.len());
        for column in &custody_columns {
            assert!(wire.topics.column_topics.contains_key(column));
        }
        assert_eq!(wire.custody_columns, custody_columns);
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
