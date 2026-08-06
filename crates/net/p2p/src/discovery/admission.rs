//! Whether a discovered peer may be dialed, and in what order.
//!
//! These are the beacon-chain phase0 p2p spec's discovery checks, mirroring
//! lighthouse's `eth2_fork_predicate`: the `fork_digest` must match, a
//! differing `next_fork_version`/`next_fork_epoch` is explicitly tolerated, and
//! the peer must advertise a port on a transport we actually speak.
//!
//! Lighthouse applies these inside the discovery query itself, via
//! `discv5.find_node_predicate`. ethrex's `IterativeLookup` takes no ENR
//! predicate, so ethlambda applies them one layer later, at dial selection. The
//! visible behavior matches; the cost is that non-matching ENRs occupy peer
//! table slots until `set_unwanted` sidelines them.

use std::collections::HashSet;
use std::net::IpAddr;

use ethlambda_types::enr::{EnrForkId, decode_attnets};
use ethrex_p2p::types::NodeRecord;
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use libssz::SszDecode;
use tracing::debug;

use super::enr::{ATTNETS_ENR_KEY, ETH2_ENR_KEY, read_extra, read_quic_port};
// `QUIC_ENR_KEY` itself is only needed by the test module below (which reaches
// it through this `use` via `super::*`); `admit` reads the quic port through
// `read_quic_port` instead of the raw key.
#[cfg(test)]
use super::enr::QUIC_ENR_KEY;

/// A peer that passed admission and is ready to dial.
#[derive(Debug, Clone, PartialEq)]
pub struct DiscoveredPeer {
    pub peer_id: PeerId,
    pub addr: Multiaddr,
    /// Attestation subnets the peer advertises in `attnets`.
    pub subnets: Vec<u64>,
    /// Human-readable tag used in tests and logs.
    pub label: String,
}

/// Why a discovered peer was turned away. Each variant is permanent for the
/// record as published, so the caller marks the contact unwanted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// No `eth2` entry, or one that does not decode. Cannot be our network.
    MissingForkId,
    /// On a different network.
    ForkDigestMismatch,
    /// Discoverable over discv5, but advertises no libp2p QUIC port.
    NoQuicPort,
    /// No `secp256k1` entry, or one that is not a valid key.
    BadPublicKey,
    /// Neither `ip` nor `ip6`.
    MissingAddress,
}

impl RejectReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingForkId => "missing or undecodable eth2 entry",
            Self::ForkDigestMismatch => "fork digest mismatch",
            Self::NoQuicPort => "no quic port advertised",
            Self::BadPublicKey => "missing or invalid secp256k1 key",
            Self::MissingAddress => "no ip or ip6 entry",
        }
    }
}

/// Apply the spec's admission checks to a discovered ENR.
pub fn admit(record: &NodeRecord, local: &EnrForkId) -> Result<DiscoveredPeer, RejectReason> {
    let raw = read_extra(record, ETH2_ENR_KEY).ok_or(RejectReason::MissingForkId)?;
    let remote = EnrForkId::from_ssz_bytes(&raw).map_err(|_| RejectReason::MissingForkId)?;

    if remote.fork_digest != local.fork_digest {
        return Err(RejectReason::ForkDigestMismatch);
    }
    if remote.next_fork_version != local.next_fork_version
        || remote.next_fork_epoch != local.next_fork_epoch
    {
        // Explicitly permitted: the spec's MAY covers peers that are not
        // compatible with an upcoming fork but are compatible right now.
        debug!(
            remote_next_fork_version = ?remote.next_fork_version,
            remote_next_fork_epoch = remote.next_fork_epoch,
            "Peer advertises a different upcoming fork; connecting anyway"
        );
    }

    let quic_port = read_quic_port(record).ok_or(RejectReason::NoQuicPort)?;

    let pairs = record.pairs();
    let public_key_bytes = pairs.secp256k1.ok_or(RejectReason::BadPublicKey)?;
    let public_key =
        libp2p::identity::secp256k1::PublicKey::try_from_bytes(public_key_bytes.as_bytes())
            .map_err(|_| RejectReason::BadPublicKey)?;
    let peer_id = PeerId::from_public_key(&libp2p::identity::PublicKey::from(public_key));

    let ip = pairs
        .ip
        .map(IpAddr::from)
        .or_else(|| pairs.ip6.map(IpAddr::from))
        .ok_or(RejectReason::MissingAddress)?;

    let addr = Multiaddr::empty()
        .with(ip.into())
        .with(Protocol::Udp(quic_port))
        .with(Protocol::QuicV1)
        .with_p2p(peer_id)
        .map_err(|_| RejectReason::BadPublicKey)?;

    let subnets = read_extra(record, ATTNETS_ENR_KEY)
        .map(|bits| decode_attnets(&bits))
        .unwrap_or_default();

    Ok(DiscoveredPeer {
        peer_id,
        addr,
        subnets,
        label: peer_id.to_string(),
    })
}

/// Order candidates so those covering the most currently-uncovered attestation
/// subnets are dialed first.
///
/// A candidate advertising no subnets scores zero and sorts last, but is never
/// dropped: with few peers, any peer is better than none.
pub fn rank_by_uncovered_subnets(candidates: &mut [DiscoveredPeer], covered: &HashSet<u64>) {
    candidates.sort_by_key(|candidate| {
        std::cmp::Reverse(
            candidate
                .subnets
                .iter()
                .filter(|subnet| !covered.contains(subnet))
                .count(),
        )
    });
}

#[cfg(test)]
impl DiscoveredPeer {
    /// A candidate carrying only what ranking looks at.
    fn for_test(label: &str, subnets: Vec<u64>) -> Self {
        Self {
            peer_id: PeerId::random(),
            addr: Multiaddr::empty(),
            subnets,
            label: label.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use ethlambda_types::enr::{FAR_FUTURE_EPOCH, encode_attnets};
    use ethrex_p2p::types::Node;
    use ethrex_rlp::encode::RLPEncode;
    use libssz::SszEncode;
    use std::collections::HashSet;
    use std::net::Ipv4Addr;

    /// Build an ENR with an arbitrary set of extra pairs, so each test can omit
    /// or corrupt exactly one entry.
    fn record_with(extra: Vec<(Bytes, Bytes)>) -> NodeRecord {
        let signer = secp256k1::SecretKey::new(&mut rand::rngs::OsRng);
        let public_key = ethrex_common::H512::from_slice(
            &secp256k1::PublicKey::from_secret_key(secp256k1::SECP256K1, &signer)
                .serialize_uncompressed()[1..],
        );
        let node = Node::new(IpAddr::from(Ipv4Addr::LOCALHOST), 9010, 0, public_key);
        NodeRecord::from_node_with_extra_pairs(&node, 1, &signer, extra).unwrap()
    }

    fn pair(key: &'static [u8], value: Vec<u8>) -> (Bytes, Bytes) {
        (Bytes::from_static(key), Bytes::from(value))
    }

    // Byte payloads go through `Bytes` so RLP encodes them as a byte string. A
    // bare `Vec<u8>` would hit the generic `Vec<T>` impl and emit a list, which
    // `read_extra` cannot decode. `u16` is a scalar and needs no wrapping.
    fn eth2_pair(fork_id: EnrForkId) -> (Bytes, Bytes) {
        pair(ETH2_ENR_KEY, Bytes::from(fork_id.to_ssz()).encode_to_vec())
    }

    fn quic_pair(port: u16) -> (Bytes, Bytes) {
        pair(QUIC_ENR_KEY, port.encode_to_vec())
    }

    fn attnets_pair(subnets: &[u64]) -> (Bytes, Bytes) {
        let bits = encode_attnets(&subnets.iter().copied().collect::<HashSet<_>>(), 8);
        pair(ATTNETS_ENR_KEY, Bytes::from(bits).encode_to_vec())
    }

    fn admit_record(record: &NodeRecord) -> Result<DiscoveredPeer, RejectReason> {
        admit(record, &EnrForkId::local())
    }

    #[test]
    fn accepts_a_well_formed_peer() {
        let record = record_with(vec![
            attnets_pair(&[2, 5]),
            eth2_pair(EnrForkId::local()),
            quic_pair(9001),
        ]);
        let peer = admit_record(&record).expect("accepted");
        assert_eq!(peer.subnets, vec![2, 5]);
        assert_eq!(
            peer.addr.to_string(),
            format!("/ip4/127.0.0.1/udp/9001/quic-v1/p2p/{}", peer.peer_id)
        );
    }

    #[test]
    fn rejects_a_peer_with_no_eth2_entry() {
        let record = record_with(vec![quic_pair(9001)]);
        assert_eq!(admit_record(&record), Err(RejectReason::MissingForkId));
    }

    #[test]
    fn rejects_a_peer_on_another_network() {
        let mut foreign = EnrForkId::local();
        foreign.fork_digest = [0xde, 0xad, 0xbe, 0xef];
        let record = record_with(vec![eth2_pair(foreign), quic_pair(9001)]);
        assert_eq!(admit_record(&record), Err(RejectReason::ForkDigestMismatch));
    }

    #[test]
    fn accepts_a_peer_with_a_different_upcoming_fork() {
        // Per the spec's MAY, and lighthouse: "next_fork_epoch and
        // next_fork_version can be different so that we can connect to peers who
        // aren't compatible with an upcoming fork. fork_digest **must** be same."
        let mut upcoming = EnrForkId::local();
        upcoming.next_fork_version = [9, 9, 9, 9];
        upcoming.next_fork_epoch = FAR_FUTURE_EPOCH - 1;
        let record = record_with(vec![eth2_pair(upcoming), quic_pair(9001)]);
        assert!(admit_record(&record).is_ok());
    }

    #[test]
    fn rejects_a_peer_with_no_quic_port() {
        // Reachable by discv5 but not over our only transport.
        let record = record_with(vec![eth2_pair(EnrForkId::local())]);
        assert_eq!(admit_record(&record), Err(RejectReason::NoQuicPort));
    }

    #[test]
    fn accepts_a_peer_with_no_attnets() {
        // subnet_predicate treats a missing bitfield as covering no subnets, but
        // that never excludes a peer from general discovery.
        let record = record_with(vec![eth2_pair(EnrForkId::local()), quic_pair(9001)]);
        let peer = admit_record(&record).expect("accepted");
        assert!(peer.subnets.is_empty());
    }

    #[test]
    fn ranks_candidates_by_uncovered_subnets() {
        let mut candidates = vec![
            DiscoveredPeer::for_test("a", vec![0]),
            DiscoveredPeer::for_test("b", vec![2]),
            DiscoveredPeer::for_test("c", vec![2, 3]),
        ];
        rank_by_uncovered_subnets(&mut candidates, &HashSet::from([0u64, 1]));
        let order: Vec<_> = candidates.iter().map(|c| c.label.clone()).collect();
        assert_eq!(order, vec!["c", "b", "a"]);
    }

    #[test]
    fn ranking_keeps_subnet_less_candidates_last_but_present() {
        let mut candidates = vec![
            DiscoveredPeer::for_test("none", vec![]),
            DiscoveredPeer::for_test("some", vec![7]),
        ];
        rank_by_uncovered_subnets(&mut candidates, &HashSet::new());
        let order: Vec<_> = candidates.iter().map(|c| c.label.clone()).collect();
        assert_eq!(order, vec!["some", "none"]);
    }
}
