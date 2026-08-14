//! Whether a discovered peer may be dialed, and in what order.
//!
//! These are the beacon-chain phase0 p2p spec's discovery checks, mirroring
//! lighthouse's `eth2_fork_predicate`: the `fork_digest` must match, a
//! differing `next_fork_version`/`next_fork_epoch` is explicitly tolerated, and
//! the peer must advertise a port on a transport we actually speak.
//!
//! Lighthouse applies these inside the discovery query itself, via
//! `discv5.find_node_predicate`. ethlambda applies them one layer later, at dial
//! selection. The visible behavior matches; the cost is that non-matching ENRs
//! occupy peer table slots until `set_unwanted` sidelines them — and only
//! permanent rejections (see [`RejectReason::is_permanent`]) get sidelined at
//! all, since ethrex never clears that flag.
//!
//! ethrex now offers a closer fit for this than it did when the module was
//! written: `PeerFilter::accepts` judges each contact as its ENR arrives, and
//! the peer table re-runs it when the peer publishes a higher-`seq` record,
//! which `set_unwanted` cannot do. Moving these checks there would drop the
//! dial-selection pass and fix the one-way `unwanted` flag. The peer table is
//! deliberately spawned with [`AcceptEveryContact`] until then, so admission
//! stays here and behavior is unchanged.

use std::collections::HashSet;
use std::net::IpAddr;

use ethlambda_types::enr::{EnrForkId, decode_attnets};
use ethrex_p2p::peer_filter::PeerFilter;
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

/// A [`PeerFilter`] that imposes nothing at the ENR level.
///
/// ethrex's own `PeerTableServer::spawn` would install `EthForkIdFilter`, which
/// demands an EIP-2124 `eth` entry compatible with a chain lean does not have,
/// and so would reject every lean contact. Lean's real checks are [`admit`],
/// applied at dial selection; see this module's own docs for why they have not
/// moved here yet.
///
/// Accepting unconditionally is what keeps the peer table's behaviour identical
/// to before ethrex grew this hook.
pub struct AcceptEveryContact;

impl PeerFilter for AcceptEveryContact {
    fn accepts(&self, _record: &NodeRecord) -> bool {
        true
    }
}

/// A peer that passed admission and is ready to dial.
#[derive(Debug, Clone, PartialEq)]
pub struct DiscoveredPeer {
    pub peer_id: PeerId,
    /// Dial targets, QUIC first then TCP, built from whichever of the two
    /// ports the record actually advertises. Never empty: [`admit`] rejects a
    /// record with neither.
    pub addrs: Vec<Multiaddr>,
    /// Attestation subnets the peer advertises in `attnets`.
    pub subnets: Vec<u64>,
    /// Human-readable tag used in tests and logs.
    pub label: String,
}

/// Why a discovered peer was turned away. Whether a reason is permanent for
/// the record as published, rather than just for the moment we happen to
/// evaluate it, is captured separately by [`RejectReason::is_permanent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// No `eth2` entry, or one that does not decode. Cannot be our network.
    MissingForkId,
    /// On a different network.
    ForkDigestMismatch,
    /// Discoverable over discv5, but advertises no dialable transport: no
    /// libp2p QUIC port and no libp2p TCP port (a port that is `0` is treated
    /// the same as absent, since it RLP-decodes the same way an absent entry
    /// does and is undialable either way).
    NoDialableTransport,
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
            Self::NoDialableTransport => "no quic or tcp port advertised",
            Self::BadPublicKey => "missing or invalid secp256k1 key",
            Self::MissingAddress => "no ip or ip6 entry",
        }
    }

    /// Whether this rejection is a permanent property of the peer rather than
    /// of the record we happen to hold.
    ///
    /// ethrex's peer table never clears `unwanted`, so marking a contact is
    /// irreversible for the life of the process. Only do it for reasons a new
    /// ENR sequence cannot fix.
    pub fn is_permanent(self) -> bool {
        match self {
            // Not our network, or not a lean node at all.
            Self::MissingForkId | Self::ForkDigestMismatch => true,
            // A record we cannot derive a peer id from is unusable whoever sent it.
            Self::BadPublicKey => true,
            // Both can be fixed by a later ENR: a node can add a quic or tcp
            // entry, and discv5's own IP voting can fill in an address that
            // was missing.
            Self::NoDialableTransport | Self::MissingAddress => false,
        }
    }
}

/// Apply the spec's admission checks to a discovered ENR.
///
/// `attestation_committee_count` bounds [`DiscoveredPeer::subnets`]: a
/// decoded subnet id `>= attestation_committee_count` is dropped before it
/// ever reaches the result. The peer's `attnets` is self-reported and
/// unauthenticated, so trusting it verbatim lets a hostile ENR pack an
/// oversized bitfield (e.g. ~290 bytes of `0xFF`) that decodes to thousands
/// of subnets, dominating `rank_by_uncovered_subnets` forever. A subnet we
/// have no committee for cannot be useful to us regardless, so the clamp is
/// correct on the merits, not just a mitigation.
pub fn admit(
    record: &NodeRecord,
    local: &EnrForkId,
    attestation_committee_count: u64,
) -> Result<DiscoveredPeer, RejectReason> {
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

    let pairs = record.pairs();

    // `None` and `Some(0)` are the same failure for either transport: no
    // dialable port. Both coincide by construction with an absent entry,
    // since that RLP-decodes to `0u16` via left-padding either way.
    let quic_port = read_quic_port(record).filter(|port| *port != 0);
    let tcp_port = pairs.tcp_port.filter(|port| *port != 0);
    if quic_port.is_none() && tcp_port.is_none() {
        return Err(RejectReason::NoDialableTransport);
    }

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

    // QUIC first: it is what most peers advertise today, and ordering it
    // ahead of TCP here is what makes discovery's own dial list agree with
    // `bootnode_dial_addrs`'s ordering.
    let mut addrs = Vec::with_capacity(2);
    if let Some(port) = quic_port {
        addrs.push(
            Multiaddr::empty()
                .with(ip.into())
                .with(Protocol::Udp(port))
                .with(Protocol::QuicV1)
                .with_p2p(peer_id)
                .map_err(|_| RejectReason::BadPublicKey)?,
        );
    }
    if let Some(port) = tcp_port {
        addrs.push(
            Multiaddr::empty()
                .with(ip.into())
                .with(Protocol::Tcp(port))
                .with_p2p(peer_id)
                .map_err(|_| RejectReason::BadPublicKey)?,
        );
    }

    let subnets = read_extra(record, ATTNETS_ENR_KEY)
        .map(|bits| decode_attnets(&bits))
        .unwrap_or_default()
        .into_iter()
        .filter(|subnet| *subnet < attestation_committee_count)
        .collect();

    Ok(DiscoveredPeer {
        peer_id,
        addrs,
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
            addrs: Vec::new(),
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
        let mut record = NodeRecord::from_node(&node, 1, &signer).unwrap();
        // `from_node` writes `tcp: 0`; the real builder leaves it unset. Drop it
        // so these records match what `build_local_enr` publishes, and re-sign
        // once with the extras applied.
        record
            .edit(&signer, |pairs| {
                pairs.tcp_port = None;
                pairs.extra_fields = extra;
            })
            .unwrap();
        record
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

    /// Like `record_with`, but with a real `tcp` port too — the shape a
    /// beacon-chain mainnet bootnode ENR actually has (`record_with` always
    /// clears `tcp_port`, so it can only ever produce a quic-only record).
    fn record_with_tcp(extra: Vec<(Bytes, Bytes)>, tcp_port: u16) -> NodeRecord {
        let signer = secp256k1::SecretKey::new(&mut rand::rngs::OsRng);
        let public_key = ethrex_common::H512::from_slice(
            &secp256k1::PublicKey::from_secret_key(secp256k1::SECP256K1, &signer)
                .serialize_uncompressed()[1..],
        );
        let node = Node::new(
            IpAddr::from(Ipv4Addr::LOCALHOST),
            9010,
            tcp_port,
            public_key,
        );
        let mut record = NodeRecord::from_node(&node, 1, &signer).unwrap();
        record
            .edit(&signer, |pairs| {
                pairs.extra_fields = extra;
            })
            .unwrap();
        record
    }

    fn attnets_pair(subnets: &[u64]) -> (Bytes, Bytes) {
        let bits = encode_attnets(&subnets.iter().copied().collect::<HashSet<_>>(), 8);
        pair(ATTNETS_ENR_KEY, Bytes::from(bits).encode_to_vec())
    }

    /// `attnets_pair` above encodes against a committee count of 8, so this
    /// matches it: subnets in the tests below are all meant to be in-range.
    const TEST_COMMITTEE_COUNT: u64 = 8;

    fn admit_record(record: &NodeRecord) -> Result<DiscoveredPeer, RejectReason> {
        admit(record, &EnrForkId::local(), TEST_COMMITTEE_COUNT)
    }

    /// Build a record whose pairs are fully controlled, bypassing
    /// `from_pairs`'s automatic `secp256k1` population.
    /// `admit` never checks the signature, so an all-zero one is fine; this
    /// is the only way to reach a record with a missing/invalid public key or
    /// with neither `ip` nor `ip6`, both of which `record_with` always fills
    /// in from the `Node` it wraps.
    fn raw_record(pairs: ethrex_p2p::types::NodeRecordPairs) -> NodeRecord {
        NodeRecord::new(ethrex_common::H512::zero(), 1, pairs)
    }

    #[test]
    fn accepts_a_well_formed_peer() {
        // This is also the quic-only case: `record_with` always clears
        // `tcp_port`, so `peer.addrs` here has exactly the one quic address.
        let record = record_with(vec![
            attnets_pair(&[2, 5]),
            eth2_pair(EnrForkId::local()),
            quic_pair(9001),
        ]);
        let peer = admit_record(&record).expect("accepted");
        assert_eq!(peer.subnets, vec![2, 5]);
        assert_eq!(
            peer.addrs,
            vec![
                format!("/ip4/127.0.0.1/udp/9001/quic-v1/p2p/{}", peer.peer_id)
                    .parse()
                    .unwrap()
            ]
        );
    }

    #[test]
    fn accepts_a_tcp_only_peer() {
        // Every published mainnet beacon-chain bootnode looks like this: `tcp`
        // and `udp`, no `quic`. Before TCP support this was `NoQuicPort`.
        let record = record_with_tcp(vec![eth2_pair(EnrForkId::local())], 9001);
        let peer = admit_record(&record).expect("accepted");
        assert_eq!(
            peer.addrs,
            vec![
                format!("/ip4/127.0.0.1/tcp/9001/p2p/{}", peer.peer_id)
                    .parse()
                    .unwrap()
            ]
        );
    }

    #[test]
    fn accepts_a_peer_with_both_transports_and_orders_quic_first() {
        let record = record_with_tcp(vec![eth2_pair(EnrForkId::local()), quic_pair(9001)], 9002);
        let peer = admit_record(&record).expect("accepted");
        assert_eq!(
            peer.addrs,
            vec![
                format!("/ip4/127.0.0.1/udp/9001/quic-v1/p2p/{}", peer.peer_id)
                    .parse()
                    .unwrap(),
                format!("/ip4/127.0.0.1/tcp/9002/p2p/{}", peer.peer_id)
                    .parse()
                    .unwrap(),
            ]
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
    fn rejects_a_peer_with_neither_quic_nor_tcp() {
        // Reachable by discv5 but not over either transport we speak.
        // `record_with` always clears `tcp_port`, so this is a plain
        // eth2-only record.
        let record = record_with(vec![eth2_pair(EnrForkId::local())]);
        assert_eq!(
            admit_record(&record),
            Err(RejectReason::NoDialableTransport)
        );
        assert!(!RejectReason::NoDialableTransport.is_permanent());
    }

    #[test]
    fn rejects_a_peer_with_a_quic_port_of_zero_and_no_tcp() {
        // A port of 0 is undialable, and this is also how an absent entry
        // decodes (left-padded to 0u16), so it must hit the same reason as
        // `rejects_a_peer_with_neither_quic_nor_tcp` rather than sail through
        // as "accepted" with an unusable `/udp/0/quic-v1` multiaddr.
        let record = record_with(vec![eth2_pair(EnrForkId::local()), quic_pair(0)]);
        assert_eq!(
            admit_record(&record),
            Err(RejectReason::NoDialableTransport)
        );
    }

    #[test]
    fn rejects_a_peer_with_an_invalid_public_key() {
        let pairs = ethrex_p2p::types::NodeRecordPairs {
            // `0xff` is not a valid compressed secp256k1 point tag (`02`/`03`).
            secp256k1: Some(ethrex_common::H264([0xff; 33])),
            ip: Some(Ipv4Addr::LOCALHOST),
            udp_port: Some(9010),
            extra_fields: vec![eth2_pair(EnrForkId::local()), quic_pair(9001)],
            ..Default::default()
        };
        assert_eq!(
            admit_record(&raw_record(pairs)),
            Err(RejectReason::BadPublicKey)
        );
    }

    #[test]
    fn rejects_a_peer_with_neither_ip_nor_ip6() {
        let signer = secp256k1::SecretKey::new(&mut rand::rngs::OsRng);
        let public_key_bytes =
            secp256k1::PublicKey::from_secret_key(secp256k1::SECP256K1, &signer).serialize();
        let pairs = ethrex_p2p::types::NodeRecordPairs {
            secp256k1: Some(ethrex_common::H264(public_key_bytes)),
            udp_port: Some(9010),
            extra_fields: vec![eth2_pair(EnrForkId::local()), quic_pair(9001)],
            ..Default::default()
        };
        assert_eq!(
            admit_record(&raw_record(pairs)),
            Err(RejectReason::MissingAddress)
        );
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
    fn drops_subnets_at_or_beyond_the_local_committee_count() {
        // A peer (hostile or just differently configured) can advertise
        // subnet ids our own committee count has no room for. `admit` must
        // silently drop those rather than surface them: a subnet we do not
        // have is never useful to us, and (per the ranking exploit this
        // guards against) letting them through would let a Sybil ENR packing
        // a huge `attnets` bitfield dominate `rank_by_uncovered_subnets`.
        let bits = encode_attnets(&HashSet::from([2u64, 8, 40]), 64);
        let record = record_with(vec![
            pair(ATTNETS_ENR_KEY, Bytes::from(bits).encode_to_vec()),
            eth2_pair(EnrForkId::local()),
            quic_pair(9001),
        ]);
        let peer = admit_record(&record).expect("accepted");
        assert_eq!(peer.subnets, vec![2]);
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
