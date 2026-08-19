//! Whether a discovered peer may be dialed, and in what order.
//!
//! These are the beacon-chain phase0 p2p spec's discovery checks, mirroring
//! lighthouse's `eth2_fork_predicate`: the `fork_digest` must match, a
//! differing `next_fork_version`/`next_fork_epoch` is explicitly tolerated, and
//! the peer must advertise a port on a transport we actually speak.
//!
//! Lighthouse applies these inside the discovery query itself, via
//! `discv5.find_node_predicate`. ethlambda hands them to ethrex as a
//! [`LeanFilter`], which the peer table consults the moment each ENR arrives. A
//! peer that does not belong is judged where the record lands, not at dial time,
//! and is not offered for dialing again until it publishes a higher-`seq`
//! record, which the peer table runs through the filter afresh.
//!
//! So the dial loop filters nothing: every contact it draws has already passed,
//! and all it does is turn the record into something dialable
//! ([`LeanFilter::dial_target`]) and rank what it got
//! ([`rank_by_uncovered_subnets`]).

use std::collections::HashSet;

use ethrex_p2p::peer_filter::PeerFilter;
use ethrex_p2p::types::NodeRecord;
use libp2p::{Multiaddr, PeerId};
use libssz::SszDecode;
use tracing::debug;

use super::enr::{
    ATTNETS_ENR_KEY, ETH2_ENR_KEY, EnrForkId, read_ip, read_public_key, read_quic_port,
    subnets_from_attnets,
};
use crate::quic_multiaddr;

/// A peer that passed admission and is ready to dial.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DiscoveredPeer {
    pub(crate) peer_id: PeerId,
    pub(crate) addr: Multiaddr,
    /// Attestation subnets the peer advertises in `attnets`.
    pub(crate) subnets: Vec<u64>,
}

/// Why a discovered peer was turned away.
///
/// No reason is final: the peer table re-runs the filter on every higher-`seq`
/// record, so a peer that adds a `quic` entry or gains an address through
/// discv5's IP voting is reconsidered without restarting the process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RejectReason {
    /// No `eth2` entry, or one that does not decode. Cannot be our network.
    MissingForkId,
    /// On a different network.
    ForkDigestMismatch,
    /// Discoverable over discv5, but advertises no dialable libp2p QUIC port
    /// (see [`read_quic_port`] for what that folds together).
    NoQuicPort,
    /// No `secp256k1` entry, or one that is not a valid key.
    BadPublicKey,
    /// Neither `ip` nor `ip6`.
    MissingAddress,
}

/// The spec's admission checks, in the shape ethrex's peer table wants them.
///
/// Holds what [`admit`] needs to judge a record, so the dial loop no longer
/// carries the local fork id and committee count around: the value handed to
/// [`PeerTableServer::spawn_with_filter`](ethrex_p2p::peer_table::PeerTableServer::spawn_with_filter)
/// judges by the same rules the dial loop later asks for dial targets. It is
/// [`Clone`] because the peer table takes ownership of the filter it runs, and
/// both fields are plain data.
#[derive(Clone)]
pub struct LeanFilter {
    fork_id: EnrForkId,
    attestation_committee_count: u64,
}

impl LeanFilter {
    pub(crate) fn new(fork_id: EnrForkId, attestation_committee_count: u64) -> Self {
        Self {
            fork_id,
            attestation_committee_count,
        }
    }

    /// What to dial for a record that has already been admitted, or `None` if it
    /// would not be.
    ///
    /// The `None` arm is unreachable for a contact drawn from the peer table,
    /// since the same policy already judged the same record. It is not an
    /// `expect` because the two are only guaranteed to agree while the record is
    /// unchanged, and the peer table hands out clones: a caller that reaches
    /// this with an arbitrary record should get nothing to dial, not a panic.
    pub(crate) fn dial_target(&self, record: &NodeRecord) -> Option<DiscoveredPeer> {
        admit(record, &self.fork_id, self.attestation_committee_count).ok()
    }
}

impl PeerFilter for LeanFilter {
    fn accepts(&self, record: &NodeRecord) -> bool {
        admit(record, &self.fork_id, self.attestation_committee_count)
            // The only place a rejection is visible: the peer table records
            // that the record failed the filter but says nothing about why.
            .inspect_err(|reason| {
                debug!(
                    ip = ?record.pairs().ip,
                    udp_port = ?record.pairs().udp_port,
                    seq = record.seq,
                    ?reason,
                    "Rejecting discovered peer"
                );
            })
            .is_ok()
    }
}

/// Apply the spec's admission checks to a discovered ENR.
///
/// `attestation_committee_count` bounds [`DiscoveredPeer::subnets`]; see
/// [`subnets_from_attnets`] for why a peer's self-reported bitfield cannot be
/// trusted past our own committee.
fn admit(
    record: &NodeRecord,
    local: &EnrForkId,
    attestation_committee_count: u64,
) -> Result<DiscoveredPeer, RejectReason> {
    let pairs = record.pairs();
    let raw = pairs
        .extra(ETH2_ENR_KEY)
        .ok_or(RejectReason::MissingForkId)?;
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

    let public_key = read_public_key(pairs).ok_or(RejectReason::BadPublicKey)?;
    let peer_id = PeerId::from_public_key(&libp2p::identity::PublicKey::from(public_key));

    let ip = read_ip(pairs).ok_or(RejectReason::MissingAddress)?;

    let subnets = pairs
        .extra(ATTNETS_ENR_KEY)
        .map(|bits| subnets_from_attnets(&bits, attestation_committee_count))
        .unwrap_or_default();

    Ok(DiscoveredPeer {
        peer_id,
        addr: quic_multiaddr(ip, quic_port, peer_id),
        subnets,
    })
}

/// Order candidates so those covering the most currently-uncovered attestation
/// subnets are dialed first.
///
/// A candidate advertising no subnets scores zero and sorts last, but is never
/// dropped: with few peers, any peer is better than none.
pub(crate) fn rank_by_uncovered_subnets(candidates: &mut [DiscoveredPeer], covered: &HashSet<u64>) {
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
mod tests {
    use super::*;
    use ethrex_p2p::types::{Node, NodeRecordPairs};
    use ethrex_p2p::utils::public_key_from_signing_key;
    use libssz::SszEncode;
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr};

    use super::super::enr::{FAR_FUTURE_EPOCH, QUIC_ENR_KEY, encode_attnets};

    /// The committee count these tests admit against. `set_attnets` encodes to
    /// the same width, so the subnets below are all meant to be in range.
    const TEST_COMMITTEE_COUNT: u64 = 8;

    /// Build an ENR, applying `set_entries` to its extras so each test can omit
    /// or corrupt exactly one of them.
    ///
    /// Entries go through the same `set_extra*` accessors `build_local_enr` uses,
    /// rather than assigning `extra_fields` directly: a record these tests accept
    /// is then one built the way production builds it, encoding included.
    fn record_with(set_entries: impl FnOnce(&mut NodeRecordPairs)) -> NodeRecord {
        let signer = secp256k1::SecretKey::new(&mut rand::rngs::OsRng);
        let public_key = public_key_from_signing_key(&signer);
        let node = Node::new(IpAddr::from(Ipv4Addr::LOCALHOST), 9010, 0, public_key);
        let mut record = NodeRecord::from_node(&node, 1, &signer).unwrap();
        // `from_node` writes `tcp: 0`; the real builder leaves it unset. Drop it
        // so these records match what `build_local_enr` publishes, and re-sign
        // once with the extras applied.
        record
            .edit(&signer, |pairs| {
                pairs.tcp_port = None;
                set_entries(pairs);
            })
            .unwrap();
        record
    }

    fn set_eth2(pairs: &mut NodeRecordPairs, fork_id: EnrForkId) {
        pairs.set_extra(ETH2_ENR_KEY, fork_id.to_ssz());
    }

    fn set_quic(pairs: &mut NodeRecordPairs, port: u16) {
        pairs.set_extra_int(QUIC_ENR_KEY, port.into());
    }

    fn set_attnets(pairs: &mut NodeRecordPairs, subnets: &[u64]) {
        let subnets = subnets.iter().copied().collect::<HashSet<_>>();
        set_attnets_bits(pairs, encode_attnets(&subnets, TEST_COMMITTEE_COUNT));
    }

    /// `attnets` from raw bytes, for the widths `encode_attnets` would not
    /// produce for us: a foreign committee count, or a hostile pad.
    fn set_attnets_bits(pairs: &mut NodeRecordPairs, bits: Vec<u8>) {
        pairs.set_extra(ATTNETS_ENR_KEY, bits);
    }

    /// The `eth2` and `quic` entries that get a record past every check except
    /// the one under test.
    fn set_admissible_entries(pairs: &mut NodeRecordPairs) {
        set_eth2(pairs, EnrForkId::local());
        set_quic(pairs, 9001);
    }

    fn admit_record(record: &NodeRecord) -> Result<DiscoveredPeer, RejectReason> {
        admit(record, &EnrForkId::local(), TEST_COMMITTEE_COUNT)
    }

    /// Build a record whose pairs are fully controlled, bypassing
    /// `from_pairs`'s automatic `secp256k1` population.
    /// `admit` never checks the signature, so an all-zero one is fine; this
    /// is the only way to reach a record with a missing/invalid public key or
    /// with neither `ip` nor `ip6`, both of which `record_with` always fills
    /// in from the `Node` it wraps.
    fn raw_record(mut pairs: NodeRecordPairs) -> NodeRecord {
        set_admissible_entries(&mut pairs);
        NodeRecord::new(ethrex_common::H512::zero(), 1, pairs)
    }

    impl DiscoveredPeer {
        /// A candidate carrying only what ranking looks at.
        fn for_test(subnets: Vec<u64>) -> Self {
            Self {
                peer_id: PeerId::random(),
                addr: Multiaddr::empty(),
                subnets,
            }
        }
    }

    #[test]
    fn accepts_a_well_formed_peer() {
        let record = record_with(|pairs| {
            set_attnets(pairs, &[2, 5]);
            set_admissible_entries(pairs);
        });
        let peer = admit_record(&record).expect("accepted");
        assert_eq!(peer.subnets, vec![2, 5]);
        assert_eq!(
            peer.addr.to_string(),
            format!("/ip4/127.0.0.1/udp/9001/quic-v1/p2p/{}", peer.peer_id)
        );
    }

    #[test]
    fn rejects_a_peer_with_no_eth2_entry() {
        let record = record_with(|pairs| set_quic(pairs, 9001));
        assert_eq!(admit_record(&record), Err(RejectReason::MissingForkId));
    }

    #[test]
    fn rejects_a_peer_on_another_network() {
        let mut foreign = EnrForkId::local();
        foreign.fork_digest = [0xde, 0xad, 0xbe, 0xef];
        let record = record_with(|pairs| {
            set_eth2(pairs, foreign);
            set_quic(pairs, 9001);
        });
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
        let record = record_with(|pairs| {
            set_eth2(pairs, upcoming);
            set_quic(pairs, 9001);
        });
        assert!(admit_record(&record).is_ok());
    }

    #[test]
    fn rejects_a_peer_with_no_quic_port() {
        // Reachable by discv5 but not over our only transport.
        let record = record_with(|pairs| set_eth2(pairs, EnrForkId::local()));
        assert_eq!(admit_record(&record), Err(RejectReason::NoQuicPort));
    }

    #[test]
    fn rejects_a_peer_with_a_quic_port_of_zero() {
        // A port of 0 is undialable, and this is also how an absent entry
        // decodes (left-padded to 0u16), so it must hit the same reason as
        // `rejects_a_peer_with_no_quic_port` rather than sail through as
        // "accepted" with an unusable `/udp/0/quic-v1` multiaddr.
        let record = record_with(|pairs| {
            set_eth2(pairs, EnrForkId::local());
            set_quic(pairs, 0);
        });
        assert_eq!(admit_record(&record), Err(RejectReason::NoQuicPort));
    }

    #[test]
    fn rejects_a_peer_with_an_invalid_public_key() {
        let pairs = NodeRecordPairs {
            // `0xff` is not a valid compressed secp256k1 point tag (`02`/`03`).
            secp256k1: Some(ethrex_common::H264([0xff; 33])),
            ip: Some(Ipv4Addr::LOCALHOST),
            udp_port: Some(9010),
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
        let compressed = signer.public_key(secp256k1::SECP256K1).serialize();
        let pairs = NodeRecordPairs {
            secp256k1: Some(ethrex_common::H264(compressed)),
            udp_port: Some(9010),
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
        let record = record_with(set_admissible_entries);
        let peer = admit_record(&record).expect("accepted");
        assert!(peer.subnets.is_empty());
    }

    #[test]
    fn drops_subnets_at_or_beyond_the_local_committee_count() {
        // A peer (hostile or just differently configured) can advertise subnet
        // ids our own committee count has no room for; `admit` must not surface
        // them. `subnets_from_attnets` is what enforces that (and is tested
        // directly in `enr`); this checks `admit` actually routes through it.
        let record = record_with(|pairs| {
            set_attnets_bits(pairs, encode_attnets(&HashSet::from([2u64, 8, 40]), 64));
            set_admissible_entries(pairs);
        });
        let peer = admit_record(&record).expect("accepted");
        assert_eq!(peer.subnets, vec![2]);
    }

    // --- what the peer table sees, and what it hands back ---

    fn filter() -> LeanFilter {
        LeanFilter::new(EnrForkId::local(), TEST_COMMITTEE_COUNT)
    }

    #[test]
    fn a_well_formed_record_is_accepted_and_dialable() {
        let record = record_with(|pairs| {
            set_attnets(pairs, &[2, 5]);
            set_admissible_entries(pairs);
        });

        assert!(filter().accepts(&record));
        let peer = filter().dial_target(&record).expect("dialable");
        assert_eq!(peer.subnets, vec![2, 5]);
    }

    #[test]
    fn another_network_is_rejected() {
        let mut foreign = EnrForkId::local();
        foreign.fork_digest = [0xde, 0xad, 0xbe, 0xef];
        let record = record_with(|pairs| {
            set_eth2(pairs, foreign);
            set_quic(pairs, 9001);
        });

        assert!(!filter().accepts(&record));
        assert!(filter().dial_target(&record).is_none());
    }

    #[test]
    fn a_missing_quic_port_is_rejected() {
        // Discoverable, but not over the only transport we speak. The peer can
        // add a `quic` entry and republish: the peer table runs the filter
        // again on a higher-`seq` record. This is what the dial-time
        // `set_unwanted` this replaced could not express, since ethrex never
        // clears that flag.
        let record = record_with(|pairs| set_eth2(pairs, EnrForkId::local()));

        assert!(!filter().accepts(&record));
        assert!(filter().dial_target(&record).is_none());
    }

    #[test]
    fn a_hostile_oversized_attnets_cannot_dominate_the_ranking() {
        // The honest peer claims one real subnet. The hostile peer claims none
        // of them but pads its `attnets` with ~290 bytes of 0xFF, decoding to
        // thousands of subnet ids no 8-subnet committee has. Unclamped, that
        // raw count would outrank every honest peer forever.
        let mut hostile_bits = vec![0u8; TEST_COMMITTEE_COUNT.div_ceil(8) as usize];
        hostile_bits.extend(vec![0xffu8; 290]);

        let honest = record_with(|pairs| {
            set_attnets(pairs, &[3]);
            set_admissible_entries(pairs);
        });
        let hostile = record_with(|pairs| {
            set_attnets_bits(pairs, hostile_bits);
            set_eth2(pairs, EnrForkId::local());
            set_quic(pairs, 9002);
        });

        let policy = filter();
        let mut admitted: Vec<_> = [honest, hostile]
            .iter()
            .map(|record| policy.dial_target(record).expect("both are admitted"))
            .collect();
        assert!(
            admitted
                .iter()
                .all(|peer| peer.subnets.iter().all(|&s| s < TEST_COMMITTEE_COUNT)),
            "no admitted peer may advertise a subnet outside the local committee"
        );

        rank_by_uncovered_subnets(&mut admitted, &HashSet::new());
        assert_eq!(
            admitted[0].subnets,
            vec![3],
            "the honest peer's real subnet must outrank the hostile peer's fabricated ones"
        );
    }

    #[test]
    fn ranks_candidates_by_uncovered_subnets() {
        // Subnet 0 is already covered, so `[0]` scores zero, `[2]` scores one
        // and `[2, 3]` scores two.
        let mut candidates = vec![
            DiscoveredPeer::for_test(vec![0]),
            DiscoveredPeer::for_test(vec![2]),
            DiscoveredPeer::for_test(vec![2, 3]),
        ];
        rank_by_uncovered_subnets(&mut candidates, &HashSet::from([0u64, 1]));
        let order: Vec<_> = candidates.iter().map(|c| c.subnets.clone()).collect();
        assert_eq!(order, vec![vec![2, 3], vec![2], vec![0]]);
    }

    #[test]
    fn ranking_keeps_subnet_less_candidates_last_but_present() {
        let mut candidates = vec![
            DiscoveredPeer::for_test(vec![]),
            DiscoveredPeer::for_test(vec![7]),
        ];
        rank_by_uncovered_subnets(&mut candidates, &HashSet::new());
        let order: Vec<_> = candidates.iter().map(|c| c.subnets.clone()).collect();
        assert_eq!(
            order,
            vec![vec![7], vec![]],
            "a subnet-less candidate sorts last but is never dropped"
        );
    }
}
