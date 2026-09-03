//! Construction and reading of the ENR ethlambda publishes over discv5.
//!
//! The entry set follows the beacon-chain phase0 p2p spec's discovery domain:
//!
//! ```text
//! id, ip, udp=<discovery port>, quic=<libp2p QUIC port>, tcp=<libp2p TCP port>,
//! secp256k1,
//! eth2    = SSZ(ENRForkID)
//! attnets = subscribed attestation subnet bitfield
//! ```
//!
//! `tcp` is the spec's own entry for the libp2p TCP listening port: ethlambda
//! binds one alongside QUIC (see `crates/net/p2p/src/lib.rs`'s `build_swarm`),
//! on the same port number, so advertising it is what lets a peer whose
//! advertised `quic` does not answer still reach us.
//!
//! Lean defines no fork schedule and its fork digest is a compile-time constant
//! rather than a genesis-derived value, so every field of [`EnrForkId`] is
//! fixed. The `eth2` check therefore separates lean from non-lean, but not one
//! lean devnet from another.

use std::collections::HashSet;
use std::net::IpAddr;

use ethlambda_types::constants::FORK_DIGEST;
use ethrex_p2p::types::{INITIAL_ENR_SEQ, Node, NodeRecord, NodeRecordPairs};
use ethrex_p2p::utils::public_key_from_signing_key;
use libssz::SszEncode;
use libssz_derive::{SszDecode, SszEncode};
use secp256k1::SecretKey;

use super::DiscoveryError;

pub(crate) const QUIC_ENR_KEY: &[u8] = b"quic";
pub(crate) const ETH2_ENR_KEY: &[u8] = b"eth2";
pub(crate) const ATTNETS_ENR_KEY: &[u8] = b"attnets";

/// Fork version of the next planned hard fork. The spec says to set this to the
/// current fork version when no fork is planned; lean has neither.
pub(crate) const NEXT_FORK_VERSION: [u8; 4] = [0; 4];

/// Sentinel for "no fork is scheduled", per the beacon spec.
pub(crate) const FAR_FUTURE_EPOCH: u64 = u64::MAX;

/// The `eth2` ENR entry: SSZ, 16 bytes, byte-identical to the beacon-chain
/// `ENRForkID` container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, SszEncode, SszDecode)]
pub(crate) struct EnrForkId {
    pub(crate) fork_digest: [u8; 4],
    pub(crate) next_fork_version: [u8; 4],
    pub(crate) next_fork_epoch: u64,
}

impl EnrForkId {
    /// This node's fork id. Constant for the lifetime of the process.
    pub(crate) fn local() -> Self {
        Self {
            fork_digest: fork_digest(),
            next_fork_version: NEXT_FORK_VERSION,
            next_fork_epoch: FAR_FUTURE_EPOCH,
        }
    }
}

/// [`FORK_DIGEST`] as raw bytes. The constant is the same hex string embedded in
/// every gossipsub topic name, so the ENR and the topics cannot disagree.
pub(crate) fn fork_digest() -> [u8; 4] {
    u32::from_str_radix(FORK_DIGEST, 16)
        .expect("FORK_DIGEST must be 8 hex digits")
        .to_be_bytes()
}

/// Encode subscribed attestation subnets as the `attnets` bitfield: bit `i` set
/// means subnet `i` is subscribed.
///
/// Lighthouse uses a fixed-width SSZ `BitVector` because the beacon
/// `ATTESTATION_SUBNET_COUNT` is a spec constant. ethlambda's
/// `attestation_committee_count` is runtime configuration, so the length is
/// derived from it and readers must tolerate a length other than their own.
/// Subnet ids at or beyond `committee_count` are dropped.
pub(crate) fn encode_attnets(subnets: &HashSet<u64>, committee_count: u64) -> Vec<u8> {
    let mut bits = vec![0u8; committee_count.div_ceil(8) as usize];
    for &subnet in subnets {
        if subnet < committee_count {
            bits[(subnet / 8) as usize] |= 1 << (subnet % 8);
        }
    }
    bits
}

/// The subnets `bits` advertises, ascending, bounded by `committee_count`.
///
/// Iterating our own committee rather than the peer's bitfield does two jobs at
/// once. A bitfield shorter than ours is not an error: its missing subnets read
/// as unsubscribed. A longer one cannot be believed either, because `attnets` is
/// self-reported and unauthenticated, so a hostile ENR could otherwise pack an
/// oversized field that decodes to thousands of subnets and dominate
/// [`rank_by_uncovered_subnets`](super::admission::rank_by_uncovered_subnets)
/// forever. A subnet we have no committee for cannot be useful to us regardless.
pub(crate) fn subnets_from_attnets(bits: &[u8], committee_count: u64) -> Vec<u64> {
    (0..committee_count)
        .filter(|subnet| {
            bits.get((subnet / 8) as usize)
                .is_some_and(|byte| byte & (1 << (subnet % 8)) != 0)
        })
        .collect()
}

/// Everything needed to build this node's ENR.
pub(crate) struct LocalEnrParams {
    pub(crate) signer: SecretKey,
    /// Address to advertise. discv5's PONG-based IP voting may replace it later.
    pub(crate) ip: IpAddr,
    /// UDP port the discv5 socket is bound to.
    pub(crate) discovery_port: u16,
    /// Port the libp2p transports are bound to, published as both the `quic`
    /// (UDP) and `tcp` entries.
    ///
    /// One field rather than two because there is only ever one number: TCP and
    /// UDP are separate namespaces, so `build_swarm` binds both listeners from
    /// the single `--gossipsub-port`. Two fields could be handed differing
    /// values that no bind would ever produce.
    pub(crate) p2p_port: u16,
    pub(crate) subscription_subnets: HashSet<u64>,
    pub(crate) attestation_committee_count: u64,
}

impl LocalEnrParams {
    /// The `Node` ethrex's discovery server takes as its local identity.
    ///
    /// Its `tcp_port` is the real port the libp2p TCP transport is bound to, now
    /// that ethlambda has one.
    pub(crate) fn local_node(&self) -> Node {
        Node::new(
            self.ip,
            self.discovery_port,
            self.p2p_port,
            public_key_from_signing_key(&self.signer),
        )
    }

    /// The full entry set this node advertises.
    ///
    /// The three consensus entries go through `set_extra`/`set_extra_int`,
    /// which pick the RLP codec once. Encoding them by hand is the trap that
    /// helper exists for: a bare `Vec<u8>` hits the generic `Vec<T>` impl and
    /// encodes as a *list* of per-byte scalars rather than a byte string, which
    /// is well-formed but unreadable by every other client, and nothing local
    /// ever complains.
    fn local_pairs(&self) -> NodeRecordPairs {
        let mut pairs = NodeRecordPairs {
            udp_port: Some(self.discovery_port),
            tcp_port: dialable_port(self.p2p_port),
            ..Default::default()
        };
        match self.ip.to_canonical() {
            IpAddr::V4(ip) => pairs.ip = Some(ip),
            IpAddr::V6(ip) => pairs.ip6 = Some(ip),
        }

        // Each setter answers whether the entry was stored, which is `false`
        // only for a key the record already has a typed field for. All three
        // below are outside that dictionary, and the tests assert each one lands
        // in the built record, so the answers are not checked here.
        let attnets = encode_attnets(&self.subscription_subnets, self.attestation_committee_count);
        pairs.set_extra(ATTNETS_ENR_KEY, attnets);
        pairs.set_extra(ETH2_ENR_KEY, EnrForkId::local().to_ssz());
        if let Some(quic_port) = dialable_port(self.p2p_port) {
            pairs.set_extra_int(QUIC_ENR_KEY, quic_port.into());
        }
        pairs
    }
}

/// The `0` filter every port on a record goes through, on the way in and on the
/// way out.
///
/// A port of `0` is spelled by the entry's absence: `--gossipsub-port 0` asks
/// the OS to pick, so the number never describes a real listener, and a peer
/// reading a literal `0` finds nothing dialable. Both readings collapse into
/// `None` so a `0` cannot mean "absent" on one side of the wire and "port zero"
/// on the other.
///
/// Deliberately the only place that rule is spelled: the ENR writer
/// ([`LocalEnrParams::local_pairs`]), both port readers here, and the bootnode
/// parser's `udp` filter all go through it.
pub(crate) fn dialable_port(port: u16) -> Option<u16> {
    Some(port).filter(|port| *port != 0)
}

/// Build and sign this node's ENR.
pub(crate) fn build_local_enr(params: &LocalEnrParams) -> Result<NodeRecord, DiscoveryError> {
    NodeRecord::from_pairs(INITIAL_ENR_SEQ, &params.signer, params.local_pairs())
        .map_err(DiscoveryError::BuildEnr)
}

/// The address a record advertises, preferring IPv4 when it carries both.
///
/// `None` for a record with neither `ip` nor `ip6`, which names no host to
/// reach. Shared with the bootnode parser so both readers agree on which family
/// wins.
pub(crate) fn read_ip(pairs: &NodeRecordPairs) -> Option<IpAddr> {
    pairs
        .ip
        .map(IpAddr::from)
        .or_else(|| pairs.ip6.map(IpAddr::from))
}

/// The `secp256k1` entry as a libp2p key, or `None` when absent or not a valid
/// compressed point.
///
/// libp2p derives the peer id from this key, so the bootnode parser and the
/// admission filter must decode it the same way or they would disagree about who
/// a record belongs to.
pub(crate) fn read_public_key(
    pairs: &NodeRecordPairs,
) -> Option<libp2p::identity::secp256k1::PublicKey> {
    let bytes = pairs.secp256k1?;
    libp2p::identity::secp256k1::PublicKey::try_from_bytes(bytes.as_bytes()).ok()
}

/// The advertised libp2p QUIC port, if it is one we could dial.
///
/// `None` covers an absent entry, an encoding `extra_int` cannot read (including
/// the non-minimal forms some clients emit), and a literal `0`. The first two
/// come straight from `extra_int`, which looks the key up before it decodes
/// anything and so reports a missing entry rather than a zero; the explicit `0`
/// is [`dialable_port`]'s business. None of the three names a port worth
/// dialing, which is why they collapse into one answer.
pub(crate) fn read_quic_port(record: &NodeRecord) -> Option<u16> {
    record
        .pairs()
        .extra_int::<u16>(QUIC_ENR_KEY)
        .and_then(dialable_port)
}

/// The advertised libp2p TCP port, if it is one we could dial.
///
/// `tcp` is a first-class entry rather than an `extra`, so an absent one is
/// already `None`; [`dialable_port`] is what folds a literal `0` into the same
/// answer. Same answer as [`read_quic_port`] gives for `quic`.
pub(crate) fn read_tcp_port(pairs: &NodeRecordPairs) -> Option<u16> {
    pairs.tcp_port.and_then(dialable_port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethrex_rlp::decode::RLPDecode as _;
    use libssz::SszDecode;
    use std::net::Ipv4Addr;

    fn build() -> NodeRecord {
        build_local_enr(&LocalEnrParams {
            signer: secp256k1::SecretKey::new(&mut rand::rngs::OsRng),
            ip: IpAddr::from(Ipv4Addr::LOCALHOST),
            discovery_port: 9010,
            p2p_port: 9001,
            subscription_subnets: HashSet::from([1u64, 4]),
            attestation_committee_count: 8,
        })
        .expect("ENR builds")
    }

    #[test]
    fn fork_digest_parses_the_constant() {
        assert_eq!(fork_digest(), [0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn enr_fork_id_is_sixteen_bytes_and_round_trips() {
        let id = EnrForkId::local();
        let bytes = id.to_ssz();
        assert_eq!(bytes.len(), 16, "ENRForkID is 4 + 4 + 8 bytes");
        assert_eq!(EnrForkId::from_ssz_bytes(&bytes).unwrap(), id);
    }

    #[test]
    fn local_fork_id_has_no_planned_fork() {
        let id = EnrForkId::local();
        assert_eq!(id.fork_digest, fork_digest());
        assert_eq!(id.next_fork_version, NEXT_FORK_VERSION);
        assert_eq!(id.next_fork_epoch, FAR_FUTURE_EPOCH);
    }

    #[test]
    fn attnets_sets_exactly_the_subscribed_bits() {
        let subnets = HashSet::from([0u64, 3, 9]);
        let bits = encode_attnets(&subnets, 16);

        assert_eq!(bits.len(), 2, "16 subnets need ceil(16/8) = 2 bytes");
        assert_eq!(subnets_from_attnets(&bits, 16), vec![0, 3, 9]);
    }

    #[test]
    fn attnets_rounds_the_byte_length_up() {
        let bits = encode_attnets(&HashSet::from([0u64]), 1);
        assert_eq!(bits.len(), 1);
        assert_eq!(subnets_from_attnets(&bits, 1), vec![0]);
    }

    #[test]
    fn attnets_ignores_out_of_range_subnets() {
        // A misconfigured subnet id must not panic or corrupt neighbouring bits.
        let bits = encode_attnets(&HashSet::from([0u64, 99]), 8);
        assert_eq!(bits, vec![0b0000_0001]);
    }

    #[test]
    fn attnets_reads_past_the_end_as_unset() {
        // A peer advertising a shorter bitfield than our committee count is not
        // an error; the missing subnets simply read as unsubscribed.
        let bits = encode_attnets(&HashSet::from([0u64]), 8);
        assert_eq!(subnets_from_attnets(&bits, 64), vec![0]);
    }

    #[test]
    fn attnets_ignores_bits_beyond_our_committee() {
        // The hostile case: a peer padding its bitfield cannot manufacture
        // subnets we have no committee for.
        let bits = encode_attnets(&HashSet::from([2u64, 8, 40]), 64);
        assert_eq!(subnets_from_attnets(&bits, 8), vec![2]);
    }

    #[test]
    fn local_enr_advertises_udp_quic_and_tcp() {
        // Inverts what this test used to pin: ethlambda now binds a TCP
        // transport alongside QUIC (see `build_swarm`), so the ENR must
        // advertise all three ports rather than omitting `tcp`.
        let record = build();
        let pairs = record.pairs();
        assert_eq!(pairs.udp_port, Some(9010));
        assert_eq!(
            pairs.tcp_port,
            Some(9001),
            "ethlambda now has a TCP listener and must advertise it"
        );
        assert_eq!(read_quic_port(&record), Some(9001));
    }

    /// The advertised ports come from configuration, not from the bound
    /// listeners, so a `--gossipsub-port 0` reaches the writer as a literal `0`
    /// that names neither of the two real OS-assigned ports. Every reader treats
    /// `0` as absent, so the writer must not emit it: the alternative is a
    /// record that satisfies lighthouse's `tcp4().is_some()` predicate while our
    /// own `admit` rejects it as `NoDialableTransport`.
    #[test]
    fn local_enr_omits_a_zero_quic_and_tcp_port() {
        let record = build_local_enr(&LocalEnrParams {
            signer: secp256k1::SecretKey::new(&mut rand::rngs::OsRng),
            ip: IpAddr::from(Ipv4Addr::LOCALHOST),
            discovery_port: 9010,
            p2p_port: 0,
            subscription_subnets: HashSet::from([1u64]),
            attestation_committee_count: 8,
        })
        .expect("ENR builds");

        assert_eq!(
            record.pairs().tcp_port,
            None,
            "a tcp: 0 must not be emitted"
        );
        assert!(
            record.pairs().extra(QUIC_ENR_KEY).is_none(),
            "a quic: 0 must not be emitted"
        );
        // The discovery port is unaffected: `spawn_discovery` binds first and
        // passes the real bound port, so a 0 never reaches here.
        assert_eq!(record.pairs().udp_port, Some(9010));
    }

    #[test]
    fn read_tcp_port_treats_zero_as_absent() {
        // Same answer `read_quic_port` gives for `quic: 0`, so the two dial
        // paths and the ENR writer cannot disagree about what `0` means.
        let mut pairs = NodeRecordPairs::default();
        assert_eq!(read_tcp_port(&pairs), None, "absent");
        pairs.tcp_port = Some(0);
        assert_eq!(read_tcp_port(&pairs), None, "explicit zero");
        pairs.tcp_port = Some(9001);
        assert_eq!(read_tcp_port(&pairs), Some(9001));
    }

    #[test]
    fn local_enr_carries_the_fork_id() {
        let record = build();
        let raw = record.pairs().extra(ETH2_ENR_KEY).expect("eth2 entry");
        assert_eq!(EnrForkId::from_ssz_bytes(&raw).unwrap(), EnrForkId::local());
    }

    #[test]
    fn local_enr_carries_the_subscribed_subnets() {
        let record = build();
        let raw = record
            .pairs()
            .extra(ATTNETS_ENR_KEY)
            .expect("attnets entry");
        assert_eq!(subnets_from_attnets(&raw, 8), vec![1, 4]);
    }

    #[test]
    fn local_enr_is_signed_and_survives_a_round_trip() {
        let record = build();
        assert!(record.verify_signature());

        let url = record.enr_url().unwrap();
        assert!(url.starts_with("enr:"));

        let decoded = NodeRecord::decode(&ethrex_common::base64::decode(
            url.strip_prefix("enr:").unwrap().as_bytes(),
        ))
        .unwrap();
        assert_eq!(decoded, record);
        assert_eq!(read_quic_port(&decoded), Some(9001));
    }

    #[test]
    fn local_enr_is_a_valid_discv5_node() {
        // ethrex's discovery stack turns records into Nodes; if that fails the
        // record can never be seeded or gossiped.
        let record = build();
        let node = Node::from_enr(&record).expect("Node::from_enr accepts our ENR");
        assert_eq!(node.udp_port, 9010);
    }
}
