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

use ethrex_p2p::types::{INITIAL_ENR_SEQ, Node, NodeRecord, NodeRecordPairs};
use ethrex_p2p::utils::{node_id, public_key_from_signing_key};
use libssz::SszEncode;
use secp256k1::SecretKey;

use super::DiscoveryError;

pub(crate) const QUIC_ENR_KEY: &[u8] = b"quic";
pub(crate) const ETH2_ENR_KEY: &[u8] = b"eth2";
pub(crate) const ATTNETS_ENR_KEY: &[u8] = b"attnets";
pub(crate) const CGC_ENR_KEY: &[u8] = b"cgc";

// The `eth2` entry's container, its two "no fork is planned" constants, and the
// lean fork digest. They live in `ethlambda-types` rather than here because the
// binary has to name the type to hand one in, and because the beacon wire
// computes its digest at startup from the fork schedule; re-exported at this
// module's old paths so every use site inside the crate is unchanged.
pub use ethlambda_types::enr::{EnrForkId, FAR_FUTURE_EPOCH, NEXT_FORK_VERSION, fork_digest};

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
/// [`rank_candidates`](super::admission::rank_candidates)
/// forever. A subnet we have no committee for cannot be useful to us regardless.
pub(crate) fn subnets_from_attnets(bits: &[u8], committee_count: u64) -> Vec<u64> {
    (0..committee_count)
        .filter(|subnet| {
            bits.get((subnet / 8) as usize)
                .is_some_and(|byte| byte & (1 << (subnet % 8)) != 0)
        })
        .collect()
}

/// The discv5 node id `node_key` derives, independent of any address or port.
///
/// `keccak256` of the uncompressed public key: exactly what
/// `LocalEnrParams::local_node`'s `Node::node_id()` computes for the same
/// key, since a peer derives our id the same way off the `secp256k1` entry we
/// publish. Exposed standalone so startup can learn what this node's own id
/// selects (its column custody) before an ENR or a swarm exists; it must stay
/// exactly the discovery server's own computation; a divergence here would
/// leave this node custodying one set while every peer expects another.
pub fn node_id_from_secret_key(node_key: &[u8]) -> Result<[u8; 32], DiscoveryError> {
    let signer = SecretKey::from_slice(node_key).map_err(DiscoveryError::NodeKey)?;
    Ok(node_id(&public_key_from_signing_key(&signer)).0)
}

/// The discv5 node id behind a libp2p [`PeerId`], or `None` when it cannot be
/// recovered from the id alone.
///
/// A peer's custody set is a function of its node id and its advertised
/// custody group count, and both sides have to compute the same one. The node
/// id is available without asking anyone: libp2p stores a public key of 42
/// bytes or fewer directly in the `PeerId`'s multihash rather than hashing it,
/// and a secp256k1 key is well inside that, so the key can be read back out
/// and put through the same `keccak256(uncompressed)` that
/// [`node_id_from_secret_key`] applies to our own.
///
/// `None` covers the two cases where that does not hold: a `PeerId` carrying a
/// real (hashed) multihash rather than an identity one, and a peer whose key
/// is not secp256k1. Neither can appear on a mainnet beacon peer, whose
/// identity the ENR's `secp256k1` entry defines, so a `None` here is a peer
/// whose custody simply stays unknown rather than an error worth failing on.
pub(crate) fn node_id_from_peer_id(peer_id: &libp2p::PeerId) -> Option<[u8; 32]> {
    const IDENTITY_MULTIHASH_CODE: u64 = 0x00;

    let multihash = peer_id.as_ref();
    if multihash.code() != IDENTITY_MULTIHASH_CODE {
        return None;
    }
    let public_key = libp2p::identity::PublicKey::try_decode_protobuf(multihash.digest()).ok()?;
    let compressed = public_key.try_into_secp256k1().ok()?.to_bytes();
    let uncompressed = secp256k1::PublicKey::from_slice(&compressed)
        .ok()?
        .serialize_uncompressed();
    // `serialize_uncompressed` leads with SEC1's 0x04 tag; the node id is over
    // the 64 coordinate bytes alone.
    Some(node_id(&ethrex_common::H512::from_slice(&uncompressed[1..])).0)
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
    /// The `eth2` entry to publish.
    ///
    /// Lean's is a compile-time constant, but the beacon wire computes its
    /// digest from the fork schedule and the anchor's genesis validators root
    /// at startup, so this cannot be reached for internally.
    pub(crate) fork_id: EnrForkId,
    /// The `cgc` entry to publish, or `None` to omit it.
    ///
    /// `Some(CUSTODY_REQUIREMENT)` on the beacon wire: it is the floor a peer
    /// may demand, and this node's actual custody only ever meets or exceeds
    /// it (`sampling_size` never samples fewer groups than that), so
    /// advertising it never overstates what this node stores and serves.
    /// `None` on lean, which has no data-availability domain.
    pub(crate) custody_group_count: Option<u64>,
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
        pairs.set_extra(ETH2_ENR_KEY, self.fork_id.to_ssz());
        if let Some(quic_port) = dialable_port(self.p2p_port) {
            pairs.set_extra_int(QUIC_ENR_KEY, quic_port.into());
        }
        if let Some(count) = self.custody_group_count {
            pairs.set_extra_int(CGC_ENR_KEY, count);
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
            fork_id: EnrForkId::local(),
            custody_group_count: None,
        })
        .expect("ENR builds")
    }

    #[test]
    fn node_id_from_secret_key_matches_the_discovery_servers_own_computation() {
        // If this function ever computed a different id than `local_node`'s
        // `Node::node_id()`, a node would custody one set of columns while
        // every peer, reading the ENR `local_node` feeds the discovery
        // server, computed a different set for it. Nothing else would catch
        // that: the columns would simply go unserved.
        let signer = secp256k1::SecretKey::new(&mut rand::rngs::OsRng);
        let params = LocalEnrParams {
            signer,
            ip: IpAddr::from(Ipv4Addr::LOCALHOST),
            discovery_port: 9010,
            p2p_port: 9001,
            subscription_subnets: HashSet::new(),
            attestation_committee_count: 64,
            fork_id: EnrForkId::local(),
            custody_group_count: None,
        };
        let expected = params.local_node().node_id().0;
        assert_eq!(
            node_id_from_secret_key(&signer.secret_bytes()).expect("a valid key"),
            expected
        );
    }

    #[test]
    fn node_id_from_peer_id_agrees_with_the_key_it_was_built_from() {
        // The two derivations have to land on the same id: this node computes
        // its own custody from the secret key, and computes a *peer's* from
        // the PeerId that key produces. A divergence would mean asking peers
        // for the columns they are not the ones custodying, silently, with
        // every request simply coming back empty.
        let signer = secp256k1::SecretKey::new(&mut rand::rngs::OsRng);
        let keypair = libp2p::identity::secp256k1::SecretKey::try_from_bytes(
            &mut signer.secret_bytes().clone(),
        )
        .map(libp2p::identity::secp256k1::Keypair::from)
        .expect("a valid key");
        let peer_id = libp2p::identity::Keypair::from(keypair)
            .public()
            .to_peer_id();

        assert_eq!(
            node_id_from_peer_id(&peer_id),
            Some(node_id_from_secret_key(&signer.secret_bytes()).expect("a valid key"))
        );
    }

    #[test]
    fn node_id_from_peer_id_declines_a_key_it_cannot_read() {
        // An ed25519 identity is not a secp256k1 one, so no node id can be
        // computed for it. This must stay a `None` rather than a wrong answer:
        // the caller treats unknown custody as "ask someone else", which is
        // safe, where a fabricated id would send requests nobody can answer.
        let peer_id = libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id();

        assert_eq!(node_id_from_peer_id(&peer_id), None);
    }

    #[test]
    fn the_published_fork_id_is_the_one_supplied() {
        // Lean's is a compile-time constant, but the beacon wire computes its
        // digest from the fork schedule at startup, so the ENR builder must not
        // reach for EnrForkId::local() behind the caller's back.
        let supplied = EnrForkId {
            fork_digest: [0x8c, 0x9f, 0x62, 0xfe],
            next_fork_version: [0x06, 0x00, 0x00, 0x00],
            next_fork_epoch: FAR_FUTURE_EPOCH,
        };
        let record = build_local_enr(&LocalEnrParams {
            signer: secp256k1::SecretKey::new(&mut rand::rngs::OsRng),
            ip: IpAddr::from(Ipv4Addr::LOCALHOST),
            discovery_port: 9010,
            p2p_port: 9001,
            subscription_subnets: HashSet::new(),
            attestation_committee_count: 64,
            fork_id: supplied,
            custody_group_count: None,
        })
        .expect("ENR builds");

        let raw = record
            .pairs()
            .extra(ETH2_ENR_KEY)
            .expect("eth2 entry present");
        assert_eq!(EnrForkId::from_ssz_bytes(&raw).unwrap(), supplied);
    }

    #[test]
    fn the_custody_group_count_is_published_only_when_asked_for() {
        // Lean has no data-availability domain, so publishing a cgc there would
        // advertise a claim with no meaning behind it.
        let record = build();
        assert_eq!(record.pairs().extra(CGC_ENR_KEY), None);

        let with_cgc = build_local_enr(&LocalEnrParams {
            signer: secp256k1::SecretKey::new(&mut rand::rngs::OsRng),
            ip: IpAddr::from(Ipv4Addr::LOCALHOST),
            discovery_port: 9010,
            p2p_port: 9001,
            subscription_subnets: HashSet::new(),
            attestation_committee_count: 64,
            fork_id: EnrForkId::local(),
            custody_group_count: Some(4),
        })
        .expect("ENR builds");
        assert_eq!(with_cgc.pairs().extra_int::<u64>(CGC_ENR_KEY), Some(4));
    }

    #[test]
    fn a_sixty_four_wide_attnets_is_eight_bytes_of_zeroes() {
        // What a node subscribing to no attestation subnet actually serves.
        // Publishing a shorter bitfield would be a different claim: readers
        // treat bits past the end as unset, but the beacon spec's attnets is a
        // fixed-width Bitvector and a short one is malformed to a strict reader.
        let record = build_local_enr(&LocalEnrParams {
            signer: secp256k1::SecretKey::new(&mut rand::rngs::OsRng),
            ip: IpAddr::from(Ipv4Addr::LOCALHOST),
            discovery_port: 9010,
            p2p_port: 9001,
            subscription_subnets: HashSet::new(),
            attestation_committee_count: 64,
            fork_id: EnrForkId::local(),
            custody_group_count: Some(4),
        })
        .expect("ENR builds");
        assert_eq!(
            record.pairs().extra(ATTNETS_ENR_KEY).as_deref(),
            Some(&[0u8; 8][..])
        );
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
            fork_id: EnrForkId::local(),
            custody_group_count: None,
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
