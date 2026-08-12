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
//! now binds one alongside QUIC (see `crates/net/p2p/src/lib.rs`'s
//! `build_swarm`), on the same port number, so advertising it is what lets a
//! peer whose advertised `quic` does not answer still reach us.

use std::collections::HashSet;
use std::net::IpAddr;

use ethlambda_types::enr::{EnrForkId, encode_attnets};
use ethrex_common::H512;
use ethrex_p2p::types::{INITIAL_ENR_SEQ, Node, NodeRecord, NodeRecordPairs};
use libssz::SszEncode;
use secp256k1::{PublicKey, SecretKey};

pub const QUIC_ENR_KEY: &[u8] = b"quic";
pub const ETH2_ENR_KEY: &[u8] = b"eth2";
pub const ATTNETS_ENR_KEY: &[u8] = b"attnets";
pub const CGC_ENR_KEY: &[u8] = b"cgc";

/// Everything needed to build this node's ENR.
pub struct LocalEnrParams {
    pub signer: SecretKey,
    /// Address to advertise. discv5's PONG-based IP voting may replace it later.
    pub ip: IpAddr,
    /// UDP port the discv5 socket is bound to.
    pub discovery_port: u16,
    /// UDP port the libp2p QUIC transport is bound to.
    pub quic_port: u16,
    /// TCP port the libp2p TCP transport is bound to. The same port number as
    /// [`Self::quic_port`]: TCP and UDP are separate namespaces, so `build_swarm`
    /// binds both without a collision.
    pub tcp_port: u16,
    pub subscription_subnets: HashSet<u64>,
    pub attestation_committee_count: u64,
    /// The `eth2` entry to publish.
    ///
    /// Lean's is a compile-time constant, but the beacon wire computes its
    /// digest from the fork schedule and the anchor's genesis validators root
    /// at startup, so this cannot be reached for internally.
    pub fork_id: EnrForkId,
    /// The `cgc` entry to publish, or `None` to omit it.
    ///
    /// `Some(CUSTODY_REQUIREMENT)` on the beacon wire, even though nothing is
    /// custodied yet: peers may reject a lower value outright, which would
    /// defeat the mode. `None` on lean, which has no data-availability domain.
    pub custody_group_count: Option<u64>,
}

impl LocalEnrParams {
    /// The `Node` ethrex's discovery server takes as its local identity.
    ///
    /// `tcp_port` is the real port the libp2p TCP transport is bound to, now
    /// that ethlambda has one.
    pub fn local_node(&self) -> Node {
        let public_key = PublicKey::from_secret_key(secp256k1::SECP256K1, &self.signer);
        Node::new(
            self.ip,
            self.discovery_port,
            self.tcp_port,
            H512::from_slice(&public_key.serialize_uncompressed()[1..]),
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
    pub fn local_pairs(&self) -> NodeRecordPairs {
        let mut pairs = NodeRecordPairs {
            udp_port: Some(self.discovery_port),
            tcp_port: Some(self.tcp_port),
            ..Default::default()
        };
        match self.ip.to_canonical() {
            IpAddr::V4(ip) => pairs.ip = Some(ip),
            IpAddr::V6(ip) => pairs.ip6 = Some(ip),
        }

        let attnets = encode_attnets(&self.subscription_subnets, self.attestation_committee_count);
        pairs.set_extra(ATTNETS_ENR_KEY, attnets);
        pairs.set_extra(ETH2_ENR_KEY, self.fork_id.to_ssz());
        pairs.set_extra_int(QUIC_ENR_KEY, self.quic_port);
        if let Some(count) = self.custody_group_count {
            pairs.set_extra_int(CGC_ENR_KEY, count);
        }
        pairs
    }
}

/// Build and sign this node's ENR.
pub fn build_local_enr(params: &LocalEnrParams) -> Result<NodeRecord, String> {
    NodeRecord::from_pairs(INITIAL_ENR_SEQ, &params.signer, params.local_pairs())
        .map_err(|err| format!("failed to build local ENR: {err}"))
}

/// Read a non-dictionary entry's RLP-decoded byte payload.
pub fn read_extra(record: &NodeRecord, key: &[u8]) -> Option<Vec<u8>> {
    record.pairs().extra(key).map(|value| value.to_vec())
}

/// The advertised libp2p QUIC port, if any.
pub fn read_quic_port(record: &NodeRecord) -> Option<u16> {
    record.pairs().extra_int::<u16>(QUIC_ENR_KEY)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_types::enr::{EnrForkId, decode_attnets};
    use ethrex_p2p::types::Node;
    use ethrex_rlp::decode::RLPDecode as _;
    use libssz::SszDecode;
    use std::collections::HashSet;
    use std::net::Ipv4Addr;

    fn test_signer() -> secp256k1::SecretKey {
        secp256k1::SecretKey::new(&mut rand::rngs::OsRng)
    }

    fn build() -> NodeRecord {
        build_local_enr(&LocalEnrParams {
            signer: test_signer(),
            ip: IpAddr::from(Ipv4Addr::LOCALHOST),
            discovery_port: 9010,
            quic_port: 9001,
            tcp_port: 9001,
            subscription_subnets: HashSet::from([1u64, 4]),
            attestation_committee_count: 8,
            fork_id: EnrForkId::local(),
            custody_group_count: None,
        })
        .expect("ENR builds")
    }

    #[test]
    fn the_published_fork_id_is_the_one_supplied() {
        // Lean's is a compile-time constant, but the beacon wire computes its
        // digest from the fork schedule at startup, so the ENR builder must not
        // reach for EnrForkId::local() behind the caller's back.
        let supplied = EnrForkId {
            fork_digest: [0x8c, 0x9f, 0x62, 0xfe],
            next_fork_version: [0x06, 0x00, 0x00, 0x00],
            next_fork_epoch: u64::MAX,
        };
        let record = build_local_enr(&LocalEnrParams {
            signer: test_signer(),
            ip: IpAddr::from(Ipv4Addr::LOCALHOST),
            discovery_port: 9010,
            quic_port: 9001,
            tcp_port: 9001,
            subscription_subnets: HashSet::new(),
            attestation_committee_count: 64,
            fork_id: supplied,
            custody_group_count: None,
        })
        .expect("ENR builds");

        let raw = read_extra(&record, ETH2_ENR_KEY).expect("eth2 entry present");
        assert_eq!(EnrForkId::from_ssz_bytes(&raw).unwrap(), supplied);
    }

    #[test]
    fn the_custody_group_count_is_published_only_when_asked_for() {
        // Lean has no data-availability domain, so publishing a cgc there would
        // advertise a claim with no meaning behind it.
        let record = build();
        assert_eq!(read_extra(&record, CGC_ENR_KEY), None);

        let with_cgc = build_local_enr(&LocalEnrParams {
            signer: test_signer(),
            ip: IpAddr::from(Ipv4Addr::LOCALHOST),
            discovery_port: 9010,
            quic_port: 9001,
            tcp_port: 9001,
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
            signer: test_signer(),
            ip: IpAddr::from(Ipv4Addr::LOCALHOST),
            discovery_port: 9010,
            quic_port: 9001,
            tcp_port: 9001,
            subscription_subnets: HashSet::new(),
            attestation_committee_count: 64,
            fork_id: EnrForkId::local(),
            custody_group_count: Some(4),
        })
        .expect("ENR builds");
        assert_eq!(read_extra(&record, ATTNETS_ENR_KEY), Some(vec![0u8; 8]));
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

    #[test]
    fn local_enr_carries_the_fork_id() {
        let record = build();
        let raw = read_extra(&record, b"eth2").expect("eth2 entry present");
        assert_eq!(EnrForkId::from_ssz_bytes(&raw).unwrap(), EnrForkId::local());
    }

    #[test]
    fn local_enr_carries_the_subscribed_subnets() {
        let record = build();
        let raw = read_extra(&record, b"attnets").expect("attnets entry present");
        assert_eq!(decode_attnets(&raw), vec![1, 4]);
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
