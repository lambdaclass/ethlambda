//! Construction and reading of the ENR ethlambda publishes over discv5.
//!
//! The entry set follows the beacon-chain phase0 p2p spec's discovery domain:
//!
//! ```text
//! id, ip, udp=<discovery port>, quic=<libp2p QUIC port>, secp256k1,
//! eth2    = SSZ(ENRForkID)
//! attnets = subscribed attestation subnet bitfield
//! ```
//!
//! There is deliberately no `tcp` entry. The spec defines it as the libp2p TCP
//! listening port and makes it optional; ethlambda speaks QUIC only, so
//! advertising one would invite a dial that cannot succeed.

use std::collections::HashSet;
use std::net::IpAddr;

use bytes::Bytes;
use ethlambda_types::enr::{EnrForkId, encode_attnets};
use ethrex_common::H512;
use ethrex_p2p::types::{INITIAL_ENR_SEQ, Node, NodeRecord};
use ethrex_rlp::decode::RLPDecode;
use ethrex_rlp::encode::RLPEncode;
use libssz::SszEncode;
use secp256k1::{PublicKey, SecretKey};

pub const QUIC_ENR_KEY: &[u8] = b"quic";
pub const ETH2_ENR_KEY: &[u8] = b"eth2";
pub const ATTNETS_ENR_KEY: &[u8] = b"attnets";

/// Everything needed to build this node's ENR.
pub struct LocalEnrParams {
    pub signer: SecretKey,
    /// Address to advertise. discv5's PONG-based IP voting may replace it later.
    pub ip: IpAddr,
    /// UDP port the discv5 socket is bound to.
    pub discovery_port: u16,
    /// UDP port the libp2p QUIC transport is bound to.
    pub quic_port: u16,
    pub subscription_subnets: HashSet<u64>,
    pub attestation_committee_count: u64,
}

impl LocalEnrParams {
    /// The `Node` ethrex's discovery server takes as its local identity.
    ///
    /// `tcp_port` is 0, which ethrex reads as "no TCP listener" and omits from
    /// the record.
    pub fn local_node(&self) -> Node {
        let public_key = PublicKey::from_secret_key(secp256k1::SECP256K1, &self.signer);
        Node::new(
            self.ip,
            self.discovery_port,
            0,
            H512::from_slice(&public_key.serialize_uncompressed()[1..]),
        )
    }

    /// ENR entries outside the EIP-778 predefined dictionary. Values are
    /// RLP-encoded, matching how `NodeRecordPairs::other` is decoded.
    pub fn extra_pairs(&self) -> Vec<(Bytes, Bytes)> {
        let attnets = encode_attnets(&self.subscription_subnets, self.attestation_committee_count);
        vec![
            (
                Bytes::from_static(ATTNETS_ENR_KEY),
                // `Vec<u8>` has a generic `RLPEncode` impl that encodes it as
                // a *list* of individually-encoded byte scalars, not as a
                // byte string. Route through `Bytes`, whose `RLPEncode` impl
                // delegates to `[u8]` and produces the byte-string encoding
                // `read_extra`'s `Bytes::decode` expects.
                Bytes::from(Bytes::from(attnets).encode_to_vec()),
            ),
            (
                Bytes::from_static(ETH2_ENR_KEY),
                Bytes::from(Bytes::from(EnrForkId::local().to_ssz()).encode_to_vec()),
            ),
            (
                Bytes::from_static(QUIC_ENR_KEY),
                Bytes::from(self.quic_port.encode_to_vec()),
            ),
        ]
    }
}

/// Build and sign this node's ENR.
pub fn build_local_enr(params: &LocalEnrParams) -> Result<NodeRecord, String> {
    NodeRecord::from_node_with_extra_pairs(
        &params.local_node(),
        INITIAL_ENR_SEQ,
        &params.signer,
        params.extra_pairs(),
    )
    .map_err(|err| format!("failed to build local ENR: {err}"))
}

/// Read a non-dictionary entry's RLP-decoded byte payload.
pub fn read_extra(record: &NodeRecord, key: &[u8]) -> Option<Vec<u8>> {
    let (_, value) = record
        .pairs()
        .other
        .iter()
        .find(|(k, _)| k.as_ref() == key)?;
    Bytes::decode(value.as_ref()).ok().map(|b| b.to_vec())
}

/// The advertised libp2p QUIC port, if any.
pub fn read_quic_port(record: &NodeRecord) -> Option<u16> {
    let (_, value) = record
        .pairs()
        .other
        .iter()
        .find(|(k, _)| k.as_ref() == QUIC_ENR_KEY)?;
    u16::decode(value.as_ref()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_types::enr::{EnrForkId, decode_attnets};
    use ethrex_p2p::types::Node;
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
            subscription_subnets: HashSet::from([1u64, 4]),
            attestation_committee_count: 8,
        })
        .expect("ENR builds")
    }

    #[test]
    fn local_enr_advertises_udp_and_quic_but_no_tcp() {
        let record = build();
        let pairs = record.pairs();
        assert_eq!(pairs.udp_port, Some(9010));
        assert_eq!(
            pairs.tcp_port, None,
            "ethlambda has no TCP listener, so it must not advertise one"
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
