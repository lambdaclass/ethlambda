use std::{net::IpAddr, time::Duration};

use ethrex_common::H264;
use ethrex_p2p::types::NodeRecord;
use ethrex_rlp::decode::RLPDecode;
use libp2p::{
    Multiaddr, PeerId,
    gossipsub::{Behaviour, MessageAuthenticity, ValidationMode},
    identity::{PublicKey, secp256k1},
    multiaddr::Protocol,
};

pub fn start_p2p(bootnodes: Vec<Bootnode>, listening_port: u16) {
    let config = libp2p::gossipsub::ConfigBuilder::default()
        // d
        .mesh_n(8)
        // d_low
        .mesh_n_low(6)
        // d_high
        .mesh_n_high(12)
        // d_lazy
        .gossip_lazy(6)
        .heartbeat_interval(Duration::from_millis(700))
        .fanout_ttl(Duration::from_secs(60))
        .history_length(6)
        .history_gossip(3)
        // seen_ttl_secs = seconds_per_slot * justification_lookback_slots * 2
        .duplicate_cache_time(Duration::from_secs(4 * 3 * 2))
        .validation_mode(ValidationMode::Anonymous)
        .build()
        .expect("invalid gossipsub config");

    let behavior: Behaviour =
        libp2p::gossipsub::Behaviour::new(MessageAuthenticity::Anonymous, config)
            .expect("failed to initiate behaviour");

    // TODO: set peer scoring params

    // TODO: load identity from config or flag
    let secret_key = secp256k1::SecretKey::try_from_bytes(
        b")\x95PR\x9ay\xbc-\xce\x007G\xc5/\xb0c\x94e\xc8\x93\xe0\x0b\x04@\xacf\x14Mb^\x06j"
            .to_vec(),
    )
    .unwrap();
    let identity = libp2p::identity::Keypair::from(secp256k1::Keypair::from(secret_key));

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_quic()
        .with_behaviour(|_| behavior)
        .expect("failed to add behaviour to swarm")
        .build();
    for bootnode in bootnodes {
        let addr = Multiaddr::empty()
            .with(bootnode.ip.into())
            .with(Protocol::Udp(bootnode.quic_port))
            .with(Protocol::QuicV1)
            .with_p2p(PeerId::from_public_key(&bootnode.public_key))
            .expect("failed to add peer ID to multiaddr");
        swarm.dial(addr).unwrap();
    }
    let addr = Multiaddr::empty()
        .with("127.0.0.1".parse::<IpAddr>().unwrap().into())
        .with(Protocol::Udp(listening_port))
        .with(Protocol::QuicV1);
    swarm
        .listen_on(addr)
        .expect("failed to bind gossipsub listening address");

    println!("P2P node started on port {listening_port}");
}

pub struct Bootnode {
    ip: IpAddr,
    quic_port: u16,
    public_key: PublicKey,
}

pub fn parse_validators_file(bootnodes_path: &str) -> Vec<Bootnode> {
    let bootnodes_yaml =
        std::fs::read_to_string(bootnodes_path).expect("Failed to read validators.yaml");

    let mut bootnodes = vec![];

    // File is YAML, but we try to avoid pulling a full YAML parser just for this
    for line in bootnodes_yaml.lines() {
        let trimmed_line = line.trim();
        if trimmed_line.is_empty() {
            continue;
        }
        let enr_str = trimmed_line.strip_prefix("- ").unwrap();
        let base64_decoded = ethrex_common::base64::decode(&enr_str.as_bytes()[4..]);
        let record = NodeRecord::decode(&base64_decoded).unwrap();
        let (_, quic_port_bytes) = record
            .pairs
            .iter()
            .find(|(key, _)| key.as_ref() == b"quic")
            .expect("node doesn't support QUIC");

        let (_, public_key_rlp) = record
            .pairs
            .iter()
            .find(|(key, _)| key.as_ref() == b"secp256k1")
            .expect("node record missing public key");

        let public_key_bytes = H264::decode(public_key_rlp).unwrap();
        let public_key =
            libp2p::identity::secp256k1::PublicKey::try_from_bytes(public_key_bytes.as_bytes())
                .unwrap();

        let quic_port = u16::decode(quic_port_bytes.as_ref()).unwrap();
        bootnodes.push(Bootnode {
            ip: "127.0.0.1".parse().unwrap(),
            quic_port,
            public_key: public_key.into(),
        });
    }
    bootnodes
}
