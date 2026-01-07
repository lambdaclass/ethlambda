use std::{net::IpAddr, time::Duration};

use ethrex_common::H264;
use ethrex_p2p::types::NodeRecord;
use ethrex_rlp::decode::RLPDecode;
use libp2p::{
    Multiaddr, PeerId, StreamProtocol,
    futures::StreamExt,
    gossipsub::{self, MessageAuthenticity, ValidationMode},
    identity::{PublicKey, secp256k1},
    multiaddr::Protocol,
    request_response::{self, Event, Message},
    swarm::{NetworkBehaviour, SwarmEvent},
};
use tracing::{info, trace};

use crate::messages::status::{STATUS_PROTOCOL_V1, Status};

mod messages;

pub async fn start_p2p(bootnodes: Vec<Bootnode>, listening_port: u16) {
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

    // TODO: setup custom message ID function
    let gossipsub = libp2p::gossipsub::Behaviour::new(MessageAuthenticity::Anonymous, config)
        .expect("failed to initiate behaviour");
    let req_resp = request_response::Behaviour::new(
        vec![(
            StreamProtocol::new(STATUS_PROTOCOL_V1),
            request_response::ProtocolSupport::Full,
        )],
        Default::default(),
    );

    let behavior = Behaviour {
        gossipsub,
        req_resp,
    };

    // TODO: set peer scoring params

    // TODO: load identity from config or flag
    let secret_key = secp256k1::SecretKey::try_from_bytes(
        b")\x95PR\x9ay\xbc-\xce\x007G\xc5/\xb0c\x94e\xc8\x93\xe0\x0b\x04@\xacf\x14Mb^\x06j"
            .to_vec(),
    )
    .unwrap();
    let identity = libp2p::identity::Keypair::from(secp256k1::Keypair::from(secret_key));

    // TODO: implement Executor with spawned?
    // libp2p::swarm::Config::with_executor(executor)
    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_quic()
        .with_behaviour(|_| behavior)
        .expect("failed to add behaviour to swarm")
        .with_swarm_config(|config| {
            // Disable idle connection timeout
            config.with_idle_connection_timeout(Duration::from_secs(u64::MAX))
        })
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

    event_loop(swarm).await;
}

/// [libp2p Behaviour](libp2p::swarm::NetworkBehaviour) combining Gossipsub and Request-Response Behaviours
#[derive(NetworkBehaviour)]
struct Behaviour {
    gossipsub: gossipsub::Behaviour,
    req_resp: request_response::Behaviour<messages::status::StatusCodec>,
}

/// Event loop for the P2P crate.
/// Processes swarm events, including incoming requests, responses, and gossip.
async fn event_loop(mut swarm: libp2p::Swarm<Behaviour>) {
    while let Some(event) = swarm.next().await {
        match event {
            SwarmEvent::Behaviour(BehaviourEvent::ReqResp(message @ Event::Message { .. })) => {
                handle_req_resp_message(&mut swarm, message).await;
            }
            // SwarmEvent::Behaviour(BehaviourEvent::ReqResp(Event::Message {
            //     peer,
            //     connection_id,
            //     message:
            //         Message::Request {
            //             request_id,
            //             request,
            //             channel,
            //         },
            // })) => {
            //     info!(finalized_slot=%request.finalized.slot, head_slot=%request.head.slot, "Received status request from peer {peer}");
            // }
            _ => {
                trace!(?event, "Ignored swarm event");
            }
        }
    }
}

async fn handle_req_resp_message(
    swarm: &mut libp2p::Swarm<Behaviour>,
    event: Event<Status, Status>,
) {
    let Event::Message {
        peer,
        connection_id: _,
        message,
    } = event
    else {
        unreachable!("we already matched on event_loop");
    };
    match message {
        Message::Request {
            request_id: _,
            request,
            channel,
        } => {
            info!(finalized_slot=%request.finalized.slot, head_slot=%request.head.slot, "Received status request from peer {peer}");
            swarm
                .behaviour_mut()
                .req_resp
                .send_response(channel, request.clone())
                .unwrap();
            swarm.behaviour_mut().req_resp.send_request(&peer, request);
        }
        Message::Response {
            request_id: _,
            response,
        } => {
            info!(finalized_slot=%response.finalized.slot, head_slot=%response.head.slot, "Received status response from peer {peer}");
        }
    }
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
