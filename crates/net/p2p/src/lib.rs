use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use ethlambda_blockchain::{BlockChain, OutboundGossip};
use ethrex_common::H264;
use ethrex_p2p::types::NodeRecord;
use ethrex_rlp::decode::RLPDecode;
use libp2p::{
    Multiaddr, PeerId, StreamProtocol,
    futures::StreamExt,
    gossipsub::{MessageAuthenticity, ValidationMode},
    identity::{PublicKey, secp256k1},
    multiaddr::Protocol,
    request_response,
    swarm::{NetworkBehaviour, SwarmEvent},
};
use sha2::Digest;
use ssz::Encode;
use tokio::sync::mpsc;
use tracing::{info, trace, warn};

use crate::{
    gossipsub::{ATTESTATION_TOPIC_KIND, BLOCK_TOPIC_KIND},
    messages::{
        MAX_COMPRESSED_PAYLOAD_SIZE,
        status::{STATUS_PROTOCOL_V1, Status},
    },
};

mod gossipsub;
mod messages;
pub mod metrics;

pub async fn start_p2p(
    node_key: Vec<u8>,
    bootnodes: Vec<Bootnode>,
    listening_socket: SocketAddr,
    blockchain: BlockChain,
    p2p_rx: mpsc::UnboundedReceiver<OutboundGossip>,
) {
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
        .message_id_fn(compute_message_id)
        // Taken from ream
        .max_transmit_size(MAX_COMPRESSED_PAYLOAD_SIZE)
        .max_messages_per_rpc(Some(500))
        .validate_messages()
        .allow_self_origin(true)
        .flood_publish(false)
        .idontwant_message_size_threshold(1000)
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

    let secret_key = secp256k1::SecretKey::try_from_bytes(node_key).expect("invalid node key");
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
    let local_peer_id = *swarm.local_peer_id();
    for bootnode in bootnodes {
        let peer_id = PeerId::from_public_key(&bootnode.public_key);
        if peer_id == local_peer_id {
            continue;
        }
        let addr = Multiaddr::empty()
            .with(bootnode.ip.into())
            .with(Protocol::Udp(bootnode.quic_port))
            .with(Protocol::QuicV1)
            .with_p2p(peer_id)
            .expect("failed to add peer ID to multiaddr");
        swarm.dial(addr).unwrap();
    }
    let addr = Multiaddr::empty()
        .with(listening_socket.ip().into())
        .with(Protocol::Udp(listening_socket.port()))
        .with(Protocol::QuicV1);
    swarm
        .listen_on(addr)
        .expect("failed to bind gossipsub listening address");

    let network = "devnet0";
    let topic_kinds = [BLOCK_TOPIC_KIND, ATTESTATION_TOPIC_KIND];
    for topic_kind in topic_kinds {
        let topic_str = format!("/leanconsensus/{network}/{topic_kind}/ssz_snappy");
        let topic = libp2p::gossipsub::IdentTopic::new(topic_str);
        swarm.behaviour_mut().gossipsub.subscribe(&topic).unwrap();
    }

    // Create topics for outbound messages
    let attestation_topic = libp2p::gossipsub::IdentTopic::new(format!(
        "/leanconsensus/{network}/{ATTESTATION_TOPIC_KIND}/ssz_snappy"
    ));
    let block_topic = libp2p::gossipsub::IdentTopic::new(format!(
        "/leanconsensus/{network}/{BLOCK_TOPIC_KIND}/ssz_snappy"
    ));

    info!("P2P node started on {listening_socket}");

    event_loop(swarm, blockchain, p2p_rx, attestation_topic, block_topic).await;
}

/// [libp2p Behaviour](libp2p::swarm::NetworkBehaviour) combining Gossipsub and Request-Response Behaviours
#[derive(NetworkBehaviour)]
struct Behaviour {
    gossipsub: libp2p::gossipsub::Behaviour,
    req_resp: request_response::Behaviour<messages::status::StatusCodec>,
}

/// Event loop for the P2P crate.
/// Processes swarm events, incoming requests, responses, gossip, and outgoing messages from blockchain.
async fn event_loop(
    mut swarm: libp2p::Swarm<Behaviour>,
    mut blockchain: BlockChain,
    mut p2p_rx: mpsc::UnboundedReceiver<OutboundGossip>,
    attestation_topic: libp2p::gossipsub::IdentTopic,
    block_topic: libp2p::gossipsub::IdentTopic,
) {
    loop {
        tokio::select! {
            biased;

            message = p2p_rx.recv() => {
                let Some(message) = message else {
                    break;
                };
                handle_outgoing_gossip(&mut swarm, message, &attestation_topic, &block_topic).await;
            }
            event = swarm.next() => {
                let Some(event) = event else {
                    break;
                };
                match event {
                    SwarmEvent::Behaviour(BehaviourEvent::ReqResp(
                        message @ request_response::Event::Message { .. },
                    )) => {
                        handle_req_resp_message(&mut swarm, message).await;
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(
                        message @ libp2p::gossipsub::Event::Message { .. },
                    )) => {
                        gossipsub::handle_gossipsub_message(&mut blockchain, message).await;
                    }
                    SwarmEvent::ConnectionEstablished {
                        peer_id,
                        endpoint,
                        num_established,
                        ..
                    } => {
                        let direction = connection_direction(&endpoint);
                        if num_established.get() == 1 {
                            metrics::notify_peer_connected(direction, "success");
                        }
                        info!(%peer_id, %direction, "Peer connected");
                    }
                    SwarmEvent::ConnectionClosed {
                        peer_id,
                        endpoint,
                        num_established,
                        cause,
                        ..
                    } => {
                        let direction = connection_direction(&endpoint);
                        let reason = match cause {
                            None => "remote_close",
                            Some(err) => {
                                // Categorize disconnection reasons
                                let err_str = err.to_string().to_lowercase();
                                if err_str.contains("timeout") || err_str.contains("timedout") || err_str.contains("keepalive") {
                                    "timeout"
                                } else if err_str.contains("reset") || err_str.contains("connectionreset") {
                                    "remote_close"
                                } else {
                                    "error"
                                }
                            }
                        };
                        if num_established == 0 {
                            metrics::notify_peer_disconnected(direction, reason);
                        }
                        info!(%peer_id, %direction, %reason, "Peer disconnected");
                    }
                    SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                        let result = if error.to_string().to_lowercase().contains("timed out") {
                            "timeout"
                        } else {
                            "error"
                        };
                        metrics::notify_peer_connected("outbound", result);
                        warn!(?peer_id, %error, "Outgoing connection error");
                    }
                    SwarmEvent::IncomingConnectionError { error, .. } => {
                        metrics::notify_peer_connected("inbound", "error");
                        warn!(%error, "Incoming connection error");
                    }
                    _ => {
                        trace!(?event, "Ignored swarm event");
                    }
                }
            }
        }
    }
}

async fn handle_outgoing_gossip(
    swarm: &mut libp2p::Swarm<Behaviour>,
    message: OutboundGossip,
    attestation_topic: &libp2p::gossipsub::IdentTopic,
    block_topic: &libp2p::gossipsub::IdentTopic,
) {
    match message {
        OutboundGossip::PublishAttestation(attestation) => {
            let slot = attestation.message.slot;
            let validator = attestation.validator_id;

            // Encode to SSZ
            let ssz_bytes = attestation.as_ssz_bytes();

            // Compress with raw snappy
            let compressed = gossipsub::compress_message(&ssz_bytes);

            // Publish to gossipsub
            let _ = swarm
                .behaviour_mut()
                .gossipsub
                .publish(attestation_topic.clone(), compressed)
                .inspect(|_| trace!(%slot, %validator, "Published attestation to gossipsub"))
                .inspect_err(|err| tracing::warn!(%slot, %validator, %err, "Failed to publish attestation to gossipsub"));
        }
        OutboundGossip::PublishBlock(signed_block) => {
            let slot = signed_block.message.block.slot;
            let proposer = signed_block.message.block.proposer_index;

            // Encode to SSZ
            let ssz_bytes = signed_block.as_ssz_bytes();

            // Compress with raw snappy
            let compressed = gossipsub::compress_message(&ssz_bytes);

            // Publish to gossipsub
            let _ = swarm
                .behaviour_mut()
                .gossipsub
                .publish(block_topic.clone(), compressed)
                .inspect(|_| info!(%slot, %proposer, "Published block to gossipsub"))
                .inspect_err(|err| tracing::warn!(%slot, %proposer, %err, "Failed to publish block to gossipsub"));
        }
    }
}

async fn handle_req_resp_message(
    swarm: &mut libp2p::Swarm<Behaviour>,
    event: request_response::Event<Status, Status>,
) {
    let request_response::Event::Message {
        peer,
        connection_id: _,
        message,
    } = event
    else {
        unreachable!("we already matched on event_loop");
    };
    match message {
        request_response::Message::Request {
            request_id: _,
            request,
            channel,
        } => {
            info!(finalized_slot=%request.finalized.slot, head_slot=%request.head.slot, "Received status request from peer {peer}");
            // TODO: send real status
            swarm
                .behaviour_mut()
                .req_resp
                .send_response(channel, request.clone())
                .unwrap();
            swarm.behaviour_mut().req_resp.send_request(&peer, request);
        }
        request_response::Message::Response {
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

pub fn parse_enrs(enrs: Vec<String>) -> Vec<Bootnode> {
    let mut bootnodes = vec![];

    // File is YAML, but we try to avoid pulling a full YAML parser just for this
    for enr_str in enrs {
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

fn connection_direction(endpoint: &libp2p::core::ConnectedPoint) -> &'static str {
    if endpoint.is_dialer() {
        "outbound"
    } else {
        "inbound"
    }
}

fn compute_message_id(message: &libp2p::gossipsub::Message) -> libp2p::gossipsub::MessageId {
    const MESSAGE_DOMAIN_INVALID_SNAPPY: [u8; 4] = [0x00, 0x00, 0x00, 0x00];
    const MESSAGE_DOMAIN_VALID_SNAPPY: [u8; 4] = [0x01, 0x00, 0x00, 0x00];

    let mut hasher = sha2::Sha256::new();
    let decompressed = snap::raw::Decoder::new().decompress_vec(&message.data);

    let (domain, data) = match decompressed.as_ref() {
        Ok(decompressed_data) => (MESSAGE_DOMAIN_VALID_SNAPPY, decompressed_data),
        Err(_) => (MESSAGE_DOMAIN_INVALID_SNAPPY, &message.data),
    };
    let topic = message.topic.as_str().as_bytes();
    let topic_len = (topic.len() as u64).to_be_bytes();
    hasher.update(domain);
    hasher.update(topic_len);
    hasher.update(topic);
    hasher.update(data);
    let hash = hasher.finalize();
    libp2p::gossipsub::MessageId(hash[..20].to_vec())
}
