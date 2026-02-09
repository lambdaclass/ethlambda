use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use ethlambda_blockchain::{BlockChain, P2PMessage};
use ethlambda_storage::Store;
use ethlambda_types::primitives::H256;
use ethrex_common::H264;
use ethrex_p2p::types::NodeRecord;
use ethrex_rlp::decode::RLPDecode;
use libp2p::{
    Multiaddr, PeerId, StreamProtocol,
    futures::StreamExt,
    gossipsub::{MessageAuthenticity, ValidationMode},
    identity::{PublicKey, secp256k1},
    multiaddr::Protocol,
    request_response::{self, OutboundRequestId},
    swarm::{NetworkBehaviour, SwarmEvent},
};
use sha2::Digest;
use tokio::sync::mpsc;
use tracing::{info, trace, warn};

use crate::{
    gossipsub::{ATTESTATION_TOPIC_KIND, BLOCK_TOPIC_KIND, publish_attestation, publish_block},
    req_resp::{
        BLOCKS_BY_ROOT_PROTOCOL_V1, Codec, MAX_COMPRESSED_PAYLOAD_SIZE, Request,
        STATUS_PROTOCOL_V1, build_status, fetch_block_from_peer,
    },
};

mod gossipsub;
pub mod metrics;
mod req_resp;

pub use metrics::populate_name_registry;

// 10ms, 40ms, 160ms, 640ms, 2560ms
const MAX_FETCH_RETRIES: u32 = 5;
const INITIAL_BACKOFF_MS: u64 = 10;
const BACKOFF_MULTIPLIER: u64 = 4;
const PEER_REDIAL_INTERVAL_SECS: u64 = 12;

enum RetryMessage {
    BlockFetch(H256),
    PeerRedial(PeerId),
}

pub(crate) struct PendingRequest {
    pub(crate) attempts: u32,
    pub(crate) last_peer: Option<PeerId>,
}

pub async fn start_p2p(
    node_key: Vec<u8>,
    bootnodes: Vec<Bootnode>,
    listening_socket: SocketAddr,
    blockchain: BlockChain,
    p2p_rx: mpsc::UnboundedReceiver<P2PMessage>,
    store: Store,
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

    let gossipsub = libp2p::gossipsub::Behaviour::new(MessageAuthenticity::Anonymous, config)
        .expect("failed to initiate behaviour");

    let req_resp = request_response::Behaviour::new(
        vec![
            (
                StreamProtocol::new(STATUS_PROTOCOL_V1),
                request_response::ProtocolSupport::Full,
            ),
            (
                StreamProtocol::new(BLOCKS_BY_ROOT_PROTOCOL_V1),
                request_response::ProtocolSupport::Full,
            ),
        ],
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
    let mut bootnode_addrs = HashMap::new();
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
        bootnode_addrs.insert(peer_id, addr.clone());
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

    info!(socket=%listening_socket, "P2P node started");

    let (retry_tx, retry_rx) = mpsc::unbounded_channel();

    let server = P2PServer {
        swarm,
        blockchain,
        store,
        p2p_rx,
        attestation_topic,
        block_topic,
        connected_peers: HashSet::new(),
        pending_requests: HashMap::new(),
        request_id_map: HashMap::new(),
        bootnode_addrs,
        retry_tx,
        retry_rx,
    };

    event_loop(server).await;
}

/// [libp2p Behaviour](libp2p::swarm::NetworkBehaviour) combining Gossipsub and Request-Response Behaviours
#[derive(NetworkBehaviour)]
pub(crate) struct Behaviour {
    gossipsub: libp2p::gossipsub::Behaviour,
    req_resp: request_response::Behaviour<Codec>,
}

pub(crate) struct P2PServer {
    pub(crate) swarm: libp2p::Swarm<Behaviour>,
    pub(crate) blockchain: BlockChain,
    pub(crate) store: Store,
    pub(crate) p2p_rx: mpsc::UnboundedReceiver<P2PMessage>,
    pub(crate) attestation_topic: libp2p::gossipsub::IdentTopic,
    pub(crate) block_topic: libp2p::gossipsub::IdentTopic,
    pub(crate) connected_peers: HashSet<PeerId>,
    pub(crate) pending_requests: HashMap<ethlambda_types::primitives::H256, PendingRequest>,
    pub(crate) request_id_map: HashMap<OutboundRequestId, ethlambda_types::primitives::H256>,
    /// Bootnode addresses for redialing when disconnected
    bootnode_addrs: HashMap<PeerId, Multiaddr>,
    /// Channel for scheduling retries (block fetches and peer redials)
    pub(crate) retry_tx: mpsc::UnboundedSender<RetryMessage>,
    retry_rx: mpsc::UnboundedReceiver<RetryMessage>,
}

/// Event loop for the P2P crate.
/// Processes swarm events, incoming requests, responses, gossip, and outgoing messages from blockchain.
async fn event_loop(mut server: P2PServer) {
    loop {
        tokio::select! {
            biased;

            message = server.p2p_rx.recv() => {
                let Some(message) = message else {
                    break;
                };
                handle_p2p_message(&mut server, message).await;
            }
            event = server.swarm.next() => {
                let Some(event) = event else {
                    break;
                };
                handle_swarm_event(&mut server, event).await;
            }
            Some(msg) = server.retry_rx.recv() => {
                match msg {
                    RetryMessage::BlockFetch(root) => handle_retry(&mut server, root).await,
                    RetryMessage::PeerRedial(peer_id) => handle_peer_redial(&mut server, peer_id).await,
                }
            }
        }
    }
}

async fn handle_swarm_event(server: &mut P2PServer, event: SwarmEvent<BehaviourEvent>) {
    match event {
        SwarmEvent::Behaviour(BehaviourEvent::ReqResp(req_resp_event)) => {
            req_resp::handle_req_resp_message(server, req_resp_event).await;
        }
        SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(
            message @ libp2p::gossipsub::Event::Message { .. },
        )) => {
            gossipsub::handle_gossipsub_message(server, message).await;
        }
        SwarmEvent::ConnectionEstablished {
            peer_id,
            endpoint,
            num_established,
            ..
        } => {
            let direction = connection_direction(&endpoint);
            if num_established.get() == 1 {
                server.connected_peers.insert(peer_id);
                let peer_count = server.connected_peers.len();
                metrics::notify_peer_connected(&Some(peer_id), direction, "success");
                // Send status request on first connection to this peer
                let our_status = build_status(&server.store);
                let our_finalized_slot = our_status.finalized.slot;
                let our_head_slot = our_status.head.slot;
                info!(
                    %peer_id,
                    %direction,
                    peer_count,
                    our_finalized_slot,
                    our_head_slot,
                    "Peer connected"
                );
                server
                    .swarm
                    .behaviour_mut()
                    .req_resp
                    .send_request_with_protocol(
                        &peer_id,
                        Request::Status(our_status),
                        libp2p::StreamProtocol::new(STATUS_PROTOCOL_V1),
                    );
            } else {
                info!(%peer_id, %direction, "Added peer connection");
            }
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
                    if err_str.contains("timeout")
                        || err_str.contains("timedout")
                        || err_str.contains("keepalive")
                    {
                        "timeout"
                    } else if err_str.contains("reset") || err_str.contains("connectionreset") {
                        "remote_close"
                    } else {
                        "error"
                    }
                }
            };
            if num_established == 0 {
                server.connected_peers.remove(&peer_id);
                let peer_count = server.connected_peers.len();
                metrics::notify_peer_disconnected(&Some(peer_id), direction, reason);

                info!(
                    %peer_id,
                    %direction,
                    %reason,
                    peer_count,
                    "Peer disconnected"
                );

                // Schedule redial if this is a bootnode
                if server.bootnode_addrs.contains_key(&peer_id) {
                    schedule_peer_redial(server.retry_tx.clone(), peer_id);
                    info!(%peer_id, "Scheduled bootnode redial in {}s", PEER_REDIAL_INTERVAL_SECS);
                }
            } else {
                info!(%peer_id, %direction, %reason, "Peer connection closed but other connections remain");
            }
        }
        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            let result = if error.to_string().to_lowercase().contains("timed out") {
                "timeout"
            } else {
                "error"
            };
            metrics::notify_peer_connected(&peer_id, "outbound", result);
            warn!(?peer_id, %error, "Outgoing connection error");

            // Schedule redial if this was a bootnode
            if let Some(pid) = peer_id
                && server.bootnode_addrs.contains_key(&pid)
                && !server.connected_peers.contains(&pid)
            {
                schedule_peer_redial(server.retry_tx.clone(), pid);
                info!(%pid, "Scheduled bootnode redial after connection error");
            }
        }
        SwarmEvent::IncomingConnectionError { peer_id, error, .. } => {
            metrics::notify_peer_connected(&peer_id, "inbound", "error");
            warn!(%error, "Incoming connection error");
        }
        _ => {
            trace!(?event, "Ignored swarm event");
        }
    }
}

async fn handle_p2p_message(server: &mut P2PServer, message: P2PMessage) {
    match message {
        P2PMessage::PublishAttestation(attestation) => {
            publish_attestation(server, attestation).await;
        }
        P2PMessage::PublishBlock(signed_block) => {
            publish_block(server, signed_block).await;
        }
        P2PMessage::FetchBlock(root) => {
            // Deduplicate - if already pending, ignore
            if server.pending_requests.contains_key(&root) {
                trace!(%root, "Block fetch already in progress, ignoring duplicate");
                return;
            }

            // Send request and track it (tracking handled internally by fetch_block_from_peer)
            fetch_block_from_peer(server, root).await;
        }
    }
}

async fn handle_retry(server: &mut P2PServer, root: H256) {
    // Check if still pending (might have succeeded during backoff)
    if !server.pending_requests.contains_key(&root) {
        trace!(%root, "Block fetch completed during backoff, skipping retry");
        return;
    }

    info!(%root, "Retrying block fetch after backoff");

    // Retry the fetch (tracking handled internally by fetch_block_from_peer)
    if !fetch_block_from_peer(server, root).await {
        tracing::error!(%root, "Failed to retry block fetch, giving up");
        server.pending_requests.remove(&root);
    }
}

async fn handle_peer_redial(server: &mut P2PServer, peer_id: PeerId) {
    // Skip if already reconnected
    if server.connected_peers.contains(&peer_id) {
        trace!(%peer_id, "Bootnode reconnected during redial delay, skipping");
        return;
    }

    if let Some(addr) = server.bootnode_addrs.get(&peer_id) {
        info!(%peer_id, "Redialing disconnected bootnode");
        // NOTE: this dial does some checks and adds a pending outbound connection attempt.
        // It does NOT block. If the dial fails, we'll later get an OutgoingConnectionError event.
        let _ = server.swarm.dial(addr.clone()).inspect_err(|e| {
            warn!(%peer_id, %e, "Failed to redial bootnode, will retry");
            // Schedule another redial attempt
            schedule_peer_redial(server.retry_tx.clone(), peer_id);
        });
    }
}

/// Schedules a peer redial after the configured delay interval.
pub(crate) fn schedule_peer_redial(retry_tx: mpsc::UnboundedSender<RetryMessage>, peer_id: PeerId) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(PEER_REDIAL_INTERVAL_SECS)).await;
        let _ = retry_tx.send(RetryMessage::PeerRedial(peer_id));
    });
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

        // TODO: support IPv6
        let (_, ip_bytes) = record
            .pairs
            .iter()
            .find(|(key, _)| key.as_ref() == b"ip")
            .expect("node record missing IP address");
        let ip_octets: [u8; 4] = ip_bytes.as_ref().try_into().expect("invalid IPv4 address");
        let ip = IpAddr::from(Ipv4Addr::from(ip_octets));

        bootnodes.push(Bootnode {
            ip,
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
