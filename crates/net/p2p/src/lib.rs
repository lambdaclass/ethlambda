use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use ethlambda_network_api::{
    InitBlockChain, P2PToBlockChainRef,
    block_chain_to_p2p::{
        FetchBlock, PublishAggregatedAttestation, PublishAttestation, PublishBlock,
    },
};
use ethlambda_storage::Store;
use ethlambda_types::primitives::H256;
use ethrex_common::H264;
use ethrex_p2p::types::NodeRecord;
use ethrex_rlp::decode::RLPDecode;
use futures::StreamExt;
use libp2p::{
    Multiaddr, PeerId, StreamProtocol,
    gossipsub::{MessageAuthenticity, ValidationMode},
    identity::{PublicKey, secp256k1},
    multiaddr::Protocol,
    request_response::{self, OutboundRequestId},
    swarm::{NetworkBehaviour, SwarmEvent},
};
use sha2::Digest;
use spawned_concurrency::actor;
use spawned_concurrency::error::ActorError;
use spawned_concurrency::message::Message;
use spawned_concurrency::protocol;
use spawned_concurrency::tasks::{
    Actor, ActorRef, ActorStart, Context, Handler, send_after, spawn_listener,
};
use tracing::{info, trace, warn};

use crate::{
    gossipsub::{
        aggregation_topic, attestation_subnet_topic, block_topic, publish_aggregated_attestation,
        publish_attestation, publish_block,
    },
    req_resp::{
        BLOCKS_BY_ROOT_PROTOCOL_V1, Codec, MAX_COMPRESSED_PAYLOAD_SIZE, Request,
        STATUS_PROTOCOL_V1, build_status, fetch_block_from_peer,
    },
    swarm_adapter::SwarmHandle,
};

mod gossipsub;
pub mod metrics;
mod req_resp;
pub(crate) mod swarm_adapter;

pub use gossipsub::ForkDigest;
pub use metrics::populate_name_registry;

// 5ms, 10ms, 20ms, 40ms, 80ms, 160ms, 320ms, 640ms, 1280ms, 2560ms
const MAX_FETCH_RETRIES: u32 = 10;
const INITIAL_BACKOFF_MS: u64 = 5;
const BACKOFF_MULTIPLIER: u64 = 2;
const PEER_REDIAL_INTERVAL_SECS: u64 = 12;

pub(crate) struct PendingRequest {
    pub(crate) attempts: u32,
    pub(crate) failed_peers: HashSet<PeerId>,
}

// --- Swarm construction ---

/// [libp2p Behaviour](libp2p::swarm::NetworkBehaviour) combining Gossipsub and Request-Response Behaviours
#[derive(NetworkBehaviour)]
pub(crate) struct Behaviour {
    gossipsub: libp2p::gossipsub::Behaviour,
    req_resp: request_response::Behaviour<Codec>,
}

/// Configuration for building the libp2p swarm.
pub struct SwarmConfig {
    pub node_key: Vec<u8>,
    pub bootnodes: Vec<Bootnode>,
    pub listening_socket: SocketAddr,
    pub validator_ids: Vec<u64>,
    pub attestation_committee_count: u64,
    pub is_aggregator: bool,
    pub aggregate_subnet_ids: Option<Vec<u64>>,
    /// Fork digest embedded in all gossipsub topic strings.
    pub fork_digest: ForkDigest,
}

/// Result of building the swarm — contains all pieces needed to start the P2P actor.
pub struct BuiltSwarm {
    pub(crate) swarm: libp2p::Swarm<Behaviour>,
    pub(crate) attestation_topics: HashMap<u64, libp2p::gossipsub::IdentTopic>,
    pub(crate) attestation_committee_count: u64,
    pub(crate) block_topic: libp2p::gossipsub::IdentTopic,
    pub(crate) aggregation_topic: libp2p::gossipsub::IdentTopic,
    pub(crate) bootnode_addrs: HashMap<PeerId, Multiaddr>,
    pub(crate) is_aggregator: bool,
    pub(crate) fork_digest: ForkDigest,
}

/// Build and configure the libp2p swarm, dial bootnodes, subscribe to topics.
pub fn build_swarm(
    config: SwarmConfig,
) -> Result<BuiltSwarm, libp2p::gossipsub::SubscriptionError> {
    let gossipsub_config = libp2p::gossipsub::ConfigBuilder::default()
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
        .allow_self_origin(true)
        .idontwant_message_size_threshold(1000)
        .build()
        .expect("invalid gossipsub config");

    let gossipsub =
        libp2p::gossipsub::Behaviour::new(MessageAuthenticity::Anonymous, gossipsub_config)
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

    let secret_key =
        secp256k1::SecretKey::try_from_bytes(config.node_key).expect("invalid node key");
    let identity = libp2p::identity::Keypair::from(secp256k1::Keypair::from(secret_key));

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_quic()
        .with_behaviour(|_| behavior)
        .expect("failed to add behaviour to swarm")
        .with_swarm_config(|c| {
            // Disable idle connection timeout
            c.with_idle_connection_timeout(Duration::from_secs(u64::MAX))
        })
        .build();
    let local_peer_id = *swarm.local_peer_id();
    let mut bootnode_addrs = HashMap::new();
    for bootnode in config.bootnodes {
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
        .with(config.listening_socket.ip().into())
        .with(Protocol::Udp(config.listening_socket.port()))
        .with(Protocol::QuicV1);
    swarm
        .listen_on(addr)
        .expect("failed to bind gossipsub listening address");

    // Subscribe to block topic (all nodes)
    let block_topic = block_topic(&config.fork_digest);
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&block_topic)
        .unwrap();

    // Subscribe to aggregation topic (all validators)
    let aggregation_topic = aggregation_topic(&config.fork_digest);
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&aggregation_topic)
        .unwrap();

    // Aggregators subscribe to attestation subnets to receive unaggregated
    // attestations. Non-aggregators don't need to subscribe; they publish via
    // gossipsub fanout.
    if config.is_aggregator {
        let mut aggregate_subnets: HashSet<u64> = config
            .validator_ids
            .iter()
            .map(|vid| vid % config.attestation_committee_count)
            .collect();
        if let Some(ref explicit_ids) = config.aggregate_subnet_ids {
            aggregate_subnets.extend(explicit_ids);
        }
        // Aggregator with no validators and no explicit subnets: fallback to subnet 0
        if aggregate_subnets.is_empty() {
            aggregate_subnets.insert(0);
        }
        for &subnet_id in &aggregate_subnets {
            let topic = attestation_subnet_topic(&config.fork_digest, subnet_id);
            swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
            info!(subnet_id, "Subscribed to attestation subnet");
        }
    }

    // Build topic cache (avoids string allocation on every publish).
    // Includes validator subnets and any explicit aggregate_subnet_ids.
    let mut attestation_topics: HashMap<u64, libp2p::gossipsub::IdentTopic> = HashMap::new();
    for &vid in &config.validator_ids {
        let subnet_id = vid % config.attestation_committee_count;
        attestation_topics
            .entry(subnet_id)
            .or_insert_with(|| attestation_subnet_topic(&config.fork_digest, subnet_id));
    }
    if let Some(ref explicit_ids) = config.aggregate_subnet_ids {
        for &subnet_id in explicit_ids {
            attestation_topics
                .entry(subnet_id)
                .or_insert_with(|| attestation_subnet_topic(&config.fork_digest, subnet_id));
        }
    }

    let metric_subnet = attestation_topics.keys().copied().min().unwrap_or(0);
    metrics::set_attestation_committee_subnet(metric_subnet);

    info!(socket=%config.listening_socket, "P2P node started");

    Ok(BuiltSwarm {
        swarm,
        attestation_topics,
        attestation_committee_count: config.attestation_committee_count,
        block_topic,
        aggregation_topic,
        bootnode_addrs,
        is_aggregator: config.is_aggregator,
        fork_digest: config.fork_digest,
    })
}

// --- P2P Actor ---

/// Public handle to the P2P actor.
pub struct P2P {
    handle: ActorRef<P2PServer>,
}

impl P2P {
    /// Build swarm, start I/O adapter, spawn actor, and wire the swarm event stream.
    pub fn spawn(built: BuiltSwarm, store: Store) -> P2P {
        let (swarm_stream, swarm_handle) = swarm_adapter::start_swarm_adapter(built.swarm);

        let server = P2PServer {
            swarm_handle,
            store,
            blockchain: None,
            attestation_topics: built.attestation_topics,
            attestation_committee_count: built.attestation_committee_count,
            block_topic: built.block_topic,
            aggregation_topic: built.aggregation_topic,
            is_aggregator: built.is_aggregator,
            connected_peers: HashSet::new(),
            pending_requests: HashMap::new(),
            request_id_map: HashMap::new(),
            bootnode_addrs: built.bootnode_addrs,
            fork_digest: built.fork_digest,
        };
        let handle = server.start();
        spawn_listener(handle.context(), swarm_stream.map(WrappedSwarmEvent));
        P2P { handle }
    }

    pub fn actor_ref(&self) -> &ActorRef<P2PServer> {
        &self.handle
    }
}

/// Message wrapper for swarm events. Not part of the protocol because
/// `SwarmEvent` contains non-Clone types (e.g. `ResponseChannel`).
pub(crate) struct WrappedSwarmEvent(SwarmEvent<BehaviourEvent>);
impl Message for WrappedSwarmEvent {
    type Result = ();
}

/// P2P actor state.
pub struct P2PServer {
    pub(crate) swarm_handle: SwarmHandle,
    pub(crate) store: Store,

    // BlockChain protocol ref (set via InitBlockChain message)
    pub(crate) blockchain: Option<P2PToBlockChainRef>,

    pub(crate) attestation_topics: HashMap<u64, libp2p::gossipsub::IdentTopic>,
    pub(crate) attestation_committee_count: u64,
    pub(crate) block_topic: libp2p::gossipsub::IdentTopic,
    pub(crate) aggregation_topic: libp2p::gossipsub::IdentTopic,
    pub(crate) is_aggregator: bool,
    pub(crate) fork_digest: ForkDigest,

    pub(crate) connected_peers: HashSet<PeerId>,
    pub(crate) pending_requests: HashMap<H256, PendingRequest>,
    pub(crate) request_id_map: HashMap<OutboundRequestId, H256>,
    bootnode_addrs: HashMap<PeerId, Multiaddr>,
}

// Protocol trait for internal messages only (retry scheduling).
// Network-api messages and swarm events are handled via manual Handler impls.
#[protocol]
pub(crate) trait P2PProtocol: Send + Sync {
    #[allow(dead_code)] // invoked via send_after, not called directly
    fn retry_block_fetch(&self, root: H256) -> Result<(), ActorError>;
    #[allow(dead_code)] // invoked via send_after, not called directly
    fn retry_peer_redial(&self, peer_id: PeerId) -> Result<(), ActorError>;
}

#[actor(protocol = P2PProtocol)]
impl P2PServer {
    #[send_handler]
    async fn handle_retry_block_fetch(
        &mut self,
        msg: p2p_protocol::RetryBlockFetch,
        _ctx: &Context<Self>,
    ) {
        let root = msg.root;
        // Check if still pending (might have succeeded during backoff)
        if !self.pending_requests.contains_key(&root) {
            trace!(%root, "Block fetch completed during backoff, skipping retry");
            return;
        }

        info!(%root, "Retrying block fetch after backoff");

        if !fetch_block_from_peer(self, root).await {
            tracing::error!(%root, "Failed to retry block fetch, giving up");
            self.pending_requests.remove(&root);
        }
    }

    #[send_handler]
    async fn handle_retry_peer_redial(
        &mut self,
        msg: p2p_protocol::RetryPeerRedial,
        _ctx: &Context<Self>,
    ) {
        let peer_id = msg.peer_id;

        // Skip if already reconnected
        if self.connected_peers.contains(&peer_id) {
            trace!(%peer_id, "Bootnode reconnected during redial delay, skipping");
            return;
        }

        if let Some(addr) = self.bootnode_addrs.get(&peer_id) {
            info!(%peer_id, "Redialing disconnected bootnode");
            self.swarm_handle.dial(addr.clone());
        }
    }
}

// --- Manual Handler impls for network-api messages ---

impl Handler<InitBlockChain> for P2PServer {
    async fn handle(&mut self, msg: InitBlockChain, _ctx: &Context<Self>) {
        self.blockchain = Some(msg.blockchain);
        info!("BlockChain protocol ref initialized");
    }
}

impl Handler<PublishBlock> for P2PServer {
    async fn handle(&mut self, msg: PublishBlock, _ctx: &Context<Self>) {
        publish_block(self, msg.block).await;
    }
}

impl Handler<PublishAttestation> for P2PServer {
    async fn handle(&mut self, msg: PublishAttestation, _ctx: &Context<Self>) {
        publish_attestation(self, msg.attestation).await;
    }
}

impl Handler<PublishAggregatedAttestation> for P2PServer {
    async fn handle(&mut self, msg: PublishAggregatedAttestation, _ctx: &Context<Self>) {
        publish_aggregated_attestation(self, msg.attestation).await;
    }
}

impl Handler<FetchBlock> for P2PServer {
    async fn handle(&mut self, msg: FetchBlock, _ctx: &Context<Self>) {
        let root = msg.root;
        // Deduplicate - if already pending, ignore
        if self.pending_requests.contains_key(&root) {
            trace!(%root, "Block fetch already in progress, ignoring duplicate");
            return;
        }
        fetch_block_from_peer(self, root).await;
    }
}

// --- Manual Handler for swarm events ---

impl Handler<WrappedSwarmEvent> for P2PServer {
    async fn handle(&mut self, msg: WrappedSwarmEvent, ctx: &Context<Self>) {
        handle_swarm_event(self, msg.0, ctx).await;
    }
}

async fn handle_swarm_event(
    server: &mut P2PServer,
    event: SwarmEvent<BehaviourEvent>,
    ctx: &Context<P2PServer>,
) {
    match event {
        SwarmEvent::Behaviour(BehaviourEvent::ReqResp(req_resp_event)) => {
            req_resp::handle_req_resp_message(server, req_resp_event, ctx).await;
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
                    .swarm_handle
                    .send_request(
                        peer_id,
                        Request::Status(our_status),
                        libp2p::StreamProtocol::new(STATUS_PROTOCOL_V1),
                    )
                    .await;
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
                    send_after(
                        Duration::from_secs(PEER_REDIAL_INTERVAL_SECS),
                        ctx.clone(),
                        p2p_protocol::RetryPeerRedial { peer_id },
                    );
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
                send_after(
                    Duration::from_secs(PEER_REDIAL_INTERVAL_SECS),
                    ctx.clone(),
                    p2p_protocol::RetryPeerRedial { peer_id: pid },
                );
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

// --- Bootnode parsing ---

pub struct Bootnode {
    pub(crate) ip: IpAddr,
    pub(crate) quic_port: u16,
    pub(crate) public_key: PublicKey,
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

        let ipv4 = record
            .pairs
            .iter()
            .find(|(key, _)| key.as_ref() == b"ip")
            .map(|(_, bytes)| {
                IpAddr::from(Ipv4Addr::decode(bytes.as_ref()).expect("invalid IPv4 address"))
            });
        let ipv6 = record
            .pairs
            .iter()
            .find(|(key, _)| key.as_ref() == b"ip6")
            .map(|(_, bytes)| {
                IpAddr::from(Ipv6Addr::decode(bytes.as_ref()).expect("invalid IPv6 address"))
            });

        // Prefer IPv4 if both are present
        let ip = ipv4.or(ipv6).expect("node record missing IP address");

        bootnodes.push(Bootnode {
            ip,
            quic_port,
            public_key: public_key.into(),
        });
    }
    bootnodes
}

// --- Utility functions ---

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
    let decompressed = gossipsub::decompress_message(&message.data).ok();

    let (domain, data) = match decompressed.as_deref() {
        Some(data) => (MESSAGE_DOMAIN_VALID_SNAPPY, data),
        None => (MESSAGE_DOMAIN_INVALID_SNAPPY, message.data.as_slice()),
    };
    let topic = message.topic.as_str().as_bytes();
    let topic_len = (topic.len() as u64).to_le_bytes();
    hasher.update(domain);
    hasher.update(topic_len);
    hasher.update(topic);
    hasher.update(data);
    let hash = hasher.finalize();
    libp2p::gossipsub::MessageId(hash[..20].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_enrs_extracts_ip_port_and_public_key() {
        // Values taken from a local devnet run with lean-quickstart
        let enrs = vec![
            "enr:-IW4QGGifTt9ypyMtChDISUNX3z4z5iPdiEPOmBoILvnDuWIKbWVmKXxZERPnw0piQyaBNCENFEPoIi-vxsnsrBig9MBgmlkgnY0gmlwhH8AAAGEcXVpY4IjKYlzZWNwMjU2azGhAhMMnGF1rmIPQ9tWgqfkNmvsG-aIyc9EJU5JFo3Tegys".to_string(),
            "enr:-IW4QPjoNZjNpzdjOqAR2rGguVAWmqpNCUCfbr-pp3rr6Dk6YO2KK5VWARr7BGr8BdmGmG75cBeVC2buzvtQ_nEWLKEBgmlkgnY0gmlwhH8AAAGEcXVpY4IjKolzZWNwMjU2azGhA5_HplOwUZ8wpF4O3g4CBsjRMI6kQYT7ph5LkeKzLgTS".to_string(),
            "enr:-IW4QNQN_PFdTfuYLGmdAWNivEJLT2tSZtn5jdBOImvh0QlLAJ1p8wHvvfD7aOa1lH88oJ8ddGK_a_FWqAQT_QY4qdMBgmlkgnY0gmlwhH8AAAGEcXVpY4IjK4lzZWNwMjU2azGhA7NTxgfOmGE2EQa4HhsXxFOeHdTLYIc2MEBczymm9IUN".to_string(),
            "enr:-IW4QI9EXVDvUIxTrCV51Gs2RtpmZu71S7ZP7RRg1OoSBVvGFeXkc5WleBffXwTcWX1Qa9F_N6MhH28TsGFhXkMCGvUBgmlkgnY0gmlwhH8AAAGEcXVpY4IjL4lzZWNwMjU2azGhA6Dm1X9PyyCNAm3RUGcZtG5U3imbj_MDPU5CtPnpeaKS".to_string(),
        ];

        let bootnodes = parse_enrs(enrs);

        assert_eq!(bootnodes.len(), 4);

        // All ENRs encode 127.0.0.1 as the IPv4 address
        for bootnode in &bootnodes {
            assert_eq!(bootnode.ip, IpAddr::from(Ipv4Addr::LOCALHOST));
        }

        // Each ENR encodes a distinct QUIC port
        assert_eq!(bootnodes[0].quic_port, 9001);
        assert_eq!(bootnodes[1].quic_port, 9002);
        assert_eq!(bootnodes[2].quic_port, 9003);
        assert_eq!(bootnodes[3].quic_port, 9007);

        // Verify the secp256k1 public keys (33-byte compressed format)
        let expected_pubkeys: Vec<[u8; 33]> = vec![
            hex::decode("02130c9c6175ae620f43db5682a7e4366bec1be688c9cf44254e49168dd37a0cac")
                .unwrap()
                .try_into()
                .unwrap(),
            hex::decode("039fc7a653b0519f30a45e0ede0e0206c8d1308ea44184fba61e4b91e2b32e04d2")
                .unwrap()
                .try_into()
                .unwrap(),
            hex::decode("03b353c607ce9861361106b81e1b17c4539e1dd4cb60873630405ccf29a6f4850d")
                .unwrap()
                .try_into()
                .unwrap(),
            hex::decode("03a0e6d57f4fcb208d026dd1506719b46e54de299b8ff3033d4e42b4f9e979a292")
                .unwrap()
                .try_into()
                .unwrap(),
        ];

        for (bootnode, expected) in bootnodes.iter().zip(expected_pubkeys.iter()) {
            let secp_key = secp256k1::PublicKey::try_from_bytes(expected).unwrap();
            let expected_key: PublicKey = secp_key.into();
            assert_eq!(bootnode.public_key, expected_key);
        }
    }
}
