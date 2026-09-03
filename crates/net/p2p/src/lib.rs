use std::{
    collections::{HashMap, HashSet, hash_map::Entry},
    net::{IpAddr, SocketAddr},
    ops::Range,
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
use ethrex_p2p::types::NodeRecord;
use ethrex_rlp::decode::RLPDecode;
use futures::{StreamExt, future::OptionFuture};
use libp2p::{
    Multiaddr, StreamProtocol,
    gossipsub::{MessageAuthenticity, ValidationMode},
    identity::{Keypair, PublicKey, secp256k1},
    multiaddr::Protocol,
    request_response::{self, OutboundRequestId},
    swarm::{NetworkBehaviour, SwarmEvent, dial_opts::DialOpts},
};
use sha2::Digest;
use spawned_concurrency::actor;
use spawned_concurrency::error::ActorError;
use spawned_concurrency::message::Message;
use spawned_concurrency::protocol;
use spawned_concurrency::tasks::{
    Actor, ActorRef, ActorStart, Context, Handler, send_after, spawn_listener,
};
use tracing::{debug, info, trace, warn};

use crate::{
    discovery::{
        DISCOVERY_DIAL_INTERVAL, DiscoveryError, DiscoverySpawnConfig,
        dial::{DiscoveryState, dial_tick, forget_discovered_peer},
        enr::{dialable_port, read_ip, read_public_key, read_quic_port, read_tcp_port},
        spawn_discovery,
    },
    gossipsub::{
        aggregation_topic, attestation_subnet_topic, block_topic, publish_aggregated_attestation,
        publish_attestation, publish_block,
    },
    req_resp::{
        BLOCKS_BY_RANGE_PROTOCOL_V1, BLOCKS_BY_ROOT_PROTOCOL_V1, Codec,
        MAX_COMPRESSED_PAYLOAD_SIZE, MAX_REQUEST_BLOCKS, Request, STATUS_PROTOCOL_V1, build_status,
        fetch_block_from_peer,
    },
    swarm_adapter::SwarmHandle,
};

pub mod discovery;
mod gossipsub;
pub mod metrics;
mod req_resp;
pub(crate) mod swarm_adapter;

pub use libp2p::PeerId;

// 5ms, 10ms, 20ms, 40ms, 80ms, 160ms, 320ms, 640ms, 1280ms, 2560ms
const MAX_FETCH_RETRIES: u32 = 10;
const INITIAL_BACKOFF_MS: u64 = 5;
const BACKOFF_MULTIPLIER: u64 = 2;
const PEER_REDIAL_INTERVAL_SECS: u64 = 12;
const MAX_SYNC_RANGE: u64 = MAX_REQUEST_BLOCKS * 64; // 65,536 slots (~3 days)

pub(crate) struct PendingRequest {
    pub(crate) attempts: u32,
    pub(crate) failed_peers: HashSet<PeerId>,
}

pub(crate) enum PendingRequestKind {
    Root(H256),
    Range { start_slot: u64, end_slot: u64 },
}

pub(crate) struct RangeSyncState {
    /// Remaining slots to request, with an exclusive end.
    pub(crate) current_range: Range<u64>,
    /// Latest advertised head slot for each peer.
    pub(crate) peer_set: HashMap<PeerId, u64>,
    pub(crate) in_flight: bool,
}

impl RangeSyncState {
    pub(crate) fn new(current_range: Range<u64>, peer: PeerId, peer_head: u64) -> Self {
        Self {
            current_range,
            peer_set: HashMap::from([(peer, peer_head)]),
            in_flight: false,
        }
    }

    pub(crate) fn merge_peer(&mut self, peer: PeerId, peer_head: u64, end_exclusive: u64) {
        self.peer_set.insert(peer, peer_head);
        self.current_range.end = self.current_range.end.max(end_exclusive);
        self.drop_stale_peers();
    }

    pub(crate) fn next_batch(&self) -> Option<(PeerId, Range<u64>)> {
        if self.in_flight || self.current_range.is_empty() {
            return None;
        }

        let (&peer, &peer_head) = self
            .peer_set
            .iter()
            .filter(|(_, head)| **head >= self.current_range.start)
            .max_by_key(|(_, head)| **head)?;
        let peer_end = peer_head.saturating_add(1);
        let batch_end = self
            .current_range
            .start
            .saturating_add(MAX_REQUEST_BLOCKS)
            .min(self.current_range.end)
            .min(peer_end);

        (batch_end > self.current_range.start)
            .then_some((peer, self.current_range.start..batch_end))
    }

    pub(crate) fn complete_batch(&mut self, end_slot: u64) {
        self.in_flight = false;
        self.current_range.start = self.current_range.start.max(end_slot.saturating_add(1));
        self.drop_stale_peers();
    }

    pub(crate) fn fail_peer(&mut self, peer: &PeerId) {
        self.in_flight = false;
        self.peer_set.remove(peer);
        self.drop_stale_peers();
    }

    fn drop_stale_peers(&mut self) {
        let start_slot = self.current_range.start;
        self.peer_set.retain(|_, head| *head >= start_slot);
    }
}

// --- Swarm construction ---

/// [libp2p Behaviour](libp2p::swarm::NetworkBehaviour) combining identify, Gossipsub
/// and Request-Response Behaviours.
///
/// `identify` is registered purely for interop: go-libp2p (gean) gates gossipsub
/// GRAFT on the identify exchange completing, so a peer that doesn't respond to
/// `/ipfs/id/1.0.0` is silently excluded from the mesh. Events from this
/// behaviour are intentionally not handled: the registration alone is enough
/// to satisfy probing peers. ream and zeam follow the same pattern.
#[derive(NetworkBehaviour)]
pub(crate) struct Behaviour {
    identify: libp2p::identify::Behaviour,
    gossipsub: libp2p::gossipsub::Behaviour,
    req_resp: request_response::Behaviour<Codec>,
}

/// Configuration for building the libp2p swarm.
///
/// INVARIANT: `subscription_subnets` is the fixed set of attestation subnets
/// this node subscribes to. It is computed once by the caller via
/// [`attestation_subscription_subnets`] and shared with the blockchain actor,
/// so both agree on exactly which subnets feed this node's gossip groups. The
/// set is consumed during [`build_swarm`] and NOT stored on [`P2PServer`]:
/// runtime toggles of the aggregator role via the admin API (see
/// [`ethlambda_types::aggregator::AggregatorController`]) intentionally do not
/// resubscribe gossip subnets; this is the leanSpec PR #636 "hot-standby model"
/// scope limitation. A node that may aggregate at runtime must include those
/// subnets here at startup.
pub struct SwarmConfig {
    pub node_key: Vec<u8>,
    pub bootnodes: Vec<Bootnode>,
    pub listening_socket: SocketAddr,
    pub validator_ids: Vec<u64>,
    pub attestation_committee_count: u64,
    /// Attestation subnets to subscribe to, precomputed via
    /// [`attestation_subscription_subnets`].
    pub subscription_subnets: HashSet<u64>,
    /// Slot duration from the network's config file. Gossipsub's duplicate
    /// cache is specified in slots, so it has to follow the network's cadence.
    pub milliseconds_per_slot: u64,
}

/// Width of gossipsub's duplicate cache, in slots: leanSpec sets
/// `seen_ttl = SECONDS_PER_SLOT * JUSTIFICATION_LOOKBACK_SLOTS * 2`.
const DUPLICATE_CACHE_SLOTS: u64 = 3 * 2;

/// The attestation subnets a node subscribes to: every validator subscribes
/// to its own committee subnet (`validator_id % attestation_committee_count`)
/// for mesh health, and an aggregator additionally subscribes to any explicit
/// `aggregate_subnet_ids`, falling back to subnet 0 when it would otherwise
/// subscribe to none.
pub fn attestation_subscription_subnets(
    validator_ids: &[u64],
    attestation_committee_count: u64,
    is_aggregator: bool,
    aggregate_subnet_ids: Option<&[u64]>,
) -> HashSet<u64> {
    let mut subnets: HashSet<u64> = validator_ids
        .iter()
        .map(|vid| vid % attestation_committee_count)
        .collect();
    if is_aggregator {
        if let Some(ids) = aggregate_subnet_ids {
            subnets.extend(ids.iter().copied());
        }
        // Fall back to subnet 0 only when the aggregator has no validators and
        // no explicit subnets; otherwise leave the set as configured.
        if subnets.is_empty() {
            subnets.insert(0);
        }
    }
    subnets
}

/// Result of building the swarm — contains all pieces needed to start the P2P actor.
pub struct BuiltSwarm {
    /// This node's libp2p peer ID, derived from the node key. Exposed so the
    /// caller can report it (e.g. via the RPC `/lean/v0/node/identity` endpoint).
    pub local_peer_id: PeerId,
    pub(crate) swarm: libp2p::Swarm<Behaviour>,
    pub(crate) attestation_topics: HashMap<u64, libp2p::gossipsub::IdentTopic>,
    pub(crate) attestation_committee_count: u64,
    pub(crate) block_topic: libp2p::gossipsub::IdentTopic,
    pub(crate) aggregation_topic: libp2p::gossipsub::IdentTopic,
    /// Every dial target per bootnode; see [`dial_addrs`]. Empty entries are never
    /// inserted; see [`bootnode_dial_addrs`].
    pub(crate) bootnode_addrs: HashMap<PeerId, Vec<Multiaddr>>,
}

/// Why [`build_swarm`] could not produce a usable swarm.
///
/// Both listeners are fatal rather than best-effort. Carrying on after a failed
/// TCP bind would leave the node advertising a `tcp` entry nothing answers,
/// which is the failure this transport exists to remove, inverted. The
/// configuration cases are caught before anything binds (`validate_ports` in
/// the CLI), so reaching this means the port is genuinely taken.
#[derive(Debug, thiserror::Error)]
pub enum SwarmBuildError {
    #[error("failed to bind the gossipsub {transport} listener on {addr}: {source}")]
    Listen {
        transport: &'static str,
        addr: Multiaddr,
        #[source]
        source: libp2p::TransportError<std::io::Error>,
    },
    #[error("failed to subscribe to a gossipsub topic: {0}")]
    Subscription(#[from] libp2p::gossipsub::SubscriptionError),
}

/// Build and configure the libp2p swarm, dial bootnodes, subscribe to topics.
pub fn build_swarm(config: SwarmConfig) -> Result<BuiltSwarm, SwarmBuildError> {
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
        .duplicate_cache_time(Duration::from_millis(
            config.milliseconds_per_slot * DUPLICATE_CACHE_SLOTS,
        ))
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
            (
                StreamProtocol::new(BLOCKS_BY_RANGE_PROTOCOL_V1),
                request_response::ProtocolSupport::Full,
            ),
        ],
        Default::default(),
    );

    let secret_key =
        secp256k1::SecretKey::try_from_bytes(config.node_key).expect("invalid node key");
    let identity = libp2p::identity::Keypair::from(secp256k1::Keypair::from(secret_key));

    // Use the same `protocol_version` string as zeam
    let identify = libp2p::identify::Behaviour::new(libp2p::identify::Config::new(
        "/ipfs/0.1.0".to_owned(),
        identity.public(),
    ));

    let behavior = Behaviour {
        identify,
        gossipsub,
        req_resp,
    };

    // TODO: set peer scoring params

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default().nodelay(true),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )
        .expect("failed to add TCP transport to swarm")
        .with_quic()
        .with_behaviour(|_| behavior)
        .expect("failed to add behaviour to swarm")
        .with_swarm_config(|c| {
            // Disable idle connection timeout
            c.with_idle_connection_timeout(Duration::from_secs(u64::MAX))
        })
        .build();
    let local_peer_id = *swarm.local_peer_id();
    let (bootnode_addrs, undialable_bootnodes) =
        merge_bootnode_dial_addrs(config.bootnodes, local_peer_id);
    // The merged map is the dial input, so every address a duplicate entry
    // contributed is in the one attempt this peer gets. A refused dial is not
    // fatal: the entry stays in `bootnode_addrs`, so the redial path picks the
    // peer up. Unwrapping here would abort a node over a bootnode file that is
    // merely redundant.
    for (peer_id, addrs) in &bootnode_addrs {
        let opts = DialOpts::peer_id(*peer_id).addresses(addrs.clone()).build();
        let _ = swarm
            .dial(opts)
            .inspect_err(|err| warn!(%peer_id, %err, "Swarm refused the initial bootnode dial"));
    }
    // Every skip in the merge is individually unremarkable and logged at
    // `debug`, but a list that produces no dial target at all leaves the node
    // isolated unless discovery is on, which is worth one line at `warn`.
    if bootnode_addrs.is_empty() && undialable_bootnodes > 0 {
        warn!(
            undialable_bootnodes,
            "No bootnode advertises a quic or tcp port, so nothing will be dialed statically; \
             peering depends entirely on discv5 discovery"
        );
    }
    let quic_addr = Multiaddr::empty()
        .with(config.listening_socket.ip().into())
        .with(Protocol::Udp(config.listening_socket.port()))
        .with(Protocol::QuicV1);
    swarm
        .listen_on(quic_addr.clone())
        .map_err(|source| SwarmBuildError::Listen {
            transport: "QUIC",
            addr: quic_addr,
            source,
        })?;
    // Same port number as the QUIC listener above: TCP and UDP are separate
    // namespaces, so this cannot collide with it.
    let tcp_addr = Multiaddr::empty()
        .with(config.listening_socket.ip().into())
        .with(Protocol::Tcp(config.listening_socket.port()));
    swarm
        .listen_on(tcp_addr.clone())
        .map_err(|source| SwarmBuildError::Listen {
            transport: "TCP",
            addr: tcp_addr,
            source,
        })?;

    // Subscribe to block topic (all nodes)
    let block_topic = block_topic();
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&block_topic)
        .unwrap();

    // Subscribe to aggregation topic (all validators)
    let aggregation_topic = aggregation_topic();
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&aggregation_topic)
        .unwrap();

    // The committee metric should reflect validator membership only, not
    // aggregator-only subscriptions.
    let metric_subnet = config
        .validator_ids
        .iter()
        .map(|vid| vid % config.attestation_committee_count)
        .min()
        .unwrap_or(0);
    metrics::set_attestation_committee_subnet(metric_subnet);

    let mut attestation_topics: HashMap<u64, libp2p::gossipsub::IdentTopic> = HashMap::new();
    for &subnet_id in &config.subscription_subnets {
        let topic = attestation_subnet_topic(subnet_id);
        swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
        info!(subnet_id, "Subscribed to attestation subnet");
        attestation_topics.insert(subnet_id, topic);
    }

    info!(socket=%config.listening_socket, "P2P node started");

    Ok(BuiltSwarm {
        local_peer_id,
        swarm,
        attestation_topics,
        attestation_committee_count: config.attestation_committee_count,
        block_topic,
        aggregation_topic,
        bootnode_addrs,
    })
}

// --- P2P Actor ---

/// Public handle to the P2P actor.
pub struct P2P {
    handle: ActorRef<P2PServer>,
}

impl P2P {
    /// Start discovery, start the I/O adapter, spawn the actor, and wire the
    /// swarm event stream.
    ///
    /// `discovery` is `Some` when discv5 discovery is enabled: the discv5
    /// server is started here, and its handle seeds the dial loop's state and
    /// schedules its first tick. `None` leaves the dial loop permanently
    /// dormant, so peering relies solely on the static bootnode list dialed by
    /// `build_swarm`.
    ///
    /// Discovery is started before the swarm adapter so a fatal discovery
    /// failure (a busy UDP port, say) surfaces before any actor is running.
    pub async fn spawn(
        built: BuiltSwarm,
        store: Store,
        node_names: HashMap<PeerId, String>,
        discovery: Option<DiscoverySpawnConfig>,
    ) -> Result<P2P, DiscoveryError> {
        if discovery.is_none() {
            info!("discv5 discovery disabled; peering from the static bootnode list only");
        }
        // `OptionFuture` awaits the spawn only when there is one to await, so the
        // disabled case stays a plain `None` without a branch of its own.
        let discovery = OptionFuture::from(discovery.map(spawn_discovery))
            .await
            .transpose()?;
        let (swarm_stream, swarm_handle) =
            swarm_adapter::start_swarm_adapter(built.swarm, node_names.clone());

        let discovery_enabled = discovery.is_some();
        let server = P2PServer {
            swarm_handle,
            store,
            blockchain: None,
            attestation_topics: built.attestation_topics,
            attestation_committee_count: built.attestation_committee_count,
            block_topic: built.block_topic,
            aggregation_topic: built.aggregation_topic,
            connected_peers: HashSet::new(),
            pending_root_requests: HashMap::new(),
            outbound_requests: HashMap::new(),
            range_sync_state: None,
            bootnode_addrs: built.bootnode_addrs,
            node_names,
            discovery: discovery.map(|handle| DiscoveryState::new(handle, built.local_peer_id)),
        };
        let handle = server.start();
        if discovery_enabled {
            send_after(
                DISCOVERY_DIAL_INTERVAL,
                handle.context(),
                p2p_protocol::DiscoverPeers,
            );
        }
        spawn_listener(handle.context(), swarm_stream.map(WrappedSwarmEvent));
        Ok(P2P { handle })
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

    pub(crate) connected_peers: HashSet<PeerId>,
    pub(crate) pending_root_requests: HashMap<H256, PendingRequest>,
    pub(crate) outbound_requests: HashMap<OutboundRequestId, PendingRequestKind>,
    pub(crate) range_sync_state: Option<RangeSyncState>,
    bootnode_addrs: HashMap<PeerId, Vec<Multiaddr>>,
    node_names: HashMap<PeerId, String>,

    /// Set when discovery is enabled. `None` disables the dial loop entirely.
    pub(crate) discovery: Option<DiscoveryState>,
}

impl P2PServer {
    fn resolve_node_name(&self, peer_id: Option<&PeerId>) -> &str {
        peer_id
            .and_then(|p| self.node_names.get(p))
            .map(String::as_str)
            .unwrap_or("unknown")
    }
}

// Protocol trait for internal messages only (retry scheduling).
// Network-api messages and swarm events are handled via manual Handler impls.
#[protocol]
pub(crate) trait P2PProtocol: Send + Sync {
    #[allow(dead_code)] // invoked via send_after, not called directly
    fn retry_block_fetch(&self, root: H256) -> Result<(), ActorError>;
    #[allow(dead_code)] // invoked via send_after, not called directly
    fn retry_peer_redial(&self, peer_id: PeerId) -> Result<(), ActorError>;
    #[allow(dead_code)] // invoked via send_after, not called directly
    fn discover_peers(&self) -> Result<(), ActorError>;
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
        if !self.pending_root_requests.contains_key(&root) {
            trace!(%root, "Block fetch completed during backoff, skipping retry");
            return;
        }

        trace!(%root, "Retrying block fetch after backoff");

        if !fetch_block_from_peer(self, root).await {
            tracing::error!(%root, "Failed to retry block fetch, giving up");
            self.pending_root_requests.remove(&root);
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

        if let Some(addrs) = self.bootnode_addrs.get(&peer_id) {
            trace!(%peer_id, "Redialing disconnected bootnode");
            self.swarm_handle
                .dial(DialOpts::peer_id(peer_id).addresses(addrs.clone()).build());
        }
    }

    #[send_handler]
    async fn handle_discover_peers(
        &mut self,
        _msg: p2p_protocol::DiscoverPeers,
        ctx: &Context<Self>,
    ) {
        // Reschedule first, so an early return never stops the loop.
        send_after(
            DISCOVERY_DIAL_INTERVAL,
            ctx.clone(),
            p2p_protocol::DiscoverPeers,
        );
        dial_tick(self).await;
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
        if self.pending_root_requests.contains_key(&root) {
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
            // Read off the connection's own address rather than which one we
            // dialed: with both QUIC and TCP offered, libp2p races every
            // address in a dial and may connect over either. This is what
            // answers "did the TCP fallback actually help", as a metric because
            // the trace field alone is invisible at default verbosity.
            let transport = transport_label(endpoint.get_remote_address());
            metrics::inc_peer_connection_transport(direction, transport);
            if num_established.get() == 1 {
                server.connected_peers.insert(peer_id);
                let peer_count = server.connected_peers.len();
                metrics::notify_peer_connected(
                    server.resolve_node_name(Some(&peer_id)),
                    direction,
                    "success",
                );
                // Send status request on first connection to this peer
                let our_status = build_status(&server.store);
                let our_finalized_slot = our_status.finalized.slot;
                let our_head_slot = our_status.head.slot;
                trace!(
                    %peer_id,
                    %direction,
                    %transport,
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
                trace!(%peer_id, %direction, %transport, "Added peer connection");
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
                forget_discovered_peer(server, &peer_id);
                let peer_count = server.connected_peers.len();
                metrics::notify_peer_disconnected(
                    server.resolve_node_name(Some(&peer_id)),
                    direction,
                    reason,
                );

                trace!(
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
                    trace!(%peer_id, "Scheduled bootnode redial in {}s", PEER_REDIAL_INTERVAL_SECS);
                }
            } else {
                trace!(%peer_id, %direction, %reason, "Peer connection closed but other connections remain");
            }
        }
        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            let result = if error.to_string().to_lowercase().contains("timed out") {
                "timeout"
            } else {
                "error"
            };
            metrics::notify_peer_connected(
                server.resolve_node_name(peer_id.as_ref()),
                "outbound",
                result,
            );
            debug!(?peer_id, %error, "Outgoing connection error");

            if let Some(pid) = peer_id {
                // A dial that never establishes ends up here rather than in
                // `ConnectionClosed`, so this is the only place a peer we dialed
                // but never connected to can be forgotten. Gated on the peer
                // being gone: a *second* dial to an already-connected peer can
                // fail here (the bootnode redial path is one way), and dropping
                // a live peer's `attnets` would make `covered_subnets`
                // under-count subnets we do in fact cover.
                if !server.connected_peers.contains(&pid) {
                    forget_discovered_peer(server, &pid);
                }

                // Schedule redial if this was a bootnode
                if server.bootnode_addrs.contains_key(&pid)
                    && !server.connected_peers.contains(&pid)
                {
                    send_after(
                        Duration::from_secs(PEER_REDIAL_INTERVAL_SECS),
                        ctx.clone(),
                        p2p_protocol::RetryPeerRedial { peer_id: pid },
                    );
                    trace!(%pid, "Scheduled bootnode redial after connection error");
                }
            }
        }
        SwarmEvent::IncomingConnectionError { peer_id, error, .. } => {
            metrics::notify_peer_connected(
                server.resolve_node_name(peer_id.as_ref()),
                "inbound",
                "error",
            );
            debug!(%error, "Incoming connection error");
        }
        _ => {
            trace!(?event, "Ignored swarm event");
        }
    }
}

// --- Node identity helpers ---

/// Derive each entry's `PeerId` from its secp256k1 private key.
///
/// Drops entries whose key fails to parse, with a `warn!` per drop.
pub fn derive_peer_ids(names_and_privkeys: HashMap<String, H256>) -> HashMap<PeerId, String> {
    names_and_privkeys
        .into_iter()
        .filter_map(|(name, mut privkey)| {
            match secp256k1::SecretKey::try_from_bytes(&mut privkey.0) {
                Ok(privkey) => {
                    let pubkey = Keypair::from(secp256k1::Keypair::from(privkey)).public();
                    Some((PeerId::from_public_key(&pubkey), name))
                }
                Err(err) => {
                    warn!(%name, %err, "Skipping node-name registry entry: invalid secp256k1 privkey");
                    None
                }
            }
        })
        .collect()
}

// --- Bootnode parsing ---

/// [`Clone`] so one parse of the bootnode file can serve both `build_swarm` and
/// discovery: every field is plain data, and cloning beats reading the file twice.
#[derive(Clone)]
pub struct Bootnode {
    pub(crate) ip: IpAddr,
    /// The libp2p QUIC port, when the ENR advertises one.
    ///
    /// `None` for a record that does not advertise one. See
    /// [`Bootnode::tcp_port`] for the other transport that can still make such
    /// a record dialable: every beacon-chain bootnode published today is
    /// exactly that case, `tcp` and `udp` but no `quic`.
    pub(crate) quic_port: Option<u16>,
    /// The libp2p TCP port, when the ENR advertises one.
    ///
    /// `None` for the ENRs lean-quickstart generates today, which carry only
    /// `ip`/`quic`/`secp256k1`. Every published mainnet beacon-chain bootnode
    /// carries this instead of `quic`, which is what makes them statically
    /// dialable now that the swarm speaks both transports.
    pub(crate) tcp_port: Option<u16>,
    /// The discv5 UDP port, when the ENR advertises one.
    ///
    /// `None` for the ENRs lean-quickstart generates today, which carry only
    /// `ip`/`quic`/`secp256k1`. Such a bootnode is still dialed statically over
    /// QUIC or TCP; it just cannot seed the discv5 routing table.
    pub(crate) udp_port: Option<u16>,
    pub(crate) public_key: PublicKey,
}

impl Bootnode {
    /// This bootnode as a discv5 seed, or `None` when its ENR advertises no
    /// `udp` port and it therefore cannot be reached by discovery.
    ///
    /// `tcp_port` carries this bootnode's real advertised TCP port when it has
    /// one, now that ethlambda dials TCP too; it is `0` only when the ENR
    /// advertises none, which ethrex reads as "no TCP listener".
    pub(crate) fn as_discovery_node(&self) -> Option<ethrex_p2p::types::Node> {
        let udp_port = self.udp_port?;
        // libp2p and ethrex hold the same key in different representations:
        // ethrex wants the 65-byte uncompressed SEC1 form with its leading 0x04
        // tag stripped.
        let uncompressed = self
            .public_key
            .clone()
            .try_into_secp256k1()
            .ok()?
            .to_bytes_uncompressed();
        // `Node::from_enr` would compute the same identity from the record, but
        // it falls back to `tcp` when `udp` is absent, which would seed a
        // tcp-only bootnode under a port discv5 does not listen on.
        Some(ethrex_p2p::types::Node::new(
            self.ip,
            udp_port,
            self.tcp_port.unwrap_or(0),
            ethrex_common::H512::from_slice(&uncompressed[1..]),
        ))
    }
}

/// Decode `enr:`-prefixed records into usable bootnodes.
///
/// Records that cannot be decoded, or that lack an IP, a public key or any
/// dialable port at all, are skipped with a warning rather than aborting
/// startup: one malformed entry in the bootnode file should not stop the node
/// from booting. A record carrying only one of `quic`, `tcp` and `udp` is kept,
/// since each is useful on its own.
pub fn parse_enrs(enrs: Vec<String>) -> Vec<Bootnode> {
    let configured = enrs.len();
    let bootnodes: Vec<Bootnode> = enrs
        .into_iter()
        .filter_map(|enr_str| {
            parse_enr(&enr_str)
                .inspect_err(
                    |reason| warn!(%reason, enr = %enr_str, "Skipping unusable bootnode ENR"),
                )
                .ok()
        })
        .collect();
    // Each rejection above already warned, but a file where *every* entry is
    // unusable boots a node with an empty bootnode list, which otherwise looks
    // identical to having configured none at all.
    if bootnodes.is_empty() && configured > 0 {
        warn!(
            configured,
            "No bootnode ENR could be used; the node starts with no bootnodes"
        );
    }
    bootnodes
}

fn parse_enr(enr_str: &str) -> Result<Bootnode, String> {
    let stripped = enr_str
        .strip_prefix("enr:")
        .ok_or_else(|| "missing enr: prefix".to_string())?;
    let decoded = ethrex_common::base64::decode(stripped.as_bytes());
    let record = NodeRecord::decode(&decoded).map_err(|err| format!("RLP decode failed: {err}"))?;
    let pairs = record.pairs();

    // A record with no dialable `quic` entry is not an error: it may still
    // advertise `tcp`, and even a record with neither is worth keeping as a
    // discv5 seed. Keep it and let `build_swarm` skip it when it picks static
    // dial targets.
    let quic_port = read_quic_port(&record);

    // An explicit `udp: 0` is no more reachable than a `quic: 0`, which
    // `read_quic_port` already rejects. Reading it verbatim would seed discv5
    // with a contact on a port nothing listens on.
    let udp_port = pairs.udp_port.and_then(dialable_port);

    // Same rule for `tcp`, the transport every published beacon-chain bootnode
    // advertises and none of them pairs with a `quic` entry.
    let tcp_port = read_tcp_port(pairs);

    let public_key = read_public_key(pairs)
        .ok_or_else(|| "node record missing or malformed public key".to_string())?;

    let ip = read_ip(pairs).ok_or_else(|| "node record missing IP address".to_string())?;

    // `quic`, `tcp` and `udp` are independently optional, but a record with none
    // of them is reachable by nothing we speak: it can be neither dialed nor
    // seeded. Drop it here rather than carry a contact no code path can use.
    if quic_port.is_none() && tcp_port.is_none() && udp_port.is_none() {
        return Err("node advertises none of quic, tcp, or udp".to_string());
    }

    Ok(Bootnode {
        ip,
        quic_port,
        tcp_port,
        udp_port,
        public_key: public_key.into(),
    })
}

// --- Utility functions ---

/// Every address worth trying for one peer, from whichever of its two ports are
/// present.
///
/// Empty when neither is, which is a discv5-only seed: it can still answer
/// FINDNODE, but there is nothing for the swarm to dial.
///
/// The order is not a preference. libp2p pushes up to `dial_concurrency_factor`
/// of these into one `FuturesUnordered` and takes whichever handshake finishes
/// first; the default factor is larger than this list can ever be, so both
/// transports are always attempted and the position here decides nothing. That
/// race is the point: a peer advertising a `quic` port nothing answers still
/// connects over `tcp` without waiting out a connect timeout first.
///
/// Shared by both dial paths, so a change to what counts as dialable cannot
/// apply to static bootnodes and discovered peers differently: static bootnodes
/// in [`build_swarm`] and discovered peers in
/// [`admission::admit`](discovery::admission).
pub(crate) fn dial_addrs(
    ip: IpAddr,
    quic_port: Option<u16>,
    tcp_port: Option<u16>,
    peer_id: PeerId,
) -> Vec<Multiaddr> {
    let mut addrs = Vec::with_capacity(2);
    if let Some(port) = quic_port {
        addrs.push(quic_multiaddr(ip, port, peer_id));
    }
    if let Some(port) = tcp_port {
        addrs.push(tcp_multiaddr(ip, port, peer_id));
    }
    addrs
}

/// Static dial targets, one entry per peer id, merged across duplicate bootnode
/// entries. Also reports how many entries named no dialable transport at all.
///
/// Two entries can name one peer: the same ENR pasted twice, or an old and a new
/// record for a single secp256k1 key. `parse_enrs` does not dedup, and
/// `DialOpts::peer_id` dials under the default `DisconnectedAndNotDialing`
/// condition, so a second dial to a peer already being dialed is refused
/// outright.
///
/// Merging before dialing rather than while dialing is what puts every address
/// into the one attempt the peer gets. Dialing per entry would take only the
/// first entry's addresses: with a stale QUIC-only record listed ahead of a
/// newer one carrying a live TCP port, startup would race a dead address alone,
/// burn the full connect timeout, and reach the live one only on the redial.
fn merge_bootnode_dial_addrs(
    bootnodes: Vec<Bootnode>,
    local_peer_id: PeerId,
) -> (HashMap<PeerId, Vec<Multiaddr>>, usize) {
    let mut merged: HashMap<PeerId, Vec<Multiaddr>> = HashMap::new();
    let mut undialable = 0usize;
    for bootnode in bootnodes {
        let peer_id = PeerId::from_public_key(&bootnode.public_key);
        if peer_id == local_peer_id {
            continue;
        }
        let addrs = bootnode_dial_addrs(&bootnode, peer_id);
        if addrs.is_empty() {
            // Discovery-only seed: reachable over discv5, but with no QUIC or
            // TCP port there is nothing for the swarm to dial.
            undialable += 1;
            debug!(%peer_id, ip = %bootnode.ip, "Bootnode advertises no dialable transport, discv5 seed only");
            continue;
        }
        match merged.entry(peer_id) {
            Entry::Occupied(mut known) => {
                debug!(
                    %peer_id,
                    ip = %bootnode.ip,
                    "Bootnode list names this peer more than once, merging its addresses"
                );
                let known = known.get_mut();
                for addr in addrs {
                    if !known.contains(&addr) {
                        known.push(addr);
                    }
                }
            }
            Entry::Vacant(unknown) => {
                unknown.insert(addrs);
            }
        }
    }
    (merged, undialable)
}

/// Dial targets for a static bootnode. See [`dial_addrs`].
pub(crate) fn bootnode_dial_addrs(bootnode: &Bootnode, peer_id: PeerId) -> Vec<Multiaddr> {
    dial_addrs(bootnode.ip, bootnode.quic_port, bootnode.tcp_port, peer_id)
}

/// The address of a libp2p QUIC listener, as [`dial_addrs`] spells it.
///
/// Infallible: `with_p2p` only rejects a multiaddr that already carries a `p2p`
/// component, and this one is built fresh.
pub(crate) fn quic_multiaddr(ip: IpAddr, quic_port: u16, peer_id: PeerId) -> Multiaddr {
    Multiaddr::empty()
        .with(ip.into())
        .with(Protocol::Udp(quic_port))
        .with(Protocol::QuicV1)
        .with_p2p(peer_id)
        .expect("a freshly built multiaddr carries no p2p component")
}

/// The address of a libp2p TCP listener, the fallback path for a peer whose
/// advertised `quic` entry does not answer.
///
/// Infallible for the same reason [`quic_multiaddr`] is.
pub(crate) fn tcp_multiaddr(ip: IpAddr, tcp_port: u16, peer_id: PeerId) -> Multiaddr {
    Multiaddr::empty()
        .with(ip.into())
        .with(Protocol::Tcp(tcp_port))
        .with_p2p(peer_id)
        .expect("a freshly built multiaddr carries no p2p component")
}

fn connection_direction(endpoint: &libp2p::core::ConnectedPoint) -> &'static str {
    if endpoint.is_dialer() {
        "outbound"
    } else {
        "inbound"
    }
}

/// "quic" or "tcp", read off which protocol the connection's own multiaddr
/// carries. `"unknown"` is unreachable in practice: every address this swarm
/// ever connects over came from one of the two transports it was built with,
/// but a swarm event is not proof of that, so this stays total rather than
/// panicking on a shape it does not expect.
fn transport_label(addr: &Multiaddr) -> &'static str {
    for protocol in addr.iter() {
        match protocol {
            Protocol::Quic | Protocol::QuicV1 => return "quic",
            Protocol::Tcp(_) => return "tcp",
            _ => {}
        }
    }
    "unknown"
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
    use std::net::Ipv4Addr;

    use ethlambda_types::constants::DEFAULT_MILLISECONDS_PER_SLOT;

    fn random_peer() -> PeerId {
        PeerId::from_public_key(&Keypair::generate_ed25519().public())
    }

    /// Proves the TCP transport `build_swarm` now adds actually completes a
    /// connection end to end, rather than only compiling. Builds two real
    /// swarms via the production entry point (port `0`, so this cannot collide
    /// with a running node or a sibling test), learns the first swarm's TCP
    /// listen address off its own `NewListenAddr` event, dials it from the
    /// second swarm, and polls both until each reports `ConnectionEstablished`.
    /// A regression to QUIC-only, or a misconfigured TCP transport, hangs here
    /// until the timeout rather than racing to a false positive.
    #[tokio::test]
    async fn two_swarms_connect_over_tcp() {
        fn build(node_key_byte: u8) -> BuiltSwarm {
            build_swarm(SwarmConfig {
                node_key: vec![node_key_byte; 32],
                bootnodes: Vec::new(),
                listening_socket: "127.0.0.1:0".parse().expect("valid socket"),
                validator_ids: Vec::new(),
                attestation_committee_count: 1,
                subscription_subnets: HashSet::new(),
                milliseconds_per_slot: DEFAULT_MILLISECONDS_PER_SLOT,
            })
            .expect("swarm builds")
        }

        let mut dialer = build(1);
        let mut listener = build(2);

        // Both a QUIC and a TCP `NewListenAddr` arrive for `listener`; only the
        // TCP one is wanted here.
        let listener_tcp_addr = loop {
            if let SwarmEvent::NewListenAddr { address, .. } =
                listener.swarm.select_next_some().await
                && address.iter().any(|p| matches!(p, Protocol::Tcp(_)))
            {
                break address
                    .with_p2p(listener.local_peer_id)
                    .expect("failed to add peer ID to multiaddr");
            }
        };

        dialer
            .swarm
            .dial(listener_tcp_addr)
            .expect("dial is accepted");

        let (mut dialer_connected, mut listener_connected) = (false, false);
        let both_connect = async {
            while !(dialer_connected && listener_connected) {
                tokio::select! {
                    event = dialer.swarm.select_next_some() => {
                        if let SwarmEvent::ConnectionEstablished { endpoint, .. } = event {
                            assert_eq!(transport_label(endpoint.get_remote_address()), "tcp");
                            dialer_connected = true;
                        }
                    }
                    event = listener.swarm.select_next_some() => {
                        if let SwarmEvent::ConnectionEstablished { endpoint, .. } = event {
                            assert_eq!(transport_label(endpoint.get_remote_address()), "tcp");
                            listener_connected = true;
                        }
                    }
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(10), both_connect)
            .await
            .expect("both swarms must connect over TCP within the timeout");
    }

    /// A bootnode file naming one peer twice must not abort the node.
    ///
    /// `DialOpts::peer_id` dials under the default `DisconnectedAndNotDialing`
    /// condition, so a second dial while the first is in flight comes back as
    /// `Err(DialPeerConditionFalse)` synchronously. Two file entries decode to
    /// one `PeerId` whenever they share a secp256k1 key: the same ENR pasted
    /// twice, or an old and a new record for one node. `parse_enrs` does not
    /// dedup, so `build_swarm` has to, and it merges the address lists rather
    /// than dropping whichever entry came second.
    ///
    /// Asserting the map is asserting the dial: `build_swarm` merges first and
    /// then dials one `DialOpts` per map entry, so what is checked here is the
    /// list the initial dial races. The pure merge itself is pinned separately
    /// by [`merging_bootnodes_keeps_every_address_for_the_initial_dial`].
    ///
    /// The QUIC-only condition (`From<Multiaddr>`) this replaced was `Always`,
    /// which is why the duplicate went unnoticed before.
    #[tokio::test]
    async fn a_bootnode_named_twice_is_dialed_once_with_both_addresses() {
        let key = secp256k1::Keypair::generate();
        let public_key: PublicKey = key.public().clone().into();
        let peer_id = PeerId::from_public_key(&public_key);
        let ip = IpAddr::from(Ipv4Addr::new(203, 0, 113, 1));
        // Two records for one key: the first advertising QUIC only, the second
        // having since added TCP. Neither port is listening, which is fine —
        // the dial only has to be *taken*.
        let bootnodes = vec![
            Bootnode {
                ip,
                quic_port: Some(9001),
                tcp_port: None,
                udp_port: Some(9000),
                public_key: public_key.clone(),
            },
            Bootnode {
                ip,
                quic_port: Some(9001),
                tcp_port: Some(9001),
                udp_port: Some(9000),
                public_key,
            },
        ];

        let built = build_swarm(SwarmConfig {
            node_key: vec![7u8; 32],
            bootnodes,
            listening_socket: "127.0.0.1:0".parse().expect("valid socket"),
            validator_ids: Vec::new(),
            attestation_committee_count: 1,
            subscription_subnets: HashSet::new(),
            milliseconds_per_slot: DEFAULT_MILLISECONDS_PER_SLOT,
        })
        .expect("a duplicated bootnode entry must not fail the build");

        assert_eq!(
            built.bootnode_addrs.len(),
            1,
            "the two entries name one peer, so they must collapse to one dial target"
        );
        let addrs = built
            .bootnode_addrs
            .get(&peer_id)
            .expect("the bootnode is tracked under its peer id");
        let expected: HashSet<Multiaddr> = HashSet::from([
            quic_multiaddr(ip, 9001, peer_id),
            tcp_multiaddr(ip, 9001, peer_id),
        ]);
        assert_eq!(
            addrs.iter().cloned().collect::<HashSet<_>>(),
            expected,
            "the merged list must carry every address the duplicate entries offered"
        );
    }

    /// The merge has to happen before the dial, not during it.
    ///
    /// The case that distinguishes them: a stale QUIC-only record listed ahead
    /// of a newer one for the same key that has since added a live TCP port,
    /// with the QUIC port dead. Merging while dialing takes only the first
    /// entry's addresses, so startup races a dead address alone and reaches the
    /// live one a redial interval later; merging first puts both into the one
    /// attempt the peer gets.
    #[test]
    fn merging_bootnodes_keeps_every_address_for_the_initial_dial() {
        let key = secp256k1::Keypair::generate();
        let public_key: PublicKey = key.public().clone().into();
        let peer_id = PeerId::from_public_key(&public_key);
        let ip = IpAddr::from(Ipv4Addr::new(203, 0, 113, 1));
        let bootnodes = vec![
            Bootnode {
                ip,
                quic_port: Some(9001),
                tcp_port: None,
                udp_port: Some(9000),
                public_key: public_key.clone(),
            },
            Bootnode {
                ip,
                quic_port: None,
                tcp_port: Some(9002),
                udp_port: Some(9000),
                public_key,
            },
            // A discv5-only seed: nothing to dial, counted separately so the
            // caller can tell "no bootnode is dialable" from "no bootnodes".
            Bootnode {
                ip,
                quic_port: None,
                tcp_port: None,
                udp_port: Some(9000),
                public_key: secp256k1::Keypair::generate().public().clone().into(),
            },
        ];

        let (merged, undialable) = merge_bootnode_dial_addrs(bootnodes, random_peer());

        assert_eq!(undialable, 1, "the transport-less entry must be counted");
        assert_eq!(merged.len(), 1, "the two records name one peer");
        let addrs = merged
            .get(&peer_id)
            .expect("the peer is keyed by its peer id");
        let expected: HashSet<Multiaddr> = HashSet::from([
            quic_multiaddr(ip, 9001, peer_id),
            tcp_multiaddr(ip, 9002, peer_id),
        ]);
        assert_eq!(
            addrs.iter().cloned().collect::<HashSet<_>>(),
            expected,
            "the address only the second entry offered must reach the first dial"
        );
    }

    /// Our own key in a bootnode list is a dial to ourselves, which
    /// `Swarm::dial` refuses as `LocalPeerId`. Dropping it in the merge keeps it
    /// out of `bootnode_addrs`, so the redial path never retries it either.
    #[test]
    fn merging_bootnodes_drops_our_own_record() {
        let key = secp256k1::Keypair::generate();
        let public_key: PublicKey = key.public().clone().into();
        let local_peer_id = PeerId::from_public_key(&public_key);
        let bootnodes = vec![Bootnode {
            ip: IpAddr::from(Ipv4Addr::new(203, 0, 113, 1)),
            quic_port: Some(9001),
            tcp_port: Some(9001),
            udp_port: Some(9000),
            public_key,
        }];

        let (merged, undialable) = merge_bootnode_dial_addrs(bootnodes, local_peer_id);

        assert!(merged.is_empty(), "we must not be a dial target");
        assert_eq!(
            undialable, 0,
            "our own record is not an undialable bootnode, it is not a bootnode"
        );
    }

    #[test]
    fn range_sync_state_merges_new_peer_ranges() {
        let first_peer = random_peer();
        let second_peer = random_peer();
        let mut state = RangeSyncState::new(10..101, first_peer, 100);

        state.merge_peer(second_peer, 150, 151);

        assert_eq!(state.current_range, 10..151);
        assert_eq!(state.peer_set.get(&first_peer), Some(&100));
        assert_eq!(state.peer_set.get(&second_peer), Some(&150));
    }

    #[test]
    fn range_sync_state_allows_only_one_batch_in_flight() {
        let first_peer = random_peer();
        let second_peer = random_peer();
        let mut state = RangeSyncState::new(10..3000, first_peer, 500);
        state.merge_peer(second_peer, 2000, 3000);

        let (selected_peer, batch) = state.next_batch().expect("batch available");
        assert_eq!(selected_peer, second_peer);
        assert_eq!(batch, 10..(10 + MAX_REQUEST_BLOCKS));

        state.in_flight = true;
        assert!(state.next_batch().is_none());
    }

    #[test]
    fn range_sync_state_advances_and_drops_stale_peers() {
        let stale_peer = random_peer();
        let current_peer = random_peer();
        let mut state = RangeSyncState::new(10..3000, stale_peer, 100);
        state.merge_peer(current_peer, 2999, 3000);
        state.in_flight = true;

        state.complete_batch(1033);

        assert_eq!(state.current_range, 1034..3000);
        assert!(!state.in_flight);
        assert!(!state.peer_set.contains_key(&stale_peer));
        assert_eq!(state.peer_set.get(&current_peer), Some(&2999));
    }

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
        assert_eq!(bootnodes[0].quic_port, Some(9001));
        assert_eq!(bootnodes[1].quic_port, Some(9002));
        assert_eq!(bootnodes[2].quic_port, Some(9003));
        assert_eq!(bootnodes[3].quic_port, Some(9007));

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

        // Devnet ENRs from lean-quickstart carry no `udp` entry, so they cannot
        // seed discv5 even though they remain dialable over QUIC.
        for bootnode in &bootnodes {
            assert_eq!(bootnode.udp_port, None);
        }
    }

    #[test]
    fn parse_enrs_extracts_the_udp_port_when_present() {
        // `secp256k1` is already bound in this module to `libp2p::identity::secp256k1`
        // (see the top-of-file `use`), so reach the raw `secp256k1` crate that
        // `ethrex_p2p::types::NodeRecord::from_pairs` expects via an explicit
        // crate-root path instead of the shadowed name.
        use ::secp256k1 as raw_secp256k1;

        // Build an ENR the way ethlambda does once discovery is enabled: udp for
        // discv5, quic for libp2p, no tcp.
        let signer = raw_secp256k1::SecretKey::new(&mut rand::rngs::OsRng);
        let mut pairs = ethrex_p2p::types::NodeRecordPairs {
            ip: Some(Ipv4Addr::LOCALHOST),
            udp_port: Some(9010),
            tcp_port: None,
            ..Default::default()
        };
        pairs.set_extra_int(b"quic", 9001);
        let record = NodeRecord::from_pairs(1, &signer, pairs).unwrap();

        let bootnodes = parse_enrs(vec![record.enr_url().unwrap()]);

        assert_eq!(bootnodes.len(), 1);
        assert_eq!(bootnodes[0].ip, IpAddr::from(Ipv4Addr::LOCALHOST));
        assert_eq!(bootnodes[0].quic_port, Some(9001));
        assert_eq!(bootnodes[0].udp_port, Some(9010));
    }

    #[test]
    fn parse_enrs_treats_a_zero_udp_port_as_absent() {
        use ::secp256k1 as raw_secp256k1;

        // `udp: 0` names no listener, exactly as `quic: 0` does not. Reading it
        // verbatim would seed discv5 with an undialable contact, so the record
        // survives only as a static dial target.
        let signer = raw_secp256k1::SecretKey::new(&mut rand::rngs::OsRng);
        let mut pairs = ethrex_p2p::types::NodeRecordPairs {
            ip: Some(Ipv4Addr::LOCALHOST),
            udp_port: Some(0),
            tcp_port: None,
            ..Default::default()
        };
        pairs.set_extra_int(b"quic", 9001);
        let record = NodeRecord::from_pairs(1, &signer, pairs).unwrap();

        let bootnodes = parse_enrs(vec![record.enr_url().unwrap()]);

        assert_eq!(bootnodes.len(), 1);
        assert_eq!(bootnodes[0].quic_port, Some(9001));
        assert_eq!(bootnodes[0].udp_port, None);
        assert!(
            bootnodes[0].as_discovery_node().is_none(),
            "a zero udp port must not become a discv5 seed"
        );
    }

    #[test]
    fn parse_enrs_drops_a_record_whose_only_ports_are_zero() {
        use ::secp256k1 as raw_secp256k1;

        // Neither port is dialable, so nothing downstream can ever use this
        // record: the same outcome as a record carrying no ports at all.
        let signer = raw_secp256k1::SecretKey::new(&mut rand::rngs::OsRng);
        let mut pairs = ethrex_p2p::types::NodeRecordPairs {
            ip: Some(Ipv4Addr::LOCALHOST),
            udp_port: Some(0),
            tcp_port: None,
            ..Default::default()
        };
        pairs.set_extra_int(b"quic", 0);
        let record = NodeRecord::from_pairs(1, &signer, pairs).unwrap();

        assert!(parse_enrs(vec![record.enr_url().unwrap()]).is_empty());
    }

    #[test]
    fn parse_enrs_keeps_a_quic_less_record_and_dials_it_over_tcp() {
        // Some nodes advertise `tcp` and `udp` but no `quic`, so requiring
        // `quic` here would drop the entire mainnet bootstrap list and leave
        // discv5 with nothing to seed from. Now that TCP is a transport we
        // speak, such a record is not merely kept as a seed: the one that
        // carries `tcp` becomes a static dial target too, over that port alone.
        //
        // The two ENRs are from eth-clients/mainnet's `bootstrap_nodes.yaml`,
        // and they differ in exactly the way that matters here: the first
        // advertises `tcp` and the second does not.
        let enrs = vec![
            "enr:-Iu4QLm7bZGdAt9NSeJG0cEnJohWcQTQaI9wFLu3Q7eHIDfrI4cwtzvEW3F3VbG9XdFXlrHyFGeXPn9snTCQJ9bnMRABgmlkgnY0gmlwhAOTJQCJc2VjcDI1NmsxoQIZdZD6tDYpkpEfVo5bgiU8MGRjhcOmHGD2nErK0UKRrIN0Y3CCIyiDdWRwgiMo".to_string(),
            "enr:-Le4QPUXJS2BTORXxyx2Ia-9ae4YqA_JWX3ssj4E_J-3z1A-HmFGrU8BpvpqhNabayXeOZ2Nq_sbeDgtzMJpLLnXFgAChGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISsaa0Zg2lwNpAkAIkHAAAAAPA8kv_-awoTiXNlY3AyNTZrMaEDHAD2JKYevx89W0CcFJFiskdcEzkH_Wdv9iW42qLK79ODdWRwgiMohHVkcDaCI4I".to_string(),
        ];

        let bootnodes = parse_enrs(enrs);

        assert_eq!(bootnodes.len(), 2, "a quic-less ENR is still a valid seed");
        for bootnode in &bootnodes {
            assert_eq!(bootnode.quic_port, None);
            // The whole point of keeping them: a `udp` port means discv5 can
            // use them, which is what `as_discovery_node` reports.
            assert_eq!(bootnode.udp_port, Some(9000));
            assert!(bootnode.as_discovery_node().is_some());
        }

        // What the TCP transport changed: the first record's `tcp` entry is now
        // a dial target, where before it produced no address and the bootnode
        // was a discv5 seed and nothing more.
        assert_eq!(bootnodes[0].tcp_port, Some(9000));
        let peer_id = PeerId::from_public_key(&bootnodes[0].public_key);
        assert_eq!(
            bootnode_dial_addrs(&bootnodes[0], peer_id),
            vec![
                format!("/ip4/3.147.37.0/tcp/9000/p2p/{peer_id}")
                    .parse::<Multiaddr>()
                    .unwrap()
            ],
            "a tcp-only bootnode is dialed over tcp alone"
        );

        // The second advertises neither, so it stays a seed with nothing to
        // dial: this is the case the `warn` in `build_swarm` counts.
        assert_eq!(bootnodes[1].tcp_port, None);
        let seed_only = PeerId::from_public_key(&bootnodes[1].public_key);
        assert!(bootnode_dial_addrs(&bootnodes[1], seed_only).is_empty());
    }

    #[test]
    fn parse_enrs_skips_malformed_records_but_keeps_the_valid_one() {
        // The rewrite's whole point is that one bad line in the bootnode file
        // must not take the others down with it. Feed it a mix of the ways an
        // entry can be malformed, plus one genuinely valid ENR (reused from
        // `parse_enrs_extracts_ip_port_and_public_key`), and check the valid
        // one survives and nothing panics along the way.
        let enrs = vec![
            "not-an-enr-at-all".to_string(), // missing "enr:" prefix
            "enr:not valid base64!!!".to_string(), // non-base64 garbage
            "enr:AAAAAAAAAAAAAAAA".to_string(), // valid base64, not valid RLP
            "enr:-IW4QGGifTt9ypyMtChDISUNX3z4z5iPdiEPOmBoILvnDuWIKbWVmKXxZERPnw0piQyaBNCENFEPoIi-vxsnsrBig9MBgmlkgnY0gmlwhH8AAAGEcXVpY4IjKYlzZWNwMjU2azGhAhMMnGF1rmIPQ9tWgqfkNmvsG-aIyc9EJU5JFo3Tegys".to_string(),
        ];

        let bootnodes = parse_enrs(enrs);

        assert_eq!(bootnodes.len(), 1, "exactly the one valid ENR must survive");
        assert_eq!(bootnodes[0].ip, IpAddr::from(Ipv4Addr::LOCALHOST));
        assert_eq!(bootnodes[0].quic_port, Some(9001));
    }
}
