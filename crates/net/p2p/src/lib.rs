use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    ops::Range,
    time::Duration,
};

use ethlambda_network_api::{
    InitBlockChain, P2PToBlockChainRef,
    block_chain_to_p2p::{
        FetchBeaconBlock, FetchBlock, PublishAggregatedAttestation, PublishAttestation,
        PublishBlock,
    },
};
use ethlambda_storage::Store;
use ethlambda_types::enr::EnrForkId;
use ethlambda_types::primitives::H256;
use ethrex_p2p::peer_table::{Contact, PeerTable, PeerTableServerProtocol as _};
use ethrex_p2p::types::NodeRecord;
use ethrex_rlp::decode::RLPDecode;
use futures::StreamExt;
use libp2p::{
    Multiaddr, StreamProtocol,
    gossipsub::{MessageAuthenticity, ValidationMode},
    identity::{Keypair, PublicKey, secp256k1},
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
use tracing::{debug, info, trace, warn};

use crate::{
    discovery::{
        DISCOVERY_CANDIDATE_BATCH, DISCOVERY_DIAL_INTERVAL, DISCOVERY_TARGET_PEERS,
        DiscoveryHandle,
        admission::{DiscoveredPeer, admit, rank_by_uncovered_subnets},
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

pub mod beacon;
pub mod discovery;
mod gossipsub;
pub mod metrics;
pub mod req_resp;
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
    /// Largest `count` a single request may ask for.
    ///
    /// Per-network: lean's `blocks_by_range/1` allows [`MAX_REQUEST_BLOCKS`],
    /// while `beacon_blocks_by_range/2` has been capped at
    /// `MAX_REQUEST_BLOCKS_DENEB` since deneb and a peer may refuse a larger
    /// request outright. Everything else about a sync session is identical on
    /// both chains, which is why this is a field rather than a second type.
    pub(crate) max_batch: u64,
}

impl RangeSyncState {
    pub(crate) fn new(current_range: Range<u64>, peer: PeerId, peer_head: u64) -> Self {
        Self::with_max_batch(current_range, peer, peer_head, MAX_REQUEST_BLOCKS)
    }

    pub(crate) fn with_max_batch(
        current_range: Range<u64>,
        peer: PeerId,
        peer_head: u64,
        max_batch: u64,
    ) -> Self {
        Self {
            current_range,
            peer_set: HashMap::from([(peer, peer_head)]),
            in_flight: false,
            max_batch,
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
            .saturating_add(self.max_batch)
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

/// Everything the dial loop needs from a running discovery server.
pub(crate) struct DiscoveryState {
    pub(crate) peer_table: PeerTable,
    pub(crate) local_fork_id: EnrForkId,
    /// Subnet ids at or beyond this are dropped from a peer's `attnets`.
    pub(crate) subnet_count: u64,
    /// Admitted candidates, best first, drained one per tick. Refilled from the
    /// peer table when empty.
    pub(crate) candidates: VecDeque<DiscoveredPeer>,
    /// Subnets advertised by peers we dialed from discovery.
    pub(crate) peer_attnets: HashMap<PeerId, Vec<u64>>,
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
}

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

/// Which network's wire this node speaks.
///
/// One `P2PServer` serves both, dispatching on this once at the top of each
/// handler, exactly as `BlockChainServer` dispatches on the state variant.
/// Nothing is shared below the match: the topic names, the req/resp protocol
/// ids, the handshake and the decode are all different, and the parts that
/// genuinely coincide (the discv5 stack, the `ssz_snappy` framing,
/// `compute_message_id`) sit one layer down and are the beacon spec's anyway.
pub enum Wire {
    Lean(LeanWire),
    /// Boxed because a `BeaconWire` carries a whole `Config` and so is four
    /// times the size of a `LeanWire`; unboxed, every lean node would pay for
    /// it in each `Wire` it moves.
    Beacon(Box<beacon::BeaconWire>),
}

/// The lean network's gossip topics.
pub struct LeanWire {
    pub(crate) attestation_topics: HashMap<u64, libp2p::gossipsub::IdentTopic>,
    pub(crate) attestation_committee_count: u64,
    pub(crate) block_topic: libp2p::gossipsub::IdentTopic,
    pub(crate) aggregation_topic: libp2p::gossipsub::IdentTopic,
}

impl Wire {
    pub(crate) fn lean(&self) -> Option<&LeanWire> {
        match self {
            Wire::Lean(lean) => Some(lean),
            Wire::Beacon(_) => None,
        }
    }

    pub(crate) fn beacon(&self) -> Option<&beacon::BeaconWire> {
        match self {
            Wire::Beacon(beacon) => Some(beacon),
            Wire::Lean(_) => None,
        }
    }
}

/// Result of building the swarm — contains all pieces needed to start the P2P actor.
pub struct BuiltSwarm {
    /// This node's libp2p peer ID, derived from the node key. Exposed so the
    /// caller can report it (e.g. via the RPC `/lean/v0/node/identity` endpoint).
    pub local_peer_id: PeerId,
    pub(crate) swarm: libp2p::Swarm<Behaviour>,
    pub(crate) wire: Wire,
    pub(crate) bootnode_addrs: HashMap<PeerId, Multiaddr>,
}

/// The gossipsub parameters both wires share.
///
/// `mesh_n` 8, low 6, high 12, the 700ms heartbeat, and the 6/3 history already
/// match the beacon spec, so `seen_ttl` is the only value that differs between
/// the two networks: lean's slot is 4s with a 3-slot justification lookback,
/// mainnet's epoch is 32 slots of 12s.
pub(crate) fn gossipsub_config(seen_ttl: Duration) -> libp2p::gossipsub::Config {
    libp2p::gossipsub::ConfigBuilder::default()
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
        .duplicate_cache_time(seen_ttl)
        .validation_mode(ValidationMode::Anonymous)
        .message_id_fn(compute_message_id)
        // Taken from ream
        .max_transmit_size(MAX_COMPRESSED_PAYLOAD_SIZE)
        .max_messages_per_rpc(Some(500))
        .allow_self_origin(true)
        .idontwant_message_size_threshold(1000)
        .build()
        .expect("invalid gossipsub config")
}

impl Behaviour {
    pub(crate) fn new(
        identify: libp2p::identify::Behaviour,
        gossipsub: libp2p::gossipsub::Behaviour,
        req_resp: request_response::Behaviour<Codec>,
    ) -> Self {
        Self {
            identify,
            gossipsub,
            req_resp,
        }
    }
}

/// Build and configure the libp2p swarm, dial bootnodes, subscribe to topics.
pub fn build_swarm(
    config: SwarmConfig,
) -> Result<BuiltSwarm, libp2p::gossipsub::SubscriptionError> {
    // seen_ttl_secs = seconds_per_slot * justification_lookback_slots * 2
    let gossipsub_config = gossipsub_config(Duration::from_secs(4 * 3 * 2));

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

    let behavior = Behaviour::new(identify, gossipsub, req_resp);

    // TODO: set peer scoring params

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
        // Discovery-only seed: reachable over discv5, but with no QUIC port
        // there is nothing for the swarm to dial.
        let Some(quic_port) = bootnode.quic_port else {
            debug!(%peer_id, ip = %bootnode.ip, "Bootnode advertises no quic port, discv5 seed only");
            continue;
        };
        let addr = Multiaddr::empty()
            .with(bootnode.ip.into())
            .with(Protocol::Udp(quic_port))
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
        wire: Wire::Lean(LeanWire {
            attestation_topics,
            attestation_committee_count: config.attestation_committee_count,
            block_topic,
            aggregation_topic,
        }),
        bootnode_addrs,
    })
}

// --- P2P Actor ---

/// Public handle to the P2P actor.
pub struct P2P {
    handle: ActorRef<P2PServer>,
}

impl P2P {
    /// Build swarm, start I/O adapter, spawn actor, and wire the swarm event stream.
    ///
    /// `discovery` is `Some` when discv5 discovery is enabled; it seeds the
    /// dial loop's state and schedules its first tick. `None` leaves the dial
    /// loop permanently dormant, so peering relies solely on the static
    /// bootnode list dialed by `build_swarm`.
    pub fn spawn(
        built: BuiltSwarm,
        store: Store,
        node_names: HashMap<PeerId, String>,
        discovery: Option<DiscoveryHandle>,
    ) -> P2P {
        let (swarm_stream, swarm_handle) =
            swarm_adapter::start_swarm_adapter(built.swarm, node_names.clone());

        let server = P2PServer {
            swarm_handle,
            store,
            blockchain: None,
            wire: built.wire,
            connected_peers: HashSet::new(),
            pending_root_requests: HashMap::new(),
            outbound_requests: HashMap::new(),
            range_sync_state: None,
            bootnode_addrs: built.bootnode_addrs,
            node_names,
            local_peer_id: built.local_peer_id,
            discovery: discovery.map(|handle| DiscoveryState {
                peer_table: handle.peer_table,
                local_fork_id: handle.local_fork_id,
                subnet_count: handle.subnet_count,
                candidates: VecDeque::new(),
                peer_attnets: HashMap::new(),
            }),
        };
        // Read the flag before `server` is moved into `start()`.
        let discovery_enabled = server.discovery.is_some();
        let handle = server.start();
        if discovery_enabled {
            send_after(
                DISCOVERY_DIAL_INTERVAL,
                handle.context(),
                p2p_protocol::DiscoverPeers,
            );
        }
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

    pub(crate) wire: Wire,

    pub(crate) connected_peers: HashSet<PeerId>,
    pub(crate) pending_root_requests: HashMap<H256, PendingRequest>,
    pub(crate) outbound_requests: HashMap<OutboundRequestId, PendingRequestKind>,
    pub(crate) range_sync_state: Option<RangeSyncState>,
    bootnode_addrs: HashMap<PeerId, Multiaddr>,
    node_names: HashMap<PeerId, String>,

    /// Set when discovery is enabled. `None` disables the dial loop entirely.
    pub(crate) discovery: Option<DiscoveryState>,
    /// Our own peer ID, so the dial loop never dials itself.
    pub(crate) local_peer_id: PeerId,
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

        info!(%root, "Retrying block fetch after backoff");

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

        if let Some(addr) = self.bootnode_addrs.get(&peer_id) {
            info!(%peer_id, "Redialing disconnected bootnode");
            self.swarm_handle.dial(addr.clone());
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

        if self.connected_peers.len() >= DISCOVERY_TARGET_PEERS {
            return;
        }

        // Snapshot what the refill needs before any `.await`, so no borrow of
        // `self.discovery` has to live across the async boundary.
        let Some((peer_table, local_fork_id, subnet_count, needs_refill)) =
            self.discovery.as_ref().map(|discovery| {
                (
                    discovery.peer_table.clone(),
                    discovery.local_fork_id,
                    discovery.subnet_count,
                    discovery.candidates.is_empty(),
                )
            })
        else {
            return;
        };

        if needs_refill {
            // ethrex serves one contact per call and records each as tried
            // before returning it, so successive calls never repeat and an
            // early `None` means the pool is exhausted.
            let mut contacts = Vec::with_capacity(DISCOVERY_CANDIDATE_BATCH);
            for _ in 0..DISCOVERY_CANDIDATE_BATCH {
                match peer_table.get_contact_to_initiate().await {
                    Ok(Some(contact)) => contacts.push(*contact),
                    _ => break,
                }
            }

            let (mut admitted, unwanted) =
                select_candidates(contacts, &local_fork_id, subnet_count);
            for node_id in unwanted {
                let _ = peer_table.set_unwanted(node_id);
            }

            let Some(discovery) = self.discovery.as_mut() else {
                return;
            };
            let covered = covered_subnets(&discovery.peer_attnets, &self.connected_peers);
            rank_by_uncovered_subnets(&mut admitted, &covered);
            discovery.candidates.extend(admitted);
        }

        let local_peer_id = self.local_peer_id;
        let Some(discovery) = self.discovery.as_mut() else {
            return;
        };
        while let Some(candidate) = discovery.candidates.pop_front() {
            if candidate.peer_id == local_peer_id
                || self.connected_peers.contains(&candidate.peer_id)
            {
                continue;
            }
            info!(
                peer_id = %candidate.peer_id,
                subnets = ?candidate.subnets,
                "Dialing discovered peer"
            );
            discovery
                .peer_attnets
                .insert(candidate.peer_id, candidate.subnets.clone());
            metrics::inc_discovered_peers_dialed();
            self.swarm_handle.dial(candidate.addr);
            break;
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
        if self.pending_root_requests.contains_key(&root) {
            trace!(%root, "Block fetch already in progress, ignoring duplicate");
            return;
        }
        fetch_block_from_peer(self, root).await;
    }
}

impl Handler<FetchBeaconBlock> for P2PServer {
    async fn handle(&mut self, msg: FetchBeaconBlock, _ctx: &Context<Self>) {
        // The by-root fetch itself lands with `beacon::sync`, which owns the
        // in-flight table this needs to deduplicate against.
        trace!(root = %msg.root, "Beacon block fetch requested");
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
            if server.wire.beacon().is_some() {
                beacon::handler::handle_beacon_gossip_message(server, message).await;
            } else {
                gossipsub::handle_gossipsub_message(server, message).await;
            }
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
                metrics::notify_peer_connected(
                    server.resolve_node_name(Some(&peer_id)),
                    direction,
                    "success",
                );
                // Compute the beacon status and its log fields first, so no
                // borrow of `server.wire` is alive across the send.
                let beacon_status = server.wire.beacon().map(|wire| {
                    (
                        beacon::handler::build_status(wire),
                        hex::encode(wire.fork_digest),
                    )
                });
                match beacon_status {
                    Some((status, digest)) => {
                        info!(
                            %peer_id,
                            %direction,
                            peer_count,
                            fork_digest = %digest,
                            "Peer connected"
                        );
                        beacon::handler::send_status(server, peer_id, status).await;
                    }
                    None => {
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
                    }
                }
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
                if let Some(discovery) = server.discovery.as_mut() {
                    discovery.peer_attnets.remove(&peer_id);
                }
                let peer_count = server.connected_peers.len();
                metrics::notify_peer_disconnected(
                    server.resolve_node_name(Some(&peer_id)),
                    direction,
                    reason,
                );

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
            metrics::notify_peer_connected(
                server.resolve_node_name(peer_id.as_ref()),
                "outbound",
                result,
            );
            warn!(?peer_id, %error, "Outgoing connection error");

            // A dial that never establishes ends up here rather than in
            // `ConnectionClosed`, so this is the only place a discovery-fed
            // `peer_attnets` entry can be removed for a peer we dialed but
            // never actually connected to. Leaving it would grow the map
            // without bound and make `covered_subnets` credit a subnet to a
            // peer that isn't connected.
            if let Some(pid) = peer_id
                && let Some(discovery) = server.discovery.as_mut()
            {
                discovery.peer_attnets.remove(&pid);
            }

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
            metrics::notify_peer_connected(
                server.resolve_node_name(peer_id.as_ref()),
                "inbound",
                "error",
            );
            warn!(%error, "Incoming connection error");
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

pub struct Bootnode {
    pub(crate) ip: IpAddr,
    /// The libp2p QUIC port, when the ENR advertises one.
    ///
    /// `None` for records that are discv5-reachable but speak no transport we
    /// have: every beacon-chain bootnode published today advertises `tcp` and
    /// `udp` but no `quic`. Such a bootnode still seeds the discv5 routing
    /// table; it just is never dialed statically.
    pub(crate) quic_port: Option<u16>,
    /// The discv5 UDP port, when the ENR advertises one.
    ///
    /// `None` for the ENRs lean-quickstart generates today, which carry only
    /// `ip`/`quic`/`secp256k1`. Such a bootnode is still dialed statically over
    /// QUIC; it just cannot seed the discv5 routing table.
    pub(crate) udp_port: Option<u16>,
    pub(crate) public_key: PublicKey,
}

impl Bootnode {
    /// This bootnode as a discv5 seed, or `None` when its ENR advertises no
    /// `udp` port and it therefore cannot be reached by discovery.
    ///
    /// `tcp_port` is 0: ethrex reads that as "no TCP listener".
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
        Some(ethrex_p2p::types::Node::new(
            self.ip,
            udp_port,
            0,
            ethrex_common::H512::from_slice(&uncompressed[1..]),
        ))
    }
}

/// Decode `enr:`-prefixed records into dialable bootnodes.
///
/// Records that cannot be decoded, or that lack a QUIC port, an IP or a public
/// key, are skipped with a warning rather than aborting startup: one malformed
/// entry in the bootnode file should not stop the node from booting.
pub fn parse_enrs(enrs: Vec<String>) -> Vec<Bootnode> {
    enrs.into_iter()
        .filter_map(|enr_str| match parse_enr(&enr_str) {
            Ok(bootnode) => Some(bootnode),
            Err(reason) => {
                warn!(%reason, enr = %enr_str, "Skipping unusable bootnode ENR");
                None
            }
        })
        .collect()
}

fn parse_enr(enr_str: &str) -> Result<Bootnode, String> {
    let stripped = enr_str
        .strip_prefix("enr:")
        .ok_or_else(|| "missing enr: prefix".to_string())?;
    let decoded = ethrex_common::base64::decode(stripped.as_bytes());
    let record = NodeRecord::decode(&decoded).map_err(|err| format!("RLP decode failed: {err}"))?;
    let pairs = record.pairs();

    // A record with no `quic` entry is not an error: it is discv5-reachable but
    // speaks no transport we have, which is exactly what every beacon-chain
    // bootnode looks like. Keep it as a discovery seed and let `build_swarm`
    // skip it when it picks static dial targets.
    // `extra_int` answers `None` both for an absent entry and for one whose
    // encoding it cannot read, which includes the non-minimal forms some
    // clients emit. Either way there is no port we can dial.
    //
    // A zero is filtered out too: an absent entry RLP-decodes to 0 via
    // left-padding, and 0 is undialable regardless, so both collapse to "no
    // quic port".
    let quic_port = pairs.extra_int::<u16>(b"quic").filter(|port| *port != 0);

    let public_key_bytes = pairs
        .secp256k1
        .ok_or_else(|| "node record missing public key".to_string())?;
    let public_key =
        libp2p::identity::secp256k1::PublicKey::try_from_bytes(public_key_bytes.as_bytes())
            .map_err(|err| format!("bad secp256k1 key: {err}"))?;

    // Prefer IPv4 if both are present.
    let ip = pairs
        .ip
        .map(IpAddr::from)
        .or_else(|| pairs.ip6.map(IpAddr::from))
        .ok_or_else(|| "node record missing IP address".to_string())?;

    // `quic` and `udp` are independently optional, but a record with neither is
    // reachable by nothing we speak: it can be neither dialed nor seeded. Drop
    // it here rather than carry a contact that no code path can ever use.
    if quic_port.is_none() && pairs.udp_port.is_none() {
        return Err("node advertises neither a quic nor a udp port".to_string());
    }

    Ok(Bootnode {
        ip,
        quic_port,
        udp_port: pairs.udp_port,
        public_key: public_key.into(),
    })
}

// --- Utility functions ---

/// Split discovered contacts into peers worth dialing and node ids to blacklist.
///
/// Pure so the admission policy can be tested without an actor, a socket or a
/// peer table. Contacts whose ENR has not arrived yet are skipped without being
/// blacklisted, and only permanent rejections are reported as unwanted.
///
/// The returned ids are `ethrex_common::H256` (discv5 node ids, i.e.
/// `PeerTable::set_unwanted`'s currency), not the ethlambda `H256` this module
/// otherwise uses for block/state roots; the two are unrelated types that
/// happen to share a name, so the crate path is spelled out here.
fn select_candidates(
    contacts: Vec<Contact>,
    local_fork_id: &EnrForkId,
    attestation_committee_count: u64,
) -> (Vec<DiscoveredPeer>, Vec<ethrex_common::H256>) {
    let mut admitted = Vec::with_capacity(contacts.len());
    let mut unwanted = Vec::new();
    for contact in contacts {
        let Some(record) = contact.record.as_ref() else {
            // ethrex's `get_contact_to_initiate` already added this node id
            // to `already_tried_peers` when it drew this contact, regardless
            // of what we do with it here. That set is only cleared once a
            // full pool scan finds nothing eligible, so skipping it now does
            // not make it any more or less likely to be redrawn soon.
            continue;
        };
        match admit(record, local_fork_id, attestation_committee_count) {
            Ok(peer) => admitted.push(peer),
            Err(reason) => {
                debug!(
                    node_id = %contact.node.node_id(),
                    reason = reason.as_str(),
                    "Rejecting discovered peer"
                );
                if reason.is_permanent() {
                    unwanted.push(contact.node.node_id());
                }
            }
        }
    }
    (admitted, unwanted)
}

/// Attestation subnets covered by peers we are currently connected to.
///
/// Only peers dialed from discovery contribute, since an inbound peer never
/// tells us its `attnets`. Treating an unknown peer as covering nothing makes
/// the ranking more eager, never wrong.
fn covered_subnets(
    peer_attnets: &HashMap<PeerId, Vec<u64>>,
    connected_peers: &HashSet<PeerId>,
) -> HashSet<u64> {
    peer_attnets
        .iter()
        .filter(|(peer, _)| connected_peers.contains(peer))
        .flat_map(|(_, subnets)| subnets.iter().copied())
        .collect()
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

    fn random_peer() -> PeerId {
        PeerId::from_public_key(&Keypair::generate_ed25519().public())
    }

    #[test]
    fn a_lean_wire_reports_its_topics_and_no_beacon_wire() {
        // The enum is what makes "subscribed to lean topics and beacon topics
        // at once" unrepresentable. `P2PServer` dispatches on it once per
        // handler, the same way `BlockChainServer` dispatches on the state
        // variant.
        let wire = Wire::Lean(LeanWire {
            attestation_topics: HashMap::new(),
            attestation_committee_count: 4,
            block_topic: block_topic(),
            aggregation_topic: aggregation_topic(),
        });
        assert!(wire.beacon().is_none());
        let lean = wire.lean().expect("a lean wire");
        assert_eq!(lean.attestation_committee_count, 4);
        assert!(lean.block_topic.to_string().starts_with("/leanconsensus/"));
    }

    #[test]
    fn range_sync_state_caps_a_batch_at_its_own_limit() {
        // A beacon session batches 128 blocks, not lean's 1024:
        // beacon_blocks_by_range/2 is capped at MAX_REQUEST_BLOCKS_DENEB, and a
        // peer may reject a larger count outright.
        let peer = random_peer();
        let state = RangeSyncState::with_max_batch(10..3000, peer, 2999, 128);

        let (selected, batch) = state.next_batch().expect("batch available");

        assert_eq!(selected, peer);
        assert_eq!(batch, 10..138);
    }

    #[test]
    fn range_sync_state_new_keeps_leans_limit() {
        // The existing constructor must not change behaviour for lean.
        let peer = random_peer();
        let state = RangeSyncState::new(10..30_000, peer, 29_999);

        let (_, batch) = state.next_batch().expect("batch available");

        assert_eq!(batch, 10..(10 + MAX_REQUEST_BLOCKS));
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
    fn covered_subnets_unions_only_connected_peers() {
        let connected = random_peer();
        let gone = random_peer();
        let mut server_subnets = HashMap::new();
        server_subnets.insert(connected, vec![1u64, 2]);
        server_subnets.insert(gone, vec![7u64]);

        let connected_peers = HashSet::from([connected]);
        let covered = covered_subnets(&server_subnets, &connected_peers);

        assert_eq!(covered, HashSet::from([1, 2]));
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
        pairs.set_extra_int(b"quic", 9001u16);
        let record = NodeRecord::from_pairs(1, &signer, pairs).unwrap();

        let bootnodes = parse_enrs(vec![record.enr_url().unwrap()]);

        assert_eq!(bootnodes.len(), 1);
        assert_eq!(bootnodes[0].ip, IpAddr::from(Ipv4Addr::LOCALHOST));
        assert_eq!(bootnodes[0].quic_port, Some(9001));
        assert_eq!(bootnodes[0].udp_port, Some(9010));
    }

    #[test]
    fn parse_enrs_keeps_a_quic_less_record_as_a_discovery_seed() {
        // Some nodes advertise `tcp` and `udp` but no `quic`, so requiring
        // `quic` here would drop the entire mainnet bootstrap list and leave
        // discv5 with nothing to seed from. Such a record is kept, with
        // `quic_port: None` telling `build_swarm` not to dial it.
        //
        // The two ENRs are from eth-clients/mainnet's `bootstrap_nodes.yaml`.
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

    /// Build a signed ENR carrying `eth2` + (optionally) `quic` + `attnets`,
    /// for [`select_candidates`] tests. `attnets_bits` is written verbatim,
    /// bypassing `encode_attnets`'s own committee-count clamp, the way a
    /// hostile peer crafting the bytes by hand would.
    fn enr_for(fork_id: EnrForkId, quic_port: Option<u16>, attnets_bits: Vec<u8>) -> NodeRecord {
        use ::secp256k1 as raw_secp256k1;
        use libssz::SszEncode;

        let signer = raw_secp256k1::SecretKey::new(&mut rand::rngs::OsRng);
        let mut pairs = ethrex_p2p::types::NodeRecordPairs {
            ip: Some(Ipv4Addr::LOCALHOST),
            udp_port: Some(9010),
            tcp_port: None,
            ..Default::default()
        };
        pairs.set_extra(crate::discovery::enr::ATTNETS_ENR_KEY, attnets_bits);
        pairs.set_extra(crate::discovery::enr::ETH2_ENR_KEY, fork_id.to_ssz());
        if let Some(port) = quic_port {
            pairs.set_extra_int(crate::discovery::enr::QUIC_ENR_KEY, port);
        }
        NodeRecord::from_pairs(1, &signer, pairs).unwrap()
    }

    /// Wrap a record in a `Contact` the way `PeerTable::get_contact_to_initiate`
    /// would once the ENR has arrived.
    fn contact_with_record(record: NodeRecord) -> Contact {
        let node =
            ethrex_p2p::types::Node::from_enr(&record).expect("record is a valid discv5 node");
        let mut contact = Contact::new(node, ethrex_p2p::peer_table::DiscoveryProtocol::Discv5);
        contact.record = Some(record);
        contact
    }

    #[test]
    fn select_candidates_admits_a_well_formed_contact() {
        let record = enr_for(
            EnrForkId::local(),
            Some(9001),
            ethlambda_types::enr::encode_attnets(&HashSet::from([2u64]), 8),
        );

        let (admitted, unwanted) =
            select_candidates(vec![contact_with_record(record)], &EnrForkId::local(), 8);

        assert_eq!(admitted.len(), 1);
        assert_eq!(admitted[0].subnets, vec![2]);
        assert!(unwanted.is_empty());
    }

    #[test]
    fn select_candidates_skips_a_pending_enr_without_blacklisting_it() {
        // Discovered by node id, but the ENR request/response round trip
        // hasn't completed yet.
        let node = ethrex_p2p::types::Node::new(
            IpAddr::from(Ipv4Addr::LOCALHOST),
            9010,
            0,
            ethrex_common::H512::zero(),
        );
        let contact = Contact::new(node, ethrex_p2p::peer_table::DiscoveryProtocol::Discv5);
        assert!(contact.record.is_none());

        let (admitted, unwanted) = select_candidates(vec![contact], &EnrForkId::local(), 8);

        assert!(admitted.is_empty());
        assert!(unwanted.is_empty());
    }

    #[test]
    fn select_candidates_blacklists_a_fork_digest_mismatch() {
        let mut foreign = EnrForkId::local();
        foreign.fork_digest = [0xde, 0xad, 0xbe, 0xef];
        let record = enr_for(foreign, Some(9001), Vec::new());
        let expected_node_id = ethrex_p2p::types::Node::from_enr(&record)
            .unwrap()
            .node_id();

        let (admitted, unwanted) =
            select_candidates(vec![contact_with_record(record)], &EnrForkId::local(), 8);

        assert!(admitted.is_empty());
        assert_eq!(
            unwanted,
            vec![expected_node_id],
            "a different network is a permanent rejection (fix 3)"
        );
    }

    #[test]
    fn select_candidates_does_not_blacklist_a_missing_quic_port() {
        // NoQuicPort is not permanent (fix 3): a later ENR can add one, so
        // blacklisting it in ethrex's peer table (which never un-blacklists)
        // would be irreversible for no good reason.
        let record = enr_for(EnrForkId::local(), None, Vec::new());

        let (admitted, unwanted) =
            select_candidates(vec![contact_with_record(record)], &EnrForkId::local(), 8);

        assert!(admitted.is_empty());
        assert!(unwanted.is_empty());
    }

    #[test]
    fn select_candidates_clamps_a_hostile_oversized_attnets_out_of_the_ranking() {
        // Mirrors fix 2's exploit. The honest peer claims one real subnet.
        // The hostile peer claims none of the real subnets but pads its
        // `attnets` bytes with ~290 bytes of 0xFF, decoding to thousands of
        // subnet ids that do not exist for an 8-subnet committee. Pre-fix,
        // that raw count would dominate `rank_by_uncovered_subnets` forever;
        // post-fix, `admit` drops every id >= the committee count before
        // ranking ever sees it, leaving the hostile peer with nothing real to
        // claim.
        const COMMITTEE_COUNT: u64 = 8;
        let mut hostile_bits = vec![0u8; COMMITTEE_COUNT.div_ceil(8) as usize];
        hostile_bits.extend(vec![0xffu8; 290]);

        let honest = enr_for(
            EnrForkId::local(),
            Some(9001),
            ethlambda_types::enr::encode_attnets(&HashSet::from([3u64]), COMMITTEE_COUNT),
        );
        let hostile = enr_for(EnrForkId::local(), Some(9002), hostile_bits);

        let (mut admitted, unwanted) = select_candidates(
            vec![contact_with_record(honest), contact_with_record(hostile)],
            &EnrForkId::local(),
            COMMITTEE_COUNT,
        );
        assert!(unwanted.is_empty());
        assert_eq!(admitted.len(), 2);
        assert!(
            admitted
                .iter()
                .all(|peer| peer.subnets.iter().all(|&s| s < COMMITTEE_COUNT)),
            "no admitted peer may advertise a subnet outside the local committee"
        );

        rank_by_uncovered_subnets(&mut admitted, &HashSet::new());
        assert_eq!(
            admitted[0].subnets,
            vec![3],
            "the honest peer's real subnet must outrank the hostile peer's fabricated ones"
        );
    }
}
