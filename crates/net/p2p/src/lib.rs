use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use ethlambda_blockchain::BlockChain;
use ethlambda_storage::Store;
use ethlambda_types::{
    ShortRoot,
    attestation::{SignedAggregatedAttestation, SignedAttestation},
    block::SignedBlockWithAttestation,
    primitives::{
        H256,
        ssz::{Encode, TreeHash},
    },
};
use ethrex_common::H264;
use ethrex_p2p::types::NodeRecord;
use ethrex_rlp::decode::RLPDecode;
use libp2p::{
    Multiaddr, PeerId, StreamProtocol,
    gossipsub::{self as libp2p_gossipsub, MessageAuthenticity, ValidationMode},
    identity::{PublicKey, secp256k1},
    multiaddr::Protocol,
    request_response,
    swarm::NetworkBehaviour,
};
use rand::seq::SliceRandom;
use sha2::Digest;
use spawned_concurrency::actor;
use spawned_concurrency::error::ActorError;
use spawned_concurrency::protocol;
use spawned_concurrency::tasks::{Actor, ActorRef, ActorStart, Context, Handler, send_after};
use tokio::sync::mpsc;
use tracing::{error, info, trace, warn};

use crate::{
    gossipsub::{
        AGGREGATION_TOPIC_KIND, ATTESTATION_SUBNET_TOPIC_PREFIX, BLOCK_TOPIC_KIND,
        encoding::compress_message,
    },
    req_resp::{
        BLOCKS_BY_ROOT_PROTOCOL_V1, BlocksByRootRequest, Codec, MAX_COMPRESSED_PAYLOAD_SIZE,
        Request, RequestedBlockRoots, Response, ResponsePayload, STATUS_PROTOCOL_V1, Status,
        build_status,
    },
    swarm_driver::{SwarmCommand, SwarmDriver},
};

mod gossipsub;
pub mod metrics;
mod req_resp;
mod swarm_driver;

pub use metrics::populate_name_registry;

// 5ms, 10ms, 20ms, 40ms, 80ms, 160ms, 320ms, 640ms, 1280ms, 2560ms
const MAX_FETCH_RETRIES: u32 = 10;
const INITIAL_BACKOFF_MS: u64 = 5;
const BACKOFF_MULTIPLIER: u64 = 2;
const PEER_REDIAL_INTERVAL_SECS: u64 = 12;

pub(crate) struct PendingRequest {
    pub(crate) attempts: u32,
}

/// Wrapper for ResponseChannel that implements Clone via Arc<Mutex<Option<_>>>.
///
/// The spawned-concurrency `#[protocol]` macro derives Clone on all generated
/// message structs, but libp2p's ResponseChannel is not Clone. This wrapper
/// allows the channel to be sent through the actor's mailbox. The inner Option
/// is taken when the response is sent, ensuring single-use semantics.
#[derive(Clone)]
pub(crate) struct ResponseChannelWrapper(
    Arc<Mutex<Option<request_response::ResponseChannel<Response>>>>,
);

impl ResponseChannelWrapper {
    pub(crate) fn new(channel: request_response::ResponseChannel<Response>) -> Self {
        Self(Arc::new(Mutex::new(Some(channel))))
    }

    pub(crate) fn take(&self) -> Option<request_response::ResponseChannel<Response>> {
        self.0.lock().unwrap().take()
    }
}

// --- P2P Protocol ---

#[protocol]
pub(crate) trait P2pProtocol: Send + Sync {
    // From SwarmDriver — gossip
    fn on_gossip_block(&self, block: SignedBlockWithAttestation) -> Result<(), ActorError>;
    fn on_gossip_attestation(&self, attestation: SignedAttestation) -> Result<(), ActorError>;
    fn on_gossip_aggregated_attestation(
        &self,
        attestation: SignedAggregatedAttestation,
    ) -> Result<(), ActorError>;

    // From SwarmDriver — req/resp
    fn on_status_request(
        &self,
        status: Status,
        channel: ResponseChannelWrapper,
        peer: PeerId,
    ) -> Result<(), ActorError>;
    fn on_blocks_by_root_request(
        &self,
        request: BlocksByRootRequest,
        channel: ResponseChannelWrapper,
        peer: PeerId,
    ) -> Result<(), ActorError>;
    fn on_status_response(&self, status: Status, peer: PeerId) -> Result<(), ActorError>;
    fn on_blocks_by_root_response(
        &self,
        blocks: Vec<SignedBlockWithAttestation>,
        peer: PeerId,
        correlation_id: u64,
    ) -> Result<(), ActorError>;
    fn on_req_resp_failure(
        &self,
        peer: PeerId,
        correlation_id: u64,
        error: String,
    ) -> Result<(), ActorError>;

    // From SwarmDriver — connections
    fn on_peer_connected(
        &self,
        peer_id: PeerId,
        direction: String,
        first_connection: bool,
    ) -> Result<(), ActorError>;
    fn on_peer_disconnected(
        &self,
        peer_id: PeerId,
        direction: String,
        reason: String,
        last_connection: bool,
    ) -> Result<(), ActorError>;
    fn on_outgoing_connection_error(
        &self,
        peer_id: Option<PeerId>,
        error: String,
    ) -> Result<(), ActorError>;

    // From BlockChain (via P2PMessage bridge)
    fn publish_attestation(&self, attestation: SignedAttestation) -> Result<(), ActorError>;
    fn publish_block(&self, signed_block: SignedBlockWithAttestation) -> Result<(), ActorError>;
    fn publish_aggregated_attestation(
        &self,
        attestation: SignedAggregatedAttestation,
    ) -> Result<(), ActorError>;
    fn fetch_block(&self, root: H256) -> Result<(), ActorError>;

    // Self-scheduled retries
    #[allow(dead_code)]
    fn retry_block_fetch(&self, root: H256) -> Result<(), ActorError>;
    #[allow(dead_code)]
    fn retry_peer_redial(&self, peer_id: PeerId) -> Result<(), ActorError>;
}

// --- P2PServer (actor state) ---

pub(crate) struct P2PServer {
    swarm_tx: mpsc::UnboundedSender<SwarmCommand>,
    blockchain: BlockChain,
    store: Store,
    attestation_topic: libp2p_gossipsub::IdentTopic,
    block_topic: libp2p_gossipsub::IdentTopic,
    aggregation_topic: libp2p_gossipsub::IdentTopic,
    connected_peers: HashSet<PeerId>,
    pending_requests: HashMap<H256, PendingRequest>,
    /// Maps correlation IDs to block roots for tracking outbound BlocksByRoot requests.
    correlation_id_map: HashMap<u64, H256>,
    next_correlation_id: u64,
    /// Bootnode addresses for redialing when disconnected.
    bootnode_addrs: HashMap<PeerId, Multiaddr>,
}

impl P2PServer {
    fn next_correlation_id(&mut self) -> u64 {
        let id = self.next_correlation_id;
        self.next_correlation_id += 1;
        id
    }

    /// Fetch a missing block from a random connected peer.
    fn fetch_block_from_peer(&mut self, root: H256) -> bool {
        if self.connected_peers.is_empty() {
            warn!(%root, "Cannot fetch block: no connected peers");
            return false;
        }

        let peers: Vec<_> = self.connected_peers.iter().copied().collect();
        let peer = match peers.choose(&mut rand::thread_rng()) {
            Some(&p) => p,
            None => {
                warn!(%root, "Failed to select random peer");
                return false;
            }
        };

        let mut roots = RequestedBlockRoots::empty();
        if let Err(err) = roots.push(root) {
            error!(%root, ?err, "Failed to create BlocksByRoot request");
            return false;
        }
        let request = BlocksByRootRequest { roots };

        info!(%peer, %root, "Sending BlocksByRoot request for missing block");

        let correlation_id = self.next_correlation_id();
        let _ = self.swarm_tx.send(SwarmCommand::SendRequest {
            correlation_id,
            peer_id: peer,
            request: Request::BlocksByRoot(request),
            protocol: StreamProtocol::new(BLOCKS_BY_ROOT_PROTOCOL_V1),
        });

        self.pending_requests
            .entry(root)
            .or_insert(PendingRequest { attempts: 1 });

        self.correlation_id_map.insert(correlation_id, root);

        true
    }

    /// Handle a fetch failure by scheduling a retry with exponential backoff.
    fn handle_fetch_failure(&mut self, root: H256, peer: PeerId, ctx: &Context<Self>) {
        let Some(pending) = self.pending_requests.get_mut(&root) else {
            return;
        };

        if pending.attempts >= MAX_FETCH_RETRIES {
            error!(
                %root, %peer, attempts = %pending.attempts,
                "Block fetch failed after max retries, giving up"
            );
            self.pending_requests.remove(&root);
            return;
        }

        let backoff_ms = INITIAL_BACKOFF_MS * BACKOFF_MULTIPLIER.pow(pending.attempts - 1);
        let backoff = Duration::from_millis(backoff_ms);

        warn!(
            %root, %peer, attempts = %pending.attempts, ?backoff,
            "Block fetch failed, scheduling retry"
        );

        pending.attempts += 1;

        send_after(backoff, ctx.clone(), p2p_protocol::RetryBlockFetch { root });
    }
}

// --- Actor implementation ---

#[actor(protocol = P2pProtocol)]
impl P2PServer {
    // --- Gossip handlers ---

    #[send_handler]
    async fn handle_on_gossip_block(
        &mut self,
        msg: p2p_protocol::OnGossipBlock,
        _ctx: &Context<Self>,
    ) {
        let signed_block = msg.block;
        let slot = signed_block.message.block.slot;
        let block_root = signed_block.message.block.tree_hash_root();
        let proposer = signed_block.message.block.proposer_index;
        let parent_root = signed_block.message.block.parent_root;
        let attestation_count = signed_block.message.block.body.attestations.len();
        info!(
            %slot,
            proposer,
            block_root = %ShortRoot(&block_root.0),
            parent_root = %ShortRoot(&parent_root.0),
            attestation_count,
            "Received block from gossip"
        );
        self.blockchain.notify_new_block(signed_block);
    }

    #[send_handler]
    async fn handle_on_gossip_attestation(
        &mut self,
        msg: p2p_protocol::OnGossipAttestation,
        _ctx: &Context<Self>,
    ) {
        let attestation = msg.attestation;
        let slot = attestation.data.slot;
        let validator = attestation.validator_id;
        info!(
            %slot,
            validator,
            head_root = %ShortRoot(&attestation.data.head.root.0),
            target_slot = attestation.data.target.slot,
            target_root = %ShortRoot(&attestation.data.target.root.0),
            source_slot = attestation.data.source.slot,
            source_root = %ShortRoot(&attestation.data.source.root.0),
            "Received attestation from gossip"
        );
        self.blockchain.notify_new_attestation(attestation);
    }

    #[send_handler]
    async fn handle_on_gossip_aggregated_attestation(
        &mut self,
        msg: p2p_protocol::OnGossipAggregatedAttestation,
        _ctx: &Context<Self>,
    ) {
        let attestation = msg.attestation;
        let slot = attestation.data.slot;
        info!(
            %slot,
            target_slot = attestation.data.target.slot,
            target_root = %ShortRoot(&attestation.data.target.root.0),
            source_slot = attestation.data.source.slot,
            source_root = %ShortRoot(&attestation.data.source.root.0),
            "Received aggregated attestation from gossip"
        );
        self.blockchain
            .notify_new_aggregated_attestation(attestation);
    }

    // --- Req/resp handlers ---

    #[send_handler]
    async fn handle_on_status_request(
        &mut self,
        msg: p2p_protocol::OnStatusRequest,
        _ctx: &Context<Self>,
    ) {
        let request = msg.status;
        let peer = msg.peer;
        info!(
            finalized_slot = %request.finalized.slot,
            head_slot = %request.head.slot,
            "Received status request from peer {peer}"
        );
        let our_status = build_status(&self.store);
        if let Some(channel) = msg.channel.take() {
            let response = Response::success(ResponsePayload::Status(our_status));
            let _ = self
                .swarm_tx
                .send(SwarmCommand::SendResponse { channel, response });
        }
    }

    #[send_handler]
    async fn handle_on_blocks_by_root_request(
        &mut self,
        msg: p2p_protocol::OnBlocksByRootRequest,
        _ctx: &Context<Self>,
    ) {
        let request = msg.request;
        let peer = msg.peer;
        let num_roots = request.roots.len();
        info!(%peer, num_roots, "Received BlocksByRoot request");

        let mut blocks = Vec::new();
        for root in request.roots.iter() {
            if let Some(signed_block) = self.store.get_signed_block(root) {
                blocks.push(signed_block);
            }
            // Missing blocks are silently skipped (per spec)
        }

        let found = blocks.len();
        info!(%peer, num_roots, found, "Responding to BlocksByRoot request");

        if let Some(channel) = msg.channel.take() {
            let response = Response::success(ResponsePayload::BlocksByRoot(blocks));
            let _ = self
                .swarm_tx
                .send(SwarmCommand::SendResponse { channel, response })
                .inspect_err(
                    |err| warn!(%peer, %err, "Failed to send BlocksByRoot response command"),
                );
        }
    }

    #[send_handler]
    async fn handle_on_status_response(
        &mut self,
        msg: p2p_protocol::OnStatusResponse,
        _ctx: &Context<Self>,
    ) {
        info!(
            finalized_slot = %msg.status.finalized.slot,
            head_slot = %msg.status.head.slot,
            "Received status response from peer {}",
            msg.peer
        );
    }

    #[send_handler]
    async fn handle_on_blocks_by_root_response(
        &mut self,
        msg: p2p_protocol::OnBlocksByRootResponse,
        ctx: &Context<Self>,
    ) {
        let blocks = msg.blocks;
        let peer = msg.peer;
        let correlation_id = msg.correlation_id;
        info!(%peer, count = blocks.len(), "Received BlocksByRoot response");

        let Some(requested_root) = self.correlation_id_map.remove(&correlation_id) else {
            warn!(%peer, correlation_id, "Received response for unknown correlation_id");
            return;
        };

        if blocks.is_empty() {
            self.correlation_id_map
                .insert(correlation_id, requested_root);
            warn!(%peer, "Received empty BlocksByRoot response");
            self.handle_fetch_failure(requested_root, peer, ctx);
            return;
        }

        for block in blocks {
            let root = block.message.block.tree_hash_root();
            if root != requested_root {
                warn!(
                    %peer,
                    received_root = %ShortRoot(&root.0),
                    expected_root = %ShortRoot(&requested_root.0),
                    "Received block with mismatched root, ignoring"
                );
                continue;
            }
            self.pending_requests.remove(&root);
            self.blockchain.notify_new_block(block);
        }
    }

    #[send_handler]
    async fn handle_on_req_resp_failure(
        &mut self,
        msg: p2p_protocol::OnReqRespFailure,
        ctx: &Context<Self>,
    ) {
        if let Some(root) = self.correlation_id_map.remove(&msg.correlation_id) {
            self.handle_fetch_failure(root, msg.peer, ctx);
        }
    }

    // --- Connection handlers ---

    #[send_handler]
    async fn handle_on_peer_connected(
        &mut self,
        msg: p2p_protocol::OnPeerConnected,
        _ctx: &Context<Self>,
    ) {
        let peer_id = msg.peer_id;
        let direction = &msg.direction;

        if msg.first_connection {
            self.connected_peers.insert(peer_id);
            let peer_count = self.connected_peers.len();
            metrics::notify_peer_connected(&Some(peer_id), direction, "success");

            let our_status = build_status(&self.store);
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

            // Send status request on first connection
            let correlation_id = self.next_correlation_id();
            let _ = self.swarm_tx.send(SwarmCommand::SendRequest {
                correlation_id,
                peer_id,
                request: Request::Status(our_status),
                protocol: StreamProtocol::new(STATUS_PROTOCOL_V1),
            });
        } else {
            info!(%peer_id, %direction, "Added peer connection");
        }
    }

    #[send_handler]
    async fn handle_on_peer_disconnected(
        &mut self,
        msg: p2p_protocol::OnPeerDisconnected,
        ctx: &Context<Self>,
    ) {
        let peer_id = msg.peer_id;
        let direction = &msg.direction;
        let reason = &msg.reason;

        if msg.last_connection {
            self.connected_peers.remove(&peer_id);
            let peer_count = self.connected_peers.len();
            metrics::notify_peer_disconnected(&Some(peer_id), direction, reason);

            info!(
                %peer_id,
                %direction,
                %reason,
                peer_count,
                "Peer disconnected"
            );

            if self.bootnode_addrs.contains_key(&peer_id) {
                send_after(
                    Duration::from_secs(PEER_REDIAL_INTERVAL_SECS),
                    ctx.clone(),
                    p2p_protocol::RetryPeerRedial { peer_id },
                );
                info!(
                    %peer_id,
                    "Scheduled bootnode redial in {}s",
                    PEER_REDIAL_INTERVAL_SECS
                );
            }
        } else {
            info!(
                %peer_id, %direction, %reason,
                "Peer connection closed but other connections remain"
            );
        }
    }

    #[send_handler]
    async fn handle_on_outgoing_connection_error(
        &mut self,
        msg: p2p_protocol::OnOutgoingConnectionError,
        ctx: &Context<Self>,
    ) {
        let peer_id = msg.peer_id;
        let error = &msg.error;
        let error_lower = error.to_lowercase();
        let result = if error_lower.contains("timeout")
            || error_lower.contains("timedout")
            || error_lower.contains("timed out")
        {
            "timeout"
        } else {
            "error"
        };
        metrics::notify_peer_connected(&peer_id, "outbound", result);
        warn!(?peer_id, %error, "Outgoing connection error");

        if let Some(pid) = peer_id
            && self.bootnode_addrs.contains_key(&pid)
            && !self.connected_peers.contains(&pid)
        {
            send_after(
                Duration::from_secs(PEER_REDIAL_INTERVAL_SECS),
                ctx.clone(),
                p2p_protocol::RetryPeerRedial { peer_id: pid },
            );
            info!(%pid, "Scheduled bootnode redial after connection error");
        }
    }

    // --- Publish handlers (from BlockChain via bridge) ---

    #[send_handler]
    async fn handle_publish_attestation(
        &mut self,
        msg: p2p_protocol::PublishAttestation,
        _ctx: &Context<Self>,
    ) {
        let attestation = msg.attestation;
        let slot = attestation.data.slot;
        let validator = attestation.validator_id;

        let ssz_bytes = attestation.as_ssz_bytes();
        let compressed = compress_message(&ssz_bytes);

        let _ = self
            .swarm_tx
            .send(SwarmCommand::GossipPublish {
                topic: self.attestation_topic.clone(),
                data: compressed,
            })
            .inspect(|_| {
                info!(
                    %slot,
                    validator,
                    target_slot = attestation.data.target.slot,
                    target_root = %ShortRoot(&attestation.data.target.root.0),
                    source_slot = attestation.data.source.slot,
                    source_root = %ShortRoot(&attestation.data.source.root.0),
                    "Published attestation to gossipsub"
                )
            })
            .inspect_err(|err| {
                warn!(
                    %slot, %validator, %err,
                    "Failed to publish attestation to gossipsub"
                )
            });
    }

    #[send_handler]
    async fn handle_publish_block(
        &mut self,
        msg: p2p_protocol::PublishBlock,
        _ctx: &Context<Self>,
    ) {
        let signed_block = msg.signed_block;
        let slot = signed_block.message.block.slot;
        let proposer = signed_block.message.block.proposer_index;
        let block_root = signed_block.message.block.tree_hash_root();
        let parent_root = signed_block.message.block.parent_root;
        let attestation_count = signed_block.message.block.body.attestations.len();

        let ssz_bytes = signed_block.as_ssz_bytes();
        let compressed = compress_message(&ssz_bytes);

        let _ = self
            .swarm_tx
            .send(SwarmCommand::GossipPublish {
                topic: self.block_topic.clone(),
                data: compressed,
            })
            .inspect(|_| {
                info!(
                    %slot,
                    proposer,
                    block_root = %ShortRoot(&block_root.0),
                    parent_root = %ShortRoot(&parent_root.0),
                    attestation_count,
                    "Published block to gossipsub"
                )
            })
            .inspect_err(|err| {
                warn!(
                    %slot, %proposer, %err,
                    "Failed to publish block to gossipsub"
                )
            });
    }

    #[send_handler]
    async fn handle_publish_aggregated_attestation(
        &mut self,
        msg: p2p_protocol::PublishAggregatedAttestation,
        _ctx: &Context<Self>,
    ) {
        let attestation = msg.attestation;
        let slot = attestation.data.slot;

        let ssz_bytes = attestation.as_ssz_bytes();
        let compressed = compress_message(&ssz_bytes);

        let _ = self
            .swarm_tx
            .send(SwarmCommand::GossipPublish {
                topic: self.aggregation_topic.clone(),
                data: compressed,
            })
            .inspect(|_| {
                info!(
                    %slot,
                    target_slot = attestation.data.target.slot,
                    target_root = %ShortRoot(&attestation.data.target.root.0),
                    source_slot = attestation.data.source.slot,
                    source_root = %ShortRoot(&attestation.data.source.root.0),
                    "Published aggregated attestation to gossipsub"
                )
            })
            .inspect_err(|err| {
                warn!(
                    %slot, %err,
                    "Failed to publish aggregated attestation to gossipsub"
                )
            });
    }

    // --- Fetch and retry handlers ---

    #[send_handler]
    async fn handle_fetch_block(&mut self, msg: p2p_protocol::FetchBlock, _ctx: &Context<Self>) {
        let root = msg.root;

        // Deduplicate — if already pending, ignore
        if self.pending_requests.contains_key(&root) {
            trace!(%root, "Block fetch already in progress, ignoring duplicate");
            return;
        }

        self.fetch_block_from_peer(root);
    }

    #[send_handler]
    async fn handle_retry_block_fetch(
        &mut self,
        msg: p2p_protocol::RetryBlockFetch,
        _ctx: &Context<Self>,
    ) {
        let root = msg.root;

        if !self.pending_requests.contains_key(&root) {
            trace!(%root, "Block fetch completed during backoff, skipping retry");
            return;
        }

        info!(%root, "Retrying block fetch after backoff");

        if !self.fetch_block_from_peer(root) {
            error!(%root, "Failed to retry block fetch, giving up");
            self.pending_requests.remove(&root);
        }
    }

    #[send_handler]
    async fn handle_retry_peer_redial(
        &mut self,
        msg: p2p_protocol::RetryPeerRedial,
        ctx: &Context<Self>,
    ) {
        let peer_id = msg.peer_id;

        if self.connected_peers.contains(&peer_id) {
            trace!(%peer_id, "Bootnode reconnected during redial delay, skipping");
            return;
        }

        if let Some(addr) = self.bootnode_addrs.get(&peer_id) {
            info!(%peer_id, "Redialing disconnected bootnode");
            let _ = self
                .swarm_tx
                .send(SwarmCommand::Dial(addr.clone()))
                .inspect_err(|e| {
                    warn!(%peer_id, %e, "Failed to send redial command, will retry");
                    send_after(
                        Duration::from_secs(PEER_REDIAL_INTERVAL_SECS),
                        ctx.clone(),
                        p2p_protocol::RetryPeerRedial { peer_id },
                    );
                });
        }
    }
}

// --- Public API ---

/// Handle to the P2P actor.
#[derive(Clone)]
pub struct P2P {
    handle: ActorRef<P2PServer>,
}

impl P2P {
    pub fn publish_attestation(&self, attestation: SignedAttestation) {
        let _ = self
            .handle
            .publish_attestation(attestation)
            .inspect_err(|err| error!(%err, "Failed to publish attestation to P2P actor"));
    }

    pub fn publish_block(&self, signed_block: SignedBlockWithAttestation) {
        let _ = self
            .handle
            .publish_block(signed_block)
            .inspect_err(|err| error!(%err, "Failed to publish block to P2P actor"));
    }

    pub fn publish_aggregated_attestation(&self, attestation: SignedAggregatedAttestation) {
        let _ = self
            .handle
            .publish_aggregated_attestation(attestation)
            .inspect_err(
                |err| error!(%err, "Failed to publish aggregated attestation to P2P actor"),
            );
    }

    pub fn fetch_block(&self, root: H256) {
        let _ = self
            .handle
            .fetch_block(root)
            .inspect_err(|err| error!(%err, "Failed to fetch block via P2P actor"));
    }
}

// --- Initialization ---

/// [libp2p Behaviour](libp2p::swarm::NetworkBehaviour) combining Gossipsub and Request-Response Behaviours
#[derive(NetworkBehaviour)]
pub(crate) struct Behaviour {
    gossipsub: libp2p::gossipsub::Behaviour,
    req_resp: request_response::Behaviour<Codec>,
}

#[allow(clippy::too_many_arguments)]
pub async fn start_p2p(
    node_key: Vec<u8>,
    bootnodes: Vec<Bootnode>,
    listening_socket: SocketAddr,
    blockchain: BlockChain,
    store: Store,
    validator_id: Option<u64>,
    attestation_committee_count: u64,
    is_aggregator: bool,
) -> Result<(P2P, tokio::task::JoinHandle<()>), libp2p::gossipsub::SubscriptionError> {
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
        .allow_self_origin(true)
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

    // Subscribe to block topic (all nodes)
    let block_topic_str = format!("/leanconsensus/{network}/{BLOCK_TOPIC_KIND}/ssz_snappy");
    let block_topic = libp2p_gossipsub::IdentTopic::new(block_topic_str);
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&block_topic)
        .unwrap();

    // Subscribe to aggregation topic (all validators)
    let aggregation_topic_str =
        format!("/leanconsensus/{network}/{AGGREGATION_TOPIC_KIND}/ssz_snappy");
    let aggregation_topic = libp2p_gossipsub::IdentTopic::new(aggregation_topic_str);
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&aggregation_topic)
        .unwrap();

    // Build attestation subnet topic (needed for publishing even without subscribing)
    // attestation_committee_count is validated to be >= 1 by clap at CLI parse time.
    let subnet_id = validator_id.map(|vid| vid % attestation_committee_count);
    let attestation_topic_kind = match subnet_id {
        Some(id) => format!("{ATTESTATION_SUBNET_TOPIC_PREFIX}_{id}"),
        // Non-validators use subnet 0 for publishing
        None => format!("{ATTESTATION_SUBNET_TOPIC_PREFIX}_0"),
    };
    let attestation_topic_str =
        format!("/leanconsensus/{network}/{attestation_topic_kind}/ssz_snappy");
    let attestation_topic = libp2p_gossipsub::IdentTopic::new(attestation_topic_str);

    // Only aggregators subscribe to attestation subnets; non-aggregators
    // publish via gossipsub's fanout mechanism without subscribing.
    if is_aggregator {
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&attestation_topic)?;
        info!(%attestation_topic_kind, "Subscribed to attestation subnet");
    }

    info!(socket=%listening_socket, "P2P node started");

    // Create channels between actor and swarm driver
    let (swarm_cmd_tx, swarm_cmd_rx) = mpsc::unbounded_channel();

    let server = P2PServer {
        swarm_tx: swarm_cmd_tx,
        blockchain,
        store,
        attestation_topic,
        block_topic,
        aggregation_topic,
        connected_peers: HashSet::new(),
        pending_requests: HashMap::new(),
        correlation_id_map: HashMap::new(),
        next_correlation_id: 0,
        bootnode_addrs,
    };

    let actor_ref = server.start();

    let driver = SwarmDriver::new(swarm, swarm_cmd_rx, actor_ref.clone());
    let driver_handle = tokio::spawn(driver.run());

    Ok((P2P { handle: actor_ref }, driver_handle))
}

// --- Types and utilities ---

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
