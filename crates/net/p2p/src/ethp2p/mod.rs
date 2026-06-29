//! Experimental ethp2p-rs erasure-coded broadcast adapter.
//!
//! This module is **feature-gated** behind `ethp2p` and **off by
//! default**. It lets ethlambda *also* broadcast gossip through
//! [ethp2p-rs](https://github.com/lambdaclass/ethp2p-rs)'s Reed-Solomon
//! broadcast engine, over a **parallel QUIC network** alongside libp2p
//! gossipsub (which is unaffected). It is ethlambda↔ethlambda only and
//! makes no spec-conformance or interop claim — see
//! `docs/ethlambda-integration-plan.md` in ethp2p-rs.
//!
//! This module wires the broadcast engine into ethlambda's P2P actor:
//! the publish handlers tee gossip here, a background task drives the
//! engine and forwards reconstructed messages back into the actor, and
//! peers are derived from the static bootnode set. It has been validated
//! by compilation, the isolated round-trip test below, and an end-to-end
//! run on a 3-node ethlambda devnet (blocks, aggregations, and attestations
//! all carried over the parallel QUIC mesh while the chain finalized
//! normally). Minimal transport hardening (Phase 6) gates any non-isolated
//! use.
//!
//! ## Model
//!
//! ethlambda uses **static bootnodes** (no dynamic discovery), so the peer
//! set is known at startup: [`Ethp2pBroadcast::start`] binds a QUIC
//! endpoint, dials the known peers, and subscribes the gossip channels.
//! Inbound peers register themselves via the QUIC transport's stream
//! preface, so only one side needs to dial.
//!
//! ## Limitations (isolated devnet only)
//!
//! - **No peer authentication.** The demo QUIC transport binds no identity
//!   to the connection, so a peer id can be spoofed. Acceptable only for an
//!   isolated, off-by-default experiment.
//! - **No live peer-health signal.** The transport never emits
//!   `PeerDisconnected`, so runtime peer loss is invisible here. The only
//!   ethlambda-side guard is a *startup* one: with fewer than
//!   [`MIN_ETHP2P_PEERS`] configured mesh peers the engine isn't started
//!   and the node relies solely on gossipsub. A true circuit-breaker that
//!   reacts to peers dropping needs transport-side disconnect events
//!   (deferred — see the integration plan's Phase 6).
//! - **Fire-and-forget sends.** Chunks dropped under load are not retried;
//!   gossipsub remains the authoritative path.

use std::fmt;
use std::io;
use std::net::SocketAddr;

use ethlambda_network_api::P2PToBlockChainRef;
use ethlambda_types::attestation::{SignedAggregatedAttestation, SignedAttestation};
use ethlambda_types::block::SignedBlock;
use ethp2p_broadcast::engine::{DeliveredMessage, Engine, StepResult, rs_relay_factory};
use ethp2p_broadcast::strategy::config::RsConfig;
use ethp2p_broadcast::strategy::rs::encode::encode as rs_encode;
use ethp2p_broadcast::strategy::rs::state::RsStrategy;
use ethp2p_transport::QuicNet;
use libssz::SszDecode;
use prost::Message as _;
use sha2::{Digest, Sha256};
use spawned_concurrency::tasks::ActorRef;
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

use crate::gossipsub::decompress_message;
use crate::{P2PServer, WrappedEthp2pDelivery};

mod metrics;

/// Minimum number of configured ethp2p mesh peers for the broadcast engine
/// to be worth running. Below this the node tees nothing and relies solely
/// on gossipsub — a *startup* guard, not a live circuit-breaker: the demo
/// QUIC transport emits no disconnect events, so runtime peer loss is not
/// observable on the ethlambda side (see the module-level Limitations).
pub(crate) const MIN_ETHP2P_PEERS: usize = 1;

/// ethp2p channel ids — mirror the gossipsub topic kinds.
pub(crate) const CHANNEL_BLOCK: &str = "block";
pub(crate) const CHANNEL_AGGREGATION: &str = "aggregation";
pub(crate) const CHANNEL_ATTESTATION: &str = "attestation";

/// The set of channels every ethlambda node subscribes to.
pub(crate) fn all_channels() -> Vec<String> {
    vec![
        CHANNEL_BLOCK.to_string(),
        CHANNEL_AGGREGATION.to_string(),
        CHANNEL_ATTESTATION.to_string(),
    ]
}

/// Capacity of the reconstructed-message delivery channel.
const DELIVERY_CAPACITY: usize = 256;

/// Derive a stable ethp2p peer id (`u64`) from a secp256k1 compressed
/// public key: the first 8 bytes of its SHA-256, big-endian.
///
/// Deterministic across restarts (same key → same id). ethp2p uses a
/// `u64` peer-id space, distinct from libp2p's multi-byte `PeerId`; this
/// is the bridge. Collision probability is negligible at devnet scale.
#[must_use]
pub fn derive_peer_id(compressed_pubkey: &[u8]) -> u64 {
    let digest = Sha256::digest(compressed_pubkey);
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(bytes)
}

/// Errors from the broadcast adapter.
#[derive(Debug)]
pub enum Ethp2pError {
    /// Reed-Solomon encoding of the payload failed.
    Encode(String),
    /// The broadcast engine rejected the operation.
    Engine(String),
}

impl fmt::Display for Ethp2pError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encode(e) => write!(f, "ethp2p encode: {e}"),
            Self::Engine(e) => write!(f, "ethp2p engine: {e}"),
        }
    }
}

impl std::error::Error for Ethp2pError {}

/// A handle to the ethp2p broadcast engine running over a parallel QUIC
/// network. Driven by the caller via [`Ethp2pBroadcast::run_one_step`].
pub struct Ethp2pBroadcast {
    engine: Engine<RsStrategy, QuicNet>,
    config: RsConfig,
    local_addr: SocketAddr,
}

impl fmt::Debug for Ethp2pBroadcast {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ethp2pBroadcast")
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

impl Ethp2pBroadcast {
    /// Bind a QUIC endpoint for `local_peer`, then for each mesh peer
    /// `(id, addr)`: QUIC-dial it if `addr` is `Some` (peers with `None`
    /// are expected to dial us — the QUIC connection is bidirectional, so
    /// only one side dials), and engine-connect *all* of them so each node
    /// announces its channel subscriptions via the BCAST handshake.
    /// Finally subscribe the given `channels`.
    ///
    /// Returns the handle plus the receiver of reconstructed
    /// [`DeliveredMessage`]s; the caller forwards those into the same
    /// pipeline gossipsub feeds (Phase 2).
    pub async fn start(
        local_peer: u64,
        bind_addr: SocketAddr,
        peers: &[(u64, Option<SocketAddr>)],
        channels: &[String],
        config: RsConfig,
    ) -> io::Result<(Self, mpsc::Receiver<DeliveredMessage>)> {
        let net = QuicNet::bind(local_peer, bind_addr)?;
        let local_addr = net.local_addr()?;

        // QUIC-level dial of peers we're responsible for dialing; peers
        // with no address dial us and self-register via the stream preface.
        for (peer, addr) in peers {
            if let Some(addr) = addr {
                net.connect(*peer, *addr).await?;
            }
        }

        let (delivered_tx, delivered_rx) = mpsc::channel(DELIVERY_CAPACITY);
        let mut engine = Engine::new(local_peer, net, delivered_tx);

        for channel in channels {
            engine
                .subscribe(channel.clone(), rs_relay_factory(config))
                .map_err(|e| io::Error::other(e.to_string()))?;
        }
        // Engine-level handshake to every mesh peer (announces our
        // subscriptions so peers will dispatch chunks to us, and vice
        // versa). Fire-and-forget: the transport delivers once the QUIC
        // connection is established in either direction.
        for (peer, _) in peers {
            engine
                .connect(*peer)
                .map_err(|e| io::Error::other(e.to_string()))?;
        }

        Ok((
            Self {
                engine,
                config,
                local_addr,
            },
            delivered_rx,
        ))
    }

    /// The QUIC socket address this endpoint is bound to (useful when
    /// binding to an ephemeral port).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Publish an opaque payload (e.g. an ssz+snappy gossip blob) on
    /// `channel` under `message_id`. Wraps the Reed-Solomon encode +
    /// origin-session setup the engine requires.
    pub fn publish_bytes(
        &mut self,
        channel: &str,
        message_id: &str,
        payload: &[u8],
    ) -> Result<(), Ethp2pError> {
        let (preamble, _shards) =
            rs_encode(payload, &self.config).map_err(|e| Ethp2pError::Encode(format!("{e:?}")))?;
        let mut preamble_bytes = Vec::with_capacity(preamble.encoded_len());
        preamble
            .encode(&mut preamble_bytes)
            .map_err(|e| Ethp2pError::Encode(e.to_string()))?;
        let strategy = RsStrategy::new_origin(payload, self.config)
            .map_err(|e| Ethp2pError::Encode(format!("{e:?}")))?;
        self.engine
            .publish(
                &channel.to_string(),
                message_id.to_string(),
                strategy,
                preamble_bytes,
            )
            .map_err(|e| Ethp2pError::Engine(e.to_string()))
    }

    /// Process one inbound network event (drive the engine forward).
    /// Callers loop this; reconstructed messages arrive on the receiver
    /// returned by [`Ethp2pBroadcast::start`].
    ///
    /// # Errors
    /// Returns the engine's error if event processing fails.
    pub async fn run_one_step(&mut self) -> Result<StepResult, Ethp2pError> {
        self.engine
            .run_one_step()
            .await
            .map_err(|e| Ethp2pError::Engine(e.to_string()))
    }
}

/// Parameters to construct the broadcast engine, computed in `build_swarm`
/// and carried to `P2P::spawn` where the engine task is spawned.
pub(crate) struct Ethp2pParams {
    pub(crate) local_peer: u64,
    pub(crate) bind_addr: SocketAddr,
    pub(crate) peers: Vec<(u64, Option<SocketAddr>)>,
    pub(crate) channels: Vec<String>,
    pub(crate) config: RsConfig,
}

impl Ethp2pParams {
    /// Construct with the default channel set and Reed-Solomon config.
    pub(crate) fn new(
        local_peer: u64,
        bind_addr: SocketAddr,
        peers: Vec<(u64, Option<SocketAddr>)>,
    ) -> Self {
        Self {
            local_peer,
            bind_addr,
            peers,
            channels: all_channels(),
            config: RsConfig::default(),
        }
    }
}

/// A request to publish a gossip payload over ethp2p, sent from the
/// P2PServer's publish handlers to the engine task.
pub(crate) struct PublishCmd {
    pub(crate) channel: String,
    pub(crate) message_id: String,
    pub(crate) payload: Vec<u8>,
}

/// Stable per-message id for an ethp2p session: hex of the SSZ bytes'
/// SHA-256. Unique per message and independent of the transport.
pub(crate) fn message_id(ssz_bytes: &[u8]) -> String {
    let digest = Sha256::digest(ssz_bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Long-lived task that owns the broadcast engine: drives it forward,
/// services publish requests, and forwards reconstructed messages into
/// the P2P actor (so they flow through the same consensus pipeline as
/// gossipsub).
pub(crate) async fn run_engine_task(
    params: Ethp2pParams,
    mut publish_rx: mpsc::UnboundedReceiver<PublishCmd>,
    actor: ActorRef<P2PServer>,
) {
    let (mut broadcast, mut delivered_rx) = match Ethp2pBroadcast::start(
        params.local_peer,
        params.bind_addr,
        &params.peers,
        &params.channels,
        params.config,
    )
    .await
    {
        Ok(pair) => pair,
        Err(e) => {
            error!(%e, "ethp2p: failed to start broadcast engine; ethp2p disabled");
            return;
        }
    };
    metrics::set_mesh_peers(params.peers.len());
    info!(
        local_peer = params.local_peer,
        peers = params.peers.len(),
        bind = %params.bind_addr,
        "ethp2p broadcast engine started"
    );

    loop {
        tokio::select! {
            r = broadcast.run_one_step() => {
                if let Err(e) = r {
                    warn!(%e, "ethp2p: run_one_step error");
                }
            }
            cmd = publish_rx.recv() => {
                match cmd {
                    Some(cmd) => {
                        match broadcast.publish_bytes(&cmd.channel, &cmd.message_id, &cmd.payload) {
                            Ok(()) => {
                                metrics::inc_published(&cmd.channel);
                                debug!(
                                    channel = %cmd.channel,
                                    bytes = cmd.payload.len(),
                                    "ethp2p: published message"
                                );
                            }
                            Err(e) => warn!(%e, channel = %cmd.channel, "ethp2p: publish failed"),
                        }
                    }
                    // Publish sender dropped (the P2P actor stopped). The
                    // engine has no driver left; shut the task down rather
                    // than spin.
                    None => {
                        info!("ethp2p: publish channel closed; stopping engine task");
                        break;
                    }
                }
            }
            delivered = delivered_rx.recv() => {
                match delivered {
                    Some(delivered) => {
                        if let Err(e) = actor
                            .recipient::<WrappedEthp2pDelivery>()
                            .send(WrappedEthp2pDelivery(delivered))
                        {
                            warn!(%e, "ethp2p: failed to forward delivery to P2P actor");
                        }
                    }
                    None => {
                        warn!("ethp2p: delivery channel closed; stopping engine task");
                        break;
                    }
                }
            }
        }
    }
}

/// Decode an ethp2p-reconstructed payload (snappy-compressed SSZ, same
/// wire form as gossipsub) and hand it to the same blockchain handlers
/// the gossipsub path uses. Dual delivery is safe: block import and
/// attestation handling are idempotent.
pub(crate) fn dispatch_delivered(blockchain: &P2PToBlockChainRef, channel: &str, payload: &[u8]) {
    let uncompressed = match decompress_message(payload) {
        Ok(bytes) => bytes,
        Err(e) => {
            error!(%e, channel, "ethp2p: failed to decompress delivered payload");
            return;
        }
    };
    metrics::inc_delivered(channel);
    // Success-path visibility: a payload was reconstructed from the
    // erasure-coded mesh and is about to enter the consensus pipeline
    // (the same one gossipsub feeds). Proof that ethp2p carried gossip.
    info!(
        channel,
        wire_bytes = payload.len(),
        ssz_bytes = uncompressed.len(),
        "ethp2p: delivered message"
    );
    match channel {
        CHANNEL_BLOCK => match SignedBlock::from_ssz_bytes(&uncompressed) {
            Ok(block) => {
                let _ = blockchain
                    .new_block(block)
                    .inspect_err(|e| error!(%e, "ethp2p: failed to forward block to blockchain"));
            }
            Err(e) => error!(?e, "ethp2p: failed to decode delivered block"),
        },
        CHANNEL_AGGREGATION => match SignedAggregatedAttestation::from_ssz_bytes(&uncompressed) {
            Ok(agg) => {
                let _ = blockchain.new_aggregated_attestation(agg).inspect_err(
                    |e| error!(%e, "ethp2p: failed to forward aggregation to blockchain"),
                );
            }
            Err(e) => error!(?e, "ethp2p: failed to decode delivered aggregation"),
        },
        CHANNEL_ATTESTATION => match SignedAttestation::from_ssz_bytes(&uncompressed) {
            Ok(att) => {
                let _ = blockchain.new_attestation(att).inspect_err(
                    |e| error!(%e, "ethp2p: failed to forward attestation to blockchain"),
                );
            }
            Err(e) => error!(?e, "ethp2p: failed to decode delivered attestation"),
        },
        other => trace!(channel = other, "ethp2p: delivered on unknown channel"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;

    fn loopback() -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
    }

    fn pseudorandom(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            out.push((state & 0xff) as u8);
        }
        out
    }

    #[test]
    fn peer_id_derivation_is_stable_and_distinct() {
        let key_a = [1_u8; 33];
        let key_b = [2_u8; 33];
        assert_eq!(derive_peer_id(&key_a), derive_peer_id(&key_a));
        assert_ne!(derive_peer_id(&key_a), derive_peer_id(&key_b));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn round_trip_block_sized_payload_over_quic() {
        let config = RsConfig::default();
        let channels = vec!["block".to_string()];
        let payload = pseudorandom(64 * 1024, 0xDEAD_BEEF);

        // Relay binds and announces to origin (origin will dial it).
        let (mut relay, mut relay_rx) =
            Ethp2pBroadcast::start(2, loopback(), &[(1, None)], &channels, config)
                .await
                .expect("relay start");
        let relay_addr = relay.local_addr();
        let (mut origin, mut _origin_rx) =
            Ethp2pBroadcast::start(1, loopback(), &[(2, Some(relay_addr))], &channels, config)
                .await
                .expect("origin start");

        let driver = async {
            let mut published = false;
            let mut steps = 0_u32;
            loop {
                tokio::select! {
                    r = origin.run_one_step() => { r.expect("origin step"); }
                    r = relay.run_one_step() => { r.expect("relay step"); }
                    Some(msg) = relay_rx.recv() => return msg,
                }
                steps += 1;
                if !published && steps >= 2 {
                    origin
                        .publish_bytes("block", "msg-1", &payload)
                        .expect("publish");
                    published = true;
                }
            }
        };

        match tokio::time::timeout(Duration::from_secs(20), driver).await {
            Ok(msg) => {
                assert_eq!(msg.channel_id, "block");
                assert_eq!(msg.message_id, "msg-1");
                assert_eq!(msg.payload, payload, "payload must round-trip over QUIC");
            }
            Err(_) => panic!("round trip timed out after 20s"),
        }
    }
}
