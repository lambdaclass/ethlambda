//! Execution-layer devp2p: transaction gossip between embedded ethrex instances.
//!
//! Consensus blocks already carry the execution payload, so peers replicate
//! *execution* through the Lean gossip network and need nothing here. What they
//! cannot replicate that way are transactions that have not been included yet: a
//! transaction submitted to one node sits in that node's mempool alone, so it
//! waits for that node's turn to propose. This module gives the execution layers
//! their own mesh so a transaction reaches every mempool and the next proposer —
//! whoever it is — can include it.
//!
//! It is a second, independent network stack: ethrex's devp2p (discv4 + RLPx over
//! TCP) alongside the consensus layer's libp2p (gossipsub over QUIC). They share
//! no keys, ports, or peer state, and each node's execution layer is identified
//! only within this mesh.
//!
//! Only the transaction-pool messages matter to us. ethrex's block-sync
//! request/response handlers are also served — that comes with `start_network`
//! and is harmless, since consensus is what actually drives block import.

use std::net::IpAddr;

use ethrex_common::H512;
use ethrex_p2p::{
    discovery::{DiscoveryConfig, INITIAL_LOOKUP_INTERVAL_MS, LOOKUP_INTERVAL_MS},
    network::{P2PContext, start_network},
    peer_table::PeerTableServer,
    rlpx::initiator::RLPxInitiator,
    tx_broadcaster::BROADCAST_INTERVAL_MS,
    types::{NetworkConfig, Node},
    utils::public_key_from_signing_key,
};
use secp256k1::SecretKey;
use tokio_util::task::TaskTracker;
use tracing::info;

use crate::{EngineError, EthrexEngine};

/// How many peers each execution layer tries to hold.
///
/// ethrex's own default is 100, which assumes a public network where candidates
/// are scarce. On a devnet of N nodes every node is a candidate, so a target
/// above N-1 means the peer table is never "full" and every node keeps dialling
/// every other one indefinitely. Nothing in ethrex sends
/// `DisconnectReason::AlreadyConnected` and `new_connected_peer` overwrites its
/// entry, so simultaneous dials in both directions leave duplicate connections
/// and duplicate transaction traffic. A small target avoids the whole problem.
pub const DEFAULT_TARGET_PEERS: usize = 8;

/// How the execution layer should join the transaction-gossip mesh.
///
/// Deliberately built from plain and standard-library types: ethrex's `SecretKey`
/// and `Node` stay behind this crate's boundary, as they do everywhere else.
#[derive(Debug, Clone)]
pub struct P2PConfig {
    /// secp256k1 key identifying this node's *execution layer*.
    ///
    /// Must not be the consensus node key. Reusing one secret across two
    /// unrelated protocols (libp2p's Noise handshake and discv4 packet
    /// signatures plus RLPx auth) is worth avoiding even though both happen to
    /// use the same curve. Derive it instead — see
    /// `bin/ethlambda/src/main.rs`.
    pub secret_key: [u8; 32],
    /// Address to bind the TCP listener and UDP socket to.
    pub bind_addr: IpAddr,
    /// Address peers are told to dial.
    ///
    /// Distinct from `bind_addr` because binding `0.0.0.0` is normal while
    /// *advertising* it is not: discv4 would propagate `0.0.0.0` to peers and
    /// every dial back would fail.
    pub advertised_addr: IpAddr,
    /// TCP (RLPx) and UDP (discv4) port. One value: ethrex emits a bare
    /// `enode://…@ip:port` when they match, and a `?discport=` suffix when they
    /// do not, so keeping them equal keeps the enode simple.
    pub port: u16,
    /// `enode://…` URLs to seed discovery with. Usually just one.
    pub bootnodes: Vec<String>,
    /// See [`DEFAULT_TARGET_PEERS`].
    pub target_peers: usize,
}

impl P2PConfig {
    /// Config for `port`, binding all interfaces and advertising loopback —
    /// the shape a single-host devnet wants.
    pub fn loopback(secret_key: [u8; 32], port: u16) -> Self {
        Self {
            secret_key,
            bind_addr: IpAddr::from([0, 0, 0, 0]),
            advertised_addr: IpAddr::from([127, 0, 0, 1]),
            port,
            bootnodes: Vec::new(),
            target_peers: DEFAULT_TARGET_PEERS,
        }
    }
}

impl EthrexEngine {
    /// Join the execution-layer transaction-gossip mesh. Returns this node's
    /// `enode://…` URL, which is what other nodes need as a bootnode.
    ///
    /// Callable once; a second call is [`EngineError::P2PAlreadyStarted`]. The
    /// spawned actors have no shutdown handle, so starting twice would leave two
    /// stacks fighting over the same port with no way to stop either.
    ///
    /// discv4 is enabled and discv5 is not. Discovery has to be on at all:
    /// `start_network` discards the bootnode list entirely when both are
    /// disabled, which would leave static peering as the only option and mean
    /// every node needs every other node's enode up front. With discv4 on, one
    /// bootnode is enough for the whole mesh to find itself. discv5 adds a
    /// second protocol surface and finds nothing discv4 cannot.
    pub async fn start_p2p(&self, config: P2PConfig) -> Result<String, EngineError> {
        if self.p2p_started.set(()).is_err() {
            return Err(EngineError::P2PAlreadyStarted);
        }

        let signer = SecretKey::from_byte_array(&config.secret_key)
            .map_err(|err| EngineError::P2PConfig(format!("invalid EL node key: {err}")))?;
        let public_key: H512 = public_key_from_signing_key(&signer);

        let bootnodes = config
            .bootnodes
            .iter()
            .map(|url| {
                Node::from_enode_url(url.trim())
                    .map_err(|err| EngineError::P2PConfig(format!("bootnode {url:?}: {err:?}")))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let local_node = Node::new(config.advertised_addr, config.port, config.port, public_key);
        let enode = local_node.enode_url();
        let network_config = NetworkConfig {
            bind_addr: config.bind_addr,
            tcp_port: config.port,
            udp_port: config.port,
        };

        let peer_table = PeerTableServer::spawn(
            local_node.node_id(),
            config.target_peers,
            self.store.clone(),
        );

        let context = P2PContext::new(
            local_node,
            network_config,
            TaskTracker::new(),
            signer,
            peer_table,
            self.store.clone(),
            self.blockchain.clone(),
            client_version(),
            // L2-only "based" sequencing context; that feature is not compiled.
            None,
            BROADCAST_INTERVAL_MS,
            LOOKUP_INTERVAL_MS,
        )
        .map_err(|err| EngineError::P2PStart(err.to_string()))?;

        // Constructing the context already spawned the transaction broadcaster,
        // so outbound gossip is live from here. The initiator makes outbound
        // connections; `start_network` accepts inbound ones and runs discovery.
        RLPxInitiator::spawn(context.clone());
        start_network(
            context,
            bootnodes,
            DiscoveryConfig {
                discv4_enabled: true,
                discv5_enabled: false,
                initial_lookup_interval: INITIAL_LOOKUP_INTERVAL_MS,
            },
        )
        .await
        .map_err(|err| EngineError::P2PStart(err.to_string()))?;

        // Without this every inbound `Transactions`, `NewPooledTransactionHashes`
        // and `PooledTransactions` message is dropped *silently* — ethrex gates
        // transaction ingest on `is_synced()`, which defaults false and is
        // otherwise only set by the Engine-API fork-choice handler we bypass.
        // Missing it looks exactly like a mesh that never formed.
        //
        // Correct for a consensus-driven execution layer: it is never behind in
        // the sense the flag means, because consensus hands it every block. No
        // syncer is reachable from a `P2PContext`, so this cannot start a snap
        // sync. Set here rather than at construction so a node without
        // execution-layer gossip does not claim to be synced.
        self.blockchain.set_synced();

        info!(
            %enode,
            target_peers = config.target_peers,
            bootnodes = config.bootnodes.len(),
            "EL devp2p enabled"
        );
        Ok(enode)
    }
}

/// Version string offered to peers in the RLPx `Hello`. Names ethlambda rather
/// than ethrex, since that is what is running.
fn client_version() -> String {
    format!("ethlambda/v{}", env!("CARGO_PKG_VERSION"))
}

/// Domain separator, so the derived key cannot collide with any other use of the
/// consensus node key.
const EL_KEY_DOMAIN: &[u8] = b"ethlambda-el-p2p";

/// Derive the execution layer's devp2p key from the consensus node key.
///
/// Deterministic, so a node keeps its execution-layer identity across restarts
/// and a devnet can predict every node's enode from keys it already has — but
/// *derived* rather than reused. libp2p's Noise handshake and devp2p's discv4
/// packet signatures plus RLPx auth are unrelated protocols, and sharing one
/// secret between them is worth avoiding even though both use secp256k1.
///
/// The result is a 32-byte scalar. It is not reduced into the curve order: a
/// keccak output landing at or above it (or at zero) is a ~2⁻¹²⁸ event, and
/// [`EthrexEngine::start_p2p`] rejects an invalid key loudly rather than
/// silently substituting another.
pub fn derive_el_node_key(consensus_node_key: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(EL_KEY_DOMAIN.len() + consensus_node_key.len());
    input.extend_from_slice(EL_KEY_DOMAIN);
    input.extend_from_slice(consensus_node_key);
    ethrex_common::utils::keccak(&input).0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_key_is_deterministic_and_differs_from_its_input() {
        let consensus_key = [0x11u8; 32];
        let derived = derive_el_node_key(&consensus_key);

        assert_eq!(
            derived,
            derive_el_node_key(&consensus_key),
            "a node must keep the same execution-layer identity across restarts"
        );
        assert_ne!(
            derived, consensus_key,
            "the execution-layer key must not be the consensus key itself"
        );
        assert!(
            SecretKey::from_byte_array(&derived).is_ok(),
            "the derived key must be a usable secp256k1 secret"
        );
    }

    #[test]
    fn different_nodes_derive_different_keys() {
        assert_ne!(
            derive_el_node_key(&[0x11u8; 32]),
            derive_el_node_key(&[0x22u8; 32])
        );
    }
}
