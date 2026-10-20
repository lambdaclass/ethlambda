//! ethrex, embedded in the beacon node's process.
//!
//! [`start`] brings up an ethrex node (store, chain, devp2p, sync) and returns
//! its RPC context, which `ethlambda-engine`'s in-process transport drives
//! through ethrex's own Engine API handlers. Nothing here speaks the Engine API
//! itself: this crate owns the node's lifetime, its flags, and the optional
//! execution JSON-RPC server.
//!
//! # Keeping in step with ethrex
//!
//! [`start`] is ethrex's `init_l1` with the RPC servers taken out: `init_l1`
//! builds its RPC context inside `bind_api` and never returns it, so the steps
//! are repeated here and the context is assembled from the same parts. When the
//! ethrex pin moves, diff `init_l1` and `init_rpc_api` (`cmd/ethrex/
//! initializers.rs`) and the binary's `server_shutdown` (`cmd/ethrex/
//! ethrex.rs`) against [`start`] and [`EmbeddedEthrex::shutdown`].

mod config;
mod http;

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use ethrex::cli::compute_effective_datadir;
use ethrex::initializers::{
    get_local_node_record, get_local_p2p_node, get_signer, init_blockchain, init_metrics,
    init_network, init_store_skip_validation_with_config, init_store_with_config,
    migrate_datadir_if_needed, regenerate_head_state,
};
use ethrex::utils::{
    NodeConfigFile, display_chain_initialization, get_client_version, get_client_version_string,
    init_datadir, is_memory_datadir, store_node_config_file,
};
use ethrex_blockchain::{BlockchainOptions, BlockchainType};
use ethrex_config::networks::Network;
use ethrex_p2p::network::P2PContext;
use ethrex_p2p::peer_handler::PeerHandler;
use ethrex_p2p::peer_table::{PeerTable, PeerTableServer};
use ethrex_p2p::rlpx::initiator::RLPxInitiator;
use ethrex_p2p::sync::{BackfillConfig, SyncMode};
use ethrex_p2p::sync_manager::SyncManager;
use ethrex_p2p::types::{LocalNode, SharedLocalNode};
use ethrex_rpc::rpc::FILTER_DURATION;
use ethrex_rpc::{
    GasTipEstimator, NodeData, RpcApiContext, clean_outdated_filters, start_block_executor,
};
use ethrex_storage::{Store, StoreConfig};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{error, info, warn};

pub use config::{ConfigError, EthrexArgs, EthrexConfig};

/// How long shutdown waits for ethrex's tasks to wind down before flushing the
/// store regardless. The flush is what must not be skipped; a task still
/// running past this only loses work the next start redoes.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Why the embedded node could not start.
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error("loading the execution genesis: {0}")]
    Genesis(String),
    #[error("opening the execution database at {datadir}: {source}")]
    Store {
        datadir: PathBuf,
        source: ethrex_storage::error::StoreError,
    },
    #[error("restoring the execution head state: {0}")]
    HeadState(String),
    #[error("setting up devp2p: {0}")]
    P2p(String),
    #[error("binding the execution JSON-RPC server on {addr}: {source}")]
    Http {
        addr: SocketAddr,
        source: std::io::Error,
    },
}

/// A running embedded ethrex.
pub struct EmbeddedEthrex {
    context: RpcApiContext,
    cancel_token: CancellationToken,
    tracker: TaskTracker,
    store: Store,
    peer_table: PeerTable,
    shared_local_node: SharedLocalNode,
    datadir: PathBuf,
    http_addr: Option<SocketAddr>,
}

/// Starts the embedded node and returns once it is ready to answer Engine API
/// calls.
///
/// Devp2p and sync start in the background; the node answers `SYNCING` until
/// it has the state a payload needs, as any execution client does.
pub async fn start(config: EthrexConfig) -> Result<EmbeddedEthrex, StartError> {
    let EthrexConfig {
        options: opts,
        http,
    } = config;
    let network = opts.network.clone().unwrap_or_else(Network::mainnet);
    let datadir = compute_effective_datadir(&opts.datadir, &network, false);

    migrate_datadir_if_needed(&opts.datadir, &datadir, &network, opts.no_migrate);
    if !is_memory_datadir(&datadir) {
        init_datadir(&datadir);
    }

    let genesis = network
        .get_genesis()
        .map_err(|err| StartError::Genesis(err.to_string()))?;
    display_chain_initialization(&genesis);
    ethrex_crypto::kzg::warm_up_trusted_setup();

    let store_config = StoreConfig {
        code_cache_size: opts.code_cache_size,
        ..opts
            .rocksdb_block_cache_size
            .map(StoreConfig::with_rocksdb_block_cache_size)
            .unwrap_or_default()
    };
    let store = if opts.skip_genesis_validation {
        init_store_skip_validation_with_config(&datadir, genesis, store_config).await
    } else {
        init_store_with_config(&datadir, genesis, store_config).await
    }
    .map_err(|source| StartError::Store {
        datadir: datadir.clone(),
        source,
    })?;

    if opts.syncmode == SyncMode::Full {
        store
            .generate_flatkeyvalue()
            .map_err(|source| StartError::Store {
                datadir: datadir.clone(),
                source,
            })?;
    }

    let blockchain = init_blockchain(
        store.clone(),
        BlockchainOptions {
            max_mempool_size: opts.mempool_max_size,
            perf_logs_enabled: true,
            r#type: BlockchainType::L1,
            max_blobs_per_block: opts.max_blobs_per_block,
            precompute_witnesses: opts.precompute_witnesses,
            private_mempool: opts.mempool_private,
            precompile_cache_enabled: !opts.no_precompile_cache,
            min_tip_wei: opts.mempool_min_tip,
            price_bump_percent: opts.mempool_price_bump,
            blob_price_bump_percent: opts.mempool_blob_price_bump,
            max_queued_txs_per_account: opts.mempool_max_queued_txs_per_account,
            bal_parallel_exec_enabled: !opts.no_bal_parallel_exec,
            bal_prefetch_enabled: !opts.no_bal_prefetch,
            bal_parallel_trie_enabled: !opts.no_bal_parallel_trie,
            blob_sampling_enabled: opts.blob_sampling || opts.blob_eager_provider,
            blob_eager_provider: opts.blob_eager_provider,
            max_reorg_depth: opts.max_reorg_depth,
            gap_admit_occupancy_threshold: opts.mempool_gap_admit_occupancy_threshold,
            mempool_prewarm_enabled: true,
        },
    );

    regenerate_head_state(&store, &blockchain)
        .await
        .map_err(|err| StartError::HeadState(err.to_string()))?;

    let signer = get_signer(&datadir);
    let (local_p2p_node, network_config) = get_local_p2p_node(&opts, &signer);
    let local_node_record = get_local_node_record(&datadir, &local_p2p_node, &signer);
    let shared_local_node: SharedLocalNode = Arc::new(RwLock::new(LocalNode {
        node: local_p2p_node.clone(),
        record: local_node_record,
    }));

    let peer_table =
        PeerTableServer::spawn(local_p2p_node.node_id(), opts.target_peers, store.clone());
    let tracker = TaskTracker::new();
    let cancel_token = CancellationToken::new();

    let p2p_context = P2PContext::new(
        local_p2p_node.clone(),
        network_config,
        tracker.clone(),
        signer,
        peer_table.clone(),
        store.clone(),
        blockchain.clone(),
        get_client_version_string(),
        None,
        opts.tx_broadcasting_time_interval,
        opts.lookup_interval,
    )
    .map_err(|err| StartError::P2p(err.to_string()))?;
    let initiator = RLPxInitiator::spawn(p2p_context.clone());
    let peer_handler = PeerHandler::new(peer_table.clone(), initiator);

    // From here to the context is `init_rpc_api` and `bind_api`, minus the
    // listeners: the sync manager the engine handlers trigger, and the block
    // executor thread `newPayload` hands blocks to.
    let backfill_config = BackfillConfig {
        mode: opts.history_chain.clone(),
        tx_index_horizon: opts.history_transactions,
    };
    let syncer = SyncManager::new(
        peer_handler.clone(),
        &opts.syncmode,
        cancel_token.clone(),
        blockchain.clone(),
        store.clone(),
        datadir.clone(),
        backfill_config,
        tracker.clone(),
    )
    .await;
    // Detached, as the node leaves it: the thread runs until every sender is
    // dropped, which is when the last context clone goes.
    let (block_worker_channel, _executor) = start_block_executor(blockchain.clone());
    let active_filters = Arc::new(Mutex::new(HashMap::new()));
    let context = RpcApiContext {
        storage: store.clone(),
        blockchain: blockchain.clone(),
        active_filters: active_filters.clone(),
        syncer: Some(Arc::new(syncer)),
        peer_handler: Some(peer_handler.clone()),
        node_data: NodeData {
            // Authenticates the Engine API port, which an embedded node does
            // not open.
            jwt_secret: bytes::Bytes::new(),
            shared_local_node: shared_local_node.clone(),
            client_version: get_client_version(),
            extra_data: opts.extra_data.clone().into(),
        },
        gas_tip_estimator: Arc::new(tokio::sync::Mutex::new(GasTipEstimator::new())),
        log_filter_handler: None,
        gas_ceil: opts.gas_limit,
        block_worker_channel,
        ws: None,
        allowed_namespaces: Arc::new(opts.http_api.iter().copied().collect::<HashSet<_>>()),
    };
    spawn_filter_cleanup(active_filters, &tracker, cancel_token.clone());

    if opts.metrics_enabled {
        init_metrics(&opts, &network, tracker.clone());
    }

    if opts.p2p_disabled {
        info!("Embedded ethrex: devp2p is disabled");
    } else {
        init_network(
            &opts,
            &network,
            &datadir,
            peer_handler,
            tracker.clone(),
            blockchain,
            p2p_context,
            shared_local_node.clone(),
        )
        .await;
    }

    let http_addr = match http {
        Some(addr) => Some(
            http::spawn(addr, context.clone(), &tracker, cancel_token.clone())
                .await
                .map_err(|source| StartError::Http { addr, source })?,
        ),
        None => None,
    };

    info!(%network, datadir = %datadir.display(), "Embedded ethrex started");
    Ok(EmbeddedEthrex {
        context,
        cancel_token,
        tracker,
        store,
        peer_table,
        shared_local_node,
        datadir,
        http_addr,
    })
}

/// Drops `eth_newFilter` filters no client has polled lately, as `bind_api`
/// does for the node's own server.
fn spawn_filter_cleanup(
    filters: ethrex_rpc::ActiveFilters,
    tracker: &TaskTracker,
    cancel: CancellationToken,
) {
    tracker.spawn(async move {
        let mut interval = tokio::time::interval(FILTER_DURATION);
        loop {
            tokio::select! {
                _ = interval.tick() => clean_outdated_filters(filters.clone(), FILTER_DURATION),
                _ = cancel.cancelled() => break,
            }
        }
    });
}

impl EmbeddedEthrex {
    /// The node's RPC context, for `EngineClient::in_process`.
    pub fn rpc_context(&self) -> RpcApiContext {
        self.context.clone()
    }

    /// Where the execution JSON-RPC server listens, if it runs: the bound
    /// address, so a requested port `0` reads as the one the OS picked.
    pub fn http_addr(&self) -> Option<SocketAddr> {
        self.http_addr
    }

    /// Resolves once something cancels the node, which an ethrex subsystem
    /// does when it fails in a way the node cannot run past. The beacon node
    /// shuts down too: without its execution client it cannot validate a
    /// payload.
    pub fn cancelled(&self) -> tokio_util::sync::WaitForCancellationFutureOwned {
        self.cancel_token.clone().cancelled_owned()
    }

    /// Stops the node and flushes its database.
    ///
    /// Call it only once nothing else drives the node, so no Engine API call
    /// is in flight while the store flushes. The order is the `ethrex`
    /// binary's: stop the tasks that feed the store, flush it, then record the
    /// node's identity and known peers for the next start.
    pub async fn shutdown(self) {
        info!("Stopping the embedded ethrex...");
        self.cancel_token.cancel();
        self.tracker.close();
        if tokio::time::timeout(SHUTDOWN_GRACE, self.tracker.wait())
            .await
            .is_err()
        {
            warn!(
                grace = ?SHUTDOWN_GRACE,
                "Embedded ethrex tasks still running; flushing the database anyway"
            );
        }

        if let Err(err) = self.store.shutdown().await {
            error!(%err, "Failed to flush the embedded ethrex database");
        }

        if !is_memory_datadir(&self.datadir) {
            let path = self.datadir.join("node_config.json");
            // Cloned out so the guard is dropped before the await below.
            let record = self
                .shared_local_node
                .read()
                .expect("shared_local_node poisoned")
                .record
                .clone();
            let node_config = NodeConfigFile::new(self.peer_table, record).await;
            store_node_config_file(node_config, path);
        }
        info!("Embedded ethrex stopped");
    }
}
