mod beacon;
mod benchmark;
mod checkpoint_sync;
mod cli;
mod command;
mod fd_limit;
mod version;

// Jemalloc causes programs to deadlock during process startup under Shadow.
// See https://github.com/shadow/shadow/issues/3763. Build the Shadow binary
// with `--no-default-features --features shadow-integration` to drop the
// (default) `jemalloc` feature and thus the `tikv-jemallocator` dependency.
#[cfg(all(feature = "jemalloc", feature = "shadow-integration"))]
compile_error!(
    "the `jemalloc` feature is incompatible with `shadow-integration`; \
     build the Shadow binary with `--no-default-features --features shadow-integration`"
);

#[cfg(all(not(target_env = "msvc"), feature = "jemalloc"))]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(all(not(target_env = "msvc"), feature = "jemalloc"))]
#[allow(non_upper_case_globals)]
#[unsafe(export_name = "malloc_conf")]
static malloc_conf: &[u8] = b"prof:true,prof_active:true,lg_prof_sample:19\0";

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::SystemTime,
};
use tokio_util::sync::CancellationToken;

use cli::{Network, Options};
use command::Command;

use ethlambda_blockchain::block_builder::ProposerConfig;
use ethlambda_blockchain::key_manager::ValidatorKeyPair;
use ethlambda_crypto::signature::ValidatorSecretKey;
use ethlambda_network_api::{InitBlockChain, InitP2P, ToBlockChainToP2PRef, ToP2PToBlockChainRef};
use ethlambda_p2p::{
    LeanWireConfig, P2P, PeerId, SwarmConfig, WireConfig, attestation_subscription_subnets,
    build_swarm, discovery::DiscoverySpawnConfig, parse_enrs,
};
use ethlambda_state_transition::beacon::fork_choice;
use ethlambda_types::primitives::{H256, HashTreeRoot as _};
use ethlambda_types::{
    aggregator::AggregatorController,
    beacon::config::Config,
    beacon::containers::SignedBeaconBlock,
    genesis::{GenesisConfig, verify_state_genesis},
    state::{State, ValidatorPubkeyBytes},
};
use eyre::WrapErr;
use serde::Deserialize;
use tracing::{error, info, warn};
use tracing_subscriber::{EnvFilter, Layer, Registry, layer::SubscriberExt};

use ethlambda_blockchain::{BlockChain, BlockChainConfig, EventBus, SyncStatusController};
use ethlambda_rpc::RpcConfig;
use ethlambda_storage::{
    Chain, MAX_RESUMABLE_DB_STATE_AGE, StorageBackend, Store, backend::RocksDBBackend,
};

const ASCII_ART: &str = r#"
      _   _     _                 _         _
  ___| |_| |__ | | __ _ _ __ ___ | |__   __| | __ _
 / _ \ __| '_ \| |/ _` | '_ ` _ \| '_ \ / _` |/ _` |
|  __/ |_| | | | | (_| | | | | | | |_) | (_| | (_| |
 \___|\__|_| |_|_|\__,_|_| |_| |_|_.__/ \__,_|\__,_|
"#;

fn main() -> eyre::Result<()> {
    match command::parse() {
        // Both node sub-commands are one startup path with a different
        // `Network`. The sub-command is only how the choice is spelled on the
        // command line.
        Command::Node(options) => {
            init_node_logging()?;
            run_node(options.into())
        }
        Command::Beacon(options) => {
            init_node_logging()?;
            run_node(options.into())
        }
        // The benchmark is synchronous, CPU-bound work, so it runs on this
        // thread and the tokio runtime is never started — rather than parking
        // a worker thread for the whole run.
        Command::Benchmark(options) => {
            init_benchmark_logging()?;
            benchmark::run(options)
        }
    }
}

/// Node logging: INFO and above, on stdout.
fn init_node_logging() -> eyre::Result<()> {
    let filter = EnvFilter::builder()
        .with_default_directive(tracing::Level::INFO.into())
        .from_env_lossy();
    let subscriber = Registry::default().with(tracing_subscriber::fmt::layer().with_filter(filter));
    tracing::subscriber::set_global_default(subscriber)
        .wrap_err("failed to set global tracing subscriber")
}

/// Benchmark logging: WARN and above, on stderr, so that the report owns stdout
/// and stays pipe-clean for `--format json | jq`.
fn init_benchmark_logging() -> eyre::Result<()> {
    let filter = EnvFilter::builder()
        .with_default_directive(tracing::Level::WARN.into())
        .from_env_lossy();
    let subscriber = Registry::default().with(
        tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr)
            .with_filter(filter),
    );
    tracing::subscriber::set_global_default(subscriber)
        .wrap_err("failed to set global tracing subscriber")
}

/// A node that has started, whichever chain it follows.
///
/// What [`wait_for_shutdown`] needs to stop, and all [`run_node`] has left to
/// assemble once the chain-specific half is done.
struct RunningNode {
    p2p: P2P,
    /// `None` on mainnet: that follower decodes gossip and imports nothing, so
    /// there is no chain actor to drive, stop or join.
    blockchain: Option<BlockChain>,
    /// The HTTP server task. Returns once `shutdown` is cancelled.
    http: tokio::task::JoinHandle<()>,
    /// Cancelled by [`wait_for_shutdown`] to stop `http`.
    shutdown: CancellationToken,
}

/// What one chain claims to serve, in the entries its ENR publishes and its
/// discv5 admission filter judges peers by.
///
/// Split out of [`DiscoverySpawnConfig`] because the other eight fields there
/// are the node key, the ports, the bootnodes and the peer target: operator
/// input, identical on either chain. Writing the whole config in each arm meant
/// typing those eight out twice, where the compiler could not tell if the two
/// copies drifted.
struct DiscoveryWireEntries {
    subscription_subnets: HashSet<u64>,
    attestation_committee_count: u64,
    fork_id: ethlambda_types::enr::EnrForkId,
    custody_group_count: Option<u64>,
}

/// What one chain's own setup produces, and everything [`run_node`] needs from
/// it to put a node on the wire.
///
/// A data bag, not an abstraction: the `match` that fills it stays inline in
/// `run_node`, because moving it into a method of its own would relocate the
/// branch rather than remove it. The fields are exactly the values the two
/// chains cannot share, in the order the code below consumes them.
struct ChainSetup {
    /// The wire-specific half of the swarm configuration: topics, protocol set,
    /// `seen_ttl`, identify version, connection limits.
    wire: WireConfig,
    /// The ENR entries that describe the wire above: the only part of the discv5
    /// configuration the two chains disagree about. Everything else in
    /// [`DiscoverySpawnConfig`] is operator-supplied and identical either way,
    /// so it is filled in once, below the match.
    discovery: DiscoveryWireEntries,
    /// Backs the req/resp handlers on both chains. Lean's is the live chain
    /// `BlockChain` drives; mainnet's is the checkpoint anchor
    /// `fetch_initial_beacon_state` resumed from disk or checkpoint-synced.
    /// Nothing on the mainnet path imports past that anchor, so its state
    /// never advances once the node is running.
    store: Store,
    /// PeerId to node name, for logs. Empty on mainnet, which has no roster.
    node_names: HashMap<PeerId, String>,
    /// The validator keys and actor configuration, or `None` on mainnet, which
    /// imports nothing and so has no chain actor.
    chain: Option<(HashMap<u64, ValidatorKeyPair>, BlockChainConfig)>,
}

/// Boot the node, on whichever chain [`Options::network`] names.
///
/// One startup path, in the order it has to happen: validate the port, register
/// the metrics, say what is running, raise the file-descriptor limit, resolve
/// the node key, then the one `match` where the two chains differ, then the
/// swarm, the discv5 server and the HTTP server, which are the same either way.
/// Mainnet stops there. Lean carries on into the chain actor.
///
/// `Network::Lean` runs the full consensus node: a `BlockChain` actor with
/// validator duties, a RocksDB store, checkpoint sync and the `/lean/v0` API.
/// `Network::Mainnet` is the wire and nothing above it: it derives mainnet's
/// fork digest, joins discv5, subscribes to the global gossip topics and logs
/// what it decodes. It keeps no chain, so it has no fork choice, only the
/// checkpoint anchor `fetch_initial_beacon_state` resolves at startup; the
/// `/lean/v0` API is served there too, off that anchored store, so that one
/// HTTP call site serves both. Those endpoints answer for a chain that imports
/// nothing past its anchor, and fixing that is its own change.
//
// Shadow single-steps execution in a discrete-event simulation, so the default
// multi-threaded runtime's worker threads add only scheduling noise, never
// parallelism. Use a single-threaded runtime under Shadow. This is an
// optimization, not a correctness requirement.
#[cfg_attr(not(feature = "shadow-integration"), tokio::main)]
#[cfg_attr(feature = "shadow-integration", tokio::main(flavor = "current_thread"))]
async fn run_node(options: Options) -> eyre::Result<()> {
    let Options { common, network } = options;

    // Before any side effect, so a port collision aborts ahead of the metrics
    // registry, the fd limit and the data directory.
    common.validate_ports()?;

    #[cfg(feature = "shadow-integration")]
    if let Network::Lean(lean) = &network {
        init_shadow_cost(&lean.shadow);
    }

    // Initialize metrics
    ethlambda_blockchain::metrics::init();
    ethlambda_blockchain::metrics::set_node_info("ethlambda", version::CLIENT_VERSION);
    ethlambda_blockchain::metrics::set_node_start_time();

    let rpc_config = RpcConfig {
        http_address: common.http_address,
        api_port: common.api_port,
        metrics_port: common.metrics_port,
        version: version::CLIENT_VERSION,
    };

    println!("{ASCII_ART}");

    info!(version = version::CLIENT_VERSION, "Starting ethlambda");

    // Raise the soft open-file-descriptor limit to the hard limit. RocksDB
    // keeps an unbounded table cache (`set_max_open_files(-1)`), so on
    // containerized hosts with the default ulimit of 1024 the store
    // eventually panics with `EMFILE`. Fail fast at startup rather than
    // stall days later when the cache outgrows the limit.
    fd_limit::raise_fd_limit().wrap_err("failed to raise RLIMIT_NOFILE")?;

    // Hive lean spec-asset suites boot the client with
    // HIVE_LEAN_TEST_DRIVER=1 so it skips the consensus/p2p stack and
    // exposes only the `/lean/v0/test_driver/...` endpoints driven by the
    // simulator. Detected here before any config / key / genesis loading
    // so the driver run doesn't touch --node-key, --custom-network-config-dir,
    // or any other consensus prerequisite the hive shim doesn't bother to
    // provision. Lean-only: the endpoints it serves are lean's, and it must
    // still precede the key resolution below.
    if matches!(network, Network::Lean(_)) && ethlambda_rpc::test_driver::test_driver_enabled() {
        info!("HIVE_LEAN_TEST_DRIVER detected; booting in test-driver mode");
        return run_test_driver(rpc_config).await;
    }

    let node_p2p_key = resolve_node_key(common.node_key.as_deref())?;

    #[cfg(all(not(target_env = "msvc"), feature = "jemalloc"))]
    info!("Using jemalloc allocator with heap profiling enabled");
    #[cfg(any(target_env = "msvc", not(feature = "jemalloc")))]
    info!("Using system allocator");

    info!(node_key=?common.node_key, "got node key");

    let p2p_socket = SocketAddr::new(IpAddr::from([0, 0, 0, 0]), common.gossipsub_port);

    // The `--bootnodes` file, read and parsed once. An absent flag is not an
    // empty list: `default_bootnodes` is what each chain falls back to.
    let bootnodes = parse_enrs(
        common
            .bootnodes
            .as_deref()
            .map(read_bootnode_strings)
            .transpose()?
            .unwrap_or_else(|| default_bootnodes(&network)),
    );

    // Shared, runtime-mutable aggregator flag, seeded from the CLI flag only
    // `node` takes: mainnet has no aggregation duty. Threaded into both the
    // blockchain actor, which reads it on every tick, and the API server, whose
    // admin endpoints can flip it at runtime.
    let aggregator = AggregatorController::new(match &network {
        Network::Lean(lean) => lean.is_aggregator,
        Network::Mainnet => false,
    });

    // Shared, runtime-readable sync status. The blockchain actor writes it each
    // tick (alongside the `lean_node_sync_status` metric); the RPC
    // `/lean/v0/node/syncing` endpoint reads it. Seeded to Idle, matching the
    // metric's startup value.
    let sync_status = SyncStatusController::default();

    // Chain-event bus: the blockchain actor is the sole publisher; each SSE
    // client (`GET /lean/v0/events`) subscribes its own receiver through the
    // clone handed to the RPC server below. With no subscribers attached, the
    // receiver-count guard in `emit` makes every emission a no-op.
    let events = EventBus::default();

    // Both chains keep a RocksDB directory now, so this is resolved once
    // rather than in each arm. Opening it before the match also means a bad
    // `--data-dir` fails before any network configuration is derived.
    let data_dir =
        std::path::absolute(&common.data_dir).unwrap_or_else(|_| common.data_dir.clone());
    info!(data_dir = %data_dir.display(), "Initializing DB");
    std::fs::create_dir_all(&data_dir)
        .wrap_err_with(|| format!("failed to create data directory {}", data_dir.display()))?;
    let backend = Arc::new(
        RocksDBBackend::open(&data_dir)
            .map_err(|err| eyre::eyre!("{err}"))
            .wrap_err_with(|| format!("failed to open RocksDB at {}", data_dir.display()))?,
    );

    let clean_checkpoint_urls = checkpoint_sync::clean_urls(&common.checkpoint_sync_url);

    // The one place the two chains diverge. Everything above is shared setup;
    // everything below is shared startup and, in `wait_for_shutdown`, shared
    // teardown.
    let setup = match network {
        // The full lean consensus node: a chain actor with validator duties, a
        // RocksDB store, checkpoint sync and the `/lean/v0` API.
        Network::Lean(lean) => {
            let config_path = lean.genesis;
            let validators_path = lean.validators;
            let validator_config = lean.validator_config;
            let validator_keys_dir = lean.hash_sig_keys_dir;

            let config_yaml = std::fs::read_to_string(&config_path).wrap_err_with(|| {
                format!(
                    "failed to read genesis config from {}",
                    config_path.display()
                )
            })?;
            let genesis_config: GenesisConfig = serde_yaml_ng::from_str(&config_yaml)
                .wrap_err_with(|| {
                    format!(
                        "failed to parse genesis config from {}",
                        config_path.display()
                    )
                })?;

            info!(
                genesis_time = genesis_config.genesis_time,
                milliseconds_per_slot = genesis_config.milliseconds_per_slot,
                validator_count = genesis_config.genesis_validators.len(),
                "Loaded genesis configuration"
            );

            let validator_config_file = read_validator_config_file(&validator_config)?;
            let node_names = load_node_names(&validator_config_file);

            // Resolve attestation_committee_count: CLI flag > validator-config.yaml > 1.
            // The CLI path is bounded by clap's `range(1..)`; enforce the same lower
            // bound here so a YAML value of 0 cannot bypass it.
            let attestation_committee_count = lean
                .attestation_committee_count
                .or(validator_config_file.config.attestation_committee_count)
                .unwrap_or(1);
            eyre::ensure!(
                attestation_committee_count >= 1,
                "attestation_committee_count must be >= 1 (got {attestation_committee_count})"
            );
            info!(
                attestation_committee_count,
                "Loaded attestation committee count"
            );
            ethlambda_blockchain::metrics::set_attestation_committee_count(
                attestation_committee_count,
            );

            let validator_keys =
                read_validator_keys(&validators_path, &validator_keys_dir, &lean.node_id)
                    .wrap_err("failed to load validator keys")?;

            let store =
                fetch_initial_state(&clean_checkpoint_urls, &genesis_config, backend.clone())
                    .await
                    .inspect_err(|err| error!(%err, "Failed to initialize state"))?;

            let validator_ids: Vec<u64> = validator_keys.keys().copied().collect();

            // Attestation subnets this node subscribes to, computed once and shared by
            // the P2P swarm (to open gossip subscriptions) and the blockchain actor
            // (to size the early-aggregation threshold), so both agree on which subnets
            // feed this node's gossip groups. Subscriptions are fixed at startup and
            // are not re-evaluated when the aggregator role is toggled at runtime; see
            // the hot-standby note on SwarmConfig.
            let subscribed_subnets = attestation_subscription_subnets(
                &validator_ids,
                attestation_committee_count,
                lean.is_aggregator,
                lean.aggregate_subnet_ids.as_deref(),
            );

            let blockchain_config = BlockChainConfig {
                aggregator: aggregator.clone(),
                sync_status_controller: sync_status.clone(),
                attestation_committee_count,
                gate_duties: !lean.disable_duty_sync_gate,
                subscribed_subnets: subscribed_subnets.clone(),
                proposer_config: ProposerConfig {
                    enable_proposer_aggregation: lean.enable_proposer_aggregation,
                    max_attestations_per_block: lean.max_attestations_per_block,
                },
            };

            ChainSetup {
                wire: WireConfig::Lean(LeanWireConfig {
                    validator_ids,
                    attestation_committee_count,
                    subscription_subnets: subscribed_subnets.clone(),
                    milliseconds_per_slot: genesis_config.milliseconds_per_slot,
                }),
                discovery: DiscoveryWireEntries {
                    subscription_subnets: subscribed_subnets,
                    attestation_committee_count,
                    fork_id: ethlambda_types::enr::EnrForkId::local(),
                    custody_group_count: None,
                },
                store,
                node_names,
                chain: Some((validator_keys, blockchain_config)),
            }
        }
        // The Ethereum Beacon Chain follower: the wire and nothing above it.
        // Every network parameter is derived rather than configured, from the
        // genesis state built into the binary: the fork digest depends on the
        // epoch, which depends on genesis time. See `crate::beacon`.
        Network::Mainnet => {
            info!(
                bootnodes = ?common.bootnodes,
                gossipsub_port = common.gossipsub_port,
                http_address = %common.http_address,
                metrics_port = common.metrics_port,
                discovery_port = common.discovery.port,
                advertise_ip = ?common.discovery.advertise_ip,
                "Resolved mainnet configuration"
            );

            let params = beacon::wire_params()?;

            let store = fetch_initial_beacon_state(&clean_checkpoint_urls, backend.clone())
                .await
                .inspect_err(|err| error!(%err, "Failed to initialize state"))?;

            ChainSetup {
                wire: WireConfig::Beacon(Box::new(params.wire)),
                discovery: DiscoveryWireEntries {
                    // No attestation subnet is subscribed, so the bitfield is
                    // 64 bits all unset: exactly what this node serves.
                    subscription_subnets: Default::default(),
                    attestation_committee_count:
                        ethlambda_p2p::beacon::constants::ATTESTATION_SUBNET_COUNT,
                    fork_id: params.fork_id,
                    custody_group_count: Some(
                        ethlambda_p2p::beacon::constants::CUSTODY_REQUIREMENT,
                    ),
                },
                store,
                node_names: HashMap::new(),
                // Nothing is imported, so there is no chain actor.
                chain: None,
            }
        }
    };

    // The operator-supplied half of the discv5 configuration, which neither
    // chain varies. Built before `build_swarm` because that moves the node key
    // and the bootnode list.
    let discovery = DiscoverySpawnConfig {
        node_key: node_p2p_key.clone(),
        bind_ip: p2p_socket.ip(),
        discovery_port: common.discovery.port,
        // Advertised as both the `quic` and `tcp` entries: TCP and UDP are
        // separate namespaces, so `build_swarm` binds both from this one number.
        p2p_port: p2p_socket.port(),
        bootnodes: bootnodes.clone(),
        advertise_ip: common.discovery.advertise_ip,
        target_peers: common.discovery.target_peers,
        subscription_subnets: setup.discovery.subscription_subnets,
        attestation_committee_count: setup.discovery.attestation_committee_count,
        fork_id: setup.discovery.fork_id,
        custody_group_count: setup.discovery.custody_group_count,
    };

    let built = build_swarm(SwarmConfig {
        node_key: node_p2p_key,
        bootnodes,
        listening_socket: p2p_socket,
        wire: setup.wire,
    })
    .wrap_err("failed to build swarm")?;

    // Captured before `built` is moved into the P2P actor; the RPC
    // `/lean/v0/node/identity` endpoint reports it.
    let local_peer_id = built.local_peer_id.to_string();

    // `P2P::spawn` starts the discv5 server from this and owns the resulting
    // handle.
    let p2p = P2P::spawn(built, setup.store.clone(), setup.node_names, discovery)
        .await
        .wrap_err("failed to start discv5 discovery")?;

    let shutdown = CancellationToken::new();
    let rpc_shutdown = shutdown.clone();
    let rpc_store = setup.store.clone();
    let rpc_aggregator = aggregator.clone();
    let rpc_sync_status = sync_status.clone();
    let rpc_events = events.clone();

    let http = tokio::spawn(async move {
        let _ = ethlambda_rpc::start_rpc_server(
            rpc_config,
            rpc_store,
            rpc_aggregator,
            rpc_sync_status,
            local_peer_id,
            rpc_events,
            rpc_shutdown,
        )
        .await
        .inspect_err(|err| error!(%err, "RPC server failed"));
    });

    let mut running_node = RunningNode {
        p2p,
        blockchain: None,
        http,
        shutdown,
    };

    let Some((validator_keys, blockchain_config)) = setup.chain else {
        // Mainnet is the wire and nothing above it: no chain actor to spawn,
        // wire up, stop or join.
        wait_for_shutdown(running_node).await;
        return Ok(());
    };

    let blockchain = BlockChain::spawn(setup.store, validator_keys, blockchain_config, events);

    let p2p_ref = running_node.p2p.actor_ref();
    let p2p = p2p_ref.to_block_chain_to_p2p_ref();

    // Wire actors together via protocol refs
    blockchain
        .actor_ref()
        .recipient::<InitP2P>()
        .send(InitP2P { p2p })
        .inspect_err(|err| error!(%err, "Failed to send InitP2P — actors not wired"))?;

    p2p_ref
        .recipient::<InitBlockChain>()
        .send(InitBlockChain {
            blockchain: blockchain.actor_ref().to_p2p_to_block_chain_ref(),
        })
        .inspect_err(|err| error!(%err, "Failed to send InitBlockChain — actors not wired"))?;

    running_node.blockchain = Some(blockchain);
    wait_for_shutdown(running_node).await;
    Ok(())
}

/// Wait for ctrl-c, then stop and join whatever is running.
///
/// A 2nd, 3rd and 4th ctrl-c escalate to `std::process::exit(1)` rather than
/// leaving shutdown stuck on an actor that hangs in `stop()`/`join()`.
///
/// Shared by both chains. Mainnet used to park on `pending()` here, so a
/// follower killed mid-write left recovery to do; it now tears down the same
/// way the lean node does.
async fn wait_for_shutdown(node: RunningNode) {
    info!("Node initialized");

    // 1st ctrl+c: start graceful shutdown
    tokio::signal::ctrl_c().await.ok();

    info!("Shutdown signal received, stopping actors and servers...");

    tokio::spawn(async move {
        // This can be turned into a loop
        tokio::signal::ctrl_c().await.ok();
        warn!(
            "Graceful shutdown in progress. Press ctrl+C 2 more times to force ungraceful shutdown"
        );
        tokio::signal::ctrl_c().await.ok();
        warn!(
            "Graceful shutdown in progress. Press ctrl+C 1 more times to force ungraceful shutdown"
        );
        tokio::signal::ctrl_c().await.ok();
        info!("Forced ungraceful shutdown...");
        std::process::exit(1);
    });

    let blockchain_ref = node
        .blockchain
        .as_ref()
        .map(|blockchain| blockchain.actor_ref().clone());
    let p2p_ref = node.p2p.actor_ref().clone();

    if let Some(blockchain_ref) = &blockchain_ref {
        blockchain_ref.context().stop();
    }
    p2p_ref.context().stop();
    node.shutdown.cancel();

    if let Some(blockchain_ref) = blockchain_ref {
        blockchain_ref.join().await;
    }
    p2p_ref.join().await;
    let _ = node.http.await;

    info!("Shutdown complete");
}

/// The ENRs to start from when `--bootnodes` was not given.
///
/// Mainnet publishes a bootnode list, so an absent flag means "use it". A lean
/// network's ENRs are per-deployment, so there is nothing to default to and an
/// absent flag means this node reaches peers only through discv5. That case
/// warns, because a node that then finds nobody is islanded and otherwise looks
/// healthy.
fn default_bootnodes(network: &Network) -> Vec<String> {
    match network {
        Network::Lean(_) => {
            warn!(
                "No --bootnodes file supplied: starting with no bootnodes. This node can \
                 only find peers via discv5."
            );
            Vec::new()
        }
        Network::Mainnet => beacon::MAINNET_BOOTNODES
            .iter()
            .map(|enr| enr.to_string())
            .collect(),
    }
}

/// Read a bootnode file into one ENR string per entry.
///
/// Shared by both chains: [`run_node`] reads the file once and hands the result
/// to [`parse_enrs`], which skips an unusable record with a warning rather than
/// failing startup, and warns again if that leaves the list empty.
///
/// YAML first, then a line-oriented fallback. The two sub-commands arrived
/// with different readers: `node` required a strict YAML sequence, `beacon`
/// used a tolerant line parser so that a list pasted from a chat message or a
/// comment left in the file would still work. Trying YAML first makes the
/// merged reader a true superset of both, which a line parser alone is not: a
/// quoted (`"enr:..."`) or flow-style (`["enr:...", ...]`) sequence is valid
/// YAML that `node` accepted before, and a line parser would hand its quotes
/// and brackets on to `parse_enrs`.
///
/// The fallback is not an error path. Anything YAML rejects, a bare list with
/// no `- ` markers or a stray `#` comment in a file that is otherwise a flow
/// sequence, is exactly what the tolerant reader exists for.
fn read_bootnode_strings(path: &Path) -> eyre::Result<Vec<String>> {
    let contents = std::fs::read_to_string(path)
        .wrap_err_with(|| format!("failed to read bootnodes from {}", path.display()))?;

    if let Ok(entries) = serde_yaml_ng::from_str::<Vec<String>>(&contents) {
        return Ok(entries);
    }

    Ok(contents
        .lines()
        .map(|line| line.trim().trim_start_matches("- ").trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.to_string())
        .collect())
}

/// Apply the Shadow-simulator sim-cost / fake-XMSS configuration from the CLI.
///
/// Compiled only under the `shadow-integration` feature. Call once at startup,
/// before any consensus/aggregation work, so the fake-proof and sim-cost hooks
/// are installed before the first signing or aggregation path runs.
#[cfg(feature = "shadow-integration")]
fn init_shadow_cost(shadow: &cli::ShadowOptions) {
    info!(
        fake = shadow.shadow_xmss_fake,
        aggregate_rate = ?shadow.shadow_xmss_aggregate_signatures_rate,
        verify_rate = ?shadow.shadow_xmss_verify_aggregated_signatures_rate,
        merge_rate = ?shadow.shadow_xmss_merge_rate,
        fake_proof_size = shadow.shadow_xmss_fake_proof_size,
        "Applying Shadow XMSS sim-cost / fake-XMSS config"
    );
    ethlambda_crypto::shadow_cost::init(
        shadow.shadow_xmss_fake,
        shadow.shadow_xmss_aggregate_signatures_rate,
        shadow.shadow_xmss_verify_aggregated_signatures_rate,
        shadow.shadow_xmss_merge_rate,
        shadow.shadow_xmss_fake_proof_size as usize,
    );
}

/// Boot the binary in Hive test-driver mode.
///
/// Skips every consensus/p2p subsystem and just exposes the
/// `/lean/v0/test_driver/...` HTTP endpoints over the configured API port.
/// The driver-mode store is seeded with an empty in-memory state and is
/// replaced on every `fork_choice/init` request from the simulator.
async fn run_test_driver(rpc_config: RpcConfig) -> eyre::Result<()> {
    use tokio::sync::RwLock;

    let driver: ethlambda_rpc::test_driver::DriverState =
        Arc::new(RwLock::new(ethlambda_rpc::test_driver::empty_driver_store()));

    let shutdown_token = CancellationToken::new();
    let rpc_shutdown = shutdown_token.clone();

    let rpc_handle = tokio::spawn(async move {
        if let Err(err) =
            ethlambda_rpc::start_test_driver_rpc_server(rpc_config, driver, rpc_shutdown).await
        {
            error!(%err, "Test-driver RPC server failed");
        }
    });

    info!("Test-driver RPC ready");

    tokio::signal::ctrl_c().await.ok();
    info!("Shutdown signal received, stopping test-driver RPC...");
    shutdown_token.cancel();
    let _ = rpc_handle.await;
    info!("Shutdown complete");

    Ok(())
}

/// Subset of `validator-config.yaml` consumed by ethlambda.
///
/// The `config` block is a network-wide settings bag shared across clients;
/// only fields ethlambda actually reads are deserialized. The `validators`
/// list feeds the node-name registry passed to `P2P::spawn`.
#[derive(Debug, Deserialize)]
struct ValidatorConfigFile {
    #[serde(default)]
    config: ValidatorConfigBlock,
    validators: Vec<ValidatorConfigEntry>,
}

#[derive(Debug, Default, Deserialize)]
struct ValidatorConfigBlock {
    #[serde(default)]
    attestation_committee_count: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ValidatorConfigEntry {
    name: String,
    privkey: H256,
}

fn read_validator_config_file(path: impl AsRef<Path>) -> eyre::Result<ValidatorConfigFile> {
    let path = path.as_ref();
    let yaml = std::fs::read_to_string(path).wrap_err_with(|| {
        format!(
            "failed to read validator config file from {}",
            path.display()
        )
    })?;
    serde_yaml_ng::from_str(&yaml).wrap_err_with(|| {
        format!(
            "failed to parse validator config file from {}",
            path.display()
        )
    })
}

fn load_node_names(file: &ValidatorConfigFile) -> HashMap<PeerId, String> {
    let names_and_privkeys = file
        .validators
        .iter()
        .map(|v| (v.name.clone(), v.privkey))
        .collect();

    ethlambda_p2p::derive_peer_ids(names_and_privkeys)
}

/// One entry in `annotated_validators.yaml` as emitted by `lean-quickstart`'s
/// genesis generator.
///
/// Each validator appears twice in the file under its node name: once with the
/// attester key and once with the proposer key. The role is determined by the
/// `_attester_` / `_proposer_` substring in `privkey_file`.
#[derive(Debug, Deserialize, Clone)]
struct AnnotatedValidator {
    index: u64,
    /// Parsed for hex-format validation only; not cross-checked against the
    /// loaded secret key since leansig doesn't expose any pk getters.
    #[serde(rename = "pubkey_hex", deserialize_with = "deser_pubkey_hex")]
    _pubkey_hex: ValidatorPubkeyBytes,
    privkey_file: PathBuf,
}

pub fn deser_pubkey_hex<'de, D>(d: D) -> Result<ValidatorPubkeyBytes, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    let value = String::deserialize(d)?;
    let pubkey: ValidatorPubkeyBytes = hex::decode(&value)
        .map_err(|_| D::Error::custom("ValidatorPubkey value is not valid hex"))?
        .try_into()
        .map_err(|_| D::Error::custom("ValidatorPubkey length != 52"))?;
    Ok(pubkey)
}

#[derive(Debug)]
enum ValidatorKeyRole {
    Attestation,
    Proposal,
}

/// Classify a privkey file as attestation or proposal based on the filename.
///
/// Matches zeam's (`pkgs/cli/src/node.zig:540`) and lantern's
/// (`client_keys.c:606`) routing, which lets all three clients share the
/// `lean-quickstart` generator output unchanged.
fn classify_role(file: &Path) -> Result<ValidatorKeyRole, String> {
    let name = file
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| format!("non-utf8 filename '{}'", file.display()))?;
    let is_attester = name.contains("attester");
    let is_proposer = name.contains("proposer");
    match (is_attester, is_proposer) {
        (true, false) => Ok(ValidatorKeyRole::Attestation),
        (false, true) => Ok(ValidatorKeyRole::Proposal),
        (false, false) => Err(format!(
            "filename '{name}' must contain 'attester' or 'proposer'"
        )),
        (true, true) => Err(format!(
            "filename '{name}' contains both 'attester' and 'proposer'; ambiguous"
        )),
    }
}

#[derive(Default)]
struct RoleSlots {
    attestation: Option<PathBuf>,
    proposal: Option<PathBuf>,
}

fn read_validator_keys(
    validators_path: impl AsRef<Path>,
    validator_keys_dir: impl AsRef<Path>,
    node_id: &str,
) -> eyre::Result<HashMap<u64, ValidatorKeyPair>> {
    let validators_path = validators_path.as_ref();
    let validator_keys_dir = validator_keys_dir.as_ref();
    let validators_yaml = std::fs::read_to_string(validators_path).wrap_err_with(|| {
        format!(
            "failed to read validators file from {}",
            validators_path.display()
        )
    })?;
    let validator_infos: BTreeMap<String, Vec<AnnotatedValidator>> =
        serde_yaml_ng::from_str(&validators_yaml).wrap_err_with(|| {
            format!(
                "failed to parse validators file from {}",
                validators_path.display()
            )
        })?;

    let validator_vec = validator_infos
        .get(node_id)
        .ok_or_else(|| eyre::eyre!("node ID '{node_id}' not found in validators config"))?;

    let resolve_path = |file: &Path| -> PathBuf {
        if file.is_absolute() {
            file.to_path_buf()
        } else {
            validator_keys_dir.join(file)
        }
    };

    // Group entries per validator index, routing each to its role slot.
    let mut grouped: BTreeMap<u64, RoleSlots> = BTreeMap::new();
    for entry in validator_vec {
        let role = classify_role(&entry.privkey_file).map_err(eyre::Report::msg)?;
        let path = resolve_path(&entry.privkey_file);
        let slots = grouped.entry(entry.index).or_default();
        let target = match role {
            ValidatorKeyRole::Attestation => &mut slots.attestation,
            ValidatorKeyRole::Proposal => &mut slots.proposal,
        };
        if target.is_some() {
            eyre::bail!("validator {}: duplicate {role:?} entry", entry.index);
        }
        *target = Some(path);
    }

    let load_key = |path: &Path, purpose: &str| -> eyre::Result<ValidatorSecretKey> {
        let bytes = std::fs::read(path)
            .wrap_err_with(|| format!("failed to read {purpose} key file {}", path.display()))?;
        ValidatorSecretKey::from_bytes(&bytes)
            .map_err(|err| eyre::eyre!("failed to parse {purpose} key {}: {err:?}", path.display()))
    };

    let mut validator_keys = HashMap::new();
    for (idx, slots) in grouped {
        let att_path = slots
            .attestation
            .ok_or_else(|| eyre::eyre!("validator {idx}: missing attester entry"))?;
        let prop_path = slots
            .proposal
            .ok_or_else(|| eyre::eyre!("validator {idx}: missing proposer entry"))?;

        info!(
            %node_id,
            index = idx,
            attestation_key = ?att_path,
            proposal_key = ?prop_path,
            "Loading validator key pair"
        );

        let attestation_key = load_key(&att_path, "attestation")?;
        let proposal_key = load_key(&prop_path, "proposal")?;

        validator_keys.insert(
            idx,
            ValidatorKeyPair {
                attestation_key,
                proposal_key,
            },
        );
    }

    info!(
        %node_id,
        count = validator_keys.len(),
        "Loaded validator key pairs"
    );

    Ok(validator_keys)
}

fn read_hex_file_bytes(path: impl AsRef<Path>) -> eyre::Result<Vec<u8>> {
    let path = path.as_ref();
    let file_content = std::fs::read_to_string(path)
        .wrap_err_with(|| format!("failed to read hex file from {}", path.display()))?;
    let hex_string = file_content.trim().trim_start_matches("0x");
    hex::decode(hex_string)
        .wrap_err_with(|| format!("failed to decode hex file from {}", path.display()))
}

/// Resolve a sub-command's node key: read `--node-key` if given, otherwise
/// generate a fresh secp256k1 key in memory.
///
/// Shared by both sub-commands, since `--node-key` is optional on both. There
/// is no precedent elsewhere in this binary for writing generated key material
/// to `--data-dir`, and doing so would need file permissions this repo does
/// not otherwise establish; keeping it in memory only is the conservative
/// choice, so a generated identity does not survive a restart.
///
/// The warning matters more on `node` than on `beacon`. `beacon` is a
/// read-only follower with no validator identity to protect, but a lean node
/// that silently changes PeerId every restart loses its place in every peer's
/// scoring and in any ENR its neighbours cached.
fn resolve_node_key(node_key_path: Option<&Path>) -> eyre::Result<Vec<u8>> {
    match node_key_path {
        Some(path) => read_hex_file_bytes(path)
            .wrap_err_with(|| format!("failed to load node key from {}", path.display())),
        None => {
            let generated = secp256k1::SecretKey::new(&mut secp256k1::rand::rngs::OsRng);
            warn!(
                "No --node-key supplied: generated an ephemeral secp256k1 key in memory for \
                 this run only. This node's PeerId and ENR will be different on the next \
                 start; pass --node-key with a persisted key file for a stable identity."
            );
            Ok(generated.secret_bytes().to_vec())
        }
    }
}

/// Fetch the initial state for the node.
///
/// State already on disk wins: a previous run's DB is resumed from whenever it
/// exists and belongs to this network, whether or not `checkpoint_urls` is
/// supplied. `checkpoint_urls` is the fallback for when there is nothing
/// resumable on disk, or when what is there has fallen too far behind the
/// current slot to be worth catching up over P2P
/// ([`MAX_RESUMABLE_DB_STATE_AGE`]).
///
/// With no resumable DB state, a non-empty `checkpoint_urls` performs checkpoint
/// sync by downloading and verifying the finalized state AND signed block from a
/// peer. URLs are tried in order: the first peer that succeeds wins, and
/// failures fall over to the next URL. Startup only aborts if every URL fails.
/// An empty `checkpoint_urls` creates a genesis state from the local genesis
/// configuration.
///
/// Aborting when every URL fails is deliberate, and applies even when a stale
/// resumable DB is in hand: an operator who configured a checkpoint URL asked
/// for a specific anchor, so an unreachable one is a misconfiguration to
/// surface at boot rather than paper over by silently starting a node that is
/// hours behind. Dropping the flag is the way to say "resume whatever is on
/// disk"; that path never aborts.
///
/// Fetching the matching signed block lets the local store serve a valid
/// anchor via the `BlocksByRoot` req-resp protocol; without it, peers
/// requesting the anchor would receive a synthetic block whose hash differs
/// from `latest_finalized.root` and would score-penalize us.
///
/// # Arguments
///
/// * `checkpoint_urls` - Zero or more base URLs of peer API servers
/// * `genesis` - Genesis configuration (for genesis_time verification and genesis state creation)
/// * `backend` - Storage backend for Store creation
///
/// # Returns
///
/// `Ok(Store)` on success, or `Err(CheckpointSyncError)` if checkpoint sync fails.
/// Genesis path is infallible and always returns `Ok`.
async fn fetch_initial_state(
    checkpoint_urls: &[String],
    genesis: &GenesisConfig,
    backend: Arc<dyn StorageBackend>,
) -> Result<Store, checkpoint_sync::CheckpointSyncError> {
    let validators = genesis.validators();

    // Prefer resuming from on-disk state to avoid re-downloading what we
    // already have. Tried before the checkpoint-sync and genesis paths so that
    // a restart without `--checkpoint-sync-url` keeps the chain instead of
    // writing a slot-0 anchor over it.
    //
    // `from_db_state` loads without judging, so the identity check is here:
    // the wrong chain or the wrong genesis aborts startup rather than being
    // built on top of.
    if let Some(store) = Store::from_db_state(backend.clone())? {
        if store.chain() != Chain::Lean {
            return Err(checkpoint_sync::CheckpointSyncError::WrongChain {
                expected: Chain::Lean,
                found: store.chain(),
            });
        }

        // The slot duration is deliberately absent from the SSZ state, so the
        // state check below cannot see it: compare the persisted config's time
        // grid. A data directory built at another cadence indexes its blocks
        // against a different time grid, which makes it as foreign as another
        // genesis.
        let persisted_grid = store.config().time_grid();
        genesis
            .verify_time_config(&persisted_grid)
            .inspect_err(|err| {
                error!(
                    %err,
                    db_genesis_time = persisted_grid.genesis_time,
                    db_milliseconds_per_slot = persisted_grid.milliseconds_per_slot,
                    expected_genesis_time = genesis.genesis_time,
                    expected_milliseconds_per_slot = genesis.milliseconds_per_slot,
                    "Persisted DB was built on a different time grid; refusing to reuse this data directory"
                )
            })?;

        let root = store.finalized_state_root()?;
        let state = store
            .get_state(&root)?
            .ok_or(ethlambda_storage::Error::UnexpectedMissingState(root))?;
        genesis.verify_state(&state).inspect_err(|err| {
            error!(
                %err,
                db_genesis_time = state.genesis_time(),
                expected_genesis_time = genesis.genesis_time,
                expected_validators = genesis.genesis_validators.len(),
                "Persisted DB belongs to a different network; refusing to reuse this data directory"
            )
        })?;

        let now_ms = SystemTime::UNIX_EPOCH
            .elapsed()
            .expect("already past the unix epoch")
            .as_millis() as u64;
        let current_slot =
            now_ms.saturating_sub(genesis.genesis_time * 1000) / genesis.milliseconds_per_slot;
        let head_slot = store.head_slot();
        let gap = current_slot.saturating_sub(head_slot);
        if gap <= MAX_RESUMABLE_DB_STATE_AGE {
            info!(head_slot, current_slot, gap, "Resuming from existing DB");
            return Ok(store);
        }
        // No checkpoint URL was configured, so just run the node against the
        // data directory it was given: that is the setup asked for, and there
        // is no anchor to switch to. The warning is the point of this arm,
        // since the DB is known to be stale and range sync may not be able to
        // close a gap this large: peers prune block signatures past
        // `SIGNATURE_PRUNING_RANGE`, so beyond that horizon they cannot serve
        // the history the node is missing.
        if checkpoint_urls.is_empty() {
            warn!(head_slot, current_slot, gap, "DB is stale; resuming anyway");
            return Ok(store);
        }
        warn!(head_slot, current_slot, gap, "DB is stale; checkpoint sync");
    }

    if checkpoint_urls.is_empty() {
        info!("No checkpoint sync URL provided, initializing from genesis state");
        let genesis_state = State::from_genesis(genesis.genesis_time, validators);
        return Ok(Store::from_anchor_state(
            backend,
            genesis_state,
            genesis.milliseconds_per_slot,
        ));
    }

    // Checkpoint sync path: try URLs in order, fail over to the next on error.
    info!(?checkpoint_urls, "Starting checkpoint sync");

    let (state, signed_block) = checkpoint_sync::fetch_anchor_with_retry(
        checkpoint_urls,
        genesis.genesis_time,
        genesis.genesis_validators_root(),
    )
    .await?;

    info!(
        slot = state.slot,
        validators = state.validators.len(),
        finalized_slot = state.latest_finalized.slot,
        anchor_block_slot = signed_block.message.slot,
        "Checkpoint sync complete"
    );

    // Initialize the store from state + anchor block body, then persist the
    // signatures so we can serve the anchor on BlocksByRoot. `insert_signed_block`
    // overlaps with what `get_forkchoice_store` already wrote, but it's
    // idempotent and the only path that also stores `BlockProof`.
    let anchor_root = signed_block.message.header().hash_tree_root();
    let mut store = Store::get_forkchoice_store(
        backend,
        state,
        signed_block.message.clone(),
        genesis.milliseconds_per_slot,
    )
    .inspect_err(|err| error!(%err, "Failed to initialize store from anchor state and block"))
    .map_err(|_| checkpoint_sync::CheckpointSyncError::AnchorPairingMismatch)?;
    store
        .insert_signed_block(anchor_root, SignedBeaconBlock::Lean(signed_block))
        .inspect_err(|err| error!(%err, "Failed to insert anchor signed block into store"))
        .map_err(|_| checkpoint_sync::CheckpointSyncError::StoreInsertSignedBlock)?;
    Ok(store)
}

/// Fetch the initial state for a beacon node.
///
/// The beacon twin of [`fetch_initial_state`], with the same precedence: a
/// resumable directory wins over a download, and a download wins over a
/// directory that has fallen too far behind
/// ([`MAX_RESUMABLE_DB_STATE_AGE`]).
///
/// One row differs. Lean initializes from its genesis config when there is
/// neither a DB nor a URL; beacon aborts. The mainnet genesis state is built
/// into the binary, so anchoring there is possible, but this node imports
/// nothing, so it would park at slot 0 while claiming to follow mainnet.
///
/// Staleness reuses [`MAX_RESUMABLE_DB_STATE_AGE`], which is expressed in
/// slots: 90 minutes at beacon's 12-second slots against 30 at lean's four.
/// Worth revisiting when block import lands and the cost of a gap becomes
/// real.
async fn fetch_initial_beacon_state(
    checkpoint_urls: &[String],
    backend: Arc<dyn StorageBackend>,
) -> Result<Store, checkpoint_sync::CheckpointSyncError> {
    let config = Config::mainnet();
    let genesis = beacon::mainnet_genesis()
        .expect("the built-in mainnet genesis decodes, checked at startup");

    if let Some(store) = Store::from_db_state(backend.clone())? {
        if store.chain() != Chain::Beacon {
            return Err(checkpoint_sync::CheckpointSyncError::WrongChain {
                expected: Chain::Beacon,
                found: store.chain(),
            });
        }

        let root = store.finalized_state_root()?;
        let state = store
            .get_state(&root)?
            .ok_or(ethlambda_storage::Error::UnexpectedMissingState(root))?;
        verify_state_genesis(
            &state,
            genesis.genesis_time,
            genesis.genesis_validators_root,
        )
        .inspect_err(|err| {
            error!(
                %err,
                db_genesis_time = state.genesis_time(),
                expected_genesis_time = genesis.genesis_time,
                "Persisted DB belongs to a different network; refusing to reuse this data directory"
            )
        })?;

        let now = SystemTime::UNIX_EPOCH
            .elapsed()
            .expect("already past the unix epoch")
            .as_secs();
        let current_slot = now.saturating_sub(genesis.genesis_time) / config.seconds_per_slot;
        // `init_beacon` writes the head in the same batch as the finalized
        // checkpoint, and `finalized_state_root` above has already succeeded,
        // so a directory that got this far has one. Asserting beats
        // substituting a slot, which would read as maximally stale and force a
        // re-sync of a directory that should have resumed.
        let (head_slot, _) = store
            .beacon_head()
            .expect("an anchored directory has a head");
        let gap = current_slot.saturating_sub(head_slot);

        if gap <= MAX_RESUMABLE_DB_STATE_AGE {
            info!(head_slot, current_slot, gap, "Resuming from existing DB");
            return Ok(store);
        }
        if checkpoint_urls.is_empty() {
            warn!(head_slot, current_slot, gap, "DB is stale; resuming anyway");
            return Ok(store);
        }
        warn!(head_slot, current_slot, gap, "DB is stale; checkpoint sync");
    }

    if checkpoint_urls.is_empty() {
        return Err(checkpoint_sync::CheckpointSyncError::BeaconGenesisSync);
    }

    info!(?checkpoint_urls, "Starting beacon checkpoint sync");

    let (state, block) = checkpoint_sync::fetch_beacon_anchor_with_retry(
        checkpoint_urls,
        &config,
        genesis.genesis_time,
        genesis.genesis_validators_root,
    )
    .await?;

    info!(
        slot = state.slot(),
        fork = %state.fork_name(),
        validators = state.validators().len(),
        finalized_epoch = state.finalized_checkpoint().epoch,
        anchor_block_slot = block.slot(),
        "Beacon checkpoint sync complete"
    );

    fork_choice::get_forkchoice_store(backend, state, block, &config)
        .inspect_err(|err| error!(%err, "Failed to initialize store from anchor state and block"))
        .map_err(|_| checkpoint_sync::CheckpointSyncError::AnchorPairingMismatch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::{Command, try_parse_from};
    use ethlambda_storage::backend::InMemoryBackend;
    use ethlambda_types::constants::DEFAULT_MILLISECONDS_PER_SLOT;
    use ethlambda_types::genesis::GenesisValidatorEntry;

    /// Validator-config snippet matching `lean-quickstart`'s ansible-devnet
    /// where networks share a non-default committee count.
    const VC_WITH_COMMITTEE_COUNT: &str = r#"
shuffle: roundrobin
deployment_mode: ansible
config:
  activeEpoch: 18
  keyType: "hash-sig"
  attestation_committee_count: 2
validators:
  - name: "ethlambda_0"
    privkey: "299550529a79bc2dce003747c52fb0639465c893e00b0440ac66144d625e066a"
    enrFields:
      ip: "127.0.0.1"
      quic: 9001
    metricsPort: 9095
    apiPort: 5055
    subnet: 0
    isAggregator: false
    count: 1
"#;

    /// Local-devnet snippet without the optional field — committee count is
    /// expected to fall back to the binary default.
    const VC_WITHOUT_COMMITTEE_COUNT: &str = r#"
shuffle: roundrobin
deployment_mode: local
config:
  activeEpoch: 18
  keyType: "hash-sig"
validators:
  - name: "ethlambda_0"
    privkey: "299550529a79bc2dce003747c52fb0639465c893e00b0440ac66144d625e066a"
    enrFields:
      ip: "127.0.0.1"
      quic: 9001
    metricsPort: 8087
    apiPort: 5055
    isAggregator: false
    count: 1
"#;

    #[test]
    fn parses_committee_count_when_present() {
        let file: ValidatorConfigFile = serde_yaml_ng::from_str(VC_WITH_COMMITTEE_COUNT).unwrap();
        assert_eq!(file.config.attestation_committee_count, Some(2));
        assert_eq!(file.validators.len(), 1);
        assert_eq!(file.validators[0].name, "ethlambda_0");
    }

    #[test]
    fn defaults_to_none_when_field_absent() {
        let file: ValidatorConfigFile =
            serde_yaml_ng::from_str(VC_WITHOUT_COMMITTEE_COUNT).unwrap();
        assert_eq!(file.config.attestation_committee_count, None);
    }

    #[test]
    fn cli_overrides_file_value() {
        let file: ValidatorConfigFile = serde_yaml_ng::from_str(VC_WITH_COMMITTEE_COUNT).unwrap();
        let cli_override: Option<u64> = Some(5);
        let resolved = cli_override
            .or(file.config.attestation_committee_count)
            .unwrap_or(1);
        assert_eq!(resolved, 5);
    }

    #[test]
    fn falls_back_to_file_when_cli_absent() {
        let file: ValidatorConfigFile = serde_yaml_ng::from_str(VC_WITH_COMMITTEE_COUNT).unwrap();
        let cli_override: Option<u64> = None;
        let resolved = cli_override
            .or(file.config.attestation_committee_count)
            .unwrap_or(1);
        assert_eq!(resolved, 2);
    }

    #[test]
    fn falls_back_to_default_when_neither_set() {
        let file: ValidatorConfigFile =
            serde_yaml_ng::from_str(VC_WITHOUT_COMMITTEE_COUNT).unwrap();
        let cli_override: Option<u64> = None;
        let resolved = cli_override
            .or(file.config.attestation_committee_count)
            .unwrap_or(1);
        assert_eq!(resolved, 1);
    }

    /// Slot of the anchor seeded into the test DB. Any non-zero slot works: a
    /// genesis re-initialization always anchors at slot 0, so a non-zero head
    /// slot is what distinguishes "resumed from disk" from "started over".
    const SEEDED_HEAD_SLOT: u64 = 12;

    /// Loopback port 1 refuses connections immediately, so the checkpoint-sync
    /// path fails fast and deterministically without reaching the network.
    const UNREACHABLE_CHECKPOINT_URL: &str = "http://127.0.0.1:1";

    fn now_secs() -> u64 {
        SystemTime::UNIX_EPOCH
            .elapsed()
            .expect("already past the unix epoch")
            .as_secs()
    }

    /// A `genesis_time` placing the current slot exactly `gap` slots ahead of
    /// [`SEEDED_HEAD_SLOT`], so a test picks which side of
    /// [`MAX_RESUMABLE_DB_STATE_AGE`] the seeded DB lands on.
    ///
    /// `current_slot` is derived from the wall clock inside
    /// [`fetch_initial_state`], so `genesis_time` is the only knob and no clock
    /// injection is needed. Sub-second truncation here only ever *shortens* the
    /// elapsed time, and a whole slot of it would have to pass between this
    /// call and the read inside the function to shift the gap.
    fn genesis_time_for_gap(gap: u64) -> u64 {
        let seconds_per_slot = DEFAULT_MILLISECONDS_PER_SLOT / 1_000;
        now_secs() - (SEEDED_HEAD_SLOT + gap) * seconds_per_slot
    }

    /// Single-validator genesis config. The pubkeys are placeholders; none of
    /// the paths under test verify signatures.
    fn test_genesis(genesis_time: u64) -> GenesisConfig {
        GenesisConfig {
            genesis_time,
            milliseconds_per_slot: DEFAULT_MILLISECONDS_PER_SLOT,
            genesis_validators: vec![GenesisValidatorEntry {
                attestation_pubkey: [1u8; 52],
                proposal_pubkey: [2u8; 52],
            }],
        }
    }

    /// Write an anchor at [`SEEDED_HEAD_SLOT`] into `backend`, standing in for a
    /// previous run's persisted chain state.
    fn seed_db(backend: Arc<dyn StorageBackend>, genesis: &GenesisConfig) {
        let mut anchor = State::from_genesis(genesis.genesis_time, genesis.validators());
        anchor.slot = SEEDED_HEAD_SLOT;
        anchor.latest_block_header.slot = SEEDED_HEAD_SLOT;
        Store::from_anchor_state(backend, anchor, DEFAULT_MILLISECONDS_PER_SLOT);
    }

    #[tokio::test]
    async fn initializes_from_genesis_when_db_is_empty() {
        let genesis = test_genesis(now_secs());
        let backend = Arc::new(InMemoryBackend::default());

        let store = fetch_initial_state(&[], &genesis, backend).await.unwrap();

        assert_eq!(store.head_slot(), 0);
    }

    #[tokio::test]
    async fn resumes_from_fresh_db_without_checkpoint_url() {
        let genesis = test_genesis(genesis_time_for_gap(MAX_RESUMABLE_DB_STATE_AGE / 2));
        let backend = Arc::new(InMemoryBackend::default());
        seed_db(backend.clone(), &genesis);

        let store = fetch_initial_state(&[], &genesis, backend).await.unwrap();

        assert_eq!(store.head_slot(), SEEDED_HEAD_SLOT);
    }

    /// With no checkpoint URL to fall back to, resuming a stale DB beats
    /// clobbering it with a slot-0 genesis anchor: P2P forward-sync can close
    /// the gap, a genesis re-init cannot.
    #[tokio::test]
    async fn resumes_from_stale_db_without_checkpoint_url() {
        let genesis = test_genesis(genesis_time_for_gap(MAX_RESUMABLE_DB_STATE_AGE + 100));
        let backend = Arc::new(InMemoryBackend::default());
        seed_db(backend.clone(), &genesis);

        let store = fetch_initial_state(&[], &genesis, backend).await.unwrap();

        assert_eq!(store.head_slot(), SEEDED_HEAD_SLOT);
    }

    /// A DB inside the resume window wins over a checkpoint URL: the store
    /// comes back even though the URL is unreachable, so nothing was dialed.
    ///
    /// This and [`falls_through_to_checkpoint_sync_when_db_is_stale`] are what
    /// pin the [`MAX_RESUMABLE_DB_STATE_AGE`] comparison. The no-URL tests
    /// cannot: both of their branches return the same store, so inverting the
    /// threshold leaves them green. The gap is exactly the window bound here,
    /// so an off-by-one to `<` also fails this test.
    #[tokio::test(start_paused = true)]
    async fn resumes_from_fresh_db_with_checkpoint_url() {
        let genesis = test_genesis(genesis_time_for_gap(MAX_RESUMABLE_DB_STATE_AGE));
        let backend = Arc::new(InMemoryBackend::default());
        seed_db(backend.clone(), &genesis);

        let urls = [UNREACHABLE_CHECKPOINT_URL.to_string()];
        let store = fetch_initial_state(&urls, &genesis, backend).await.unwrap();

        assert_eq!(store.head_slot(), SEEDED_HEAD_SLOT);
    }

    /// Past the resume window a checkpoint URL takes over, so an unreachable
    /// one surfaces as a startup error rather than a silent stale resume.
    ///
    /// Paused time collapses the `CHECKPOINT_RETRY_BACKOFF` sleeps between
    /// attempts; the connection refusal itself is immediate.
    #[tokio::test(start_paused = true)]
    async fn falls_through_to_checkpoint_sync_when_db_is_stale() {
        let genesis = test_genesis(genesis_time_for_gap(MAX_RESUMABLE_DB_STATE_AGE + 1));
        let backend = Arc::new(InMemoryBackend::default());
        seed_db(backend.clone(), &genesis);

        let urls = [UNREACHABLE_CHECKPOINT_URL.to_string()];
        // `Store` is not `Debug`, so unwrap the error by pattern rather than
        // with `expect_err`.
        let Err(err) = fetch_initial_state(&urls, &genesis, backend).await else {
            panic!("unreachable checkpoint URL must abort startup");
        };

        assert!(
            matches!(err, checkpoint_sync::CheckpointSyncError::Http(_)),
            "expected a transport error, got {err:?}"
        );
    }

    /// A DB from another network aborts startup rather than being re-anchored:
    /// writing genesis on top would leave the foreign blocks in place, and
    /// slot-indexed reads would serve them to peers.
    #[tokio::test]
    async fn fails_when_db_genesis_time_differs() {
        let seeded_genesis = test_genesis(now_secs());
        let backend = Arc::new(InMemoryBackend::default());
        seed_db(backend.clone(), &seeded_genesis);

        let other_genesis = test_genesis(seeded_genesis.genesis_time + 1);
        // `Store` is not `Debug`, so unwrap the error by pattern.
        let Err(err) = fetch_initial_state(&[], &other_genesis, backend.clone()).await else {
            panic!("a foreign DB must not be silently re-anchored");
        };

        assert!(
            matches!(err, checkpoint_sync::CheckpointSyncError::Genesis(_)),
            "unexpected error: {err}"
        );
        // The foreign chain is left untouched, not overwritten with a new anchor.
        let store = Store::from_db_state(backend)
            .expect("original DB still loads")
            .expect("store exists");
        assert_eq!(store.head_slot(), SEEDED_HEAD_SLOT);
    }

    /// Same genesis time, different validator registry: the case the previous
    /// `genesis_time`-only check could not see.
    #[tokio::test]
    async fn fails_when_db_validator_set_differs() {
        let genesis_time = now_secs();
        let seeded_genesis = test_genesis(genesis_time);
        let backend = Arc::new(InMemoryBackend::default());
        seed_db(backend.clone(), &seeded_genesis);

        let mut other_genesis = test_genesis(genesis_time);
        other_genesis.genesis_validators[0].attestation_pubkey = [9u8; 52];
        let Err(err) = fetch_initial_state(&[], &other_genesis, backend).await else {
            panic!("a foreign validator set must not be silently re-anchored");
        };

        assert!(
            matches!(err, checkpoint_sync::CheckpointSyncError::Genesis(_)),
            "unexpected error: {err}"
        );
    }

    /// A lean node must refuse a beacon-tagged data directory outright rather
    /// than building lean rows on top of it: doing so would leave the beacon
    /// chain's blocks in place, still reachable through the slot-indexed reads
    /// that serve `BlocksByRange`, so peers would be served the wrong chain.
    #[tokio::test]
    async fn fails_when_db_holds_a_beacon_chain() {
        use ethlambda_types::beacon::config::Config;
        use ethlambda_types::beacon::containers::Checkpoint as BeaconCheckpoint;

        let backend = Arc::new(InMemoryBackend::default());
        // Non-zero root, the way the storage crate's own tests build a beacon
        // anchor: a zero root would trip `UnanchoredDirectory` before the
        // chain-tag check this test targets ever ran.
        let anchor = BeaconCheckpoint {
            epoch: 0,
            root: H256::from([1u8; 32]),
        };
        Store::init_beacon(
            backend.clone(),
            now_secs(),
            Config::mainnet(),
            anchor.root,
            Store::beacon_checkpoint_as_stored(anchor),
        );

        let genesis = test_genesis(now_secs());
        let Err(err) = fetch_initial_state(&[], &genesis, backend).await else {
            panic!("a beacon data directory must not be opened as lean");
        };

        assert!(
            matches!(
                err,
                checkpoint_sync::CheckpointSyncError::WrongChain {
                    expected: Chain::Lean,
                    found: Chain::Beacon,
                }
            ),
            "unexpected error: {err}"
        );
    }

    /// Beacon has no genesis-sync path: with nothing on disk and no URL, there
    /// is no anchor to start from and startup says so rather than parking a
    /// node at slot 0 claiming to follow mainnet.
    #[tokio::test]
    async fn beacon_without_a_db_or_a_url_aborts() {
        let backend = Arc::new(InMemoryBackend::default());

        // `Store` is not `Debug`, so unwrap the error by pattern rather than
        // with `expect_err`.
        let Err(err) = fetch_initial_beacon_state(&[], backend).await else {
            panic!("no anchor is available");
        };

        assert!(matches!(
            err,
            checkpoint_sync::CheckpointSyncError::BeaconGenesisSync
        ));
    }

    /// A lean directory is not a beacon one. Loading it would write beacon
    /// rows over a lean chain's tables, and the slot-indexed reads behind
    /// `BlocksByRange` would serve its blocks to beacon peers.
    #[tokio::test]
    async fn beacon_refuses_a_lean_data_directory() {
        let genesis = test_genesis(now_secs());
        let backend = Arc::new(InMemoryBackend::default());
        seed_db(backend.clone(), &genesis);

        let urls = [UNREACHABLE_CHECKPOINT_URL.to_string()];
        // `Store` is not `Debug`, so unwrap the error by pattern rather than
        // with `expect_err`.
        let Err(err) = fetch_initial_beacon_state(&urls, backend).await else {
            panic!("a lean directory is not resumable as beacon");
        };

        assert!(matches!(
            err,
            checkpoint_sync::CheckpointSyncError::WrongChain {
                expected: Chain::Beacon,
                found: Chain::Lean,
            }
        ));
    }

    /// A unique path under the OS temp dir, so parallel test runs cannot
    /// collide on the same file.
    fn temp_key_path(label: &str) -> std::path::PathBuf {
        let nanos = SystemTime::UNIX_EPOCH
            .elapsed()
            .expect("already past the unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("ethlambda-test-node-key-{label}-{nanos}.key"))
    }

    #[test]
    fn a_supplied_node_key_is_read_verbatim_and_stable_across_calls() {
        // A `PeerId` is a pure function of the key bytes (see
        // `ethlambda_p2p::derive_peer_ids`), so two calls returning the same
        // bytes for the same file is exactly what "the same PeerId across two
        // runs" comes down to, without pulling libp2p's key derivation into
        // this crate's tests.
        let path = temp_key_path("supplied");
        std::fs::write(&path, "01".repeat(32)).expect("temp key file writes");

        let first = resolve_node_key(Some(path.as_path())).expect("reads the supplied key");
        let second = resolve_node_key(Some(path.as_path())).expect("reads the supplied key");

        let _ = std::fs::remove_file(&path);
        assert_eq!(first, second);
    }

    #[test]
    fn a_missing_node_key_generates_a_valid_key_that_differs_from_a_supplied_one() {
        let path = temp_key_path("baseline");
        std::fs::write(&path, "01".repeat(32)).expect("temp key file writes");
        let supplied = resolve_node_key(Some(path.as_path())).expect("reads the supplied key");
        let _ = std::fs::remove_file(&path);

        let generated_a = resolve_node_key(None).expect("generates a key");
        let generated_b = resolve_node_key(None).expect("generates a key");

        // "Accepted": the bytes are a valid secp256k1 secret key, the same
        // check `build_swarm` performs before deriving the swarm identity.
        secp256k1::SecretKey::from_slice(&generated_a)
            .expect("generated key is a valid secp256k1 secret key");

        assert_ne!(generated_a, supplied);
        assert_ne!(generated_a, generated_b, "two generations must not collide");
    }

    /// Write `contents` to a scratch file and read it back as a bootnode list.
    fn read_bootnodes_from(label: &str, contents: &str) -> Vec<String> {
        let nanos = SystemTime::UNIX_EPOCH
            .elapsed()
            .expect("already past the unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("ethlambda-test-enrs-{label}-{nanos}.yaml"));
        std::fs::write(&path, contents).expect("temp bootnode file writes");
        let entries = read_bootnode_strings(&path).expect("bootnode file reads");
        let _ = std::fs::remove_file(&path);
        entries
    }

    /// The shapes `node` accepted before the two readers merged. A line parser
    /// alone would hand the quotes and brackets on to `parse_enrs`, which is
    /// why YAML is tried first.
    #[test]
    fn the_bootnode_reader_still_accepts_every_yaml_shape() {
        assert_eq!(
            read_bootnodes_from("block", "- enr:aaa\n- enr:bbb\n"),
            ["enr:aaa", "enr:bbb"]
        );
        assert_eq!(
            read_bootnodes_from("quoted", "- \"enr:aaa\"\n- 'enr:bbb'\n"),
            ["enr:aaa", "enr:bbb"]
        );
        assert_eq!(
            read_bootnodes_from("flow", "[\"enr:aaa\", \"enr:bbb\"]\n"),
            ["enr:aaa", "enr:bbb"]
        );
    }

    /// The shapes only `beacon`'s tolerant reader accepted. These are not YAML
    /// sequences, so they reach the line-oriented fallback.
    #[test]
    fn the_bootnode_reader_still_accepts_a_bare_or_commented_list() {
        assert_eq!(
            read_bootnodes_from("bare", "enr:aaa\nenr:bbb\n"),
            ["enr:aaa", "enr:bbb"]
        );
        assert_eq!(
            read_bootnodes_from("comments", "# peers\n- enr:aaa\n\n  # aside\nenr:bbb\n"),
            ["enr:aaa", "enr:bbb"]
        );
    }

    #[test]
    fn an_empty_bootnode_file_yields_no_entries() {
        assert!(read_bootnodes_from("empty", "").is_empty());
        assert!(read_bootnodes_from("blank", "\n\n  \n").is_empty());
    }

    #[test]
    fn an_unreadable_bootnode_file_is_an_error_but_an_absent_one_is_not() {
        // The flag is optional on both chains, so no flag is not an error;
        // what an absent list *means* is each chain's own decision, made in
        // `default_bootnodes`. A path that was supplied and cannot be read is
        // still a hard failure: the operator named a file, so a typo must not
        // look like "no peers".
        let absent: Option<&Path> = None;
        assert!(
            absent
                .map(read_bootnode_strings)
                .transpose()
                .expect("no flag is not an error")
                .is_none()
        );
        let missing = std::env::temp_dir().join("ethlambda-test-enrs-does-not-exist.yaml");
        assert!(read_bootnode_strings(&missing).is_err());
    }

    /// The two chains read the same absent flag in opposite directions, so an
    /// arm that starts answering like the other one is a silent peering change:
    /// mainnet with no seeds cannot bootstrap, and a lean node handed mainnet's
    /// ENRs dials peers that will reject it.
    #[test]
    fn an_absent_bootnode_flag_falls_back_per_chain() {
        let argv = [
            "ethlambda",
            "node",
            "--genesis",
            "config.yaml",
            "--validators",
            "validators.yaml",
            "--validator-config",
            "validator-config.yaml",
            "--hash-sig-keys-dir",
            "keys",
            "--node-id",
            "ethlambda_0",
        ];
        let Command::Node(node) = try_parse_from(argv).expect("`node` parses") else {
            panic!("`node` must resolve to the node sub-command");
        };
        assert!(default_bootnodes(&Options::from(node).network).is_empty());

        assert_eq!(
            default_bootnodes(&Network::Mainnet).len(),
            beacon::MAINNET_BOOTNODES.len()
        );
    }
}
