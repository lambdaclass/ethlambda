mod beacon;
mod benchmark;
mod checkpoint_sync;
mod cli;
mod command;
mod fd_limit;
mod network;
mod validator;
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
use ethlambda_engine::types::ClientVersionV1;
use ethlambda_engine::{EngineClient, JwtSecret};
use ethlambda_network_api::{
    InitBlockChain, InitP2P, ToBlockChainToP2PRef, ToP2PToBlockChainRef, ToRpcToP2PRef,
};
use ethlambda_p2p::{
    LeanWireConfig, P2P, PeerId, SwarmConfig, WireConfig, attestation_subscription_subnets,
    build_swarm, discovery::DiscoverySpawnConfig, parse_enrs,
};
use ethlambda_state_transition::beacon::fork_choice;
use ethlambda_types::primitives::{H256, HashTreeRoot as _};
use ethlambda_types::{
    aggregator::AggregatorController,
    beacon::config::Config,
    beacon::containers::{
        BeaconState, SignedBeaconBlock, altair, bellatrix, capella, deneb, electra, gloas, phase0,
    },
    beacon::fork::ForkName,
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
        Command::Validator(options) => {
            init_node_logging()?;
            validator::run(options)
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
    /// The chain actor, on both lean and mainnet: the beacon follower runs one
    /// too, so there is always exactly one to stop and join. `run_node`
    /// spawns and wires it before building this struct, which is what keeps
    /// this a plain `BlockChain` rather than an `Option` describing a state
    /// the node never reaches.
    blockchain: BlockChain,
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

/// What [`ChainSetup::chain`] hands `run_node` to spawn this chain's actor.
///
/// Lean carries validator keys and duty configuration because
/// [`BlockChain::spawn`] needs both; beacon carries its custody columns and
/// the data-availability enforcement flag, the two values
/// [`BlockChain::spawn_beacon`] needs beyond the store, the sync-status
/// controller and the event bus that `run_node` already owns outside this
/// struct.
enum ChainActor {
    /// The lean node's chain actor: its validator keys and duty configuration.
    Lean(HashMap<u64, ValidatorKeyPair>, BlockChainConfig),
    /// The beacon follower's chain actor. No validator keys and no validator
    /// duties, but it does need the columns this node samples, which
    /// `BlockChain::spawn_beacon` uses to decide when a fulu block has its
    /// data.
    Beacon {
        custody_columns: Vec<u64>,
        /// The execution client to validate payloads against, `None` when
        /// `--execution-endpoint` was not given.
        engine: Option<EngineClient>,
        safe_slots_to_import_optimistically: u64,
    },
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
    /// Backs the req/resp handlers on both chains. Both start from the
    /// checkpoint anchor `fetch_initial_state`/`fetch_initial_beacon_state`
    /// resumed from disk or checkpoint-synced, and both then have a
    /// `BlockChain` actor (`spawn`/`spawn_beacon`) driving it forward: lean
    /// through validator duties, mainnet as a duty-free follower running fork
    /// choice on imported blocks.
    store: Store,
    /// PeerId to node name, for logs. Empty on mainnet, which has no roster.
    node_names: HashMap<PeerId, String>,
    /// What to spawn this chain's actor with: lean's validator keys and duty
    /// configuration, or beacon's custody columns and data-availability flag.
    chain: ChainActor,
}

/// Boot the node, on whichever chain [`Options::network`] names.
///
/// One startup path, in the order it has to happen: validate the port, register
/// the metrics, say what is running, raise the file-descriptor limit, resolve
/// the node key, then the one `match` where the two chains differ, then the
/// swarm, the discv5 server and the HTTP server, then the chain actor, which are
/// the same either way. Both chains end up with a spawned, wired-up
/// `BlockChain`, so `wait_for_shutdown` stops and joins one on either network.
///
/// `Network::Lean` runs the full consensus node: a `BlockChain` actor with
/// validator duties, a RocksDB store, checkpoint sync and the `/lean/v0` API.
/// `Network::Mainnet` runs a beacon follower on whichever network `--network`
/// resolved to (mainnet by default): it derives that network's fork digest,
/// joins discv5, subscribes to the global gossip topics, resolves the
/// checkpoint anchor `fetch_initial_beacon_state` at startup, then hands the
/// resulting store to a `BlockChain` actor spawned with `spawn_beacon`, which
/// imports blocks through fork choice with no validator keys and no duties.
/// The `/lean/v0` API is served off the store on both chains, so one HTTP call
/// site serves both, but its endpoints still read metadata keys and state
/// variants a beacon store does not carry, so they do not yet answer for a
/// beacon directory; fixing that is its own change.
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
    ethlambda_p2p::metrics::init();
    ethlambda_state_transition::metrics::init();
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

    // Resolved once, here, above the bootnode fallback below that reads it:
    // `default_bootnodes` needs the loaded network's own bootnode list, and
    // loading a directory decodes a multi-megabyte genesis state, so this must
    // not run twice for one process. `network` is matched by reference so it
    // is still available, below, to be matched by value into `ChainSetup`.
    let network_source = match &network {
        Network::Lean(_) => None,
        Network::Mainnet { mainnet, .. } => {
            let spec = network::NetworkSpec::parse(&mainnet.network)?;
            Some(network::NetworkSource::resolve(&spec)?)
        }
    };

    // The `--bootnodes` file, read and parsed once. An absent flag is not an
    // empty list: `default_bootnodes` is what each chain falls back to.
    let bootnodes = parse_enrs(
        common
            .bootnodes
            .as_deref()
            .map(read_bootnode_strings)
            .transpose()?
            .unwrap_or_else(|| default_bootnodes(network_source.as_ref())),
    );

    // Shared, runtime-mutable aggregator flag, seeded from the CLI flag only
    // `node` takes: mainnet has no aggregation duty. Threaded into both the
    // blockchain actor, which reads it on every tick, and the API server, whose
    // admin endpoints can flip it at runtime.
    let aggregator = AggregatorController::new(match &network {
        Network::Lean(lean) => lean.is_aggregator,
        Network::Mainnet { .. } => false,
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
                chain: ChainActor::Lean(validator_keys, blockchain_config),
            }
        }
        // The Ethereum Beacon Chain follower: the wire plus a duty-free chain
        // actor (`ChainActor::Beacon`, filled in below) that imports blocks
        // through fork choice. Every network parameter is derived rather than
        // configured, from the resolved network's genesis values: the fork
        // digest depends on the epoch, which depends on genesis time. See
        // `crate::beacon`.
        Network::Mainnet { mainnet, execution } => {
            let source = network_source
                .expect("network_source is Some whenever network is Network::Mainnet");

            info!(
                network = %source.name(),
                bootnodes = ?common.bootnodes,
                gossipsub_port = common.gossipsub_port,
                http_address = %common.http_address,
                metrics_port = common.metrics_port,
                discovery_port = common.discovery.port,
                advertise_ip = ?common.discovery.advertise_ip,
                "Resolved network configuration"
            );

            // The node id is the discovery one, so what this node custodies is
            // what any peer computes for it from its ENR: `spawn_discovery`
            // derives its own copy from the same `node_p2p_key` bytes below, by
            // the same computation, so the two cannot disagree about this
            // node's identity.
            let node_id = beacon::beacon_node_id(&node_p2p_key)?;
            let params = beacon::wire_params(
                &source,
                node_id,
                common.node_key.is_some(),
                mainnet.custody_group_count,
            )?;

            // Cloned ahead of the move into `WireConfig::Beacon` below: the
            // chain actor needs its own copy to gate fulu import on, the same
            // columns the wire config uses to size custody group
            // advertisements and req/resp serving.
            let custody_columns = params.wire.custody_columns.clone();

            // Cloned ahead of the same move, for the ENR entry below: the
            // record has to advertise exactly the subnets the swarm subscribes
            // to, and both readings come from this one computation.
            let attestation_subnets: HashSet<u64> =
                params.wire.attestation_subnets.iter().copied().collect();

            // The anchored beacon store. `P2PServer` holds it for the lean
            // handlers, and the two beacon block handlers read it too: it is
            // what `beacon_blocks_by_{range,root}/2` are answered from.
            let store =
                fetch_initial_beacon_state(&clean_checkpoint_urls, backend.clone(), &source)
                    .await
                    .inspect_err(|err| error!(%err, "Failed to initialize state"))?;

            let engine = match &execution {
                None => {
                    info!(
                        "No execution client configured; beacon blocks import without \
                         payload validation"
                    );
                    None
                }
                Some(options) => {
                    let secret = JwtSecret::from_file(&options.jwt_secret)
                        .map_err(|err| eyre::eyre!("reading --execution-jwt-secret: {err}"))?;
                    let client = EngineClient::new(options.endpoint.clone(), secret)
                        .map_err(|err| eyre::eyre!("building the engine client: {err}"))?;
                    info!(endpoint = %options.endpoint, "Execution client configured");

                    let ours = ClientVersionV1 {
                        // `identification.md` reserves two-letter codes per
                        // client; none is assigned to ethlambda, and `XX` is
                        // what the document names for a client without one.
                        code: "XX".to_string(),
                        name: "ethlambda".to_string(),
                        version: version::CLIENT_VERSION.to_string(),
                        // `identification.md` types `commit` as DATA, 4 bytes,
                        // and geth decodes it into `hexutil.Bytes`, which
                        // rejects a bare hex string with "hex string without
                        // 0x prefix". So the prefix is not cosmetic: without
                        // it `engine_getClientVersionV1` comes back an RPC
                        // error and the handshake below never identifies
                        // anything. `get` rather than a slice or `take(8)`,
                        // since `VERGEN_GIT_SHA` is not guaranteed to be eight
                        // or more characters in every build configuration.
                        commit: format!(
                            "0x{}",
                            env!("VERGEN_GIT_SHA").get(..8).unwrap_or("00000000")
                        ),
                    };
                    // A handshake failure is not a reason to refuse to run: the
                    // execution client may simply be starting up, and every
                    // call that matters has its own retry ladder.
                    let _ = client
                        .handshake(&ours)
                        .await
                        .inspect_err(|err| warn!(%err, "Engine API handshake failed"));

                    Some(client)
                }
            };

            ChainSetup {
                wire: WireConfig::Beacon(Box::new(params.wire)),
                discovery: DiscoveryWireEntries {
                    // The backbone subnets this node's id selects, so the ENR's
                    // `attnets` names what the gossip subscription actually
                    // holds. Both come from `wire_params`' one computation
                    // rather than from two, which is what keeps a peer's
                    // reading of this record true of the node behind it.
                    subscription_subnets: attestation_subnets,
                    attestation_committee_count:
                        ethlambda_p2p::beacon::constants::ATTESTATION_SUBNET_COUNT,
                    fork_id: params.fork_id,
                    custody_group_count: Some(mainnet.custody_group_count),
                },
                store,
                node_names: HashMap::new(),
                // A beacon follower has no validator keys and no duties, but
                // it does import blocks through fork choice, so it gets the
                // `Beacon` chain actor below.
                chain: ChainActor::Beacon {
                    custody_columns,
                    engine,
                    safe_slots_to_import_optimistically: mainnet
                        .safe_slots_to_import_optimistically,
                },
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
        // The same number `discovery` above carries to the dial loop: on beacon
        // the connection limits are derived from it, so the swarm refuses what
        // the loop has stopped asking for.
        target_peers: common.discovery.target_peers,
        wire: setup.wire,
    })
    .wrap_err("failed to build swarm")?;

    // Captured before `built` is moved into the P2P actor; the RPC
    // `/lean/v0/node/identity` endpoint reports it.
    let local_peer_id = built.local_peer_id.to_string();

    // `P2P::spawn` starts the discv5 server from this and owns the resulting
    // handle.
    // Filled by the Beacon API's pool endpoint and the aggregator subnets, and
    // read by the aggregate endpoint and block production; unused on lean.
    let attestation_pool =
        ethlambda_state_transition::beacon::attestation_pool::SharedAttestationPool::default();
    let p2p = P2P::spawn(
        built,
        setup.store.clone(),
        setup.node_names,
        discovery,
        attestation_pool.clone(),
    )
    .await
    .wrap_err("failed to start discv5 discovery")?;

    let shutdown = CancellationToken::new();
    let rpc_shutdown = shutdown.clone();
    let rpc_store = setup.store.clone();
    let rpc_aggregator = aggregator.clone();
    let rpc_sync_status = sync_status.clone();
    let rpc_events = events.clone();
    let rpc_p2p = p2p.actor_ref().to_rpc_to_p2p_ref();
    // Block production builds its payloads with the same execution client the
    // chain actor validates them with.
    let rpc_engine = match &setup.chain {
        ChainActor::Beacon { engine, .. } => engine.clone(),
        ChainActor::Lean(..) => None,
    };

    // Which HTTP surface this node serves follows from the store's own chain
    // tag rather than from the sub-command, so the two can never disagree.
    // A beacon node served `/lean/v0` until now, off a store those handlers
    // cannot read: they reach for lean state variants and metadata keys a
    // beacon directory never carries, so calling one panicked that request.
    let serves_beacon_api = setup.store.chain() == ethlambda_storage::Chain::Beacon;

    let http = tokio::spawn(async move {
        let served = if serves_beacon_api {
            ethlambda_rpc::start_beacon_rpc_server(
                rpc_config,
                rpc_store,
                rpc_sync_status,
                ethlambda_rpc::BeaconApiHandles {
                    p2p: rpc_p2p,
                    attestation_pool: attestation_pool.clone(),
                    engine: rpc_engine,
                },
                local_peer_id,
                rpc_shutdown,
            )
            .await
        } else {
            ethlambda_rpc::start_rpc_server(
                rpc_config,
                rpc_store,
                rpc_aggregator,
                rpc_sync_status,
                local_peer_id,
                rpc_events,
                rpc_shutdown,
            )
            .await
        };
        let _ = served.inspect_err(|err| error!(%err, "RPC server failed"));
    });

    let blockchain = match setup.chain {
        ChainActor::Lean(validator_keys, config) => {
            BlockChain::spawn(setup.store, validator_keys, config, events)
        }
        ChainActor::Beacon {
            custody_columns,
            engine,
            safe_slots_to_import_optimistically,
        } => {
            check_custody_set(&custody_columns)?;
            BlockChain::spawn_beacon(
                setup.store,
                sync_status,
                events,
                custody_columns,
                engine,
                safe_slots_to_import_optimistically,
            )
        }
    };

    let p2p_ref = p2p.actor_ref();
    let p2p_to_block_chain = p2p_ref.to_block_chain_to_p2p_ref();

    // Wire actors together via protocol refs
    blockchain
        .actor_ref()
        .recipient::<InitP2P>()
        .send(InitP2P {
            p2p: p2p_to_block_chain,
        })
        .inspect_err(|err| error!(%err, "Failed to send InitP2P — actors not wired"))?;

    p2p_ref
        .recipient::<InitBlockChain>()
        .send(InitBlockChain {
            blockchain: blockchain.actor_ref().to_p2p_to_block_chain_ref(),
        })
        .inspect_err(|err| error!(%err, "Failed to send InitBlockChain — actors not wired"))?;

    wait_for_shutdown(RunningNode {
        p2p,
        blockchain,
        http,
        shutdown,
    })
    .await;
    Ok(())
}

/// Reject a beacon node with no custody set before it spawns.
///
/// `data_availability_for` used to refuse this per block. It cannot any more:
/// the replay benchmark is a legitimate caller with an empty set, and the
/// actor cannot tell the two apart. A node can, here, once, at startup.
fn check_custody_set(custody_columns: &[u64]) -> eyre::Result<()> {
    eyre::ensure!(
        !custody_columns.is_empty(),
        "beacon node computed an empty custody set; it would treat every fulu \
         block as available without checking a column"
    );
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

    let blockchain_ref = node.blockchain.actor_ref().clone();
    let p2p_ref = node.p2p.actor_ref().clone();

    blockchain_ref.context().stop();
    p2p_ref.context().stop();
    node.shutdown.cancel();

    blockchain_ref.join().await;
    p2p_ref.join().await;
    let _ = node.http.await;

    info!("Shutdown complete");
}

/// The ENRs to start from when `--bootnodes` was not given.
///
/// A resolved network (built-in mainnet, or a loaded directory) publishes its
/// own bootnode list, so an absent flag means "use it". A lean network's ENRs
/// are per-deployment, so there is nothing to default to and an absent flag
/// means this node reaches peers only through discv5. That case warns, because
/// a node that then finds nobody is islanded and otherwise looks healthy.
fn default_bootnodes(source: Option<&network::NetworkSource>) -> Vec<String> {
    match source {
        None => {
            warn!(
                "No --bootnodes file supplied: starting with no bootnodes. This node can \
                 only find peers via discv5."
            );
            Vec::new()
        }
        Some(source) => source.bootnodes(),
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
    Ok(parse_bootnode_strings(&contents))
}

/// [`read_bootnode_strings`] without the file: also what a built-in network's
/// embedded `bootstrap_nodes.yaml` is read through, so a file on disk and a
/// file in the binary cannot be parsed two different ways.
fn parse_bootnode_strings(contents: &str) -> Vec<String> {
    if let Ok(entries) = serde_yaml_ng::from_str::<Vec<String>>(contents) {
        return entries;
    }

    contents
        .lines()
        .map(|line| line.trim().trim_start_matches("- ").trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.to_string())
        .collect()
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
/// The warning below is about `PeerId`/ENR churn, which costs a lean node its
/// place in every peer's scoring and in any ENR its neighbours cached.
/// `beacon` has no validator identity to protect, but it is not exempt
/// either: its custody columns are a function of this same node id, so an
/// unstable identity there means a different custody set on every restart.
/// `beacon::wire_params` carries its own, more specific warning about that;
/// see it for why `beacon` needs a second one.
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
    'resume: {
        if let Some(mut store) = Store::from_db_state(backend.clone())? {
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

            // Justified and finalized must both have a persisted state before
            // anything else is trusted: `repair_head` below assumes it, and a
            // directory that fails this check needs a fresh anchor, not a
            // storage-layer repair (see `Store::verify_anchor_states`'s doc).
            // Treated exactly like a stale DB below: fall back to checkpoint
            // sync if a URL is configured (`break 'resume` does that, the same
            // way falling out of this `match` without returning does further
            // down), otherwise fail naming the remedy.
            let state = match store.verify_anchor_states() {
                Ok(state) => state,
                Err(err @ ethlambda_storage::Error::AnchorStateLost { checkpoint }) => {
                    if checkpoint_urls.is_empty() {
                        error!(?checkpoint, %err, "Anchor checkpoint's state is missing");
                        return Err(err.into());
                    }
                    warn!(
                        ?checkpoint,
                        "Anchor checkpoint's state is missing; checkpoint sync"
                    );
                    break 'resume;
                }
                Err(err) => return Err(err.into()),
            };

            genesis.verify_state(&state).inspect_err(|err| {
                error!(
                    %err,
                    db_genesis_time = state.genesis_time(),
                    expected_genesis_time = genesis.genesis_time,
                    expected_validators = genesis.genesis_validators.len(),
                    "Persisted DB belongs to a different network; refusing to reuse this data directory"
                )
            })?;

            // The only mutation on this path, and only reached once both
            // checks above have passed; see `Store::from_db_state`'s doc.
            // `repair_head` can raise the same `AnchorStateLost` its own doc
            // lists as one of its three outcomes (the walk reaching at or
            // below finalized), so it gets the same fallback rather than a
            // bare `?`: a node with a checkpoint-sync URL configured should
            // resync, not abort, in exactly the situation this repair exists
            // for.
            match store.repair_head() {
                Ok(()) => {}
                Err(err @ ethlambda_storage::Error::AnchorStateLost { checkpoint }) => {
                    if checkpoint_urls.is_empty() {
                        error!(?checkpoint, %err, "Anchor checkpoint's state is missing");
                        return Err(err.into());
                    }
                    warn!(
                        ?checkpoint,
                        "Anchor checkpoint's state is missing; checkpoint sync"
                    );
                    break 'resume;
                }
                Err(err) => return Err(err.into()),
            }

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
            // No checkpoint URL was configured, so just run the node
            // against the data directory it was given: that is the setup
            // asked for, and there is no anchor to switch to. The warning
            // is the point of this arm, since the DB is known to be stale
            // and range sync may not be able to close a gap this large:
            // peers prune block signatures past `SIGNATURE_PRUNING_RANGE`,
            // so beyond that horizon they cannot serve the history the
            // node is missing.
            if checkpoint_urls.is_empty() {
                warn!(head_slot, current_slot, gap, "DB is stale; resuming anyway");
                return Ok(store);
            }
            warn!(head_slot, current_slot, gap, "DB is stale; checkpoint sync");
        }
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

/// Name the first configuration field that disagrees with the persisted one.
///
/// A changed fork epoch leaves genesis time and the validators root untouched,
/// so `verify_state_genesis` cannot see it, while putting this node on a
/// different chain from its peers at that epoch. Comparing the whole struct
/// catches it, and naming the field is what makes the failure actionable:
/// Lighthouse reports the same situation as an SSZ decode error whose own
/// message admits it is guessing between a wrong network and a corrupt
/// database.
fn first_config_difference(persisted: &Config, supplied: &Config) -> Option<String> {
    macro_rules! compare {
        ($($field:ident),+ $(,)?) => {
            $(
                if persisted.$field != supplied.$field {
                    return Some(format!(
                        "{}: directory has {:?}, config file says {:?}",
                        stringify!($field), persisted.$field, supplied.$field
                    ));
                }
            )+
        };
    }

    // Every field of `Config`, named once, with no `..`: adding a field there
    // is a compile error here until it is triaged into `compare!` below or
    // bound to `_` with a comment saying why it is operator tuning rather
    // than chain identity. This binds nothing useful (`compare!` reads
    // `persisted`/`supplied` directly); it exists purely to force that
    // choice.
    let Config {
        // Identity. `preset_base` is compared below: `check_preset` and the
        // directory's preset byte already pin the compiled preset, and this
        // also pins the stored string, which `/eth/v1/config/spec` reports, to
        // the file's. `config_name` is only a label with no consensus effect,
        // so the caller warns about a changed one rather than refusing it:
        // renaming a devnet must not cost its nodes their data directories.
        preset_base: _,
        config_name: _,

        // Genesis construction: read only while building a genesis state
        // from Eth1 deposit history, never again once one exists. Not chain
        // identity for a directory that already has a state.
        min_genesis_active_validator_count: _,
        min_genesis_time: _,
        genesis_delay: _,
        // Comes from the genesis state, not the config file;
        // `verify_state_genesis` already covers it.
        genesis_time: _,

        // Fork scheduling: compared below. Changes which fork a block signs
        // under and when, so a mismatch here silently forks this node from
        // its peers.
        genesis_fork_version: _,
        altair_fork_version: _,
        altair_fork_epoch: _,
        bellatrix_fork_version: _,
        bellatrix_fork_epoch: _,
        capella_fork_version: _,
        capella_fork_epoch: _,
        deneb_fork_version: _,
        deneb_fork_epoch: _,
        electra_fork_version: _,
        electra_fork_epoch: _,
        fulu_fork_version: _,
        fulu_fork_epoch: _,
        gloas_fork_version: _,
        gloas_fork_epoch: _,

        // Time parameters: `seconds_per_slot`/`slot_duration_ms` (compared
        // below) move every slot boundary. The rest are operator-visible
        // timing preferences (reorg cutoffs, sync-message windows) that do
        // not change which block is valid.
        seconds_per_slot: _,
        slot_duration_ms: _,
        seconds_per_eth1_block: _,
        // Compared below: bounds how many validators may enter the
        // exit/activation queue and when a proposer/exiting validator is
        // eligible, both state-transition rules.
        min_validator_withdrawability_delay: _,
        shard_committee_period: _,
        eth1_follow_distance: _,
        attestation_due_bps: _,
        aggregate_due_bps: _,
        proposer_reorg_cutoff_bps: _,
        sync_message_due_bps: _,
        contribution_due_bps: _,
        attestation_due_bps_gloas: _,
        aggregate_due_bps_gloas: _,
        sync_message_due_bps_gloas: _,
        contribution_due_bps_gloas: _,
        payload_due_bps: _,
        payload_attestation_due_bps: _,
        // Compared below, alongside `min_validator_withdrawability_delay`:
        // the builder-registry counterpart, also a state-transition rule.
        min_builder_withdrawability_delay: _,

        // Validator cycle: compared below. Churn and inactivity-leak
        // parameters change which exits, activations and inactivity scores a
        // block may legally carry.
        inactivity_score_bias: _,
        inactivity_score_recovery_rate: _,
        ejection_balance: _,
        min_per_epoch_churn_limit: _,
        churn_limit_quotient: _,
        max_per_epoch_activation_churn_limit: _,
        min_per_epoch_churn_limit_electra: _,
        max_per_epoch_activation_exit_churn_limit: _,
        churn_limit_quotient_gloas: _,
        max_per_epoch_activation_churn_limit_gloas: _,

        // Fork choice: weighting/timing knobs a node applies to its own view
        // of the chain. They change which head a node *prefers*, not which
        // block is valid, so two nodes running different values still agree
        // on validity.
        proposer_score_boost: _,
        reorg_head_weight_threshold: _,
        reorg_parent_weight_threshold: _,
        reorg_max_epochs_since_finalization: _,

        // Transition (bellatrix): mainnet crossed this in 2022 and every
        // shipped network leaves it at its default; not worth chain-identity
        // treatment for the same reason the fork-choice group above is not.
        terminal_total_difficulty: _,
        terminal_block_hash: _,
        terminal_block_hash_activation_epoch: _,

        // Blob limits: compared below. Bound how many blobs a block may
        // legally carry.
        max_blobs_per_block_deneb: _,
        max_blobs_per_block_electra: _,
        blob_schedule: _,

        // Networking: describe the wire, not the state transition. A
        // config.yaml carries them only so `/eth/v1/config/spec` can echo
        // them back; nothing here changes which block is valid.
        attestation_propagation_slot_range: _,
        attestation_subnet_count: _,
        attestation_subnet_extra_bits: _,
        blob_sidecar_subnet_count: _,
        blob_sidecar_subnet_count_electra: _,
        data_column_sidecar_subnet_count: _,
        epochs_per_subnet_subscription: _,
        max_payload_size: _,
        max_request_blocks: _,
        max_request_blocks_deneb: _,
        max_request_payloads: _,
        maximum_gossip_clock_disparity: _,
        message_domain_invalid_snappy: _,
        message_domain_valid_snappy: _,
        min_epochs_for_blob_sidecars_requests: _,
        min_epochs_for_data_column_sidecars_requests: _,
        subnets_per_node: _,

        // Deposit contract: compared below. Never read by the state
        // transition itself (a deposit is processed from the block, not the
        // contract), but kept as a network fingerprint: two networks sharing
        // every consensus parameter while watching different Eth1 contracts
        // are still different networks.
        deposit_chain_id: _,
        deposit_network_id: _,
        deposit_contract_address: _,

        // PeerDAS custody: describes what this node samples/custodies, an
        // operator/wire choice, not a state-transition rule.
        balance_per_additional_custody_group: _,
        custody_requirement: _,
        number_of_custody_groups: _,
        samples_per_slot: _,
        validator_custody_requirement: _,

        // Compared below: electra's Gwei-denominated consolidation churn
        // limit, alongside the other churn fields above.
        consolidation_churn_limit_quotient: _,

        // Networking (added after an incomplete initial key list): the same
        // wire-description reasoning as the networking group above.
        attestation_subnet_prefix_bits: _,
        max_request_blob_sidecars: _,
        max_request_blob_sidecars_electra: _,
        max_request_data_column_sidecars: _,
        min_epochs_for_block_requests: _,
    } = persisted;

    compare!(
        preset_base,
        genesis_fork_version,
        altair_fork_version,
        altair_fork_epoch,
        bellatrix_fork_version,
        bellatrix_fork_epoch,
        capella_fork_version,
        capella_fork_epoch,
        deneb_fork_version,
        deneb_fork_epoch,
        electra_fork_version,
        electra_fork_epoch,
        fulu_fork_version,
        fulu_fork_epoch,
        gloas_fork_version,
        gloas_fork_epoch,
        seconds_per_slot,
        slot_duration_ms,
        min_validator_withdrawability_delay,
        min_builder_withdrawability_delay,
        shard_committee_period,
        inactivity_score_bias,
        inactivity_score_recovery_rate,
        ejection_balance,
        min_per_epoch_churn_limit,
        churn_limit_quotient,
        max_per_epoch_activation_churn_limit,
        min_per_epoch_churn_limit_electra,
        max_per_epoch_activation_exit_churn_limit,
        churn_limit_quotient_gloas,
        max_per_epoch_activation_churn_limit_gloas,
        consolidation_churn_limit_quotient,
        max_blobs_per_block_deneb,
        max_blobs_per_block_electra,
        blob_schedule,
        deposit_chain_id,
        deposit_network_id,
        deposit_contract_address,
    );
    None
}

/// Refuses an anchor state in `fork` if this node cannot follow that fork yet,
/// currently gloas.
///
/// `fork_choice::get_forkchoice_store` accepts a gloas anchor, since fork choice
/// itself handles the fork. This node's wiring does not: nothing delivers
/// payload envelopes or payload attestations to the chain actor, and
/// `process_or_pend_block` refuses every gloas block, so a follower anchored
/// here would sit at its anchor forever, looking alive while importing
/// nothing. Refusing at startup reports the real reason instead. Checked ahead
/// of any store construction, on both anchor sources (a loaded network's
/// genesis state can schedule `GLOAS_FORK_EPOCH: 0`, and a checkpoint provider
/// can serve a gloas finalized state), so a rejected anchor writes nothing to
/// the data directory.
///
/// Keeps the refusal distinguishable from a peer serving a mismatched anchor
/// pair: reporting both as `AnchorPairingMismatch` would tell an operator to
/// look for a bad peer when the real answer is "wait for this build to support
/// the fork".
fn refuse_unfollowable_fork(fork: ForkName) -> Result<(), checkpoint_sync::CheckpointSyncError> {
    if fork.is_followed() {
        Ok(())
    } else {
        Err(checkpoint_sync::CheckpointSyncError::UnsupportedFork { fork })
    }
}

/// Fetch the initial state for a beacon node.
///
/// The beacon twin of [`fetch_initial_state`], with the same precedence: a
/// resumable directory wins over a download, and a download wins over a
/// directory that has fallen too far behind
/// ([`MAX_RESUMABLE_DB_STATE_AGE`]).
///
/// One row differs, and only partly. Lean initializes from its genesis config
/// when there is neither a DB nor a URL; beacon does the same for a
/// [`network::NetworkSource::Loaded`] network, since a freshly started devnet
/// has no checkpoint provider at slot 0 and this is the only way to join one.
/// A built-in network still aborts: this node imports nothing at startup, so
/// it would park at slot 0 while claiming to follow a chain that has been live
/// for years (and no built-in network carries a genesis state at all; see
/// [`network::built_in`]). See [`genesis_anchor_block`] for the block this
/// pairs with the genesis state to build that anchor.
///
/// Staleness reuses [`MAX_RESUMABLE_DB_STATE_AGE`], which is expressed in
/// slots: 90 minutes at beacon's 12-second slots against 30 at lean's four.
/// Worth revisiting when block import lands and the cost of a gap becomes
/// real.
async fn fetch_initial_beacon_state(
    checkpoint_urls: &[String],
    backend: Arc<dyn StorageBackend>,
    source: &network::NetworkSource,
) -> Result<Store, checkpoint_sync::CheckpointSyncError> {
    let config = source.config().clone();
    let genesis = source.genesis();

    'resume: {
        if let Some(mut store) = Store::from_db_state(backend.clone())? {
            if store.chain() != Chain::Beacon {
                return Err(checkpoint_sync::CheckpointSyncError::WrongChain {
                    expected: Chain::Beacon,
                    found: store.chain(),
                });
            }

            // Justified and finalized must both have a persisted state before
            // anything else is trusted: `repair_head` below assumes it, and a
            // directory that fails this check needs a fresh anchor, not a
            // storage-layer repair (see `Store::verify_anchor_states`'s doc).
            // Treated exactly like a stale DB below: fall back to checkpoint
            // sync if a URL is configured (`break 'resume` does that, the same
            // way falling out of this `match` without returning does further
            // down), otherwise fail naming the remedy.
            let state = match store.verify_anchor_states() {
                Ok(state) => state,
                Err(err @ ethlambda_storage::Error::AnchorStateLost { checkpoint }) => {
                    if checkpoint_urls.is_empty() {
                        error!(?checkpoint, %err, "Anchor checkpoint's state is missing");
                        return Err(err.into());
                    }
                    warn!(
                        ?checkpoint,
                        "Anchor checkpoint's state is missing; checkpoint sync"
                    );
                    break 'resume;
                }
                Err(err) => return Err(err.into()),
            };

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

            let persisted = store.config();
            if let Some(difference) = first_config_difference(&persisted, &config) {
                error!(%difference, "Persisted config disagrees with the network config");
                return Err(checkpoint_sync::CheckpointSyncError::ConfigChanged { difference });
            }
            // Not a chain value, so not refused (see `first_config_difference`).
            // `Metadata["config"]` is never rewritten, so the stored name is
            // the one `/eth/v1/config/spec` goes on reporting.
            if persisted.config_name != config.config_name {
                warn!(
                    stored = %persisted.config_name,
                    supplied = %config.config_name,
                    "CONFIG_NAME differs from the one this data directory was initialized with; \
                     resuming, and reporting the stored name"
                );
            }

            // The only mutation on this path, and only reached once both
            // checks above have passed; see `Store::from_db_state`'s doc.
            // Also what makes `beacon_head`'s `.expect` below safe: a
            // directory whose head had no state at all would have failed
            // `verify_anchor_states` above instead of reaching here (see
            // "A head with no block at all" on `repair_head`'s doc), so
            // this call always leaves the head naming a real block, once it
            // does not fall through below.
            //
            // `repair_head` can raise the same `AnchorStateLost` its own doc
            // lists as one of its three outcomes (the walk reaching at or
            // below finalized), so it gets the same fallback rather than a
            // bare `?`: a node with a checkpoint-sync URL configured should
            // resync, not abort, in exactly the situation this repair exists
            // for.
            match store.repair_head() {
                Ok(()) => {}
                Err(err @ ethlambda_storage::Error::AnchorStateLost { checkpoint }) => {
                    if checkpoint_urls.is_empty() {
                        error!(?checkpoint, %err, "Anchor checkpoint's state is missing");
                        return Err(err.into());
                    }
                    warn!(
                        ?checkpoint,
                        "Anchor checkpoint's state is missing; checkpoint sync"
                    );
                    break 'resume;
                }
                Err(err) => return Err(err.into()),
            }

            let now = SystemTime::UNIX_EPOCH
                .elapsed()
                .expect("already past the unix epoch")
                .as_secs();
            let current_slot = now.saturating_sub(genesis.genesis_time) / config.seconds_per_slot;
            let (head_slot, _) = store
                .beacon_head()
                .expect("repair_head leaves the head naming a real block");
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
    }

    // A loaded network carries its own genesis state, which is a legitimate
    // anchor: a fresh devnet has no checkpoint provider at slot 0, so this is
    // the only way to join one. A built-in network still refuses, because
    // every one has been live for years and this follower would sit at slot 0
    // claiming to follow a live chain.
    if checkpoint_urls.is_empty() {
        let network::NetworkSource::Loaded(loaded) = source else {
            return Err(checkpoint_sync::CheckpointSyncError::BeaconGenesisSync);
        };

        let state = loaded.genesis_state.as_ref().clone();
        refuse_unfollowable_fork(state.fork_name())
            .inspect_err(|err| error!(%err, "Cannot anchor at this network's genesis state"))?;
        let block = genesis_anchor_block(&state);
        info!(
            genesis_time = genesis.genesis_time,
            fork = state.fork_name().as_str(),
            "No checkpoint URL and no resumable directory: anchoring at this network's genesis"
        );
        return fork_choice::get_forkchoice_store(backend, state, block, &config)
            .inspect_err(|err| error!(%err, "Failed to initialize store from the genesis state"))
            .map_err(|_| checkpoint_sync::CheckpointSyncError::AnchorPairingMismatch);
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
        validators = state.validator_count(),
        finalized_epoch = state.finalized_checkpoint().epoch,
        anchor_block_slot = block.slot(),
        "Beacon checkpoint sync complete"
    );

    refuse_unfollowable_fork(state.fork_name())
        .inspect_err(|err| error!(%err, "Cannot anchor at the checkpoint provider's state"))?;
    fork_choice::get_forkchoice_store(backend, state, block, &config)
        .inspect_err(|err| error!(%err, "Failed to initialize store from anchor state and block"))
        .map_err(|_| checkpoint_sync::CheckpointSyncError::AnchorPairingMismatch)
}

/// The block the specification pairs with a genesis anchor state.
///
/// `get_forkchoice_store` wants the block that produced the anchor state. At
/// genesis no such block exists, so the specification substitutes an empty
/// block carrying the genesis state root. The state's own
/// `latest_block_header` already describes that block with a zeroed state
/// root, so filling the root in and rebuilding the body is the whole
/// construction.
///
/// The body has to be rebuilt rather than read off the state, because the
/// state does not carry one: `latest_block_header.body_root` is only ever a
/// merkle root, never the body itself. `state.fork_name()`'s empty body is
/// what that root already commits to (see `BeaconBlockBody::empty` on each
/// fork whose body cannot derive `Default`, in `ethlambda-types`), so
/// rebuilding it here and letting `get_forkchoice_store` check the header
/// hash is what proves this reconstruction matches what the state actually
/// describes, rather than assuming it.
fn genesis_anchor_block(state: &BeaconState) -> SignedBeaconBlock {
    let header = state.latest_block_header();
    let slot = header.slot;
    let proposer_index = header.proposer_index;
    let parent_root = header.parent_root;
    let state_root = state.hash_tree_root();

    match state.fork_name() {
        ForkName::Phase0 => SignedBeaconBlock::Phase0(phase0::SignedBeaconBlock {
            message: phase0::BeaconBlock {
                slot,
                proposer_index,
                parent_root,
                state_root,
                body: phase0::BeaconBlockBody::default(),
            },
            signature: Default::default(),
        }),
        ForkName::Altair => SignedBeaconBlock::Altair(altair::SignedBeaconBlock {
            message: altair::BeaconBlock {
                slot,
                proposer_index,
                parent_root,
                state_root,
                body: altair::BeaconBlockBody::default(),
            },
            signature: Default::default(),
        }),
        ForkName::Bellatrix => SignedBeaconBlock::Bellatrix(bellatrix::SignedBeaconBlock {
            message: bellatrix::BeaconBlock {
                slot,
                proposer_index,
                parent_root,
                state_root,
                body: bellatrix::BeaconBlockBody::empty(),
            },
            signature: Default::default(),
        }),
        ForkName::Capella => SignedBeaconBlock::Capella(capella::SignedBeaconBlock {
            message: capella::BeaconBlock {
                slot,
                proposer_index,
                parent_root,
                state_root,
                body: capella::BeaconBlockBody::empty(),
            },
            signature: Default::default(),
        }),
        ForkName::Deneb => SignedBeaconBlock::Deneb(deneb::SignedBeaconBlock {
            message: deneb::BeaconBlock {
                slot,
                proposer_index,
                parent_root,
                state_root,
                body: deneb::BeaconBlockBody::empty(),
            },
            signature: Default::default(),
        }),
        ForkName::Electra => SignedBeaconBlock::Electra(electra::SignedBeaconBlock {
            message: electra::BeaconBlock {
                slot,
                proposer_index,
                parent_root,
                state_root,
                body: electra::BeaconBlockBody::empty(),
            },
            signature: Default::default(),
        }),
        // Fulu's block is byte-for-byte electra's; see `SignedBeaconBlock::Fulu`'s
        // own doc comment for why it wraps `electra::SignedBeaconBlock` instead
        // of a fork-specific type.
        ForkName::Fulu => SignedBeaconBlock::Fulu(electra::SignedBeaconBlock {
            message: electra::BeaconBlock {
                slot,
                proposer_index,
                parent_root,
                state_root,
                body: electra::BeaconBlockBody::empty(),
            },
            signature: Default::default(),
        }),
        ForkName::Gloas => SignedBeaconBlock::Gloas(gloas::SignedBeaconBlock {
            message: gloas::BeaconBlock {
                slot,
                proposer_index,
                parent_root,
                state_root,
                body: gloas::BeaconBlockBody::empty(),
            },
            signature: Default::default(),
        }),
        // Never reached: this is only called on a network's own genesis
        // state, and every `NetworkSource` decodes a beacon fork there
        // (`NetworkDir::load` resolves the fork from `Config::fork_at_epoch`,
        // which only ever names a `ForkName::ALL` member).
        ForkName::Lean => {
            unreachable!("a beacon network's genesis state is never ForkName::Lean")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::{Command, try_parse_from};
    use ethlambda_storage::ForkCheckpoints;
    use ethlambda_storage::backend::InMemoryBackend;
    use ethlambda_types::block::{Block, BlockBody, MultiMessageAggregate, SignedBlock};
    use ethlambda_types::checkpoint::Checkpoint;
    use ethlambda_types::constants::DEFAULT_MILLISECONDS_PER_SLOT;
    use ethlambda_types::genesis::GenesisValidatorEntry;

    /// Fork choice accepts a gloas anchor, so the node has to be the one to
    /// refuse it: nothing here delivers the payload envelopes a gloas chain
    /// needs. Every fork this node does follow must still be let through.
    #[test]
    fn startup_refuses_a_gloas_anchor_and_only_a_gloas_anchor() {
        assert!(matches!(
            refuse_unfollowable_fork(ForkName::Gloas),
            Err(checkpoint_sync::CheckpointSyncError::UnsupportedFork {
                fork: ForkName::Gloas
            })
        ));
        for fork in ForkName::ALL {
            if fork != ForkName::Gloas {
                assert!(
                    refuse_unfollowable_fork(fork).is_ok(),
                    "{fork} must stay followable"
                );
            }
        }
    }

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

    #[test]
    fn a_beacon_node_refuses_an_empty_custody_set() {
        // The per-block fence moved here. A node that reached the actor with
        // no custody set would treat every fulu block as available without
        // ever checking a column.
        let err = check_custody_set(&[]).expect_err("an empty set must not start a node");
        assert!(
            err.to_string().contains("custody"),
            "the error names what is wrong: {err}"
        );

        check_custody_set(&[0, 1, 2]).expect("a real custody set starts a node");
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

    /// A minimal signed lean block, the same shape the storage crate's own
    /// tests use: empty body, no proof content, only the fields the diff
    /// chain and the fork-choice walk actually read.
    fn signed_block(slot: u64, proposer_index: u64, parent_root: H256) -> SignedBlock {
        SignedBlock {
            message: Block {
                slot,
                proposer_index,
                parent_root,
                state_root: H256::ZERO,
                body: BlockBody::default(),
            },
            proof: MultiMessageAggregate::default(),
        }
    }

    /// A child of `parent` at `slot`, inheriting its `config` and
    /// `validators` rather than building an unrelated one:
    /// `StateDiff` omits both, trusting they never change from parent to
    /// child.
    fn child_state(parent: &State, slot: u64, parent_root: H256) -> State {
        let mut hbh = parent.historical_block_hashes.to_vec();
        hbh.push(parent_root);
        let mut child = parent.clone();
        child.slot = slot;
        child.latest_block_header = ethlambda_types::block::BlockHeader {
            slot,
            proposer_index: 0,
            parent_root,
            state_root: H256::ZERO,
            body_root: H256::ZERO,
        };
        child.historical_block_hashes = hbh.try_into().expect("within limit");
        child
    }

    /// `repair_head` itself can raise `AnchorStateLost` (its own doc lists
    /// the walk reaching at or below finalized as one of its three
    /// outcomes), a separate path from the `verify_anchor_states` pre-check
    /// covered by [`falls_through_to_checkpoint_sync_when_db_is_stale`] and
    /// its siblings. This pins that it gets the same fallback rather than a
    /// bare `?`: an unreachable checkpoint URL surfaces as a transport
    /// error, proving checkpoint sync was actually attempted, not skipped in
    /// favor of aborting.
    #[tokio::test(start_paused = true)]
    async fn falls_through_to_checkpoint_sync_when_repair_head_loses_the_anchor() {
        let genesis = test_genesis(now_secs());
        let backend = Arc::new(InMemoryBackend::default());

        let mut anchor = State::from_genesis(genesis.genesis_time, genesis.validators());
        anchor.slot = SEEDED_HEAD_SLOT;
        anchor.latest_block_header.slot = SEEDED_HEAD_SLOT;
        let mut store = Store::from_anchor_state(
            backend.clone(),
            anchor.clone(),
            DEFAULT_MILLISECONDS_PER_SLOT,
        );
        let r0 = store.head().expect("head root");

        // A real, state-backed block one slot ahead, made both the justified
        // and the finalized checkpoint: `verify_anchor_states` must pass for
        // the flow to reach `repair_head` at all.
        let finalized_slot = SEEDED_HEAD_SLOT + 1;
        let finalized_block = signed_block(finalized_slot, 0, r0);
        let r1 = finalized_block.message.hash_tree_root();
        store
            .insert_signed_block(r1, SignedBeaconBlock::Lean(finalized_block))
            .expect("insert finalized block");
        store
            .insert_state(
                r1,
                BeaconState::Lean(child_state(&anchor, finalized_slot, r0)),
            )
            .expect("insert finalized state");
        let finalized_checkpoint = Checkpoint {
            root: r1,
            slot: finalized_slot,
        };
        store
            .update_checkpoints(ForkCheckpoints::new(
                r1,
                Some(finalized_checkpoint),
                Some(finalized_checkpoint),
            ))
            .expect("advance justified and finalized");

        // A sibling of the finalized block, same slot and parent, distinguished
        // only by proposer index so its root differs, with no state ever
        // inserted for it. Its parent is the anchor, not `r1`, so
        // `repair_head`'s walk steps straight from here to the anchor's own
        // slot without ever reaching `r1`; see its doc's finalized-slot bound.
        let sibling_block = signed_block(finalized_slot, 1, r0);
        let sibling_root = sibling_block.message.hash_tree_root();
        store
            .insert_signed_block(sibling_root, SignedBeaconBlock::Lean(sibling_block))
            .expect("insert sibling block");
        store
            .update_checkpoints(ForkCheckpoints::head_only(sibling_root))
            .expect("move head to the stateless sibling");

        drop(store);

        let urls = [UNREACHABLE_CHECKPOINT_URL.to_string()];
        // `Store` is not `Debug`, so unwrap the error by pattern rather than
        // with `expect_err`.
        let Err(err) = fetch_initial_state(&urls, &genesis, backend).await else {
            panic!("an unreachable checkpoint URL must abort startup, not silently resume");
        };
        assert!(
            matches!(err, checkpoint_sync::CheckpointSyncError::Http(_)),
            "expected checkpoint sync to actually be attempted (a transport error), got {err:?}"
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
            0,
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

    /// Beacon has no genesis-sync path on the built-in network: with nothing
    /// on disk and no URL, there is no anchor to start from and startup says
    /// so rather than parking a node at slot 0 claiming to follow mainnet.
    #[tokio::test]
    async fn beacon_without_a_db_or_a_url_aborts() {
        let backend = Arc::new(InMemoryBackend::default());
        let source = network::NetworkSource::built_in_mainnet().unwrap();

        // `Store` is not `Debug`, so unwrap the error by pattern rather than
        // with `expect_err`.
        let Err(err) = fetch_initial_beacon_state(&[], backend, &source).await else {
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
        let source = network::NetworkSource::built_in_mainnet().unwrap();

        let urls = [UNREACHABLE_CHECKPOINT_URL.to_string()];
        // `Store` is not `Debug`, so unwrap the error by pattern rather than
        // with `expect_err`.
        let Err(err) = fetch_initial_beacon_state(&urls, backend, &source).await else {
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

    /// A fresh devnet has no checkpoint provider at slot 0, so a loaded
    /// network anchors at its own `genesis.ssz` instead of refusing.
    #[tokio::test]
    async fn a_loaded_network_anchors_at_genesis_without_a_checkpoint_url() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::copy(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/networks/devnet/config.yaml"),
            dir.path().join("config.yaml"),
        )
        .unwrap();
        let state = beacon::mainnet_genesis_state().unwrap();
        std::fs::write(dir.path().join("genesis.ssz"), state.to_ssz()).unwrap();

        let loaded = network::dir::NetworkDir::load(dir.path()).unwrap();
        let source = network::NetworkSource::Loaded(Box::new(loaded));
        let backend: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new());

        let store = fetch_initial_beacon_state(&[], backend, &source)
            .await
            .expect("a loaded network anchors at its own genesis");
        assert_eq!(store.chain(), Chain::Beacon);
        let (head_slot, _) = store
            .beacon_head()
            .expect("an anchored directory has a head");
        assert_eq!(head_slot, 0, "a genesis anchor is at slot 0");
    }

    /// A loaded network can schedule gloas at epoch 0, which makes its own
    /// genesis state a gloas one. Fork choice accepts that anchor, so startup
    /// has to be what refuses it, with the reason that names the fork, and
    /// before anything is written to the data directory.
    #[tokio::test]
    async fn a_gloas_genesis_is_refused_before_the_store_is_built() {
        use ethlambda_state_transition::beacon::config::Config;
        use ethlambda_state_transition::beacon::upgrade::upgrade_state;

        // Every fork from altair on scheduled at epoch 0, in the file and in
        // the config the genesis state is upgraded with.
        let scheduled = [
            ForkName::Altair,
            ForkName::Bellatrix,
            ForkName::Capella,
            ForkName::Deneb,
            ForkName::Electra,
            ForkName::Fulu,
            ForkName::Gloas,
        ];
        let fixture = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/networks/devnet/config.yaml"),
        )
        .unwrap();
        let config_text: String = fixture
            .lines()
            .map(|line| {
                match scheduled.iter().find(|fork| {
                    let key = format!("{}_FORK_EPOCH:", fork.as_str().to_uppercase());
                    line.starts_with(&key)
                }) {
                    Some(fork) => format!("{}_FORK_EPOCH: 0", fork.as_str().to_uppercase()),
                    None => line.to_string(),
                }
            })
            .collect::<Vec<_>>()
            .join("\n");

        let mut config = Config::mainnet();
        let mut state = beacon::mainnet_genesis_state().unwrap();
        for fork in scheduled {
            config = config.with_fork_epoch(fork, 0);
            state = upgrade_state(&state, fork, &config).unwrap();
        }
        assert_eq!(state.fork_name(), ForkName::Gloas);

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config.yaml"), config_text).unwrap();
        std::fs::write(dir.path().join("genesis.ssz"), state.to_ssz()).unwrap();
        let loaded = network::dir::NetworkDir::load(dir.path()).unwrap();
        let source = network::NetworkSource::Loaded(Box::new(loaded));
        let backend: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new());

        // `Store` is not `Debug`, so take the error by pattern.
        let Err(err) = fetch_initial_beacon_state(&[], backend.clone(), &source).await else {
            panic!("a gloas genesis must not become an anchor");
        };
        assert!(
            matches!(
                err,
                checkpoint_sync::CheckpointSyncError::UnsupportedFork {
                    fork: ForkName::Gloas
                }
            ),
            "the refusal must name the fork: {err}"
        );
        assert!(
            Store::from_db_state(backend).unwrap().is_none(),
            "a refused anchor leaves the directory empty"
        );
    }

    /// A changed fork epoch leaves genesis time and the validators root
    /// untouched, so `verify_state_genesis` cannot see it, while putting this
    /// node on a different chain from its peers from that epoch on. Resuming
    /// must compare the persisted config too, and name the field that moved.
    #[tokio::test]
    async fn a_resume_with_an_edited_config_names_the_field_that_changed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::copy(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/networks/devnet/config.yaml"),
            dir.path().join("config.yaml"),
        )
        .unwrap();
        let state = beacon::mainnet_genesis_state().unwrap();
        std::fs::write(dir.path().join("genesis.ssz"), state.to_ssz()).unwrap();

        let loaded = network::dir::NetworkDir::load(dir.path()).unwrap();
        let source = network::NetworkSource::Loaded(Box::new(loaded));
        let backend: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new());

        // Anchor once, so the directory is resumable.
        fetch_initial_beacon_state(&[], backend.clone(), &source)
            .await
            .expect("first run anchors");

        // Now resume with one fork epoch moved. Genesis time and validators
        // root are untouched, so the existing check cannot see this.
        let mut edited = network::dir::NetworkDir::load(dir.path()).unwrap();
        edited.config.electra_fork_epoch += 1;
        let tampered = network::NetworkSource::Loaded(Box::new(edited));

        // `Store` is not `Debug`, so unwrap the error by pattern rather than
        // with `unwrap_err`.
        let Err(err) = fetch_initial_beacon_state(&[], backend, &tampered).await else {
            panic!("an edited config must not be silently resumed");
        };
        let message = format!("{err}");
        assert!(
            message.contains("electra_fork_epoch"),
            "the error should name the field that changed: {message}"
        );
    }

    /// `churn_limit_quotient` is one of the state-transition fields the
    /// original field list omitted entirely: a directory with a different
    /// churn quotient from its config file accepted a different set of
    /// exits/activations as valid on each side, silently. Representative of
    /// the whole group `first_config_difference` was missing.
    #[test]
    fn a_changed_churn_limit_quotient_is_now_caught() {
        let persisted = Config::mainnet();
        let mut supplied = Config::mainnet();
        supplied.churn_limit_quotient += 1;

        let difference = first_config_difference(&persisted, &supplied)
            .expect("a changed churn_limit_quotient must be caught");
        assert!(
            difference.contains("churn_limit_quotient"),
            "the error should name the field that changed: {difference}"
        );
    }

    /// A changed `PRESET_BASE` is refused, and the error shows both names as
    /// text. A changed `CONFIG_NAME` is a label with no consensus effect, so it
    /// resumes (the caller only warns), unless a chain value changed with it.
    #[test]
    fn a_changed_preset_name_is_caught_but_a_changed_config_name_is_not() {
        let persisted = Config::mainnet();

        let mut other_preset = Config::mainnet();
        other_preset.preset_base = "minimal".try_into().unwrap();
        let difference = first_config_difference(&persisted, &other_preset)
            .expect("a changed PRESET_BASE must be caught");
        assert_eq!(
            difference,
            r#"preset_base: directory has "mainnet", config file says "minimal""#
        );

        let mut renamed = Config::mainnet();
        renamed.config_name = "devnet-2".try_into().unwrap();
        assert_eq!(first_config_difference(&persisted, &renamed), None);

        renamed.altair_fork_epoch += 1;
        let difference = first_config_difference(&persisted, &renamed)
            .expect("a rename must not hide a changed chain value");
        assert!(
            difference.starts_with("altair_fork_epoch:"),
            "got {difference}"
        );
    }

    /// Every built-in network has been live for years, and this follower
    /// imports nothing at startup, so anchoring at genesis would park it at
    /// slot 0 while claiming to follow a live chain. That refusal is
    /// deliberate and must survive; no built-in network carries a genesis
    /// state to anchor at in the first place.
    #[tokio::test]
    async fn the_built_in_network_still_requires_a_checkpoint_url() {
        for built_in in network::BuiltInNetwork::ALL {
            let spec = network::NetworkSpec::BuiltIn(built_in);
            let source = network::NetworkSource::resolve(&spec).unwrap();
            let backend: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new());
            // `Store` is not `Debug`, so unwrap the error by pattern rather
            // than with `unwrap_err`.
            let Err(err) = fetch_initial_beacon_state(&[], backend, &source).await else {
                panic!("{} must not anchor at its own genesis", built_in.name());
            };
            assert!(
                format!("{err}").contains("checkpoint"),
                "{}: the error should point at --checkpoint-sync-url: {err}",
                built_in.name()
            );
        }
    }

    /// Pins the one invariant `get_forkchoice_store` actually checks: the
    /// anchor block's message must hash to the same root as the anchor
    /// state's own `latest_block_header`, once that header's placeholder
    /// zero `state_root` is filled in the same way `get_forkchoice_store`
    /// fills it.
    #[test]
    fn a_genesis_anchor_block_hashes_to_the_states_own_header() {
        let state = beacon::mainnet_genesis_state().unwrap();
        let block = genesis_anchor_block(&state);

        let mut header = state.latest_block_header().clone();
        header.state_root = state.hash_tree_root();

        assert_eq!(block.message_hash_tree_root(), header.hash_tree_root());
    }

    /// The same invariant, pinned at every fork: `BeaconBlockBody::empty()`
    /// (or, pre-bellatrix, `Default`) is only exercised above through
    /// mainnet's own genesis, which is phase0, so the four hand-written
    /// `empty()` impls (bellatrix, capella, deneb, electra; fulu reuses
    /// electra's block) had no coverage at all.
    ///
    /// Mainnet's genesis is the only real genesis state this binary carries,
    /// and it is phase0, so a later fork's state is manufactured by chaining
    /// the real `upgrade_state` functions. Those clone `latest_block_header`
    /// verbatim (an upgrade is not a block import), so the header inherited
    /// from genesis still names phase0's empty-body root; it is re-stamped
    /// to each new fork's own empty body below, exactly as a genesis
    /// generator targeting that fork directly would have to.
    ///
    /// Chains all the way through gloas: `upgrade_state` handles every fork
    /// from altair to gloas, so this loop exercises `genesis_anchor_block`'s
    /// gloas arm the same way it does every earlier fork's.
    #[test]
    fn a_genesis_anchor_block_hashes_to_the_states_own_header_at_every_fork() {
        let config = Config::mainnet();
        let mut state = beacon::mainnet_genesis_state().unwrap();

        for fork in ForkName::ALL {
            if fork != ForkName::Phase0 {
                state = ethlambda_state_transition::beacon::upgrade::upgrade_state(
                    &state, fork, &config,
                )
                .unwrap_or_else(|err| panic!("upgrade to {fork:?} failed: {err}"));
            }

            let empty_body_root = match fork {
                ForkName::Phase0 => phase0::BeaconBlockBody::default().hash_tree_root(),
                ForkName::Altair => altair::BeaconBlockBody::default().hash_tree_root(),
                ForkName::Bellatrix => bellatrix::BeaconBlockBody::empty().hash_tree_root(),
                ForkName::Capella => capella::BeaconBlockBody::empty().hash_tree_root(),
                ForkName::Deneb => deneb::BeaconBlockBody::empty().hash_tree_root(),
                ForkName::Electra | ForkName::Fulu => {
                    electra::BeaconBlockBody::empty().hash_tree_root()
                }
                ForkName::Gloas => gloas::BeaconBlockBody::empty().hash_tree_root(),
                ForkName::Lean => unreachable!("ForkName::ALL excludes Lean"),
            };
            state.latest_block_header_mut().body_root = empty_body_root;

            let block = genesis_anchor_block(&state);
            let mut header = state.latest_block_header().clone();
            header.state_root = state.hash_tree_root();

            assert_eq!(
                block.message_hash_tree_root(),
                header.hash_tree_root(),
                "invariant broke at fork {fork:?}"
            );
        }
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
        assert!(matches!(Options::from(node).network, Network::Lean(_)));
        assert!(default_bootnodes(None).is_empty());

        let mainnet_source = network::NetworkSource::built_in_mainnet().unwrap();
        let fallback = default_bootnodes(Some(&mainnet_source));
        assert!(!fallback.is_empty());
        assert_eq!(fallback, mainnet_source.bootnodes());
    }
}
