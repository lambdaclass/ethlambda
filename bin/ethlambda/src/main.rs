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
    collections::{BTreeMap, HashMap},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::SystemTime,
};
use tokio_util::sync::CancellationToken;

use command::Command;

use ethlambda_blockchain::MILLISECONDS_PER_SLOT;
use ethlambda_blockchain::block_builder::ProposerConfig;
use ethlambda_blockchain::key_manager::ValidatorKeyPair;
use ethlambda_crypto::signature::ValidatorSecretKey;
use ethlambda_network_api::{InitBlockChain, InitP2P, ToBlockChainToP2PRef, ToP2PToBlockChainRef};
use ethlambda_p2p::{
    Bootnode, P2P, PeerId, SwarmConfig, attestation_subscription_subnets, build_swarm,
    discovery::DiscoverySpawnConfig, parse_enrs,
};
use ethlambda_types::primitives::{H256, HashTreeRoot as _};
use ethlambda_types::{
    aggregator::AggregatorController,
    genesis::GenesisConfig,
    state::{State, ValidatorPubkeyBytes},
};
use eyre::WrapErr;
use serde::Deserialize;
use tracing::{error, info, warn};
use tracing_subscriber::{EnvFilter, Layer, Registry, layer::SubscriberExt};

use ethlambda_blockchain::{BlockChain, BlockChainConfig, EventBus, SyncStatusController};
use ethlambda_rpc::RpcConfig;
use ethlambda_storage::{
    MAX_RESUMABLE_DB_STATE_AGE, StorageBackend, Store, backend::RocksDBBackend,
};

const ASCII_ART: &str = r#"
      _   _     _                 _         _
  ___| |_| |__ | | __ _ _ __ ___ | |__   __| | __ _
 / _ \ __| '_ \| |/ _` | '_ ` _ \| '_ \ / _` |/ _` |
|  __/ |_| | | | | (_| | | | | | | |_) | (_| | (_| |
 \___|\__|_| |_|_|\__,_|_| |_| |_|_.__/ \__,_|\__,_|
"#;

// Shadow single-steps execution in a discrete-event simulation, so the default
// multi-threaded runtime's worker threads add only scheduling noise, never
// parallelism. Use a single-threaded runtime under Shadow. This is an
// optimization, not a correctness requirement.
#[cfg_attr(not(feature = "shadow-integration"), tokio::main)]
#[cfg_attr(feature = "shadow-integration", tokio::main(flavor = "current_thread"))]
async fn main() -> eyre::Result<()> {
    let filter = EnvFilter::builder()
        .with_default_directive(tracing::Level::INFO.into())
        .from_env_lossy();
    let subscriber = Registry::default().with(tracing_subscriber::fmt::layer().with_filter(filter));
    tracing::subscriber::set_global_default(subscriber)
        .wrap_err("failed to set global tracing subscriber")?;

    let Command::Node(options) = command::parse();
    options.validate_discovery()?;

    #[cfg(feature = "shadow-integration")]
    init_shadow_cost(&options.shadow);

    // Initialize metrics
    ethlambda_blockchain::metrics::init();
    ethlambda_blockchain::metrics::set_node_info("ethlambda", version::CLIENT_VERSION);
    ethlambda_blockchain::metrics::set_node_start_time();

    let rpc_config = RpcConfig {
        http_address: options.http_address,
        api_port: options.api_port,
        metrics_port: options.metrics_port,
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
    // provision.
    if ethlambda_rpc::test_driver::test_driver_enabled() {
        info!("HIVE_LEAN_TEST_DRIVER detected; booting in test-driver mode");
        return run_test_driver(rpc_config).await;
    }

    let node_p2p_key = read_hex_file_bytes(&options.node_key).wrap_err_with(|| {
        format!(
            "failed to load node key from {}",
            options.node_key.display()
        )
    })?;
    let p2p_socket = SocketAddr::new(IpAddr::from([0, 0, 0, 0]), options.gossipsub_port);

    #[cfg(all(not(target_env = "msvc"), feature = "jemalloc"))]
    info!("Using jemalloc allocator with heap profiling enabled");
    #[cfg(any(target_env = "msvc", not(feature = "jemalloc")))]
    info!("Using system allocator");

    info!(node_key=?options.node_key, "got node key");

    let config_path = options.genesis;
    let bootnodes_path = options.bootnodes;
    let validators_path = options.validators;
    let validator_config = options.validator_config;
    let validator_keys_dir = options.hash_sig_keys_dir;

    let config_yaml = std::fs::read_to_string(&config_path).wrap_err_with(|| {
        format!(
            "failed to read genesis config from {}",
            config_path.display()
        )
    })?;
    let genesis_config: GenesisConfig =
        serde_yaml_ng::from_str(&config_yaml).wrap_err_with(|| {
            format!(
                "failed to parse genesis config from {}",
                config_path.display()
            )
        })?;

    info!(
        genesis_time = genesis_config.genesis_time,
        validator_count = genesis_config.genesis_validators.len(),
        "Loaded genesis configuration"
    );

    let validator_config_file = read_validator_config_file(&validator_config)?;
    let node_names = load_node_names(&validator_config_file);

    // Resolve attestation_committee_count: CLI flag > validator-config.yaml > 1.
    // The CLI path is bounded by clap's `range(1..)`; enforce the same lower
    // bound here so a YAML value of 0 cannot bypass it.
    let attestation_committee_count = options
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
    ethlambda_blockchain::metrics::set_attestation_committee_count(attestation_committee_count);

    let bootnodes = read_bootnodes(&bootnodes_path)?;

    let validator_keys =
        read_validator_keys(&validators_path, &validator_keys_dir, &options.node_id)
            .wrap_err("failed to load validator keys")?;

    let data_dir =
        std::path::absolute(&options.data_dir).unwrap_or_else(|_| options.data_dir.clone());
    info!(data_dir = %data_dir.display(), "Initializing DB");
    std::fs::create_dir_all(&data_dir)
        .wrap_err_with(|| format!("failed to create data directory {}", data_dir.display()))?;
    let backend = Arc::new(
        RocksDBBackend::open(&data_dir)
            .map_err(|err| eyre::eyre!("{err}"))
            .wrap_err_with(|| format!("failed to open RocksDB at {}", data_dir.display()))?,
    );

    let clean_checkpoint_urls: Vec<String> = options
        .checkpoint_sync_url
        .into_iter()
        .map(|url| url.trim().to_string())
        .filter(|url| !url.is_empty())
        .collect();

    let store = fetch_initial_state(&clean_checkpoint_urls, &genesis_config, backend.clone())
        .await
        .inspect_err(|err| error!(%err, "Failed to initialize state"))?;

    let validator_ids: Vec<u64> = validator_keys.keys().copied().collect();

    // Shared, runtime-mutable aggregator flag. Seeded from the CLI and
    // threaded into both the blockchain actor (which reads on every tick)
    // and the API server (which exposes GET/POST admin endpoints).
    let aggregator = AggregatorController::new(options.is_aggregator);

    // Attestation subnets this node subscribes to, computed once and shared by
    // the P2P swarm (to open gossip subscriptions) and the blockchain actor
    // (to size the early-aggregation threshold), so both agree on which subnets
    // feed this node's gossip groups. Subscriptions are fixed at startup and
    // are not re-evaluated when the aggregator role is toggled at runtime; see
    // the hot-standby note on SwarmConfig.
    let subscribed_subnets = attestation_subscription_subnets(
        &validator_ids,
        attestation_committee_count,
        options.is_aggregator,
        options.aggregate_subnet_ids.as_deref(),
    );

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

    let blockchain_config = BlockChainConfig {
        aggregator: aggregator.clone(),
        sync_status_controller: sync_status.clone(),
        attestation_committee_count,
        gate_duties: !options.disable_duty_sync_gate,
        subscribed_subnets: subscribed_subnets.clone(),
        proposer_config: ProposerConfig {
            enable_proposer_aggregation: options.enable_proposer_aggregation,
            max_attestations_per_block: options.max_attestations_per_block,
        },
    };

    let blockchain = BlockChain::spawn(
        store.clone(),
        validator_keys,
        blockchain_config,
        events.clone(),
    );

    let built = build_swarm(SwarmConfig {
        node_key: node_p2p_key.clone(),
        bootnodes: bootnodes.clone(),
        listening_socket: p2p_socket,
        validator_ids,
        attestation_committee_count,
        subscription_subnets: subscribed_subnets.clone(),
    })
    .wrap_err("failed to build swarm")?;

    // Capture the local peer ID before `built` is moved into the P2P actor; the
    // RPC `/lean/v0/node/identity` endpoint reports it.
    let local_peer_id = built.local_peer_id.to_string();

    // `None` when discovery is disabled; `P2P::spawn` starts the discv5 server
    // from it and owns the resulting handle.
    let discovery = options.discovery.enable.then(|| DiscoverySpawnConfig {
        node_key: node_p2p_key,
        bind_ip: p2p_socket.ip(),
        discovery_port: options.discovery.port,
        quic_port: p2p_socket.port(),
        subscription_subnets: subscribed_subnets,
        attestation_committee_count,
        bootnodes,
        advertise_ip: options.discovery.advertise_ip,
        target_peers: options.discovery.target_peers,
    });

    let p2p = P2P::spawn(built, store.clone(), node_names, discovery)
        .await
        .wrap_err("failed to start discv5 discovery")?;

    // Wire actors together via protocol refs
    blockchain
        .actor_ref()
        .recipient::<InitP2P>()
        .send(InitP2P {
            p2p: p2p.actor_ref().to_block_chain_to_p2p_ref(),
        })
        .inspect_err(|err| error!(%err, "Failed to send InitP2P — actors not wired"))?;
    p2p.actor_ref()
        .recipient::<InitBlockChain>()
        .send(InitBlockChain {
            blockchain: blockchain.actor_ref().to_p2p_to_block_chain_ref(),
        })
        .inspect_err(|err| error!(%err, "Failed to send InitBlockChain — actors not wired"))?;

    let shutdown_token = CancellationToken::new();
    let rpc_shutdown = shutdown_token.clone();

    let rpc_handle = tokio::spawn(async move {
        let _ = ethlambda_rpc::start_rpc_server(
            rpc_config,
            store,
            aggregator,
            sync_status,
            local_peer_id,
            events,
            rpc_shutdown,
        )
        .await
        .inspect_err(|err| error!(%err, "RPC server failed"));
    });

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

    let blockchain_ref = blockchain.actor_ref().clone();
    let p2p_ref = p2p.actor_ref().clone();
    blockchain_ref.context().stop();
    p2p_ref.context().stop();
    shutdown_token.cancel();

    blockchain_ref.join().await;
    p2p_ref.join().await;
    let _ = rpc_handle.await;

    info!("Shutdown complete");

    Ok(())
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

fn read_bootnodes(bootnodes_path: impl AsRef<Path>) -> eyre::Result<Vec<Bootnode>> {
    let bootnodes_path = bootnodes_path.as_ref();
    let bootnodes_yaml = std::fs::read_to_string(bootnodes_path).wrap_err_with(|| {
        format!(
            "failed to read bootnodes file from {}",
            bootnodes_path.display()
        )
    })?;
    let enrs: Vec<String> = serde_yaml_ng::from_str(&bootnodes_yaml).wrap_err_with(|| {
        format!(
            "failed to parse bootnodes file from {}",
            bootnodes_path.display()
        )
    })?;
    Ok(parse_enrs(enrs))
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

    // Prefer resuming from on-disk state to avoid re-downloading what we already
    // have. Tried before the checkpoint-sync and genesis paths so that a restart
    // without `--checkpoint-sync-url` keeps the chain instead of writing a
    // slot-0 anchor over it.
    if let Some(store) = Store::from_db_state(backend.clone(), genesis)? {
        let now_ms = SystemTime::UNIX_EPOCH
            .elapsed()
            .expect("already past the unix epoch")
            .as_millis() as u64;
        let current_slot =
            now_ms.saturating_sub(genesis.genesis_time * 1000) / MILLISECONDS_PER_SLOT;
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
        return Ok(Store::from_anchor_state(backend, genesis_state));
    }

    // Checkpoint sync path: try URLs in order, fail over to the next on error.
    info!(?checkpoint_urls, "Starting checkpoint sync");

    let (state, signed_block) = checkpoint_sync::fetch_anchor_with_retry(
        checkpoint_urls,
        genesis.genesis_time,
        &validators,
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
    let mut store = Store::get_forkchoice_store(backend, state, signed_block.message.clone())
        .inspect_err(|err| error!(%err, "Failed to initialize store from anchor state and block"))
        .map_err(|_| checkpoint_sync::CheckpointSyncError::AnchorPairingMismatch)?;
    store
        .insert_signed_block(anchor_root, signed_block)
        .inspect_err(|err| error!(%err, "Failed to insert anchor signed block into store"))
        .map_err(|_| checkpoint_sync::CheckpointSyncError::StoreInsertSignedBlock)?;
    Ok(store)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_storage::backend::InMemoryBackend;
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
        let seconds_per_slot = MILLISECONDS_PER_SLOT / 1_000;
        now_secs() - (SEEDED_HEAD_SLOT + gap) * seconds_per_slot
    }

    /// Single-validator genesis config. The pubkeys are placeholders; none of
    /// the paths under test verify signatures.
    fn test_genesis(genesis_time: u64) -> GenesisConfig {
        GenesisConfig {
            genesis_time,
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
        Store::from_anchor_state(backend, anchor);
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
            matches!(err, checkpoint_sync::CheckpointSyncError::DbState(_)),
            "unexpected error: {err}"
        );
        // The foreign chain is left untouched, not overwritten with a new anchor.
        let store = Store::from_db_state(backend, &seeded_genesis)
            .expect("original DB still loads under its own genesis")
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
            matches!(err, checkpoint_sync::CheckpointSyncError::DbState(_)),
            "unexpected error: {err}"
        );
    }
}
