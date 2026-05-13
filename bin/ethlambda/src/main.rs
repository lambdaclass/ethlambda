mod checkpoint_sync;
mod version;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[allow(non_upper_case_globals)]
#[unsafe(export_name = "malloc_conf")]
static malloc_conf: &[u8] = b"prof:true,prof_active:true,lg_prof_sample:19\0";

use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio_util::sync::CancellationToken;

use clap::Parser;
use ethlambda_blockchain::key_manager::ValidatorKeyPair;
use ethlambda_network_api::{InitBlockChain, InitP2P, ToBlockChainToP2PRef, ToP2PToBlockChainRef};
use ethlambda_p2p::{Bootnode, P2P, PeerId, SwarmConfig, build_swarm, parse_enrs};
use ethlambda_types::primitives::H256;
use ethlambda_types::{
    aggregator::AggregatorController,
    genesis::GenesisConfig,
    signature::ValidatorSecretKey,
    state::{State, ValidatorPubkeyBytes},
};
use serde::Deserialize;
use tracing::{error, info, warn};
use tracing_subscriber::{EnvFilter, Layer, Registry, layer::SubscriberExt};

use ethlambda_blockchain::BlockChain;
use ethlambda_ethrex_client::{ETHLAMBDA_ENGINE_CAPABILITIES, EngineClient, JwtSecret};
use ethlambda_rpc::RpcConfig;
use ethlambda_storage::{StorageBackend, Store, backend::RocksDBBackend};

const ASCII_ART: &str = r#"
      _   _     _                 _         _
  ___| |_| |__ | | __ _ _ __ ___ | |__   __| | __ _
 / _ \ __| '_ \| |/ _` | '_ ` _ \| '_ \ / _` |/ _` |
|  __/ |_| | | | | (_| | | | | | | |_) | (_| | (_| |
 \___|\__|_| |_|_|\__,_|_| |_| |_|_.__/ \__,_|\__,_|
"#;

#[derive(Debug, clap::Parser)]
#[command(name = "ethlambda", author = "LambdaClass", version = version::CLIENT_VERSION, about = "ethlambda consensus client")]
struct CliOptions {
    /// Path to the chain genesis config (e.g., config.yaml).
    #[arg(long)]
    genesis: PathBuf,
    /// Path to the validator registry (e.g., annotated_validators.yaml).
    #[arg(long)]
    validators: PathBuf,
    /// Path to the bootnode list (e.g., nodes.yaml).
    #[arg(long)]
    bootnodes: PathBuf,
    /// Path to validator-config.yaml (validator name registry for metrics labels).
    #[arg(long)]
    validator_config: PathBuf,
    /// Directory containing per-validator XMSS keys (e.g., hash-sig-keys/).
    #[arg(long)]
    hash_sig_keys_dir: PathBuf,
    #[arg(long, default_value = "9000")]
    gossipsub_port: u16,
    #[arg(long, default_value = "127.0.0.1")]
    http_address: IpAddr,
    #[arg(long, default_value = "5052")]
    api_port: u16,
    #[arg(long, default_value = "5054")]
    metrics_port: u16,
    #[arg(long)]
    node_key: PathBuf,
    /// The node ID to look up in annotated_validators.yaml (e.g., "ethlambda_0")
    #[arg(long)]
    node_id: String,
    /// URL to download checkpoint state from (e.g., http://peer:5052/lean/v0/states/finalized)
    /// When set, skips genesis initialization and syncs from checkpoint.
    #[arg(long)]
    checkpoint_sync_url: Option<String>,
    /// Whether this node acts as a committee aggregator.
    ///
    /// Seeds the initial value of the live aggregator flag shared by the
    /// blockchain actor and the admin API. The flag can be toggled at
    /// runtime via `POST /lean/v0/admin/aggregator`. Runtime toggles do
    /// NOT persist across restarts and do NOT update gossip subnet
    /// subscriptions, which are frozen at startup — standby aggregators
    /// should boot with this flag enabled to establish subscriptions, then
    /// use the admin endpoint to rotate duties (hot-standby model).
    #[arg(long, default_value = "false")]
    is_aggregator: bool,
    /// Number of attestation committees (subnets) per slot.
    ///
    /// If unset, falls back to `config.attestation_committee_count` from
    /// `validator-config.yaml` in the network config dir, or `1` if that
    /// field is also absent.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    attestation_committee_count: Option<u64>,
    /// Subnet IDs this aggregator should subscribe to (comma-separated).
    /// Requires --is-aggregator. Defaults to the subnets of the node's validators.
    #[arg(long, value_delimiter = ',', requires = "is_aggregator")]
    aggregate_subnet_ids: Option<Vec<u64>>,
    /// Directory for RocksDB storage
    #[arg(long, default_value = "./data")]
    data_dir: PathBuf,
    /// URL of the ethrex (or other EL) Engine API auth endpoint, e.g. `http://127.0.0.1:8551`.
    ///
    /// When unset, Engine API integration is disabled and ethlambda runs as
    /// a consensus-only node. When set, `--execution-jwt-secret` is required.
    #[arg(long, requires = "execution_jwt_secret")]
    execution_endpoint: Option<String>,
    /// Path to a file containing the 32-byte JWT secret shared with the EL,
    /// as a single line of hex (optionally `0x`-prefixed). Same format used
    /// by Lighthouse/Teku/Prysm/ethrex.
    #[arg(long, requires = "execution_endpoint")]
    execution_jwt_secret: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let filter = EnvFilter::builder()
        .with_default_directive(tracing::Level::INFO.into())
        .from_env_lossy();
    let subscriber = Registry::default().with(tracing_subscriber::fmt::layer().with_filter(filter));
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let options = CliOptions::parse();

    // Initialize metrics
    ethlambda_blockchain::metrics::init();
    ethlambda_blockchain::metrics::set_node_info("ethlambda", version::CLIENT_VERSION);
    ethlambda_blockchain::metrics::set_node_start_time();

    let rpc_config = RpcConfig {
        http_address: options.http_address,
        api_port: options.api_port,
        metrics_port: options.metrics_port,
    };

    println!("{ASCII_ART}");

    info!(version = version::CLIENT_VERSION, "Starting ethlambda");

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

    let node_p2p_key = read_hex_file_bytes(&options.node_key);
    let p2p_socket = SocketAddr::new(IpAddr::from([0, 0, 0, 0]), options.gossipsub_port);

    #[cfg(not(target_env = "msvc"))]
    info!("Using jemalloc allocator with heap profiling enabled");
    #[cfg(target_env = "msvc")]
    info!("Using system allocator (MSVC target)");

    info!(node_key=?options.node_key, "got node key");

    let config_path = options.genesis;
    let bootnodes_path = options.bootnodes;
    let validators_path = options.validators;
    let validator_config = options.validator_config;
    let validator_keys_dir = options.hash_sig_keys_dir;

    let config_yaml = std::fs::read_to_string(&config_path).expect("Failed to read config.yaml");
    let genesis_config: GenesisConfig =
        serde_yaml_ng::from_str(&config_yaml).expect("Failed to parse config.yaml");

    info!(
        genesis_time = genesis_config.genesis_time,
        validator_count = genesis_config.genesis_validators.len(),
        "Loaded genesis configuration"
    );

    let validator_config_file = read_validator_config_file(&validator_config);
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

    let bootnodes = read_bootnodes(&bootnodes_path);

    let validator_keys =
        read_validator_keys(&validators_path, &validator_keys_dir, &options.node_id)
            .expect("Failed to load validator keys");

    let data_dir =
        std::path::absolute(&options.data_dir).unwrap_or_else(|_| options.data_dir.clone());
    info!(data_dir = %data_dir.display(), "Initializing DB");
    std::fs::create_dir_all(&data_dir).expect("Failed to create data directory");
    let backend = Arc::new(RocksDBBackend::open(&data_dir).expect("Failed to open RocksDB"));

    let store = fetch_initial_state(
        options.checkpoint_sync_url.as_deref(),
        &genesis_config,
        backend.clone(),
    )
    .await
    .inspect_err(|err| error!(%err, "Failed to initialize state"))?;

    let validator_ids: Vec<u64> = validator_keys.keys().copied().collect();

    // Shared, runtime-mutable aggregator flag. Seeded from the CLI and
    // threaded into both the blockchain actor (which reads on every tick)
    // and the API server (which exposes GET/POST admin endpoints).
    let aggregator = AggregatorController::new(options.is_aggregator);

    let execution_client = build_execution_client(
        options.execution_endpoint.as_deref(),
        options.execution_jwt_secret.as_deref(),
    )
    .await;

    let blockchain = BlockChain::spawn(
        store.clone(),
        validator_keys,
        aggregator.clone(),
        execution_client,
    );

    // Note: SwarmConfig.is_aggregator is intentionally a plain bool, not the
    // AggregatorController — subnet subscriptions are decided once here and
    // are not re-evaluated at runtime. Toggling via the admin API affects
    // aggregation logic but not the gossip mesh. See crates/net/p2p/src/lib.rs
    // for the invariant.
    let built = build_swarm(SwarmConfig {
        node_key: node_p2p_key,
        bootnodes,
        listening_socket: p2p_socket,
        validator_ids,
        attestation_committee_count,
        is_aggregator: options.is_aggregator,
        aggregate_subnet_ids: options.aggregate_subnet_ids,
    })
    .expect("failed to build swarm");

    let p2p = P2P::spawn(built, store.clone(), node_names);

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
        let _ = ethlambda_rpc::start_rpc_server(rpc_config, store, aggregator, rpc_shutdown)
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

fn read_validator_config_file(path: impl AsRef<Path>) -> ValidatorConfigFile {
    let yaml = std::fs::read_to_string(&path).expect("Failed to read validator config file");
    serde_yaml_ng::from_str(&yaml).expect("Failed to parse validator config file")
}

fn load_node_names(file: &ValidatorConfigFile) -> HashMap<PeerId, String> {
    let names_and_privkeys = file
        .validators
        .iter()
        .map(|v| (v.name.clone(), v.privkey))
        .collect();

    ethlambda_p2p::derive_peer_ids(names_and_privkeys)
}

fn read_bootnodes(bootnodes_path: impl AsRef<Path>) -> Vec<Bootnode> {
    let bootnodes_yaml =
        std::fs::read_to_string(bootnodes_path).expect("Failed to read bootnodes file");
    let enrs: Vec<String> =
        serde_yaml_ng::from_str(&bootnodes_yaml).expect("Failed to parse bootnodes file");
    parse_enrs(enrs)
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
) -> Result<HashMap<u64, ValidatorKeyPair>, String> {
    let validators_path = validators_path.as_ref();
    let validator_keys_dir = validator_keys_dir.as_ref();
    let validators_yaml = std::fs::read_to_string(validators_path)
        .map_err(|err| format!("Failed to read validators file: {err}"))?;
    let validator_infos: BTreeMap<String, Vec<AnnotatedValidator>> =
        serde_yaml_ng::from_str(&validators_yaml)
            .map_err(|err| format!("Failed to parse validators file: {err}"))?;

    let validator_vec = validator_infos
        .get(node_id)
        .ok_or_else(|| format!("Node ID '{node_id}' not found in validators config"))?;

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
        let role = classify_role(&entry.privkey_file)?;
        let path = resolve_path(&entry.privkey_file);
        let slots = grouped.entry(entry.index).or_default();
        let target = match role {
            ValidatorKeyRole::Attestation => &mut slots.attestation,
            ValidatorKeyRole::Proposal => &mut slots.proposal,
        };
        if target.is_some() {
            return Err(format!(
                "validator {}: duplicate {role:?} entry",
                entry.index
            ));
        }
        *target = Some(path);
    }

    let load_key = |path: &Path, purpose: &str| -> Result<ValidatorSecretKey, String> {
        let bytes = std::fs::read(path).map_err(|err| {
            format!(
                "Failed to read {purpose} key file {}: {err}",
                path.display()
            )
        })?;
        ValidatorSecretKey::from_bytes(&bytes)
            .map_err(|err| format!("Failed to parse {purpose} key {}: {err:?}", path.display()))
    };

    let mut validator_keys = HashMap::new();
    for (idx, slots) in grouped {
        let att_path = slots
            .attestation
            .ok_or_else(|| format!("validator {idx}: missing attester entry"))?;
        let prop_path = slots
            .proposal
            .ok_or_else(|| format!("validator {idx}: missing proposer entry"))?;

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

/// Build the optional Engine API client and run the capability handshake.
///
/// Returns `None` when integration is disabled (neither flag provided).
/// Returns `None` and logs an error when construction or the handshake
/// fails — consensus must keep running regardless of EL state.
async fn build_execution_client(
    endpoint: Option<&str>,
    jwt_path: Option<&Path>,
) -> Option<EngineClient> {
    // CLI requires both-or-neither; defensive recheck for clarity.
    let (endpoint, jwt_path) = match (endpoint, jwt_path) {
        (Some(e), Some(p)) => (e, p),
        (None, None) => return None,
        _ => {
            error!("Both --execution-endpoint and --execution-jwt-secret are required together");
            return None;
        }
    };

    let secret = match JwtSecret::from_file(jwt_path) {
        Ok(s) => s,
        Err(err) => {
            error!(path = %jwt_path.display(), %err, "Failed to load JWT secret");
            return None;
        }
    };

    let client = match EngineClient::new(endpoint, secret) {
        Ok(c) => c,
        Err(err) => {
            error!(%err, "Failed to construct EngineClient");
            return None;
        }
    };

    info!(endpoint, "Engine API integration enabled");

    match client
        .exchange_capabilities(ETHLAMBDA_ENGINE_CAPABILITIES)
        .await
    {
        Ok(caps) => info!(count = caps.len(), "EL capability handshake succeeded"),
        Err(err) => warn!(
            %err,
            "EL capability handshake failed (will keep retrying on each tick)"
        ),
    }

    Some(client)
}

fn read_hex_file_bytes(path: impl AsRef<Path>) -> Vec<u8> {
    let path = path.as_ref();
    let Ok(file_content) = std::fs::read_to_string(path)
        .inspect_err(|err| error!(file=%path.display(), %err, "Failed to read hex file"))
    else {
        std::process::exit(1);
    };
    let hex_string = file_content.trim().trim_start_matches("0x");
    let Ok(bytes) = hex::decode(hex_string)
        .inspect_err(|err| error!(file=%path.display(), %err, "Failed to decode hex file"))
    else {
        std::process::exit(1);
    };
    bytes
}

/// Fetch the initial state for the node.
///
/// If `checkpoint_url` is provided, performs checkpoint sync by downloading
/// and verifying the finalized state from a remote peer. Otherwise, creates
/// a genesis state from the local genesis configuration.
///
/// # Arguments
///
/// * `checkpoint_url` - Optional URL to fetch checkpoint state from
/// * `genesis` - Genesis configuration (for genesis_time verification and genesis state creation)
/// * `validators` - Validator set (moved for genesis state creation)
/// * `backend` - Storage backend for Store creation
///
/// # Returns
///
/// `Ok(Store)` on success, or `Err(CheckpointSyncError)` if checkpoint sync fails.
/// Genesis path is infallible and always returns `Ok`.
async fn fetch_initial_state(
    checkpoint_url: Option<&str>,
    genesis: &GenesisConfig,
    backend: Arc<dyn StorageBackend>,
) -> Result<Store, checkpoint_sync::CheckpointSyncError> {
    let validators = genesis.validators();

    let Some(checkpoint_url) = checkpoint_url else {
        info!("No checkpoint sync URL provided, initializing from genesis state");
        let genesis_state = State::from_genesis(genesis.genesis_time, validators);
        return Ok(Store::from_anchor_state(backend, genesis_state));
    };

    // Checkpoint sync path
    info!(%checkpoint_url, "Starting checkpoint sync");

    let state =
        checkpoint_sync::fetch_checkpoint_state(checkpoint_url, genesis.genesis_time, &validators)
            .await?;

    info!(
        slot = state.slot,
        validators = state.validators.len(),
        finalized_slot = state.latest_finalized.slot,
        "Checkpoint sync complete"
    );

    // Store the anchor state and header, without body
    Ok(Store::from_anchor_state(backend, state))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Validator-config snippet matching `lean-quickstart`'s ansible-devnet
    /// (devnet-4) where networks share a non-default committee count.
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
}
