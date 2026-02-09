mod checkpoint_sync;
mod version;

use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
};

use clap::Parser;
use ethlambda_p2p::{Bootnode, parse_enrs, start_p2p};
use ethlambda_types::primitives::H256;
use ethlambda_types::{
    genesis::GenesisConfig,
    signature::ValidatorSecretKey,
    state::{State, ValidatorPubkeyBytes},
};
use serde::Deserialize;
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, Layer, Registry, layer::SubscriberExt};

use ethlambda_blockchain::BlockChain;
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
    #[arg(long)]
    custom_network_config_dir: PathBuf,
    #[arg(long, default_value = "9000")]
    gossipsub_port: u16,
    #[arg(long, default_value = "127.0.0.1")]
    metrics_address: IpAddr,
    #[arg(long, default_value = "5054")]
    metrics_port: u16,
    #[arg(long)]
    node_key: PathBuf,
    /// The node ID to look up in annotated_validators.yaml (e.g., "ethlambda_0")
    #[arg(long)]
    node_id: String,
    /// URL of a peer to download checkpoint state from (e.g., http://peer:5052)
    /// When set, skips genesis initialization and syncs from checkpoint.
    #[arg(long)]
    checkpoint_sync_url: Option<String>,
}

#[tokio::main]
async fn main() {
    let filter = EnvFilter::builder()
        .with_default_directive(tracing::Level::INFO.into())
        .from_env_lossy();
    let subscriber = Registry::default().with(tracing_subscriber::fmt::layer().with_filter(filter));
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let options = CliOptions::parse();

    // Set node info metrics
    ethlambda_blockchain::metrics::set_node_info("ethlambda", version::CLIENT_VERSION);
    ethlambda_blockchain::metrics::set_node_start_time();

    let metrics_socket = SocketAddr::new(options.metrics_address, options.metrics_port);
    let node_p2p_key = read_hex_file_bytes(&options.node_key);
    let p2p_socket = SocketAddr::new(IpAddr::from([0, 0, 0, 0]), options.gossipsub_port);

    println!("{ASCII_ART}");

    info!(version = version::CLIENT_VERSION, "Starting ethlambda");

    info!(node_key=?options.node_key, "got node key");

    let config_path = options.custom_network_config_dir.join("config.yaml");
    let bootnodes_path = options.custom_network_config_dir.join("nodes.yaml");
    let validators_path = options
        .custom_network_config_dir
        .join("annotated_validators.yaml");
    let validator_config = options
        .custom_network_config_dir
        .join("validator-config.yaml");
    let validator_keys_dir = options.custom_network_config_dir.join("hash-sig-keys");

    let config_yaml = std::fs::read_to_string(&config_path).expect("Failed to read config.yaml");
    let genesis_config: GenesisConfig =
        serde_yaml_ng::from_str(&config_yaml).expect("Failed to parse config.yaml");

    info!(
        genesis_time = genesis_config.genesis_time,
        validator_count = genesis_config.genesis_validators.len(),
        "Loaded genesis configuration"
    );

    populate_name_registry(&validator_config);
    let bootnodes = read_bootnodes(&bootnodes_path);

    let validator_keys =
        read_validator_keys(&validators_path, &validator_keys_dir, &options.node_id);

    let backend = Arc::new(RocksDBBackend::open("./data").expect("Failed to open RocksDB"));

    let store = fetch_initial_state(
        options.checkpoint_sync_url.as_deref(),
        &genesis_config,
        backend.clone(),
    )
    .await
    .inspect_err(|err| error!(%err, "Failed to initialize state"))
    .unwrap_or_else(|_| std::process::exit(1));

    let (p2p_tx, p2p_rx) = tokio::sync::mpsc::unbounded_channel();
    let blockchain = BlockChain::spawn(store.clone(), p2p_tx, validator_keys);

    let p2p_handle = tokio::spawn(start_p2p(
        node_p2p_key,
        bootnodes,
        p2p_socket,
        blockchain,
        p2p_rx,
        store.clone(),
    ));

    ethlambda_rpc::start_rpc_server(metrics_socket, store)
        .await
        .unwrap();

    info!("Node initialized");

    tokio::select! {
        _ = p2p_handle => {
            panic!("P2P node task has exited unexpectedly");
        }
        _ = tokio::signal::ctrl_c() => {
            // Ctrl-C received, shutting down
        }
    }
    println!("Shutting down...");
}

fn populate_name_registry(validator_config: impl AsRef<Path>) {
    #[derive(Deserialize)]
    struct Validator {
        name: String,
        privkey: H256,
    }
    #[derive(Deserialize)]
    struct Config {
        validators: Vec<Validator>,
    }
    let config_yaml =
        std::fs::read_to_string(&validator_config).expect("Failed to read validator config file");
    let config: Config =
        serde_yaml_ng::from_str(&config_yaml).expect("Failed to parse validator config file");

    let names_and_privkeys = config
        .validators
        .into_iter()
        .map(|v| (v.name, v.privkey))
        .collect();

    // Populates a dictionary used for labeling metrics with node names
    ethlambda_p2p::metrics::populate_name_registry(names_and_privkeys);
}

fn read_bootnodes(bootnodes_path: impl AsRef<Path>) -> Vec<Bootnode> {
    let bootnodes_yaml =
        std::fs::read_to_string(bootnodes_path).expect("Failed to read bootnodes file");
    let enrs: Vec<String> =
        serde_yaml_ng::from_str(&bootnodes_yaml).expect("Failed to parse bootnodes file");
    parse_enrs(enrs)
}

#[derive(Debug, Deserialize)]
struct AnnotatedValidator {
    index: u64,
    #[serde(rename = "pubkey_hex")]
    #[serde(deserialize_with = "deser_pubkey_hex")]
    _pubkey: ValidatorPubkeyBytes,
    privkey_file: PathBuf,
}

// Taken from ethrex-common
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

fn read_validator_keys(
    validators_path: impl AsRef<Path>,
    validator_keys_dir: impl AsRef<Path>,
    node_id: &str,
) -> HashMap<u64, ValidatorSecretKey> {
    let validators_path = validators_path.as_ref();
    let validator_keys_dir = validator_keys_dir.as_ref();
    let validators_yaml =
        std::fs::read_to_string(validators_path).expect("Failed to read validators file");
    // File is a map from validator name to its annotated info (the info is inside a vec for some reason)
    let validator_infos: BTreeMap<String, Vec<AnnotatedValidator>> =
        serde_yaml_ng::from_str(&validators_yaml).expect("Failed to parse validators file");

    let validator_vec = validator_infos
        .get(node_id)
        .unwrap_or_else(|| panic!("Node ID '{}' not found in validators config", node_id));

    let mut validator_keys = HashMap::new();

    for validator in validator_vec {
        let validator_index = validator.index;

        // Resolve the secret key file path relative to the validators config directory
        let secret_key_path = if validator.privkey_file.is_absolute() {
            validator.privkey_file.clone()
        } else {
            validator_keys_dir.join(&validator.privkey_file)
        };

        info!(node_id=%node_id, index=validator_index, secret_key_file=?secret_key_path, "Loading validator secret key");

        // Read the hex-encoded secret key file
        let secret_key_bytes =
            std::fs::read(&secret_key_path).expect("Failed to read validator secret key file");

        // Parse the secret key
        let secret_key = ValidatorSecretKey::from_bytes(&secret_key_bytes).unwrap_or_else(|err| {
            error!(node_id=%node_id, index=validator_index, secret_key_file=?secret_key_path, ?err, "Failed to parse validator secret key");
            std::process::exit(1);
        });

        validator_keys.insert(validator_index, secret_key);
    }

    info!(
        node_id = %node_id,
        count = validator_keys.len(),
        "Loaded validator secret keys"
    );

    validator_keys
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
    let store = if let Some(checkpoint_url) = checkpoint_url {
        // Checkpoint sync path
        info!(%checkpoint_url, "Starting checkpoint sync");

        let state = checkpoint_sync::fetch_checkpoint_state(checkpoint_url).await?;

        // Verify against local genesis config
        checkpoint_sync::verify_checkpoint_state(&state, genesis.genesis_time, &validators)?;

        info!(
            slot = state.slot,
            validators = state.validators.len(),
            finalized_slot = state.latest_finalized.slot,
            "Checkpoint sync complete"
        );

        // Store the anchor state and header, without body
        Store::from_anchor_state(backend, state)
    } else {
        let genesis_state = State::from_genesis(genesis.genesis_time, validators);
        Store::from_anchor_state(backend, genesis_state)
    };

    Ok(store)
}
