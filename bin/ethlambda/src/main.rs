use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

use clap::Parser;
use ethlambda_p2p::{Bootnode, parse_enrs, start_p2p};
use ethlambda_rpc::metrics::start_prometheus_metrics_api;
use ethlambda_types::{
    genesis::Genesis,
    state::{State, Validator, ValidatorPubkeyBytes},
};
use serde::Deserialize;
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, Layer, Registry, layer::SubscriberExt};

use ethlambda_blockchain::BlockChain;

const ASCII_ART: &str = r#"
      _   _     _                 _         _
  ___| |_| |__ | | __ _ _ __ ___ | |__   __| | __ _
 / _ \ __| '_ \| |/ _` | '_ ` _ \| '_ \ / _` |/ _` |
|  __/ |_| | | | | (_| | | | | | | |_) | (_| | (_| |
 \___|\__|_| |_|_|\__,_|_| |_| |_|_.__/ \__,_|\__,_|
"#;

#[derive(Debug, clap::Parser)]
struct CliOptions {
    #[arg(long)]
    custom_network_config_dir: PathBuf,
    #[arg(long)]
    gossipsub_port: u16,
    #[arg(long)]
    metrics_address: IpAddr,
    #[arg(long)]
    metrics_port: u16,
    #[arg(long)]
    node_key: PathBuf,
}

#[tokio::main]
async fn main() {
    let filter = EnvFilter::builder()
        .with_default_directive(tracing::Level::INFO.into())
        .from_env_lossy();
    let subscriber = Registry::default().with(tracing_subscriber::fmt::layer().with_filter(filter));
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let options = CliOptions::parse();

    let metrics_socket = SocketAddr::new(options.metrics_address, options.metrics_port);
    let node_p2p_key = read_hex_file_bytes(&options.node_key);
    let p2p_socket = SocketAddr::new(IpAddr::from([0, 0, 0, 0]), options.gossipsub_port);

    println!("{ASCII_ART}");

    info!(node_key=?options.node_key, "got node key");

    let genesis_path = options.custom_network_config_dir.join("genesis.json");
    let bootnodes_path = options.custom_network_config_dir.join("nodes.yaml");
    let validators_path = options
        .custom_network_config_dir
        .join("annotated_validators.yaml");

    let genesis_json = std::fs::read_to_string(&genesis_path).expect("Failed to read genesis.json");
    let genesis: Genesis =
        serde_json::from_str(&genesis_json).expect("Failed to parse genesis.json");

    let bootnodes = read_bootnodes(&bootnodes_path);

    let validators = read_validators(&validators_path);

    let genesis_state = State::from_genesis(&genesis, validators);

    let blockchain = BlockChain::spawn(genesis_state);

    let p2p_handle = tokio::spawn(start_p2p(node_p2p_key, bootnodes, p2p_socket, blockchain));

    start_prometheus_metrics_api(metrics_socket).await.unwrap();

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
    pubkey: ValidatorPubkeyBytes,
    // privkey_file: PathBuf,
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

fn read_validators(validators_path: impl AsRef<Path>) -> Vec<Validator> {
    let validators_yaml =
        std::fs::read_to_string(validators_path).expect("Failed to read validators file");
    // File is a map from validator name to its annotated info (the info is inside a vec for some reason)
    let validator_infos: BTreeMap<String, Vec<AnnotatedValidator>> =
        serde_yaml_ng::from_str(&validators_yaml).expect("Failed to parse validators file");

    let mut validators: Vec<Validator> = validator_infos
        .into_values()
        .map(|v| Validator {
            pubkey: v[0].pubkey,
            index: v[0].index,
        })
        .collect();

    validators.sort_by_key(|v| v.index);
    let num_validators = validators.len();

    validators.dedup_by_key(|v| v.index);

    if validators.len() != num_validators {
        panic!("Duplicate validator indices found in config");
    }

    validators
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
