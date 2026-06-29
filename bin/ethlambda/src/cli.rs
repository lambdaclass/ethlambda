//! Command-line interface for the ethlambda binary.

use std::net::IpAddr;
use std::path::PathBuf;

use crate::version;

#[derive(Debug, clap::Parser)]
#[command(name = "ethlambda", author = "LambdaClass", version = version::CLIENT_VERSION, about = "ethlambda consensus client")]
pub(crate) struct CliOptions {
    /// Path to the chain genesis config (e.g., config.yaml).
    #[arg(long)]
    pub(crate) genesis: PathBuf,
    /// Path to the validator registry (e.g., annotated_validators.yaml).
    #[arg(long)]
    pub(crate) validators: PathBuf,
    /// Path to the bootnode list (e.g., nodes.yaml).
    #[arg(long)]
    pub(crate) bootnodes: PathBuf,
    /// Path to validator-config.yaml (validator name registry for metrics labels).
    #[arg(long)]
    pub(crate) validator_config: PathBuf,
    /// Directory containing per-validator XMSS keys (e.g., hash-sig-keys/).
    #[arg(long)]
    pub(crate) hash_sig_keys_dir: PathBuf,
    #[arg(long, default_value = "9000")]
    pub(crate) gossipsub_port: u16,
    #[arg(long, default_value = "127.0.0.1")]
    pub(crate) http_address: IpAddr,
    #[arg(long, default_value = "5052")]
    pub(crate) api_port: u16,
    #[arg(long, default_value = "5054")]
    pub(crate) metrics_port: u16,
    #[arg(long)]
    pub(crate) node_key: PathBuf,
    /// The node ID to look up in annotated_validators.yaml (e.g., "ethlambda_0")
    #[arg(long)]
    pub(crate) node_id: String,
    /// Base URL(s) of checkpoint-sync peer API servers (e.g., http://peer:5052).
    /// When set, skips genesis initialization and fetches the finalized state
    /// and block from each peer's `/lean/v0/states/finalized` and
    /// `/lean/v0/blocks/finalized` endpoints. For backward compatibility, a
    /// URL ending in `/lean/v0/states/finalized` is accepted and the trailing
    /// path is stripped.
    ///
    /// Multiple URLs may be supplied for redundancy, either comma-separated
    /// (`--checkpoint-sync-url u1,u2`) or by repeating the flag
    /// (`--checkpoint-sync-url u1 --checkpoint-sync-url u2`). URLs are tried
    /// in order; the first one that succeeds is used and any failures fall
    /// over to the next URL. Startup only aborts if every URL fails.
    #[arg(long, value_delimiter = ',')]
    pub(crate) checkpoint_sync_url: Vec<String>,
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
    pub(crate) is_aggregator: bool,
    /// Number of attestation committees (subnets) per slot.
    ///
    /// If unset, falls back to `config.attestation_committee_count` from
    /// `validator-config.yaml` in the network config dir, or `1` if that
    /// field is also absent.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    pub(crate) attestation_committee_count: Option<u64>,
    /// Subnet IDs this aggregator should subscribe to (comma-separated).
    /// Requires --is-aggregator. Defaults to the subnets of the node's validators.
    #[arg(long, value_delimiter = ',', requires = "is_aggregator")]
    pub(crate) aggregate_subnet_ids: Option<Vec<u64>>,
    /// Directory for RocksDB storage
    #[arg(long, default_value = "./data")]
    pub(crate) data_dir: PathBuf,
    /// Disable the sync-gate's suppression of validator duties.
    ///
    /// By default a node that judges itself to be syncing (local head lagging
    /// wall clock while the network still progresses) skips block proposal,
    /// attestation production, and aggregate re-derivation. With this flag the
    /// sync state is still tracked and exported via `lean_node_sync_status`,
    /// but it no longer suppresses any duty: the gate becomes observe-only.
    #[arg(long, default_value = "false")]
    pub(crate) disable_duty_sync_gate: bool,
}
