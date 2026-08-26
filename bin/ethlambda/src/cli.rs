//! Command-line interface for the ethlambda binary.

use ethlambda_p2p::discovery::DEFAULT_DISCOVERY_TARGET_PEERS;
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Debug, clap::Args)]
pub(crate) struct NodeOptions {
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
    /// UDP port for the libp2p QUIC listener.
    ///
    /// Defaults one above `--discovery.port` so that `--discovery.enable` works
    /// on its own: both are UDP sockets and cannot share a port.
    #[arg(long, default_value = "9001")]
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
    /// When set, fetches the finalized state and block from each peer's
    /// `/lean/v0/states/finalized` and `/lean/v0/blocks/finalized` endpoints.
    /// For backward compatibility, a URL ending in
    /// `/lean/v0/states/finalized` is accepted and the trailing path is
    /// stripped.
    ///
    /// This is a fallback, not a precedence: state already in the data
    /// directory always wins, so these URLs are only used when there is no
    /// resumable state on disk (or it has fallen too far behind the current
    /// slot). With neither resumable state nor URLs, the node starts from
    /// genesis.
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
    /// Enable proposer-side aggregation of attestation proofs when building a
    /// block.
    ///
    /// A block may carry at most one entry per `AttestationData`, so the
    /// proposer must collapse same-data proofs either way. When set,
    /// `build_block` merges them via recursive single-message aggregation into a single
    /// union-coverage proof per data (leanSpec #510), maximizing voter coverage
    /// at the cost of a leanVM aggregation per duplicated data entry. When unset
    /// (the default), it instead keeps only the single best-coverage proof per
    /// data and drops the rest, skipping the leanVM work at the cost of lower
    /// coverage.
    #[arg(long, default_value = "false")]
    pub(crate) enable_proposer_aggregation: bool,
    /// Maximum number of distinct attestations to pack when building a block.
    ///
    /// Bounds how many distinct `AttestationData` entries the proposer includes
    /// in a block it builds. This is a proposer-side self-limit only: it does
    /// NOT change the consensus cap for accepting blocks from peers, which
    /// stays at `MAX_ATTESTATIONS_DATA`. Values above `MAX_ATTESTATIONS_DATA`
    /// are clamped to it, since a block carrying more would be rejected by
    /// `on_block`.
    #[arg(long, default_value = "3")]
    pub(crate) max_attestations_per_block: usize,
    #[command(flatten)]
    pub(crate) discovery: DiscoveryConfig,
    /// Shadow-simulator sim-cost + fake-XMSS flags (only under the
    /// `shadow-integration` feature).
    #[cfg(feature = "shadow-integration")]
    #[command(flatten)]
    pub(crate) shadow: ShadowOptions,
}

/// discv5 peer discovery. Off by default: nothing else on the lean network
/// speaks discv5 yet, so enabling it only finds other ethlambda nodes.
#[derive(Debug, clap::Args)]
pub(crate) struct DiscoveryConfig {
    /// Enable discv5 peer discovery.
    ///
    /// Works with the default ports. If either is overridden, `--discovery.port`
    /// must still differ from `--gossipsub-port`: both are UDP sockets and they
    /// cannot share one port.
    #[arg(long = "discovery.enable", default_value = "false")]
    pub(crate) enable: bool,
    /// UDP port for the discv5 socket.
    ///
    /// Independent of `--gossipsub-port`, which carries libp2p QUIC and
    /// defaults one port above this one.
    #[arg(long = "discovery.port", default_value = "9000")]
    pub(crate) port: u16,
    /// IP address to advertise in the ENR.
    ///
    /// Defaults to the bind address, which is the wildcard `0.0.0.0` and is not
    /// dialable as published. Set this to the address peers should reach this
    /// node on: `127.0.0.1` for a local devnet, or the host's public address.
    /// discv5's PONG-based IP voting may still replace it at runtime.
    #[arg(long = "discovery.advertise-ip")]
    pub(crate) advertise_ip: Option<std::net::IpAddr>,
    /// Connected-peer count above which discovery stops dialing.
    ///
    /// Governs the dial loop only, not discv5's own lookup pacing. The loop
    /// keeps ticking either way and resumes dialing as soon as the connected
    /// count drops back below this, so 0 means "discover and serve, never
    /// dial".
    #[arg(long = "discovery.target-peers", default_value_t = DEFAULT_DISCOVERY_TARGET_PEERS)]
    pub(crate) target_peers: usize,
}

impl NodeOptions {
    /// Reject a discovery port that collides with the QUIC port.
    ///
    /// Both are UDP. Without this the collision surfaces at bind time as an
    /// opaque `EADDRINUSE` on whichever socket loses the race.
    pub(crate) fn validate_discovery(&self) -> eyre::Result<()> {
        if self.discovery.enable && self.discovery.port == self.gossipsub_port {
            eyre::bail!(
                "--discovery.port ({}) must differ from --gossipsub-port ({}): \
                 both bind UDP and cannot share a port",
                self.discovery.port,
                self.gossipsub_port
            );
        }
        Ok(())
    }
}

/// Shadow-simulator sim-cost + fake-XMSS flags. Compiled only under the
/// `shadow-integration` feature.
#[cfg(feature = "shadow-integration")]
#[derive(Debug, clap::Args)]
pub(crate) struct ShadowOptions {
    /// Shadow sim only: replace the XMSS aggregation prover/verifier with a
    /// deterministic stub (no leanVM proving/verifying). Off by default.
    #[arg(long, default_value = "false")]
    pub(crate) shadow_xmss_fake: bool,

    /// Shadow sim only: signatures aggregated per second. Injects a sleep of
    /// n/rate seconds into aggregation so its CPU cost shows up on Shadow's
    /// virtual clock. Unset or <= 0 disables.
    #[arg(long)]
    pub(crate) shadow_xmss_aggregate_signatures_rate: Option<f64>,

    /// Shadow sim only: signatures verified per aggregate per second; injects
    /// a sleep of n/rate seconds into verification. Unset or <= 0 disables.
    #[arg(long)]
    pub(crate) shadow_xmss_verify_aggregated_signatures_rate: Option<f64>,

    /// Shadow sim only: Type-1 components merged into a Type-2 per second;
    /// injects a sleep of n/rate seconds into the proposal Type-2 merge.
    /// Unset or <= 0 disables.
    #[arg(long)]
    pub(crate) shadow_xmss_merge_rate: Option<f64>,

    /// Shadow sim only: byte length of each fake stub proof. Defaults to 32
    /// KiB; capped at the 512 KiB on-wire proof limit.
    #[arg(
        long,
        default_value_t = ethlambda_crypto::shadow_cost::DEFAULT_FAKE_PROOF_SIZE as u64,
        value_parser = clap::value_parser!(u64).range(1..=524_288)
    )]
    pub(crate) shadow_xmss_fake_proof_size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::{Command, try_parse_from};

    /// The required flags, so a test can vary only what it cares about.
    ///
    /// `NodeOptions` is a `clap::Args` group rather than a parser of its own,
    /// so this parses through the real dispatch, as the binary does.
    fn parse(extra: &[&str]) -> NodeOptions {
        let mut argv = vec![
            "ethlambda",
            "--genesis",
            "config.yaml",
            "--validators",
            "validators.yaml",
            "--bootnodes",
            "nodes.yaml",
            "--validator-config",
            "validator-config.yaml",
            "--hash-sig-keys-dir",
            "keys",
            "--node-key",
            "node.key",
            "--node-id",
            "ethlambda_0",
        ];
        argv.extend_from_slice(extra);
        let Command::Node(options) = try_parse_from(argv).expect("node options parse");
        options
    }

    /// `--discovery.enable` on its own has to work: a default that is never
    /// valid makes the flag a guaranteed startup failure.
    #[test]
    fn default_ports_let_discovery_be_enabled_alone() {
        let options = parse(&["--discovery.enable"]);

        assert_ne!(options.discovery.port, options.gossipsub_port);
        assert!(options.validate_discovery().is_ok());
    }

    #[test]
    fn colliding_ports_are_rejected_only_when_discovery_is_enabled() {
        let ports = ["--gossipsub-port", "9000", "--discovery.port", "9000"];
        let mut enabled = ports.to_vec();
        enabled.push("--discovery.enable");

        assert!(parse(&ports).validate_discovery().is_ok());
        assert!(parse(&enabled).validate_discovery().is_err());
    }
}
