//! Command-line interface for the ethlambda binary.

use std::net::IpAddr;
use std::path::PathBuf;

use crate::version;

// Node options plus optional sub-commands.
//
// The seven node-required arguments are declared `Option<T>` with
// `required = true`: together with `subcommand_negates_reqs`, clap keeps
// enforcing them (with its native missing-argument errors) for the flat node
// invocation while letting sub-commands parse without any of them. Plain
// non-`Option` fields would make sub-command invocations fail during derive
// extraction even though validation was negated.
// `args_conflicts_with_subcommands` rejects mixed invocations
// (e.g. `--genesis x benchmark`) instead of silently ignoring the node flags.
//
// NOT a doc comment: clap derive turns struct doc comments into the
// `long_about` shown by `--help`, and this note is for maintainers, not users.
#[derive(Debug, clap::Parser)]
#[command(
    name = "ethlambda",
    author = "LambdaClass",
    version = version::CLIENT_VERSION,
    about = "ethlambda consensus client",
    subcommand_negates_reqs = true,
    args_conflicts_with_subcommands = true
)]
pub(crate) struct CliOptions {
    #[command(subcommand)]
    pub(crate) command: Option<Command>,
    /// Path to the chain genesis config (e.g., config.yaml).
    #[arg(long, required = true)]
    pub(crate) genesis: Option<PathBuf>,
    /// Path to the validator registry (e.g., annotated_validators.yaml).
    #[arg(long, required = true)]
    pub(crate) validators: Option<PathBuf>,
    /// Path to the bootnode list (e.g., nodes.yaml).
    #[arg(long, required = true)]
    pub(crate) bootnodes: Option<PathBuf>,
    /// Path to validator-config.yaml (validator name registry for metrics labels).
    #[arg(long, required = true)]
    pub(crate) validator_config: Option<PathBuf>,
    /// Directory containing per-validator XMSS keys (e.g., hash-sig-keys/).
    #[arg(long, required = true)]
    pub(crate) hash_sig_keys_dir: Option<PathBuf>,
    #[arg(long, default_value = "9000")]
    pub(crate) gossipsub_port: u16,
    #[arg(long, default_value = "127.0.0.1")]
    pub(crate) http_address: IpAddr,
    #[arg(long, default_value = "5052")]
    pub(crate) api_port: u16,
    #[arg(long, default_value = "5054")]
    pub(crate) metrics_port: u16,
    #[arg(long, required = true)]
    pub(crate) node_key: Option<PathBuf>,
    /// The node ID to look up in annotated_validators.yaml (e.g., "ethlambda_0")
    #[arg(long, required = true)]
    pub(crate) node_id: Option<String>,
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
    /// Shadow-simulator sim-cost + fake-XMSS flags (only under the
    /// `shadow-integration` feature).
    #[cfg(feature = "shadow-integration")]
    #[command(flatten)]
    pub(crate) shadow: ShadowOptions,
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

#[derive(Debug, clap::Subcommand)]
pub(crate) enum Command {
    /// Benchmark block building offline against a controlled workload.
    Benchmark(crate::benchmark::BenchmarkOptions),
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;
    use clap::error::ErrorKind;

    /// The flat node invocation shape used by lean-quickstart, the Dockerfile,
    /// and the devnet skills. It must keep parsing unchanged.
    const FLAT_INVOCATION: &[&str] = &[
        "ethlambda",
        "--genesis",
        "config.yaml",
        "--validators",
        "annotated_validators.yaml",
        "--bootnodes",
        "nodes.yaml",
        "--validator-config",
        "validator-config.yaml",
        "--hash-sig-keys-dir",
        "hash-sig-keys/",
        "--node-key",
        "node.key",
        "--node-id",
        "ethlambda_0",
        "--gossipsub-port",
        "9001",
        "--is-aggregator",
    ];

    #[test]
    fn flat_node_invocation_parses_unchanged() {
        let options = CliOptions::try_parse_from(FLAT_INVOCATION).expect("flat invocation parses");
        assert!(options.command.is_none());
        assert_eq!(options.genesis.as_deref(), Some("config.yaml".as_ref()));
        assert_eq!(options.node_id.as_deref(), Some("ethlambda_0"));
        assert_eq!(options.gossipsub_port, 9001);
        assert!(options.is_aggregator);
    }

    #[test]
    fn missing_required_node_flag_keeps_clap_error() {
        let without_genesis: Vec<&str> = FLAT_INVOCATION
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != 1 && *i != 2)
            .map(|(_, arg)| *arg)
            .collect();
        let err = CliOptions::try_parse_from(without_genesis)
            .expect_err("missing --genesis must still error");
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn benchmark_subcommand_parses_without_node_args() {
        let options = CliOptions::try_parse_from([
            "ethlambda",
            "benchmark",
            "synthetic",
            "--mock-crypto",
            "--iterations",
            "3",
        ])
        .expect("benchmark subcommand parses without node args");
        assert!(matches!(options.command, Some(Command::Benchmark(_))));
        assert!(options.genesis.is_none());
        assert!(options.node_id.is_none());
    }

    #[test]
    fn node_flags_mixed_with_subcommand_are_rejected() {
        let err = CliOptions::try_parse_from([
            "ethlambda",
            "--genesis",
            "config.yaml",
            "benchmark",
            "synthetic",
        ])
        .expect_err("mixing node flags with a subcommand must be rejected");
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn mock_crypto_conflicts_with_proposer_aggregation() {
        let err = CliOptions::try_parse_from([
            "ethlambda",
            "benchmark",
            "synthetic",
            "--mock-crypto",
            "--enable-proposer-aggregation",
        ])
        .expect_err("--mock-crypto cannot drive real leanVM aggregation");
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn node_id_value_named_benchmark_is_not_a_subcommand() {
        let mut args: Vec<&str> = FLAT_INVOCATION.to_vec();
        let node_id_position = args
            .iter()
            .position(|arg| *arg == "ethlambda_0")
            .expect("node id value present");
        args[node_id_position] = "benchmark";
        let options =
            CliOptions::try_parse_from(args).expect("flag values must not become subcommands");
        assert!(options.command.is_none());
        assert_eq!(options.node_id.as_deref(), Some("benchmark"));
    }
}
