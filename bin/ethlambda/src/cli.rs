//! Command-line interface for the ethlambda binary.

use std::ffi::{OsStr, OsString};
use std::net::IpAddr;
use std::path::PathBuf;

use crate::version;

/// The subcommand a bare invocation resolves to.
const DEFAULT_SUBCOMMAND: &str = "lean";

/// Every first-position token that must reach clap untouched: the two
/// subcommands, clap's generated `help` subcommand, and the top-level help and
/// version flags.
const PASSTHROUGH: [&str; 7] = ["lean", "beacon", "help", "-h", "--help", "-V", "--version"];

#[derive(Debug, clap::Parser)]
#[command(name = "ethlambda", author = "LambdaClass", version = version::CLIENT_VERSION, about = "ethlambda consensus client")]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

/// The chain this process follows.
///
/// Both payloads are boxed. `LeanOptions` carries a dozen more fields than
/// `BeaconOptions`, and an unboxed enum is as large as its largest variant
/// everywhere it is moved.
#[derive(Debug, clap::Subcommand)]
pub(crate) enum Command {
    /// Run the lean consensus client. This is the default: an invocation whose
    /// first argument is not a subcommand has `lean` inserted ahead of it, so
    /// every existing bare-flag caller keeps working.
    Lean(Box<LeanOptions>),
    /// Follow the Ethereum Beacon Chain.
    Beacon(Box<BeaconOptions>),
}

/// Insert the default `lean` subcommand when argv does not start with one.
///
/// clap has no native default subcommand, and every existing caller passes bare
/// flags: the Docker `ENTRYPOINT`, `lean-quickstart`'s `ethlambda-cmd.sh`, the
/// Hive client shim, `preview-config.nix`, and the `docker run` blocks in
/// `.claude/skills/devnet-runner/`. Rewriting argv is what keeps all of them
/// working unedited, and it keeps `--help` free of the duplicated argument
/// groups that clap's `args_conflicts_with_subcommands` pattern produces.
///
/// The rule is one line: pass through if the first argument is in
/// [`PASSTHROUGH`], otherwise insert [`DEFAULT_SUBCOMMAND`] ahead of it. `--` is
/// not special-cased, so `ethlambda -- x` becomes `ethlambda lean -- x`; neither
/// subcommand takes positional arguments, so both spellings end in a clap error
/// and the injection only decides which command it names.
///
/// An argv with nothing past the program name is left alone, so a bare
/// `ethlambda` prints the subcommand listing rather than `lean`'s
/// missing-flag error.
pub(crate) fn inject_default_subcommand<I, T>(args: I) -> Vec<OsString>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let mut args: Vec<OsString> = args.into_iter().map(Into::into).collect();
    let Some(first) = args.get(1) else {
        return args;
    };
    let passes_through = PASSTHROUGH
        .iter()
        .copied()
        .any(|name| first.as_os_str() == OsStr::new(name));
    if !passes_through {
        args.insert(1, OsString::from(DEFAULT_SUBCOMMAND));
    }
    args
}

/// Flags every subcommand takes, with the same meaning and the same
/// requiredness on each.
///
/// `--node-id`, `--bootnodes`, `--checkpoint-sync-url`, and `--discovery.*` are
/// deliberately not here even though the design document groups them as common:
/// each of them is required on one subcommand and optional or absent on the
/// other, and a flattened struct has one requiredness.
#[derive(Debug, clap::Args)]
pub(crate) struct CommonOptions {
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
    /// Directory for RocksDB storage
    #[arg(long, default_value = "./data")]
    pub(crate) data_dir: PathBuf,
}

/// Flags for the lean consensus client.
#[derive(Debug, clap::Args)]
pub(crate) struct LeanOptions {
    #[command(flatten)]
    pub(crate) common: CommonOptions,
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
    /// Requires `--discovery.port` to differ from `--gossipsub-port`: both are
    /// UDP sockets and they cannot share one port.
    #[arg(long = "discovery.enable", default_value = "false")]
    pub(crate) enable: bool,
    /// UDP port for the discv5 socket.
    ///
    /// Independent of `--gossipsub-port`, which carries libp2p QUIC. Both
    /// default to 9000, so enabling discovery means changing one of them.
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
}

impl LeanOptions {
    /// Reject a discovery port that collides with the QUIC port.
    ///
    /// Both are UDP. Without this the collision surfaces at bind time as an
    /// opaque `EADDRINUSE` on whichever socket loses the race.
    pub(crate) fn validate_discovery(&self) -> Result<(), String> {
        if self.discovery.enable && self.discovery.port == self.common.gossipsub_port {
            return Err(format!(
                "--discovery.port ({}) must differ from --gossipsub-port ({}): \
                 both bind UDP and cannot share a port",
                self.discovery.port, self.common.gossipsub_port
            ));
        }
        Ok(())
    }
}

/// Flags for `ethlambda beacon`, the Ethereum Beacon Chain follower.
#[derive(Debug, clap::Args)]
pub(crate) struct BeaconOptions {
    #[command(flatten)]
    pub(crate) common: CommonOptions,
    /// Base URL(s) of Beacon API servers to take the anchor from, e.g.
    /// `https://checkpointz.example`.
    ///
    /// Required, unlike lean's flag of the same name. The anchor state is the
    /// only source of `genesis_validators_root` and `genesis_time`, and the
    /// fork digest that keys every gossip topic, the ENR `eth2` entry, and
    /// discv5 admission is computed from them. Multiple URLs may be supplied
    /// comma-separated or by repeating the flag; they are tried in order.
    #[arg(long, value_delimiter = ',', required = true)]
    pub(crate) checkpoint_sync_url: Vec<String>,
    /// Path to a bootnode list (ENRs, one per YAML entry) replacing the
    /// built-in mainnet list.
    #[arg(long)]
    pub(crate) bootnodes: Option<PathBuf>,
    #[command(flatten)]
    pub(crate) discovery: BeaconDiscoveryConfig,
}

/// discv5 peer discovery for `ethlambda beacon`.
///
/// There is no `--discovery.enable` here, by design: published mainnet bootnode
/// ENRs carry no `quic` entry, so none of them is statically dialable and a
/// crawl is the only way to reach a peer. Discovery is always on for this
/// subcommand.
#[derive(Debug, clap::Args)]
pub(crate) struct BeaconDiscoveryConfig {
    /// UDP port for the discv5 socket. Defaults to `--gossipsub-port` + 1,
    /// which keeps it off the QUIC port without the operator picking a number.
    #[arg(long = "discovery.port")]
    pub(crate) port: Option<u16>,
    /// IP address to advertise in the ENR.
    ///
    /// Defaults to the bind address, which is the wildcard `0.0.0.0` and is not
    /// dialable as published. discv5's PONG-based IP voting may still replace
    /// it at runtime.
    #[arg(long = "discovery.advertise-ip")]
    pub(crate) advertise_ip: Option<IpAddr>,
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
    use clap::Parser;

    /// The smallest argv that satisfies every required `lean` flag, with no
    /// subcommand: exactly the shape every existing caller uses.
    fn base_args() -> Vec<&'static str> {
        vec![
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
        ]
    }

    /// Parse a bare-flag argv exactly the way `main` does.
    fn parse_lean(args: Vec<&str>) -> LeanOptions {
        match Cli::parse_from(inject_default_subcommand(args)).command {
            Command::Lean(options) => *options,
            Command::Beacon(_) => panic!("bare flags must resolve to the lean subcommand"),
        }
    }

    /// Render an injector result for comparison against a plain string list.
    fn as_strings(args: &[OsString]) -> Vec<&str> {
        args.iter()
            .map(|arg| arg.to_str().expect("test argv is utf-8"))
            .collect()
    }

    #[test]
    fn discovery_is_disabled_by_default_on_port_9000() {
        let opts = parse_lean(base_args());
        assert!(!opts.discovery.enable);
        assert_eq!(opts.discovery.port, 9000);
    }

    #[test]
    fn discovery_flags_use_a_dotted_prefix() {
        let mut args = base_args();
        args.extend(["--discovery.enable", "--discovery.port", "9010"]);
        let opts = parse_lean(args);
        assert!(opts.discovery.enable);
        assert_eq!(opts.discovery.port, 9010);
    }

    #[test]
    fn discovery_port_may_equal_gossipsub_port_until_validated() {
        // Both default to 9000. Parsing accepts it; validate_discovery rejects it
        // so the failure names the real problem instead of surfacing as EADDRINUSE.
        let mut args = base_args();
        args.push("--discovery.enable");
        let opts = parse_lean(args);
        assert_eq!(opts.discovery.port, opts.common.gossipsub_port);
        assert!(opts.validate_discovery().is_err());
    }

    #[test]
    fn distinct_ports_validate() {
        let mut args = base_args();
        args.extend(["--discovery.enable", "--discovery.port", "9010"]);
        let opts = parse_lean(args);
        assert!(opts.validate_discovery().is_ok());
    }

    #[test]
    fn colliding_ports_are_fine_while_discovery_is_off() {
        let opts = parse_lean(base_args());
        assert_eq!(opts.discovery.port, opts.common.gossipsub_port);
        assert!(opts.validate_discovery().is_ok());
    }

    #[test]
    fn advertise_ip_defaults_to_none() {
        let opts = parse_lean(base_args());
        assert_eq!(opts.discovery.advertise_ip, None);
    }

    #[test]
    fn advertise_ip_parses_an_explicit_address() {
        let mut args = base_args();
        args.extend(["--discovery.advertise-ip", "203.0.113.7"]);
        let opts = parse_lean(args);
        assert_eq!(
            opts.discovery.advertise_ip,
            Some(std::net::IpAddr::from([203, 0, 113, 7]))
        );
    }

    /// The contract every existing caller depends on: the Docker ENTRYPOINT,
    /// lean-quickstart's ethlambda-cmd.sh, the Hive client shim,
    /// preview-config.nix, and the devnet-runner `docker run` blocks all pass
    /// bare flags with no subcommand.
    #[test]
    fn bare_flags_get_the_lean_subcommand() {
        let args = inject_default_subcommand(["ethlambda", "--genesis", "config.yaml"]);
        assert_eq!(
            as_strings(&args),
            ["ethlambda", "lean", "--genesis", "config.yaml"]
        );
    }

    #[test]
    fn an_explicit_lean_subcommand_is_left_alone() {
        let args = inject_default_subcommand(["ethlambda", "lean", "--genesis", "config.yaml"]);
        assert_eq!(
            as_strings(&args),
            ["ethlambda", "lean", "--genesis", "config.yaml"]
        );
    }

    #[test]
    fn an_explicit_beacon_subcommand_is_left_alone() {
        let args = inject_default_subcommand([
            "ethlambda",
            "beacon",
            "--checkpoint-sync-url",
            "https://checkpointz.example",
        ]);
        assert_eq!(
            as_strings(&args),
            [
                "ethlambda",
                "beacon",
                "--checkpoint-sync-url",
                "https://checkpointz.example"
            ]
        );
    }

    #[test]
    fn the_generated_help_subcommand_is_left_alone() {
        // clap adds a `help` subcommand of its own as soon as subcommands
        // exist. Injecting ahead of it would turn `ethlambda help beacon` into
        // `ethlambda lean help beacon`, which prints the wrong page.
        let args = inject_default_subcommand(["ethlambda", "help", "beacon"]);
        assert_eq!(as_strings(&args), ["ethlambda", "help", "beacon"]);
    }

    #[test]
    fn help_and_version_flags_are_left_alone() {
        // These four belong to the top-level command. `--version` is not
        // propagated to subcommands, so injecting would turn it into an
        // "unexpected argument" error.
        for flag in ["-h", "--help", "-V", "--version"] {
            let args = inject_default_subcommand(["ethlambda", flag]);
            assert_eq!(
                as_strings(&args),
                ["ethlambda", flag],
                "{flag} must reach the top-level command"
            );
        }
    }

    #[test]
    fn an_argv_with_only_the_program_name_is_left_alone() {
        // A bare `ethlambda` then prints clap's subcommand listing, which is
        // the right answer now that there are two chains to choose from.
        // Nothing regresses: today's binary already exits non-zero there,
        // because --genesis and six other flags are required.
        let args = inject_default_subcommand(["ethlambda"]);
        assert_eq!(as_strings(&args), ["ethlambda"]);
    }

    #[test]
    fn an_empty_argv_is_left_alone() {
        // `execve` can hand a process an argv with no program name at all.
        // Indexing instead of checking would panic here.
        let args = inject_default_subcommand(Vec::<&str>::new());
        assert!(args.is_empty());
    }

    #[test]
    fn a_leading_double_dash_gets_the_lean_subcommand() {
        // `--` is not special-cased: it is not a subcommand name, so it takes
        // the default like any other first token. Neither subcommand accepts
        // positional arguments, so this argv is an error either way; the
        // injection only decides which command the error names.
        let args = inject_default_subcommand(["ethlambda", "--", "--genesis"]);
        assert_eq!(as_strings(&args), ["ethlambda", "lean", "--", "--genesis"]);
    }

    #[test]
    fn a_help_flag_after_the_first_argument_is_not_special() {
        // Only the first argument is classified, so this `--help` is lean's.
        let args = inject_default_subcommand(["ethlambda", "--genesis", "config.yaml", "--help"]);
        assert_eq!(
            as_strings(&args),
            ["ethlambda", "lean", "--genesis", "config.yaml", "--help"]
        );
    }

    #[test]
    fn bare_flags_parse_as_the_lean_subcommand() {
        let options = parse_lean(base_args());
        assert_eq!(options.genesis, PathBuf::from("config.yaml"));
        assert_eq!(options.node_id, "ethlambda_0");
        assert_eq!(options.common.api_port, 5052);
    }

    #[test]
    fn an_explicit_lean_subcommand_parses_the_same_flags() {
        let mut args = vec!["ethlambda", "lean"];
        args.extend(base_args().into_iter().skip(1));
        let Command::Lean(options) = Cli::parse_from(args).command else {
            panic!("`lean` must resolve to the lean subcommand");
        };
        assert_eq!(options.genesis, PathBuf::from("config.yaml"));
        assert_eq!(options.node_id, "ethlambda_0");
    }

    #[test]
    fn the_beacon_subcommand_parses() {
        let Command::Beacon(options) = Cli::parse_from([
            "ethlambda",
            "beacon",
            "--node-key",
            "node.key",
            "--checkpoint-sync-url",
            "https://checkpointz.example",
        ])
        .command
        else {
            panic!("`beacon` must resolve to the beacon subcommand");
        };
        assert_eq!(options.checkpoint_sync_url, ["https://checkpointz.example"]);
        assert_eq!(options.common.node_key, PathBuf::from("node.key"));
        // No flag given, so the built-in mainnet ENR list applies.
        assert_eq!(options.bootnodes, None);
    }

    #[test]
    fn beacon_requires_a_checkpoint_sync_url() {
        // The anchor state is the only source of genesis_validators_root, and
        // therefore of the fork digest every topic and the ENR are keyed on.
        let result = Cli::try_parse_from(["ethlambda", "beacon", "--node-key", "node.key"]);
        assert!(
            result.is_err(),
            "--checkpoint-sync-url must be required on beacon"
        );
    }

    #[test]
    fn beacon_requires_a_node_key() {
        let result = Cli::try_parse_from([
            "ethlambda",
            "beacon",
            "--checkpoint-sync-url",
            "https://checkpointz.example",
        ]);
        assert!(
            result.is_err(),
            "--node-key is common and required on both subcommands"
        );
    }

    #[test]
    fn beacon_rejects_lean_only_flags() {
        let result = Cli::try_parse_from([
            "ethlambda",
            "beacon",
            "--node-key",
            "node.key",
            "--checkpoint-sync-url",
            "https://checkpointz.example",
            "--genesis",
            "config.yaml",
        ]);
        assert!(
            result.is_err(),
            "--genesis is a lean flag and must not parse under beacon"
        );
    }

    #[test]
    fn beacon_has_no_discovery_enable_flag() {
        // Mainnet bootnode ENRs carry no `quic` entry, so none of them is
        // statically dialable and a crawl is the only way to find a peer.
        // Discovery is forced on, which means there is nothing to toggle.
        let result = Cli::try_parse_from([
            "ethlambda",
            "beacon",
            "--node-key",
            "node.key",
            "--checkpoint-sync-url",
            "https://checkpointz.example",
            "--discovery.enable",
        ]);
        assert!(result.is_err(), "beacon must not accept --discovery.enable");
    }

    #[test]
    fn lean_still_requires_its_own_flags() {
        // The subcommand split is what makes this a clap error rather than a
        // hand-written check over Option fields.
        let result = Cli::try_parse_from(["ethlambda", "lean", "--node-key", "node.key"]);
        assert!(
            result.is_err(),
            "lean must still require --genesis and the rest"
        );
    }

    #[test]
    fn the_command_tree_is_well_formed() {
        // clap's own assertions: duplicate argument ids, dangling `requires`
        // targets, defaults that conflict with a value parser. Flattening one
        // struct into two subcommands is exactly the shape that trips them.
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
