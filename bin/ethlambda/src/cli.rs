//! Command-line interface for the ethlambda binary.

use ethlambda_p2p::discovery::DEFAULT_DISCOVERY_TARGET_PEERS;
use ethlambda_types::beacon::constants::SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY;
use std::net::IpAddr;
use std::path::PathBuf;

/// Flags every sub-command takes, with the same meaning on each.
///
/// `--node-key`, `--bootnodes` and `--checkpoint-sync-url` used to be declared
/// once per sub-command because each was required on one and optional on the
/// other, and a flattened struct has one requiredness. They are optional on
/// both now, which is what lets one declaration serve both: each sub-command
/// decides what an absent value means, and says so on the field below.
///
/// The `--discovery.*` flags are here too, in one [`DiscoveryConfig`], and mean
/// the same thing on both: discv5 is always on, on [`DEFAULT_DISCOVERY_PORT`]
/// unless `--discovery.port` says otherwise. See
/// [`CommonOptions::validate_ports`].
///
/// `--node-id` is still not here: it exists only on `node`.
#[derive(Debug, clap::Args)]
pub(crate) struct CommonOptions {
    /// Port for the libp2p listeners: UDP for QUIC and TCP for the noise+yamux
    /// fallback, both on this same number.
    ///
    /// TCP and UDP are separate namespaces, so one number names both. It must
    /// still differ from every other port the node binds: `--discovery.port`
    /// (also UDP), and `--api-port`/`--metrics-port` (also TCP).
    ///
    /// Defaults one above the discv5 port, since both are UDP sockets and
    /// cannot share a port.
    #[arg(long, default_value = "9001")]
    pub(crate) gossipsub_port: u16,
    #[arg(long, default_value = "127.0.0.1")]
    pub(crate) http_address: IpAddr,
    #[arg(long, default_value = "5052")]
    pub(crate) api_port: u16,
    #[arg(long, default_value = "5054")]
    pub(crate) metrics_port: u16,
    /// Directory for RocksDB storage
    #[arg(long, default_value = "./data")]
    pub(crate) data_dir: PathBuf,
    /// Hex file holding the secp256k1 key that is this node's libp2p and
    /// discv5 identity.
    ///
    /// Optional on both sub-commands. When omitted, a fresh key is generated
    /// in memory at startup (logged as a warning) and used for that run only,
    /// so the PeerId and ENR differ on the next start. Pass a persisted key
    /// file for a stable identity.
    #[arg(long)]
    pub(crate) node_key: Option<PathBuf>,
    /// Path to a bootnode list: ENRs, one per YAML entry.
    ///
    /// Optional on both sub-commands, but an absent file means different
    /// things. `beacon` falls back to whatever `--network` resolved to: a
    /// built-in network's own ENR list, or a loaded directory's own
    /// `bootstrap_nodes.yaml`/`.txt` (empty if the directory has neither).
    /// `node` has no built-in list for a lean network, so it starts with no
    /// bootnodes and reaches peers only through discv5, if that is enabled.
    #[arg(long)]
    pub(crate) bootnodes: Option<PathBuf>,
    /// Base URL(s) of the peer API servers to take a checkpoint from, e.g.
    /// `http://peer:5052`.
    ///
    /// Multiple URLs may be supplied for redundancy, either comma-separated
    /// (`--checkpoint-sync-url u1,u2`) or by repeating the flag
    /// (`--checkpoint-sync-url u1 --checkpoint-sync-url u2`). URLs are tried
    /// in order; the first one that succeeds is used and any failures fall
    /// over to the next. Startup only aborts if every URL fails.
    ///
    /// On `node` this reads each peer's `/lean/v0/states/finalized` and
    /// `/lean/v0/blocks/finalized`, and is a fallback rather than a
    /// precedence: state already in the data directory always wins, so these
    /// URLs are only used when there is no resumable state on disk (or it has
    /// fallen too far behind the current slot). With neither resumable state
    /// nor URLs, the node starts from genesis. For backward compatibility a
    /// URL ending in `/lean/v0/states/finalized` is accepted and the trailing
    /// path is stripped.
    ///
    /// On `beacon` this reads each peer's standard Beacon API,
    /// `/eth/v2/debug/beacon/states/finalized` and `/eth/v2/beacon/blocks/{slot}`,
    /// with the same resumable-directory precedence `node` uses, plus one more
    /// fallback below it. A network loaded with `--network` (a directory of
    /// published files) anchors at its own `genesis.ssz` when there is
    /// neither a resumable directory nor a URL, since a freshly started devnet
    /// has no checkpoint provider at slot 0 and this is the only way to join
    /// one. The built-in networks (`mainnet`, `sepolia`, `hoodi`) still refuse
    /// that fallback: each has been live for years, and this follower imports
    /// nothing at startup, so anchoring there would park it at slot 0 while
    /// claiming to follow a live chain. With neither a resumable directory, a
    /// URL, nor a loaded network's genesis, startup aborts.
    #[arg(long, value_delimiter = ',')]
    pub(crate) checkpoint_sync_url: Vec<String>,
    #[command(flatten)]
    pub(crate) discovery: DiscoveryConfig,
}

/// Which chain this process follows, and the flags only that chain takes.
///
/// Lean's payload lives in the variant rather than beside it: `--genesis` and
/// the validator flags mean nothing to a beacon follower, so holding them in
/// one flat struct would make them `Option` and leave `run_node` unwrapping
/// what the tag promised was there.
#[derive(Debug)]
pub(crate) enum Network {
    /// The lean consensus chain this repo implements: `ethlambda node`.
    Lean(Box<LeanOptions>),
    /// The Ethereum Beacon Chain: `ethlambda beacon`.
    ///
    /// Carries this chain's own flags and `execution`, the execution client
    /// its payloads are validated against. Everything else it needs is a
    /// common flag.
    Mainnet {
        mainnet: MainnetOptions,
        execution: Option<ExecutionOptions>,
    },
}

/// The execution client pairing, present only when both flags were supplied.
///
/// A struct rather than two `Option`s on the variant, so "endpoint without
/// secret" cannot be represented past this point: `From<BeaconOptions>` is
/// where the pair is checked, once.
#[derive(Debug)]
pub(crate) struct ExecutionOptions {
    pub(crate) endpoint: String,
    pub(crate) jwt_secret: PathBuf,
}

/// Everything [`crate::run_node`] needs, for either chain.
///
/// One entry point takes this, so the startup steps that are not
/// chain-specific happen once and in one order: metrics registration, the
/// version banner, the file-descriptor limit, the node key, the HTTP server
/// and the shutdown sequence.
#[derive(Debug)]
pub(crate) struct Options {
    pub(crate) common: CommonOptions,
    pub(crate) network: Network,
}

impl From<NodeOptions> for Options {
    fn from(options: NodeOptions) -> Self {
        Options {
            common: options.common,
            network: Network::Lean(Box::new(options.lean)),
        }
    }
}

impl From<BeaconOptions> for Options {
    fn from(options: BeaconOptions) -> Self {
        let execution = match (options.execution_endpoint, options.execution_jwt_secret) {
            (Some(endpoint), Some(jwt_secret)) => Some(ExecutionOptions {
                endpoint,
                jwt_secret,
            }),
            (None, None) => None,
            // Unreachable: `requires` on each of the two flags is what rules a
            // half-configured Engine API out, so the parser answers a mismatch
            // with a usage error long before this conversion runs.
            // `cli::tests::execution_flags_come_as_a_pair` pins that.
            _ => unreachable!(
                "clap's `requires` rejects --execution-endpoint without \
                 --execution-jwt-secret, and the reverse"
            ),
        };

        Options {
            common: options.common,
            network: Network::Mainnet {
                mainnet: options.mainnet,
                execution,
            },
        }
    }
}

/// The `node` sub-command's argv: the common flags plus lean's own.
///
/// The `node` sub-command owns the top-level `Parser` attributes, so this is a
/// plain `Args`: see `crate::command`. It exists to be parsed and then
/// converted into [`Options`]; nothing reads it directly.
#[derive(Debug, clap::Args)]
pub(crate) struct NodeOptions {
    #[command(flatten)]
    pub(crate) common: CommonOptions,
    #[command(flatten)]
    pub(crate) lean: LeanOptions,
}

/// The `beacon` sub-command's argv: the common flags plus this chain's own.
///
/// Mirrors [`NodeOptions`], which is the point: a flag that means nothing to
/// the other chain lives in that chain's struct, so neither `run_node` arm has
/// to unwrap an `Option` the tag already promised was there. Beyond
/// [`MainnetOptions`], it carries the execution client pairing
/// (`--execution-endpoint` and `--execution-jwt-secret`, which are given
/// together or not at all), whose checked form is what `Network::Mainnet`
/// holds.
#[derive(Debug, clap::Args)]
pub(crate) struct BeaconOptions {
    #[command(flatten)]
    pub(crate) common: CommonOptions,
    #[command(flatten)]
    pub(crate) mainnet: MainnetOptions,

    /// Base URL of the execution client's Engine API endpoint, e.g.
    /// `http://127.0.0.1:8551`.
    ///
    /// Paired with `--execution-jwt-secret`: supplying one without the other is
    /// a usage error, since an Engine API endpoint always requires
    /// authentication. With neither, this node imports blocks without asking
    /// any execution client about their payloads, which is what it did before
    /// this flag existed.
    #[arg(long, requires = "execution_jwt_secret")]
    pub(crate) execution_endpoint: Option<String>,

    /// File holding the 32-byte hex JWT secret shared with the execution
    /// client.
    #[arg(long, requires = "execution_endpoint")]
    pub(crate) execution_jwt_secret: Option<PathBuf>,
}

/// Flags only the beacon chain takes.
#[derive(Debug, clap::Args)]
pub(crate) struct MainnetOptions {
    /// How many custody groups this node custodies, advertised as the ENR's
    /// `cgc` and used to size its own custody set.
    ///
    /// Raising it makes this node useful to more peers and costs it storage and
    /// bandwidth in proportion: a node at `NUMBER_OF_CUSTODY_GROUPS` is a
    /// supernode, custodying every column. Lowering it is not possible below
    /// `CUSTODY_REQUIREMENT`, which the specification makes the floor every
    /// node must meet.
    ///
    /// Note this is not the number of columns custodied. That is
    /// `sampling_size`, the larger of this and `SAMPLES_PER_SLOT`, so the
    /// default of `CUSTODY_REQUIREMENT` still custodies `SAMPLES_PER_SLOT`
    /// columns; the two only coincide once this is raised past that floor.
    ///
    /// Changing it changes which columns this node custodies, so sidecars
    /// already on disk belong to the old set. Nothing is corrupted by that,
    /// but the node serves a set it has not finished filling until it has
    /// backfilled the difference.
    #[arg(
        long = "custody-group-count",
        default_value_t = ethlambda_types::beacon::constants::CUSTODY_REQUIREMENT,
        value_parser = clap::value_parser!(u64).range(
            ethlambda_types::beacon::constants::CUSTODY_REQUIREMENT
                ..=ethlambda_types::beacon::constants::NUMBER_OF_CUSTODY_GROUPS
        ),
    )]
    pub(crate) custody_group_count: u64,

    /// How far behind the wall clock a block must be before it may be imported
    /// optimistically on age alone.
    ///
    /// `optimistic-sync.md` requires this to be operator-configurable, for
    /// manual recovery from a poisoned fork choice store. It only ever gates a
    /// merge transition block, which a mainnet follower anchored past the merge
    /// never sees.
    #[arg(long, default_value_t = SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY)]
    pub(crate) safe_slots_to_import_optimistically: u64,

    /// Which network to follow: a built-in name (`mainnet`, `sepolia` or
    /// `hoodi`), or a path to a directory of published network files.
    ///
    /// A value containing a slash is always read as a directory, so `mainnet`
    /// names the built-in network and `./mainnet` names a directory. The
    /// directory must hold `config.yaml` and `genesis.ssz`, and may hold
    /// `bootstrap_nodes.yaml` or `bootstrap_nodes.txt`; this is the layout
    /// `eth-clients` publishes and kurtosis mounts at `/network-configs`.
    #[arg(long, default_value = crate::network::DEFAULT_NETWORK)]
    pub(crate) network: String,
}

/// Flags only the lean chain takes.
#[derive(Debug, clap::Args)]
pub(crate) struct LeanOptions {
    /// Path to the chain genesis config (e.g., config.yaml).
    #[arg(long)]
    pub(crate) genesis: PathBuf,
    /// Path to the validator registry (e.g., annotated_validators.yaml).
    #[arg(long)]
    pub(crate) validators: PathBuf,
    /// Path to validator-config.yaml (validator name registry for metrics labels).
    #[arg(long)]
    pub(crate) validator_config: PathBuf,
    /// Directory containing per-validator XMSS keys (e.g., hash-sig-keys/).
    #[arg(long)]
    pub(crate) hash_sig_keys_dir: PathBuf,
    /// The node ID to look up in annotated_validators.yaml (e.g., "ethlambda_0")
    #[arg(long)]
    pub(crate) node_id: String,
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
    /// Every ID must be below --attestation-committee-count; the node refuses to
    /// start otherwise, since a higher ID names a topic no validator publishes on.
    ///
    /// The first ID is also this node's aggregation duty subnet: where its
    /// aggregation window starts, and what --skip-redundant-aggregation
    /// rotates ownership over. Order matters, so give co-located aggregators
    /// different first IDs. Unset, the duty subnet falls back to the lowest
    /// subscribed subnet, which is the same value on every node whose
    /// validators span all subnets.
    #[arg(long, value_delimiter = ',', requires = "is_aggregator")]
    pub(crate) aggregate_subnet_ids: Option<Vec<u64>>,
    /// Sit out aggregation candidates whose level another duty subnet owns
    /// this slot. Requires --is-aggregator.
    ///
    /// By default every aggregator merges proofs for a window of subnets
    /// starting at its duty subnet, and windows belonging to neighbouring duty
    /// subnets overlap, so some prover work is duplicated. With this flag an
    /// aggregator skips a candidate whose width it does not own in the current
    /// slot and spends that job on the next-best attestation data instead. The
    /// owner rotates with the slot, so no node is permanently the one sitting
    /// out, and the narrowest width is owned by everyone, so a candidate whose
    /// pool holds nothing on this node's subnet, which is the raw-signature
    /// case, is never skipped.
    ///
    /// Worth enabling when leanVM prover CPU is the bottleneck on co-located
    /// aggregators.
    ///
    /// Deployment precondition: give every subnet below
    /// --attestation-committee-count an aggregator holding it as its duty
    /// subnet. Ownership is `duty_subnet % width == slot % width`, so on a
    /// sparser placement a width can have no owner at all while every
    /// configured node is healthy. With duty subnets {0, 2} at committee count
    /// 4, nothing owns width 4 in an odd slot, and since this flag also
    /// disables the full-width fallback, that merge level is simply dropped
    /// for the slot. The narrower levels still run and the next slot rotates to
    /// a different owner, but the loss is structural, not just the cost of a
    /// node that is down or late.
    #[arg(long, default_value = "false", requires = "is_aggregator")]
    pub(crate) skip_redundant_aggregation: bool,
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
    /// Prove on leanVM's bump arena instead of the system allocator.
    ///
    /// Buys proving throughput with memory: the arena's slabs stay faulted in
    /// across proofs (a phase reset abandons their contents, it does not return
    /// the pages), and on Linux it also stops glibc trimming its own heap. RSS
    /// therefore ratchets up to the process's allocation high-water mark and
    /// stays there for the lifetime of the node. Off by default so a long-lived
    /// node keeps bounded memory; worth enabling on hosts with memory to spare
    /// where proving latency is the constraint.
    ///
    /// Read once at startup: the allocator is fixed before the first proof.
    #[arg(long, default_value = "false")]
    pub(crate) prover_arena: bool,
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

/// The discv5 peer-discovery flags, taken by both chains and meaning the same
/// thing on each.
///
/// There is no `--discovery.enable`: discv5 is always on. `beacon` never had a
/// choice, since published mainnet bootnode ENRs carry no `quic` entry and so
/// are not statically dialable, and a lean node given no `--bootnodes` file has
/// no other way to reach a peer either. What used to be the off switch is now
/// the bootnode list plus whatever the crawl finds.
#[derive(Debug, clap::Args)]
pub(crate) struct DiscoveryConfig {
    /// UDP port for the discv5 socket. Must differ from `--gossipsub-port`:
    /// both bind UDP and cannot share a port.
    #[arg(long = "discovery.port", default_value_t = DEFAULT_DISCOVERY_PORT)]
    pub(crate) port: u16,
    /// IP address to advertise in the ENR.
    ///
    /// Defaults to the bind address, which is the wildcard `0.0.0.0` and is not
    /// dialable as published. Set this to the address peers should reach this
    /// node on: `127.0.0.1` for a local devnet, or the host's public address.
    /// discv5's PONG-based IP voting may still replace it at runtime.
    #[arg(long = "discovery.advertise-ip")]
    pub(crate) advertise_ip: Option<IpAddr>,
    /// How many peers this node holds.
    ///
    /// The dial loop stops above it and resumes as soon as the connected count
    /// drops back below, and on `beacon` it is also what the swarm's own
    /// connection limits are derived from: the ceiling itself, the share of it
    /// inbound demand may hold, and the rest, reserved for peers this node
    /// dials. One number, so a reservation the swarm does not keep is never one
    /// the dial loop chases. See `beacon::swarm::max_connections`.
    ///
    /// 0 therefore means "hold no peers", dialing none and admitting none, not
    /// "serve without dialing". Discv5's own lookup pacing is unaffected either
    /// way: the loop keeps ticking and the crawl keeps running.
    #[arg(long = "discovery.target-peers", default_value_t = DEFAULT_DISCOVERY_TARGET_PEERS)]
    pub(crate) target_peers: usize,
}

/// The discv5 port both chains bind when `--discovery.port` is absent.
///
/// A fixed number rather than one derived from `--gossipsub-port`: devnet
/// configuration has passed this pair explicitly since discv5 landed, and
/// changing what an absent flag means would move a running network's socket.
pub(crate) const DEFAULT_DISCOVERY_PORT: u16 = 9000;

impl CommonOptions {
    /// Reject port assignments that cannot all bind, before anything binds.
    ///
    /// Called once at the top of `run_node`, for either chain, so a port that
    /// cannot work aborts before the metrics registry, the file-descriptor
    /// limit and the data directory are touched.
    ///
    /// There are two clashes to catch, on two protocols. `--discovery.port` and
    /// `--gossipsub-port` are both UDP. `--gossipsub-port` also binds TCP for
    /// the noise+yamux listener, which puts it in the same namespace as the
    /// HTTP servers: sharing that number with `--api-port` was legal while the
    /// swarm bound UDP only, and is now a real collision. Without these checks
    /// either surfaces at bind time as an opaque `EADDRINUSE` on whichever
    /// socket loses the race.
    ///
    /// The TCP comparisons skip `0`, which is not a port but a request for one:
    /// two `0` binds always land on different OS-assigned ports and can never
    /// collide. Rejecting a pair of them would refuse the setup that exists to
    /// avoid collisions, which test harnesses and several-nodes-per-host runs
    /// rely on. `--gossipsub-port 0` is rejected on its own grounds below, so
    /// the UDP comparison never sees one.
    pub(crate) fn validate_ports(&self) -> eyre::Result<()> {
        // discv5 is always on, so the ENR always names this port. Port 0 asks
        // the OS to pick, so the two listeners land on different real ports and
        // the record advertises neither of them: a peer reading it finds
        // nothing dialable.
        if self.gossipsub_port == 0 {
            eyre::bail!(
                "--gossipsub-port 0 cannot be used: discv5 publishes an ENR \
                 naming that port, which no peer can dial"
            );
        }
        let discovery_port = self.discovery.port;
        let gossipsub_port = self.gossipsub_port;
        if discovery_port == gossipsub_port {
            eyre::bail!(
                "--discovery.port ({discovery_port}) must differ from \
                 --gossipsub-port ({gossipsub_port}): both bind UDP and cannot \
                 share a port"
            );
        }
        for (flag, port) in [
            ("--api-port", self.api_port),
            ("--metrics-port", self.metrics_port),
        ] {
            if port == gossipsub_port {
                eyre::bail!(
                    "{flag} ({port}) must differ from --gossipsub-port \
                     ({gossipsub_port}): the libp2p swarm binds TCP on that \
                     port as well as UDP"
                );
            }
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

    /// The smallest argv that satisfies every required `node` flag, with no
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

    /// The required flags, so a test can vary only what it cares about.
    fn parse(extra: &[&str]) -> NodeOptions {
        let mut argv = base_args();
        argv.extend_from_slice(extra);
        parse_node(argv)
    }

    /// Parse a bare-flag argv exactly the way `main` does, through the real
    /// dispatch: `NodeOptions` is a `clap::Args` group, not a parser of its own.
    fn parse_node(args: Vec<&str>) -> NodeOptions {
        match try_parse_from(args).expect("node options parse") {
            Command::Node(options) => options,
            other => panic!("bare flags must resolve to the node subcommand, got {other:?}"),
        }
    }

    /// The two defaults have to work together: discv5 is always on, so a
    /// default discovery port equal to the default gossip port would make every
    /// out-of-the-box run fail the collision check.
    #[test]
    fn the_default_ports_do_not_collide_on_either_chain() {
        let node = parse(&[]);
        assert_eq!(node.common.discovery.port, DEFAULT_DISCOVERY_PORT);
        assert_ne!(DEFAULT_DISCOVERY_PORT, node.common.gossipsub_port);
        assert!(node.common.validate_ports().is_ok());

        let beacon = parse_beacon(beacon_args());
        assert_eq!(beacon.common.discovery.port, DEFAULT_DISCOVERY_PORT);
        assert_ne!(DEFAULT_DISCOVERY_PORT, beacon.common.gossipsub_port);
        assert!(beacon.common.validate_ports().is_ok());
    }

    /// Both sockets are UDP, so a clash cannot be left to bind time, where it
    /// surfaces as an opaque `EADDRINUSE` on whichever one loses the race.
    #[test]
    fn a_discovery_port_equal_to_the_gossipsub_port_is_rejected() {
        // Reached from either direction: move the gossip port onto the
        // discovery default, or the discovery port onto the gossip default.
        assert!(
            parse(&["--gossipsub-port", "9000"])
                .common
                .validate_ports()
                .is_err()
        );
        let mut args = beacon_args();
        args.extend(["--discovery.port", "9001"]);
        assert!(parse_beacon(args).common.validate_ports().is_err());
    }

    #[test]
    fn an_explicit_discovery_port_wins_on_both_chains() {
        let node = parse(&["--discovery.port", "9100"]);
        assert_eq!(node.common.discovery.port, 9100);
        assert!(node.common.validate_ports().is_ok());

        let mut args = beacon_args();
        args.extend(["--discovery.port", "9100"]);
        let beacon = parse_beacon(args);
        assert_eq!(beacon.common.discovery.port, 9100);
        assert!(beacon.common.validate_ports().is_ok());
    }

    /// Unlike the UDP clash above, this one has nothing to do with discovery:
    /// the swarm binds TCP either way, so an HTTP port sharing the number
    /// always loses one of the two listeners.
    #[test]
    fn an_http_port_sharing_the_gossipsub_port_is_rejected() {
        // A port no default claims, so only the flag under test collides and
        // the message can be checked for naming it.
        const SHARED: &str = "9100";

        for flag in ["--api-port", "--metrics-port"] {
            let err = parse(&["--gossipsub-port", SHARED, flag, SHARED])
                .common
                .validate_ports()
                .expect_err("a TCP clash with an HTTP port must be rejected");
            assert!(
                err.to_string().contains(flag),
                "the message must name the offending flag, got: {err}"
            );
        }
    }

    /// `--api-port` and `--metrics-port` sharing one number is supported (the
    /// RPC crate merges the routers onto a single listener), so the TCP check
    /// must not sweep that up.
    #[test]
    fn api_and_metrics_may_share_a_port() {
        let options = parse(&["--api-port", "5052", "--metrics-port", "5052"]);

        assert!(options.common.validate_ports().is_ok());
    }

    /// Port 0 leaves the two listeners on different OS-assigned ports, so the
    /// one number the ENR publishes describes neither. discv5 is always on, so
    /// there is no invocation left where that is harmless.
    #[test]
    fn gossipsub_port_zero_is_rejected() {
        let err = parse(&["--gossipsub-port", "0"])
            .common
            .validate_ports()
            .expect_err("gossipsub port 0 cannot be published in an ENR");
        assert!(
            !err.to_string().contains("must differ"),
            "0 must be rejected on its own grounds, not as a clash, got: {err}"
        );
    }

    /// Two `0`s are two OS-assigned ports, so the TCP equality checks must not
    /// read them as a clash: an HTTP port asking the OS to pick is a supported
    /// configuration, and the rejection it meets under `--gossipsub-port 0` has
    /// to be the ENR one above rather than a collision that is not there.
    #[test]
    fn port_zero_never_counts_as_a_clash() {
        for flag in ["--api-port", "--metrics-port"] {
            let err = parse(&["--gossipsub-port", "0", flag, "0"])
                .common
                .validate_ports()
                .expect_err("gossipsub port 0 stays invalid under discv5");
            assert!(
                !err.to_string().contains("must differ"),
                "0 == 0 must not be reported as a clash, got: {err}"
            );
        }
        assert!(
            parse(&["--api-port", "0", "--metrics-port", "0"])
                .common
                .validate_ports()
                .is_ok(),
            "HTTP ports asking the OS to pick must be accepted"
        );
    }

    #[test]
    fn bare_flags_parse_as_the_node_subcommand() {
        let options = parse_node(base_args());
        assert_eq!(options.lean.genesis, PathBuf::from("config.yaml"));
        assert_eq!(options.lean.node_id, "ethlambda_0");
        assert_eq!(options.common.api_port, 5052);
    }

    #[test]
    fn an_explicit_node_subcommand_parses_the_same_flags() {
        let mut args = vec!["ethlambda", "node"];
        args.extend(base_args().into_iter().skip(1));
        let Command::Node(options) = try_parse_from(args).expect("`node` parses") else {
            panic!("`node` must resolve to the node subcommand");
        };
        assert_eq!(options.lean.genesis, PathBuf::from("config.yaml"));
        assert_eq!(options.lean.node_id, "ethlambda_0");
    }

    #[test]
    fn the_beacon_subcommand_parses() {
        let Command::Beacon(options) = try_parse_from([
            "ethlambda",
            "beacon",
            "--node-key",
            "node.key",
            "--checkpoint-sync-url",
            "https://checkpointz.example",
        ])
        .expect("`beacon` parses") else {
            panic!("`beacon` must resolve to the beacon subcommand");
        };
        assert_eq!(
            options.common.checkpoint_sync_url,
            ["https://checkpointz.example"]
        );
        assert_eq!(options.common.node_key, Some(PathBuf::from("node.key")));
        // No flag given, so the built-in mainnet ENR list applies.
        assert_eq!(options.common.bootnodes, None);
    }

    /// Drop `flag` and the value after it from an argv.
    fn without(args: &[&'static str], flag: &str) -> Vec<&'static str> {
        let at = args
            .iter()
            .position(|arg| *arg == flag)
            .unwrap_or_else(|| panic!("{flag} is in the argv"));
        let mut args = args.to_vec();
        args.drain(at..=at + 1);
        args
    }

    /// The three flags that moved into [`CommonOptions`] are optional on both
    /// sub-commands, so clap accepts an argv carrying none of them. What an
    /// absent value *means* is each sub-command's own decision, made at
    /// startup in `main`; the two tests after this one pin the answers that
    /// are not simply "carry on with nothing".
    #[test]
    fn the_shared_flags_are_optional_on_both_sub_commands() {
        let node = parse_node(without(&without(&base_args(), "--node-key"), "--bootnodes"));
        assert_eq!(node.common.node_key, None);
        assert_eq!(node.common.bootnodes, None);
        assert!(node.common.checkpoint_sync_url.is_empty());

        let beacon = parse_beacon(vec!["ethlambda", "beacon"]);
        assert_eq!(beacon.common.node_key, None);
        assert_eq!(beacon.common.bootnodes, None);
        assert!(beacon.common.checkpoint_sync_url.is_empty());
    }

    #[test]
    fn beacon_needs_no_checkpoint_sync_url() {
        // `--checkpoint-sync-url` was once `required = true` here, because the
        // fork digest every gossip topic and the ENR are keyed on came from a
        // Beacon API. It comes from the genesis state built into the binary
        // now, so a bare `beacon` is a complete invocation.
        let options = parse_beacon(vec!["ethlambda", "beacon"]);
        assert!(options.common.checkpoint_sync_url.is_empty());
    }

    #[test]
    fn beacon_accepts_a_checkpoint_sync_url() {
        // Declared once for both sub-commands, so `beacon` parses it the same
        // way `node` does; it is now how a beacon follower gets its anchor.
        let options = parse_beacon(vec![
            "ethlambda",
            "beacon",
            "--checkpoint-sync-url",
            "https://checkpointz.example",
        ]);
        assert_eq!(
            options.common.checkpoint_sync_url,
            ["https://checkpointz.example"]
        );
    }

    #[test]
    fn an_absent_node_key_parses_on_both_sub_commands() {
        // Both generate an ephemeral in-memory key instead (`main`'s
        // `resolve_node_key`), so neither rejects the argv. On `node` that is
        // a behavior change: `--node-key` used to be required there.
        assert_eq!(
            parse_node(without(&base_args(), "--node-key"))
                .common
                .node_key,
            None
        );
        assert_eq!(
            parse_beacon(vec![
                "ethlambda",
                "beacon",
                "--checkpoint-sync-url",
                "https://checkpointz.example",
            ])
            .common
            .node_key,
            None
        );
    }

    #[test]
    fn beacon_rejects_lean_only_flags() {
        let result = try_parse_from([
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

    // `beacon_has_no_discovery_enable_flag` lived here, and after that a test
    // asserting `beacon` parsed `--discovery.enable=false` and ignored it. The
    // flag is gone: discv5 is always on, on both chains, so there is no longer
    // an argv that says otherwise and nothing left to ignore. See
    // `the_default_ports_do_not_collide_on_either_chain` above.

    #[test]
    fn lean_still_requires_its_own_flags() {
        // The subcommand split is what makes this a clap error rather than a
        // hand-written check over Option fields.
        let result = try_parse_from(["ethlambda", "lean", "--node-key", "node.key"]);
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
        crate::command::Cli::command().debug_assert();
    }

    /// The smallest argv that satisfies every required `beacon` flag.
    fn beacon_args() -> Vec<&'static str> {
        vec![
            "ethlambda",
            "beacon",
            "--node-key",
            "node.key",
            "--checkpoint-sync-url",
            "https://checkpointz.example",
        ]
    }

    fn parse_beacon(args: Vec<&str>) -> BeaconOptions {
        match try_parse_from(args).expect("beacon argv parses") {
            Command::Beacon(options) => options,
            other => panic!("the beacon argv must resolve to the beacon subcommand, got {other:?}"),
        }
    }

    /// The invariant `From<BeaconOptions>`'s `unreachable!` rests on. Each
    /// flag `requires` the other, so a half-configured Engine API is a usage
    /// error out of the parser rather than a panic several frames later.
    ///
    /// Replaces `an_endpoint_without_a_secret_is_refused`, which pinned that
    /// panic. Same invariant, checked one layer earlier and over both halves
    /// rather than one.
    #[test]
    fn execution_flags_come_as_a_pair() {
        for half in [
            vec!["--execution-endpoint", "http://127.0.0.1:8551"],
            vec!["--execution-jwt-secret", "jwt.hex"],
        ] {
            let mut args = beacon_args();
            args.extend_from_slice(&half);
            let err = try_parse_from(args).expect_err("one half alone must not parse");
            assert_eq!(
                err.kind(),
                clap::error::ErrorKind::MissingRequiredArgument,
                "a missing pair is a usage error, not a panic: {err}"
            );
        }

        let mut args = beacon_args();
        args.extend_from_slice(&[
            "--execution-endpoint",
            "http://127.0.0.1:8551",
            "--execution-jwt-secret",
            "jwt.hex",
        ]);
        let beacon = parse_beacon(args);
        assert!(beacon.execution_endpoint.is_some());
        assert!(beacon.execution_jwt_secret.is_some());
    }

    #[test]
    fn the_execution_flags_are_absent_by_default() {
        let beacon = parse_beacon(beacon_args());

        assert!(beacon.execution_endpoint.is_none());
        assert!(beacon.execution_jwt_secret.is_none());
        assert_eq!(
            beacon.mainnet.safe_slots_to_import_optimistically,
            SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY
        );
    }

    #[test]
    fn both_execution_flags_together_pair_into_one_value() {
        let mut args = beacon_args();
        args.extend([
            "--execution-endpoint",
            "http://127.0.0.1:8551",
            "--execution-jwt-secret",
            "jwt.hex",
        ]);

        let options: Options = parse_beacon(args).into();

        match options.network {
            Network::Mainnet {
                execution: Some(execution),
                ..
            } => {
                assert_eq!(execution.endpoint, "http://127.0.0.1:8551");
                assert_eq!(execution.jwt_secret, PathBuf::from("jwt.hex"));
            }
            other => panic!("expected a paired execution client, got {other:?}"),
        }
    }
}
