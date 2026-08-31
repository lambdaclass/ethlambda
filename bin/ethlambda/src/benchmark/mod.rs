//! Offline block-building benchmark (`ethlambda benchmark`).
//!
//! Drives the exact production proposer path — `produce_block_with_signatures`,
//! the same entry `BlockChainServer::propose_block` uses — against a synthetic
//! in-memory chain, and reports per-phase timing distributions. Gossip publish
//! and the slot-alignment sleep are outside the measured span, matching the
//! node's own `lean_block_building_time_seconds` boundary.
//!
//! See docs/benchmarking.md for what is and is not measured, how to read a
//! report, and the current limitations.

mod corpus;
mod report;

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::time::Instant;

use ethlambda_blockchain::block_builder::ProposerConfig;
use ethlambda_blockchain::metrics::BLOCK_PROPOSAL_ATTESTATION_BUILD_PHASES;
use ethlambda_blockchain::store::{on_block_without_verification, produce_block_with_signatures};
use ethlambda_storage::{NEW_PAYLOAD_CAP, Store};
use ethlambda_types::block::{MultiMessageAggregate, SignedBlock};
use ethlambda_types::primitives::HashTreeRoot as _;
use eyre::WrapErr as _;

use report::{Environment, Params, Report, Sample};

#[derive(Debug, clap::Args)]
pub(crate) struct BenchmarkOptions {
    #[command(subcommand)]
    workload: Workload,
}

#[derive(Debug, clap::Subcommand)]
enum Workload {
    /// Benchmark block building on a synthetic in-memory chain.
    Synthetic(SyntheticOptions),
}

#[derive(Debug, clap::Args)]
struct SyntheticOptions {
    /// Number of validators in the synthetic genesis.
    #[arg(long, default_value = "8", value_parser = clap::value_parser!(u64).range(1..=4096))]
    num_validators: u64,
    /// Unmeasured chain-advancement slots before measuring. Builds and imports
    /// one block per slot so the measured builds run on a state with
    /// representative historical roots and justifications, and warms the state
    /// cache.
    #[arg(long, default_value = "8")]
    warmup_slots: u64,
    /// Aggregate proofs seeded per AttestationData, mimicking committee
    /// aggregators covering disjoint validator subsets. The default of 1 (one
    /// full-coverage proof per data) keeps justification/finalization
    /// advancing every slot. Higher values exercise multi-proof selection and
    /// same-data collapse, but without --enable-proposer-aggregation the block
    /// then carries only the best partial proof (< 2/3 coverage), so
    /// justification stalls — the real coverage cost of disabling proposer
    /// aggregation.
    #[arg(long, default_value = "1", value_parser = clap::value_parser!(u64).range(1..))]
    proofs_per_data: u64,
    /// Deterministic seed for the synthetic validator set. Two runs with the
    /// same seed and parameters produce identical per-iteration block roots.
    #[arg(long, default_value = "42")]
    seed: u64,
    #[command(flatten)]
    common: CommonOptions,
}

impl SyntheticOptions {
    fn validate(&self) -> eyre::Result<()> {
        eyre::ensure!(
            self.common.mock_crypto,
            "real-crypto benchmarking is not implemented yet; rerun with --mock-crypto"
        );
        // The pending pool evicts whole data-root entries FIFO once its proof
        // cap is exceeded, so a single slot's batch larger than the cap would
        // silently seed nothing and every measured block would be empty.
        eyre::ensure!(
            self.proofs_per_data as usize <= NEW_PAYLOAD_CAP,
            "--proofs-per-data {} exceeds the pending-pool capacity ({NEW_PAYLOAD_CAP}); \
             one slot's batch would be evicted whole and every measured block would be empty",
            self.proofs_per_data
        );
        Ok(())
    }
}

impl From<&SyntheticOptions> for Params {
    fn from(options: &SyntheticOptions) -> Self {
        Self {
            mode: "synthetic",
            mock_crypto: options.common.mock_crypto,
            num_validators: options.num_validators,
            warmup_slots: options.warmup_slots,
            proofs_per_data: options.proofs_per_data,
            seed: options.seed,
            iterations: options.common.iterations,
            enable_proposer_aggregation: options.common.enable_proposer_aggregation,
            max_attestations_per_block: options.common.max_attestations_per_block,
        }
    }
}

#[derive(Debug, clap::Args)]
struct CommonOptions {
    /// Measured iterations (one built block each), after warmup.
    #[arg(long, default_value = "10", value_parser = clap::value_parser!(u64).range(1..))]
    iterations: u64,
    /// Seed pools with empty placeholder proofs instead of real XMSS/leanVM
    /// crypto. Measures selection + best-proof compaction + state transition
    /// only; runs in seconds. Conflicts with --enable-proposer-aggregation,
    /// whose recursive aggregation needs real proof bytes.
    #[arg(long, conflicts_with = "enable_proposer_aggregation")]
    mock_crypto: bool,
    /// Mirrors the node flag: collapse same-data proofs via recursive leanVM
    /// aggregation instead of keeping the single best-coverage proof.
    #[arg(long)]
    enable_proposer_aggregation: bool,
    /// Mirrors the node flag: distinct AttestationData cap per built block.
    #[arg(long, default_value = "3")]
    max_attestations_per_block: usize,
    /// Report format printed to stdout. Logs go to stderr, so JSON output can
    /// be piped directly (e.g. into jq).
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    format: OutputFormat,
    /// Also write the JSON report to this file.
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum OutputFormat {
    Human,
    Json,
}

pub(crate) fn run(options: BenchmarkOptions) -> eyre::Result<()> {
    let Workload::Synthetic(synthetic) = options.workload;
    run_synthetic(synthetic)
}

fn run_synthetic(options: SyntheticOptions) -> eyre::Result<()> {
    options.validate()?;
    let common = &options.common;

    let proposer_config = ProposerConfig {
        enable_proposer_aggregation: common.enable_proposer_aggregation,
        max_attestations_per_block: common.max_attestations_per_block,
    };
    let corpus = corpus::SyntheticCorpus::new(options.num_validators, options.proofs_per_data);
    let mut store = corpus.genesis_store(options.seed);

    let total_slots = options
        .warmup_slots
        .checked_add(common.iterations)
        .ok_or_else(|| eyre::eyre!("--warmup-slots plus --iterations overflows u64"))?;

    let mut samples = Vec::with_capacity(common.iterations as usize);
    for slot in 1..=total_slots {
        let sample = build_one_slot(
            &corpus,
            &mut store,
            slot,
            options.num_validators,
            proposer_config,
        )?;
        let measured = slot > options.warmup_slots;
        log_progress(slot, total_slots, measured, &sample);
        if measured {
            samples.push(Sample {
                iteration: slot - options.warmup_slots,
                ..sample
            });
        }
    }
    eyre::ensure!(
        samples.len() as u64 == common.iterations,
        "collected {} samples but expected {}; the measured-slot accounting drifted",
        samples.len(),
        common.iterations
    );

    let report = Report::new(Environment::collect(), Params::from(&options), samples);

    match common.format {
        OutputFormat::Human => println!("{}", report.human_table()),
        OutputFormat::Json => println!("{}", report.to_json()?),
    }
    if let Some(path) = &common.output {
        std::fs::write(path, report.to_json()?)
            .wrap_err_with(|| format!("failed to write report to {}", path.display()))?;
        eprintln!("report written to {}", path.display());
    }

    Ok(())
}

/// One line per built slot, on stderr so the report keeps stdout to itself.
fn log_progress(slot: u64, total_slots: u64, measured: bool, sample: &Sample) {
    let label = if measured { "measured" } else { "warmup" };
    eprintln!(
        "[{slot}/{total_slots}] {label}: built block in {:.3}ms \
         (attestations={}, pool_entries={})",
        sample.wall_seconds * 1e3,
        sample.attestations_packed,
        sample.pool_entries,
    );
}

/// Seed the pool, build one block the way the proposer does, and import it.
///
/// The returned sample carries `iteration: 0`; the caller sets it for the slots
/// it keeps. Warmup and measured slots do exactly the same work — only whether
/// the sample is kept differs — so there is one code path for both.
fn build_one_slot(
    corpus: &corpus::SyntheticCorpus,
    store: &mut Store,
    slot: u64,
    num_validators: u64,
    proposer_config: ProposerConfig,
) -> eyre::Result<Sample> {
    // Seed the pending pool with the previous slot's attestations, exactly
    // where gossip aggregates would sit before the proposal tick promotes them
    // to the known pool. Entries from earlier slots stay in the known pool, as
    // they would on a live node.
    let pool_entries = corpus.seed_pool(store, slot - 1)?;

    // Round-robin proposer, matching `is_proposer`.
    let proposer = slot % num_validators;

    let phases = PhaseTimer::start();
    let build_start = Instant::now();
    let (block, aggregates, _checkpoints) =
        produce_block_with_signatures(store, slot, proposer, proposer_config)
            .wrap_err_with(|| format!("block build failed at slot {slot}"))?;
    let wall_seconds = build_start.elapsed().as_secs_f64();
    let phases = phases.finish()?;

    let block_root = block.hash_tree_root();
    let attestations_packed = block.body.attestations.len();
    let aggregates_count = aggregates.len();

    // Import the built block (outside the measured span) so the next iteration
    // builds one slot ahead of head, like a live proposer; building repeatedly
    // on a fixed head would make `process_slots` cost grow with the iteration
    // index.
    let signed_block = SignedBlock {
        message: block,
        proof: MultiMessageAggregate::default(),
    };
    on_block_without_verification(store, signed_block)
        .wrap_err_with(|| format!("importing the built block failed at slot {slot}"))?;

    // Clamped: the unattributed preamble makes the remainder positive in
    // practice, but summing many small phase values can round just above the
    // wall measurement, and a negative overhead would read as an accounting bug.
    let overhead_seconds = (wall_seconds - phases.values().sum::<f64>()).max(0.0);

    Ok(Sample {
        iteration: 0,
        slot,
        proposer,
        block_root: format!("0x{}", hex::encode(block_root.0)),
        wall_seconds,
        phases,
        overhead_seconds,
        attestations_packed,
        aggregates: aggregates_count,
        pool_entries,
    })
}

const PHASE_HISTOGRAM: &str = "lean_block_proposal_attestation_build_phase_seconds";

/// Exact per-phase durations for one block build, taken from the block-proposal
/// phase histogram in the default prometheus registry.
///
/// Histogram sums accumulate the raw f64 seconds of every observation, so the
/// difference between two readings IS the build's phase time — bucket
/// boundaries play no role, and the hot path needs no extra instrumentation.
struct PhaseTimer {
    /// Per-phase (sample_sum, sample_count) before the build.
    before: HashMap<String, (f64, u64)>,
}

impl PhaseTimer {
    fn start() -> Self {
        Self { before: read() }
    }

    /// Per-phase durations since [`PhaseTimer::start`].
    ///
    /// Each phase must have been observed exactly once — one `build_block` in
    /// this single-threaded process — so anything else means the accounting
    /// drifted and attribution would be wrong. That is a hard error, not a
    /// warning: a silently mis-attributed report is worse than no report.
    fn finish(self) -> eyre::Result<BTreeMap<String, f64>> {
        let after = read();
        let mut phases = BTreeMap::new();
        for &phase in BLOCK_PROPOSAL_ATTESTATION_BUILD_PHASES {
            let (sum_before, count_before) = self.before.get(phase).copied().unwrap_or((0.0, 0));
            let (sum_after, count_after) = after.get(phase).copied().unwrap_or((0.0, 0));
            let observations = count_after.saturating_sub(count_before);
            eyre::ensure!(
                observations == 1,
                "phase '{phase}' was observed {observations} times during one build \
                 (expected 1); phase attribution would be wrong"
            );
            phases.insert(phase.to_string(), sum_after - sum_before);
        }
        Ok(phases)
    }
}

/// Current (sample_sum, sample_count) per phase label.
fn read() -> HashMap<String, (f64, u64)> {
    ethlambda_metrics::gather()
        .iter()
        .filter(|family| family.name() == PHASE_HISTOGRAM)
        .flat_map(|family| family.get_metric())
        .filter_map(|metric| {
            let phase = metric
                .get_label()
                .iter()
                .find(|label| label.name() == "phase")?
                .value()
                .to_string();
            let histogram = metric.get_histogram();
            Some((
                phase,
                (histogram.get_sample_sum(), histogram.get_sample_count()),
            ))
        })
        .collect()
}
