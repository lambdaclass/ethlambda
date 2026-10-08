//! The import workload: fetch a real block range into an SSZ corpus, then
//! replay it offline through the client's own import path.
//!
//! See docs/benchmarking.md for what is and is not measured.

use std::path::PathBuf;

use eyre::WrapErr as _;

pub(crate) mod corpus;
pub(crate) mod fetch;
pub(crate) mod replay;
pub(crate) mod source;

use super::OutputFormat;
use corpus::Manifest;
use source::HttpSource;

/// Flags for `ethlambda benchmark import`.
#[derive(Debug, clap::Args)]
pub(crate) struct ImportOptions {
    #[command(subcommand)]
    phase: Phase,
}

#[derive(Debug, clap::Subcommand)]
enum Phase {
    /// Pull a block range from a running beacon node into a corpus.
    Fetch(FetchOptions),
    /// Replay a corpus through this client's import path.
    Replay(ReplayOptions),
}

#[derive(Debug, clap::Args)]
struct FetchOptions {
    /// Base URL of the source beacon node, e.g. `http://127.0.0.1:5052`.
    #[arg(long)]
    url: String,
    /// First slot of the range, and its first sample, so it must hold a block.
    /// The anchor is the block at the first slot of the epoch before it (fork
    /// choice can only anchor there); the blocks in between are fetched too,
    /// and replayed as unsampled warm-up.
    #[arg(long)]
    from: u64,
    /// Last slot of the range, inclusive. May not pass the source's head.
    /// Otherwise not capped: `fetch` streams, so a long range costs disk and
    /// time but not memory.
    #[arg(long)]
    to: u64,
    /// Corpus directory to create.
    #[arg(long)]
    corpus: PathBuf,
    /// Replace an existing corpus in that directory.
    #[arg(long)]
    force: bool,
    /// Which network the source follows.
    #[arg(long, default_value = crate::network::DEFAULT_NETWORK)]
    network: String,
}

/// Flags for `ethlambda benchmark import replay`.
///
/// Defined here rather than in `replay.rs` so the flags and the code reading
/// them live together.
#[derive(Debug, clap::Args)]
pub(crate) struct ReplayOptions {
    /// Corpus directory written by `fetch`.
    #[arg(long)]
    pub corpus: PathBuf,
    /// Which network the corpus belongs to. Checked against the manifest's
    /// recorded genesis validators root before anything is built.
    #[arg(long, default_value = crate::network::DEFAULT_NETWORK)]
    pub network: String,
    /// Where to build the replay's RocksDB store. A real backend rather than
    /// the in-memory one, because state persistence is 9% of an import and an
    /// in-memory backend would delete that cost from the measurement.
    #[arg(long)]
    pub data_dir: PathBuf,
    /// Replace an existing store in that directory.
    #[arg(long)]
    pub force: bool,
    /// How far behind the wall clock a block must be before it may be
    /// imported optimistically on age alone. A corpus replay never sees a
    /// merge transition block, the only thing this gates, so the default is
    /// almost always right; it is exposed for parity with `beacon`'s own flag
    /// of the same name.
    #[arg(long, default_value_t = ethlambda_types::beacon::constants::SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY)]
    pub safe_slots_to_import_optimistically: u64,
    /// Report format printed to stdout. Logs go to stderr, so JSON output can
    /// be piped directly (e.g. into jq).
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,
    /// Also write the JSON report to this file.
    #[arg(long)]
    pub output: Option<PathBuf>,
}

/// The import workload's entry.
///
/// `#[tokio::main]` here rather than on `benchmark::run`: the synthetic
/// workload is synchronous CPU-bound work and deliberately never starts a
/// runtime, while this one does HTTP and awaits the import path. Mirrors how
/// `run_node` carries its own attribute.
#[tokio::main]
pub(crate) async fn run(options: ImportOptions) -> eyre::Result<()> {
    match options.phase {
        Phase::Fetch(fetch) => run_fetch(fetch).await,
        Phase::Replay(replay) => run_replay(replay).await,
    }
}

async fn run_fetch(options: FetchOptions) -> eyre::Result<()> {
    let spec = crate::network::NetworkSpec::parse(&options.network)?;
    let network = crate::network::NetworkSource::resolve(&spec)?;
    let source = HttpSource::new(options.url.clone(), network.config().clone())
        .wrap_err("building the beacon API client")?;

    // `fetch_corpus` only refuses a non-empty directory; deleting it first is
    // this flag's job, exactly as `--force` does for `replay`'s data dir.
    if options.force && options.corpus.exists() {
        std::fs::remove_dir_all(&options.corpus).wrap_err_with(|| {
            format!(
                "removing the existing corpus at {}",
                options.corpus.display()
            )
        })?;
    }

    let manifest: Manifest = fetch::fetch_corpus(
        &source,
        &options.corpus,
        options.from,
        options.to,
        &options.network,
        network.config(),
        &network.genesis(),
    )
    .await?;

    let gaps = manifest.missing_slots();
    println!(
        "fetched {} blocks for slots [{}, {}] ({} gaps, plus {} warm-up blocks) into {}; \
         anchor slot={} root={}",
        manifest.slots.len(),
        manifest.range_start,
        manifest.range_end,
        gaps.len(),
        manifest.warmup_slots.len(),
        options.corpus.display(),
        manifest.anchor_slot,
        manifest.anchor_block_root,
    );

    Ok(())
}

async fn run_replay(options: ReplayOptions) -> eyre::Result<()> {
    let report = replay::replay_corpus(&options.corpus, &options).await?;

    match options.format {
        OutputFormat::Human => println!("{}", report.human_table()),
        OutputFormat::Json => println!("{}", report.to_json()?),
    }
    if let Some(path) = &options.output {
        std::fs::write(path, report.to_json()?)
            .wrap_err_with(|| format!("failed to write report to {}", path.display()))?;
        eprintln!("report written to {}", path.display());
    }

    Ok(())
}
