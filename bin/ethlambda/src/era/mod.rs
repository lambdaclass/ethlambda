//! Replaying real chain history from `.era` files (`ethlambda replay-era`).
//!
//! Era files carry every block of 8192 slots plus the state at their end, so
//! they are a source of real mainnet, Sepolia and Hoodi history that no node
//! has to still hold. The command applies the blocks with the beacon state
//! transition, checking every signature and `state_root`, and compares the end
//! with the stored state. See docs/era_replay.md.

mod download;
mod e2store;
mod replay;
mod report;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use eyre::{WrapErr as _, bail, ensure, eyre};
use tracing::info;

use crate::network::{DEFAULT_NETWORK, NetworkSource, NetworkSpec};
use replay::{Replay, SLOTS_PER_ERA};
use report::EraReport;

/// One `--era` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EraArg {
    Number(u64),
    /// The newest era the host lists; needs `--download`.
    Latest,
}

fn parse_era(value: &str) -> Result<EraArg, String> {
    if value == "latest" {
        return Ok(EraArg::Latest);
    }
    value
        .parse()
        .map(EraArg::Number)
        .map_err(|_| format!("`{value}` is neither an era number nor `latest`"))
}

#[derive(Debug, clap::Args)]
pub(crate) struct ReplayEraOptions {
    /// Built-in network name or a directory of published network files.
    #[arg(long, default_value = DEFAULT_NETWORK)]
    network: String,
    /// Directory holding (and receiving) the `.era` files.
    #[arg(long)]
    era_dir: PathBuf,
    /// Era to replay; repeat for several. Consecutive numbers continue from
    /// the same in-memory state. `latest` is the newest era on the host.
    #[arg(long = "era", required = true, value_parser = parse_era)]
    eras: Vec<EraArg>,
    /// Fetch missing era files from https://<network>.era.nimbus.team/.
    #[arg(long)]
    download: bool,
    /// Stop the era after this many applied blocks (smoke mode). The
    /// end-of-era oracle is skipped. Takes a single `--era`, since a smoke run
    /// stops mid-era and has no state to chain from.
    #[arg(long)]
    max_blocks: Option<u64>,
    /// Write a JSON report of every era to this path.
    #[arg(long)]
    report: Option<PathBuf>,
}

/// `--max-blocks` leaves the state mid-era, so a second `--era` could only
/// start fresh from its predecessor's file and apply K more blocks: a run that
/// looks chained and is not. Refuse it instead.
fn check_max_blocks(eras: &[EraArg], max_blocks: Option<u64>) -> eyre::Result<()> {
    ensure!(
        max_blocks.is_none() || eras.len() <= 1,
        "--max-blocks stops an era mid-way, so it cannot be combined with several --era values; \
         run each era as its own smoke run"
    );
    Ok(())
}

pub(crate) fn run(options: ReplayEraOptions) -> eyre::Result<()> {
    check_max_blocks(&options.eras, options.max_blocks)?;
    let spec = NetworkSpec::parse(&options.network)?;
    let source = NetworkSource::resolve(&spec)?;
    let config = source.config();
    // The file prefix and the host name are the config's own name.
    let name = config.config_name.as_str().to_string();
    ensure!(
        !name.is_empty(),
        "the network config has no CONFIG_NAME to name era files by"
    );
    let gloas_epoch = gloas_fork_epoch(&spec)?;

    std::fs::create_dir_all(&options.era_dir)
        .wrap_err_with(|| format!("creating {}", options.era_dir.display()))?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let client = crate::checkpoint_sync::build_client()?;

    // Resolve `latest`, then refuse anything this build cannot process before
    // downloading gigabytes for it.
    let remote = if options.download {
        Some(runtime.block_on(download::list_remote(&client, &name))?)
    } else {
        None
    };
    let mut eras = Vec::new();
    for arg in &options.eras {
        eras.push(match arg {
            EraArg::Number(era) => *era,
            EraArg::Latest => {
                let remote = remote.as_ref().ok_or_else(|| {
                    eyre!("`--era latest` needs --download to learn what is newest")
                })?;
                *remote.keys().next_back().expect("a listing is never empty")
            }
        });
    }
    for &era in &eras {
        ensure!(era >= 1, "era 0 holds no blocks; replay starts at era 1");
        check_replayable(era, gloas_epoch, &name)?;
    }

    // Files needed: each era's own and its predecessor's.
    let wanted: BTreeSet<u64> = eras.iter().flat_map(|&era| [era - 1, era]).collect();
    let mut paths = std::collections::BTreeMap::new();
    for era in wanted {
        let path = match download::find_local(&options.era_dir, &name, era)? {
            Some(path) => path,
            None => {
                let Some(remote) = &remote else {
                    bail!(
                        "no {name} era {era} file in {}; pass --download to fetch it",
                        options.era_dir.display()
                    );
                };
                let file_name = remote.get(&era).ok_or_else(|| {
                    eyre!("{} does not list {name} era {era}", download::host(&name))
                })?;
                runtime.block_on(download::fetch(&client, &name, file_name, &options.era_dir))?
            }
        };
        paths.insert(era, path);
    }

    let mut replay = Replay::new(&name, config, options.max_blocks);
    let mut reports: Vec<EraReport> = Vec::new();
    for &era in &eras {
        let report = replay.era(era, &paths[&(era - 1)], &paths[&era]);
        let failed = report.error.is_some();
        reports.push(report);
        if failed {
            break;
        }
    }

    if let Some(path) = &options.report {
        write_report(path, &reports)?;
    }
    if let Some(report) = reports.iter().find(|r| r.error.is_some()) {
        bail!(
            "era {} failed: {}",
            report.era,
            report.error.as_deref().unwrap_or_default()
        );
    }
    info!(eras = reports.len(), "All eras replayed");
    Ok(())
}

fn write_report(path: &Path, reports: &[EraReport]) -> eyre::Result<()> {
    let json = serde_json::to_vec_pretty(reports)?;
    std::fs::write(path, json).wrap_err_with(|| format!("writing {}", path.display()))
}

/// Refuse an era whose closing state belongs to a fork this build cannot
/// process. `Config` has no gloas fork, so decoding such a state as fulu would
/// fail with an SSZ error that names neither the fork nor the fix.
fn check_replayable(era: u64, gloas_epoch: Option<u64>, name: &str) -> eyre::Result<()> {
    let end_epoch = era * SLOTS_PER_ERA / ethlambda_types::beacon::preset::SLOTS_PER_EPOCH;
    if let Some(gloas) = gloas_epoch
        && end_epoch >= gloas
    {
        bail!(
            "{name} era {era} ends at epoch {end_epoch}, at or past the gloas fork (epoch {gloas}), \
             which this build cannot process; the last replayable era is {}",
            (gloas * ethlambda_types::beacon::preset::SLOTS_PER_EPOCH).div_ceil(SLOTS_PER_ERA) - 1
        );
    }
    Ok(())
}

/// The `GLOAS_FORK_EPOCH` a network's `config.yaml` schedules, which
/// [`ethlambda_types::beacon::config::Config`] drops as an unknown key.
fn gloas_fork_epoch(spec: &NetworkSpec) -> eyre::Result<Option<u64>> {
    let text = match spec {
        NetworkSpec::BuiltIn(network) => network.config_yaml().to_string(),
        NetworkSpec::Directory(dir) => {
            let path = dir.join("config.yaml");
            std::fs::read_to_string(&path)
                .wrap_err_with(|| format!("reading {}", path.display()))?
        }
    };
    Ok(parse_gloas_epoch(&text))
}

fn parse_gloas_epoch(config_yaml: &str) -> Option<u64> {
    config_yaml
        .lines()
        .find_map(|line| line.trim().strip_prefix("GLOAS_FORK_EPOCH:"))
        .and_then(|value| value.split('#').next()?.trim().parse().ok())
        // An unscheduled fork carries the far-future sentinel.
        .filter(|&epoch| epoch != u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::BuiltInNetwork;

    #[test]
    fn the_gloas_epoch_is_read_from_the_config_text() {
        assert_eq!(
            parse_gloas_epoch("FULU_FORK_EPOCH: 5\nGLOAS_FORK_EPOCH: 353024 # Wed\n"),
            Some(353_024)
        );
        assert_eq!(
            parse_gloas_epoch("GLOAS_FORK_EPOCH: 18446744073709551615"),
            None
        );
        assert_eq!(parse_gloas_epoch("FULU_FORK_EPOCH: 5"), None);
    }

    #[test]
    fn eras_past_gloas_are_refused() {
        // Sepolia: gloas at epoch 353024 = era 1379.
        assert!(check_replayable(1378, Some(353_024), "sepolia").is_ok());
        let err = check_replayable(1379, Some(353_024), "sepolia").unwrap_err();
        assert!(
            err.to_string().contains("last replayable era is 1378"),
            "{err}"
        );
        assert!(check_replayable(9999, None, "mainnet").is_ok());
    }

    #[test]
    fn era_arguments_parse() {
        assert_eq!(parse_era("290"), Ok(EraArg::Number(290)));
        assert_eq!(parse_era("latest"), Ok(EraArg::Latest));
        assert!(parse_era("soon").is_err());
    }

    #[test]
    fn max_blocks_refuses_chained_eras() {
        let one = [EraArg::Number(9)];
        let two = [EraArg::Number(9), EraArg::Number(10)];
        assert!(check_max_blocks(&one, Some(512)).is_ok());
        assert!(check_max_blocks(&two, None).is_ok());
        let err = check_max_blocks(&two, Some(512)).unwrap_err();
        assert!(err.to_string().contains("--max-blocks"), "{err}");
    }

    #[test]
    fn built_in_networks_name_their_era_files_by_config_name() {
        for network in BuiltInNetwork::ALL {
            let source = NetworkSource::resolve(&NetworkSpec::BuiltIn(network)).unwrap();
            assert_eq!(source.config().config_name.as_str(), network.name());
        }
    }
}
