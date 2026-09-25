//! Reading a network directory.
//!
//! The layout is the one `eth-clients/<network>/metadata` publishes and
//! kurtosis mounts at `/network-configs`, so a devnet's artifact is consumed
//! unmodified. Only three entries are read; everything else in the directory,
//! including the execution-layer files and the deposit contract metadata, is
//! ignored.

use std::path::{Path, PathBuf};

use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::containers::BeaconState;
use ethlambda_types::beacon::fork::ForkName;

use super::config_file::{ConfigFile, ConfigFileError};

pub(crate) const CONFIG_FILE: &str = "config.yaml";
pub(crate) const GENESIS_STATE_FILE: &str = "genesis.ssz";
pub(crate) const BOOTNODES_YAML: &str = "bootstrap_nodes.yaml";
pub(crate) const BOOTNODES_TXT: &str = "bootstrap_nodes.txt";

/// One loaded network directory.
#[derive(Debug)]
pub(crate) struct NetworkDir {
    pub(crate) config: Config,
    pub(crate) genesis_state: Box<BeaconState>,
    pub(crate) bootnodes: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum NetworkDirError {
    #[error("{} is required but was not found in the network directory", path.display())]
    Missing { path: PathBuf },
    #[error("could not read {}: {source}", path.display())]
    Unreadable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{}: {source}", path.display())]
    Config {
        path: PathBuf,
        #[source]
        source: ConfigFileError,
    },
    #[error("{}: {source}", path.display())]
    Preset {
        path: PathBuf,
        #[source]
        source: super::PresetCheckError,
    },
    #[error("{}: {source}", path.display())]
    Constants {
        path: PathBuf,
        #[source]
        source: super::ConstantsMismatch,
    },
    // `{fork:?}` rather than `{fork}`: `ForkName` exposes `as_str` and does not
    // implement `Display`.
    #[error("{} did not decode as a {fork:?} BeaconState: {reason}", path.display())]
    Genesis {
        path: PathBuf,
        fork: ForkName,
        reason: String,
    },
    #[error("could not read bootnodes from {}: {reason}", path.display())]
    Bootnodes { path: PathBuf, reason: String },
    #[error(
        "{}: SECONDS_PER_SLOT is 0, which the wall-clock-to-slot arithmetic divides by",
        path.display()
    )]
    ZeroSecondsPerSlot { path: PathBuf },
}

impl NetworkDir {
    /// Read `base`'s three consumed entries.
    pub(crate) fn load(base: &Path) -> Result<Self, NetworkDirError> {
        let config_path = base.join(CONFIG_FILE);
        let text = read_required(&config_path)?;
        let parsed = ConfigFile::parse(&text).map_err(|source| NetworkDirError::Config {
            path: config_path.clone(),
            source,
        })?;
        parsed.warn_about_ignored_keys();

        // Before `genesis.ssz` is decoded: its container bounds are the
        // compiled preset's, so a directory built for the other preset would
        // otherwise fail as an SSZ error rather than naming the cargo feature
        // that fixes it.
        super::check_preset(parsed.config.preset_base.as_str()).map_err(|source| {
            NetworkDirError::Preset {
                path: config_path.clone(),
                source,
            }
        })?;
        super::check_constants(&parsed.config).map_err(|source| NetworkDirError::Constants {
            path: config_path.clone(),
            source,
        })?;

        let genesis_path = base.join(GENESIS_STATE_FILE);
        let genesis_bytes = read_required_bytes(&genesis_path)?;
        // The fork comes from this network's own schedule at epoch 0, never
        // hardcoded. Mainnet's genesis is phase0 because its altair epoch is
        // far in the future, but a devnet typically schedules every fork at
        // epoch 0 and ships a genesis state in the newest one, so decoding as
        // phase0 would fail on exactly the networks this flag exists for.
        let fork = parsed.config.fork_at_epoch(0);
        let genesis_state = BeaconState::from_ssz(fork, &genesis_bytes).map_err(|err| {
            NetworkDirError::Genesis {
                path: genesis_path,
                fork,
                reason: format!("{err:?}"),
            }
        })?;

        let bootnodes = read_bootnodes(base)?;

        // A zero divides in `epoch_at` and `milliseconds_per_interval` (both
        // key wall-clock time off `seconds_per_slot`/`slot_duration_ms`), so
        // it must be rejected here rather than loading cleanly into a config
        // that panics the first time a duty fires.
        if parsed.config.seconds_per_slot == 0 {
            return Err(NetworkDirError::ZeroSecondsPerSlot {
                path: config_path.clone(),
            });
        }
        // Two fields cannot come from the file and must be reconciled here,
        // once, before anything reads the config.
        let mut config = parsed.config;
        super::derive_genesis_fields(&mut config, genesis_state.genesis_time());

        Ok(Self {
            config,
            genesis_state: Box::new(genesis_state),
            bootnodes,
        })
    }
}

/// Read the first bootnode file present, preferring the YAML spelling.
///
/// Both spellings appear: `eth-clients` publishes `bootstrap_nodes.yaml` and
/// kurtosis ships that plus `bootstrap_nodes.txt`. The existing `--bootnodes`
/// parser (`read_bootnode_strings`, in `main.rs`) already accepts either
/// shape, so this only picks a file and reuses it rather than re-parsing.
fn read_bootnodes(base: &Path) -> Result<Vec<String>, NetworkDirError> {
    for name in [BOOTNODES_YAML, BOOTNODES_TXT] {
        let path = base.join(name);
        if !path.exists() {
            continue;
        }
        return crate::read_bootnode_strings(&path).map_err(|source| NetworkDirError::Bootnodes {
            path,
            reason: source.to_string(),
        });
    }
    Ok(Vec::new())
}

fn read_required(path: &Path) -> Result<String, NetworkDirError> {
    if !path.exists() {
        return Err(NetworkDirError::Missing {
            path: path.to_path_buf(),
        });
    }
    std::fs::read_to_string(path).map_err(|source| NetworkDirError::Unreadable {
        path: path.to_path_buf(),
        source,
    })
}

fn read_required_bytes(path: &Path) -> Result<Vec<u8>, NetworkDirError> {
    if !path.exists() {
        return Err(NetworkDirError::Missing {
            path: path.to_path_buf(),
        });
    }
    std::fs::read(path).map_err(|source| NetworkDirError::Unreadable {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/networks")
            .join(name)
    }

    /// Build a complete directory in a temp dir: the devnet fixture plus a
    /// genesis state, which is too large to check in.
    fn complete_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::copy(
            fixture("devnet").join("config.yaml"),
            dir.path().join("config.yaml"),
        )
        .unwrap();
        std::fs::copy(
            fixture("devnet").join("bootstrap_nodes.txt"),
            dir.path().join("bootstrap_nodes.txt"),
        )
        .unwrap();
        let state = crate::beacon::mainnet_genesis_state().unwrap();
        std::fs::write(dir.path().join("genesis.ssz"), state.to_ssz()).unwrap();
        dir
    }

    /// The same directory, but with a genesis state whose `genesis_time` is
    /// `genesis_time` rather than mainnet's.
    fn complete_dir_with_genesis_time(genesis_time: u64) -> tempfile::TempDir {
        let dir = complete_dir();
        let mut state = crate::beacon::mainnet_genesis_state().unwrap();
        *state.genesis_time_mut() = genesis_time;
        std::fs::write(dir.path().join("genesis.ssz"), state.to_ssz()).unwrap();
        dir
    }

    #[test]
    fn a_complete_directory_loads() {
        let dir = complete_dir();
        let loaded = NetworkDir::load(dir.path()).unwrap();
        assert_eq!(loaded.config.config_name.as_str(), "ethlambda-devnet");
        assert_eq!(loaded.config.deposit_chain_id, 3_151_908);
        assert_eq!(loaded.bootnodes.len(), 2);
    }

    #[test]
    fn the_two_derived_fields_are_reconciled_against_the_genesis_state() {
        // The genesis state here MUST carry a genesis_time different from
        // `Config::mainnet().genesis_time`. `genesis_time` is `#[serde(skip)]`
        // under a container-level `default`, so an unreconciled config inherits
        // mainnet's 1606824023; writing mainnet's own state would make this
        // assertion pass even with the reconciliation deleted.
        const DEVNET_GENESIS_TIME: u64 = 1_700_000_000;
        let dir = complete_dir_with_genesis_time(DEVNET_GENESIS_TIME);
        let loaded = NetworkDir::load(dir.path()).unwrap();

        assert_eq!(
            loaded.config.genesis_time, DEVNET_GENESIS_TIME,
            "genesis_time must come from the state, not from the serde default"
        );
        assert_ne!(
            loaded.config.genesis_time,
            Config::mainnet().genesis_time,
            "the test is only meaningful if the state differs from the default"
        );

        // The devnet fixture deliberately carries an inconsistent pair:
        // SECONDS_PER_SLOT is 6 while SLOT_DURATION_MS is still mainnet's
        // 12000. The seconds field is authoritative on a beacon chain, so the
        // derivation has to win over what the file says.
        assert_eq!(loaded.config.seconds_per_slot, 6);
        assert_eq!(loaded.config.slot_duration_ms, 6_000);
    }

    #[test]
    fn a_missing_config_names_the_path() {
        let dir = complete_dir();
        std::fs::remove_file(dir.path().join("config.yaml")).unwrap();
        let err = NetworkDir::load(dir.path()).unwrap_err().to_string();
        assert!(err.contains("config.yaml"), "got {err}");
    }

    #[test]
    fn a_zero_seconds_per_slot_is_rejected_naming_the_field() {
        let dir = complete_dir();
        let devnet_text = std::fs::read_to_string(fixture("devnet").join("config.yaml")).unwrap();
        let zeroed_text = devnet_text.replacen("SECONDS_PER_SLOT: 6", "SECONDS_PER_SLOT: 0", 1);
        assert_ne!(
            zeroed_text, devnet_text,
            "fixture no longer carries SECONDS_PER_SLOT in the expected form"
        );
        std::fs::write(dir.path().join("config.yaml"), zeroed_text).unwrap();

        let err = NetworkDir::load(dir.path()).unwrap_err().to_string();
        assert!(err.contains("SECONDS_PER_SLOT"), "got {err}");
    }

    /// Write `dir`'s `config.yaml` as the devnet fixture's with one line
    /// replaced.
    fn replace_config_line(dir: &tempfile::TempDir, from: &str, to: &str) {
        let devnet_text = std::fs::read_to_string(fixture("devnet").join("config.yaml")).unwrap();
        let text = devnet_text.replacen(from, to, 1);
        assert_ne!(text, devnet_text, "fixture no longer carries {from:?}");
        std::fs::write(dir.path().join("config.yaml"), text).unwrap();
    }

    /// A directory built for the other preset must fail naming the preset,
    /// not as an SSZ error from decoding its genesis state against this
    /// build's container bounds.
    #[test]
    fn a_preset_mismatch_is_reported_before_the_genesis_state_is_decoded() {
        let dir = complete_dir();
        let other = if super::super::compiled_preset() == "mainnet" {
            "minimal"
        } else {
            "mainnet"
        };
        replace_config_line(
            &dir,
            "PRESET_BASE: 'mainnet'",
            &format!("PRESET_BASE: '{other}'"),
        );
        // No preset decodes these bytes, so reaching the decode would fail as
        // `Genesis` rather than `Preset`.
        std::fs::write(dir.path().join("genesis.ssz"), b"not a state").unwrap();

        let err = NetworkDir::load(dir.path()).unwrap_err();
        assert!(matches!(err, NetworkDirError::Preset { .. }), "got {err}");
        assert!(
            err.to_string().contains("Rebuild with --features"),
            "got {err}"
        );
    }

    #[test]
    fn a_changed_compiled_constant_is_refused_naming_the_key() {
        let dir = complete_dir();
        replace_config_line(&dir, "CUSTODY_REQUIREMENT: 4", "CUSTODY_REQUIREMENT: 8");

        let err = NetworkDir::load(dir.path()).unwrap_err();
        assert!(
            matches!(err, NetworkDirError::Constants { .. }),
            "got {err}"
        );
        let err = err.to_string();
        assert!(err.contains("config.yaml"), "got {err}");
        assert!(err.contains("CUSTODY_REQUIREMENT is 8"), "got {err}");
    }

    #[test]
    fn a_missing_genesis_state_names_the_path() {
        let dir = complete_dir();
        std::fs::remove_file(dir.path().join("genesis.ssz")).unwrap();
        let err = NetworkDir::load(dir.path()).unwrap_err().to_string();
        assert!(err.contains("genesis.ssz"), "got {err}");
    }

    #[test]
    fn bootnodes_are_optional() {
        let dir = complete_dir();
        std::fs::remove_file(dir.path().join("bootstrap_nodes.txt")).unwrap();
        let loaded = NetworkDir::load(dir.path()).unwrap();
        assert!(loaded.bootnodes.is_empty());
    }

    /// A genesis state encoded in a later fork's shape must load through the
    /// fork the config schedules for epoch 0, not through phase0 (see the
    /// `fork` comment in [`NetworkDir::load`]). Nothing exercised that path:
    /// `devnet`'s fixture keeps mainnet's fork schedule, so its `genesis.ssz`
    /// always decodes as `Phase0`.
    #[test]
    fn a_genesis_state_at_a_later_fork_decodes_through_its_own_schedule() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::copy(
            fixture("devnet-electra").join("config.yaml"),
            dir.path().join("config.yaml"),
        )
        .unwrap();

        // A real electra state, produced by chaining the actual upgrade
        // functions off mainnet's phase0 genesis, rather than a hand-built
        // one: this exercises the same SSZ shape a devnet's genesis
        // generator would ship.
        let config = Config::mainnet();
        let mut state = crate::beacon::mainnet_genesis_state().unwrap();
        for fork in [
            ForkName::Altair,
            ForkName::Bellatrix,
            ForkName::Capella,
            ForkName::Deneb,
            ForkName::Electra,
        ] {
            state =
                ethlambda_state_transition::beacon::upgrade::upgrade_state(&state, fork, &config)
                    .unwrap_or_else(|err| panic!("upgrade to {fork:?} failed: {err}"));
        }
        assert_eq!(state.fork_name(), ForkName::Electra);
        std::fs::write(dir.path().join("genesis.ssz"), state.to_ssz()).unwrap();

        let loaded = NetworkDir::load(dir.path()).unwrap();
        assert_eq!(loaded.genesis_state.fork_name(), ForkName::Electra);
    }

    #[test]
    fn the_yaml_bootnode_file_wins_over_the_text_one() {
        // kurtosis ships both. Reading either is correct; reading one
        // deterministically is what makes the behaviour testable.
        let dir = complete_dir();
        std::fs::write(
            dir.path().join("bootstrap_nodes.yaml"),
            "- enr:-Iu4QLm7bZGdAt9NSeJG0cEnJohWcQTQaI9wFLu3Q7eHIDfrI4cwtzvEW3F3VbG9XdFXlrHyFGeXPn9snTCQJ9bnMRABgmlkgnY0gmlwhAOTJQCJc2VjcDI1NmsxoQIZdZD6tDYpkpEfVo5bgiU8MGRjhcOmHGD2nErK0UKRrIN0Y3CCIyiDdWRwgiMo\n",
        )
        .unwrap();
        let loaded = NetworkDir::load(dir.path()).unwrap();
        assert_eq!(loaded.bootnodes.len(), 1, "the yaml file should have won");
    }
}
