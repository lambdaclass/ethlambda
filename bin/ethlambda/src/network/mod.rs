//! Resolving which network `ethlambda beacon` follows.
//!
//! A `--network` value is either a built-in name or a path. The two are told
//! apart by a slash rather than by probing the filesystem, so a directory
//! named `mainnet` can never shadow the built-in and a mistyped name fails
//! saying what names exist rather than saying a path is missing.

pub(crate) mod built_in;
pub(crate) mod config_file;
pub(crate) mod dir;

use std::path::PathBuf;

use ethlambda_types::beacon::config::Config;

pub(crate) use built_in::BuiltInNetwork;

/// The default when `--network` is absent.
pub(crate) const DEFAULT_NETWORK: &str = BuiltInNetwork::Mainnet.name();

/// What a `--network` value named.
#[derive(Debug, Clone)]
pub(crate) enum NetworkSpec {
    /// A network compiled into the binary.
    BuiltIn(BuiltInNetwork),
    /// A directory of published files.
    Directory(PathBuf),
}

#[derive(Debug, thiserror::Error)]
#[error(
    "unknown network {name:?}; known networks are {known}. \
         To load a network from disk, give a path containing a slash, \
         for example ./{name}"
)]
pub(crate) struct UnknownNetwork {
    name: String,
    known: String,
}

impl NetworkSpec {
    /// Classify one `--network` value.
    pub(crate) fn parse(value: &str) -> Result<Self, UnknownNetwork> {
        if value.contains('/') {
            return Ok(Self::Directory(PathBuf::from(value)));
        }
        if let Some(network) = BuiltInNetwork::from_name(value) {
            return Ok(Self::BuiltIn(network));
        }
        let known: Vec<&str> = BuiltInNetwork::ALL.iter().map(|n| n.name()).collect();
        Err(UnknownNetwork {
            name: value.to_string(),
            known: known.join(", "),
        })
    }
}

/// The preset this binary's containers were compiled against.
///
/// Read from `ethlambda-types`, never re-derived here with a local
/// `cfg!(feature = "preset-minimal")`. That feature belongs to
/// `ethlambda-types`; `bin/ethlambda` does not declare it, so a `cfg!` in this
/// crate is **always false** and would report "mainnet" even in a minimal
/// build. The check would then wave through exactly the configuration it
/// exists to refuse.
pub(crate) fn compiled_preset() -> &'static str {
    ethlambda_types::beacon::preset::Preset::ACTIVE.name()
}

#[derive(Debug, thiserror::Error)]
#[error(
    "this build serves the {compiled} preset, but the network config declares \
         PRESET_BASE: {declared}. Rebuild with --features ethlambda-types/preset-{declared} \
         to follow this network."
)]
pub(crate) struct PresetMismatch {
    compiled: &'static str,
    declared: String,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PresetCheckError {
    /// `config_file::unknown_preset` fills `preset_base` with an empty string
    /// when `PRESET_BASE` is absent, precisely so this can fail closed rather
    /// than assume "mainnet". Reported on its own, distinctly from
    /// [`PresetMismatch`]: with no declared preset, `{declared}` in that
    /// error's message would render as an empty string, reading as "declares
    /// PRESET_BASE: " with no indication anything is actually missing.
    #[error(
        "the network config does not declare PRESET_BASE, so this build cannot check its \
         preset against the network's"
    )]
    Missing,
    #[error(transparent)]
    Mismatch(#[from] PresetMismatch),
}

/// Refuse a configuration whose preset this build cannot serve.
///
/// A hard error rather than a warning. The preset sets SSZ container bounds, so
/// running anyway would produce a chain that is not spec compliant while
/// looking healthy: Prysm's equivalent check half-works for exactly this
/// reason, changing its timing constants but not its container shapes.
pub(crate) fn check_preset(declared: &str) -> Result<(), PresetCheckError> {
    if declared.is_empty() {
        return Err(PresetCheckError::Missing);
    }
    if declared == compiled_preset() {
        return Ok(());
    }
    Err(PresetMismatch {
        compiled: compiled_preset(),
        declared: declared.to_string(),
    }
    .into())
}

/// Fill in the two [`Config`] fields a `config.yaml` cannot be trusted for.
///
/// Shared by a loaded directory and the built-in networks, whose configs both
/// come out of [`config_file::ConfigFile::parse`].
///
/// `genesis_time` is `#[serde(skip)]`, so parsing leaves it at whatever
/// `Config::default()` carries, which is mainnet's 2020 genesis. It is a
/// property of the genesis state: mainnet's `MIN_GENESIS_TIME` is 23 seconds
/// before its actual genesis, so reading it from the file would put every slot
/// boundary off by that much.
///
/// `slot_duration_ms` is always derived, never read from the file. A beacon
/// chain's slots are a whole number of seconds, so `SECONDS_PER_SLOT` is
/// authoritative and the millisecond field exists for lean's sub-second
/// cadence. A config carrying `SECONDS_PER_SLOT: 6` and no `SLOT_DURATION_MS`
/// would otherwise keep mainnet's 12000 by default, and every duty would fire
/// at the wrong time while the second-resolution field looked correct.
fn derive_genesis_fields(config: &mut Config, genesis_time: u64) {
    config.genesis_time = genesis_time;
    config.slot_duration_ms = config.seconds_per_slot * 1_000;
}

/// A resolved network: everything startup needs before it can build a swarm.
///
/// The built-in arm holds what the binary carries; the loaded arm holds what
/// a directory supplied. Both answer the same questions, so everything
/// downstream reads this rather than branching on where the values came from.
///
/// Both arms are boxed: `Config` is large enough that an inline copy would
/// make one variant far bigger than the other's pointer, which is what
/// `clippy::large_enum_variant` (denied by `make lint`) catches.
#[derive(Debug)]
pub(crate) enum NetworkSource {
    BuiltIn(Box<built_in::BuiltIn>),
    Loaded(Box<dir::NetworkDir>),
}

impl NetworkSource {
    /// Resolve a classified `--network` value.
    pub(crate) fn resolve(spec: &NetworkSpec) -> eyre::Result<Self> {
        match spec {
            NetworkSpec::BuiltIn(network) => {
                tracing::info!(network = network.name(), "Using the built-in network");
                Ok(Self::BuiltIn(Box::new(network.resolve()?)))
            }
            NetworkSpec::Directory(path) => {
                let loaded = dir::NetworkDir::load(path)?;
                check_preset(&loaded.preset_base)?;
                tracing::info!(
                    network = %loaded.config_name,
                    path = %path.display(),
                    "Loaded network from directory"
                );
                Ok(Self::Loaded(Box::new(loaded)))
            }
        }
    }

    /// The built-in mainnet network, for the tests that want a real network
    /// without writing a directory.
    #[cfg(test)]
    pub(crate) fn built_in_mainnet() -> eyre::Result<Self> {
        Ok(Self::BuiltIn(Box::new(BuiltInNetwork::Mainnet.resolve()?)))
    }

    pub(crate) fn config(&self) -> &Config {
        match self {
            Self::BuiltIn(built_in) => &built_in.config,
            Self::Loaded(loaded) => &loaded.config,
        }
    }

    /// The resolved network's name, for logging: a built-in network's name,
    /// or a loaded directory's own `CONFIG_NAME`.
    pub(crate) fn name(&self) -> &str {
        match self {
            Self::BuiltIn(built_in) => built_in.network.name(),
            Self::Loaded(loaded) => &loaded.config_name,
        }
    }

    /// The two genesis values the fork digest is derived from.
    ///
    /// Read off the genesis state for a loaded network. A built-in network
    /// carries no state at all (see [`built_in`]), so it answers from the
    /// pair it was resolved with.
    pub(crate) fn genesis(&self) -> crate::beacon::Genesis {
        match self {
            Self::BuiltIn(built_in) => built_in.genesis,
            Self::Loaded(loaded) => crate::beacon::Genesis::of(&loaded.genesis_state),
        }
    }

    /// The bootnodes this network ships, before `--bootnodes` overrides them.
    pub(crate) fn bootnodes(&self) -> Vec<String> {
        match self {
            Self::BuiltIn(built_in) => built_in.bootnodes.clone(),
            Self::Loaded(loaded) => loaded.bootnodes.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_known_name_resolves_to_the_built_in() {
        for (name, expected) in [
            ("mainnet", BuiltInNetwork::Mainnet),
            ("sepolia", BuiltInNetwork::Sepolia),
            ("hoodi", BuiltInNetwork::Hoodi),
        ] {
            assert!(
                matches!(
                    NetworkSpec::parse(name),
                    Ok(NetworkSpec::BuiltIn(network)) if network == expected
                ),
                "{name} should name its built-in network"
            );
        }
    }

    #[test]
    fn the_default_network_is_built_in_mainnet() {
        assert!(matches!(
            NetworkSpec::parse(DEFAULT_NETWORK),
            Ok(NetworkSpec::BuiltIn(BuiltInNetwork::Mainnet))
        ));
    }

    #[test]
    fn a_bare_unknown_name_errors_listing_the_known_ones() {
        let err = NetworkSpec::parse("holesky").unwrap_err().to_string();
        assert!(err.contains("holesky"), "got {err}");
        for network in BuiltInNetwork::ALL {
            assert!(
                err.contains(network.name()),
                "the error should list every known network: {err}"
            );
        }
    }

    /// Each name resolves to its own chain rather than to mainnet's, which is
    /// what a list of names with a single dispatch arm behind it would do.
    #[test]
    fn each_built_in_network_resolves_to_its_own_chain() {
        let mut roots = Vec::new();
        for network in BuiltInNetwork::ALL {
            let source = NetworkSource::resolve(&NetworkSpec::BuiltIn(network)).unwrap();
            assert_eq!(source.name(), network.name());
            roots.push(source.genesis().genesis_validators_root);
        }
        roots.sort();
        roots.dedup();
        assert_eq!(roots.len(), BuiltInNetwork::ALL.len());
    }

    #[test]
    fn a_value_with_a_slash_is_always_a_directory() {
        // Never looked up as a name, so a directory called `mainnet` cannot
        // shadow the built-in.
        assert!(matches!(
            NetworkSpec::parse("./mainnet"),
            Ok(NetworkSpec::Directory(_))
        ));
        assert!(matches!(
            NetworkSpec::parse("/network-configs"),
            Ok(NetworkSpec::Directory(_))
        ));
    }

    #[test]
    fn the_compiled_preset_is_what_a_config_must_declare() {
        assert!(check_preset(compiled_preset()).is_ok());

        let other = if compiled_preset() == "mainnet" {
            "minimal"
        } else {
            "mainnet"
        };
        let err = check_preset(other).unwrap_err().to_string();
        assert!(err.contains(other), "got {err}");
        assert!(
            err.contains("preset-minimal") || err.contains("preset-mainnet"),
            "name the cargo feature: {err}"
        );
    }

    #[test]
    fn an_absent_preset_base_is_a_distinct_error_from_a_mismatch() {
        // `config_file::unknown_preset` fills an absent PRESET_BASE with "".
        let err = check_preset("").unwrap_err().to_string();
        assert!(err.contains("PRESET_BASE"), "got {err}");
        assert!(
            !err.contains("Rebuild with --features"),
            "a missing PRESET_BASE must not read as a preset mismatch: {err}"
        );
    }
}
