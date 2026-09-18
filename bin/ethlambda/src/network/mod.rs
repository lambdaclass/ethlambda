//! Resolving which network `ethlambda beacon` follows.
//!
//! A `--network` value is either a built-in name or a path. The two are told
//! apart by a slash rather than by probing the filesystem, so a directory
//! named `mainnet` can never shadow the built-in and a mistyped name fails
//! saying what names exist rather than saying a path is missing.

pub(crate) mod config_file;
pub(crate) mod dir;

use std::path::PathBuf;

use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::containers::BeaconState;

/// The built-in networks, by the name `--network` accepts.
pub(crate) const BUILT_IN_NETWORKS: [&str; 1] = ["mainnet"];

/// The default when `--network` is absent.
pub(crate) const DEFAULT_NETWORK: &str = "mainnet";

/// What a `--network` value named.
#[derive(Debug, Clone)]
pub(crate) enum NetworkSpec {
    /// A network compiled into the binary.
    BuiltIn(String),
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
        if BUILT_IN_NETWORKS.contains(&value) {
            return Ok(Self::BuiltIn(value.to_string()));
        }
        Err(UnknownNetwork {
            name: value.to_string(),
            known: BUILT_IN_NETWORKS.join(", "),
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

/// A resolved network: everything startup needs before it can build a swarm.
///
/// The built-in arm keeps the compiled-in constants; the loaded arm holds what
/// a directory supplied. Both answer the same three questions, so everything
/// downstream reads this rather than branching on where the values came from.
#[derive(Debug)]
pub(crate) enum NetworkSource {
    BuiltInMainnet {
        genesis_state: Box<BeaconState>,
        // Boxed like `genesis_state`, not inline: `Config` is large enough
        // that an inline copy here would make this variant far bigger than
        // `Loaded`'s single pointer, which is what `clippy::large_enum_variant`
        // (denied by `make lint`) catches.
        config: Box<Config>,
    },
    Loaded(Box<dir::NetworkDir>),
}

impl NetworkSource {
    /// Resolve a classified `--network` value.
    pub(crate) fn resolve(spec: &NetworkSpec) -> eyre::Result<Self> {
        match spec {
            NetworkSpec::BuiltIn(name) => {
                // `BUILT_IN_NETWORKS` has exactly one entry today, so `name`
                // can only be "mainnet" here (`NetworkSpec::parse` only
                // constructs this variant for a value found in that list).
                // Nothing dispatches on `name` below: a second built-in
                // network would silently resolve to mainnet too. Adding a
                // registry now would be speculative for a single entry, so
                // this assertion is the guard instead -- it turns loud the
                // day `BUILT_IN_NETWORKS` actually grows.
                debug_assert_eq!(
                    name, "mainnet",
                    "a second built-in network needs its own dispatch here, not just a list entry"
                );
                tracing::info!(network = %name, "Using the built-in network");
                Self::built_in_mainnet()
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

    /// The built-in mainnet network.
    pub(crate) fn built_in_mainnet() -> eyre::Result<Self> {
        Ok(Self::BuiltInMainnet {
            genesis_state: Box::new(crate::beacon::mainnet_genesis_state()?),
            config: Box::new(Config::mainnet()),
        })
    }

    pub(crate) fn config(&self) -> &Config {
        match self {
            Self::BuiltInMainnet { config, .. } => config.as_ref(),
            Self::Loaded(loaded) => &loaded.config,
        }
    }

    /// The resolved network's name, for logging: the one built-in name, or a
    /// loaded directory's own `CONFIG_NAME`.
    pub(crate) fn name(&self) -> &str {
        match self {
            Self::BuiltInMainnet { .. } => "mainnet",
            Self::Loaded(loaded) => &loaded.config_name,
        }
    }

    pub(crate) fn genesis_state(&self) -> &BeaconState {
        // `as_ref` on both arms, not `&`: the fields are `Box<BeaconState>`,
        // so a bare borrow yields `&Box<BeaconState>`.
        match self {
            Self::BuiltInMainnet { genesis_state, .. } => genesis_state.as_ref(),
            Self::Loaded(loaded) => loaded.genesis_state.as_ref(),
        }
    }

    /// The two genesis values the fork digest is derived from.
    pub(crate) fn genesis(&self) -> crate::beacon::Genesis {
        let state = self.genesis_state();
        crate::beacon::Genesis {
            genesis_time: state.genesis_time(),
            genesis_validators_root: state.genesis_validators_root(),
        }
    }

    /// The bootnodes this network ships, before `--bootnodes` overrides them.
    pub(crate) fn bootnodes(&self) -> Vec<String> {
        match self {
            Self::BuiltInMainnet { .. } => crate::beacon::MAINNET_BOOTNODES
                .iter()
                .map(|enr| enr.to_string())
                .collect(),
            Self::Loaded(loaded) => loaded.bootnodes.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_known_name_resolves_to_the_built_in() {
        assert!(matches!(
            NetworkSpec::parse("mainnet"),
            Ok(NetworkSpec::BuiltIn(_))
        ));
    }

    #[test]
    fn a_bare_unknown_name_errors_listing_the_known_ones() {
        let err = NetworkSpec::parse("hoodi").unwrap_err().to_string();
        assert!(err.contains("hoodi"), "got {err}");
        assert!(
            err.contains("mainnet"),
            "the error should list what is known: {err}"
        );
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
