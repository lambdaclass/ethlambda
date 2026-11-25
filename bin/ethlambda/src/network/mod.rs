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
use ethlambda_types::beacon::preset::{Preset, PresetAlreadyActive};

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

#[derive(Debug, thiserror::Error)]
pub(crate) enum PresetSelectError {
    /// `Config::preset_base` defaults to an empty name when `PRESET_BASE` is
    /// absent, precisely so this can fail closed rather than assume
    /// "mainnet". Reported on its own, distinctly from
    /// [`PresetSelectError::Unsupported`]: with no declared preset, the name
    /// in that error's message would render as an empty string, reading as
    /// "PRESET_BASE: " with no indication anything is actually missing.
    #[error("the network config does not declare PRESET_BASE, so its preset is unknown")]
    Missing,
    /// A preset the specification does not define, or one (such as `gnosis`)
    /// whose values this node does not carry.
    #[error(
        "the network config declares PRESET_BASE: {declared}, which this node has no values \
         for; it runs mainnet or minimal"
    )]
    Unsupported { declared: String },
    /// Something in this process read a preset value before the network was
    /// resolved, and froze another preset. A startup ordering bug, not an
    /// operator error.
    #[error(transparent)]
    AlreadyActive(#[from] PresetAlreadyActive),
}

/// Run this process on the preset a network's config declares.
///
/// Called as soon as a `config.yaml` parses, before anything is decoded
/// against it: for a loaded directory, before its `genesis.ssz`, whose
/// container bounds come from the preset. Every beacon container checks its
/// lengths, decodes and merkleizes against the preset selected here, and the
/// first read freezes it, so nothing on this path may read a preset value
/// before this call.
///
/// A missing or unknown `PRESET_BASE` is a hard error rather than a fallback
/// to mainnet. The preset sets SSZ container bounds, so a node on the wrong
/// one would produce a chain that is not spec compliant while looking
/// healthy: Prysm's equivalent check half-works for exactly this reason,
/// changing its timing constants but not its container shapes.
pub(crate) fn select_preset(declared: &str) -> Result<Preset, PresetSelectError> {
    if declared.is_empty() {
        return Err(PresetSelectError::Missing);
    }
    let preset: Preset = declared
        .parse()
        .map_err(|_| PresetSelectError::Unsupported {
            declared: declared.to_string(),
        })?;
    Preset::select(preset)?;
    Ok(preset)
}

/// Makes the network's `X_MAX_COMMITTEE_COUNT_PER_SLOT` the cap every PQ
/// committee count of this process uses (consensus-specs pq `af898d07`).
/// After [`select_preset`], whose `MAX_COMMITTEES_PER_SLOT_PQ` bounds it: a
/// value above that, or zero, is moved into range with a warning rather than
/// refused, since the key is a testing knob and `CommitteeBits` could not
/// hold more committees anyway.
pub(crate) fn select_committee_cap(config: &Config) {
    let declared = config.x_max_committee_count_per_slot;
    let cap = ethlambda_types::beacon::config::select_x_max_committee_count_per_slot(config);
    if cap != declared {
        tracing::warn!(
            declared,
            used = cap,
            max_committees_per_slot_pq =
                ethlambda_types::beacon::preset::max_committees_per_slot_pq(),
            "X_MAX_COMMITTEE_COUNT_PER_SLOT is outside 1..=MAX_COMMITTEES_PER_SLOT_PQ; using the nearest value"
        );
    }
}

/// One `config.yaml` key that the node runs on a compile-time constant for,
/// set to another value.
#[derive(Debug)]
pub(crate) struct ConstantMismatch {
    /// The key as the file spells it.
    key: String,
    declared: String,
    compiled: String,
}

/// Every [`ConstantMismatch`] one configuration has, reported together so an
/// operator fixes them in one pass rather than one restart per key.
#[derive(Debug)]
pub(crate) struct ConstantsMismatch(Vec<ConstantMismatch>);

impl std::fmt::Display for ConstantsMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the network config sets values this build cannot run with, since it uses \
             compile-time constants for them:"
        )?;
        for ConstantMismatch {
            key,
            declared,
            compiled,
        } in &self.0
        {
            write!(f, " {key} is {declared}, this build uses {compiled};")?;
        }
        Ok(())
    }
}

impl std::error::Error for ConstantsMismatch {}

/// Refuse a configuration that sets a value this build runs on a compile-time
/// constant for to anything else.
///
/// `Config` carries these keys so that `/eth/v1/config/spec` can report them,
/// but the networking and custody code reads the constants, some of which size
/// a type (the `attnets` bitfield is an `SszBitvector` of
/// `ATTESTATION_SUBNET_COUNT` bits). Refusing the mismatch at startup is what
/// keeps the endpoint truthful: every `Config` that reaches the store equals
/// the constants on these keys. It is a hard error rather than a warning for
/// the reason [`select_preset`] is one. A node that disagrees with its peers
/// about custody or subnet counts would still look healthy while failing to
/// serve or verify what they expect.
///
/// The list is every `Config` field whose key names a value this build also
/// defines as a constant; a field the node does not act on at all (such as
/// `SUBNETS_PER_NODE`, since it subscribes to no attestation subnet) has no
/// constant to disagree with and is reported as the file sets it.
pub(crate) fn check_constants(config: &Config) -> Result<(), ConstantsMismatch> {
    use ethlambda_p2p::beacon::{constants as p2p, protocols};
    use ethlambda_types::beacon::constants;

    let mut mismatches = Vec::new();
    macro_rules! check {
        ($($field:ident == $compiled:expr),+ $(,)?) => {
            $(
                if config.$field != $compiled {
                    mismatches.push(ConstantMismatch {
                        key: stringify!($field).to_ascii_uppercase(),
                        declared: format!("{:?}", config.$field),
                        compiled: format!("{:?}", $compiled),
                    });
                }
            )+
        };
    }
    check!(
        attestation_subnet_count == p2p::ATTESTATION_SUBNET_COUNT,
        attestation_subnet_count_pq == p2p::ATTESTATION_SUBNET_COUNT_PQ,
        data_column_sidecar_subnet_count == constants::DATA_COLUMN_SIDECAR_SUBNET_COUNT,
        number_of_custody_groups == constants::NUMBER_OF_CUSTODY_GROUPS,
        custody_requirement == constants::CUSTODY_REQUIREMENT,
        samples_per_slot == constants::SAMPLES_PER_SLOT,
        min_epochs_for_data_column_sidecars_requests
            == constants::MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS,
        maximum_gossip_clock_disparity == constants::MAXIMUM_GOSSIP_CLOCK_DISPARITY,
        max_request_blocks == protocols::MAX_REQUEST_BLOCKS,
        max_request_blocks_deneb == protocols::MAX_REQUEST_BLOCKS_DENEB,
        max_request_payloads == protocols::MAX_REQUEST_PAYLOADS,
        max_request_data_column_sidecars == protocols::max_request_data_column_sidecars(),
        max_payload_size == ethlambda_p2p::MAX_PAYLOAD_SIZE as u64,
        message_domain_invalid_snappy == ethlambda_p2p::MESSAGE_DOMAIN_INVALID_SNAPPY,
        message_domain_valid_snappy == ethlambda_p2p::MESSAGE_DOMAIN_VALID_SNAPPY,
    );

    if mismatches.is_empty() {
        Ok(())
    } else {
        Err(ConstantsMismatch(mismatches))
    }
}

/// Fill in the [`Config`] field a `config.yaml` cannot be trusted for.
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
/// The slot-time fields are not touched here: they are reconciled once, at
/// parse time (see `config_file::reconcile_slot_time`), so built-in and
/// loaded networks share the rule.
fn derive_genesis_fields(config: &mut Config, genesis_time: u64) {
    config.genesis_time = genesis_time;
}

/// Warn at startup when `config` schedules a fork this build does not follow
/// ([`ForkName::is_followed`](ethlambda_types::beacon::fork::ForkName::is_followed)),
/// whichever way this network was resolved.
///
/// Shared by a loaded directory and the built-in networks for the same
/// reason [`derive_genesis_fields`] is. The ignored-keys warning
/// (`ConfigFile::warn_about_ignored_keys`) does not say this: it names keys
/// the build does not claim, and the keys of a fork it does claim parse
/// cleanly. So this says it explicitly instead of leaving it to be discovered
/// as a stall: from that fork's epoch the chain actor refuses every block, so
/// a follower stops making progress there regardless of how cleanly its
/// config parsed. A loaded network reaches this the same as a built-in one,
/// and can even schedule such a fork at epoch 0, in which case its own genesis
/// state already decodes as that fork and startup refuses it outright
/// (`refuse_unfollowable_fork` in `main.rs`); this warning fires first either
/// way. Every fork `ForkName` models is followed today, gloas included, so
/// this is the guard for the next fork the node cannot follow.
fn warn_if_unfollowed_fork_scheduled(network: &str, config: &Config) {
    let unfollowed = ethlambda_types::beacon::fork::ForkName::ALL
        .into_iter()
        .filter(|fork| !fork.is_followed());
    for fork in unfollowed {
        let fork_epoch = config.fork_epoch(fork);
        if fork_epoch != ethlambda_types::beacon::constants::FAR_FUTURE_EPOCH {
            tracing::warn!(
                network,
                fork = fork.as_str(),
                fork_epoch,
                "This build stops following this chain at the epoch of a fork it does \
                 not follow; crossing it is not a stall a restart clears, since the \
                 chain actor refuses every block of that fork"
            );
        }
    }
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
                let resolved = network.resolve()?;
                tracing::info!(
                    network = network.name(),
                    preset = %Preset::active(),
                    "Using the built-in network"
                );
                Ok(Self::BuiltIn(Box::new(resolved)))
            }
            NetworkSpec::Directory(path) => {
                // `load` selects the preset and checks the constants itself,
                // before it decodes `genesis.ssz`, whose container bounds the
                // preset sets.
                let loaded = dir::NetworkDir::load(path)?;
                tracing::info!(
                    network = %loaded.config.config_name,
                    preset = %Preset::active(),
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

    /// The resolved network's `CONFIG_NAME`, for logging. A built-in
    /// network's is its own name, whatever its file says (see
    /// [`BuiltInNetwork::resolve`]), which `every_built_in_network_resolves`
    /// checks.
    pub(crate) fn name(&self) -> &str {
        self.config().config_name.as_str()
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

    /// The bootnodes this network ships, which `beacon`'s `--bootnodes`
    /// entries are added to (never replace).
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
            ("plataberget", BuiltInNetwork::Plataberget),
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

    /// The tests share one process, so whichever preset froze first (another
    /// test's read, or the read below) is the one a config may select; the
    /// other is refused as already superseded rather than silently mixed in.
    #[test]
    fn a_config_selects_its_preset_once() {
        let active = Preset::active();
        assert_eq!(select_preset(active.name()).unwrap(), active);

        let other = match active {
            Preset::Mainnet => Preset::Minimal,
            Preset::Minimal => Preset::Mainnet,
        };
        let err = select_preset(other.name()).unwrap_err();
        assert!(
            matches!(err, PresetSelectError::AlreadyActive(_)),
            "got {err}"
        );
        assert!(err.to_string().contains(other.name()), "got {err}");
        assert_eq!(Preset::active(), active);
    }

    #[test]
    fn a_preset_without_values_is_refused_by_name() {
        let err = select_preset("gnosis").unwrap_err();
        assert!(
            matches!(err, PresetSelectError::Unsupported { .. }),
            "got {err}"
        );
        assert!(err.to_string().contains("gnosis"), "got {err}");
    }

    /// The specification's own configs must pass, or every built-in network
    /// and every devnet derived from one would be refused.
    #[test]
    fn the_shipped_configs_match_the_compiled_constants() {
        check_constants(&Config::mainnet()).unwrap();
        check_constants(&Config::minimal()).unwrap();
    }

    #[test]
    fn a_config_that_changes_a_compiled_constant_is_refused_naming_each_key() {
        let mut config = Config::mainnet();
        config.custody_requirement = 8;
        config.message_domain_valid_snappy = [0x02, 0x00, 0x00, 0x00];

        let err = check_constants(&config).unwrap_err().to_string();
        assert!(
            err.contains("CUSTODY_REQUIREMENT is 8, this build uses 4"),
            "got {err}"
        );
        assert!(
            err.contains("MESSAGE_DOMAIN_VALID_SNAPPY is [2, 0, 0, 0]"),
            "got {err}"
        );
    }

    #[test]
    fn a_config_that_changes_the_envelope_request_ceiling_is_refused() {
        let mut config = Config::mainnet();
        config.max_request_payloads = 64;

        let err = check_constants(&config).unwrap_err().to_string();
        assert!(err.contains("MAX_REQUEST_PAYLOADS is 64"), "got {err}");
    }

    #[test]
    fn an_absent_preset_base_is_a_distinct_error_from_an_unknown_one() {
        // `Config::preset_base` defaults an absent PRESET_BASE to "".
        let err = select_preset("").unwrap_err();
        assert!(matches!(err, PresetSelectError::Missing), "got {err}");
        assert!(err.to_string().contains("PRESET_BASE"), "got {err}");
    }
}
