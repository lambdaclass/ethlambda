//! Runtime chain configuration: the values `configs/mainnet.yaml` and
//! `configs/minimal.yaml` set per network, as opposed to constants (fixed by
//! the specification, see [`crate::beacon::constants`]) or preset values (compile-time
//! container bounds, see [`crate::beacon::preset`]).
//!
//! Fork *scheduling* lives here rather than at compile time specifically
//! because the `transition` fixture suite needs to move a fork's activation
//! epoch per test case; there is no other reason a fork version or epoch
//! could not have been a preset. Everything else in [`Config`] is here simply
//! because the specification itself calls it configuration.
//!
//! # What is left out
//!
//! - **Forks this build cannot process.** `HEZE_FORK_VERSION`/`HEZE_FORK_EPOCH`
//!   and `EIP8321_FORK_VERSION`/`EIP8321_FORK_EPOCH` (its own later fork
//!   schedule) stay out for the same reason `GLOAS_*` used to: a fork version
//!   stored here would give [`Config::fork_at_epoch`] a fork
//!   [`crate::beacon::fork::ForkName`] has no variant for, so each is
//!   reported as an unknown key instead. `GAS_LIMIT_SCHEDULE` (gloas-era)
//!   stays out too, since it is a list rather than a scalar. The rest are
//!   heze-era data keys, not gloas's, with no reader in this build at all:
//!   `INCLUSION_LIST_DUE_BPS`, `MAX_REQUEST_INCLUSION_LIST`,
//!   `MIN_SLOTS_FOR_INCLUSION_LISTS_REQUESTS`, and
//!   `MAX_TRANSACTIONS_BYTES_PER_INCLUSION_LIST` (EIP-7805's fork-choice-enforced
//!   inclusion lists), and `CONFIRMATION_BYZANTINE_THRESHOLD` (the Fast
//!   Confirmation Rule).
//!
//! `PRESET_BASE` and `CONFIG_NAME` used to be left out as well, because they
//! are strings and this struct is SSZ-encoded into the database. They are here
//! now, as bounded [`ConfigName`]s, so that `/eth/v1/config/spec` reads every
//! value it reports from the one `Config` the store holds, rather than having
//! the name threaded to it separately from startup.
//!
//! Networking values and the deposit contract identity used to be left out too,
//! on the grounds that the state transition never reads them. They are here now
//! because they have a second reader: `/eth/v1/config/spec` must echo every key
//! a `config.yaml` carries, and a key with no typed home would be reported as
//! unknown on every startup of every valid configuration, which would bury a
//! real typo among forty legitimate warnings.
//!
//! The genesis-section values are all included. `GENESIS_FORK_VERSION` is fork
//! scheduling rather than genesis construction, since [`Config::fork_version`]
//! reads it on every phase0-era signature. The other three
//! (`MIN_GENESIS_ACTIVE_VALIDATOR_COUNT`, `MIN_GENESIS_TIME`, `GENESIS_DELAY`)
//! are read only while building a genesis state from Eth1 deposit history, and
//! never again once that state exists, but the beacon STF's `genesis` module
//! needs them and the `genesis` fixture suite checks them.

use libssz_derive::{SszDecode, SszEncode};
use libssz_types::SszList;

use crate::beacon::constants;
use crate::beacon::fork::ForkName;
use crate::beacon::lean_fork_unreachable;
use crate::beacon::primitives::{Epoch, ExecutionBlockHash, Gwei, U256, Uint256, Version};
use crate::chain_config::ChainConfig;
use crate::constants::INTERVALS_PER_SLOT;

/// One entry in fulu's blob schedule: from `epoch` onward (until a later
/// entry takes over), a block may carry up to `max_blobs_per_block` blobs.
///
/// Modeled as a plain struct rather than a `(Epoch, u64)` tuple so that
/// [`Config::max_blobs_per_block`]'s search reads as "find the entry", not
/// "find the pair".
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SszEncode, SszDecode, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct BlobScheduleEntry {
    /// The first epoch this entry applies to.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub epoch: Epoch,
    /// The blob count limit from `epoch` onward.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub max_blobs_per_block: u64,
}

/// How many blob-schedule entries a persisted [`Config`] can carry.
///
/// A storage bound, not a consensus one: SSZ needs a bounded list and the real
/// schedule holds roughly one entry per fork, so this is generous. Raising it
/// changes the on-disk encoding, which is why the database carries a format
/// version.
pub const MAX_BLOB_SCHEDULE_ENTRIES: usize = 32;

/// How many bytes a [`ConfigName`] can hold.
///
/// A storage bound, not a consensus one, for the same reason as
/// [`MAX_BLOB_SCHEDULE_ENTRIES`]: the specification leaves both names
/// unbounded, and the ones in use (`mainnet`, `minimal`, `sepolia`, `hoodi`,
/// kurtosis's `testnet`) are a few bytes each.
pub const MAX_CONFIG_NAME_LENGTH: usize = 256;

/// A name a `config.yaml` carries: its `CONFIG_NAME` or `PRESET_BASE`.
///
/// Text of at most [`MAX_CONFIG_NAME_LENGTH`] bytes, which every constructor
/// checks. SSZ-encoded as a `List[uint8, MAX_CONFIG_NAME_LENGTH]`, since
/// [`Config`] is persisted to the database; (de)serialized as a plain string,
/// which is how both the file and `/eth/v1/config/spec` write it.
///
/// Held as a `String` rather than as the byte list it encodes to, so that
/// [`Self::as_str`] borrows instead of re-checking UTF-8 on every call. The SSZ
/// impls are written out for that reason: a derive would need the field to be
/// the list.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ConfigName(String);

/// The quoted text: a resume that refuses a changed `PRESET_BASE`, or warns
/// about a changed `CONFIG_NAME`, prints both through `{:?}`.
impl std::fmt::Debug for ConfigName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

/// A name longer than [`MAX_CONFIG_NAME_LENGTH`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{length} bytes is longer than the {MAX_CONFIG_NAME_LENGTH} a config name may hold")]
pub struct ConfigNameTooLong {
    pub length: usize,
}

impl ConfigName {
    /// A name known to fit, such as a built-in network's.
    ///
    /// # Panics
    ///
    /// If `name` is longer than [`MAX_CONFIG_NAME_LENGTH`].
    fn fixed(name: &str) -> Self {
        Self::try_from(name).expect("a built-in name fits the bound")
    }

    /// The name as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for ConfigName {
    type Error = ConfigNameTooLong;

    fn try_from(name: &str) -> Result<Self, Self::Error> {
        if name.len() > MAX_CONFIG_NAME_LENGTH {
            return Err(ConfigNameTooLong { length: name.len() });
        }
        Ok(Self(name.to_owned()))
    }
}

impl std::fmt::Display for ConfigName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The name's bytes, which is how `SszList<u8, MAX_CONFIG_NAME_LENGTH>`
/// encodes them too: a list of a fixed-size basic type is its elements
/// concatenated, with no length prefix of its own.
impl libssz::SszEncode for ConfigName {
    fn is_fixed_size() -> bool {
        false
    }

    fn fixed_size() -> usize {
        0
    }

    fn encoded_len(&self) -> usize {
        self.0.len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.0.as_bytes());
    }
}

impl libssz::SszDecode for ConfigName {
    fn is_fixed_size() -> bool {
        false
    }

    fn fixed_size() -> usize {
        0
    }

    /// Decoded through the list type, so an over-long name is refused with
    /// the list's own error.
    ///
    /// Lossy rather than fallible on bytes that are not UTF-8. Every
    /// constructor takes a `&str`, so only a corrupt database can hold such
    /// bytes, and `DecodeError` has no variant that describes them. A repaired
    /// `PRESET_BASE` still fails the resume comparison against the file's,
    /// and a repaired `CONFIG_NAME` shows up in the warning about it.
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, libssz::DecodeError> {
        let list = SszList::<u8, MAX_CONFIG_NAME_LENGTH>::from_ssz_bytes(bytes)?;
        Ok(Self(String::from_utf8_lossy(&list).into_owned()))
    }
}

impl serde::Serialize for ConfigName {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for ConfigName {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::try_from(name.as_str()).map_err(serde::de::Error::custom)
    }
}

/// The runtime configuration for one network: fork scheduling plus every
/// other value the state transition and fork choice read at runtime rather
/// than at compile time.
///
/// Construct one with [`Config::mainnet`], [`Config::minimal`], or
/// [`Config::active`]; adjust a single fork's activation epoch with
/// [`Config::with_fork_epoch`] for fixture-driven tests that need one.
#[derive(
    Debug, Clone, PartialEq, Eq, SszEncode, SszDecode, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", default)]
pub struct Config {
    // -- Identity ---------------------------------------------------------
    /// `PRESET_BASE`: which preset the file was written for.
    ///
    /// Startup refuses a file whose value differs from the compiled preset, so
    /// on a running node this always names [`crate::beacon::preset::Preset::ACTIVE`].
    ///
    /// Defaults to empty rather than to mainnet's value when the file omits
    /// it: the startup check has to fail on an absent key rather than guess.
    #[serde(default)]
    pub preset_base: ConfigName,
    /// `CONFIG_NAME`: the network's name, for logging and
    /// `/eth/v1/config/spec`. Empty when the file omits it.
    #[serde(default)]
    pub config_name: ConfigName,

    // -- Genesis construction ---------------------------------------------
    /// How many active validators the chain needs before it may start.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub min_genesis_active_validator_count: u64,
    /// The earliest wall-clock time the chain may start at, whatever the Eth1
    /// deposit history says.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub min_genesis_time: u64,
    /// How long after the Eth1 block that satisfies the genesis conditions the
    /// chain actually starts.
    ///
    /// The delay exists so that validators who deposited just before the
    /// threshold was crossed still have time to get their nodes running.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub genesis_delay: u64,
    /// The wall-clock second the chain's slot 0 began, which every slot
    /// boundary is computed from.
    ///
    /// Distinct from [`Self::min_genesis_time`], which is only the earliest
    /// time the deposit-driven genesis rules would have permitted: on mainnet
    /// that is 1606824000 against an actual genesis of 1606824023. Reusing
    /// that one for the clock would put every slot boundary 23 seconds off.
    ///
    /// On a beacon chain this is read off the anchor state at bootstrap. On a
    /// lean chain it comes from the genesis config file.
    #[serde(skip)]
    pub genesis_time: u64,

    // -- Fork scheduling --------------------------------------------------
    /// The `Fork.current_version` a phase0 block or attestation signs under,
    /// and the value every later fork's version is a successor to. Also
    /// mixed into `compute_fork_data_root` when computing the genesis
    /// validators root's domain, alongside the all-zero genesis validators
    /// root, at chain start.
    #[serde(with = "crate::beacon::serde_helpers::hex_array")]
    pub genesis_fork_version: Version,
    /// The `Fork.current_version` an altair block or attestation signs under.
    #[serde(with = "crate::beacon::serde_helpers::hex_array")]
    pub altair_fork_version: Version,
    /// The epoch altair activates at, or [`constants::FAR_FUTURE_EPOCH`] if it
    /// is not scheduled on this network.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub altair_fork_epoch: Epoch,
    /// The `Fork.current_version` a bellatrix block or attestation signs
    /// under.
    #[serde(with = "crate::beacon::serde_helpers::hex_array")]
    pub bellatrix_fork_version: Version,
    /// The epoch bellatrix (the Merge) activates at, or
    /// [`constants::FAR_FUTURE_EPOCH`] if it is not scheduled.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub bellatrix_fork_epoch: Epoch,
    /// The `Fork.current_version` a capella block or attestation signs under.
    #[serde(with = "crate::beacon::serde_helpers::hex_array")]
    pub capella_fork_version: Version,
    /// The epoch capella activates at, or [`constants::FAR_FUTURE_EPOCH`] if
    /// it is not scheduled.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub capella_fork_epoch: Epoch,
    /// The `Fork.current_version` a deneb block or attestation signs under.
    #[serde(with = "crate::beacon::serde_helpers::hex_array")]
    pub deneb_fork_version: Version,
    /// The epoch deneb activates at, or [`constants::FAR_FUTURE_EPOCH`] if it
    /// is not scheduled.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub deneb_fork_epoch: Epoch,
    /// The `Fork.current_version` an electra block or attestation signs
    /// under.
    #[serde(with = "crate::beacon::serde_helpers::hex_array")]
    pub electra_fork_version: Version,
    /// The epoch electra activates at, or [`constants::FAR_FUTURE_EPOCH`] if
    /// it is not scheduled.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub electra_fork_epoch: Epoch,
    /// The `Fork.current_version` a fulu block or attestation signs under.
    #[serde(with = "crate::beacon::serde_helpers::hex_array")]
    pub fulu_fork_version: Version,
    /// The epoch fulu activates at, or [`constants::FAR_FUTURE_EPOCH`] if it
    /// is not scheduled.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub fulu_fork_epoch: Epoch,
    /// The `Fork.current_version` a gloas block or attestation signs under.
    #[serde(with = "crate::beacon::serde_helpers::hex_array")]
    pub gloas_fork_version: Version,
    /// The epoch gloas activates at, or [`constants::FAR_FUTURE_EPOCH`] if it
    /// is not scheduled.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub gloas_fork_epoch: Epoch,

    // -- Time parameters ---------------------------------------------------
    /// Wall-clock seconds per slot. Deprecated in favor of
    /// [`Self::slot_duration_ms`] for anything needing sub-second precision,
    /// but still how `compute_time_at_slot` and the fork choice store's
    /// `genesis_time`-to-slot arithmetic convert between a slot number and a
    /// wall-clock time.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub seconds_per_slot: u64,
    /// Milliseconds per slot. What the fork choice store's timeliness
    /// checks (`get_attestation_due_ms` and friends) actually divide the
    /// `*_due_bps` fields below by; equal to `seconds_per_slot * 1000` on
    /// every network this crate ships a constructor for, but tracked
    /// separately because the specification does.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub slot_duration_ms: u64,
    /// The assumed seconds per execution-layer block, used to convert
    /// [`Self::eth1_follow_distance`] (a block count) into a voting-period
    /// safety margin.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub seconds_per_eth1_block: u64,
    /// Epochs a validator must wait after its exit is processed before its
    /// balance becomes withdrawable.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub min_validator_withdrawability_delay: Epoch,
    /// Epochs a validator must be active before it is eligible to propose,
    /// perform voluntary exits, or (from electra) initiate a consolidation.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub shard_committee_period: Epoch,
    /// Execution-layer blocks a state's Eth1 vote must lag the execution
    /// chain's head by, so that every node's view of "current" Eth1 data
    /// agrees despite network latency and minor reorgs.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub eth1_follow_distance: u64,
    /// Basis points of [`Self::slot_duration_ms`] by which an attestation is
    /// due; read by the fork choice store's `get_attestation_due_ms`.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub attestation_due_bps: u64,
    /// Basis points of [`Self::slot_duration_ms`] by which an aggregate
    /// attestation is due; read by `get_aggregate_due_ms`.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub aggregate_due_bps: u64,
    /// Basis points of [`Self::slot_duration_ms`] past which a proposer must
    /// no longer attempt a late-block reorg; read by
    /// `get_proposer_reorg_cutoff_ms`.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub proposer_reorg_cutoff_bps: u64,
    /// Basis points of [`Self::slot_duration_ms`] by which a sync committee
    /// message is due (altair); read by `get_sync_message_due_ms`.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub sync_message_due_bps: u64,
    /// Basis points of [`Self::slot_duration_ms`] by which a sync committee
    /// contribution is due (altair); read by `get_contribution_due_ms`.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub contribution_due_bps: u64,
    /// Gloas: [`Self::attestation_due_bps`]'s replacement, now that ePBS
    /// (EIP-7732) moves the attestation deadline earlier in the slot to make
    /// room for the payload and payload-attestation windows below.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub attestation_due_bps_gloas: u64,
    /// Gloas: [`Self::aggregate_due_bps`]'s replacement, for the reason
    /// [`Self::attestation_due_bps_gloas`] gives.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub aggregate_due_bps_gloas: u64,
    /// Gloas: [`Self::sync_message_due_bps`]'s replacement, for the reason
    /// [`Self::attestation_due_bps_gloas`] gives.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub sync_message_due_bps_gloas: u64,
    /// Gloas: [`Self::contribution_due_bps`]'s replacement, for the reason
    /// [`Self::attestation_due_bps_gloas`] gives.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub contribution_due_bps_gloas: u64,
    /// Gloas (EIP-7732): basis points of [`Self::slot_duration_ms`] by which
    /// the builder's execution payload is due.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub payload_due_bps: u64,
    /// Gloas (EIP-7732): basis points of [`Self::slot_duration_ms`] by which
    /// a payload attestation is due.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub payload_attestation_due_bps: u64,
    /// Gloas: epochs a builder must wait after its exit is processed before
    /// its collateral becomes withdrawable, the builder-registry counterpart
    /// to [`Self::min_validator_withdrawability_delay`].
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub min_builder_withdrawability_delay: Epoch,

    // -- Validator cycle -----------------------------------------------------
    /// Score points added to a validator's inactivity score for each epoch it
    /// is offline (or the chain is leaking) without a timely target vote.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub inactivity_score_bias: u64,
    /// Score points subtracted from a validator's inactivity score for each
    /// epoch it casts a timely target vote while the chain is not leaking.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub inactivity_score_recovery_rate: u64,
    /// Effective balance floor below which a validator is force-exited at the
    /// next opportunity, regardless of its own wishes.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub ejection_balance: Gwei,
    /// The minimum validators allowed to enter the activation/exit queue in
    /// one epoch, regardless of the active validator set's size. Prevents the
    /// churn limit from collapsing to zero on a small validator set.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub min_per_epoch_churn_limit: u64,
    /// Active validators per unit of per-epoch activation/exit churn: the
    /// churn limit before electra is `active_validator_count /
    /// churn_limit_quotient`, floored at [`Self::min_per_epoch_churn_limit`].
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub churn_limit_quotient: u64,
    /// Deneb: an additional cap on the activation churn limit specifically
    /// (separate from the combined activation/exit limit above), so that
    /// activations cannot alone consume the whole per-epoch churn budget.
    /// Superseded by [`Self::max_per_epoch_activation_exit_churn_limit`] from
    /// electra onward, but the specification keeps both names rather than
    /// reusing one.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub max_per_epoch_activation_churn_limit: u64,
    /// Electra: the churn limit is now denominated in Gwei rather than a
    /// validator count (`get_balance_churn_limit`), and this is its floor,
    /// replacing [`Self::min_per_epoch_churn_limit`] from electra onward.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub min_per_epoch_churn_limit_electra: Gwei,
    /// Electra: the ceiling on the portion of the (Gwei-denominated) churn
    /// limit dedicated to activations and exits, as opposed to
    /// consolidations (`get_activation_exit_churn_limit`).
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub max_per_epoch_activation_exit_churn_limit: Gwei,
    /// Gloas (EIP-8061): the *validator* registry's own churn quotient for
    /// this fork, read by `get_activation_churn_limit`/`get_exit_churn_limit`.
    /// Not a builder-registry value, despite the name pattern this crate uses
    /// elsewhere for gloas-specific fields.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub churn_limit_quotient_gloas: u64,
    /// Gloas (EIP-8061): the ceiling on how much validator activation churn
    /// one epoch may admit, this fork's counterpart to
    /// [`Self::max_per_epoch_activation_churn_limit`] (deneb) and
    /// [`Self::max_per_epoch_activation_exit_churn_limit`] (electra). Not a
    /// builder-registry value; see [`Self::churn_limit_quotient_gloas`].
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub max_per_epoch_activation_churn_limit_gloas: Gwei,

    // -- Fork choice ---------------------------------------------------------
    /// Percentage boost, relative to a single committee's weight, given to a
    /// block proposed on time when comparing it against competitors for head.
    /// Deters "balancing" attacks that rely on splitting the vote right at a
    /// slot boundary.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub proposer_score_boost: u64,
    /// Percentage of committee weight the current head must be below the
    /// parent's competing child by for a proposer to consider reorging it out.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub reorg_head_weight_threshold: u64,
    /// Percentage of committee weight the parent block must exceed for a
    /// proposer to consider reorging its late child out.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub reorg_parent_weight_threshold: u64,
    /// How many epochs finality is allowed to lag before a proposer refuses to
    /// attempt a reorg at all, regardless of the weight thresholds above.
    /// Reorgs are a liveness optimization; this bounds how much they may risk
    /// finality progress to pursue it.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub reorg_max_epochs_since_finalization: Epoch,

    // -- Transition (bellatrix) -----------------------------------------------
    /// The proof-of-work total difficulty at or above which a PoW block
    /// becomes a valid terminal block for the Merge transition.
    /// [`Uint256`]-sized because total difficulty accumulates over the
    /// entire PoW chain's history and long since overflowed 64 bits.
    #[serde(deserialize_with = "deserialize_terminal_total_difficulty")]
    pub terminal_total_difficulty: Uint256,
    /// A specific PoW block hash that overrides [`Self::terminal_total_difficulty`]
    /// as the terminal block, if set to anything other than the zero hash.
    /// Existed as an emergency override in case total-difficulty tracking
    /// disagreed across clients near the Merge; every shipped network left it
    /// unset.
    pub terminal_block_hash: ExecutionBlockHash,
    /// The epoch at or after which [`Self::terminal_block_hash`], if set, is
    /// honored. Guards against an old override value being replayed before
    /// the network is ready for it.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub terminal_block_hash_activation_epoch: Epoch,

    // -- Blob limits -----------------------------------------------------------
    /// Deneb's fixed cap on `blob_kzg_commitments` per block, in effect from
    /// deneb until electra raises it.
    #[serde(
        rename = "MAX_BLOBS_PER_BLOCK",
        with = "crate::beacon::serde_helpers::quoted_or_bare"
    )]
    pub max_blobs_per_block_deneb: u64,
    /// Electra's fixed cap on `blob_kzg_commitments` per block. Also the value
    /// [`Self::max_blobs_per_block`] falls back to for any epoch fulu's blob
    /// schedule does not (yet) cover, matching `get_blob_parameters`'s own
    /// fallback of `BlobParameters(ELECTRA_FORK_EPOCH,
    /// MAX_BLOBS_PER_BLOCK_ELECTRA)`.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub max_blobs_per_block_electra: u64,
    /// Fulu's blob schedule (EIP7892): a possibly-empty list of `(epoch,
    /// limit)` entries, kept sorted ascending by epoch, that lets the blob
    /// count limit change again after electra without a new hard fork per
    /// change. Read through [`Config::max_blobs_per_block`] rather than
    /// directly.
    #[serde(
        deserialize_with = "deserialize_blob_schedule",
        serialize_with = "crate::beacon::serde_helpers::seq::serialize"
    )]
    pub blob_schedule: SszList<BlobScheduleEntry, MAX_BLOB_SCHEDULE_ENTRIES>,

    // -- Networking --------------------------------------------------------
    // These describe the wire rather than the state transition, so nothing in
    // this crate reads them. They are here because a `config.yaml` carries
    // them, `/eth/v1/config/spec` has to echo them, and a field with no typed
    // home would otherwise be reported as an unknown key on every startup of
    // every valid configuration. Where the node runs on a compile-time
    // constant instead (here and in the PeerDAS custody group below), the
    // binary's `network::check_constants` refuses a network that sets another
    // value, so the endpoint never reports one the node does not use.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub attestation_propagation_slot_range: u64,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub attestation_subnet_count: u64,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub attestation_subnet_extra_bits: u64,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub blob_sidecar_subnet_count: u64,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub blob_sidecar_subnet_count_electra: u64,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub data_column_sidecar_subnet_count: u64,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub epochs_per_subnet_subscription: u64,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub max_payload_size: u64,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub max_request_blocks: u64,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub max_request_blocks_deneb: u64,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub max_request_payloads: u64,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub maximum_gossip_clock_disparity: u64,
    #[serde(with = "crate::beacon::serde_helpers::hex_array")]
    pub message_domain_invalid_snappy: [u8; 4],
    #[serde(with = "crate::beacon::serde_helpers::hex_array")]
    pub message_domain_valid_snappy: [u8; 4],
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub min_epochs_for_blob_sidecars_requests: u64,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub min_epochs_for_data_column_sidecars_requests: u64,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub subnets_per_node: u64,

    // -- Deposit contract --------------------------------------------------
    // Which Eth1 chain and contract a validator client watches for deposits.
    // The state transition only processes deposits already in a block, so it
    // never looks the contract up; `/eth/v1/config/deposit_contract` serves
    // these.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub deposit_chain_id: u64,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub deposit_network_id: u64,
    #[serde(with = "crate::beacon::serde_helpers::hex_array")]
    pub deposit_contract_address: [u8; 20],

    // -- PeerDAS custody ---------------------------------------------------
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub balance_per_additional_custody_group: u64,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub custody_requirement: u64,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub number_of_custody_groups: u64,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub samples_per_slot: u64,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub validator_custody_requirement: u64,

    // -- Other runtime values ----------------------------------------------
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub consolidation_churn_limit_quotient: u64,

    // -- Networking (added after an incomplete initial key list) -----------
    // These five are additional keys mainnet's own published `config.yaml`
    // carries; missed initially because the key list this struct was
    // checked against came from a genesis generator's example rather than
    // the published file itself.
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub attestation_subnet_prefix_bits: u64,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub max_request_blob_sidecars: u64,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub max_request_blob_sidecars_electra: u64,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub max_request_data_column_sidecars: u64,
    #[serde(with = "crate::beacon::serde_helpers::quoted_or_bare")]
    pub min_epochs_for_block_requests: u64,
}

/// Mainnet's values, which is what an absent key in a `config.yaml` falls back
/// to.
///
/// Deserialization is deliberately permissive: no client surveyed rejects a
/// configuration for a missing key, and a network that predates a field should
/// still load. Mainnet is the right fallback because every other network is
/// described as a deviation from it.
impl Default for Config {
    fn default() -> Self {
        Self::mainnet()
    }
}

/// Deserializes `TERMINAL_TOTAL_DIFFICULTY`.
///
/// The one integer field [`crate::beacon::serde_helpers::quoted_or_bare`]
/// cannot cover: [`Uint256`] has no `FromStr` impl (only the inherent
/// [`Uint256::from_dec_str`], kept because nothing on the shipping path parses
/// one otherwise), so this reimplements `quoted_or_bare`'s "take the scalar as
/// a string either way" trick against that inherent parser instead.
fn deserialize_terminal_total_difficulty<'de, D>(deserializer: D) -> Result<Uint256, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let text = <String as serde::Deserialize>::deserialize(deserializer)?;
    Uint256::from_dec_str(text.trim()).map_err(serde::de::Error::custom)
}

/// Deserializes `BLOB_SCHEDULE`.
///
/// The YAML shape is a list of mappings (`{EPOCH, MAX_BLOBS_PER_BLOCK}`), not a
/// scalar, so neither [`crate::beacon::serde_helpers::quoted_or_bare`] nor
/// [`crate::beacon::serde_helpers::hex_array`] applies: this reads the list as
/// a plain `Vec<BlobScheduleEntry>` (each entry deserializing its own two
/// scalar fields through `quoted_or_bare`) and then converts it into the
/// bounded [`SszList`], erroring clearly if the file names more entries than
/// [`MAX_BLOB_SCHEDULE_ENTRIES`] allows.
fn deserialize_blob_schedule<'de, D>(
    deserializer: D,
) -> Result<SszList<BlobScheduleEntry, MAX_BLOB_SCHEDULE_ENTRIES>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let entries = <Vec<BlobScheduleEntry> as serde::Deserialize>::deserialize(deserializer)?;
    entries.try_into().map_err(|err| {
        serde::de::Error::custom(format!(
            "BLOB_SCHEDULE carries more than {MAX_BLOB_SCHEDULE_ENTRIES} entries: {err:?}"
        ))
    })
}

/// Mainnet's `TERMINAL_TOTAL_DIFFICULTY`.
///
/// A `const` rather than `Uint256::from_dec_str(..).expect(..)` inside
/// [`Config::mainnet`], so the digits are converted once at compile time instead
/// of on every construction, and a typo is a build failure rather than a panic.
const MAINNET_TERMINAL_TOTAL_DIFFICULTY: Uint256 =
    Uint256::from_u128(58_750_000_000_000_000_000_000);

/// Minimal's `TERMINAL_TOTAL_DIFFICULTY`, 2^256 - 2^10.
///
/// Past 128 bits, so written as the little-endian bytes [`Uint256`] stores
/// rather than as decimal digits. Those bytes are unreadable by construction, so
/// a test below pins this and [`MAINNET_TERMINAL_TOTAL_DIFFICULTY`] against the
/// decimal strings the configuration files actually carry.
const MINIMAL_TERMINAL_TOTAL_DIFFICULTY: Uint256 = {
    let mut bytes = [0xff; 32];
    bytes[0] = 0x00;
    bytes[1] = 0xfc;
    U256(bytes)
};

impl Config {
    /// The configuration matching Ethereum mainnet, as of the pinned
    /// specification version's `configs/mainnet.yaml`.
    pub fn mainnet() -> Self {
        Config {
            preset_base: ConfigName::fixed("mainnet"),
            config_name: ConfigName::fixed("mainnet"),
            min_genesis_active_validator_count: 16_384,
            min_genesis_time: 1_606_824_000,
            genesis_delay: 604_800,
            genesis_time: 1_606_824_023,
            genesis_fork_version: [0x00, 0x00, 0x00, 0x00],
            altair_fork_version: [0x01, 0x00, 0x00, 0x00],
            altair_fork_epoch: 74_240,
            bellatrix_fork_version: [0x02, 0x00, 0x00, 0x00],
            bellatrix_fork_epoch: 144_896,
            capella_fork_version: [0x03, 0x00, 0x00, 0x00],
            capella_fork_epoch: 194_048,
            deneb_fork_version: [0x04, 0x00, 0x00, 0x00],
            deneb_fork_epoch: 269_568,
            electra_fork_version: [0x05, 0x00, 0x00, 0x00],
            electra_fork_epoch: 364_032,
            fulu_fork_version: [0x06, 0x00, 0x00, 0x00],
            fulu_fork_epoch: 411_392,
            gloas_fork_version: [0x07, 0x00, 0x00, 0x00],
            gloas_fork_epoch: constants::FAR_FUTURE_EPOCH,

            seconds_per_slot: 12,
            slot_duration_ms: 12_000,
            seconds_per_eth1_block: 14,
            min_validator_withdrawability_delay: 256,
            shard_committee_period: 256,
            eth1_follow_distance: 2_048,
            attestation_due_bps: 3_333,
            aggregate_due_bps: 6_667,
            proposer_reorg_cutoff_bps: 1_667,
            sync_message_due_bps: 3_333,
            contribution_due_bps: 6_667,
            attestation_due_bps_gloas: 2_500,
            aggregate_due_bps_gloas: 5_000,
            sync_message_due_bps_gloas: 2_500,
            contribution_due_bps_gloas: 5_000,
            payload_due_bps: 5_000,
            payload_attestation_due_bps: 7_500,
            min_builder_withdrawability_delay: 64,

            inactivity_score_bias: 4,
            inactivity_score_recovery_rate: 16,
            ejection_balance: 16_000_000_000,
            min_per_epoch_churn_limit: 4,
            churn_limit_quotient: 65_536,
            max_per_epoch_activation_churn_limit: 8,
            min_per_epoch_churn_limit_electra: 128_000_000_000,
            max_per_epoch_activation_exit_churn_limit: 256_000_000_000,
            churn_limit_quotient_gloas: 32_768,
            max_per_epoch_activation_churn_limit_gloas: 256_000_000_000,

            proposer_score_boost: 40,
            reorg_head_weight_threshold: 20,
            reorg_parent_weight_threshold: 160,
            reorg_max_epochs_since_finalization: 2,

            // Reached September 15, 2022 (the Merge); mainnet has been on
            // proof of stake ever since, so this and the two fields below
            // never trigger again in practice, but are still read by any
            // faithful implementation of `validate_merge_block`.
            terminal_total_difficulty: MAINNET_TERMINAL_TOTAL_DIFFICULTY,
            terminal_block_hash: ExecutionBlockHash::ZERO,
            terminal_block_hash_activation_epoch: constants::FAR_FUTURE_EPOCH,

            max_blobs_per_block_deneb: 6,
            max_blobs_per_block_electra: 9,
            blob_schedule: vec![
                BlobScheduleEntry {
                    epoch: 412_672,
                    max_blobs_per_block: 15,
                },
                BlobScheduleEntry {
                    epoch: 419_072,
                    max_blobs_per_block: 21,
                },
            ]
            .try_into()
            .expect("mainnet blob schedule within bound"),

            attestation_propagation_slot_range: 32,
            attestation_subnet_count: 64,
            attestation_subnet_extra_bits: 0,
            blob_sidecar_subnet_count: 6,
            blob_sidecar_subnet_count_electra: 9,
            data_column_sidecar_subnet_count: 128,
            epochs_per_subnet_subscription: 256,
            max_payload_size: 10_485_760,
            max_request_blocks: 1_024,
            max_request_blocks_deneb: 128,
            max_request_payloads: 128,
            maximum_gossip_clock_disparity: 500,
            message_domain_invalid_snappy: [0x00, 0x00, 0x00, 0x00],
            message_domain_valid_snappy: [0x01, 0x00, 0x00, 0x00],
            min_epochs_for_blob_sidecars_requests: 4_096,
            min_epochs_for_data_column_sidecars_requests: 4_096,
            subnets_per_node: 2,

            deposit_chain_id: 1,
            deposit_network_id: 1,
            deposit_contract_address: [
                0x00, 0x00, 0x00, 0x00, 0x21, 0x9a, 0xb5, 0x40, 0x35, 0x6c, 0xbb, 0x83, 0x9c, 0xbe,
                0x05, 0x30, 0x3d, 0x77, 0x05, 0xfa,
            ],

            balance_per_additional_custody_group: 32_000_000_000,
            custody_requirement: 4,
            number_of_custody_groups: 128,
            samples_per_slot: 8,
            validator_custody_requirement: 8,

            consolidation_churn_limit_quotient: 65_536,

            attestation_subnet_prefix_bits: 6,
            max_request_blob_sidecars: 768,
            max_request_blob_sidecars_electra: 1_152,
            max_request_data_column_sidecars: 16_384,
            min_epochs_for_block_requests: 33_024,
        }
    }

    /// The configuration matching the specification's `minimal` preset, as of
    /// the pinned specification version's `configs/minimal.yaml`.
    ///
    /// Every fork after phase0 defaults to
    /// [`constants::FAR_FUTURE_EPOCH`] here: `minimal` is a base for spec
    /// fixtures, not a network of its own, and each fixture's `meta.yaml`
    /// picks which single fork boundary it wants to exercise via
    /// [`Config::with_fork_epoch`] rather than inheriting a fixed schedule.
    pub fn minimal() -> Self {
        Config {
            preset_base: ConfigName::fixed("minimal"),
            config_name: ConfigName::fixed("minimal"),
            min_genesis_active_validator_count: 64,
            min_genesis_time: 1_578_009_600,
            genesis_delay: 300,
            // `minimal` is a base for spec fixtures, not a network of its
            // own: no real chain ever started under it, so there is no real
            // wall-clock second to record here.
            genesis_time: 0,
            genesis_fork_version: [0x00, 0x00, 0x00, 0x01],
            altair_fork_version: [0x01, 0x00, 0x00, 0x01],
            altair_fork_epoch: constants::FAR_FUTURE_EPOCH,
            bellatrix_fork_version: [0x02, 0x00, 0x00, 0x01],
            bellatrix_fork_epoch: constants::FAR_FUTURE_EPOCH,
            capella_fork_version: [0x03, 0x00, 0x00, 0x01],
            capella_fork_epoch: constants::FAR_FUTURE_EPOCH,
            deneb_fork_version: [0x04, 0x00, 0x00, 0x01],
            deneb_fork_epoch: constants::FAR_FUTURE_EPOCH,
            electra_fork_version: [0x05, 0x00, 0x00, 0x01],
            electra_fork_epoch: constants::FAR_FUTURE_EPOCH,
            fulu_fork_version: [0x06, 0x00, 0x00, 0x01],
            fulu_fork_epoch: constants::FAR_FUTURE_EPOCH,
            gloas_fork_version: [0x07, 0x00, 0x00, 0x01],
            gloas_fork_epoch: constants::FAR_FUTURE_EPOCH,

            seconds_per_slot: 6,
            slot_duration_ms: 6_000,
            seconds_per_eth1_block: 14,
            min_validator_withdrawability_delay: 256,
            shard_committee_period: 64,
            eth1_follow_distance: 16,
            attestation_due_bps: 3_333,
            aggregate_due_bps: 6_667,
            proposer_reorg_cutoff_bps: 1_667,
            sync_message_due_bps: 3_333,
            contribution_due_bps: 6_667,
            attestation_due_bps_gloas: 2_500,
            aggregate_due_bps_gloas: 5_000,
            sync_message_due_bps_gloas: 2_500,
            contribution_due_bps_gloas: 5_000,
            payload_due_bps: 5_000,
            payload_attestation_due_bps: 7_500,
            min_builder_withdrawability_delay: 2,

            inactivity_score_bias: 4,
            inactivity_score_recovery_rate: 16,
            ejection_balance: 16_000_000_000,
            min_per_epoch_churn_limit: 2,
            churn_limit_quotient: 32,
            max_per_epoch_activation_churn_limit: 4,
            min_per_epoch_churn_limit_electra: 64_000_000_000,
            max_per_epoch_activation_exit_churn_limit: 128_000_000_000,
            churn_limit_quotient_gloas: 16,
            max_per_epoch_activation_churn_limit_gloas: 128_000_000_000,

            proposer_score_boost: 40,
            reorg_head_weight_threshold: 20,
            reorg_parent_weight_threshold: 160,
            reorg_max_epochs_since_finalization: 2,

            // configs/minimal.yaml sets this to 2**256 - 2**10: large enough
            // that no spec test's simulated PoW chain reaches it.
            terminal_total_difficulty: MINIMAL_TERMINAL_TOTAL_DIFFICULTY,
            terminal_block_hash: ExecutionBlockHash::ZERO,
            terminal_block_hash_activation_epoch: constants::FAR_FUTURE_EPOCH,

            max_blobs_per_block_deneb: 6,
            max_blobs_per_block_electra: 9,
            blob_schedule: SszList::new(),

            attestation_propagation_slot_range: 32,
            attestation_subnet_count: 64,
            attestation_subnet_extra_bits: 0,
            blob_sidecar_subnet_count: 6,
            blob_sidecar_subnet_count_electra: 9,
            data_column_sidecar_subnet_count: 128,
            epochs_per_subnet_subscription: 256,
            max_payload_size: 10_485_760,
            max_request_blocks: 1_024,
            max_request_blocks_deneb: 128,
            max_request_payloads: 128,
            maximum_gossip_clock_disparity: 500,
            message_domain_invalid_snappy: [0x00, 0x00, 0x00, 0x00],
            message_domain_valid_snappy: [0x01, 0x00, 0x00, 0x00],
            min_epochs_for_blob_sidecars_requests: 4_096,
            min_epochs_for_data_column_sidecars_requests: 4_096,
            subnets_per_node: 2,

            // configs/minimal.yaml: Ethereum Goerli testnet's chain and
            // network id, not mainnet's; the contract address is not
            // Goerli's real one, just the file's own repeating placeholder.
            deposit_chain_id: 5,
            deposit_network_id: 5,
            deposit_contract_address: [
                0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78,
                0x90, 0x12, 0x34, 0x56, 0x78, 0x90,
            ],

            balance_per_additional_custody_group: 32_000_000_000,
            custody_requirement: 4,
            number_of_custody_groups: 128,
            samples_per_slot: 8,
            validator_custody_requirement: 8,

            consolidation_churn_limit_quotient: 32,

            attestation_subnet_prefix_bits: 6,
            max_request_blob_sidecars: 768,
            max_request_blob_sidecars_electra: 1_152,
            max_request_data_column_sidecars: 16_384,
            min_epochs_for_block_requests: 33_024,
        }
    }

    /// The configuration a lean chain runs on: a real `genesis_time`, the slot
    /// duration its network config file sets, and a placeholder for everything
    /// else.
    ///
    /// A lean chain has no beacon fork schedule, no Eth1 deposit contract and
    /// no execution layer, but it is stored through the same `Metadata["config"]`
    /// row as a beacon chain so that one accessor serves both. The placeholders
    /// are chosen so that a beacon-shaped gate reading this by mistake fails
    /// closed: every fork epoch is `FAR_FUTURE_EPOCH`, so no fork ever reads as
    /// activated, rather than epoch 0, which would read as "activated at
    /// genesis" for all eight of them.
    pub fn lean(genesis_time: u64, slot_duration_ms: u64) -> Self {
        Self {
            // A lean `config.yaml` has no `PRESET_BASE` or `CONFIG_NAME` key,
            // and a lean chain has no beacon preset, so there is neither name
            // to carry.
            preset_base: ConfigName::default(),
            config_name: ConfigName::default(),
            genesis_time,
            slot_duration_ms,
            // Truncated on a cadence that is not a whole number of seconds.
            // Nothing on the lean path reads it: lean schedules every duty off
            // `slot_duration_ms`, and the second-resolution field exists for
            // the beacon spec's own `compute_time_at_slot`.
            seconds_per_slot: slot_duration_ms / 1_000,
            altair_fork_epoch: constants::FAR_FUTURE_EPOCH,
            bellatrix_fork_epoch: constants::FAR_FUTURE_EPOCH,
            capella_fork_epoch: constants::FAR_FUTURE_EPOCH,
            deneb_fork_epoch: constants::FAR_FUTURE_EPOCH,
            electra_fork_epoch: constants::FAR_FUTURE_EPOCH,
            fulu_fork_epoch: constants::FAR_FUTURE_EPOCH,
            gloas_fork_epoch: constants::FAR_FUTURE_EPOCH,
            ..Config::mainnet()
        }
    }

    /// Genesis as a millisecond timestamp, the zero point every tick
    /// computation measures from.
    pub fn genesis_time_ms(&self) -> u64 {
        self.genesis_time * 1_000
    }

    /// Interval duration in milliseconds.
    ///
    /// Exact on a lean chain: [`crate::genesis::GenesisConfig`] rejects a slot
    /// duration that is not a multiple of [`INTERVALS_PER_SLOT`].
    pub fn milliseconds_per_interval(&self) -> u64 {
        self.slot_duration_ms / INTERVALS_PER_SLOT
    }

    /// This configuration's time grid, the part a lean node schedules duties
    /// off.
    ///
    /// A [`ChainConfig`] rather than a borrow of `self`: it is two `u64`s and
    /// `Copy`, so a caller can hold it across the `&mut Store` the tick
    /// pipeline takes, and the metrics helpers can keep taking it by value.
    pub fn time_grid(&self) -> ChainConfig {
        ChainConfig::new(self.genesis_time, self.slot_duration_ms)
    }

    /// The configuration matching the compiled-in preset: [`Config::minimal`]
    /// when this crate is built with the `preset-minimal` feature,
    /// [`Config::mainnet`] otherwise.
    ///
    /// For code that already knows its preset at compile time (unlike the
    /// `transition` fixture suite, which needs to pick a configuration, and
    /// possibly override a fork epoch, per test case).
    pub fn active() -> Self {
        if cfg!(feature = "preset-minimal") {
            Self::minimal()
        } else {
            Self::mainnet()
        }
    }

    /// The fork active at `epoch`: the newest fork whose activation epoch is
    /// both scheduled (not [`constants::FAR_FUTURE_EPOCH`]) and at or before
    /// `epoch`.
    ///
    /// The "scheduled" check matters because an unscheduled fork's epoch
    /// field holds [`constants::FAR_FUTURE_EPOCH`], which is a real, huge
    /// `Epoch` value, not a `None`. Comparing epochs naively (newest fork
    /// whose epoch is `<= epoch`, full stop) would treat that sentinel as a
    /// legitimate activation epoch and could only ever be beaten by querying
    /// an even larger epoch, so an unscheduled fork would still eventually
    /// "activate" once the chain ran long enough. Filtering out
    /// [`constants::FAR_FUTURE_EPOCH`] first is what makes "not scheduled"
    /// mean "never", as intended.
    ///
    /// Phase0 is always scheduled (its epoch is
    /// [`crate::beacon::constants::GENESIS_EPOCH`], never the sentinel), so this
    /// always finds at least phase0 and never needs to fail.
    pub fn fork_at_epoch(&self, epoch: Epoch) -> ForkName {
        ForkName::ALL
            .into_iter()
            .rev()
            .find(|&fork| {
                let scheduled_at = self.fork_epoch(fork);
                scheduled_at != constants::FAR_FUTURE_EPOCH && scheduled_at <= epoch
            })
            .unwrap_or(ForkName::Phase0)
    }

    /// The `Fork.current_version` value blocks and attestations of `fork`
    /// sign under.
    pub fn fork_version(&self, fork: ForkName) -> Version {
        match fork {
            ForkName::Phase0 => self.genesis_fork_version,
            ForkName::Altair => self.altair_fork_version,
            ForkName::Bellatrix => self.bellatrix_fork_version,
            ForkName::Capella => self.capella_fork_version,
            ForkName::Deneb => self.deneb_fork_version,
            ForkName::Electra => self.electra_fork_version,
            ForkName::Fulu => self.fulu_fork_version,
            ForkName::Gloas => self.gloas_fork_version,
            ForkName::Lean => lean_fork_unreachable("Config::fork_version"),
        }
    }

    /// The epoch `fork` activates at, or [`constants::FAR_FUTURE_EPOCH`] if it
    /// is not scheduled on this configuration. Phase0 always returns
    /// [`constants::GENESIS_EPOCH`]: it is the chain's starting fork, not a
    /// configurable activation.
    pub fn fork_epoch(&self, fork: ForkName) -> Epoch {
        match fork {
            ForkName::Phase0 => constants::GENESIS_EPOCH,
            ForkName::Altair => self.altair_fork_epoch,
            ForkName::Bellatrix => self.bellatrix_fork_epoch,
            ForkName::Capella => self.capella_fork_epoch,
            ForkName::Deneb => self.deneb_fork_epoch,
            ForkName::Electra => self.electra_fork_epoch,
            ForkName::Fulu => self.fulu_fork_epoch,
            ForkName::Gloas => self.gloas_fork_epoch,
            ForkName::Lean => lean_fork_unreachable("Config::fork_epoch"),
        }
    }

    /// Returns a copy of this configuration with `fork`'s activation epoch
    /// set to `epoch`, leaving every other fork's schedule untouched.
    ///
    /// For the `transition` fixture suite, which starts from
    /// [`Config::minimal`] (where every fork after phase0 defaults to
    /// unscheduled) and overrides exactly the one boundary each test case
    /// exercises.
    ///
    /// Phase0's activation is not stored as a field (it is always
    /// [`constants::GENESIS_EPOCH`], see [`Config::fork_epoch`]), so passing
    /// `ForkName::Phase0` here has no effect.
    pub fn with_fork_epoch(mut self, fork: ForkName, epoch: Epoch) -> Self {
        match fork {
            ForkName::Phase0 => {}
            ForkName::Altair => self.altair_fork_epoch = epoch,
            ForkName::Bellatrix => self.bellatrix_fork_epoch = epoch,
            ForkName::Capella => self.capella_fork_epoch = epoch,
            ForkName::Deneb => self.deneb_fork_epoch = epoch,
            ForkName::Electra => self.electra_fork_epoch = epoch,
            ForkName::Fulu => self.fulu_fork_epoch = epoch,
            ForkName::Gloas => self.gloas_fork_epoch = epoch,
            ForkName::Lean => lean_fork_unreachable("Config::with_fork_epoch"),
        }
        self
    }

    /// Override one fork's version, for a network whose schedule differs from
    /// mainnet's. Phase0's version is `genesis_fork_version` and is set there.
    pub fn with_fork_version(mut self, fork: ForkName, version: Version) -> Self {
        match fork {
            ForkName::Phase0 => self.genesis_fork_version = version,
            ForkName::Altair => self.altair_fork_version = version,
            ForkName::Bellatrix => self.bellatrix_fork_version = version,
            ForkName::Capella => self.capella_fork_version = version,
            ForkName::Deneb => self.deneb_fork_version = version,
            ForkName::Electra => self.electra_fork_version = version,
            ForkName::Fulu => self.fulu_fork_version = version,
            ForkName::Gloas => self.gloas_fork_version = version,
            // Matches `fork_version`'s own arm: reaching this means a caller
            // dispatched on the wrong chain, which is a bug in the caller.
            ForkName::Lean => lean_fork_unreachable("Config::with_fork_version"),
        }
        self
    }

    /// The blob parameters in effect at `epoch`, as
    /// `(epoch, max_blobs_per_block)`, from fulu's [`Self::blob_schedule`].
    ///
    /// This is `get_blob_parameters`: the schedule is searched from its
    /// latest entry backward for the first one whose epoch is at or before
    /// `epoch`; if none matches (the schedule is empty, as in
    /// [`Config::minimal`]'s default, or every entry is still in the future),
    /// this falls back to electra's own activation and
    /// [`Self::max_blobs_per_block_electra`], exactly as the specification's
    /// own `get_blob_parameters` falls back to `MAX_BLOBS_PER_BLOCK_ELECTRA`.
    ///
    /// The pair's *epoch* matters as much as its limit, since
    /// [`crate::beacon::fork_digest::compute_fork_digest`] hashes both: that is
    /// why this returns the pair and [`Self::max_blobs_per_block`] is the thin
    /// half of it, rather than the search being written once per caller.
    pub fn blob_parameters(&self, epoch: Epoch) -> (Epoch, u64) {
        self.blob_schedule
            .iter()
            .rev()
            .find(|entry| entry.epoch <= epoch)
            .map(|entry| (entry.epoch, entry.max_blobs_per_block))
            .unwrap_or((self.electra_fork_epoch, self.max_blobs_per_block_electra))
    }

    /// The blob count limit for a block proposed in `epoch`. See
    /// [`Self::blob_parameters`].
    ///
    /// This is fulu's helper: a deneb- or electra-only block's blob count is
    /// bounded by [`Self::max_blobs_per_block_deneb`] or
    /// [`Self::max_blobs_per_block_electra`] directly instead, matching how
    /// the specification only introduces `get_blob_parameters` at fulu.
    pub fn max_blobs_per_block(&self, epoch: Epoch) -> u64 {
        self.blob_parameters(epoch).1
    }
}

#[cfg(test)]
mod tests {
    use libssz::{SszDecode as _, SszEncode as _};

    use super::*;

    #[test]
    fn the_terminal_total_difficulties_match_the_config_files() {
        assert_eq!(
            Config::mainnet().terminal_total_difficulty,
            Uint256::from_dec_str("58750000000000000000000").unwrap(),
        );
        assert_eq!(
            Config::minimal().terminal_total_difficulty,
            Uint256::from_dec_str(
                "115792089237316195423570985008687907853269984665640564039457584007913129638912",
            )
            .unwrap(),
        );
    }

    #[test]
    fn fork_at_epoch_matches_mainnet_boundaries() {
        let config = Config::mainnet();
        // At each boundary: the epoch just before it still reports the
        // previous fork, and the boundary epoch itself already reports the
        // new one.
        let boundaries = [
            (config.altair_fork_epoch, ForkName::Phase0, ForkName::Altair),
            (
                config.bellatrix_fork_epoch,
                ForkName::Altair,
                ForkName::Bellatrix,
            ),
            (
                config.capella_fork_epoch,
                ForkName::Bellatrix,
                ForkName::Capella,
            ),
            (config.deneb_fork_epoch, ForkName::Capella, ForkName::Deneb),
            (
                config.electra_fork_epoch,
                ForkName::Deneb,
                ForkName::Electra,
            ),
            (config.fulu_fork_epoch, ForkName::Electra, ForkName::Fulu),
        ];
        for (boundary, before, at_and_after) in boundaries {
            assert_eq!(config.fork_at_epoch(boundary - 1), before);
            assert_eq!(config.fork_at_epoch(boundary), at_and_after);
        }
    }

    #[test]
    fn unscheduled_forks_are_never_returned() {
        // Minimal's stock configuration leaves every fork after phase0 at
        // FAR_FUTURE_EPOCH. Querying any epoch, including the largest
        // possible one, must still resolve to phase0 rather than treating
        // the sentinel as a legitimate (if enormous) activation epoch.
        let config = Config::minimal();
        assert_eq!(config.fork_at_epoch(0), ForkName::Phase0);
        assert_eq!(config.fork_at_epoch(Epoch::MAX), ForkName::Phase0);
    }

    #[test]
    fn with_fork_epoch_shifts_a_single_boundary() {
        let config = Config::minimal().with_fork_epoch(ForkName::Altair, 10);
        assert_eq!(config.fork_at_epoch(9), ForkName::Phase0);
        assert_eq!(config.fork_at_epoch(10), ForkName::Altair);
        // Every later fork is still unscheduled, so a far-future epoch still
        // resolves to the one fork that was actually overridden.
        assert_eq!(config.fork_at_epoch(1_000_000), ForkName::Altair);
    }

    #[test]
    fn gloas_keys_are_claimed_and_parse() {
        let yaml = "GLOAS_FORK_VERSION: 0x07000000\nGLOAS_FORK_EPOCH: 12\n\
                    CHURN_LIMIT_QUOTIENT_GLOAS: 32768\nMIN_BUILDER_WITHDRAWABILITY_DELAY: 64\n\
                    PAYLOAD_DUE_BPS: 5000\nPAYLOAD_ATTESTATION_DUE_BPS: 7500\nMAX_REQUEST_PAYLOADS: 128\n";
        let config: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(config.gloas_fork_version, [0x07, 0, 0, 0]);
        assert_eq!(config.fork_epoch(ForkName::Gloas), 12);
        assert_eq!(config.fork_at_epoch(12), ForkName::Gloas);
        assert_eq!(config.max_request_payloads, 128);
    }

    #[test]
    fn max_blobs_per_block_selects_the_active_schedule_entry() {
        let config = Config::mainnet();
        let first = config.blob_schedule[0];
        let second = config.blob_schedule[1];

        assert_eq!(
            config.max_blobs_per_block(first.epoch - 1),
            config.max_blobs_per_block_electra
        );
        assert_eq!(
            config.max_blobs_per_block(first.epoch),
            first.max_blobs_per_block
        );
        assert_eq!(
            config.max_blobs_per_block(second.epoch - 1),
            first.max_blobs_per_block
        );
        assert_eq!(
            config.max_blobs_per_block(second.epoch),
            second.max_blobs_per_block
        );
        assert_eq!(
            config.max_blobs_per_block(second.epoch + 1_000),
            second.max_blobs_per_block
        );
    }

    #[test]
    fn minimal_has_no_blob_schedule_and_falls_back_to_electra() {
        let config = Config::minimal();
        assert!(config.blob_schedule.is_empty());
        assert_eq!(
            config.max_blobs_per_block(0),
            config.max_blobs_per_block_electra
        );
    }

    #[test]
    fn a_config_round_trips_through_ssz() {
        let config = Config::mainnet();
        let bytes = config.to_ssz();
        assert_eq!(
            Config::from_ssz_bytes(&bytes).expect("valid config"),
            config
        );
    }

    #[test]
    fn a_lean_config_carries_its_time_grid_and_nothing_else_meaningful() {
        let config = Config::lean(1_770_407_233, 4_000);
        assert_eq!(config.genesis_time, 1_770_407_233);
        assert_eq!(config.slot_duration_ms, 4_000);
        assert_eq!(config.seconds_per_slot, 4);

        // Every fork epoch is FAR_FUTURE_EPOCH: a lean chain has no beacon
        // fork schedule, and a placeholder that reads as "scheduled at epoch
        // 0" would make a beacon-shaped gate fire on a lean chain.
        assert_eq!(config.altair_fork_epoch, constants::FAR_FUTURE_EPOCH);
        assert_eq!(config.fulu_fork_epoch, constants::FAR_FUTURE_EPOCH);
    }

    #[test]
    fn a_lean_config_round_trips_through_ssz() {
        let config = Config::lean(7, 4_000);
        let bytes = config.to_ssz();
        assert_eq!(
            Config::from_ssz_bytes(&bytes).expect("valid config"),
            config
        );
    }

    #[test]
    fn genesis_time_is_not_min_genesis_time() {
        // Different quantities, and mainnet is the case that proves it:
        // min_genesis_time is the earliest the deposit-driven rules permit,
        // 23 seconds before the chain actually started. Reusing it for the
        // clock would put every slot boundary 23 seconds off.
        let config = Config::mainnet();
        assert_eq!(config.min_genesis_time, 1_606_824_000);
        assert_eq!(config.genesis_time, 1_606_824_023);
        assert_ne!(config.genesis_time, config.min_genesis_time);
    }

    #[test]
    fn mainnets_own_config_file_parses_to_the_built_in_config() {
        // The fork schedule, slot timing and churn values in eth-clients'
        // published file must be exactly what `Config::mainnet` hardcodes. If
        // they ever diverge, one of the two is wrong.
        let text = include_str!("../../../../../bin/ethlambda/assets/mainnet/config.yaml");
        let parsed: Config = serde_yaml_ng::from_str(text).expect("mainnet config.yaml parses");
        let built_in = Config::mainnet();

        assert_eq!(parsed.genesis_fork_version, built_in.genesis_fork_version);
        assert_eq!(parsed.altair_fork_epoch, built_in.altair_fork_epoch);
        assert_eq!(parsed.electra_fork_epoch, built_in.electra_fork_epoch);
        assert_eq!(parsed.fulu_fork_epoch, built_in.fulu_fork_epoch);
        assert_eq!(parsed.seconds_per_slot, built_in.seconds_per_slot);
        assert_eq!(parsed.churn_limit_quotient, built_in.churn_limit_quotient);
        assert_eq!(parsed.ejection_balance, built_in.ejection_balance);

        // Every equality above holds for an empty document too, since
        // `Config`'s serde default is `Config::mainnet()` itself: this is a
        // drift check between our hardcoded values and eth-clients', not
        // proof the file is read at all. Prove that separately by editing one
        // line the file carries and checking the parsed value follows the
        // edit rather than staying at the default.
        let perturbed_text = text.replacen(
            "CHURN_LIMIT_QUOTIENT: 65536",
            "CHURN_LIMIT_QUOTIENT: 12345",
            1,
        );
        assert_ne!(
            perturbed_text, text,
            "fixture no longer carries CHURN_LIMIT_QUOTIENT in the expected form"
        );
        let perturbed: Config = serde_yaml_ng::from_str(&perturbed_text).unwrap();
        assert_eq!(perturbed.churn_limit_quotient, 12_345);
    }

    #[test]
    fn genesis_time_does_not_come_from_the_config_file() {
        // Whatever serde does for a skipped field under a container-level
        // default, the one thing that must hold is that the file's own
        // MIN_GENESIS_TIME never becomes genesis_time: mainnet's differ by 23
        // seconds, and using the wrong one moves every slot boundary. A later
        // task fills this from the genesis state.
        let text = include_str!("../../../../../bin/ethlambda/assets/mainnet/config.yaml");
        let parsed: Config = serde_yaml_ng::from_str(text).unwrap();
        assert_ne!(
            parsed.genesis_time, 1_606_824_000,
            "MIN_GENESIS_TIME leaked in"
        );

        // The assertion above holds for an empty document too: `genesis_time`
        // is `#[serde(skip)]` and always takes the container default,
        // regardless of what the file says. Prove this document is actually
        // being parsed by perturbing MIN_GENESIS_TIME and checking it lands
        // in `min_genesis_time` while `genesis_time` -- unreachable from any
        // config key -- stays exactly where it started.
        let perturbed_text = text.replacen(
            "MIN_GENESIS_TIME: 1606824000",
            "MIN_GENESIS_TIME: 999999999",
            1,
        );
        assert_ne!(
            perturbed_text, text,
            "fixture no longer carries MIN_GENESIS_TIME in the expected form"
        );
        let perturbed: Config = serde_yaml_ng::from_str(&perturbed_text).unwrap();
        assert_eq!(perturbed.min_genesis_time, 999_999_999);
        assert_eq!(perturbed.genesis_time, parsed.genesis_time);
    }

    #[test]
    fn the_networking_and_deposit_keys_come_from_the_file() {
        let text = include_str!("../../../../../bin/ethlambda/assets/mainnet/config.yaml");
        let parsed: Config = serde_yaml_ng::from_str(text).unwrap();

        assert_eq!(parsed.attestation_subnet_count, 64);
        assert_eq!(parsed.subnets_per_node, 2);
        assert_eq!(parsed.max_payload_size, 10_485_760);
        assert_eq!(parsed.max_request_blocks, 1_024);
        assert_eq!(parsed.max_request_blocks_deneb, 128);
        assert_eq!(parsed.maximum_gossip_clock_disparity, 500);
        assert_eq!(parsed.message_domain_valid_snappy, [0x01, 0x00, 0x00, 0x00]);
        assert_eq!(
            parsed.message_domain_invalid_snappy,
            [0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(parsed.deposit_chain_id, 1);
        assert_eq!(parsed.deposit_network_id, 1);
        assert_eq!(
            parsed.deposit_contract_address,
            hex::decode("00000000219ab540356cBB839Cbe05303d7705Fa")
                .unwrap()
                .as_slice()
        );
        assert_eq!(parsed.custody_requirement, 4);
        assert_eq!(parsed.number_of_custody_groups, 128);
        assert_eq!(parsed.samples_per_slot, 8);
        assert_eq!(parsed.validator_custody_requirement, 8);
        assert_eq!(parsed.balance_per_additional_custody_group, 32_000_000_000);

        // Every equality above holds for an empty document too, since each of
        // these fields' serde default is mainnet's own value, which is
        // exactly what the file carries. Prove the file is actually driving
        // the parse: perturb one field from each group above (networking,
        // deposit contract, custody) and check the parsed value follows the
        // file rather than the default.
        let networking_text = text.replacen(
            "ATTESTATION_SUBNET_COUNT: 64",
            "ATTESTATION_SUBNET_COUNT: 32",
            1,
        );
        assert_ne!(
            networking_text, text,
            "fixture no longer carries ATTESTATION_SUBNET_COUNT in the expected form"
        );
        let networking: Config = serde_yaml_ng::from_str(&networking_text).unwrap();
        assert_eq!(networking.attestation_subnet_count, 32);

        let deposit_text = text.replacen("DEPOSIT_CHAIN_ID: 1", "DEPOSIT_CHAIN_ID: 7", 1);
        assert_ne!(
            deposit_text, text,
            "fixture no longer carries DEPOSIT_CHAIN_ID in the expected form"
        );
        let deposit: Config = serde_yaml_ng::from_str(&deposit_text).unwrap();
        assert_eq!(deposit.deposit_chain_id, 7);

        let custody_text = text.replacen("CUSTODY_REQUIREMENT: 4", "CUSTODY_REQUIREMENT: 6", 1);
        assert_ne!(
            custody_text, text,
            "fixture no longer carries CUSTODY_REQUIREMENT in the expected form"
        );
        let custody: Config = serde_yaml_ng::from_str(&custody_text).unwrap();
        assert_eq!(custody.custody_requirement, 6);
    }

    #[test]
    fn a_key_absent_from_the_file_falls_back_to_mainnet() {
        // mainnet's own config.yaml carries no MAX_REQUEST_PAYLOADS. The default
        // has to fill it rather than the parse failing.
        let text = include_str!("../../../../../bin/ethlambda/assets/mainnet/config.yaml");
        let parsed: Config = serde_yaml_ng::from_str(text).unwrap();
        assert_eq!(
            parsed.max_request_payloads,
            Config::mainnet().max_request_payloads
        );

        // The assertion above holds for an empty document too: there is
        // nothing in the fixture for MAX_REQUEST_PAYLOADS to differ from.
        // Prove this document is actually parsed, not silently treated as
        // empty, by perturbing an unrelated key and checking it takes effect
        // alongside the still-absent one's default.
        let perturbed_text = text.replacen("SUBNETS_PER_NODE: 2", "SUBNETS_PER_NODE: 5", 1);
        assert_ne!(
            perturbed_text, text,
            "fixture no longer carries SUBNETS_PER_NODE in the expected form"
        );
        let perturbed: Config = serde_yaml_ng::from_str(&perturbed_text).unwrap();
        assert_eq!(perturbed.subnets_per_node, 5);
        assert_eq!(
            perturbed.max_request_payloads,
            Config::mainnet().max_request_payloads,
            "MAX_REQUEST_PAYLOADS is still absent; it must keep defaulting"
        );
    }

    #[test]
    fn the_names_come_from_the_file_and_default_to_empty() {
        let text = include_str!("../../../../../bin/ethlambda/assets/mainnet/config.yaml");
        let parsed: Config = serde_yaml_ng::from_str(text).unwrap();
        assert_eq!(parsed.preset_base.as_str(), "mainnet");
        assert_eq!(parsed.config_name.as_str(), "mainnet");

        // Not mainnet's values, which every other absent key falls back to:
        // an absent PRESET_BASE has to fail the startup preset check rather
        // than pass it by default.
        let bare: Config = serde_yaml_ng::from_str("SECONDS_PER_SLOT: 12").unwrap();
        assert_eq!(bare.preset_base, ConfigName::default());
        assert_eq!(bare.config_name, ConfigName::default());
    }

    #[test]
    fn a_config_name_is_bounded_and_round_trips() {
        let longest = "n".repeat(MAX_CONFIG_NAME_LENGTH);
        let name = ConfigName::try_from(longest.as_str()).unwrap();
        assert_eq!(name.as_str(), longest);
        assert_eq!(ConfigName::from_ssz_bytes(&name.to_ssz()).unwrap(), name);
        assert_eq!(
            serde_json::to_value(&name).unwrap(),
            serde_json::Value::String(longest.clone())
        );

        let too_long = format!("{longest}n");
        assert_eq!(
            ConfigName::try_from(too_long.as_str()),
            Err(ConfigNameTooLong {
                length: MAX_CONFIG_NAME_LENGTH + 1
            })
        );
        let yaml = format!("CONFIG_NAME: {too_long}");
        let err = serde_yaml_ng::from_str::<Config>(&yaml).unwrap_err();
        assert!(err.to_string().contains("config name"), "got {err}");
    }

    /// The hand-written SSZ impls must encode exactly what the byte list they
    /// replaced did, or every `DB_VERSION` 4 directory written before them
    /// would decode into the wrong fields.
    #[test]
    fn a_config_name_encodes_as_the_byte_list_it_replaced() {
        let name = ConfigName::fixed("ethlambda-devnet");
        let list: SszList<u8, MAX_CONFIG_NAME_LENGTH> =
            b"ethlambda-devnet".to_vec().try_into().unwrap();
        assert_eq!(name.to_ssz(), list.to_ssz());
        assert_eq!(ConfigName::from_ssz_bytes(&list.to_ssz()).unwrap(), name);

        let over_long = vec![b'n'; MAX_CONFIG_NAME_LENGTH + 1];
        assert!(ConfigName::from_ssz_bytes(&over_long).is_err());

        // Only a corrupt database holds these, and the name survives as text.
        let not_utf8 = ConfigName::from_ssz_bytes(&[b'a', 0xff]).unwrap();
        assert_eq!(not_utf8.as_str(), "a\u{fffd}");
    }

    #[test]
    fn the_blob_schedule_parses_from_the_file() {
        let text = include_str!("../../../../../bin/ethlambda/assets/mainnet/config.yaml");
        let parsed: Config = serde_yaml_ng::from_str(text).unwrap();
        assert_eq!(parsed.blob_schedule, Config::mainnet().blob_schedule);

        // The equality above holds for an empty document too: `blob_schedule`'s
        // serde default is mainnet's own schedule. Perturb one entry's limit
        // and check the parsed schedule follows the file instead of staying
        // at the default.
        let perturbed_text = text.replacen("MAX_BLOBS_PER_BLOCK: 15", "MAX_BLOBS_PER_BLOCK: 99", 1);
        assert_ne!(
            perturbed_text, text,
            "fixture no longer carries the first BLOB_SCHEDULE entry in the expected form"
        );
        let perturbed: Config = serde_yaml_ng::from_str(&perturbed_text).unwrap();
        assert_eq!(perturbed.blob_schedule[0].max_blobs_per_block, 99);
        assert_ne!(perturbed.blob_schedule, Config::mainnet().blob_schedule);
    }

    #[test]
    fn the_spec_config_serializes_in_the_beacon_apis_encoding() {
        let json = serde_json::to_value(Config::mainnet()).expect("serializes");

        // Keys are SCREAMING_SNAKE_CASE, as /eth/v1/config/spec reports them.
        assert!(json.get("SECONDS_PER_SLOT").is_some(), "got keys: {json}");

        // Every integer is a quoted decimal string, not a bare number.
        assert_eq!(json["SECONDS_PER_SLOT"], "12");
        assert!(json["DEPOSIT_CHAIN_ID"].is_string());
        assert!(json["ELECTRA_FORK_EPOCH"].is_string());

        // Byte strings are 0x-prefixed hex.
        assert!(
            json["GENESIS_FORK_VERSION"]
                .as_str()
                .unwrap()
                .starts_with("0x"),
            "got {}",
            json["GENESIS_FORK_VERSION"]
        );
        assert!(
            json["DEPOSIT_CONTRACT_ADDRESS"]
                .as_str()
                .unwrap()
                .starts_with("0x"),
            "got {}",
            json["DEPOSIT_CONTRACT_ADDRESS"]
        );
        assert!(
            json["TERMINAL_BLOCK_HASH"]
                .as_str()
                .unwrap()
                .starts_with("0x"),
            "got {}",
            json["TERMINAL_BLOCK_HASH"]
        );

        // Uint256 is quoted DECIMAL in this API, not hex.
        let ttd = json["TERMINAL_TOTAL_DIFFICULTY"].as_str().expect("quoted");
        assert!(!ttd.starts_with("0x"), "got {ttd}");
        assert!(ttd.chars().all(|c| c.is_ascii_digit()), "got {ttd}");

        // genesis_time is #[serde(skip)]: it is not a config.yaml key and
        // /eth/v1/beacon/genesis is where it is reported.
        assert!(json.get("GENESIS_TIME").is_none());
    }

    #[test]
    fn the_blob_schedule_serializes_as_a_list_of_quoted_entries() {
        let mut config = Config::mainnet();
        config.blob_schedule = SszList::try_from(vec![BlobScheduleEntry {
            epoch: 100,
            max_blobs_per_block: 9,
        }])
        .expect("within capacity");

        let json = serde_json::to_value(&config).expect("serializes");
        let entry = &json["BLOB_SCHEDULE"][0];
        assert_eq!(entry["EPOCH"], "100");
        assert_eq!(entry["MAX_BLOBS_PER_BLOCK"], "9");
    }
}
