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
//! # What is deliberately left out
//!
//! - **Networking values** (gossip mesh parameters, request/response size
//!   limits, subnet counts, `MAX_PAYLOAD_SIZE`, and so on): this crate
//!   implements the state transition and fork choice, not the wire protocol,
//!   so nothing here would ever read them.
//! - **Deposit contract identity** (`DEPOSIT_CHAIN_ID`, `DEPOSIT_NETWORK_ID`,
//!   `DEPOSIT_CONTRACT_ADDRESS`): these tell a validator client which Eth1
//!   chain and contract to watch for deposits. The state transition only ever
//!   processes deposits that are already included in a block (via
//!   `Eth1Data` votes or, from electra onward, execution layer requests); it
//!   never itself looks the deposit contract up.
//!
//! The genesis-section values are all included. `GENESIS_FORK_VERSION` is fork
//! scheduling rather than genesis construction, since [`Config::fork_version`]
//! reads it on every phase0-era signature. The other three
//! (`MIN_GENESIS_ACTIVE_VALIDATOR_COUNT`, `MIN_GENESIS_TIME`, `GENESIS_DELAY`)
//! are read only while building a genesis state from Eth1 deposit history, and
//! never again once that state exists, but `ethlambda_beacon::genesis` needs them
//! and the `genesis` fixture suite checks them.

use crate::beacon::constants;
use crate::beacon::fork::ForkName;
use crate::beacon::primitives::{Epoch, ExecutionBlockHash, Gwei, Uint256, Version};

/// One entry in fulu's blob schedule: from `epoch` onward (until a later
/// entry takes over), a block may carry up to `max_blobs_per_block` blobs.
///
/// Modeled as a plain struct rather than a `(Epoch, u64)` tuple so that
/// [`Config::max_blobs_per_block`]'s search reads as "find the entry", not
/// "find the pair".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobScheduleEntry {
    /// The first epoch this entry applies to.
    pub epoch: Epoch,
    /// The blob count limit from `epoch` onward.
    pub max_blobs_per_block: u64,
}

/// The runtime configuration for one network: fork scheduling plus every
/// other value the state transition and fork choice read at runtime rather
/// than at compile time.
///
/// Construct one with [`Config::mainnet`], [`Config::minimal`], or
/// [`Config::active`]; adjust a single fork's activation epoch with
/// [`Config::with_fork_epoch`] for fixture-driven tests that need one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    // -- Genesis construction ---------------------------------------------
    /// How many active validators the chain needs before it may start.
    pub min_genesis_active_validator_count: u64,
    /// The earliest wall-clock time the chain may start at, whatever the Eth1
    /// deposit history says.
    pub min_genesis_time: u64,
    /// How long after the Eth1 block that satisfies the genesis conditions the
    /// chain actually starts.
    ///
    /// The delay exists so that validators who deposited just before the
    /// threshold was crossed still have time to get their nodes running.
    pub genesis_delay: u64,

    // -- Fork scheduling --------------------------------------------------
    /// The `Fork.current_version` a phase0 block or attestation signs under,
    /// and the value every later fork's version is a successor to. Also
    /// mixed into `compute_fork_data_root` when computing the genesis
    /// validators root's domain, alongside the all-zero genesis validators
    /// root, at chain start.
    pub genesis_fork_version: Version,
    /// The `Fork.current_version` an altair block or attestation signs under.
    pub altair_fork_version: Version,
    /// The epoch altair activates at, or [`constants::FAR_FUTURE_EPOCH`] if it
    /// is not scheduled on this network.
    pub altair_fork_epoch: Epoch,
    /// The `Fork.current_version` a bellatrix block or attestation signs
    /// under.
    pub bellatrix_fork_version: Version,
    /// The epoch bellatrix (the Merge) activates at, or
    /// [`constants::FAR_FUTURE_EPOCH`] if it is not scheduled.
    pub bellatrix_fork_epoch: Epoch,
    /// The `Fork.current_version` a capella block or attestation signs under.
    pub capella_fork_version: Version,
    /// The epoch capella activates at, or [`constants::FAR_FUTURE_EPOCH`] if
    /// it is not scheduled.
    pub capella_fork_epoch: Epoch,
    /// The `Fork.current_version` a deneb block or attestation signs under.
    pub deneb_fork_version: Version,
    /// The epoch deneb activates at, or [`constants::FAR_FUTURE_EPOCH`] if it
    /// is not scheduled.
    pub deneb_fork_epoch: Epoch,
    /// The `Fork.current_version` an electra block or attestation signs
    /// under.
    pub electra_fork_version: Version,
    /// The epoch electra activates at, or [`constants::FAR_FUTURE_EPOCH`] if
    /// it is not scheduled.
    pub electra_fork_epoch: Epoch,
    /// The `Fork.current_version` a fulu block or attestation signs under.
    pub fulu_fork_version: Version,
    /// The epoch fulu activates at, or [`constants::FAR_FUTURE_EPOCH`] if it
    /// is not scheduled.
    pub fulu_fork_epoch: Epoch,

    // -- Time parameters ---------------------------------------------------
    /// Wall-clock seconds per slot. Deprecated in favor of
    /// [`Self::slot_duration_ms`] for anything needing sub-second precision,
    /// but still how `compute_time_at_slot` and the fork choice store's
    /// `genesis_time`-to-slot arithmetic convert between a slot number and a
    /// wall-clock time.
    pub seconds_per_slot: u64,
    /// Milliseconds per slot. What the fork choice store's timeliness
    /// checks (`get_attestation_due_ms` and friends) actually divide the
    /// `*_due_bps` fields below by; equal to `seconds_per_slot * 1000` on
    /// every network this crate ships a constructor for, but tracked
    /// separately because the specification does.
    pub slot_duration_ms: u64,
    /// The assumed seconds per execution-layer block, used to convert
    /// [`Self::eth1_follow_distance`] (a block count) into a voting-period
    /// safety margin.
    pub seconds_per_eth1_block: u64,
    /// Epochs a validator must wait after its exit is processed before its
    /// balance becomes withdrawable.
    pub min_validator_withdrawability_delay: Epoch,
    /// Epochs a validator must be active before it is eligible to propose,
    /// perform voluntary exits, or (from electra) initiate a consolidation.
    pub shard_committee_period: Epoch,
    /// Execution-layer blocks a state's Eth1 vote must lag the execution
    /// chain's head by, so that every node's view of "current" Eth1 data
    /// agrees despite network latency and minor reorgs.
    pub eth1_follow_distance: u64,
    /// Basis points of [`Self::slot_duration_ms`] by which an attestation is
    /// due; read by the fork choice store's `get_attestation_due_ms`.
    pub attestation_due_bps: u64,
    /// Basis points of [`Self::slot_duration_ms`] by which an aggregate
    /// attestation is due; read by `get_aggregate_due_ms`.
    pub aggregate_due_bps: u64,
    /// Basis points of [`Self::slot_duration_ms`] past which a proposer must
    /// no longer attempt a late-block reorg; read by
    /// `get_proposer_reorg_cutoff_ms`.
    pub proposer_reorg_cutoff_bps: u64,
    /// Basis points of [`Self::slot_duration_ms`] by which a sync committee
    /// message is due (altair); read by `get_sync_message_due_ms`.
    pub sync_message_due_bps: u64,
    /// Basis points of [`Self::slot_duration_ms`] by which a sync committee
    /// contribution is due (altair); read by `get_contribution_due_ms`.
    pub contribution_due_bps: u64,

    // -- Validator cycle -----------------------------------------------------
    /// Score points added to a validator's inactivity score for each epoch it
    /// is offline (or the chain is leaking) without a timely target vote.
    pub inactivity_score_bias: u64,
    /// Score points subtracted from a validator's inactivity score for each
    /// epoch it casts a timely target vote while the chain is not leaking.
    pub inactivity_score_recovery_rate: u64,
    /// Effective balance floor below which a validator is force-exited at the
    /// next opportunity, regardless of its own wishes.
    pub ejection_balance: Gwei,
    /// The minimum validators allowed to enter the activation/exit queue in
    /// one epoch, regardless of the active validator set's size. Prevents the
    /// churn limit from collapsing to zero on a small validator set.
    pub min_per_epoch_churn_limit: u64,
    /// Active validators per unit of per-epoch activation/exit churn: the
    /// churn limit before electra is `active_validator_count /
    /// churn_limit_quotient`, floored at [`Self::min_per_epoch_churn_limit`].
    pub churn_limit_quotient: u64,
    /// Deneb: an additional cap on the activation churn limit specifically
    /// (separate from the combined activation/exit limit above), so that
    /// activations cannot alone consume the whole per-epoch churn budget.
    /// Superseded by [`Self::max_per_epoch_activation_exit_churn_limit`] from
    /// electra onward, but the specification keeps both names rather than
    /// reusing one.
    pub max_per_epoch_activation_churn_limit: u64,
    /// Electra: the churn limit is now denominated in Gwei rather than a
    /// validator count (`get_balance_churn_limit`), and this is its floor,
    /// replacing [`Self::min_per_epoch_churn_limit`] from electra onward.
    pub min_per_epoch_churn_limit_electra: Gwei,
    /// Electra: the ceiling on the portion of the (Gwei-denominated) churn
    /// limit dedicated to activations and exits, as opposed to
    /// consolidations (`get_activation_exit_churn_limit`).
    pub max_per_epoch_activation_exit_churn_limit: Gwei,

    // -- Fork choice ---------------------------------------------------------
    /// Percentage boost, relative to a single committee's weight, given to a
    /// block proposed on time when comparing it against competitors for head.
    /// Deters "balancing" attacks that rely on splitting the vote right at a
    /// slot boundary.
    pub proposer_score_boost: u64,
    /// Percentage of committee weight the current head must be below the
    /// parent's competing child by for a proposer to consider reorging it out.
    pub reorg_head_weight_threshold: u64,
    /// Percentage of committee weight the parent block must exceed for a
    /// proposer to consider reorging its late child out.
    pub reorg_parent_weight_threshold: u64,
    /// How many epochs finality is allowed to lag before a proposer refuses to
    /// attempt a reorg at all, regardless of the weight thresholds above.
    /// Reorgs are a liveness optimization; this bounds how much they may risk
    /// finality progress to pursue it.
    pub reorg_max_epochs_since_finalization: Epoch,

    // -- Transition (bellatrix) -----------------------------------------------
    /// The proof-of-work total difficulty at or above which a PoW block
    /// becomes a valid terminal block for the Merge transition.
    /// [`Uint256`]-sized because total difficulty accumulates over the
    /// entire PoW chain's history and long since overflowed 64 bits.
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
    pub terminal_block_hash_activation_epoch: Epoch,

    // -- Blob limits -----------------------------------------------------------
    /// Deneb's fixed cap on `blob_kzg_commitments` per block, in effect from
    /// deneb until electra raises it.
    pub max_blobs_per_block_deneb: u64,
    /// Electra's fixed cap on `blob_kzg_commitments` per block. Also the value
    /// [`Self::max_blobs_per_block`] falls back to for any epoch fulu's blob
    /// schedule does not (yet) cover, matching `get_blob_parameters`'s own
    /// fallback of `BlobParameters(ELECTRA_FORK_EPOCH,
    /// MAX_BLOBS_PER_BLOCK_ELECTRA)`.
    pub max_blobs_per_block_electra: u64,
    /// Fulu's blob schedule (EIP7892): a possibly-empty list of `(epoch,
    /// limit)` entries, kept sorted ascending by epoch, that lets the blob
    /// count limit change again after electra without a new hard fork per
    /// change. Read through [`Config::max_blobs_per_block`] rather than
    /// directly.
    pub blob_schedule: Vec<BlobScheduleEntry>,
}

impl Config {
    /// The configuration matching Ethereum mainnet, as of the pinned
    /// specification version's `configs/mainnet.yaml`.
    pub fn mainnet() -> Self {
        Config {
            min_genesis_active_validator_count: 16_384,
            min_genesis_time: 1_606_824_000,
            genesis_delay: 604_800,
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

            inactivity_score_bias: 4,
            inactivity_score_recovery_rate: 16,
            ejection_balance: 16_000_000_000,
            min_per_epoch_churn_limit: 4,
            churn_limit_quotient: 65_536,
            max_per_epoch_activation_churn_limit: 8,
            min_per_epoch_churn_limit_electra: 128_000_000_000,
            max_per_epoch_activation_exit_churn_limit: 256_000_000_000,

            proposer_score_boost: 40,
            reorg_head_weight_threshold: 20,
            reorg_parent_weight_threshold: 160,
            reorg_max_epochs_since_finalization: 2,

            // Reached September 15, 2022 (the Merge); mainnet has been on
            // proof of stake ever since, so this and the two fields below
            // never trigger again in practice, but are still read by any
            // faithful implementation of `validate_merge_block`.
            terminal_total_difficulty: Uint256::from_dec_str("58750000000000000000000")
                .expect("valid decimal literal"),
            terminal_block_hash: ExecutionBlockHash::zero(),
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
            ],
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
            min_genesis_active_validator_count: 64,
            min_genesis_time: 1_578_009_600,
            genesis_delay: 300,
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

            inactivity_score_bias: 4,
            inactivity_score_recovery_rate: 16,
            ejection_balance: 16_000_000_000,
            min_per_epoch_churn_limit: 2,
            churn_limit_quotient: 32,
            max_per_epoch_activation_churn_limit: 4,
            min_per_epoch_churn_limit_electra: 64_000_000_000,
            max_per_epoch_activation_exit_churn_limit: 128_000_000_000,

            proposer_score_boost: 40,
            reorg_head_weight_threshold: 20,
            reorg_parent_weight_threshold: 160,
            reorg_max_epochs_since_finalization: 2,

            // configs/minimal.yaml sets this to 2**256 - 2**10: large enough
            // that no spec test's simulated PoW chain reaches it.
            terminal_total_difficulty: Uint256::from_dec_str(
                "115792089237316195423570985008687907853269984665640564039457584007913129638912",
            )
            .expect("valid decimal literal"),
            terminal_block_hash: ExecutionBlockHash::zero(),
            terminal_block_hash_activation_epoch: constants::FAR_FUTURE_EPOCH,

            max_blobs_per_block_deneb: 6,
            max_blobs_per_block_electra: 9,
            blob_schedule: Vec::new(),
        }
    }

    /// The configuration matching the compiled-in preset: [`Config::minimal`]
    /// when this crate is built with the `preset-minimal` feature,
    /// [`Config::mainnet`] otherwise.
    ///
    /// For code that already knows its preset at compile time (unlike the
    /// `transition` fixture suite, which needs to pick a configuration, and
    /// possibly override a fork epoch, per test case).
    #[cfg(not(feature = "preset-minimal"))]
    pub fn active() -> Self {
        Self::mainnet()
    }

    /// See the `preset-minimal` branch of [`Config::active`] above; `cfg`
    /// picks exactly one of the two to compile.
    #[cfg(feature = "preset-minimal")]
    pub fn active() -> Self {
        Self::minimal()
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
            ForkName::Lean => unreachable!(
                "lean state reached a beacon accessor (fork_version); \
                 BlockChainServer must dispatch on fork_name() before this point"
            ),
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
            ForkName::Lean => unreachable!(
                "lean state reached a beacon accessor (fork_epoch); \
                 BlockChainServer must dispatch on fork_name() before this point"
            ),
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
            ForkName::Lean => unreachable!(
                "lean state reached a beacon accessor (with_fork_epoch); \
                 BlockChainServer must dispatch on fork_name() before this point"
            ),
        }
        self
    }

    /// The blob count limit for a block proposed in `epoch`, from fulu's
    /// [`Self::blob_schedule`].
    ///
    /// Mirrors `get_blob_parameters`: the schedule is searched from its
    /// latest entry backward for the first one whose epoch is at or before
    /// `epoch`; if none matches (the schedule is empty, as in
    /// [`Config::minimal`]'s default, or every entry is still in the future),
    /// this falls back to [`Self::max_blobs_per_block_electra`], exactly as
    /// the specification's own `get_blob_parameters` falls back to
    /// `MAX_BLOBS_PER_BLOCK_ELECTRA`.
    ///
    /// This is fulu's helper: a deneb- or electra-only block's blob count is
    /// bounded by [`Self::max_blobs_per_block_deneb`] or
    /// [`Self::max_blobs_per_block_electra`] directly instead, matching how
    /// the specification only introduces `get_blob_parameters` at fulu.
    pub fn max_blobs_per_block(&self, epoch: Epoch) -> u64 {
        self.blob_schedule
            .iter()
            .rev()
            .find(|entry| entry.epoch <= epoch)
            .map(|entry| entry.max_blobs_per_block)
            .unwrap_or(self.max_blobs_per_block_electra)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
