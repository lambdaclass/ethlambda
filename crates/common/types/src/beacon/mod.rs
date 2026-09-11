//! Beacon Chain types, namespaced away from the lean types alongside them.
//!
//! `ethlambda-types` already has `primitives`, `constants`, and `checkpoint`
//! modules of its own, and lean's `Checkpoint` is a different type from
//! beacon's by the same name. Everything moved out of the beacon state
//! transition lives
//! under this module so both sets can coexist.

pub mod config;
pub mod constants;
pub mod containers;
pub mod error;
pub mod fork;
pub mod fork_choice;
pub mod fork_digest;
pub mod preset;
pub mod primitives;

/// Panics, naming the beacon accessor a lean state reached.
///
/// The boundary is structural rather than type-level: [`containers::BeaconState`]
/// carries a `Lean` variant, so every beacon-only accessor needs an arm for it.
/// Written once here so the wording, and the diagnosis it points at, cannot
/// drift from one such arm to the next.
///
/// This is the state-shaped boundary: reaching it means a handler dispatched on
/// the wrong thing. For the fork-shaped one see [`lean_fork_unreachable`], kept
/// separate because the two are crossed by different mistakes.
///
/// `#[track_caller]` so the panic still reports the arm's own file and line, the
/// way an `unreachable!` written inline there would have.
#[cold]
#[track_caller]
pub(crate) fn lean_state_unreachable(function: &str) -> ! {
    unreachable!(
        "lean state reached a beacon accessor ({function}); \
         BlockChainServer must dispatch on fork_name() before this point"
    )
}

/// Panics, naming the Beacon Chain-only function [`fork::ForkName::Lean`] reached.
///
/// The fork-shaped counterpart to [`lean_state_unreachable`]: lean is not a point
/// on the beacon fork schedule at all, so no state is involved and the fault is
/// the argument the caller passed rather than the state it dispatched on.
#[cold]
#[track_caller]
pub(crate) fn lean_fork_unreachable(function: &str) -> ! {
    unreachable!(
        "ForkName::Lean reached a Beacon Chain function ({function}); \
         lean is not a point on the beacon fork schedule, so the caller \
         passed a fork it should have dispatched on first"
    )
}

/// Panics, naming the Beacon Chain-only block accessor a lean block reached.
///
/// The block-shaped counterpart to [`lean_state_unreachable`]. A lean block is
/// a real variant of [`containers::SignedBeaconBlock`] and answers every
/// accessor whose field it actually has; this is for the one it does not,
/// `signature`, since lean signs with a `MultiMessageAggregate` proof rather
/// than a `BlsSignature`.
#[cold]
#[track_caller]
pub(crate) fn lean_block_unreachable(function: &str) -> ! {
    unreachable!(
        "lean block reached a beacon accessor ({function}); \
         a lean block has no BLS signature"
    )
}

/// Panics, naming the beacon fork a lean-only caller reached.
///
/// The mirror image of [`lean_state_unreachable`] and [`lean_block_unreachable`]:
/// those fire when a lean value meets a beacon accessor, this one when a beacon
/// value meets a caller that only ever runs against a lean store. Both mean a
/// handler dispatched on the wrong thing, so both are `unreachable!` rather than
/// a `Result` no correct caller would see.
///
/// Written once here, like its counterparts, so the wording cannot drift across
/// the call sites that peel [`containers::BeaconState::Lean`] back off. The
/// fork it actually found is what says which chain's value took the wrong path.
#[cold]
#[track_caller]
pub(crate) fn beacon_value_unreachable(what: &str, fork: fork::ForkName) -> ! {
    unreachable!(
        "a {fork:?} {what} reached a lean-only caller; \
         a data directory holds one chain for its whole life, so the store's \
         chain tag and the caller disagree"
    )
}

#[cfg(test)]
mod tests {
    /// A type-level assertion that the namespace does not reintroduce a second
    /// 32-byte hash: assigning one to the other only compiles while
    /// [`primitives::Root`] names the very same type as the lean `H256`, which
    /// is what lets a beacon block root reach a store lookup unconverted.
    #[test]
    fn a_beacon_root_is_the_lean_hash() {
        let beacon: super::primitives::Root = super::primitives::Root::ZERO;
        let _lean: crate::primitives::H256 = beacon;
    }

    #[test]
    fn beacon_constants_are_reachable_beside_lean_constants() {
        // Both crates define a `constants` module; the namespace keeps them
        // apart. `FAR_FUTURE_EPOCH` is the sentinel every unscheduled fork
        // epoch carries.
        assert_eq!(super::constants::FAR_FUTURE_EPOCH, u64::MAX);
        assert_eq!(crate::constants::FORK_DIGEST, "12345678");
    }

    #[test]
    fn fork_ordering_is_reachable_from_the_namespace() {
        use super::fork::ForkName;
        assert!(ForkName::Fulu > ForkName::Phase0);
    }

    #[test]
    fn preset_slots_per_epoch_matches_the_selected_preset() {
        #[cfg(not(feature = "preset-minimal"))]
        assert_eq!(super::preset::SLOTS_PER_EPOCH, 32);
        #[cfg(feature = "preset-minimal")]
        assert_eq!(super::preset::SLOTS_PER_EPOCH, 8);
    }

    #[test]
    fn mainnet_config_carries_the_fulu_schedule() {
        let config = super::config::Config::mainnet();
        assert_eq!(config.fulu_fork_version, [0x06, 0x00, 0x00, 0x00]);
        assert_eq!(config.fulu_fork_epoch, 411_392);
        // The two blob-parameter-only forks, which perturb the fork digest.
        assert_eq!(config.blob_schedule.len(), 2);
        assert_eq!(config.blob_schedule[0].epoch, 412_672);
        assert_eq!(config.blob_schedule[0].max_blobs_per_block, 15);
        assert_eq!(config.blob_schedule[1].epoch, 419_072);
        assert_eq!(config.blob_schedule[1].max_blobs_per_block, 21);
    }

    #[test]
    fn the_beacon_containers_are_reachable_from_the_namespace() {
        use super::containers::{BeaconState, phase0};

        // A type-level assertion: naming the variant constructor as a function
        // proves both the enum and the per-fork struct resolve, with nothing to
        // construct. No fork's BeaconState derives Default.
        let _: fn(phase0::BeaconState) -> BeaconState = BeaconState::Phase0;
    }
}
