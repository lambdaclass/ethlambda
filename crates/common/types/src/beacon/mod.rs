//! Beacon Chain types, namespaced away from the lean types alongside them.
//!
//! `ethlambda-types` already has `primitives`, `constants`, and `checkpoint`
//! modules of its own, and lean's `Checkpoint` is a different type from
//! beacon's by the same name. Everything moved out of `ethlambda-beacon` lives
//! under this module so both sets can coexist.

pub mod config;
pub mod constants;
pub mod containers;
pub mod error;
pub mod fork;
pub mod fork_digest;
pub mod preset;
pub mod primitives;

#[cfg(test)]
mod tests {
    #[test]
    fn beacon_and_lean_roots_are_distinct_types() {
        let beacon: super::primitives::Root = super::primitives::Root::zero();
        let lean = crate::primitives::H256::ZERO;
        assert_eq!(beacon.0, lean.0);
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
