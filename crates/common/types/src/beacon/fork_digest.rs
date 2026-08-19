//! The four bytes that separate one network, fork, and blob schedule from
//! another on the wire.
//!
//! Lives here rather than in `ethlambda-beacon` because the networking crate
//! needs it and must not depend on the state transition: `ethlambda-beacon`
//! pulls in `blst` and `c-kzg`, neither of which a gossip topic name has any
//! business requiring. `ethlambda_beacon::helpers::misc` re-exports
//! [`compute_fork_data_root`] at its old path.

use sha2::{Digest as _, Sha256};

use crate::beacon::config::Config;
use crate::beacon::constants;
use crate::beacon::containers::shared::ForkData;
use crate::beacon::fork::ForkName;
use crate::beacon::primitives::{Epoch, ForkDigest, HashTreeRoot as _, Root, Version};

/// The root binding a fork version to a chain's genesis validator set.
///
/// Mixing both into every signing domain and into the fork digest is what keeps
/// a signature, or a gossip topic, from one chain or fork from being valid on
/// another.
pub fn compute_fork_data_root(current_version: Version, genesis_validators_root: Root) -> Root {
    ForkData {
        current_version,
        genesis_validators_root,
    }
    .hash_tree_root()
}

/// The four bytes every gossip topic name and the `eth2` ENR entry carry, for a
/// chain with this schedule, this genesis validator set, and this epoch.
///
/// This is fulu's `compute_fork_digest` (EIP-7892). Before fulu the digest is
/// simply the fork data root's first four bytes. From fulu on, the blob
/// parameters are xored in, so that a blob-parameter-only fork moves the digest
/// and therefore the topic names without needing a new fork version.
pub fn compute_fork_digest(
    config: &Config,
    genesis_validators_root: Root,
    epoch: Epoch,
) -> ForkDigest {
    let fork = config.fork_at_epoch(epoch);
    let base = compute_fork_data_root(config.fork_version(fork), genesis_validators_root);

    if fork < ForkName::Fulu {
        return base.0[..4].try_into().expect("a Root is 32 bytes");
    }

    let (bp_epoch, bp_max_blobs) = config.blob_parameters(epoch);
    let mut hasher = Sha256::new();
    hasher.update(bp_epoch.to_le_bytes());
    hasher.update(bp_max_blobs.to_le_bytes());
    let mask = hasher.finalize();

    core::array::from_fn(|index| base.0[index] ^ mask[index])
}

/// The next epoch at which [`compute_fork_digest`] changes, if there is one.
///
/// Both fork activations and blob-schedule entries qualify: crossing either one
/// strands a running node on topic names no peer is publishing to. Unscheduled
/// forks carry [`constants::FAR_FUTURE_EPOCH`], a real value rather than a
/// `None`, so they are filtered out before the minimum is taken.
pub fn next_fork_boundary(config: &Config, epoch: Epoch) -> Option<Epoch> {
    ForkName::ALL
        .into_iter()
        .map(|fork| config.fork_epoch(fork))
        .chain(config.blob_schedule.iter().map(|entry| entry.epoch))
        .filter(|&boundary| boundary != constants::FAR_FUTURE_EPOCH && boundary > epoch)
        .min()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::config::Config;
    use crate::beacon::primitives::Root;

    /// Ethereum mainnet's `genesis_validators_root`.
    fn mainnet_gvr() -> Root {
        Root::from_slice(
            &hex::decode("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95")
                .expect("valid hex"),
        )
    }

    #[test]
    fn mainnet_digests_match_the_ones_observed_on_the_wire() {
        // Every value here was read off a live mainnet discv5 crawl and is
        // recorded in docs/discovery.md. Both branches of the fulu rule are
        // covered: the pre-fulu truncation and the EIP-7892 blob-parameter xor.
        let config = Config::mainnet();
        let gvr = mainnet_gvr();
        let cases = [
            // phase0, still advertised by bootnode records never re-published.
            (0u64, [0xb5, 0x30, 0x3f, 0x2a]),
            // electra.
            (364_032u64, [0xad, 0x53, 0x2c, 0xeb]),
            // fulu, before the first blob-schedule entry: the parameters fall
            // back to (electra_fork_epoch, max_blobs_per_block_electra).
            (411_392u64, [0xcc, 0x2c, 0x5c, 0xdb]),
            // fulu, first BPO fork.
            (412_672u64, [0xcb, 0x0d, 0x1a, 0xcc]),
            // fulu, second BPO fork: mainnet's current digest.
            (419_072u64, [0x8c, 0x9f, 0x62, 0xfe]),
        ];
        for (epoch, expected) in cases {
            assert_eq!(
                compute_fork_digest(&config, gvr, epoch),
                expected,
                "digest at epoch {epoch}"
            );
        }
    }

    #[test]
    fn the_digest_holds_between_boundaries() {
        // A digest that changed every epoch would mean the node re-subscribed
        // constantly; it must only move at a fork or blob-schedule boundary.
        let config = Config::mainnet();
        let gvr = mainnet_gvr();
        assert_eq!(
            compute_fork_digest(&config, gvr, 419_072),
            compute_fork_digest(&config, gvr, 419_072 + 5_000)
        );
        assert_ne!(
            compute_fork_digest(&config, gvr, 419_071),
            compute_fork_digest(&config, gvr, 419_072)
        );
    }

    #[test]
    fn next_boundary_covers_both_fork_and_blob_schedule_epochs() {
        let config = Config::mainnet();
        // A plain fork boundary.
        assert_eq!(next_fork_boundary(&config, 0), Some(74_240));
        // A blob-parameter-only fork is a boundary too: it moves the digest.
        assert_eq!(next_fork_boundary(&config, 411_392), Some(412_672));
        assert_eq!(next_fork_boundary(&config, 412_672), Some(419_072));
        // Past the last scheduled boundary there is nothing left to warn about.
        assert_eq!(next_fork_boundary(&config, 419_072), None);
    }

    #[test]
    fn far_future_forks_are_not_boundaries() {
        // Minimal leaves every fork after phase0 at FAR_FUTURE_EPOCH, which is a
        // real, enormous Epoch rather than a None; treating it as a boundary
        // would schedule a warning for the heat death of the universe.
        assert_eq!(next_fork_boundary(&Config::minimal(), 0), None);
    }

    #[test]
    fn fork_data_root_binds_the_version_and_the_chain() {
        let a = compute_fork_data_root([1, 0, 0, 0], Root::zero());
        let b = compute_fork_data_root([2, 0, 0, 0], Root::zero());
        let c = compute_fork_data_root([1, 0, 0, 0], Root::repeat_byte(1));
        assert_ne!(a, b);
        assert_ne!(a, c);
    }
}
