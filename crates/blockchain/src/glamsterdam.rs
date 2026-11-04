//! The Glamsterdam banner, logged once this node imports the chain's first
//! gloas block.
//!
//! The fork goes live with a block, not at a slot: gloas applies from
//! `GLOAS_FORK_EPOCH` on, but the epoch can open with missed slots, so the
//! first gloas block is the first one gloas applies to while it did not apply
//! to its parent.

use ethlambda_storage::{Chain, Store};
use ethlambda_types::{
    ShortRoot,
    beacon::{config::Config, signing::compute_epoch_at_slot},
    primitives::H256,
};
use tracing::info;

const BANNER: &str = include_str!("../assets/glamsterdam_banner.txt");

/// Whether this process may still log the banner.
///
/// Settled by the first gloas block this process imports, whether or not that
/// block is the chain's first. Blocks import parent-first, so a node that
/// imports the chain's first gloas block imports it before any other. One
/// that does not (it started after the fork, or was checkpoint-synced past
/// it) never will, and asking every later import for its parent's slot would
/// cost a whole-block decode per block for the rest of the process's life.
#[derive(Debug)]
pub(crate) struct GlamsterdamBanner {
    pending: bool,
}

impl Default for GlamsterdamBanner {
    fn default() -> Self {
        Self { pending: true }
    }
}

impl GlamsterdamBanner {
    /// Logs the banner if the beacon block just imported at `slot` is the
    /// chain's first gloas block.
    pub(crate) fn on_block_imported(
        &mut self,
        store: &Store,
        slot: u64,
        block_root: H256,
        parent_root: H256,
    ) {
        if !self.pending || store.chain() != Chain::Beacon {
            return;
        }
        let parent_slot = || store.block_entry(&parent_root).map(|(slot, _)| slot);
        if self.take_first_gloas_block(&store.config(), slot, parent_slot) {
            log(slot, block_root);
        }
    }

    /// Whether the block at `slot` is the chain's first gloas block, settling
    /// the banner on the first gloas block either way.
    ///
    /// `parent_slot` is called only for that block, since on a beacon store it
    /// decodes the whole parent block. `None` (no parent block on record)
    /// settles without a banner.
    fn take_first_gloas_block(
        &mut self,
        config: &Config,
        slot: u64,
        parent_slot: impl FnOnce() -> Option<u64>,
    ) -> bool {
        if !self.pending || !is_gloas(config, slot) {
            return false;
        }
        self.pending = false;
        parent_slot().is_some_and(|parent_slot| !is_gloas(config, parent_slot))
    }
}

/// Whether gloas, or a fork after it, applies at `slot`.
fn is_gloas(config: &Config, slot: u64) -> bool {
    config
        .fork_at_epoch(compute_epoch_at_slot(slot))
        .has_payload_envelopes()
}

/// Logs the banner one line at a time, so every line carries the log
/// formatter's prefix instead of only the first.
fn log(slot: u64, block_root: H256) {
    info!("");
    for line in BANNER.lines() {
        info!("{line}");
    }
    info!("");
    let epoch = compute_epoch_at_slot(slot);
    info!(
        %slot,
        epoch,
        block_root = %ShortRoot(&block_root.0),
        "Glamsterdam is live: imported the first gloas block"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_types::beacon::{fork::ForkName, preset::SLOTS_PER_EPOCH};

    const GLOAS_EPOCH: u64 = 5;
    const FORK_SLOT: u64 = GLOAS_EPOCH * SLOTS_PER_EPOCH;

    fn gloas_at(epoch: u64) -> Config {
        Config::mainnet()
            .with_fork_epoch(ForkName::Fulu, 0)
            .with_fork_epoch(ForkName::Gloas, epoch)
    }

    fn no_parent_read() -> Option<u64> {
        panic!("the parent's slot was read for a block gloas does not apply to")
    }

    #[test]
    fn the_block_crossing_the_fork_is_the_first() {
        let mut banner = GlamsterdamBanner::default();
        let first = banner
            .take_first_gloas_block(&gloas_at(GLOAS_EPOCH), FORK_SLOT, || Some(FORK_SLOT - 1));
        assert!(first);
    }

    #[test]
    fn missed_slots_at_the_fork_still_leave_a_first_block() {
        let mut banner = GlamsterdamBanner::default();
        let slot = FORK_SLOT + SLOTS_PER_EPOCH + 3;
        let first =
            banner.take_first_gloas_block(&gloas_at(GLOAS_EPOCH), slot, || Some(FORK_SLOT - 2));
        assert!(first);
    }

    #[test]
    fn blocks_before_the_fork_neither_log_nor_settle() {
        let config = gloas_at(GLOAS_EPOCH);
        let mut banner = GlamsterdamBanner::default();
        assert!(!banner.take_first_gloas_block(&config, FORK_SLOT - 1, no_parent_read));
        assert!(banner.take_first_gloas_block(&config, FORK_SLOT, || Some(FORK_SLOT - 1)));
    }

    #[test]
    fn the_banner_is_logged_once() {
        let config = gloas_at(GLOAS_EPOCH);
        let mut banner = GlamsterdamBanner::default();
        assert!(banner.take_first_gloas_block(&config, FORK_SLOT, || Some(FORK_SLOT - 1)));
        // A competing first gloas block, on a fork from the same parent.
        assert!(!banner.take_first_gloas_block(&config, FORK_SLOT + 1, no_parent_read));
    }

    #[test]
    fn a_node_started_after_the_fork_settles_without_a_banner() {
        let config = gloas_at(GLOAS_EPOCH);
        let mut banner = GlamsterdamBanner::default();
        let slot = FORK_SLOT + 10;
        assert!(!banner.take_first_gloas_block(&config, slot, || Some(slot - 1)));
        assert!(!banner.pending);
    }

    #[test]
    fn a_parent_off_record_settles_without_a_banner() {
        let mut banner = GlamsterdamBanner::default();
        assert!(!banner.take_first_gloas_block(&gloas_at(GLOAS_EPOCH), FORK_SLOT, || None));
        assert!(!banner.pending);
    }

    #[test]
    fn no_first_gloas_block_without_a_scheduled_fork() {
        let config = Config::mainnet().with_fork_epoch(ForkName::Fulu, 0);
        let mut banner = GlamsterdamBanner::default();
        assert!(!banner.take_first_gloas_block(&config, u64::MAX, no_parent_read));
        assert!(banner.pending);
    }
}
