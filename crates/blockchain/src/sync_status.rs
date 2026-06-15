use crate::metrics::SyncStatus;

/// Local head lag beyond which the node is considered to be syncing.
///
/// See: leanSpec PR #708.
const SYNC_LAG_THRESHOLD: u64 = 4;
/// Freshest-known block lag beyond which the network is considered stalled.
///
/// During a network-wide stall the node remains synced so validators can help
/// the chain recover.
const NETWORK_STALL_THRESHOLD: u64 = 8;
/// Recovery band that prevents the sync status from flapping near the threshold.
const SYNC_HYSTERESIS_BAND: u64 = 2;

#[derive(Default)]
pub(crate) struct SyncStatusTracker {
    syncing: bool,
}

impl SyncStatusTracker {
    pub(crate) fn update(
        &mut self,
        current_slot: u64,
        head_slot: u64,
        max_seen_slot: u64,
    ) -> SyncStatus {
        let head_lag = current_slot.saturating_sub(head_slot);
        let network_lag = current_slot.saturating_sub(max_seen_slot);

        if network_lag > NETWORK_STALL_THRESHOLD {
            self.syncing = false;
        } else if self.syncing {
            self.syncing = head_lag > SYNC_LAG_THRESHOLD.saturating_sub(SYNC_HYSTERESIS_BAND);
        } else {
            self.syncing = head_lag > SYNC_LAG_THRESHOLD;
        }

        if self.syncing {
            SyncStatus::Syncing
        } else {
            SyncStatus::Synced
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_status_allows_lag_through_threshold() {
        let mut tracker = SyncStatusTracker::default();

        for lag in 0..=SYNC_LAG_THRESHOLD {
            assert_eq!(tracker.update(10 + lag, 10, 10 + lag), SyncStatus::Synced);
        }
    }

    #[test]
    fn sync_status_detects_local_lag_when_fresh_blocks_are_known() {
        let mut tracker = SyncStatusTracker::default();
        let current_slot = 10 + SYNC_LAG_THRESHOLD + 1;

        assert_eq!(
            tracker.update(current_slot, 10, current_slot),
            SyncStatus::Syncing
        );
    }

    #[test]
    fn sync_status_treats_stale_known_blocks_as_network_stall() {
        let mut tracker = SyncStatusTracker::default();

        assert_eq!(tracker.update(100, 0, 0), SyncStatus::Synced);
    }

    #[test]
    fn sync_status_hysteresis_prevents_flapping() {
        let mut tracker = SyncStatusTracker::default();

        assert_eq!(tracker.update(15, 10, 15), SyncStatus::Syncing);
        assert_eq!(tracker.update(15, 11, 15), SyncStatus::Syncing);
        assert_eq!(tracker.update(15, 10, 15), SyncStatus::Syncing);
        assert_eq!(tracker.update(15, 13, 15), SyncStatus::Synced);
    }

    #[test]
    fn network_stall_reopens_sync_status() {
        let mut tracker = SyncStatusTracker::default();

        assert_eq!(tracker.update(20, 0, 20), SyncStatus::Syncing);
        assert_eq!(tracker.update(30, 0, 20), SyncStatus::Synced);
    }

    #[test]
    fn future_head_saturates_lag_at_zero() {
        let mut tracker = SyncStatusTracker::default();

        assert_eq!(tracker.update(15, 20, 20), SyncStatus::Synced);
    }
}
