use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use ethlambda_types::beacon::preset::SLOTS_PER_EPOCH;
use tracing::info;

use crate::metrics::SyncStatus;

/// Shared, runtime-readable node sync status.
///
/// The blockchain actor is the sole writer: once per tick it calls
/// [`SyncStatusController::set`] with the same [`SyncStatus`] it feeds the
/// `lean_node_sync_status` metric (see `BlockChainServer::update_sync_status`).
/// Read paths outside the actor — notably the RPC `/lean/v0/node/syncing`
/// endpoint — clone the controller and read the current status without touching
/// actor state. Mirrors [`ethlambda_types::aggregator::AggregatorController`].
#[derive(Clone, Debug)]
pub struct SyncStatusController {
    status: Arc<AtomicU8>,
}

impl SyncStatusController {
    /// Construct a controller seeded with `initial` (the actor seeds
    /// [`SyncStatus::Idle`], matching the metric's startup value).
    pub fn new(initial: SyncStatus) -> Self {
        Self {
            status: Arc::new(AtomicU8::new(initial as u8)),
        }
    }

    /// Publish the current sync status.
    pub fn set(&self, status: SyncStatus) {
        self.status.store(status as u8, Ordering::Relaxed);
    }

    /// Read the current sync status.
    pub fn get(&self) -> SyncStatus {
        SyncStatus::from_u8(self.status.load(Ordering::Relaxed))
    }
}

impl Default for SyncStatusController {
    fn default() -> Self {
        Self::new(SyncStatus::Idle)
    }
}

/// How far behind a node may fall before it reports itself syncing, per chain.
///
/// The node is syncing only when **both** of these hold:
///
/// - its head trails the wall clock by more than [`Self::clock_lag`], which is
///   local evidence no peer can forge, and
/// - the head its peers report (see `Store::network_head`) is more than
///   [`Self::peer_lead`] slots ahead of its own.
///
/// This is Lighthouse's and Prysm's shape. Lighthouse serves duties unless a
/// range sync is running *and* the head is over `sync_tolerance_epochs` (2)
/// behind the clock, and only a peer more than 32 slots ahead starts a range
/// sync. Prysm resyncs only when the head is two epochs behind the clock *and*
/// peers report a head two epochs ahead. Peers decide between "the network is
/// ahead of me" and "the network is stalled"; the clock keeps a peer's claim
/// from idling a node whose own head is current.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SyncThresholds {
    /// Slots the head may trail the wall clock before the node can be syncing.
    pub(crate) clock_lag: u64,
    /// Slots the peers' head must lead ours before the node can be syncing.
    pub(crate) peer_lead: u64,
    /// Recovery band: once syncing, both lags must drop this many slots below
    /// their thresholds before the node reports synced again, so the status
    /// does not flap at the boundary.
    pub(crate) hysteresis: u64,
    /// Slots after the first tick during which, with no peer having reported a
    /// head yet, the node assumes the network is at the wall clock.
    ///
    /// The first tick runs before any peer has answered a `Status`, so without
    /// this a node resuming a stale database would read "no peer is ahead" as a
    /// stalled network and do its duties on that stale head until the first
    /// handshake lands. Prysm holds a starting node in initial sync until it
    /// has peers; this bounds that hold, so a node that never finds a peer (a
    /// single-node devnet, or one cut off from the start) still falls back to
    /// treating the silence as a stall.
    pub(crate) startup_grace: u64,
}

impl SyncThresholds {
    /// Lean consensus: leanSpec PR #708's lag threshold and hysteresis band,
    /// applied to both conditions, with the stall override replaced by the peer
    /// lead (see `docs/spec_deviations.md`). Lean has no epochs, so neither
    /// client's epoch-sized tolerance carries over.
    pub(crate) const LEAN: Self = Self {
        clock_lag: 4,
        peer_lead: 4,
        hysteresis: 2,
        startup_grace: 8,
    };

    /// The Beacon Chain: Lighthouse's numbers. Two epochs of clock lag
    /// (`DEFAULT_SYNC_TOLERANCE_EPOCHS`, Prysm's `shouldReSync` too) and a peer
    /// lead of one epoch (`SLOT_IMPORT_TOLERANCE`, the lead that makes a
    /// Lighthouse peer `Advanced`). Neither client has a hysteresis band. The
    /// startup hold is an epoch, since finding beacon peers through discovery
    /// can take a while; Prysm holds until it has peers, however long.
    pub(crate) const BEACON: Self = Self {
        clock_lag: 2 * SLOTS_PER_EPOCH,
        peer_lead: SLOTS_PER_EPOCH,
        hysteresis: 0,
        startup_grace: SLOTS_PER_EPOCH,
    };
}

pub(crate) struct SyncStatusTracker {
    syncing: bool,
    /// Whether the syncing state suppresses validator duties.
    ///
    /// When `false`, [`Self::update`] still tracks `syncing` and drives the
    /// `lean_node_sync_status` metric, but [`Self::duties_allowed`] always
    /// returns `true`: the gate is observe-only. Seeded from the CLI
    /// `--disable-duty-sync-gate` flag (gating stays on by default).
    gate_duties: bool,
    thresholds: SyncThresholds,
    /// The slot at which the startup hold ends; set by the first update.
    startup_ends_at: Option<u64>,
    /// Whether any peer has reported a head yet. Once one has, losing every
    /// peer reads as a stall, not as startup.
    heard_from_peers: bool,
}

impl SyncStatusTracker {
    /// Build a tracker, choosing whether the syncing state gates duties.
    pub(crate) fn new(gate_duties: bool, thresholds: SyncThresholds) -> Self {
        Self {
            syncing: false,
            gate_duties,
            thresholds,
            startup_ends_at: None,
            heard_from_peers: false,
        }
    }

    /// Re-judge the status at `current_slot` (the wall clock's slot).
    ///
    /// `network_head` is the head slot the node's peers report, or `None` when
    /// no connected peer has reported one. With no report the node cannot be
    /// behind anyone, so it reads as synced (a stalled or empty network, where
    /// its validators should keep working), except during the startup hold.
    pub(crate) fn update(
        &mut self,
        current_slot: u64,
        head_slot: u64,
        network_head: Option<u64>,
    ) -> SyncStatus {
        let SyncThresholds {
            clock_lag: clock_threshold,
            peer_lead: lead_threshold,
            hysteresis,
            startup_grace,
        } = self.thresholds;
        let startup_ends_at = *self
            .startup_ends_at
            .get_or_insert(current_slot.saturating_add(startup_grace));
        self.heard_from_peers |= network_head.is_some();
        let starting_up = !self.heard_from_peers && current_slot < startup_ends_at;

        // During the startup hold, assume the network is at the clock.
        let network_head = network_head.or(starting_up.then_some(current_slot));
        let clock_lag = current_slot.saturating_sub(head_slot);
        let peer_lead = network_head.map_or(0, |slot| slot.saturating_sub(head_slot));
        let band = if self.syncing { hysteresis } else { 0 };
        let was_syncing = self.syncing;

        self.syncing = clock_lag > clock_threshold.saturating_sub(band)
            && peer_lead > lead_threshold.saturating_sub(band);

        if self.syncing != was_syncing {
            info!(
                current_slot,
                head_slot,
                network_head,
                clock_lag,
                peer_lead,
                starting_up,
                syncing = self.syncing,
                "Sync status changed"
            );
        }

        if self.syncing {
            SyncStatus::Syncing
        } else {
            SyncStatus::Synced
        }
    }

    /// Whether the tracker currently considers the node to be syncing,
    /// regardless of whether that gates duties.
    pub(crate) fn is_syncing(&self) -> bool {
        self.syncing
    }

    pub(crate) fn duties_allowed(&self) -> bool {
        // Gate disabled: the syncing state is observe-only, never suppresses duties.
        !self.gate_duties || !self.syncing
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEAN: SyncThresholds = SyncThresholds::LEAN;

    /// A lean tracker past its startup hold, with peers heard from, so each
    /// test exercises the steady-state rule unless it says otherwise.
    fn steady_lean() -> SyncStatusTracker {
        let mut tracker = SyncStatusTracker::new(true, LEAN);
        tracker.update(0, 0, Some(0));
        tracker
    }

    #[test]
    fn behind_both_the_clock_and_the_peers_is_syncing() {
        let mut tracker = steady_lean();
        // Issue #559: the head is 550 slots back and peers are at the clock.
        assert_eq!(tracker.update(600, 50, Some(600)), SyncStatus::Syncing);
        assert!(!tracker.duties_allowed());
    }

    #[test]
    fn lag_up_to_the_threshold_is_synced() {
        let mut tracker = steady_lean();
        for lag in 0..=LEAN.clock_lag {
            let current = 10 + lag;
            assert_eq!(
                tracker.update(current, 10, Some(current)),
                SyncStatus::Synced
            );
        }
        let current = 10 + LEAN.clock_lag + 1;
        assert_eq!(
            tracker.update(current, 10, Some(current)),
            SyncStatus::Syncing
        );
    }

    #[test]
    fn a_stalled_network_keeps_duties_on_however_long_it_lasts() {
        // Nobody is ahead of us: the network is not producing, so validators
        // keep working to restart it, at any clock lag. leanSpec's
        // `test_network_wide_stall_keeps_duties_live`.
        let mut tracker = steady_lean();
        for current in [10, 50, 1_000] {
            assert_eq!(tracker.update(current, 0, Some(0)), SyncStatus::Synced);
        }
    }

    #[test]
    fn missed_proposals_do_not_close_the_gate() {
        // leanSpec #1194: several empty slots in a row push the clock lag past
        // the threshold on every honest node, but no peer is ahead of any of
        // them, so none stops working.
        let mut tracker = steady_lean();
        assert_eq!(tracker.update(16, 10, Some(10)), SyncStatus::Synced);
        assert_eq!(tracker.update(16, 10, Some(11)), SyncStatus::Synced);
    }

    #[test]
    fn a_peer_ahead_cannot_idle_a_node_at_the_clock() {
        // The clock condition is what bounds a lying peer: our own head is
        // current, so no claimed lead turns duties off.
        let mut tracker = steady_lean();
        assert_eq!(tracker.update(100, 98, Some(500)), SyncStatus::Synced);
    }

    #[test]
    fn losing_every_peer_reads_as_a_stall() {
        let mut tracker = steady_lean();
        assert_eq!(tracker.update(100, 50, Some(100)), SyncStatus::Syncing);
        // Cut off: no peer reports anything any more.
        assert_eq!(tracker.update(120, 50, None), SyncStatus::Synced);
        // Back in touch, still behind.
        assert_eq!(tracker.update(130, 50, Some(130)), SyncStatus::Syncing);
    }

    #[test]
    fn startup_holds_a_stale_node_until_a_peer_reports() {
        let mut tracker = SyncStatusTracker::new(true, LEAN);
        // Resumed 300 slots behind, nobody heard from yet.
        assert_eq!(tracker.update(300, 0, None), SyncStatus::Syncing);
        // The first handshake says the network is with us after all.
        assert_eq!(tracker.update(301, 0, Some(0)), SyncStatus::Synced);
    }

    #[test]
    fn the_startup_hold_ends_without_peers() {
        // A node that never finds a peer stops holding after the grace period
        // and treats the silence as a stall, so a single node still works.
        let mut tracker = SyncStatusTracker::new(true, LEAN);
        assert_eq!(tracker.update(300, 0, None), SyncStatus::Syncing);
        let after_grace = 300 + LEAN.startup_grace;
        assert_eq!(tracker.update(after_grace, 0, None), SyncStatus::Synced);
    }

    #[test]
    fn a_current_node_is_synced_from_the_first_tick() {
        let mut tracker = SyncStatusTracker::new(true, LEAN);
        assert_eq!(tracker.update(300, 299, None), SyncStatus::Synced);
    }

    #[test]
    fn hysteresis_prevents_flapping() {
        let mut tracker = steady_lean();
        assert_eq!(tracker.update(15, 10, Some(15)), SyncStatus::Syncing);
        // Inside the band on both counts: still syncing.
        assert_eq!(tracker.update(15, 12, Some(15)), SyncStatus::Syncing);
        // Below the band on the clock: synced.
        assert_eq!(tracker.update(15, 13, Some(15)), SyncStatus::Synced);
    }

    #[test]
    fn the_beacon_thresholds_are_lighthouses() {
        let mut tracker = SyncStatusTracker::new(true, SyncThresholds::BEACON);
        tracker.update(0, 0, Some(0));
        let epoch = SLOTS_PER_EPOCH;
        // A checkpoint-synced follower 100 slots back with peers at the clock.
        assert_eq!(tracker.update(1_000, 900, Some(1_000)), SyncStatus::Syncing);
        // Within two epochs of the clock, Lighthouse serves duties.
        assert_eq!(
            tracker.update(1_000, 1_000 - 2 * epoch, Some(1_000)),
            SyncStatus::Synced
        );
        // Peers within an epoch of us are not `Advanced`.
        assert_eq!(
            tracker.update(1_000, 900, Some(900 + epoch)),
            SyncStatus::Synced
        );
    }

    #[test]
    fn a_disabled_gate_still_tracks_but_never_blocks() {
        let mut tracker = SyncStatusTracker::new(false, LEAN);
        tracker.update(0, 0, Some(0));
        assert_eq!(tracker.update(600, 50, Some(600)), SyncStatus::Syncing);
        assert!(tracker.is_syncing());
        assert!(tracker.duties_allowed());
    }

    #[test]
    fn a_future_head_saturates_at_zero() {
        let mut tracker = steady_lean();
        assert_eq!(tracker.update(15, 20, Some(20)), SyncStatus::Synced);
    }
}
