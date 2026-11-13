use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

pub(crate) use ethlambda_network_api::sync::SyncThresholds;
use tracing::{info, warn};

use crate::metrics::SyncStatus;

/// Shared, runtime-readable node sync status.
///
/// The blockchain actor is the sole writer: whenever it judges the gate (every
/// tick, every head recompute, and every lean block arrival) it calls
/// [`SyncStatusController::set`] with the same [`SyncStatus`] it feeds the
/// `lean_node_sync_status` metric (see `BlockChainServer::judge_sync_status`).
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

/// The head slot the tracker last saw rise, and the wall-clock slot it rose at.
#[derive(Clone, Copy, Debug)]
struct Progress {
    head_slot: u64,
    at: u64,
}

/// The sync gate: judges, from the clock, the node's own head and the head its
/// peers report, whether the node is too far behind to do validator duties.
/// See [`SyncThresholds`] for the rule and the numbers.
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
    /// How many connected peers last reported a head; see
    /// [`Self::note_reporting_peers`].
    reporting_peers: usize,
    /// Whether [`SyncThresholds::startup_peers`] peers have reported, which
    /// ends the startup hold for good: peers dropping off afterwards make the
    /// view thinner, not the assumption true again.
    heard_from_peers: bool,
    /// When the head last advanced; set by the first update.
    progress: Option<Progress>,
    /// The wall-clock slot from which the node has been behind both the clock
    /// and its peers, while it still is.
    behind_since: Option<u64>,
    /// The head slot at which a peer-reported lead was given up on for making
    /// no progress (see [`SyncThresholds::stall_window`]). Holds the node
    /// synced until the head moves past it: the peers that claimed the lead
    /// repeat it on every refresh, so a fresh report is no reason to believe
    /// them again.
    stalled_at_head: Option<u64>,
}

impl SyncStatusTracker {
    /// Build a tracker, choosing whether the syncing state gates duties.
    pub(crate) fn new(gate_duties: bool, thresholds: SyncThresholds) -> Self {
        Self {
            syncing: false,
            gate_duties,
            thresholds,
            startup_ends_at: None,
            reporting_peers: 0,
            heard_from_peers: false,
            progress: None,
            behind_since: None,
            stalled_at_head: None,
        }
    }

    /// Note how many connected peers have reported a `Status` head, counting
    /// those this node already holds (`PeerView::reporting_peers`). Read by
    /// the next judgment, which ends the startup hold once it reaches
    /// [`SyncThresholds::startup_peers`].
    pub(crate) fn note_reporting_peers(&mut self, reporting_peers: usize) {
        self.reporting_peers = reporting_peers;
    }

    /// Re-judge the status at `current_slot` (the wall clock's slot).
    ///
    /// `network_head` is the highest head the node's peers report that it
    /// does not already hold, or `None` when no connected peer reports one.
    /// With no report the node cannot be behind anyone, so it reads as synced
    /// (a stalled or empty network, where its validators should keep
    /// working), except during the startup hold, which assumes the network is
    /// at least at the clock until [`SyncThresholds::startup_peers`] peers
    /// have reported or [`SyncThresholds::startup_grace`] slots have passed.
    pub(crate) fn update(
        &mut self,
        current_slot: u64,
        head_slot: u64,
        network_head: Option<u64>,
    ) -> SyncStatus {
        self.judge(current_slot, head_slot, network_head, false)
    }

    /// [`Self::update`] for a node that knows the network is at least at the
    /// clock without any peer saying so: a beacon follower whose clock is past
    /// a fork it does not follow (`clock_is_past_followed_forks`). Exempt from
    /// the stall backstop like the startup hold is, since the head of a node
    /// that cannot follow the fork never advances, and that is the point.
    pub(crate) fn update_with_network_at_clock(
        &mut self,
        current_slot: u64,
        head_slot: u64,
    ) -> SyncStatus {
        self.judge(current_slot, head_slot, None, true)
    }

    fn judge(
        &mut self,
        current_slot: u64,
        head_slot: u64,
        network_head: Option<u64>,
        network_at_clock: bool,
    ) -> SyncStatus {
        let SyncThresholds {
            clock_lag: clock_threshold,
            peer_lead: lead_threshold,
            hysteresis,
            startup_grace,
            startup_peers,
            stall_window,
            ..
        } = self.thresholds;
        let startup_ends_at = *self
            .startup_ends_at
            .get_or_insert(current_slot.saturating_add(startup_grace));
        if !self.heard_from_peers && self.reporting_peers >= startup_peers {
            self.heard_from_peers = true;
            if current_slot < startup_ends_at {
                info!(
                    current_slot,
                    head_slot,
                    network_head,
                    reporting_peers = self.reporting_peers,
                    "Enough peers have reported; ending the startup hold early"
                );
            }
        }
        let starting_up = !self.heard_from_peers && current_slot < startup_ends_at;

        let progress = self.progress.get_or_insert(Progress {
            head_slot,
            at: current_slot,
        });
        if head_slot > progress.head_slot {
            *progress = Progress {
                head_slot,
                at: current_slot,
            };
        } else if head_slot < progress.head_slot {
            // The head moved back (an `INVALID` execution verdict cutting a
            // branch out): progress is measured from where it now is, or the
            // re-imports below the old mark would not count. Moving back is
            // not itself progress, so `at` stays.
            progress.head_slot = head_slot;
        }
        let progress = *progress;
        match self.stalled_at_head {
            Some(stalled) if head_slot > stalled => self.stalled_at_head = None,
            // Same for a head that moved back below where the lead was given
            // up on: the next advance from there releases it.
            Some(stalled) if head_slot < stalled => self.stalled_at_head = Some(head_slot),
            _ => {}
        }

        // During the startup hold, assume the network is at least at the
        // clock: a report can add lead, never take it away, since the first
        // peer to answer may be as stale as we are. Enough of them reporting
        // ends the hold (see above); one does not.
        let assumed = starting_up || network_at_clock;
        let network_head = if assumed {
            Some(network_head.map_or(current_slot, |slot| slot.max(current_slot)))
        } else {
            network_head
        };
        let clock_lag = current_slot.saturating_sub(head_slot);
        let peer_lead = network_head.map_or(0, |slot| slot.saturating_sub(head_slot));
        let band = if self.syncing { hysteresis } else { 0 };
        let behind = clock_lag > clock_threshold.saturating_sub(band)
            && peer_lead > lead_threshold.saturating_sub(band);
        // Counted only while behind on the peers' word: time spent behind on
        // an assumption (the startup hold) must not use up the window, or a
        // node whose first peer answers late in the hold would give up on it
        // before its first range batch could land.
        let behind_since = if behind && !assumed {
            *self.behind_since.get_or_insert(current_slot)
        } else {
            self.behind_since = None;
            current_slot
        };

        // The backstop: behind on the peers' word alone (the startup hold has
        // its own bound), with the head flat for a whole window since the
        // node fell behind on that word or last advanced. Whoever claims the
        // lead is not delivering it, which is what a stalled network looks
        // like too.
        let flat_for = current_slot.saturating_sub(behind_since.max(progress.at));
        if behind && !assumed && self.stalled_at_head.is_none() && flat_for > stall_window {
            warn!(
                current_slot,
                head_slot,
                network_head,
                flat_for,
                "Peers report a head this node is not reaching; treating the network as stalled"
            );
            self.stalled_at_head = Some(head_slot);
        }

        let was_syncing = self.syncing;
        self.syncing = behind && (assumed || self.stalled_at_head.is_none());

        if self.syncing != was_syncing {
            info!(
                current_slot,
                head_slot,
                network_head,
                clock_lag,
                peer_lead,
                starting_up,
                stalled = self.stalled_at_head.is_some(),
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
    use ethlambda_types::beacon::preset::SLOTS_PER_EPOCH;

    use super::*;

    const LEAN: SyncThresholds = SyncThresholds::LEAN;
    const BEACON: SyncThresholds = SyncThresholds::BEACON;

    /// A tracker past its startup hold, with the head at genesis and every
    /// peer with it, so each test exercises the steady-state rule unless it
    /// says otherwise.
    fn steady(thresholds: SyncThresholds) -> SyncStatusTracker {
        let mut tracker = SyncStatusTracker::new(true, thresholds);
        tracker.update(0, 0, Some(0));
        tracker.update(thresholds.startup_grace, 0, Some(0));
        tracker
    }

    fn steady_lean() -> SyncStatusTracker {
        steady(LEAN)
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
    fn a_refresh_old_report_still_shows_a_node_past_the_clock_threshold() {
        // Finding: a lean report is up to `status_refresh_slots` old. A node
        // just past the clock threshold, whose peers were a slot behind the
        // clock when they last reported, must still read as behind them.
        let mut tracker = steady_lean();
        let current = 100;
        let head = current - LEAN.clock_lag - 1;
        let stale_report = current - 1 - LEAN.status_refresh_slots;
        assert_eq!(
            tracker.update(current, head, Some(stale_report)),
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
        // them by more than propagation, so none stops working.
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
    fn a_lead_that_never_turns_into_progress_is_a_stall() {
        // A peer claims a head it does not serve (an empty answer, invalid
        // blocks, no answer) while the network is stalled with us behind the
        // clock. It costs one stall window, not the rest of the stall.
        let mut tracker = steady_lean();
        assert_eq!(tracker.update(100, 50, Some(100)), SyncStatus::Syncing);
        let last_syncing = 100 + LEAN.stall_window;
        assert_eq!(
            tracker.update(last_syncing, 50, Some(last_syncing)),
            SyncStatus::Syncing
        );
        assert_eq!(
            tracker.update(last_syncing + 1, 50, Some(last_syncing + 1)),
            SyncStatus::Synced
        );
        assert!(tracker.duties_allowed());
        // The claim keeps coming on every refresh; it is not believed again
        // while the head stays where it was given up on.
        assert_eq!(tracker.update(500, 50, Some(500)), SyncStatus::Synced);
    }

    #[test]
    fn steady_progress_keeps_a_long_catch_up_syncing() {
        // A slow catch-up advancing a slot every few, far behind peers at the
        // clock, never trips the backstop.
        let mut tracker = steady_lean();
        for current in 100..400 {
            let head = 50 + (current - 100) / 4;
            assert_eq!(
                tracker.update(current, head, Some(current)),
                SyncStatus::Syncing,
                "slot {current}"
            );
        }
    }

    #[test]
    fn a_head_advance_after_a_trip_re_arms_the_gate() {
        let mut tracker = steady_lean();
        tracker.update(100, 50, Some(100));
        let tripped = 101 + LEAN.stall_window;
        assert_eq!(
            tracker.update(tripped, 50, Some(tripped)),
            SyncStatus::Synced
        );
        // A block lands but leaves the node behind: the peers were right
        // after all, and the window starts over from the advance.
        assert_eq!(
            tracker.update(tripped + 1, 51, Some(tripped + 1)),
            SyncStatus::Syncing
        );
        let end = tripped + 1 + LEAN.stall_window;
        assert_eq!(tracker.update(end, 51, Some(end)), SyncStatus::Syncing);
        assert_eq!(
            tracker.update(end + 1, 51, Some(end + 1)),
            SyncStatus::Synced
        );
    }

    #[test]
    fn the_backstop_does_not_shorten_the_startup_hold() {
        // A stall window shorter than the hold: the head stays flat through
        // the whole hold, and the node holds for all of it.
        let thresholds = SyncThresholds {
            stall_window: 2,
            ..LEAN
        };
        let mut tracker = SyncStatusTracker::new(true, thresholds);
        for current in 300..300 + LEAN.startup_grace {
            assert_eq!(
                tracker.update(current, 0, None),
                SyncStatus::Syncing,
                "slot {current}"
            );
        }
    }

    #[test]
    fn a_report_late_in_the_startup_hold_still_gets_a_whole_stall_window() {
        // A beacon node resumed 100 slots behind finds its first peer only in
        // the hold's last slot. The window the head has to start moving in
        // runs from the end of the hold, not from startup: the hold and the
        // window are both an epoch, so counting from startup would give the
        // first range batch no time at all.
        let mut tracker = SyncStatusTracker::new(true, BEACON);
        let start = 1_000;
        let head = start - 100;
        let hold_ends = start + BEACON.startup_grace;
        for current in start..hold_ends - 1 {
            assert_eq!(tracker.update(current, head, None), SyncStatus::Syncing);
        }
        let last_held = hold_ends - 1;
        assert_eq!(
            tracker.update(last_held, head, Some(last_held)),
            SyncStatus::Syncing
        );
        let window_end = hold_ends + BEACON.stall_window;
        for current in hold_ends..=window_end {
            assert_eq!(
                tracker.update(current, head, Some(current)),
                SyncStatus::Syncing,
                "slot {current}"
            );
        }
    }

    #[test]
    fn a_head_that_moves_back_and_climbs_again_is_progress() {
        // An `INVALID` execution verdict moves the head back. Re-importing
        // from there is progress even while still below the old head.
        let mut tracker = steady_lean();
        assert_eq!(tracker.update(100, 60, Some(100)), SyncStatus::Syncing);
        assert_eq!(tracker.update(105, 50, Some(105)), SyncStatus::Syncing);
        assert_eq!(tracker.update(110, 51, Some(110)), SyncStatus::Syncing);
        let past_the_old_window = 101 + LEAN.stall_window;
        assert_eq!(
            tracker.update(past_the_old_window, 51, Some(past_the_old_window)),
            SyncStatus::Syncing
        );
    }

    #[test]
    fn a_network_known_to_be_at_the_clock_is_not_a_stall() {
        // Past a fork the node cannot follow, the head never advances again;
        // that must not read as a stall the way an unserved claim does.
        let mut tracker = steady_lean();
        for current in [100, 100 + LEAN.stall_window + 1, 1_000] {
            assert_eq!(
                tracker.update_with_network_at_clock(current, 50),
                SyncStatus::Syncing,
                "slot {current}"
            );
        }
    }

    #[test]
    fn startup_holds_a_stale_node_without_peers() {
        let mut tracker = SyncStatusTracker::new(true, LEAN);
        // Resumed 300 slots behind, nobody heard from yet.
        assert_eq!(tracker.update(300, 0, None), SyncStatus::Syncing);
    }

    #[test]
    fn a_stale_first_report_does_not_end_the_startup_hold() {
        // Finding: the first peer to answer may be as stale as we are, or
        // still syncing itself. Its report can only add lead during the hold.
        let mut tracker = SyncStatusTracker::new(true, LEAN);
        assert_eq!(tracker.update(300, 0, None), SyncStatus::Syncing);
        assert_eq!(tracker.update(301, 0, Some(0)), SyncStatus::Syncing);
        // Once the hold is over, the same report reads as a stall.
        let after_grace = 300 + LEAN.startup_grace;
        assert_eq!(tracker.update(after_grace, 0, Some(0)), SyncStatus::Synced);
    }

    #[test]
    fn enough_reporting_peers_end_the_startup_hold() {
        // A slow network start, not a stale node: ten slots behind the clock
        // inside the hold, with every peer level with us (their heads are
        // ones we hold, so there is no network head). One short of the count
        // keeps the hold; reaching it lets the peers' word stand.
        let mut tracker = SyncStatusTracker::new(true, LEAN);
        assert_eq!(tracker.update(300, 290, None), SyncStatus::Syncing);
        tracker.note_reporting_peers(LEAN.startup_peers - 1);
        assert_eq!(tracker.update(301, 290, None), SyncStatus::Syncing);
        tracker.note_reporting_peers(LEAN.startup_peers);
        assert_eq!(tracker.update(302, 290, None), SyncStatus::Synced);
    }

    #[test]
    fn the_startup_hold_stays_over_once_enough_peers_reported() {
        let mut tracker = SyncStatusTracker::new(true, LEAN);
        tracker.note_reporting_peers(LEAN.startup_peers);
        assert_eq!(tracker.update(300, 290, None), SyncStatus::Synced);
        // Peers dropping off thin the view; they do not bring the hold back.
        tracker.note_reporting_peers(1);
        assert_eq!(tracker.update(301, 290, None), SyncStatus::Synced);
    }

    #[test]
    fn one_current_peer_among_the_reporters_still_shows_the_lead() {
        // The hold is over, but a stale node is still caught: the highest
        // report is the network head, so one current peer among the five is
        // enough.
        let mut tracker = SyncStatusTracker::new(true, BEACON);
        tracker.note_reporting_peers(BEACON.startup_peers);
        assert_eq!(tracker.update(1000, 100, Some(999)), SyncStatus::Syncing);
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
        let epoch = SLOTS_PER_EPOCH;
        // A checkpoint-synced follower 100 slots back with peers at the clock.
        assert_eq!(
            steady(BEACON).update(1_000, 900, Some(1_000)),
            SyncStatus::Syncing
        );
        // Within two epochs of the clock, Lighthouse serves duties.
        assert_eq!(
            steady(BEACON).update(1_000, 1_000 - 2 * epoch, Some(1_000)),
            SyncStatus::Synced
        );
        // Peers within an epoch of us are not `Advanced`.
        assert_eq!(
            steady(BEACON).update(1_000, 900, Some(900 + epoch)),
            SyncStatus::Synced
        );
    }

    #[test]
    fn a_beacon_follower_at_the_clock_threshold_does_not_flap() {
        // Finding: importing about a block a slot right at the two-epoch
        // boundary, the lag alternates between just over and just at the
        // threshold, once per tick and once per arrival.
        let mut tracker = steady(BEACON);
        let boundary = BEACON.clock_lag;
        let mut head = 1_000 - boundary - 1;
        assert_eq!(
            tracker.update(1_000, head, Some(1_000)),
            SyncStatus::Syncing
        );
        for current in 1_000..1_100 {
            // An arrival brings the lag back down to the threshold...
            head += 1;
            assert_eq!(
                tracker.update(current, head, Some(current)),
                SyncStatus::Syncing,
                "arrival at slot {current}"
            );
            // ...and the next tick pushes it over again.
            assert_eq!(
                tracker.update(current + 1, head, Some(current + 1)),
                SyncStatus::Syncing,
                "tick at slot {}",
                current + 1
            );
        }
        // Gaining on the clock by the band releases it.
        let current = 1_100;
        let caught_up = current - (boundary - BEACON.hysteresis);
        assert_eq!(
            tracker.update(current, caught_up, Some(current)),
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
