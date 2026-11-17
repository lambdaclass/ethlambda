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
    /// The head slot progress is measured from: the highest the head has
    /// reached, or where it last moved back to. Set by the first update.
    progress_head: Option<u64>,
    /// Slots the node has spent behind on its peers' word since its head last
    /// advanced, measured against [`SyncThresholds::stall_window`].
    ///
    /// Added up rather than measured from when the node last fell behind: a
    /// claim that lapses for a moment (a peer reporting a block this node
    /// holds, a reconnect) would otherwise restart the window, and a peer
    /// doing that every few slots could keep the node idle indefinitely. A
    /// stretch behind counts in full; a slot reached after a lapse counts
    /// once, so a lapse at every slot boundary pauses nothing.
    behind_for: u64,
    /// The wall-clock slot of the last judgment that found the node behind on
    /// its peers' word, already counted into [`Self::behind_for`].
    counted_at: Option<u64>,
    /// The wall-clock slot from which no judgment has found the node behind
    /// on its peers' word, while that lasts. A lapse longer than the stall
    /// window (an outage, peers that stopped claiming) ends the count: the
    /// next claim gets a window of its own, once per head position.
    lapsed_at: Option<u64>,
    /// Whether a claim after a long lapse has already had a fresh window at
    /// the current head. Once per head position, so that claiming for most
    /// of a window, lapsing for a whole one and claiming again cannot keep
    /// a node idle for half of all slots indefinitely.
    renewed: bool,
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
            progress_head: None,
            behind_for: 0,
            counted_at: None,
            lapsed_at: None,
            renewed: false,
            stalled_at_head: None,
        }
    }

    /// Re-judge the status at `current_slot` (the wall clock's slot).
    ///
    /// `network_head` is the highest head the node's peers report that it
    /// does not already hold, or `None` when no connected peer reports one.
    /// With no report the node cannot be behind anyone, so it reads as synced
    /// (a stalled or empty network, where its validators should keep
    /// working), from the first judgment on.
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
    /// the stall backstop, since the head of a node that cannot follow the
    /// fork never advances, and that is the point.
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
            stall_window,
            ..
        } = self.thresholds;

        let progress_head = *self.progress_head.get_or_insert(head_slot);
        if head_slot > progress_head {
            self.progress_head = Some(head_slot);
            self.behind_for = 0;
            self.counted_at = None;
            self.lapsed_at = None;
            self.renewed = false;
        } else if head_slot < progress_head {
            // The head moved back (an `INVALID` execution verdict cutting a
            // branch out, a reorg onto a shorter branch). The peers may have
            // been right about the chain all along, so the stall window starts
            // over and a lead given up on is believed again, as after an
            // advance; progress is measured from where the head now is, or
            // the re-imports below the old mark would not count. Only fork
            // choice moves the head, so no peer can do this to the node.
            self.progress_head = Some(head_slot);
            self.behind_for = 0;
            self.counted_at = None;
            self.lapsed_at = None;
            self.renewed = false;
            self.stalled_at_head = None;
        }
        if self
            .stalled_at_head
            .is_some_and(|stalled| head_slot > stalled)
        {
            self.stalled_at_head = None;
        }

        let network_head = if network_at_clock {
            Some(current_slot)
        } else {
            network_head
        };
        let clock_lag = current_slot.saturating_sub(head_slot);
        let peer_lead = network_head.map_or(0, |slot| slot.saturating_sub(head_slot));
        let band = if self.syncing { hysteresis } else { 0 };
        // The band never takes the lead below a slot: a peer one slot ahead is
        // ordinary propagation, and on lean, whose lead threshold is one, the
        // band would otherwise keep a node syncing on any peer a slot ahead of
        // it, such as one holding an orphaned block.
        let lead_floor = lead_threshold
            .saturating_sub(band)
            .max(lead_threshold.min(1));
        let behind = clock_lag > clock_threshold.saturating_sub(band) && peer_lead > lead_floor;

        // Counted only while behind on the peers' word: behind on the clock's
        // word (past a fork the node does not follow) is no claim that a peer
        // can fail to deliver.
        let on_peers_word = behind && !network_at_clock;
        if on_peers_word {
            self.behind_for = match (self.counted_at, self.lapsed_at.take()) {
                // Behind since the last judgment: the whole stretch counts.
                (Some(counted), None) => self.behind_for + current_slot.saturating_sub(counted),
                // Back after a lapse longer than the window: a new claim,
                // with a window of its own, once per head position. Only
                // once something was counted at this head: the first claim
                // after a quiet stretch starts from zero anyway, and must not
                // use up the renewal an outage later would need.
                (Some(_), Some(lapsed))
                    if !self.renewed && current_slot.saturating_sub(lapsed) > stall_window =>
                {
                    self.renewed = true;
                    0
                }
                // Back after a shorter lapse: this slot counts once, however
                // many judgments it has.
                (Some(counted), Some(_)) => self.behind_for + u64::from(current_slot != counted),
                // Behind for the first time since the head advanced.
                (None, _) => self.behind_for,
            };
            self.counted_at = Some(current_slot);
        } else {
            self.lapsed_at.get_or_insert(current_slot);
        }

        // The backstop: behind on the peers' word for a whole window, all of
        // it with the head flat. Whoever claims the lead is not delivering it,
        // which is what a stalled network looks like too.
        let behind_for = self.behind_for;
        if on_peers_word && self.stalled_at_head.is_none() && behind_for > stall_window {
            warn!(
                current_slot,
                head_slot,
                network_head,
                behind_for,
                "Peers report a head this node is not reaching; treating the network as stalled"
            );
            self.stalled_at_head = Some(head_slot);
        }

        let was_syncing = self.syncing;
        self.syncing = behind && (network_at_clock || self.stalled_at_head.is_none());

        if self.syncing != was_syncing {
            info!(
                current_slot,
                head_slot,
                network_head,
                clock_lag,
                peer_lead,
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

    /// A tracker that has judged once, at genesis with every peer there too.
    fn steady(thresholds: SyncThresholds) -> SyncStatusTracker {
        let mut tracker = SyncStatusTracker::new(true, thresholds);
        tracker.update(0, 0, Some(0));
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
    fn a_late_first_report_still_gets_a_whole_stall_window() {
        // A beacon node resumed 100 slots behind finds its first peer two
        // epochs after startup, its head flat all along. The window the head
        // has to start moving in runs from that report, not from startup, or
        // the first range batch would get no time at all.
        let mut tracker = SyncStatusTracker::new(true, BEACON);
        let start = 1_000;
        let head = start - 100;
        let first_report = start + 2 * BEACON.stall_window;
        for current in start..first_report {
            assert_eq!(tracker.update(current, head, None), SyncStatus::Synced);
        }
        let window_end = first_report + BEACON.stall_window;
        for current in first_report..=window_end {
            assert_eq!(
                tracker.update(current, head, Some(current)),
                SyncStatus::Syncing,
                "slot {current}"
            );
        }
        assert_eq!(
            tracker.update(window_end + 1, head, Some(window_end + 1)),
            SyncStatus::Synced
        );
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
    fn a_head_that_moves_back_after_a_stall_is_judged_afresh() {
        // Finding: after an `INVALID` verdict cut the branch out, the stall
        // stayed, and the node kept its duties on peers that may well have
        // been right.
        let mut tracker = steady_lean();
        assert_eq!(tracker.update(100, 60, Some(100)), SyncStatus::Syncing);
        let tripped = 101 + LEAN.stall_window;
        assert_eq!(
            tracker.update(tripped, 60, Some(tripped)),
            SyncStatus::Synced
        );
        assert_eq!(
            tracker.update(tripped + 1, 55, Some(tripped + 1)),
            SyncStatus::Syncing
        );
        // And gets a whole window from there.
        let end = tripped + 1 + LEAN.stall_window;
        assert_eq!(tracker.update(end, 55, Some(end)), SyncStatus::Syncing);
        assert_eq!(
            tracker.update(end + 1, 55, Some(end + 1)),
            SyncStatus::Synced
        );
    }

    #[test]
    fn a_network_known_to_be_at_the_clock_is_not_a_stall() {
        // Past a fork the node cannot follow, the head never advances again;
        // that must not read as a stall the way an unserved claim does. The
        // clock is the evidence here, so it counts from the first judgment.
        let mut tracker = SyncStatusTracker::new(true, LEAN);
        for current in [100, 100 + LEAN.stall_window + 1, 1_000] {
            assert_eq!(
                tracker.update_with_network_at_clock(current, 50),
                SyncStatus::Syncing,
                "slot {current}"
            );
        }
    }

    #[test]
    fn a_stale_node_keeps_its_duties_until_a_peer_shows_a_lead() {
        // Resumed 300 slots behind. Like Lighthouse's initial `Stalled`, the
        // clock alone does not stop duties: if every node is behind it at
        // once, assuming the network is at the clock would idle all of them.
        let mut tracker = SyncStatusTracker::new(true, LEAN);
        assert_eq!(tracker.update(300, 0, None), SyncStatus::Synced);
        assert!(tracker.duties_allowed());
        // The first peer to answer is as stale as we are: still no lead.
        assert_eq!(tracker.update(301, 0, Some(0)), SyncStatus::Synced);
        // A peer at the clock shows the lead, and duties stop at once.
        assert_eq!(tracker.update(302, 0, Some(302)), SyncStatus::Syncing);
        assert!(!tracker.duties_allowed());
    }

    #[test]
    fn a_current_node_is_synced_from_the_first_tick() {
        let mut tracker = SyncStatusTracker::new(true, LEAN);
        assert_eq!(tracker.update(300, 299, None), SyncStatus::Synced);
    }

    #[test]
    fn a_lead_that_lapses_now_and_then_does_not_restart_the_stall_window() {
        // Finding: a single judgment without the lead (the claiming peer
        // reporting a block we hold, or reconnecting) restarted the window,
        // so a peer doing that every few slots kept the node idle for good.
        let mut tracker = steady_lean();
        let start = 100;
        assert_eq!(tracker.update(start, 50, Some(start)), SyncStatus::Syncing);
        let lapse_every = LEAN.stall_window / 2;
        let give_up_by = start + 2 * LEAN.stall_window;
        let mut gave_up = false;
        for current in start + 1..=give_up_by {
            let claim = if current % lapse_every == 0 {
                Some(50)
            } else {
                Some(current)
            };
            let status = tracker.update(current, 50, claim);
            gave_up |= claim == Some(current) && status == SyncStatus::Synced;
        }
        assert!(gave_up, "the window never ran out");
        // Given up on, the claim is not believed again while the head is flat.
        let next = give_up_by + 1;
        assert_eq!(tracker.update(next, 50, Some(next)), SyncStatus::Synced);
    }

    #[test]
    fn a_lead_that_lapses_at_every_slot_boundary_still_runs_out() {
        // Finding: a lapse discarded the stretch on either side of it, so a
        // claim dropped just before each slot's first judgment and made again
        // before its second kept the count at zero. Lean is judged several
        // times a slot, and only some of those judgments gate duties.
        let mut tracker = steady_lean();
        assert_eq!(tracker.update(100, 50, Some(100)), SyncStatus::Syncing);
        let mut gave_up_at = None;
        for current in 101..=100 + 2 * LEAN.stall_window {
            tracker.update(current, 50, Some(50));
            if tracker.update(current, 50, Some(current)) == SyncStatus::Synced {
                gave_up_at.get_or_insert(current);
            }
        }
        assert_eq!(gave_up_at, Some(101 + LEAN.stall_window));

        // Beacon is judged about once a slot: a claim made every other slot
        // stretches the window to twice its length, no more.
        let mut tracker = steady(BEACON);
        assert_eq!(tracker.update(1_000, 900, Some(1_000)), SyncStatus::Syncing);
        let mut gave_up_at = None;
        for current in 1_001..=1_000 + 3 * BEACON.stall_window {
            let claim = (current % 2 == 1).then_some(current);
            let status = tracker.update(current, 900, claim.or(Some(900)));
            if claim.is_some() && status == SyncStatus::Synced {
                gave_up_at.get_or_insert(current);
            }
        }
        let gave_up_at = gave_up_at.expect("the window ran out");
        assert!(
            gave_up_at <= 1_002 + 2 * BEACON.stall_window,
            "{gave_up_at}"
        );
    }

    #[test]
    fn a_claim_back_after_a_long_lapse_gets_a_whole_window() {
        // Finding: time counted before an outage carried over, so a node that
        // reconnected after hours gave up on its peers' lead a slot later,
        // before its first range batch could land.
        let mut tracker = steady_lean();
        // A quiet stretch first, longer than a window, at the same head: the
        // first claim after it must not use up the renewal.
        assert_eq!(tracker.update(80, 50, None), SyncStatus::Synced);
        assert_eq!(tracker.update(100, 50, Some(100)), SyncStatus::Syncing);
        for current in 101..=110 {
            assert_eq!(
                tracker.update(current, 50, Some(current)),
                SyncStatus::Syncing
            );
        }
        // Cut off, head flat, for far longer than a window.
        assert_eq!(tracker.update(111, 50, None), SyncStatus::Synced);
        assert_eq!(tracker.update(300, 50, None), SyncStatus::Synced);
        let back = 301;
        for current in back..=back + LEAN.stall_window {
            assert_eq!(
                tracker.update(current, 50, Some(current)),
                SyncStatus::Syncing,
                "slot {current}"
            );
        }
        let past = back + LEAN.stall_window + 1;
        assert_eq!(tracker.update(past, 50, Some(past)), SyncStatus::Synced);
    }

    #[test]
    fn a_fresh_window_after_a_long_lapse_comes_once_per_head() {
        // Finding: claiming for most of a window, lapsing for a whole one
        // and claiming again got a fresh window every time, so the node sat
        // idle for about half of all slots, indefinitely.
        let mut tracker = steady_lean();
        let window = LEAN.stall_window;
        let mut current = 100;
        let mut idle = 0;
        for _ in 0..10 {
            for _ in 0..window {
                if tracker.update(current, 50, Some(current)) == SyncStatus::Syncing {
                    idle += 1;
                }
                current += 1;
            }
            for _ in 0..=window {
                tracker.update(current, 50, None);
                current += 1;
            }
        }
        // The first window, one renewal, and a slot each for the claims that
        // trip it: bounded, however many rounds.
        assert!(idle <= 2 * window + 2, "idle for {idle} slots");
        // A head advance gives the next claim its own window again.
        assert_eq!(
            tracker.update(current, 51, Some(current)),
            SyncStatus::Syncing
        );
    }

    #[test]
    fn the_band_never_takes_the_lead_below_a_slot() {
        // Finding: on lean (lead threshold 1, band 2) a node already syncing
        // stayed syncing on a peer one slot ahead. Here it has caught up to
        // the network's head at 10 during a run of missed proposals, and one
        // peer holds an orphan at 11 that nobody built on.
        let mut tracker = steady_lean();
        assert_eq!(tracker.update(16, 5, Some(16)), SyncStatus::Syncing);
        assert_eq!(tracker.update(16, 10, Some(11)), SyncStatus::Synced);
        // Two slots ahead is still a lead.
        assert_eq!(tracker.update(16, 10, Some(12)), SyncStatus::Syncing);
        // The beacon band is unaffected: 32 - 4 slots of lead keep it syncing.
        let mut beacon = steady(BEACON);
        assert_eq!(beacon.update(1_000, 900, Some(1_000)), SyncStatus::Syncing);
        let lead = BEACON.peer_lead - BEACON.hysteresis + 1;
        assert_eq!(
            beacon.update(1_000, 900, Some(900 + lead)),
            SyncStatus::Syncing
        );
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
