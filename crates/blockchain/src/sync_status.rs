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
///
/// How the stall window is kept, in short:
///
/// | event | effect |
/// |---|---|
/// | head advances past `high_water` | progress: window starts over, stall released |
/// | head climbs past the highest reached since a move back (`climb`) | progress, likewise |
/// | first move back below a high-water mark, or (once per mark) a new low below the climb's | window starts over, stall released |
/// | a judgment behind on the peers' word | slots added to the count (`StallCount`): a stretch in full up to half a window (a longer gap between judgments is a pause), a slot after a short lapse once |
/// | a claim after a lapse longer than the window, with something counted | count back to zero, once per count (`renewed`) |
/// | the count past the window | stall: synced until progress |
/// | a judgment more than half a window older than the last | the wall clock stepped back: the count's slots move back with it |
///
/// With the head flat, no schedule of claims and lapses keeps the node
/// syncing for more than about two windows' worth of slots at one head:
/// `no_claim_schedule_idles_a_flat_head_past_two_windows` checks that.
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
    /// The latest wall-clock slot judged at. A judgment carrying an older one,
    /// by up to half a window, is judged at this one, so time never runs
    /// backwards between judgments whatever clock a caller reads. One further
    /// back is the wall clock stepping back, and moves this back with it.
    last_slot: u64,
    /// The highest head reached since the stall window last started over.
    /// Only an advance past it is progress. Set by the first update.
    high_water: Option<u64>,
    /// The head at the last judgment, to tell a move back.
    last_head: Option<u64>,
    /// After the head moved back below [`Self::high_water`], while it has not
    /// yet climbed past it. Climbing past the highest head reached since is
    /// progress (a branch being re-imported after an `INVALID` cut), and so,
    /// once per mark, is a new low (a deeper cut); a later new low only lowers
    /// the floor. A head flipping between two branches, or stepping down a
    /// slot at a time, therefore restarts the window a bounded number of
    /// times per mark.
    climb: Option<Climb>,
    /// The stall window's count at the current head position.
    stall: StallCount,
    /// Whether a peer-reported lead was given up on for making no progress
    /// (see [`SyncThresholds::stall_window`]). Holds the node synced until
    /// the head makes progress: the peers that claimed the lead repeat it on
    /// every refresh, so a fresh report is no reason to believe them again.
    stalled: bool,
}

/// The head's course since it moved back below the high-water mark; see
/// `SyncStatusTracker::climb`.
#[derive(Debug, Clone, Copy)]
struct Climb {
    /// The lowest head reached since the move back.
    low: u64,
    /// The highest head reached since the move back, or since the deeper cut.
    high: u64,
    /// Whether a deeper cut has already started the window over at this mark.
    deeper_cut: bool,
}

/// How long the node has been behind on its peers' word with its head making
/// no progress, measured against [`SyncThresholds::stall_window`]. Starts
/// over (`Default`) whenever the head makes progress.
///
/// Invariants: `counted_at` is `None` only while nothing was judged behind
/// since the count started, and `behind_for` is then zero; `lapsed_at` is
/// `Some` only while the latest judgment was not behind on the peers' word
/// (it may have been on the clock's), and the next judgment that is takes it.
#[derive(Debug, Default)]
struct StallCount {
    /// Slots counted so far.
    ///
    /// Added up rather than measured from when the node last fell behind: a
    /// claim that lapses for a moment (a peer reporting a block this node
    /// holds, a reconnect) would otherwise restart the window, and a peer
    /// doing that every few slots could keep the node idle indefinitely. A
    /// stretch behind counts in full, up to half a window per judgment; a
    /// slot reached after a lapse counts once, so a lapse at every slot
    /// boundary pauses nothing.
    behind_for: u64,
    /// The wall-clock slot of the last judgment that found the node behind on
    /// its peers' word, already counted into `behind_for`.
    counted_at: Option<u64>,
    /// The wall-clock slot from which no judgment has found the node behind
    /// on its peers' word, while that lasts. A lapse longer than the window
    /// (an outage, peers that stopped claiming) ends the count: the next
    /// claim gets a window of its own, once per count.
    lapsed_at: Option<u64>,
    /// Whether a claim after a long lapse has already had a fresh window in
    /// this count. Once per count, so that claiming for most of a window,
    /// lapsing for a whole one and claiming again cannot keep a node idle for
    /// half of all slots indefinitely.
    renewed: bool,
}

impl StallCount {
    /// Most slots one judgment adds: half the window, and at least one.
    fn max_stretch(stall_window: u64) -> u64 {
        (stall_window / 2).max(1)
    }

    /// Note a judgment at `current_slot`, behind on the peers' word or not,
    /// and return the slots counted so far.
    fn count(&mut self, current_slot: u64, on_peers_word: bool, stall_window: u64) -> u64 {
        if !on_peers_word {
            self.lapsed_at.get_or_insert(current_slot);
            return self.behind_for;
        }
        self.behind_for = match (self.counted_at, self.lapsed_at.take()) {
            // Behind since the last judgment: the whole stretch counts, up to
            // half a window. Judgments come at least once a slot, so a longer
            // gap is time the process was not running (a `docker pause`, a
            // host suspend), when no peer could deliver anything either: the
            // first judgment after a resume must not spend the window before
            // range sync has had a chance. Half a window is far above what
            // one handler holds the actor for, so a slow node's window does
            // not stretch.
            (Some(counted), None) => self.behind_for.saturating_add(
                current_slot
                    .saturating_sub(counted)
                    .min(Self::max_stretch(stall_window)),
            ),
            // Back after a lapse longer than the window: a new claim, with a
            // window of its own, once per count. Only once something was
            // counted: the first claim after a quiet stretch starts from zero
            // anyway, and must not use up the renewal an outage later would
            // need.
            (Some(_), Some(lapsed))
                if !self.renewed
                    && self.behind_for > 0
                    && current_slot.saturating_sub(lapsed) > stall_window =>
            {
                self.renewed = true;
                0
            }
            // Back after a shorter lapse: this slot counts once, however many
            // judgments it has.
            (Some(counted), Some(_)) => self
                .behind_for
                .saturating_add(u64::from(current_slot != counted)),
            // Behind for the first time in this count.
            (None, _) => self.behind_for,
        };
        self.counted_at = Some(current_slot);
        self.behind_for
    }

    /// Move the count's slots back by `back`, for a wall clock that stepped
    /// back that far: what was counted stays counted, and the next slot
    /// counts once.
    fn step_back(&mut self, back: u64) {
        for slot in self.counted_at.iter_mut().chain(self.lapsed_at.iter_mut()) {
            *slot = slot.saturating_sub(back);
        }
    }
}

impl SyncStatusTracker {
    /// Build a tracker, choosing whether the syncing state gates duties.
    pub(crate) fn new(gate_duties: bool, thresholds: SyncThresholds) -> Self {
        Self {
            syncing: false,
            gate_duties,
            thresholds,
            last_slot: 0,
            high_water: None,
            last_head: None,
            climb: None,
            stall: StallCount::default(),
            stalled: false,
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

        // Time never runs backwards between judgments, or the stall window
        // would count the same slots twice: a judgment a little older than
        // the last (a tick judging at the slot it read on entry, after work
        // that judged at a fresher one) is judged at the last. Further back
        // than one judgment counts forward (half a window), it is the wall
        // clock stepping back (a clock that ran ahead, corrected). Judged at
        // the last, the count would then stop until the clock passed it
        // again, holding a node behind out of its duties for as long as the
        // step on top of the window. The count's slots move back instead.
        let back = self.last_slot.saturating_sub(current_slot);
        let current_slot = if back > StallCount::max_stretch(stall_window) {
            self.stall.step_back(back);
            current_slot
        } else {
            current_slot.max(self.last_slot)
        };
        self.last_slot = current_slot;

        let high_water = *self.high_water.get_or_insert(head_slot);
        let last_head = self.last_head.replace(head_slot).unwrap_or(head_slot);
        if head_slot > high_water {
            // Progress: past every head reached since the window last started
            // over. The window starts over, and a lead given up on is believed
            // again.
            self.high_water = Some(head_slot);
            self.climb = None;
            self.start_window_over();
        } else if let Some(climb) = &mut self.climb {
            if head_slot > climb.high {
                // Climbing back after a move back: each block past the
                // highest reached since is progress, so a re-import after an
                // `INVALID` cut stays syncing while it lasts.
                climb.high = head_slot;
                self.start_window_over();
            } else if head_slot < climb.low {
                climb.low = head_slot;
                if !climb.deeper_cut {
                    // A deeper cut than the first: the peers may be right
                    // again. Once per mark, or a head stepping down a slot
                    // at a time would restart the window at every step.
                    climb.deeper_cut = true;
                    climb.high = head_slot;
                    self.start_window_over();
                }
            }
        } else if head_slot < last_head {
            // The head moved back (an `INVALID` execution verdict cutting a
            // branch out, a reorg onto a shorter branch). The peers may have
            // been right about the chain all along, so the window starts over
            // and a lead given up on is believed again.
            self.climb = Some(Climb {
                low: head_slot,
                high: head_slot,
                deeper_cut: false,
            });
            self.start_window_over();
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
        let behind_for = self.stall.count(current_slot, on_peers_word, stall_window);

        // The backstop: behind on the peers' word for a whole window, all of
        // it with the head flat. Whoever claims the lead is not delivering it,
        // which is what a stalled network looks like too.
        if on_peers_word && !self.stalled && behind_for > stall_window {
            warn!(
                current_slot,
                head_slot,
                network_head,
                behind_for,
                "Peers report a head this node is not reaching; treating the network as stalled"
            );
            self.stalled = true;
        }

        let was_syncing = self.syncing;
        self.syncing = behind && (network_at_clock || !self.stalled);

        if self.syncing != was_syncing {
            info!(
                current_slot,
                head_slot,
                network_head,
                clock_lag,
                peer_lead,
                stalled = self.stalled,
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

    /// Start the stall window over, and believe a lead given up on again.
    fn start_window_over(&mut self) {
        self.stall = StallCount::default();
        self.stalled = false;
    }

    /// The latest wall-clock slot judged at.
    pub(crate) fn judged_through(&self) -> u64 {
        self.last_slot
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

    /// Judge once a slot through `walls`, as the tick does, with the head at
    /// `head` and a peer claiming a head at the clock; returns the last
    /// status.
    fn behind_through(
        tracker: &mut SyncStatusTracker,
        walls: std::ops::RangeInclusive<u64>,
        head: u64,
    ) -> SyncStatus {
        walls
            .map(|current| tracker.update(current, head, Some(current)))
            .last()
            .expect("at least one slot")
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
            behind_through(&mut tracker, 101..=last_syncing, 50),
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
            behind_through(&mut tracker, 101..=tripped, 50),
            SyncStatus::Synced
        );
        // A block lands but leaves the node behind: the peers were right
        // after all, and the window starts over from the advance.
        assert_eq!(
            tracker.update(tripped + 1, 51, Some(tripped + 1)),
            SyncStatus::Syncing
        );
        let end = tripped + 1 + LEAN.stall_window;
        assert_eq!(
            behind_through(&mut tracker, tripped + 2..=end, 51),
            SyncStatus::Syncing
        );
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
    fn a_pause_does_not_spend_the_stall_window() {
        // Finding: one judgment added the whole gap since the last, so a
        // process paused for longer than the window (`docker pause`, a host
        // suspend) gave up on its peers at the first judgment after the
        // resume, before range sync could move its head, and read as synced
        // on its stale head.
        for thresholds in [LEAN, BEACON] {
            let window = thresholds.stall_window;
            let mut tracker = SyncStatusTracker::new(true, thresholds);
            let head = 50;
            let start = head + 2 * thresholds.clock_lag + 1;
            assert_eq!(
                tracker.update(start, head, Some(start)),
                SyncStatus::Syncing
            );
            // Paused for ten windows: the resume counts half of one.
            let resumed = start + 10 * window;
            let half = window / 2;
            for current in resumed..=resumed + (window - half) {
                assert_eq!(
                    tracker.update(current, head, Some(current)),
                    SyncStatus::Syncing,
                    "slot {current}"
                );
            }
            // Still flat, the rest of the window runs out as before.
            let tripped = resumed + (window - half) + 1;
            assert_eq!(
                tracker.update(tripped, head, Some(tripped)),
                SyncStatus::Synced
            );
        }
    }

    #[test]
    fn a_clock_stepped_back_does_not_stop_the_stall_window() {
        // Finding: a judgment older than the last was judged at the last, so
        // a wall clock that ran ahead and was then stepped back stopped the
        // count until the clock passed the old reading again, holding a node
        // behind out of its duties for as long as the step on top of the
        // window.
        for thresholds in [LEAN, BEACON] {
            let window = thresholds.stall_window;
            let half = window / 2;
            let mut tracker = SyncStatusTracker::new(true, thresholds);
            let head = 50;
            let start = head + 2 * thresholds.clock_lag + 1;
            assert_eq!(
                tracker.update(start, head, Some(start)),
                SyncStatus::Syncing
            );
            behind_through(&mut tracker, start + 1..=start + 3, head);
            // One judgment with the clock ten windows ahead, counting half a
            // window, then the clock is stepped back to the right time.
            let ahead = start + 3 + 10 * window;
            assert_eq!(
                tracker.update(ahead, head, Some(start + 3)),
                SyncStatus::Syncing
            );
            assert_eq!(tracker.judged_through(), ahead);
            assert_eq!(
                tracker.update(start + 4, head, Some(start + 4)),
                SyncStatus::Syncing
            );
            assert_eq!(tracker.judged_through(), start + 4);
            // Three slots before, half a window for the jump ahead, the slot
            // after the step back counts nothing, the rest one a slot.
            let last_syncing = start + 1 + window - half;
            assert_eq!(
                behind_through(&mut tracker, start + 5..=last_syncing, head),
                SyncStatus::Syncing
            );
            assert_eq!(
                tracker.update(last_syncing + 1, head, Some(last_syncing + 1)),
                SyncStatus::Synced,
                "window {window}"
            );
        }
    }

    #[test]
    fn a_head_climbing_back_after_a_move_back_is_progress() {
        // An `INVALID` execution verdict moves the head back: the window
        // starts over there, and each re-imported block past the highest
        // reached since is progress, so a slow re-climb stays syncing.
        let mut tracker = steady_lean();
        assert_eq!(tracker.update(100, 60, Some(100)), SyncStatus::Syncing);
        assert_eq!(tracker.update(105, 50, Some(105)), SyncStatus::Syncing);
        for (step, head) in (51..=60).enumerate() {
            let current = 105 + 10 * (step as u64 + 1);
            assert_eq!(
                tracker.update(current, head, Some(current)),
                SyncStatus::Syncing,
                "head {head}"
            );
        }
        // Flat again: the window then runs out as usual.
        let flat_from = 205;
        let end = flat_from + LEAN.stall_window;
        assert_eq!(
            behind_through(&mut tracker, flat_from + 1..=end, 60),
            SyncStatus::Syncing
        );
        assert_eq!(
            tracker.update(end + 1, 60, Some(end + 1)),
            SyncStatus::Synced
        );
    }

    #[test]
    fn a_deeper_cut_during_a_re_climb_is_judged_afresh() {
        // Finding: once a re-climb had begun, a second `INVALID` cut moving
        // the head lower still kept a stall given up on in the meantime.
        let mut tracker = steady_lean();
        assert_eq!(tracker.update(100, 60, Some(100)), SyncStatus::Syncing);
        assert_eq!(tracker.update(101, 50, Some(101)), SyncStatus::Syncing);
        assert_eq!(tracker.update(102, 55, Some(102)), SyncStatus::Syncing);
        let tripped = 103 + LEAN.stall_window;
        assert_eq!(
            behind_through(&mut tracker, 103..=tripped, 55),
            SyncStatus::Synced
        );
        // Back to 52: above the climb's low, so not on its own a new cut.
        assert_eq!(
            tracker.update(tripped + 1, 52, Some(tripped + 1)),
            SyncStatus::Synced
        );
        // Below it: a deeper cut, and the peers are believed again.
        assert_eq!(
            tracker.update(tripped + 2, 45, Some(tripped + 2)),
            SyncStatus::Syncing
        );
    }

    #[test]
    fn a_head_stepping_down_a_slot_at_a_time_does_not_hold_the_window_open() {
        // Finding: every new low started the window over, so a head moving
        // down a slot at a time, more often than the window runs out, kept
        // the node idle for as long as it kept going down.
        let mut tracker = steady_lean();
        assert_eq!(tracker.update(100, 60, Some(100)), SyncStatus::Syncing);
        let mut gave_up_at = None;
        for step in 1..=50u64 {
            let current = 100 + 4 * step;
            let head = 60 - step;
            let status = tracker.update(current, head, Some(current));
            if status == SyncStatus::Synced {
                gave_up_at.get_or_insert(current);
            }
        }
        let gave_up_at = gave_up_at.expect("the window ran out");
        assert!(gave_up_at <= 112 + LEAN.stall_window, "{gave_up_at}");
    }

    #[test]
    fn a_head_flipping_between_two_branches_does_not_hold_the_window_open() {
        // Finding: every flip, up or down, started the window over, so a head
        // flipping between branches at two slots, with a peer claiming a lead
        // throughout, kept the node idle indefinitely.
        let mut tracker = steady_lean();
        assert_eq!(tracker.update(100, 60, Some(100)), SyncStatus::Syncing);
        let mut gave_up_at = None;
        let last = 100 + 4 * LEAN.stall_window;
        for current in 101..=last {
            let head = if current % 2 == 0 { 60 } else { 59 };
            let status = tracker.update(current, head, Some(current));
            if status == SyncStatus::Synced {
                gave_up_at.get_or_insert(current);
            }
            if current == last {
                assert_eq!(status, SyncStatus::Synced, "stays given up on");
            }
        }
        // Two restarts at most (the first flip down, then the climb back to
        // the mark), then the window runs out.
        let gave_up_at = gave_up_at.expect("the window ran out");
        assert!(gave_up_at <= 103 + LEAN.stall_window, "{gave_up_at}");
    }

    #[test]
    fn a_judgment_older_than_the_last_counts_no_slot_twice() {
        // Finding: lean's tick judges at the slot it was scheduled for, and a
        // tick handled behind a catch-up's arrivals took time backwards, so
        // the next arrival counted the same slots again.
        let mut tracker = steady_lean();
        assert_eq!(tracker.update(100, 50, Some(100)), SyncStatus::Syncing);
        behind_through(&mut tracker, 101..=110, 50);
        tracker.update(105, 50, Some(105));
        tracker.update(110, 50, Some(110));
        let end = 100 + LEAN.stall_window;
        assert_eq!(
            behind_through(&mut tracker, 111..=end, 50),
            SyncStatus::Syncing
        );
        assert_eq!(
            tracker.update(end + 1, 50, Some(end + 1)),
            SyncStatus::Synced
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
            behind_through(&mut tracker, 101..=tripped, 60),
            SyncStatus::Synced
        );
        assert_eq!(
            tracker.update(tripped + 1, 55, Some(tripped + 1)),
            SyncStatus::Syncing
        );
        // And gets a whole window from there.
        let end = tripped + 1 + LEAN.stall_window;
        assert_eq!(
            behind_through(&mut tracker, tripped + 2..=end, 55),
            SyncStatus::Syncing
        );
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

    /// A small deterministic generator, so the schedule test needs no
    /// dependency and fails the same way every run.
    struct XorShift(u64);

    impl XorShift {
        fn below(&mut self, n: u64) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x % n
        }
    }

    #[test]
    fn no_claim_schedule_idles_a_flat_head_past_two_windows() {
        // The backstop's bound against arbitrary schedules: with the head
        // flat, a peer making and dropping its claim however it likes, within
        // and across slots, gets the node to read syncing in at most two
        // windows' worth of slots (the first, and one renewal after a long
        // lapse), give or take a slot of rounding at each.
        for thresholds in [LEAN, BEACON] {
            let window = thresholds.stall_window;
            for seed in 1..=300u64 {
                let mut rng = XorShift(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
                let mut tracker = SyncStatusTracker::new(true, thresholds);
                let head = 50;
                let start = head + 2 * thresholds.clock_lag + 1;
                // Runs of claims and lapses, from a slot to a few windows long,
                // judged one to three times a slot.
                let mut claiming = true;
                let mut run_left = 0;
                let mut idle_slots = 0;
                for current in start..start + 30 * window {
                    if run_left == 0 {
                        claiming = !claiming;
                        run_left = 1 + rng.below(3 * window);
                    }
                    run_left -= 1;
                    let mut idle = false;
                    for _ in 0..1 + rng.below(3) {
                        // Within a slot, a claim may lapse for a judgment.
                        let claim = claiming && rng.below(4) != 0;
                        let network_head = claim.then_some(current);
                        idle |= tracker.update(current, head, network_head) == SyncStatus::Syncing;
                    }
                    idle_slots += u64::from(idle);
                }
                assert!(
                    idle_slots <= 2 * window + 2,
                    "seed {seed}, window {window}: idle for {idle_slots} slots"
                );
            }
        }
    }

    #[test]
    fn no_head_course_below_its_mark_idles_a_node_for_long() {
        // The backstop's bound with the head moving: a head wandering below
        // the highest it reached (branch flips, `INVALID` cuts, re-imports),
        // never past it, with a peer claiming a lead throughout, starts the
        // window over once on its first move back, once per new high on the
        // way back up, and once more for one deeper cut. A wander over
        // `depth` slots therefore idles the node for at most `2 * depth + 3`
        // windows, however long it goes on.
        for thresholds in [LEAN, BEACON] {
            let window = thresholds.stall_window;
            for seed in 1..=300u64 {
                let mut rng = XorShift(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
                let mut tracker = SyncStatusTracker::new(true, thresholds);
                let mark = 60;
                let depth = 1 + rng.below(5);
                let start = mark + 2 * thresholds.clock_lag + 1;
                // The first judgment is at the mark, so the wander starts
                // below the highest head the tracker has seen.
                let mut head = mark;
                tracker.update(start, head, Some(start));
                let mut idle_slots = 1;
                for current in start + 1..start + 100 * window {
                    let mut idle = false;
                    for _ in 0..1 + rng.below(3) {
                        // Now and then the head moves, anywhere within
                        // `depth` of the mark.
                        if rng.below(4) == 0 {
                            head = mark - rng.below(depth + 1);
                        }
                        let status = tracker.update(current, head, Some(current));
                        idle |= status == SyncStatus::Syncing;
                    }
                    idle_slots += u64::from(idle);
                }
                let bound = (2 * depth + 3) * window + 2;
                assert!(
                    idle_slots <= bound,
                    "seed {seed}, window {window}, depth {depth}: idle for {idle_slots} slots"
                );
            }
        }
    }

    #[test]
    fn a_single_judgment_behind_does_not_use_up_the_renewal() {
        // Finding: one judgment behind, then a long lapse, used up the fresh
        // window an outage after real counting would need.
        let mut tracker = steady_lean();
        assert_eq!(tracker.update(100, 50, Some(100)), SyncStatus::Syncing);
        assert_eq!(tracker.update(101, 50, None), SyncStatus::Synced);
        for current in 200..=210 {
            assert_eq!(
                tracker.update(current, 50, Some(current)),
                SyncStatus::Syncing
            );
        }
        assert_eq!(tracker.update(211, 50, None), SyncStatus::Synced);
        // The outage the renewal is for: a whole window on reconnect.
        let back = 400;
        for current in back..=back + LEAN.stall_window {
            assert_eq!(
                tracker.update(current, 50, Some(current)),
                SyncStatus::Syncing,
                "slot {current}"
            );
        }
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
