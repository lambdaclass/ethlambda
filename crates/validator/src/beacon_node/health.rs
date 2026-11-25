//! What each configured beacon node last said about its own sync status.
//!
//! # One probe a slot, ahead of the boundary
//!
//! [`run`] asks every node for `GET /eth/v1/node/syncing` once a slot, all at
//! once, a sixth of a slot before the slot's boundary: 2 s on mainnet's 12 s
//! slots, Lighthouse's lookahead. That is after the previous slot's last duty
//! offset (the payload timeliness committee vote, three quarters in) and early
//! enough that a healthy node has answered by the boundary. The duty loop reads
//! the answers there and never waits for one. The probe runs on its own task and
//! clock, as the doppelganger check does, so a slow node never delays a duty
//! and an overrunning duty never delays a probe.
//!
//! # What the answers are read for
//!
//! - **The slot's gate** ([`slot_signs`]). A slot signs nothing (no block,
//!   attestation, aggregate, sync committee message, contribution or payload
//!   timeliness vote) when at least one node answered the probe taken for it
//!   and every node that answered reported syncing or optimistic. A node that
//!   did not answer does not count as syncing: the 503 a duty endpoint answers
//!   while its node syncs still covers it, so nodes that cannot be reached
//!   never stop duties on their own. Only the probe taken for the slot counts,
//!   so a late answer, or a probe task that stopped, opens the gate rather than
//!   holding it shut. A node whose answer is still on its way at the boundary,
//!   and that answered synced the slot before, holds the gate open too, so a
//!   slow synced node does not lose the slot to a fast syncing one.
//! - **Routing** ([`NodeHealth::ranked`]). The fallback asks the nodes whose
//!   last probe passed (neither syncing nor optimistic) first, in command-line
//!   order, then the rest, in the same order. Positions stay command-line
//!   positions, so a blinded block still goes back to the node that produced it.
//! - **Two calls the Beacon API leaves ungated.** No 503 covers a syncing
//!   node's head root, or an optimistic node's payload attestation data, so the
//!   fallback does not ask a node whose last probe reported syncing or
//!   optimistic, or got no answer, for either. Without that, a passed node
//!   failing either call would hand it to the next node in the walk, which may
//!   be that one. Unlike the gate, a node that did not answer is not given the
//!   benefit of the doubt here: no 503 stands behind it.
//!
//! # No clock-based rule
//!
//! Nothing here judges a node by how old its head looks against this client's
//! clock. During a network-wide stall every head is old, and clients that stop
//! signing then keep the chain stalled. The signal is the node's own
//! `is_syncing` and `is_optimistic`. `head_slot` and `sync_distance` are kept in
//! the record, not acted on. A record older than two slots is no longer read for
//! routing, which only ever moves a node back to plain command-line order.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock, PoisonError, RwLock};
use std::time::{Duration, SystemTime};

use ethlambda_types::beacon::primitives::Slot;
use tracing::{info, warn};

use crate::beacon_node::BeaconNodeApi;
use crate::beacon_node::fallback::FallbackBeaconNode;
use crate::slot_clock::SlotClock;

/// How far ahead of a slot's boundary its probe is taken, as a fraction of the
/// slot: a sixth, which is Lighthouse's 2 s on mainnet's 12 s slots. Past the
/// payload timeliness committee vote, the latest duty offset of the slot
/// before, at three quarters.
const PROBE_LEAD_DIVISOR: u32 = 6;

/// How many slots a node's last probe is read for routing. Each probe replaces
/// the last one a slot later, so only a probe task that stopped leaves one this
/// old.
const ROUTING_SLOTS: u32 = 2;

/// One node's `GET /eth/v1/node/syncing` answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncStatus {
    /// The node's head slot. `None` when the node sent none, or one that is not
    /// a quoted integer: see `SyncingDto::head_slot`.
    pub head_slot: Option<Slot>,
    /// How many slots the node's head is behind its own wall clock. `None` as
    /// for `head_slot`.
    pub sync_distance: Option<u64>,
    /// The node's consensus head is behind the network's.
    pub is_syncing: bool,
    /// The node's head has an execution payload its execution client has not
    /// validated. `false` when the node left the field out.
    pub is_optimistic: bool,
    /// The node cannot reach its execution client. Logged, never acted on: the
    /// node reports `is_optimistic` once that starts to matter. `false` when
    /// the node left the field out.
    pub el_offline: bool,
}

impl SyncStatus {
    /// Neither syncing nor optimistic: a node a validator may sign against.
    pub fn is_synced(&self) -> bool {
        !self.is_syncing && !self.is_optimistic
    }
}

/// One probe of one node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    /// The slot the probe was taken ahead of. The slot's gate reads this probe
    /// and no other.
    pub slot: Slot,
    /// When the request was sent.
    pub at: SystemTime,
    /// The node's answer, or why there is none: an error, or no answer within
    /// the probe's budget.
    pub outcome: Result<SyncStatus, String>,
}

impl Probe {
    pub fn standing(&self) -> Standing {
        match &self.outcome {
            Ok(status) => Standing::of(status),
            Err(_) => Standing::NoAnswer,
        }
    }
}

/// What a node's probe says about it, in the terms the gate and the routing
/// read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// Answered, neither syncing nor optimistic.
    Synced,
    /// Answered `is_syncing: true`, optimistic or not.
    Syncing,
    /// Answered `is_optimistic: true` and not syncing.
    Optimistic,
    /// The probe failed: an error, or no answer in time.
    NoAnswer,
    /// Not probed yet, or the last probe is too old to read.
    Unknown,
}

impl Standing {
    pub fn of(status: &SyncStatus) -> Self {
        if status.is_syncing {
            Self::Syncing
        } else if status.is_optimistic {
            Self::Optimistic
        } else {
            Self::Synced
        }
    }

    /// The node said it is one a validator must not sign against.
    pub fn is_unsynced(self) -> bool {
        matches!(self, Self::Syncing | Self::Optimistic)
    }

    /// Whether a call the Beacon API gives no 503 for in an unsynced state may
    /// go to the node: its probe answered synced, or there is no probe to
    /// read, as in a fallback no probe task runs for. A probe that failed
    /// vouches for nothing, and nothing else would stop the answer.
    pub fn may_serve_ungated(self) -> bool {
        matches!(self, Self::Synced | Self::Unknown)
    }
}

/// How the nodes that answered one round of probes split.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncVerdict {
    /// Nodes that answered at all.
    pub answered: usize,
    /// Of those, the ones neither syncing nor optimistic.
    pub synced: usize,
    pub syncing: usize,
    pub optimistic: usize,
    /// Nodes whose probe for the slot had not come back when it was read, and
    /// that answered synced for the slot before. Not counted as answering.
    pub awaited_synced: usize,
}

impl SyncVerdict {
    pub fn tally(standings: impl IntoIterator<Item = Standing>) -> Self {
        let mut verdict = Self::default();
        for standing in standings {
            match standing {
                Standing::Synced => verdict.synced += 1,
                Standing::Syncing => verdict.syncing += 1,
                Standing::Optimistic => verdict.optimistic += 1,
                Standing::NoAnswer | Standing::Unknown => continue,
            }
            verdict.answered += 1;
        }
        verdict
    }

    /// Whether duties may be signed: some node answered synced, or no node
    /// answered at all, which leaves each duty to its endpoint's 503, or a
    /// node that was synced a slot ago has not answered yet.
    pub fn signs(&self) -> bool {
        self.answered == 0 || self.synced > 0 || self.awaited_synced > 0
    }
}

/// The last probe of each configured beacon node, in command-line order.
///
/// Shared, so the fallback that routes requests by it and anything that reports
/// on the nodes read the same records. [`Self::snapshot`] is the cheap read for
/// the latter.
pub struct NodeHealth {
    probes: RwLock<Vec<Option<Probe>>>,
    /// Whether each node's last probe that answered reported its execution
    /// client offline. A probe with no answer leaves it as it was, so the
    /// change logs compare one answer with the last.
    el_offline: Vec<AtomicBool>,
    /// How long a probe is read for routing. Unset until [`run`] starts, so a
    /// fallback that is never probed on a schedule (a test, the voluntary-exit
    /// command) reads whatever it holds.
    read_for: OnceLock<Duration>,
}

impl NodeHealth {
    pub fn new(nodes: usize) -> Self {
        Self {
            probes: RwLock::new(vec![None; nodes]),
            el_offline: (0..nodes).map(|_| AtomicBool::new(false)).collect(),
            read_for: OnceLock::new(),
        }
    }

    /// Every node's last probe, in command-line order: `None` for a node not
    /// probed yet. A copy, so a caller holds no lock.
    pub fn snapshot(&self) -> Vec<Option<Probe>> {
        self.read().clone()
    }

    /// Stop reading a probe for routing once it is older than `age`.
    pub fn expire_after(&self, age: Duration) {
        let _ = self.read_for.set(age);
    }

    /// Keep `probe` as the node at `position`'s last, and log what changed: a
    /// node that stopped or started answering synced, and `el_offline` going on
    /// or off. Only changes, since a probe runs every slot.
    pub fn record(&self, position: usize, probe: Probe) {
        let standing = probe.standing();
        let el_offline = is_el_offline(&probe);
        let (head_slot, sync_distance) = match &probe.outcome {
            Ok(status) => (status.head_slot, status.sync_distance),
            Err(_) => (None, None),
        };
        let error = probe.outcome.as_ref().err().cloned();
        let previous = {
            let mut probes = self.probes.write().unwrap_or_else(PoisonError::into_inner);
            let Some(held) = probes.get_mut(position) else {
                return;
            };
            held.replace(probe)
        };

        let was = previous.as_ref().map(Probe::standing);
        if was != Some(standing) {
            match standing {
                Standing::Synced if was.is_some() => info!(
                    position,
                    ?head_slot,
                    "Beacon node reports it is synced; duties go to it first again"
                ),
                Standing::Syncing => warn!(
                    position,
                    ?head_slot,
                    ?sync_distance,
                    "Beacon node reports it is syncing; duties go to the other nodes first"
                ),
                Standing::Optimistic => warn!(
                    position,
                    ?head_slot,
                    "Beacon node reports an optimistic head; duties go to the other nodes first"
                ),
                Standing::NoAnswer => warn!(
                    position,
                    error = error.as_deref().unwrap_or_default(),
                    "Beacon node did not answer its sync probe"
                ),
                Standing::Synced | Standing::Unknown => {}
            }
        }
        // Against the last probe that answered, so a failed probe in between
        // neither hides the execution client coming back nor repeats it going.
        if standing == Standing::NoAnswer {
            return;
        }
        let was_el_offline = self.el_offline[position].swap(el_offline, Ordering::Relaxed);
        if el_offline && !was_el_offline {
            warn!(
                position,
                "Beacon node reports its execution client is offline; it will go optimistic if it \
                 has not already"
            );
        } else if was_el_offline && !el_offline {
            info!(position, "Beacon node reports its execution client is back");
        }
    }

    /// Every position, the nodes whose last probe passed first, then the rest,
    /// each group in command-line order, with each node's standing.
    ///
    /// The order requests walk the nodes in. Nothing more than passed or not:
    /// with no probe held, it is plain command-line order.
    pub fn ranked(&self) -> Vec<(usize, Standing)> {
        self.ranked_at(SystemTime::now())
    }

    fn ranked_at(&self, now: SystemTime) -> Vec<(usize, Standing)> {
        let read_for = self.read_for.get().copied();
        let probes = self.read();
        let standings = probes.iter().enumerate().map(|(position, probe)| {
            let standing = match probe {
                Some(probe) if !is_stale(probe, read_for, now) => probe.standing(),
                _ => Standing::Unknown,
            };
            (position, standing)
        });
        let (mut ranked, rest): (Vec<_>, Vec<_>) =
            standings.partition(|(_, standing)| *standing == Standing::Synced);
        ranked.extend(rest);
        ranked
    }

    /// How the probes taken for `slot` split. A node whose last probe was taken
    /// for another slot did not answer this one; one still on the slot before's
    /// synced answer is counted apart, as awaited.
    pub fn verdict(&self, slot: Slot) -> SyncVerdict {
        let probes = self.read();
        let for_slot = probes.iter().flatten().filter(|probe| probe.slot == slot);
        let mut verdict = SyncVerdict::tally(for_slot.map(Probe::standing));
        verdict.awaited_synced = probes
            .iter()
            .flatten()
            .filter(|probe| probe.slot + 1 == slot && probe.standing() == Standing::Synced)
            .count();
        verdict
    }

    /// The records are plain values with no invariant between them, so one a
    /// panicking writer left behind is still a record worth reading.
    fn read(&self) -> std::sync::RwLockReadGuard<'_, Vec<Option<Probe>>> {
        self.probes.read().unwrap_or_else(PoisonError::into_inner)
    }
}

fn is_el_offline(probe: &Probe) -> bool {
    matches!(&probe.outcome, Ok(status) if status.el_offline)
}

fn is_stale(probe: &Probe, read_for: Option<Duration>, now: SystemTime) -> bool {
    read_for.is_some_and(|limit| now.duration_since(probe.at).unwrap_or_default() > limit)
}

/// The duty loop's gate for `slot`, read at its boundary: whether the slot's
/// duties may be signed, by the probe taken ahead of it. A slot it withholds is
/// logged and counted here.
pub fn slot_signs(health: &NodeHealth, slot: Slot) -> bool {
    let verdict = health.verdict(slot);
    if verdict.signs() {
        return true;
    }
    let SyncVerdict {
        answered,
        syncing,
        optimistic,
        ..
    } = verdict;
    warn!(
        %slot,
        answered,
        syncing,
        optimistic,
        "Every beacon node that answered this slot's sync probe is syncing or optimistic; \
         signing nothing in this slot"
    );
    crate::metrics::inc_slots_skipped_syncing();
    crate::metrics::set_beacon_node_available(false);
    false
}

/// Probe every node in `beacon_node` once a slot, ahead of each boundary, for
/// the life of the client. See the module doc.
pub async fn run<B: BeaconNodeApi>(beacon_node: Arc<FallbackBeaconNode<B>>, clock: SlotClock) {
    beacon_node
        .health()
        .expire_after(clock.slot_duration() * ROUTING_SLOTS);
    let mut last = None;
    loop {
        let (slot, wait) = next_probe(&clock, last, SystemTime::now());
        tokio::time::sleep(wait).await;
        // Until the next probe is due, so rounds never overlap and a node that
        // hangs is recorded as not answering by then.
        let budget = probe_time(&clock, slot + 1)
            .duration_since(SystemTime::now())
            .unwrap_or_default();
        beacon_node.probe(slot, budget).await;
        last = Some(slot);
    }
}

/// When the probe for `slot` is taken: [`PROBE_LEAD_DIVISOR`]'s fraction of a
/// slot before its boundary.
fn probe_time(clock: &SlotClock, slot: Slot) -> SystemTime {
    let start = clock.start_of(slot);
    let lead = clock.slot_duration() / PROBE_LEAD_DIVISOR;
    start.checked_sub(lead).unwrap_or(start)
}

/// The slot to probe for next, given the last one probed, and how long until
/// its probe is due.
///
/// The slot is the first whose boundary is still ahead, and never one already
/// probed. Inside its lead already (a client just started, or a probe that
/// overran), the wait is zero, so the slot the duty loop serves next has a
/// probe whenever one can answer before its boundary.
fn next_probe(clock: &SlotClock, last: Option<Slot>, now: SystemTime) -> (Slot, Duration) {
    let ahead = clock.slot_at(now).map_or(0, |slot| slot + 1);
    let slot = last.map_or(ahead, |last| ahead.max(last + 1));
    let wait = probe_time(clock, slot)
        .duration_since(now)
        .unwrap_or_default();
    (slot, wait)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    use crate::beacon_node::mock::MockBeaconNode;

    const GENESIS: u64 = 1_000_000;

    fn status(is_syncing: bool, is_optimistic: bool) -> SyncStatus {
        SyncStatus {
            head_slot: Some(100),
            sync_distance: Some(0),
            is_syncing,
            is_optimistic,
            el_offline: false,
        }
    }

    fn probe(slot: Slot, outcome: Result<SyncStatus, String>) -> Probe {
        Probe {
            slot,
            at: SystemTime::now(),
            outcome,
        }
    }

    fn synced(slot: Slot) -> Probe {
        probe(slot, Ok(status(false, false)))
    }

    fn syncing(slot: Slot) -> Probe {
        probe(slot, Ok(status(true, false)))
    }

    fn optimistic(slot: Slot) -> Probe {
        probe(slot, Ok(status(false, true)))
    }

    fn down(slot: Slot) -> Probe {
        probe(slot, Err("connection refused".to_string()))
    }

    fn health(probes: Vec<Probe>) -> NodeHealth {
        let health = NodeHealth::new(probes.len());
        for (position, probe) in probes.into_iter().enumerate() {
            health.record(position, probe);
        }
        health
    }

    /// A slot is withheld only when some node answered and none of those that
    /// did is synced. Nodes that did not answer change nothing either way.
    #[test]
    fn a_slot_is_withheld_only_when_every_node_that_answered_is_unsynced() {
        let slot = 10;
        let cases = [
            (vec![synced(slot)], true),
            (vec![down(slot)], true),
            (vec![down(slot), down(slot)], true),
            (vec![syncing(slot)], false),
            (vec![optimistic(slot)], false),
            (vec![syncing(slot), optimistic(slot)], false),
            (vec![syncing(slot), down(slot)], false),
            (vec![syncing(slot), synced(slot)], true),
            (vec![optimistic(slot), down(slot), synced(slot)], true),
        ];
        for (probes, signs) in cases {
            let standings: Vec<Standing> = probes.iter().map(Probe::standing).collect();
            assert_eq!(health(probes).verdict(slot).signs(), signs, "{standings:?}");
        }
    }

    /// Only the probe taken for the slot counts: a node still on the last
    /// slot's answer has not answered this one, so an old "syncing" cannot hold
    /// a slot shut.
    #[test]
    fn only_the_probe_taken_for_the_slot_counts() {
        let health = health(vec![syncing(9), syncing(9)]);
        assert!(health.verdict(10).signs());
        assert_eq!(health.verdict(10).answered, 0);

        let health_now = NodeHealth::new(2);
        health_now.record(0, syncing(9));
        health_now.record(1, syncing(10));
        let verdict = health_now.verdict(10);
        assert_eq!((verdict.answered, verdict.syncing), (1, 1));
        assert!(!verdict.signs());
    }

    /// A synced node whose answer for the slot is still on its way holds the
    /// slot open against a fast syncing one. Once its answer is in, or its
    /// probe failed, the slot's own answers decide.
    #[test]
    fn a_synced_node_still_answering_holds_the_slot_open() {
        let nodes = NodeHealth::new(2);
        nodes.record(0, synced(9));
        nodes.record(1, syncing(10));
        let verdict = nodes.verdict(10);
        assert_eq!((verdict.answered, verdict.awaited_synced), (1, 1));
        assert!(verdict.signs());

        nodes.record(0, down(10));
        assert!(!nodes.verdict(10).signs(), "its probe failed");

        let older = health(vec![synced(8), syncing(10)]);
        assert!(!older.verdict(10).signs(), "synced two slots ago only");
    }

    #[test]
    fn the_gate_counts_each_kind_of_answer() {
        let slot = 4;
        let health = health(vec![syncing(slot), optimistic(slot), down(slot)]);
        assert_eq!(
            health.verdict(slot),
            SyncVerdict {
                answered: 2,
                synced: 0,
                syncing: 1,
                optimistic: 1,
                awaited_synced: 0,
            }
        );
        assert!(!slot_signs(&health, slot));
    }

    /// Syncing and optimistic together is syncing: the node is behind, which
    /// says more than that its head is unvalidated.
    #[test]
    fn a_syncing_and_optimistic_node_stands_as_syncing() {
        assert_eq!(Standing::of(&status(true, true)), Standing::Syncing);
        assert_eq!(Standing::of(&status(false, true)), Standing::Optimistic);
        assert_eq!(Standing::of(&status(false, false)), Standing::Synced);
    }

    #[test]
    fn nodes_that_passed_come_first_in_command_line_order() {
        let health = health(vec![
            syncing(3),
            synced(3),
            down(3),
            synced(3),
            optimistic(3),
        ]);
        let order: Vec<usize> = health
            .ranked()
            .into_iter()
            .map(|(position, _)| position)
            .collect();
        assert_eq!(order, vec![1, 3, 0, 2, 4]);
    }

    /// Before any probe the walk is the command-line order, unchanged, which
    /// is what every fallback that is never probed relies on.
    #[test]
    fn an_unprobed_health_keeps_command_line_order() {
        let health = NodeHealth::new(3);
        assert_eq!(
            health.ranked(),
            vec![
                (0, Standing::Unknown),
                (1, Standing::Unknown),
                (2, Standing::Unknown)
            ]
        );
    }

    /// A probe older than the bound is not read for routing: the node goes
    /// back to command-line order, as if never probed.
    #[test]
    fn a_stale_probe_is_not_read_for_routing() {
        let health = NodeHealth::new(2);
        health.expire_after(Duration::from_secs(24));
        let taken = SystemTime::now();
        health.record(0, syncing(3));
        health.record(
            1,
            Probe {
                at: taken,
                ..synced(3)
            },
        );

        let fresh = health.ranked_at(taken + Duration::from_secs(1));
        assert_eq!(fresh[0], (1, Standing::Synced));

        let later = health.ranked_at(taken + Duration::from_secs(60));
        assert_eq!(later, vec![(0, Standing::Unknown), (1, Standing::Unknown)]);
    }

    /// A probe with no answer leaves the execution client's last reported
    /// state as it was, so the next answer is compared with the one before it.
    #[test]
    fn a_failed_probe_leaves_the_execution_clients_state() {
        let el_offline = |slot| {
            probe(
                slot,
                Ok(SyncStatus {
                    el_offline: true,
                    ..status(false, false)
                }),
            )
        };
        let nodes = NodeHealth::new(1);
        let held = |nodes: &NodeHealth| nodes.el_offline[0].load(Ordering::Relaxed);
        nodes.record(0, el_offline(3));
        nodes.record(0, down(4));
        assert!(held(&nodes), "no answer, nothing changed");
        nodes.record(0, synced(5));
        assert!(!held(&nodes));
    }

    /// The snapshot is every node's last probe, in command-line order, with
    /// what the node said about its head.
    #[test]
    fn the_snapshot_holds_each_nodes_last_probe() {
        let health = NodeHealth::new(3);
        health.record(2, syncing(7));
        health.record(0, synced(6));
        health.record(0, synced(7));

        let snapshot = health.snapshot();
        assert_eq!(snapshot.len(), 3);
        assert_eq!(snapshot[0].as_ref().map(|probe| probe.slot), Some(7));
        assert!(snapshot[1].is_none());
        let syncing = snapshot[2].as_ref().expect("probed");
        assert_eq!(
            syncing.outcome.as_ref().expect("answered").head_slot,
            Some(100)
        );
    }

    fn clock() -> SlotClock {
        SlotClock::new(GENESIS, 12_000, 3_333, 6_667)
    }

    fn at_ms(since_genesis_ms: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(GENESIS) + Duration::from_millis(since_genesis_ms)
    }

    /// On mainnet's 12 s slots the probe is taken 2 s before each boundary.
    #[test]
    fn the_probe_is_taken_a_sixth_of_a_slot_before_the_boundary() {
        let clock = clock();
        assert_eq!(probe_time(&clock, 5), at_ms(5 * 12_000 - 2_000));
    }

    /// The first probe is for the next boundary, the one the duty loop serves
    /// first, and waits for that boundary's lead.
    #[test]
    fn the_first_probe_is_for_the_next_boundary() {
        let clock = clock();
        let (slot, wait) = next_probe(&clock, None, at_ms(3 * 12_000 + 500));
        assert_eq!(slot, 4);
        assert_eq!(wait, Duration::from_millis(12_000 - 2_000 - 500));
    }

    /// A client started inside the lead probes at once, for the boundary
    /// ahead of it.
    #[test]
    fn a_client_started_inside_the_lead_probes_at_once() {
        let clock = clock();
        let (slot, wait) = next_probe(&clock, None, at_ms(3 * 12_000 + 11_000));
        assert_eq!((slot, wait), (4, Duration::ZERO));
    }

    #[test]
    fn later_probes_wait_for_the_lead_before_their_boundary() {
        let clock = clock();
        // Slot 4 was just probed, in slot 3; slot 5's is due 2 s before it.
        let now = at_ms(3 * 12_000 + 10_100);
        let (slot, wait) = next_probe(&clock, Some(4), now);
        assert_eq!(slot, 5);
        assert_eq!(wait, Duration::from_millis(12_000 - 100));
    }

    /// A probe that ran past the boundary it was for does not hold the next
    /// one back: the next is for the next boundary still ahead.
    #[test]
    fn an_overrun_probe_moves_on_to_the_next_boundary() {
        let clock = clock();
        let now = at_ms(5 * 12_000 + 11_000);
        let (slot, wait) = next_probe(&clock, Some(4), now);
        assert_eq!(slot, 6);
        assert_eq!(wait, Duration::ZERO, "inside slot 6's lead already");
    }

    /// Before genesis the first probe waits for slot 0's lead.
    #[test]
    fn before_genesis_the_first_probe_is_slot_zeros() {
        let clock = clock();
        let now = UNIX_EPOCH + Duration::from_secs(GENESIS - 60);
        let (slot, wait) = next_probe(&clock, None, now);
        assert_eq!(slot, 0);
        assert_eq!(wait, Duration::from_secs(58));
    }

    fn fallback(nodes: Vec<MockBeaconNode>) -> FallbackBeaconNode<MockBeaconNode> {
        FallbackBeaconNode::new(nodes)
    }

    /// A probe asks every node and records each in its own position, an
    /// error in place of an answer for a node that is down.
    #[tokio::test]
    async fn a_probe_records_every_node_in_command_line_order() {
        let syncing = MockBeaconNode {
            syncing: true,
            ..MockBeaconNode::new()
        };
        let fallback = fallback(vec![
            MockBeaconNode::new(),
            syncing,
            MockBeaconNode::failing("down"),
        ]);
        fallback.probe(8, Duration::from_secs(1)).await;

        let snapshot = fallback.health().snapshot();
        let standings: Vec<Standing> = snapshot
            .iter()
            .map(|probe| probe.as_ref().expect("probed").standing())
            .collect();
        assert_eq!(
            standings,
            vec![Standing::Synced, Standing::Syncing, Standing::NoAnswer]
        );
        assert!(snapshot.iter().flatten().all(|probe| probe.slot == 8));
    }

    /// A node that does not answer within the budget is recorded as not
    /// answering, and does not hold back the others' records.
    #[tokio::test(start_paused = true)]
    async fn a_hung_node_is_recorded_as_not_answering_within_the_budget() {
        let hung = MockBeaconNode::new().with_sync_status_delay(Duration::from_secs(60));
        let fallback = fallback(vec![hung, MockBeaconNode::new()]);

        let started = tokio::time::Instant::now();
        fallback.probe(8, Duration::from_secs(2)).await;
        assert!(started.elapsed() < Duration::from_secs(3));

        let snapshot = fallback.health().snapshot();
        let hung = snapshot[0].as_ref().expect("recorded");
        assert_eq!(hung.standing(), Standing::NoAnswer);
        assert!(
            hung.outcome
                .as_ref()
                .expect_err("no answer")
                .contains("no answer")
        );
        assert_eq!(
            snapshot[1].as_ref().expect("recorded").standing(),
            Standing::Synced
        );
    }

    /// The issue's first case: a node that passes the epoch's refresh and then
    /// goes optimistic withholds the next slot, whose probe says so. The duty
    /// loop then runs no proposal and no slot duties for it. Of those duties,
    /// the sync committee message and the payload vote are also refused at the
    /// fallback, which does not ask an optimistic node for either.
    #[tokio::test]
    async fn a_node_gone_optimistic_after_the_refresh_withholds_the_next_slot() {
        use ethlambda_types::beacon::primitives::{BlsPubkey, Bytes32, Root};
        use tokio::sync::RwLock;

        use crate::beacon_node::ValidatorEntry;
        use crate::beacon_node::dto::{PtcDutyDto, SyncDutyDto, encode_hex};
        use crate::duties::DutiesService;
        use crate::payload_attestation::PayloadAttestationService;
        use crate::proposer_settings::ProposerSettings;
        use crate::signing::SigningContext;
        use crate::sync_committee::SyncCommitteeService;

        let mut node = MockBeaconNode::new()
            .with_duties(3, Root::repeat_byte(1), Vec::new())
            .with_duties(4, Root::repeat_byte(2), Vec::new())
            .with_proposers(3, Root::repeat_byte(1), Vec::new())
            .with_head_root(Root::repeat_byte(5));
        node.validators = vec![ValidatorEntry {
            index: 11,
            pubkey: BlsPubkey([1; 48]),
            status: "active_ongoing".to_string(),
            slashed: false,
        }];
        let beacon_node = Arc::new(fallback(vec![node]));
        let context = Arc::new(SigningContext::new(
            ethlambda_types::beacon::config::Config::mainnet(),
            Root::ZERO,
        ));
        let settings = ProposerSettings::new(Bytes32::ZERO, None);
        let mut duties = DutiesService::new(beacon_node.clone(), Vec::new());

        let slot = 3 * ethlambda_types::beacon::preset::slots_per_epoch();
        beacon_node.probe(slot, Duration::from_secs(1)).await;
        assert!(slot_signs(beacon_node.health(), slot));
        crate::refresh_epoch(
            &beacon_node,
            &mut duties,
            &[BlsPubkey([1; 48])],
            3,
            &settings,
            &context,
        )
        .await
        .expect("the refresh passes on a synced node");

        beacon_node.nodes()[0].set_sync_status(SyncStatus {
            is_optimistic: true,
            ..beacon_node.nodes()[0].current_status()
        });
        beacon_node.probe(slot + 1, Duration::from_secs(1)).await;
        assert!(
            !slot_signs(beacon_node.health(), slot + 1),
            "the next slot signs nothing"
        );

        // A real key, so a node that did serve the head root or the payload
        // data would get a signed message submitted, which the asserts below
        // catch. With no key the services sign nothing either way.
        let (store, pubkeys) = crate::test_support::store_with_keys(1);
        let store = RwLock::new(store);
        let sync_duty = SyncDutyDto {
            pubkey: encode_hex(&pubkeys[0].0),
            validator_index: 11,
            validator_sync_committee_indices: vec![0],
        };
        let sync = SyncCommitteeService::new(beacon_node.clone(), context.clone());
        let root = sync
            .publish_messages(slot + 1, &[sync_duty], &store)
            .await
            .expect("not a failure");
        assert!(root.is_none(), "no head root to sign");

        let ptc_duty = PtcDutyDto {
            pubkey: encode_hex(&pubkeys[0].0),
            validator_index: 11,
            slot: slot + 1,
        };
        let ptc = PayloadAttestationService::new(beacon_node.clone(), context);
        let voted = ptc
            .attest(slot + 1, &[ptc_duty], &store)
            .await
            .expect("not a failure");
        assert_eq!(voted, 0);

        let node = &beacon_node.nodes()[0];
        assert!(node.submitted_sync_messages().is_empty());
        assert_eq!(node.payload_attestation_data_call_count(), 0);
        assert!(node.submitted_payload_attestations().is_empty());
    }

    /// The issue's third case: a node that is syncing but not optimistic
    /// answers its stale head with `execution_optimistic: false`, which the
    /// head root fetch alone cannot tell apart. Its probe can, so no message is
    /// signed over that root, even when a synced node listed ahead of it fails
    /// the fetch.
    #[tokio::test]
    async fn no_sync_committee_message_is_signed_over_a_syncing_nodes_head() {
        use ethlambda_types::beacon::primitives::Root;
        use tokio::sync::RwLock;

        use crate::beacon_node::dto::{SyncDutyDto, encode_hex};
        use crate::signing::SigningContext;
        use crate::sync_committee::SyncCommitteeService;

        let stale = || MockBeaconNode {
            syncing: true,
            ..MockBeaconNode::new().with_head_root(Root::repeat_byte(9))
        };
        let failing_synced = MockBeaconNode::new().failing_call("head_block_root", "timed out");
        let context = Arc::new(SigningContext::new(
            ethlambda_types::beacon::config::Config::mainnet(),
            Root::ZERO,
        ));
        // A real key, so a stale root that reached the service would be signed
        // and submitted, which the assert below catches.
        let (store, pubkeys) = crate::test_support::store_with_keys(1);
        let store = RwLock::new(store);
        let duty = SyncDutyDto {
            pubkey: encode_hex(&pubkeys[0].0),
            validator_index: 11,
            validator_sync_committee_indices: vec![0],
        };

        for nodes in [vec![stale()], vec![failing_synced, stale()]] {
            let beacon_node = Arc::new(fallback(nodes));
            beacon_node.probe(20, Duration::from_secs(1)).await;
            let service = SyncCommitteeService::new(beacon_node.clone(), context.clone());
            let signed = service
                .publish_messages(20, std::slice::from_ref(&duty), &store)
                .await;
            assert!(
                matches!(
                    signed,
                    Ok(None) | Err(crate::error::Error::AllBeaconNodesFailed(_))
                ),
                "got {signed:?}"
            );
            assert!(
                beacon_node
                    .nodes()
                    .iter()
                    .all(|node| node.submitted_sync_messages().is_empty())
            );
        }
    }
}
