//! Confirmation and the available chain's locks (fork-choice.md:
//! `get_live_locks`, `compute_confirmed_path_and_lock`,
//! `compute_fast_path_and_lock`, `compute_slow_lock`, `add_lock`,
//! `update_locks_and_confirmation`, `update_confirmation`, `unlock`).
//!
//! A confirmation of slot `s` runs at the next slot's support cutoff over the
//! slot's votes. A live lock vetoes any candidate that conflicts with it; an
//! accepted candidate becomes `latest_confirmed` unless that already extends
//! it, and locks the deepest node of its path that passes the fast test (half
//! of all committee seats support it) or the slow test (it is under every
//! saved confirmation of the window). A lock lives until the head vote
//! deadline `SLOW_LOCK_WINDOW + 1` slots later, anchors every head walk, and
//! moves up to an ancestor when half the seats oppose it.

use std::collections::HashSet;

use crate::fork_choice::{FgFrame, View, get_equivocating_indices};
use crate::params::support_cutoff;
use crate::store::Store;
use crate::types::{ForkChoiceNode, INFINITE_TIME, Slot, Tick};

impl Store {
    /// `get_live_locks(store, fg_frame, time_ms)`: the locks with a deadline
    /// after `time` whose node is in the frame.
    pub(crate) fn get_live_locks(
        &self,
        frame: &FgFrame,
        time: Tick,
    ) -> Vec<(Tick, ForkChoiceNode)> {
        self.locks
            .range((time.saturating_add(1))..)
            .filter(|(_, lock)| frame.tree.contains(lock))
            .map(|(deadline, lock)| (*deadline, *lock))
            .collect()
    }

    /// The live locks at the store's time, for diagnostics.
    pub fn live_locks(&self) -> Vec<(Tick, ForkChoiceNode)> {
        self.get_live_locks(&self.get_fg_frame(), self.time)
    }

    /// `compute_confirmed_path_and_lock(store, fg_frame, confirmed,
    /// test_predicate)`: the non-genesis nodes of the frame at or above
    /// `confirmed` that pass the test, and the deepest of them.
    pub(crate) fn compute_confirmed_path_and_lock(
        &self,
        frame: &FgFrame,
        confirmed: &ForkChoiceNode,
        test_predicate: impl Fn(&ForkChoiceNode) -> bool,
    ) -> (HashSet<ForkChoiceNode>, Option<ForkChoiceNode>) {
        let path: HashSet<ForkChoiceNode> = self
            .node_ancestors(*confirmed, 0)
            .filter(|node| {
                frame.tree.contains(node) && self.is_after_genesis(node) && test_predicate(node)
            })
            .collect();
        let lock = self.get_deepest_node(&path);
        (path, lock)
    }

    /// `compute_fast_path_and_lock`: the path nodes whose confirmation support
    /// is at least half of all committee seats.
    pub(crate) fn compute_fast_path_and_lock(
        &self,
        frame: &FgFrame,
        view: &View,
        slot: Slot,
        confirmed: &ForkChoiceNode,
    ) -> (HashSet<ForkChoiceNode>, Option<ForkChoiceNode>) {
        let scores = self.confirmation_scores(view, slot, &frame.finalized_node);
        let seats = self.committees.seats_count();
        self.compute_confirmed_path_and_lock(frame, confirmed, |node| {
            2 * scores.score(node) >= seats
        })
    }

    /// `compute_slow_lock(store, fg_frame, slot, confirmed)`: with a saved
    /// confirmation in the frame for each of the `SLOW_LOCK_WINDOW - 1`
    /// preceding slots, the deepest non-genesis node at or above `confirmed`
    /// and every one of them.
    pub(crate) fn compute_slow_lock(
        &self,
        frame: &FgFrame,
        slot: Slot,
        confirmed: &ForkChoiceNode,
    ) -> Option<ForkChoiceNode> {
        let window = self.params.slow_lock_window;
        if slot + 1 < window {
            return None;
        }
        let previous_slots = (slot + 1 - window)..slot;
        let mut saved = Vec::new();
        for j in previous_slots {
            let confirmation = self.saved_confirmations.get(&j)?;
            if !frame.tree.contains(confirmation) {
                return None;
            }
            saved.push(*confirmation);
        }
        let under_all: Vec<HashSet<ForkChoiceNode>> = saved
            .iter()
            .map(|confirmation| self.node_ancestors(*confirmation, 0).collect())
            .collect();
        let (_, slow_lock) = self.compute_confirmed_path_and_lock(frame, confirmed, |node| {
            under_all.iter().all(|ancestors| ancestors.contains(node))
        });
        slow_lock
    }

    /// `add_lock(store, deadline, node)`.
    pub fn add_lock(&mut self, deadline: Tick, node: ForkChoiceNode) {
        self.locks.insert(deadline, node);
    }

    /// `update_locks_and_confirmation`: save the confirmation, lock the
    /// deeper of the fast and slow locks, and move `latest_confirmed` to the
    /// confirmation unless it stays in the frame and extends it.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn update_locks_and_confirmation(
        &mut self,
        slot: Slot,
        frame: &FgFrame,
        confirmed: ForkChoiceNode,
        fast_confirmed_path: HashSet<ForkChoiceNode>,
        fast_lock: Option<ForkChoiceNode>,
        slow_lock: Option<ForkChoiceNode>,
    ) {
        self.fast_confirmed_path = fast_confirmed_path;
        self.saved_confirmations.insert(slot, confirmed);
        let lock = match (fast_lock, slow_lock) {
            (Some(fast), Some(slow)) => self.get_deepest_node([&fast, &slow]),
            (fast, slow) => fast.or(slow),
        };
        if let Some(lock) = lock {
            let deadline = self.params.lock_deadline(slot);
            self.add_lock(deadline, lock);
        }
        if !(frame.tree.contains(&self.latest_confirmed)
            && self.is_ancestor(&self.latest_confirmed, &confirmed))
        {
            self.latest_confirmed = confirmed;
        }
    }

    /// `update_confirmation(store, slot)`: the confirmation of `slot`, run at
    /// the next slot's support cutoff before the clock reaches it.
    pub(crate) fn update_confirmation(&mut self, slot: Slot) {
        let frame = self.get_fg_frame();
        let view = self.get_combined_local_view(slot, INFINITE_TIME, support_cutoff(slot));
        let Some(confirmed) = self.get_confirmed_head(&frame, &view, slot) else {
            self.fast_confirmed_path.clear();
            return;
        };
        let vetoed = self
            .get_live_locks(&frame, self.time)
            .iter()
            .any(|(_, lock)| !self.is_compatible(lock, &confirmed));
        if vetoed {
            // Saved even when vetoed: the slow lock reads it.
            self.saved_confirmations.insert(slot, confirmed);
            self.fast_confirmed_path.clear();
            return;
        }
        let (fast_confirmed_path, fast_lock) =
            self.compute_fast_path_and_lock(&frame, &view, slot, &confirmed);
        let slow_lock = self.compute_slow_lock(&frame, slot, &confirmed);
        self.update_locks_and_confirmation(
            slot,
            &frame,
            confirmed,
            fast_confirmed_path,
            fast_lock,
            slow_lock,
        );
    }

    /// `unlock(store, slot, time_ms)`: move every live lock that
    /// non-equivocating holders of at least half of all seats oppose (their
    /// resolved votes of `slot` conflict with it) to its deepest ancestor in
    /// the frame opposed by fewer, keeping its deadline.
    pub(crate) fn unlock(&mut self, slot: Slot, time: Tick) {
        let frame = self.get_fg_frame();
        let view = self.get_combined_local_view(slot, INFINITE_TIME, INFINITE_TIME);
        let equivocating = get_equivocating_indices(&view.votes);
        let seats = self.committees.seats_count();
        let opposers: Vec<_> = view
            .support_votes
            .iter()
            .filter(|vote| !equivocating.contains(&vote.validator_index))
            .collect();
        let is_opposed_by_majority = |store: &Store, node: &ForkChoiceNode| {
            let opposing: HashSet<_> = opposers
                .iter()
                .filter(|vote| !store.is_compatible(&vote.supported_node, node))
                .map(|vote| vote.validator_index)
                .collect();
            let opposing_seats: u64 = opposing
                .into_iter()
                .map(|validator| store.committees.seats(slot, validator))
                .sum();
            2 * opposing_seats >= seats
        };
        for (deadline, lock) in self.get_live_locks(&frame, time) {
            if !is_opposed_by_majority(self, &lock) {
                continue;
            }
            let fallback_path: Vec<ForkChoiceNode> = self
                .node_ancestors(lock, 0)
                .filter(|node| frame.tree.contains(node) && !is_opposed_by_majority(self, node))
                .collect();
            // The finalized node is never opposed (every resolved vote is
            // under it), so the path is never empty.
            if let Some(fallback) = self.get_deepest_node(&fallback_path) {
                self.add_lock(deadline, fallback);
            }
        }
    }
}
