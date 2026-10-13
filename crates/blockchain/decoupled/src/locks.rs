//! Goldilocks locks: how the available chain stays put across bounded
//! asynchrony.
//!
//! A lock pins the start of the Goldfish walk: every fork-choice run starts
//! from the deepest live lock in the filtered tree (the *anchor*), and the
//! slot committee's votes decide the walk from there. Locks form and dissolve
//! by four rules, two each way:
//!
//! | Rule | When | Effect |
//! |---|---|---|
//! | Fast lock | the confirmation update of slot `s` sees at least `n/2` of the whole committee `𝒦_s` supporting `B` | lock the deepest such `B` until `s + k` |
//! | Slow lock | the confirmation updates of `k` consecutive slots each confirmed a block | lock their deepest common ancestor until `s + k` |
//! | Fast unlock | before every fork-choice run, at least `n/2` of the committee oppose the lock | the lock steps back to the deepest ancestor with fewer than `n/2` opponents |
//! | Expiry | a lock is not renewed within `k` slots | it is dropped |
//!
//! `n` is the committee size, not the participation: half of the whole
//! committee means a fast lock is backed by a quorum that a conflicting fast
//! lock cannot also gather, and a fast lock's voters are enough to unlock any
//! lock that conflicts with it.
//!
//! # Support and opposition
//!
//! A committee member's *stance* in a slot is the deepest common ancestor of
//! the processed heads of its votes in that slot: its one head when it voted
//! once, less when it equivocated. It supports `B` when `B ⪯ stance` and
//! opposes `B` otherwise. Votes whose head is not processed are left out on
//! both sides: their head may well extend `B`, so counting them as
//! opposition would unlock on missing data.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use ethlambda_types::primitives::H256;

use crate::store::Store;
use crate::types::{GoldfishVote, LockStatus, Slot, ValidatorIndex};

/// `count ≥ n/2`, without division.
pub(crate) fn at_least_half(count: u64, committee: u64) -> bool {
    committee > 0 && 2 * count >= committee
}

/// `|𝒦_s|` for every slot: the lock thresholds are relative to the whole
/// committee, not to whoever voted, so the engine must know its size.
#[derive(Clone)]
pub struct CommitteeSizes(Arc<dyn Fn(Slot) -> u64 + Send + Sync>);

impl CommitteeSizes {
    pub fn new(size: impl Fn(Slot) -> u64 + Send + Sync + 'static) -> Self {
        Self(Arc::new(size))
    }

    /// The same committee size every slot: every validator, on the lean
    /// chain.
    pub fn fixed(size: u64) -> Self {
        Self::new(move |_| size)
    }

    pub fn size(&self, slot: Slot) -> u64 {
        (self.0)(slot)
    }
}

impl std::fmt::Debug for CommitteeSizes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CommitteeSizes(..)")
    }
}

impl Store {
    /// `|𝒦_s|`. Every validator unless the host said otherwise
    /// ([`Store::with_committee_sizes`]).
    pub fn committee_size(&self, slot: Slot) -> u64 {
        self.committee_sizes.size(slot)
    }

    /// Use `sizes` for `|𝒦_s|`. A chain whose slot committee is not every
    /// validator must set this before any vote is counted.
    pub fn with_committee_sizes(mut self, sizes: CommitteeSizes) -> Self {
        self.committee_sizes = sizes;
        self
    }

    /// Lock `block` from the confirmation update of `slot`, or renew it.
    pub(crate) fn form_lock(&mut self, block: H256, slot: Slot) {
        let deadline = slot + self.params.lock_period;
        let entry = self.locks.entry(block).or_insert(deadline);
        *entry = (*entry).max(deadline);
    }

    /// Whether a lock with `deadline` anchors a walk over votes of `slot`.
    pub(crate) fn lock_is_live(deadline: Slot, slot: Slot) -> bool {
        slot < deadline
    }

    /// The anchor of a walk over votes of `slot` inside `tree`: the deepest
    /// live lock in it, or the fork-choice root.
    pub(crate) fn anchor_in(&self, tree: &HashSet<H256>, slot: Slot) -> H256 {
        self.deepest_live_lock(tree, slot)
            .unwrap_or(self.frame.root)
    }

    pub(crate) fn deepest_live_lock(&self, tree: &HashSet<H256>, slot: Slot) -> Option<H256> {
        self.locks
            .iter()
            .filter(|(block, deadline)| {
                Self::lock_is_live(**deadline, slot) && tree.contains(*block)
            })
            .map(|(block, _)| *block)
            .reduce(|a, b| if self.deeper(&a, &b) { a } else { b })
    }

    /// Each committee member's stance in `slot`: the deepest common ancestor
    /// of its votes' processed heads.
    pub(crate) fn stances(&self, votes: &[GoldfishVote], slot: Slot) -> Vec<H256> {
        let mut heads: HashMap<ValidatorIndex, H256> = HashMap::new();
        for vote in votes {
            if vote.slot != slot || !self.vote_resolves(vote) {
                continue;
            }
            match heads.get(&vote.validator) {
                None => {
                    heads.insert(vote.validator, vote.head);
                }
                Some(head) => {
                    let meet = self.meet(head, &vote.head).unwrap_or(self.anchor);
                    heads.insert(vote.validator, meet);
                }
            }
        }
        heads.into_values().collect()
    }

    /// How many of `tips` each block at or above `Σ.F`'s depth is an ancestor
    /// of. A block absent from the map has no supporter.
    pub(crate) fn support_counts(&self, tips: &[H256]) -> HashMap<H256, u64> {
        let floor = self.depth(&self.finalized).unwrap_or(0);
        let mut counts: HashMap<H256, u64> = HashMap::new();
        for tip in tips {
            let mut cursor = Some(*tip);
            while let Some(root) = cursor {
                let Some(node) = self.node(&root) else {
                    break;
                };
                if node.depth < floor {
                    break;
                }
                *counts.entry(root).or_default() += 1;
                cursor = node.parent;
            }
        }
        counts
    }

    /// The fast unlock: before a fork-choice run over `votes` of `slot`, every
    /// lock that at least half of `𝒦_slot` opposes steps back to its deepest
    /// ancestor with fewer opponents than that, keeping its deadline. A lock
    /// that would step back past `Σ.F` is dropped.
    pub(crate) fn step_back_locks(&mut self, votes: &[GoldfishVote], slot: Slot) {
        let committee = self.committee_size(slot);
        if committee == 0 || self.locks.is_empty() {
            return;
        }
        let stances = self.stances(votes, slot);
        if !at_least_half(stances.len() as u64, committee) {
            // Fewer than half the committee spoke: nothing can be opposed by
            // half of it.
            return;
        }
        let support = self.support_counts(&stances);
        let voters = stances.len() as u64;
        let opposed = |block: &H256| {
            let supporters = support.get(block).copied().unwrap_or(0);
            at_least_half(voters - supporters, committee)
        };
        let locks: Vec<(H256, Slot)> = self.locks.iter().map(|(b, d)| (*b, *d)).collect();
        for (block, deadline) in locks {
            if !opposed(&block) {
                continue;
            }
            self.locks.remove(&block);
            let mut cursor = self.node(&block).and_then(|node| node.parent);
            while let Some(root) = cursor {
                if !self.is_ancestor(&self.finalized, &root) || root == self.finalized {
                    break;
                }
                if !opposed(&root) {
                    let entry = self.locks.entry(root).or_insert(deadline);
                    *entry = (*entry).max(deadline);
                    break;
                }
                cursor = self.node(&root).and_then(|node| node.parent);
            }
        }
    }

    /// The live locks at the current slot, deepest first.
    pub fn locks(&self) -> Vec<LockStatus> {
        let reading = self.slot.saturating_sub(1);
        let mut live: Vec<LockStatus> = self
            .locks
            .iter()
            .filter(|(_, deadline)| Self::lock_is_live(**deadline, reading))
            .filter_map(|(block, deadline)| {
                Some(LockStatus {
                    block: self.block_ref(block)?,
                    deadline: *deadline,
                })
            })
            .collect();
        live.sort_by(|a, b| {
            let (da, db) = (self.depth(&a.block.root), self.depth(&b.block.root));
            db.cmp(&da).then(b.block.root.cmp(&a.block.root))
        });
        live
    }

    /// Drop locks no walk can read any more: expired for every slot a duty
    /// still reads, or no longer strictly above `Σ.F`.
    pub(crate) fn prune_locks(&mut self) {
        let oldest_read = self.slot.saturating_sub(1);
        let finalized = self.finalized;
        let keep: HashSet<H256> = self
            .locks
            .iter()
            .filter(|(block, deadline)| {
                Self::lock_is_live(**deadline, oldest_read)
                    && **block != finalized
                    && self.is_ancestor(&finalized, block)
            })
            .map(|(block, _)| *block)
            .collect();
        self.locks.retain(|block, _| keep.contains(block));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{Params, slot_start};
    use crate::types::{BlockInput, Electorate};

    fn root(byte: u8) -> H256 {
        H256([byte; 32])
    }

    fn block(store: &mut Store, byte: u8, slot: Slot, parent: H256) -> H256 {
        let input = BlockInput {
            root: root(byte),
            parent_root: parent,
            slot,
            proposer: 0,
            votes: Vec::new(),
            support_votes: Vec::new(),
            attestations: Vec::new(),
        };
        store.on_block(&input).expect("admitted");
        input.root
    }

    fn vote(validator: u64, slot: Slot, head: H256) -> GoldfishVote {
        GoldfishVote {
            validator,
            slot,
            head,
        }
    }

    /// `G ← A ← B` and `A ← C`, all processed by slot 3.
    fn fork() -> (Store, [H256; 4]) {
        let genesis = H256::ZERO;
        let mut store = Store::from_genesis(Params::default(), Electorate::uniform(4), genesis);
        store.advance_to(slot_start(3));
        let a = block(&mut store, 1, 1, genesis);
        let b = block(&mut store, 2, 2, a);
        let c = block(&mut store, 3, 2, a);
        (store, [genesis, a, b, c])
    }

    #[test]
    fn half_a_committee_against_a_lock_steps_it_back() {
        let (mut store, [_, a, b, c]) = fork();
        store.form_lock(b, 2);
        // One of four against B: fewer than n/2, the lock holds.
        store.step_back_locks(&[vote(0, 2, c)], 2);
        assert_eq!(store.locks.get(&b), Some(&6));
        // Two of four: B steps back to A, the deepest ancestor C's voters
        // do not oppose, keeping its deadline.
        store.step_back_locks(&[vote(0, 2, c), vote(1, 2, c)], 2);
        assert_eq!(store.locks.get(&b), None);
        assert_eq!(store.locks.get(&a), Some(&6));
    }

    #[test]
    fn votes_for_a_descendant_do_not_oppose() {
        let (mut store, [_, a, b, _]) = fork();
        let d = block(&mut store, 4, 3, b);
        store.form_lock(b, 2);
        let votes: Vec<_> = (0..4).map(|v| vote(v, 3, d)).collect();
        store.step_back_locks(&votes, 3);
        assert_eq!(store.locks.get(&b), Some(&6));
        // Votes for an ancestor do not support the lock: half of them
        // step it back to that ancestor.
        let votes: Vec<_> = (0..2).map(|v| vote(v, 3, a)).collect();
        store.step_back_locks(&votes, 3);
        assert_eq!(store.locks.get(&a), Some(&6));
    }

    #[test]
    fn an_equivocator_opposes_what_its_votes_disagree_on() {
        let (mut store, [_, a, b, c]) = fork();
        store.form_lock(b, 2);
        // Validator 0 votes B and C: its stance is A, so it opposes B. With
        // validator 1 on C that is half the committee.
        store.step_back_locks(&[vote(0, 2, b), vote(0, 2, c), vote(1, 2, c)], 2);
        assert_eq!(store.locks.get(&a), Some(&6));
    }

    #[test]
    fn votes_for_unknown_heads_count_neither_way() {
        let (mut store, [_, _, b, _]) = fork();
        store.form_lock(b, 2);
        let unknown = root(0x77);
        store.step_back_locks(&[vote(0, 2, unknown), vote(1, 2, unknown)], 2);
        assert_eq!(store.locks.get(&b), Some(&6));
    }

    #[test]
    fn a_lock_anchors_walks_until_its_deadline() {
        let (mut store, [genesis, _, b, _]) = fork();
        store.form_lock(b, 2);
        let tree = store.filtered_tree(None);
        let deadline = 2 + store.params.lock_period;
        assert_eq!(store.anchor_in(&tree, deadline - 1), b);
        assert_eq!(store.anchor_in(&tree, deadline), genesis);
    }

    #[test]
    fn the_committee_size_sets_the_thresholds() {
        let (store, [_, _, b, c]) = fork();
        let mut store = store.with_committee_sizes(CommitteeSizes::fixed(6));
        store.form_lock(b, 2);
        // A committee of six needs three opponents.
        store.step_back_locks(&[vote(0, 2, c), vote(1, 2, c)], 2);
        assert_eq!(store.locks.get(&b), Some(&6));
        store.step_back_locks(&[vote(0, 2, c), vote(1, 2, c), vote(2, 2, c)], 2);
        assert_eq!(store.locks.get(&b), None);
    }
}
