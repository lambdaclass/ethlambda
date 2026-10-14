//! Goldilocks lock entries: how the available chain stays put across bounded
//! asynchrony (the specification's figure 7 and section 3.2).
//!
//! `𝒜.lock_entries` is a set of entries `(B, d)`, a block and a deadline. An
//! entry is *live* while `d > t` and `B ∈ Φ.tree`; a block is *locked* when
//! it is an ancestor of (or is) the block of a live entry. Every walk of a
//! duty starts at the *anchor*: the deepest locked block of the full viable
//! tree, or `Φ.fc_root` when there is none.
//!
//! | Rule | When | Effect |
//! |---|---|---|
//! | Write | the confirmation update of slot `s` confirms `C` and no live lock vetoes it | lock the deepest block on the path to `C` that passes the fast test (half of `𝒦_s` supports it) or the slow test (it is under the saved confirmations of the previous `k − 1` slots), until `t_{s+k} + 5Δ` |
//! | Revocation | at `t_s + Δ`, before the vote, against the slot-`(s − 1)` votes | each live entry moves back to the deepest ancestor that fewer than half of `𝒦_{s−1}` oppose |
//! | Expiry | the first tick at or after the deadline | the entry is removed |
//!
//! An opponent of `B'` is a validator with one resolved slot-`(s − 1)` vote
//! whose head conflicts with `B'`. A vote for an ancestor or a descendant of
//! `B'` does not oppose it, an equivocator never opposes, and a vote whose
//! head is not resolved counts neither way.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use ethlambda_types::primitives::H256;

use crate::params::slot_of;
use crate::store::Store;
use crate::types::{LockStatus, Slot, Tick, ValidatorIndex};

/// `|𝒦_s|` for every slot: the fast test and revocation are relative to the
/// whole committee, not to whoever voted, so the engine must know its size.
#[derive(Clone)]
pub struct CommitteeSizes(Arc<dyn Fn(Slot) -> u64 + Send + Sync>);

impl CommitteeSizes {
    pub fn new(size: impl Fn(Slot) -> u64 + Send + Sync + 'static) -> Self {
        Self(Arc::new(size))
    }

    /// The same committee size every slot: every validator, as Goldilocks
    /// specifies (`𝒦_s = V`).
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

    /// Add the entry `(block, deadline)`. Entries on one block keep the later
    /// deadline: they lock the same blocks, revocation moves them alike, and
    /// the earlier one expires first.
    pub(crate) fn add_lock_entry(&mut self, block: H256, deadline: Tick) {
        let entry = self.lock_entries.entry(block).or_insert(deadline);
        *entry = (*entry).max(deadline);
    }

    /// The live entries: `d > t` and `B ∈ Φ.tree`.
    pub(crate) fn live_entries(&self) -> impl Iterator<Item = (H256, Tick)> + '_ {
        let now = self.now();
        self.lock_entries
            .iter()
            .filter(move |(block, deadline)| {
                **deadline > now && self.is_ancestor(&self.finalized, block)
            })
            .map(|(block, deadline)| (*block, *deadline))
    }

    /// `get_anchor(𝒜, Φ, t)`: the deepest locked block of `viable` (the full
    /// viable tree), or `Φ.fc_root` when there is none. The locked blocks of
    /// an entry in the viable tree are a path from the root down, so its
    /// deepest one is the first viable block on the way up from the entry.
    pub(crate) fn get_anchor(&self, viable: &HashSet<H256>) -> H256 {
        let root_depth = self.depth(&self.frame.root).unwrap_or(0);
        let mut anchor: Option<H256> = None;
        for (block, _) in self.live_entries() {
            let mut cursor = Some(block);
            while let Some(current) = cursor {
                let Some(node) = self.node(&current) else {
                    break;
                };
                if node.depth < root_depth {
                    break;
                }
                if viable.contains(&current) {
                    if anchor.is_none_or(|best| self.deeper(&current, &best)) {
                        anchor = Some(current);
                    }
                    break;
                }
                cursor = node.parent;
            }
        }
        anchor.unwrap_or(self.frame.root)
    }

    /// `revoke_locks(𝒜, Φ, t, s)` at `t_s + Δ`, against every held slot-`(s
    /// − 1)` vote: each live entry moves back to the deepest non-genesis
    /// `B'` with `Φ.F ⪯ B' ⪯ B` that fewer than half of `𝒦_{s−1}` oppose,
    /// keeping its deadline, or is deleted when there is no such block.
    /// Entries that are not live are dropped.
    pub(crate) fn revoke_locks(&mut self, slot: Slot) {
        let Some(previous) = slot.checked_sub(1) else {
            return;
        };
        let votes = self.goldfish_votes(previous);
        let mut per_validator: HashMap<ValidatorIndex, usize> = HashMap::new();
        for vote in &votes {
            *per_validator.entry(vote.validator).or_default() += 1;
        }
        // Resolved heads of the non-equivocators. A resolved head is in the
        // tree; one strictly below `Φ.F` is compatible with every candidate,
        // so it can be kept without changing any count.
        let heads: Vec<H256> = votes
            .iter()
            .filter(|vote| per_validator[&vote.validator] == 1 && self.vote_resolves(vote))
            .map(|vote| vote.head)
            .collect();
        let committee = self.committee_size(previous);
        let floor_depth = self
            .depth(&self.finalized)
            .unwrap_or(0)
            .max(self.depth(&self.anchor).unwrap_or(0) + 1);

        let live: Vec<(H256, Tick)> = self.live_entries().collect();
        let mut entries: HashMap<H256, Tick> = HashMap::new();
        for (block, deadline) in live {
            let Some(depth) = self.depth(&block) else {
                continue;
            };
            // A head conflicts with the ancestor of `block` at depth `d`
            // exactly when it leaves `block`'s chain above `d`: its meet with
            // `block` is shallower than `d` and it is not itself on the chain.
            let branch_points: Vec<u64> = heads
                .iter()
                .filter(|head| !self.is_ancestor(head, &block))
                .filter_map(|head| self.meet_depth(head, &block))
                .collect();
            let opponents = |d: u64| branch_points.iter().filter(|&&m| m < d).count() as u64;
            // Opponents only grow with depth, so the deepest candidate is the
            // first one from the bottom that passes.
            let moved = (floor_depth..=depth)
                .rev()
                .find(|&d| 2 * opponents(d) < committee)
                .and_then(|d| self.ancestor_at_depth(&block, d));
            if let Some(moved) = moved {
                let entry = entries.entry(moved).or_insert(deadline);
                *entry = (*entry).max(deadline);
            }
        }
        self.lock_entries = entries;
    }

    /// The depth of the deepest common ancestor of two processed blocks.
    pub(crate) fn meet_depth(&self, a: &H256, b: &H256) -> Option<u64> {
        let depth = self.depth(a)?.min(self.depth(b)?);
        let mut x = self.ancestor_at_depth(a, depth)?;
        let mut y = self.ancestor_at_depth(b, depth)?;
        let mut depth = depth;
        while x != y {
            depth = depth.checked_sub(1)?;
            x = self.node(&x)?.parent?;
            y = self.node(&y)?.parent?;
        }
        Some(depth)
    }

    /// The live lock entries, deepest first, with each deadline given as the
    /// slot at whose vote time it expires.
    pub fn locks(&self) -> Vec<LockStatus> {
        let mut live: Vec<LockStatus> = self
            .live_entries()
            .filter_map(|(block, deadline)| {
                Some(LockStatus {
                    block: self.block_ref(&block)?,
                    deadline: slot_of(deadline),
                })
            })
            .collect();
        live.sort_by(|a, b| {
            let (da, db) = (self.depth(&a.block.root), self.depth(&b.block.root));
            db.cmp(&da).then(b.block.root.cmp(&a.block.root))
        });
        live
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{Params, slot_start, vote_time};
    use crate::types::{BlockInput, Electorate, GoldfishVote};

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

    const FAR: Tick = 1000;

    /// `G ← A ← B` and `A ← C`, all processed by slot 3, with the slot-2
    /// votes `votes` held.
    fn fork(votes: &[GoldfishVote]) -> (Store, [H256; 4]) {
        let genesis = H256::ZERO;
        let mut store = Store::from_genesis(Params::default(), Electorate::uniform(4), genesis);
        store.advance_to(slot_start(2));
        let a = block(&mut store, 1, 1, genesis);
        let b = block(&mut store, 2, 2, a);
        let c = block(&mut store, 3, 2, a);
        for v in votes {
            store.on_goldfish_vote(*v);
        }
        store.advance_to(slot_start(3));
        (store, [genesis, a, b, c])
    }

    fn revoke(store: &mut Store) {
        store.revoke_locks(3);
    }

    #[test]
    fn half_a_committee_against_a_lock_moves_it_back() {
        let c = root(3);
        let (mut store, [_, a, b, _]) = fork(&[vote(0, 2, c)]);
        store.add_lock_entry(b, FAR);
        // One of four against B: fewer than n/2, the entry stays.
        revoke(&mut store);
        assert_eq!(store.lock_entries.get(&b), Some(&FAR));

        let (mut store, _) = fork(&[vote(0, 2, c), vote(1, 2, c)]);
        store.add_lock_entry(b, FAR);
        // Two of four: B moves back to A, which C's voters do not oppose,
        // keeping its deadline.
        revoke(&mut store);
        assert_eq!(store.lock_entries.get(&b), None);
        assert_eq!(store.lock_entries.get(&a), Some(&FAR));
    }

    #[test]
    fn votes_for_an_ancestor_or_a_descendant_do_not_oppose() {
        let a = root(1);
        let (mut store, [_, _, b, _]) = fork(&[vote(0, 2, a), vote(1, 2, a), vote(2, 2, a)]);
        store.add_lock_entry(b, FAR);
        revoke(&mut store);
        assert_eq!(store.lock_entries.get(&b), Some(&FAR));
    }

    #[test]
    fn equivocators_never_oppose() {
        let (b, c) = (root(2), root(3));
        let (mut store, _) = fork(&[
            vote(0, 2, c),
            vote(0, 2, b),
            vote(1, 2, c),
            vote(1, 2, b),
            vote(2, 2, c),
        ]);
        store.add_lock_entry(b, FAR);
        // Validators 0 and 1 equivocate; only validator 2 opposes B.
        revoke(&mut store);
        assert_eq!(store.lock_entries.get(&b), Some(&FAR));
    }

    #[test]
    fn votes_for_unknown_heads_count_neither_way() {
        let unknown = root(0x77);
        let (mut store, [_, _, b, _]) = fork(&[vote(0, 2, unknown), vote(1, 2, unknown)]);
        store.add_lock_entry(b, FAR);
        revoke(&mut store);
        assert_eq!(store.lock_entries.get(&b), Some(&FAR));
    }

    #[test]
    fn an_entry_with_no_unopposed_ancestor_is_deleted() {
        // Every non-genesis ancestor of B is opposed by votes for a sibling
        // of A.
        let genesis = H256::ZERO;
        let mut store = Store::from_genesis(Params::default(), Electorate::uniform(4), genesis);
        store.advance_to(slot_start(2));
        let a = block(&mut store, 1, 1, genesis);
        let b = block(&mut store, 2, 2, a);
        let d = block(&mut store, 4, 2, genesis);
        store.on_goldfish_vote(vote(0, 2, d));
        store.on_goldfish_vote(vote(1, 2, d));
        store.advance_to(slot_start(3));
        store.add_lock_entry(b, FAR);
        revoke(&mut store);
        assert!(store.lock_entries.is_empty());
    }

    #[test]
    fn the_committee_size_sets_the_threshold() {
        let c = root(3);
        let (store, [_, _, b, _]) = fork(&[vote(0, 2, c), vote(1, 2, c)]);
        let mut store = store.with_committee_sizes(CommitteeSizes::fixed(6));
        store.add_lock_entry(b, FAR);
        // A committee of six needs three opponents.
        revoke(&mut store);
        assert_eq!(store.lock_entries.get(&b), Some(&FAR));
    }

    #[test]
    fn an_entry_expires_at_its_deadline() {
        let (mut store, [genesis, _, b, _]) = fork(&[]);
        let deadline = vote_time(5);
        store.add_lock_entry(b, deadline);
        let viable = store.viable_tree(None);
        assert_eq!(store.get_anchor(&viable), b);
        store.advance_to(deadline - 1);
        assert_eq!(store.get_anchor(&viable), b);
        store.advance_to(deadline);
        assert_eq!(store.get_anchor(&viable), genesis);
    }

    #[test]
    fn the_anchor_is_the_deepest_viable_ancestor_of_an_entry() {
        let (mut store, [_, a, b, _]) = fork(&[]);
        store.add_lock_entry(b, FAR);
        // Without B in the tree the anchor walks up to A.
        let mut viable = store.viable_tree(None);
        viable.remove(&b);
        assert_eq!(store.get_anchor(&viable), a);
    }
}
