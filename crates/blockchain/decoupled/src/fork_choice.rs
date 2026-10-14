//! The available chain's fork choice inside the FG frame (the
//! specification's figure 8): the viable tree, the Goldfish score and
//! eligibility, and the GHOST walk from the anchor.
//!
//! ```text
//! blocks ─▶ state transition ─▶ F, J, h_max ─▶ frame ─▶ viable tree ─┐
//!                                  lock entries ─▶ anchor ────────────┼─▶ walk ─▶ head
//!                                 Goldfish votes ─▶ scores ───────────┘
//! ```
//!
//! Locks give the anchor, votes give the walk. Network attestations are not
//! an input: they reach the fork choice only through the chain states of the
//! blocks that carry them.

use std::collections::{HashMap, HashSet};

use ethlambda_types::primitives::H256;

use crate::store::Store;
use crate::types::{BlockRef, GoldfishVote, Slot, ValidatorIndex};

/// The vote sets a Goldfish walk reads: `votes` decides participation and
/// equivocation, `support_votes ⊆ votes` decides subtree support.
#[derive(Debug, Clone, Default)]
pub struct VoteView {
    pub votes: Vec<GoldfishVote>,
    pub support_votes: Vec<GoldfishVote>,
}

impl VoteView {
    pub fn new(mut votes: Vec<GoldfishVote>, mut support_votes: Vec<GoldfishVote>) -> Self {
        votes.sort();
        votes.dedup();
        support_votes.sort();
        support_votes.dedup();
        Self {
            votes,
            support_votes,
        }
    }
}

/// `goldfish_score(votes, support_votes, s, ·)` for every block, plus the
/// participant count, precomputed once per walk.
pub(crate) struct Scores {
    equivocators: u64,
    pub(crate) voters: u64,
    support: HashMap<H256, u64>,
}

impl Scores {
    pub(crate) fn score(&self, block: &H256) -> u64 {
        self.equivocators + self.support.get(block).copied().unwrap_or(0)
    }

    /// `2 · score(B) > voters_count`.
    pub(crate) fn majority(&self, block: &H256) -> bool {
        2 * self.score(block) > self.voters
    }
}

impl Store {
    /// For every descendant of `root` inside `view` (all of `Σ.𝒯` when
    /// `None`), the largest chain-state height in its subtree within `view`.
    /// `view` must be parent-closed, which both views the protocol uses are.
    fn subtree_max_heights(&self, root: &H256, view: Option<&HashSet<H256>>) -> HashMap<H256, u64> {
        let mut result = HashMap::new();
        let in_view = |block: &H256| view.is_none_or(|v| v.contains(block));
        if !self.contains(root) || !in_view(root) {
            return result;
        }
        // Iterative post-order.
        let mut stack = vec![(*root, false)];
        while let Some((block, expanded)) = stack.pop() {
            let node = &self.blocks[&block];
            if expanded {
                let best = node
                    .children
                    .iter()
                    .filter_map(|child| result.get(child).copied())
                    .fold(node.state.height, u64::max);
                result.insert(block, best);
            } else {
                stack.push((block, true));
                for child in &node.children {
                    if in_view(child) {
                        stack.push((*child, false));
                    }
                }
            }
        }
        result
    }

    /// `has_viable_descendant(Σ, B)`: some processed `B'` with `B ⪯ B'` has
    /// state height at least the head height floor.
    pub(crate) fn has_viable_descendant(&self, block: &H256) -> bool {
        let floor = self.frame.floor;
        self.subtree_max_heights(block, None)
            .get(block)
            .is_some_and(|&h| h >= floor)
    }

    /// `viable_tree(Φ, tree)`: the blocks of `tree` (all of `Φ.tree` when
    /// `None`) that extend `Φ.fc_root` and have a viable head in `tree` among
    /// their descendants.
    pub(crate) fn viable_tree(&self, view: Option<&HashSet<H256>>) -> HashSet<H256> {
        let frame = self.frame;
        self.subtree_max_heights(&frame.root, view)
            .into_iter()
            .filter(|(_, h)| *h >= frame.floor)
            .map(|(block, _)| block)
            .collect()
    }

    /// The full viable tree `viable_tree(Φ, Φ.tree)`, for diagnostics.
    pub fn viable_block_tree(&self) -> HashSet<H256> {
        self.viable_tree(None)
    }

    /// Precompute `goldfish_score` over a vote view for slot `slot`.
    ///
    /// Supporters are the non-equivocators with a support vote of slot `slot`
    /// whose head is processed, of slot at most the vote's, and descends from
    /// the block; counts are marked down to `floor` (the walk's start), below
    /// which the walk never asks.
    pub(crate) fn scores(&self, view: &VoteView, slot: Slot, floor: &H256) -> Scores {
        let mut per_validator: HashMap<ValidatorIndex, usize> = HashMap::new();
        for vote in &view.votes {
            *per_validator.entry(vote.validator).or_default() += 1;
        }
        let equivocating: HashSet<ValidatorIndex> = per_validator
            .iter()
            .filter(|(_, count)| **count >= 2)
            .map(|(validator, _)| *validator)
            .collect();
        let floor_depth = self.depth(floor).unwrap_or(0);

        let mut support: HashMap<H256, u64> = HashMap::new();
        let mut counted: HashSet<ValidatorIndex> = HashSet::new();
        for vote in &view.support_votes {
            if vote.slot != slot || equivocating.contains(&vote.validator) {
                continue;
            }
            // A non-equivocator holds one vote; count it once.
            if !counted.insert(vote.validator) {
                continue;
            }
            let Some(head) = self.node(&vote.head) else {
                continue;
            };
            if head.slot > vote.slot {
                continue;
            }
            let mut cursor = vote.head;
            loop {
                let node = &self.blocks[&cursor];
                if node.depth < floor_depth {
                    break;
                }
                *support.entry(cursor).or_default() += 1;
                match node.parent {
                    Some(parent) => cursor = parent,
                    None => break,
                }
            }
        }
        Scores {
            equivocators: equivocating.len() as u64,
            voters: per_validator.len() as u64,
            support,
        }
    }

    /// `ghost(anchor, tree, score, eligible)`: descend from `anchor` through
    /// eligible children in `tree`, taking the highest score, ties to the
    /// greater root, and stop where no child is eligible. The anchor itself
    /// need not be in `tree`.
    pub(crate) fn ghost(
        &self,
        anchor: H256,
        in_tree: impl Fn(&H256) -> bool,
        scores: &Scores,
        eligible: impl Fn(&H256) -> bool,
    ) -> H256 {
        let mut head = anchor;
        loop {
            let Some(node) = self.node(&head) else {
                return head;
            };
            let best = node
                .children
                .iter()
                .filter(|child| in_tree(child) && eligible(child))
                .max_by(|a, b| scores.score(a).cmp(&scores.score(b)).then(a.cmp(b)));
            match best {
                Some(child) => head = *child,
                None => return head,
            }
        }
    }

    /// `goldfish_eligible(Φ, t, votes, support_votes, s, B)`: a child of a
    /// block that is not a viable head is eligible outright, and so is a
    /// block of the current slot; otherwise it needs a strict majority of the
    /// voters.
    ///
    /// Every head walk starts at `Φ.fc_root` or below it, so a parent the
    /// walk reaches extends the root, and a viable head is a parent whose
    /// state height reaches the floor.
    pub(crate) fn goldfish_eligible(&self, scores: &Scores, block: &H256) -> bool {
        let Some(node) = self.node(block) else {
            return false;
        };
        let parent_is_viable_head = node
            .parent
            .and_then(|parent| self.node(&parent))
            .is_some_and(|parent| parent.state.height >= self.frame.floor);
        !parent_is_viable_head || node.slot == self.slot || scores.majority(block)
    }

    /// `get_head_in_tree(𝒜, Φ, t, tree, votes, support_votes, s)`: the
    /// Goldfish walk over `tree` and the votes of `slot`, from the anchor of
    /// the full viable tree.
    pub(crate) fn head_in_tree(&self, tree: &HashSet<H256>, view: &VoteView, slot: Slot) -> H256 {
        let anchor = self.get_anchor(&self.viable_tree(None));
        let scores = self.scores(view, slot, &anchor);
        self.ghost(
            anchor,
            |block| tree.contains(block),
            &scores,
            |block| self.goldfish_eligible(&scores, block),
        )
    }

    /// `get_head(𝒜, Φ, t, votes, support_votes, s)`: the walk over the full
    /// viable tree.
    pub fn head_with(&self, view: &VoteView, slot: Slot) -> H256 {
        let tree = self.viable_tree(None);
        self.head_in_tree(&tree, view, slot)
    }

    /// The pool's votes for `slot` as a view: every held vote, and the
    /// resolved ones as support.
    pub(crate) fn pool_view(&self, slot: Slot) -> VoteView {
        let votes = self.goldfish_votes(slot);
        let support = votes
            .iter()
            .filter(|vote| self.vote_resolves(vote))
            .copied()
            .collect();
        VoteView::new(votes, support)
    }

    /// The slot whose votes [`Store::head`] reads: the current slot once it
    /// has votes, else the previous one.
    fn head_slot(&self) -> Slot {
        let slot = self.slot;
        if self
            .gf_votes
            .get(&slot)
            .is_some_and(|pool| !pool.is_empty())
        {
            slot
        } else {
            slot.saturating_sub(1)
        }
    }

    /// The node's current head, for users and the execution layer: the walk
    /// over the latest slot that has votes. The FG action reads its own head
    /// (the walk over the current slot's votes at `a_r`).
    pub fn head(&self) -> H256 {
        let slot = self.head_slot();
        self.head_with(&self.pool_view(slot), slot)
    }

    /// `AC_CONFIRMED(𝒜, Φ)`: the available tip. The confirmation record when
    /// it is still in `Φ.tree`, else `Φ.F`.
    pub fn confirmed(&self) -> BlockRef {
        let root = if self.is_ancestor(&self.finalized, &self.latest_confirmed) {
            self.latest_confirmed
        } else {
            self.finalized
        };
        self.block_ref(&root)
            .expect("the record is in the tree or is F")
    }
}
