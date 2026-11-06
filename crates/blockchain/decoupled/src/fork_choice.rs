//! The composed fork choice (PROTOCOL.md figure `alg:fc-full`, appendix A.5,
//! A.10): viability, the FG root, the filtered tree, the Goldfish score and
//! the GHOST walk from the SG root.

use std::collections::{HashMap, HashSet};

use ethlambda_types::primitives::H256;

use crate::store::Store;
use crate::types::{GoldfishVote, Slot, ValidatorIndex};

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
    /// `get_fg_root(Σ)`: `Σ.J` when `h_max = h_j + 1`, else `Σ.F`.
    pub fn fg_root(&self) -> H256 {
        if self.max_height == self.justified_height + 1 {
            self.justified
        } else {
            self.finalized
        }
    }

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

    /// `viable_tree(Σ) ∋ B`: `Σ.F ⪯ B` and some processed descendant of `B`
    /// has state height at least `h_max − 1`.
    pub(crate) fn is_viable(&self, block: &H256) -> bool {
        if !self.is_ancestor(&self.finalized, block) {
            return false;
        }
        let threshold = self.max_height.saturating_sub(1);
        self.subtree_max_heights(block, None)
            .get(block)
            .is_some_and(|&h| h >= threshold)
    }

    /// `get_filtered_block_tree_from(Σ, blocks)`: the viable blocks of the
    /// view that descend from the FG root, viability recomputed inside the
    /// view. `None` is the full processed tree.
    pub(crate) fn filtered_tree(&self, view: Option<&HashSet<H256>>) -> HashSet<H256> {
        let root = self.fg_root();
        let threshold = self.max_height.saturating_sub(1);
        // `Σ.F ⪯ root` always holds, so the descendants of the root are
        // descendants of `Σ.F`.
        self.subtree_max_heights(&root, view)
            .into_iter()
            .filter(|(_, h)| *h >= threshold)
            .map(|(block, _)| block)
            .collect()
    }

    /// The filtered tree over the full processed tree, for diagnostics.
    pub fn filtered_block_tree(&self) -> HashSet<H256> {
        self.filtered_tree(None)
    }

    /// Precompute `goldfish_score` over a vote view for slot `slot`.
    ///
    /// Supporters are the non-equivocators with a support vote of slot `slot`
    /// whose head is processed, of slot at most the vote's, and descends from
    /// the block; counts are marked down to `floor` (the walk's anchor), below
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
        tree: &HashSet<H256>,
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
                .filter(|child| tree.contains(child) && eligible(child))
                .max_by(|a, b| scores.score(a).cmp(&scores.score(b)).then(a.cmp(b)));
            match best {
                Some(child) => head = *child,
                None => return head,
            }
        }
    }

    /// `goldfish_eligible(Σ, votes, support_votes, s, B)`: a child of a block
    /// below the height band is eligible outright; otherwise it needs a
    /// majority, unless it is a current-slot proposal.
    pub(crate) fn goldfish_eligible(&self, scores: &Scores, block: &H256) -> bool {
        let Some(node) = self.node(block) else {
            return false;
        };
        let parent_height = node
            .parent
            .and_then(|parent| self.node(&parent))
            .map(|parent| parent.state.height)
            .unwrap_or(node.state.height);
        parent_height < self.max_height.saturating_sub(1)
            || scores.majority(block)
            || node.slot == self.slot
    }

    /// `get_head_in_tree(Σ, tree, votes, support_votes, k)`: the Goldfish walk
    /// from the SG root over `tree`.
    pub(crate) fn head_in_tree(&self, tree: &HashSet<H256>, view: &VoteView, slot: Slot) -> H256 {
        let anchor = self.sg_root();
        let scores = self.scores(view, slot, &anchor);
        self.ghost(anchor, tree, &scores, |block| {
            self.goldfish_eligible(&scores, block)
        })
    }

    /// `get_head(Σ, votes, support_votes, k)` over the full filtered tree.
    pub fn head_with(&self, view: &VoteView, slot: Slot) -> H256 {
        let tree = self.filtered_tree(None);
        self.head_in_tree(&tree, view, slot)
    }

    /// The pool's votes for `slot` as a view: every held vote, and the
    /// resolved ones as support (the proposer's view, `propose_block`).
    pub(crate) fn pool_view(&self, slot: Slot) -> VoteView {
        let votes = self.goldfish_votes(slot);
        let support = votes
            .iter()
            .filter(|vote| self.vote_resolves(vote))
            .copied()
            .collect();
        VoteView::new(votes, support)
    }

    /// The node's current fork-choice head: the walk a proposer at the next
    /// opportunity would take, over the latest slot that has votes.
    ///
    /// The protocol has no single "head"; this is what the host reports to
    /// users and to the execution layer.
    pub fn head(&self) -> H256 {
        let slot = self.slot;
        let current = self.pool_view(slot);
        if !current.votes.is_empty() {
            return self.head_with(&current, slot);
        }
        let previous = slot.saturating_sub(1);
        self.head_with(&self.pool_view(previous), previous)
    }
}
