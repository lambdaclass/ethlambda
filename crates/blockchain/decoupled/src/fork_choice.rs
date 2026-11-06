//! The fork choice over payload-aware nodes (fork-choice.md, "Helpers",
//! "Finality gadget" and the available chain's walks), with the gloas/heze
//! node helpers it builds on (`get_node_children`, `get_ancestor`,
//! `is_ancestor`, the payload tiebreaker).
//!
//! A block has a `Pending` node, whose children are its `Empty` node and, once
//! its payload is verified, its `Full` node; a child block hangs under the
//! parent node of the branch it builds on. A host without payloads therefore
//! walks `Pending → Empty → Pending → …`, with the `Empty` step always taken
//! (see `is_eligible_for_head_walk`).

use std::collections::{HashMap, HashSet};

use ethlambda_types::primitives::H256;

use crate::params::{GENESIS_SLOT, view_freeze};
use crate::store::Store;
use crate::types::{AcVote, ForkChoiceNode, PayloadStatus, Slot, Tick, ValidatorIndex};

/// `FGFrame`: the finality gadget's constraint on every available-chain walk.
#[derive(Debug, Clone)]
pub struct FgFrame {
    /// The finalized block's `Pending` node.
    pub finalized_node: ForkChoiceNode,
    /// The justified block's `Pending` node when the justification is the
    /// latest height and uncontested, else the finalized one.
    pub forkchoice_root: ForkChoiceNode,
    /// Every node of the finalized node's subtree.
    pub tree: HashSet<ForkChoiceNode>,
    /// The nodes of the tree under `forkchoice_root` whose block passes the
    /// height floor.
    pub viable_heads: HashSet<ForkChoiceNode>,
}

/// An AC view: a vote set and its supporting subset.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct View {
    pub votes: HashSet<AcVote>,
    pub support_votes: HashSet<AcVote>,
}

/// A walk's precomputed scores: a base every node gets, plus the seats marked
/// on each node by the supporters below it.
pub(crate) struct Scores {
    base: u64,
    support: HashMap<ForkChoiceNode, u64>,
}

impl Scores {
    pub(crate) fn score(&self, node: &ForkChoiceNode) -> u64 {
        self.base + self.support.get(node).copied().unwrap_or(0)
    }
}

/// `get_equivocating_indices(votes)`: validators with more than one distinct
/// vote.
pub fn get_equivocating_indices(votes: &HashSet<AcVote>) -> HashSet<ValidatorIndex> {
    let mut seen = HashSet::new();
    let mut equivocating = HashSet::new();
    for vote in votes {
        if !seen.insert(vote.validator_index) {
            equivocating.insert(vote.validator_index);
        }
    }
    equivocating
}

impl Store {
    // ── Nodes ──────────────────────────────────────────────────────────────

    /// `get_node_children(store, node)`.
    pub(crate) fn get_node_children(&self, node: &ForkChoiceNode) -> Vec<ForkChoiceNode> {
        let Some(block) = self.block(&node.root) else {
            return Vec::new();
        };
        match node.payload_status {
            PayloadStatus::Pending => {
                let mut children = vec![ForkChoiceNode::empty(node.root)];
                if self.is_payload_verified(&node.root) {
                    children.push(ForkChoiceNode::full(node.root));
                }
                children
            }
            status => block
                .children
                .iter()
                .filter(|child| {
                    self.block(child)
                        .is_some_and(|child| child.parent_payload_status == status)
                })
                .map(|child| ForkChoiceNode::pending(*child))
                .collect(),
        }
    }

    /// The node one step up from `node`: a block's `Pending` node above its
    /// `Empty` and `Full` ones, and the parent's branch above a `Pending` one.
    pub(crate) fn node_parent(&self, node: &ForkChoiceNode) -> Option<ForkChoiceNode> {
        match node.payload_status {
            PayloadStatus::Pending => {
                let block = self.block(&node.root)?;
                let parent = block.parent?;
                self.contains(&parent).then_some(ForkChoiceNode {
                    root: parent,
                    payload_status: block.parent_payload_status,
                })
            }
            _ => Some(ForkChoiceNode::pending(node.root)),
        }
    }

    /// `node` and every node above it whose block is at least `floor_depth`
    /// deep.
    pub(crate) fn node_ancestors(
        &self,
        node: ForkChoiceNode,
        floor_depth: u64,
    ) -> impl Iterator<Item = ForkChoiceNode> + '_ {
        std::iter::successors(Some(node), |current| self.node_parent(current)).take_while(
            move |current| {
                self.block(&current.root)
                    .is_some_and(|block| block.depth >= floor_depth)
            },
        )
    }

    /// `get_ancestor(store, node, slot)`: the node of `node`'s chain at the
    /// latest block of slot at most `slot`, with the payload branch the chain
    /// takes there.
    pub(crate) fn get_ancestor(&self, node: &ForkChoiceNode, slot: Slot) -> Option<ForkChoiceNode> {
        let mut current = *node;
        loop {
            let block = self.block(&current.root)?;
            if block.slot <= slot {
                return Some(current);
            }
            let parent = block.parent?;
            self.contains(&parent).then_some(())?;
            current = ForkChoiceNode {
                root: parent,
                payload_status: block.parent_payload_status,
            };
        }
    }

    /// `is_ancestor(store, node, ancestor)`: `ancestor` is `node` or above it,
    /// a `Pending` ancestor standing for either branch of its block.
    pub fn is_ancestor(&self, node: &ForkChoiceNode, ancestor: &ForkChoiceNode) -> bool {
        let Some(slot) = self.block_slot(&ancestor.root) else {
            return false;
        };
        let Some(at) = self.get_ancestor(node, slot) else {
            return false;
        };
        at.root == ancestor.root
            && (at.payload_status == ancestor.payload_status
                || ancestor.payload_status == PayloadStatus::Pending)
    }

    /// `get_deepest_node(store, nodes)`: the highest slot, `Empty`/`Full` over
    /// `Pending`. The spec leaves ties to Python's `max`; here they go to the
    /// greater root, then the greater payload status.
    pub(crate) fn get_deepest_node<'a>(
        &self,
        nodes: impl IntoIterator<Item = &'a ForkChoiceNode>,
    ) -> Option<ForkChoiceNode> {
        nodes
            .into_iter()
            .max_by_key(|node| {
                (
                    self.block_slot(&node.root).unwrap_or(0),
                    node.payload_status != PayloadStatus::Pending,
                    node.root,
                    node.payload_status,
                )
            })
            .copied()
    }

    /// `is_compatible(store, node_1, node_2)`: the two nodes lie on one chain.
    pub fn is_compatible(&self, a: &ForkChoiceNode, b: &ForkChoiceNode) -> bool {
        match self.get_deepest_node([a, b]) {
            Some(deepest) if deepest == *a => self.is_ancestor(a, b),
            _ => self.is_ancestor(b, a),
        }
    }

    /// `get_subtree(store, subtree_root)`.
    pub(crate) fn get_subtree(&self, root: &ForkChoiceNode) -> HashSet<ForkChoiceNode> {
        let mut subtree = HashSet::new();
        if !self.contains(&root.root) {
            return subtree;
        }
        let mut stack = vec![*root];
        while let Some(node) = stack.pop() {
            if subtree.insert(node) {
                stack.extend(self.get_node_children(&node));
            }
        }
        subtree
    }

    /// The roots of `root`'s block subtree, `root` included.
    pub(crate) fn block_subtree(&self, root: &H256) -> Vec<H256> {
        let mut found = Vec::new();
        let mut stack = vec![*root];
        while let Some(current) = stack.pop() {
            if let Some(block) = self.block(&current) {
                found.push(current);
                stack.extend(block.children.iter().copied());
            }
        }
        found
    }

    /// `get_block_and_payload_receipt_time(store, node)`.
    pub(crate) fn get_block_and_payload_receipt_time(&self, node: &ForkChoiceNode) -> Tick {
        let block = self.block(&node.root).map_or(Tick::MAX, |b| b.receipt_time);
        match node.payload_status {
            PayloadStatus::Full => {
                let payload = self
                    .payloads
                    .get(&node.root)
                    .map_or(Tick::MAX, |p| p.receipt_time);
                block.max(payload)
            }
            _ => block,
        }
    }

    // ── Payload decisions ──────────────────────────────────────────────────

    /// `is_previous_slot_payload_decision(store, node)`.
    pub(crate) fn is_previous_slot_payload_decision(&self, node: &ForkChoiceNode) -> bool {
        let is_previous_slot = self
            .block_slot(&node.root)
            .is_some_and(|slot| slot + 1 == self.current_slot());
        is_previous_slot && node.payload_status != PayloadStatus::Pending
    }

    /// `should_extend_payload(store, root)` (heze). EIP-8453's `on_block` no
    /// longer calls `update_proposer_boost_root`, so `proposer_boost_root`
    /// stays empty and the rule reduces to a verified payload that satisfies
    /// the inclusion list constraints.
    pub(crate) fn should_extend_payload(&self, root: &H256) -> bool {
        self.payloads
            .get(root)
            .is_some_and(|payload| payload.inclusion_list_satisfied)
    }

    /// `get_payload_status_tiebreaker(store, node)`.
    pub(crate) fn get_payload_status_tiebreaker(&self, node: &ForkChoiceNode) -> u8 {
        if self.is_previous_slot_payload_decision(node) {
            match node.payload_status {
                PayloadStatus::Empty => 1,
                _ if self.should_extend_payload(&node.root) => 2,
                _ => 0,
            }
        } else {
            node.payload_status.into()
        }
    }

    // ── Finality gadget ────────────────────────────────────────────────────

    /// `is_fg_contest(store)`: the maximum known height is one above the
    /// justified one, and a block at that height extends the finalized block
    /// but conflicts with the justified one.
    pub fn is_fg_contest(&self) -> bool {
        if self.max_height > self.justified_checkpoint.height + 1 {
            return false;
        }
        let justified = self.justified_checkpoint.root;
        self.block_subtree(&self.finalized_checkpoint.root)
            .iter()
            .any(|root| {
                self.block(root)
                    .is_some_and(|block| block.fg.target.height == self.max_height)
                    && !self.is_ancestor_root(root, &justified)
            })
    }

    /// `is_fg_viable_block(store, block_root)`, with `is_fg_contest` already
    /// evaluated: the height floor is `max_height` during a contest and
    /// `max_height - 1` otherwise.
    pub(crate) fn is_fg_viable_block(&self, root: &H256, contest: bool) -> bool {
        let Some(block) = self.block(root) else {
            return false;
        };
        let height = block.fg.target.height;
        if contest {
            height >= self.max_height
        } else {
            height + 1 >= self.max_height
        }
    }

    /// `has_viable_descendant(store, block_root)`.
    pub(crate) fn has_viable_descendant(&self, root: &H256) -> bool {
        let contest = self.is_fg_contest();
        self.block_subtree(root)
            .iter()
            .any(|descendant| self.is_fg_viable_block(descendant, contest))
    }

    /// `get_fg_frame(store)`.
    pub fn get_fg_frame(&self) -> FgFrame {
        let finalized_node = ForkChoiceNode::pending(self.finalized_checkpoint.root);
        let tree = self.get_subtree(&finalized_node);
        let contest = self.is_fg_contest();
        let forkchoice_block =
            if self.max_height == self.justified_checkpoint.height + 1 && !contest {
                self.justified_checkpoint.root
            } else {
                self.finalized_checkpoint.root
            };
        let forkchoice_root = ForkChoiceNode::pending(forkchoice_block);
        let under_root: HashSet<H256> = self.block_subtree(&forkchoice_block).into_iter().collect();
        let viable_heads = tree
            .iter()
            .filter(|node| {
                under_root.contains(&node.root) && self.is_fg_viable_block(&node.root, contest)
            })
            .copied()
            .collect();
        FgFrame {
            finalized_node,
            forkchoice_root,
            tree,
            viable_heads,
        }
    }

    /// `get_viable_subtree(store, fg_frame, tree)`: the nodes of `tree` under
    /// the forkchoice root that are ancestors of a viable head in `tree`.
    pub(crate) fn get_viable_subtree(
        &self,
        frame: &FgFrame,
        tree: &HashSet<ForkChoiceNode>,
    ) -> HashSet<ForkChoiceNode> {
        let root = frame.forkchoice_root;
        let Some(root_depth) = self.block(&root.root).map(|block| block.depth) else {
            return HashSet::new();
        };
        let mut viable = HashSet::new();
        for head in tree.intersection(&frame.viable_heads) {
            for node in self.node_ancestors(*head, root_depth) {
                if tree.contains(&node) && !viable.insert(node) {
                    // Already marked, and so is everything above it.
                    break;
                }
                if node == root {
                    break;
                }
            }
        }
        viable
    }

    // ── Walks ──────────────────────────────────────────────────────────────

    /// `compute_ghost_head(store, anchor, tree, get_score, is_eligible)`:
    /// descend from `anchor` through eligible children in `tree`, taking the
    /// highest `(score, root, payload tiebreaker)`.
    pub(crate) fn compute_ghost_head(
        &self,
        anchor: ForkChoiceNode,
        tree: &HashSet<ForkChoiceNode>,
        get_score: impl Fn(&ForkChoiceNode) -> u64,
        is_eligible: impl Fn(&ForkChoiceNode) -> bool,
    ) -> ForkChoiceNode {
        let mut head = anchor;
        loop {
            let best = self
                .get_node_children(&head)
                .into_iter()
                .filter(|child| tree.contains(child) && is_eligible(child))
                .max_by_key(|child| {
                    (
                        get_score(child),
                        child.root,
                        self.get_payload_status_tiebreaker(child),
                    )
                });
            match best {
                Some(child) => head = child,
                None => return head,
            }
        }
    }

    /// Mark `seats` on every supported node and its ancestors down to block
    /// depth `floor_depth`.
    fn mark_support(
        &self,
        supporters: impl IntoIterator<Item = (ForkChoiceNode, u64)>,
        floor_depth: u64,
    ) -> HashMap<ForkChoiceNode, u64> {
        let mut marks = HashMap::new();
        for (node, seats) in supporters {
            if seats == 0 || !self.contains(&node.root) {
                continue;
            }
            for ancestor in self.node_ancestors(node, floor_depth) {
                *marks.entry(ancestor).or_insert(0) += seats;
            }
        }
        marks
    }

    /// The seats of every distinct voter in `votes` (`voting_seats_count`).
    pub(crate) fn voting_seats_count(&self, votes: &HashSet<AcVote>, slot: Slot) -> u64 {
        let voters: HashSet<ValidatorIndex> = votes.iter().map(|v| v.validator_index).collect();
        voters
            .into_iter()
            .map(|validator| self.committees.seats(slot, validator))
            .sum()
    }

    /// `compute_head_walk_score` for every node at or below `floor`'s block:
    /// the equivocators' seats count for every node; a non-equivocator's seats
    /// count for the nodes its support vote of `slot` is at or below.
    pub(crate) fn head_walk_scores(
        &self,
        view: &View,
        slot: Slot,
        floor: &ForkChoiceNode,
    ) -> Scores {
        let equivocating = get_equivocating_indices(&view.votes);
        let base = equivocating
            .iter()
            .map(|validator| self.committees.seats(slot, *validator))
            .sum();
        let supporters = view
            .support_votes
            .iter()
            .filter(|vote| !equivocating.contains(&vote.validator_index) && vote.slot == slot)
            .map(|vote| {
                (
                    vote.supported_node,
                    self.committees.seats(slot, vote.validator_index),
                )
            });
        let floor_depth = self.block(&floor.root).map_or(0, |block| block.depth);
        Scores {
            base,
            support: self.mark_support(supporters, floor_depth),
        }
    }

    /// `compute_confirmation_score` for every node at or below `floor`'s
    /// block: only non-equivocators' support counts.
    pub(crate) fn confirmation_scores(
        &self,
        view: &View,
        slot: Slot,
        floor: &ForkChoiceNode,
    ) -> Scores {
        let equivocating = get_equivocating_indices(&view.votes);
        let supporters = view
            .support_votes
            .iter()
            .filter(|vote| !equivocating.contains(&vote.validator_index))
            .map(|vote| {
                (
                    vote.supported_node,
                    self.committees.seats(slot, vote.validator_index),
                )
            });
        let floor_depth = self.block(&floor.root).map_or(0, |block| block.depth);
        Scores {
            base: 0,
            support: self.mark_support(supporters, floor_depth),
        }
    }

    /// `is_eligible_for_head_walk`: a payload decision of the previous slot,
    /// a child of a block that is not a viable head, a block of the current
    /// slot, or a node whose score exceeds half the participating seats.
    pub(crate) fn is_eligible_for_head_walk(
        &self,
        frame: &FgFrame,
        scores: &Scores,
        voting_seats: u64,
        node: &ForkChoiceNode,
    ) -> bool {
        if self.is_previous_slot_payload_decision(node) {
            return true;
        }
        let Some(block) = self.block(&node.root) else {
            return false;
        };
        let parent_is_viable_head = block.parent.is_some_and(|parent| {
            frame
                .viable_heads
                .contains(&ForkChoiceNode::pending(parent))
        });
        if !parent_is_viable_head {
            return true;
        }
        if block.slot == self.current_slot() {
            return true;
        }
        2 * scores.score(node) > voting_seats
    }

    /// `get_head_walk_anchor(store, fg_frame)`: the deepest node of the full
    /// viable subtree at or above a live lock, else the forkchoice root.
    pub(crate) fn get_head_walk_anchor(&self, frame: &FgFrame) -> ForkChoiceNode {
        let viable = self.get_viable_subtree(frame, &frame.tree);
        let mut locked = HashSet::new();
        for (_, lock) in self.get_live_locks(frame, self.time) {
            for node in self.node_ancestors(lock, 0) {
                if viable.contains(&node) {
                    locked.insert(node);
                }
            }
        }
        self.get_deepest_node(&locked)
            .unwrap_or(frame.forkchoice_root)
    }

    /// `get_head_in_tree(store, fg_frame, tree, votes, support_votes, slot)`.
    pub(crate) fn get_head_in_tree(
        &self,
        frame: &FgFrame,
        tree: &HashSet<ForkChoiceNode>,
        view: &View,
        slot: Slot,
    ) -> ForkChoiceNode {
        let anchor = self.get_head_walk_anchor(frame);
        let viable_subtree = self.get_viable_subtree(frame, tree);
        let scores = self.head_walk_scores(view, slot, &anchor);
        let voting_seats = self.voting_seats_count(&view.votes, slot);
        self.compute_ghost_head(
            anchor,
            &viable_subtree,
            |node| scores.score(node),
            |node| self.is_eligible_for_head_walk(frame, &scores, voting_seats, node),
        )
    }

    /// `get_voter_subtree(store, tree, slot)`: the nodes received before the
    /// previous slot's view freeze, and the ancestors of `slot`'s proposals.
    pub(crate) fn get_voter_subtree(
        &self,
        tree: &HashSet<ForkChoiceNode>,
        slot: Slot,
    ) -> HashSet<ForkChoiceNode> {
        let freeze = view_freeze(slot.saturating_sub(1));
        let mut ancestors_of_proposals = HashSet::new();
        for proposal in tree
            .iter()
            .filter(|node| self.block_slot(&node.root) == Some(slot))
        {
            for node in self.node_ancestors(*proposal, 0) {
                if !ancestors_of_proposals.insert(node) {
                    break;
                }
            }
        }
        tree.iter()
            .filter(|node| {
                self.get_block_and_payload_receipt_time(node) < freeze
                    || ancestors_of_proposals.contains(node)
            })
            .copied()
            .collect()
    }

    /// `get_confirmed_head(store, fg_frame, votes, support_votes, slot)`: the
    /// confirmation walk from the finalized node over the whole frame, every
    /// step needing more than half the participating seats; `None` when the
    /// walk ends on a node without that support.
    pub(crate) fn get_confirmed_head(
        &self,
        frame: &FgFrame,
        view: &View,
        slot: Slot,
    ) -> Option<ForkChoiceNode> {
        let voting_seats = self.voting_seats_count(&view.votes, slot);
        let scores = self.confirmation_scores(view, slot, &frame.finalized_node);
        let is_eligible = |node: &ForkChoiceNode| 2 * scores.score(node) > voting_seats;
        let head = self.compute_ghost_head(
            frame.finalized_node,
            &frame.tree,
            |node| scores.score(node),
            is_eligible,
        );
        is_eligible(&head).then_some(head)
    }

    /// Whether `node`'s block is after genesis
    /// (`compute_confirmed_path_and_lock` excludes genesis).
    pub(crate) fn is_after_genesis(&self, node: &ForkChoiceNode) -> bool {
        self.block_slot(&node.root)
            .is_some_and(|slot| slot > GENESIS_SLOT)
    }
}
