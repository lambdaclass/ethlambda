//! The cumulative node store Σ and its handlers.
//!
//! The store keeps messages and their receipt stamps, the processed block tree
//! with every block's chain state, the finality caches, the fork-choice frame
//! the finality gadget imposes, and the available chain's locks. Views,
//! filtered trees and scores are derived when used, from stamps compared
//! against past instants.
//!
//! # Trust boundary
//!
//! The engine checks what the protocol's handlers check. It does not verify
//! signatures, committee membership or the proposer schedule: those depend on
//! each chain's keys and shuffling, so the host checks them before it calls a
//! handler.

use std::collections::{BTreeMap, HashMap, VecDeque};

use ethlambda_types::primitives::H256;

use crate::chain_state::{ChainState, state_transition};
use crate::locks::CommitteeSizes;
use crate::params::{Params, confirmation_time, slot_of, slot_start, support_cutoff};
use crate::types::{
    Attestation, AttestationData, BlockInput, BlockRef, Electorate, GoldfishVote, Height, Slot,
    Tick, ValidatorIndex,
};

/// The stamp of the anchor block: `Σ.timestamp(B_gen) = −∞`.
pub const ANCHOR_STAMP: Tick = Tick::MIN;

/// Attestations the pool keeps per validator. An honest validator attests
/// once per height on its chain, plus once per reorg to another entry and
/// once per new justification to finalize, so a handful covers every
/// attestation still useful; past it the oldest is evicted, which only ever
/// costs the sender itself.
pub const MAX_POOLED_ATTESTATIONS_PER_VALIDATOR: usize = 8;

/// One processed block.
#[derive(Debug, Clone)]
pub(crate) struct Node {
    pub(crate) parent: Option<H256>,
    pub(crate) slot: Slot,
    /// Parent edges from the anchor.
    pub(crate) depth: u64,
    /// `Σ.timestamp(B)`.
    pub(crate) stamp: Tick,
    /// `Σ.σ[B]`.
    pub(crate) state: ChainState,
    pub(crate) votes: Vec<GoldfishVote>,
    pub(crate) support_votes: Vec<GoldfishVote>,
    pub(crate) children: Vec<H256>,
}

#[derive(Debug, Clone)]
pub(crate) struct PooledVote {
    pub(crate) vote: GoldfishVote,
    pub(crate) stamp: Tick,
}

/// Why `on_block` refused a block. Only [`BlockError::FutureSlot`] and
/// [`BlockError::UnknownParent`] are transient: the same block can be offered
/// again once the clock or the tree has moved.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BlockError {
    #[error("block slot {slot} is after the current slot {current}")]
    FutureSlot { slot: Slot, current: Slot },
    #[error("block already processed")]
    Duplicate,
    #[error("parent {0:?} not processed")]
    UnknownParent(H256),
    #[error("block does not descend from the finalized block")]
    NotDescendantOfFinalized,
    #[error("block slot {slot} is not after its parent's slot {parent_slot}")]
    SlotNotAfterParent { slot: Slot, parent_slot: Slot },
    #[error("carried vote of slot {vote_slot} in a block of slot {slot}")]
    VoteOfWrongSlot { vote_slot: Slot, slot: Slot },
    #[error("support vote not among the carried votes")]
    SupportNotSubset,
}

/// What a tick asks the host to do. The store side of the tick (clock, fast
/// unlocks, the confirmation update and its locks) has already run when this
/// is returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TickEvents {
    pub tick: Tick,
    pub slot: Slot,
    /// `t = t_s`, `s > 0`: the slot's proposer builds its block now.
    pub propose: bool,
    /// `t = t_s + Δ`, `s > 0`: committee members cast their Goldfish vote.
    pub vote: bool,
    /// `t = t_s + 2Δ`, `s > 0`, right after the confirmation update of slot
    /// `s − 1`: every validator reads its attestation input and attests if
    /// it has something new to say.
    pub attest: bool,
}

/// The fork-choice frame the finality gadget imposes on the available chain:
/// the walk stays inside the descendants of `root` whose subtree reaches
/// height `floor`.
///
/// ```text
/// J at h_max − 1?   a block at h_max not on J?   root   floor
/// no                —                            F      h_max − 1
/// yes               no                           J      h_max − 1
/// yes               yes (a contest)              F      h_max
/// ```
///
/// A contest never goes away: once a block at `h_max` that does not extend
/// `J` is seen, that `J` is spent for this `h_max`, even if finality later
/// prunes the contesting branch. So each height changes the frame at most
/// twice (J revealed, then contested) before it rises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame {
    pub root: H256,
    pub floor: Height,
}

/// The decoupled-consensus store Σ.
#[derive(Debug, Clone)]
pub struct Store {
    pub(crate) params: Params,
    pub(crate) electorate: Electorate,
    /// `Σ.t`: the last tick run, `None` before the first.
    pub(crate) time: Option<Tick>,
    /// `Σ.s`.
    pub(crate) slot: Slot,
    pub(crate) anchor: H256,
    /// `Σ.𝒯` with `Σ.σ[·]` and `Σ.timestamp[·]` of blocks.
    pub(crate) blocks: HashMap<H256, Node>,
    /// The finalized block's ancestors, indexed by depth, for O(1) ancestry
    /// below `Σ.F`.
    pub(crate) finalized_chain: Vec<H256>,
    /// `Σ.gf_votes[·]`.
    pub(crate) gf_votes: BTreeMap<Slot, Vec<PooledVote>>,
    /// Attestations waiting to be carried by a block, by validator, oldest
    /// first. They feed proposals only: the fork choice reads attestations
    /// through the chain states of blocks, never from the network.
    pub(crate) attestations: HashMap<ValidatorIndex, Vec<Attestation>>,
    /// `|𝒦_s|`.
    pub(crate) committee_sizes: CommitteeSizes,
    /// `Σ.F`, and the height at which it was justified (`σ.h_F` of the
    /// chain state that finalized it).
    pub(crate) finalized: H256,
    pub(crate) finalized_height: Height,
    /// `Σ.J`, `Σ.h_j`.
    pub(crate) justified: H256,
    pub(crate) justified_height: Height,
    /// `Σ.h_max`.
    pub(crate) max_height: Height,
    /// The fork-choice frame, refreshed whenever a block is processed.
    pub(crate) frame: Frame,
    /// The `(h_max, J)` the frame last evaluated in full.
    pub(crate) frame_key: Option<(Height, H256)>,
    /// The `(h_max, J)` a contest has spent.
    pub(crate) contested: Option<(Height, H256)>,
    /// Locked blocks and their deadlines.
    pub(crate) locks: HashMap<H256, Slot>,
    /// The deepest block the latest confirmation update fast locked.
    pub(crate) fg_confirmed: Option<H256>,
    /// The latest confirmation updates, oldest first, at most `k` of them:
    /// the slot and the block it confirmed, if any.
    pub(crate) confirmations: VecDeque<(Slot, Option<H256>)>,
}

impl Store {
    /// A store anchored at `anchor` (genesis, or the block the protocol starts
    /// from), whose post-state is `anchor_state`.
    ///
    /// Everything below the anchor is out of the store's view: the anchor is
    /// `B_gen` of the formal model, with stamp `−∞`.
    pub fn new(
        params: Params,
        electorate: Electorate,
        anchor: BlockRef,
        anchor_state: ChainState,
    ) -> Self {
        let root = anchor.root;
        let node = Node {
            parent: None,
            slot: anchor.slot,
            depth: 0,
            stamp: ANCHOR_STAMP,
            state: anchor_state,
            votes: Vec::new(),
            support_votes: Vec::new(),
            children: Vec::new(),
        };
        let committee_sizes = CommitteeSizes::fixed(electorate.len() as u64);
        let mut store = Self {
            params,
            electorate,
            time: None,
            slot: anchor.slot,
            anchor: root,
            blocks: HashMap::from([(root, node)]),
            finalized_chain: vec![root],
            gf_votes: BTreeMap::new(),
            attestations: HashMap::new(),
            committee_sizes,
            finalized: root,
            finalized_height: 0,
            justified: root,
            justified_height: 0,
            max_height: 1,
            frame: Frame { root, floor: 0 },
            frame_key: None,
            contested: None,
            locks: HashMap::new(),
            fg_confirmed: None,
            confirmations: VecDeque::new(),
        };
        store.refresh_frame(None);
        store
    }

    /// A store anchored at genesis with the initial chain state.
    pub fn from_genesis(params: Params, electorate: Electorate, genesis_root: H256) -> Self {
        let anchor = BlockRef {
            root: genesis_root,
            slot: 0,
        };
        let state = ChainState::initial(anchor, electorate.len());
        Self::new(params, electorate, anchor, state)
    }

    pub fn params(&self) -> &Params {
        &self.params
    }

    pub fn electorate(&self) -> &Electorate {
        &self.electorate
    }

    /// `Σ.t`, the last tick run.
    pub fn time(&self) -> Option<Tick> {
        self.time
    }

    /// `Σ.s`.
    pub fn current_slot(&self) -> Slot {
        self.slot
    }

    /// The stamp an object processed now receives.
    pub(crate) fn now(&self) -> Tick {
        self.time.unwrap_or(ANCHOR_STAMP)
    }

    // ── Clock ──────────────────────────────────────────────────────────────

    /// Run every public tick up to and including `now`, in order, and return
    /// the duties each one asks for. A store that has never ticked runs only
    /// `now`: a node that joins does not replay the past.
    ///
    /// Call this before every handler, with the current wall-clock tick, so an
    /// object is stamped after the tick of its own instant.
    pub fn advance_to(&mut self, now: Tick) -> Vec<TickEvents> {
        let first = match self.time {
            Some(last) if now <= last => return Vec::new(),
            Some(last) => last + 1,
            None => now,
        };
        (first..=now).map(|t| self.on_tick(t)).collect()
    }

    /// One public tick, store side.
    ///
    /// Advances the clock, then: at `t_s` and `t_s + Δ` steps locks back
    /// before the proposer's and the voters' fork choice (each over the view
    /// that run reads), and at `t_s + 2Δ` runs the confirmation update of
    /// slot `s − 1`. Proposals, votes and attestations need the host's keys,
    /// so they come back as [`TickEvents`]; the host runs them, in that order,
    /// against the store as this call leaves it.
    pub fn on_tick(&mut self, t: Tick) -> TickEvents {
        let slot = slot_of(t);
        self.time = Some(t);
        self.slot = slot;
        self.prune();

        let start = slot_start(slot);
        let propose = slot > 0 && t == start;
        let vote = slot > 0 && t == start + 1;
        let attest = slot > 0 && t == support_cutoff(slot);
        if propose {
            let votes = self.goldfish_votes(slot - 1);
            self.step_back_locks(&votes, slot - 1);
        }
        if vote {
            let view = self.voter_view(slot);
            self.step_back_locks(&view.votes, slot - 1);
        }
        if attest {
            self.update_confirmation(slot - 1);
        }
        TickEvents {
            tick: t,
            slot,
            propose,
            vote,
            attest,
        }
    }

    /// Discard what no rule can read any more: Goldfish votes older than the
    /// previous slot (votes that old are refused on arrival and read by no
    /// duty), expired locks, and attestations that can no longer count on
    /// any viable chain.
    fn prune(&mut self) {
        let oldest_slot = self.slot.saturating_sub(1);
        self.gf_votes = self.gf_votes.split_off(&oldest_slot);
        self.prune_locks();
        let (max_height, finalized_height) = (self.max_height, self.finalized_height);
        self.attestations.retain(|_, pooled| {
            pooled.retain(|attestation| useful(&attestation.data, max_height, finalized_height));
            !pooled.is_empty()
        });
    }

    // ── Ancestry ───────────────────────────────────────────────────────────

    pub fn contains(&self, root: &H256) -> bool {
        self.blocks.contains_key(root)
    }

    pub(crate) fn node(&self, root: &H256) -> Option<&Node> {
        self.blocks.get(root)
    }

    pub(crate) fn depth(&self, root: &H256) -> Option<u64> {
        self.blocks.get(root).map(|node| node.depth)
    }

    pub fn block_slot(&self, root: &H256) -> Option<Slot> {
        self.blocks.get(root).map(|node| node.slot)
    }

    pub fn block_ref(&self, root: &H256) -> Option<BlockRef> {
        self.block_slot(root)
            .map(|slot| BlockRef { root: *root, slot })
    }

    /// `Σ.σ[B]`.
    pub fn chain_state(&self, root: &H256) -> Option<&ChainState> {
        self.blocks.get(root).map(|node| &node.state)
    }

    /// The parent of a processed block.
    pub fn parent(&self, root: &H256) -> Option<H256> {
        self.blocks.get(root).and_then(|node| node.parent)
    }

    /// The ancestor of `root` at `depth`, or `None` when `root` is unknown or
    /// shallower than `depth`.
    pub(crate) fn ancestor_at_depth(&self, root: &H256, depth: u64) -> Option<H256> {
        let mut current = *root;
        let mut node = self.blocks.get(&current)?;
        if node.depth < depth {
            return None;
        }
        loop {
            if node.depth == depth {
                return Some(current);
            }
            // Below the finalized block the chain is indexed: jump.
            if let Some(&on_chain) = self.finalized_chain.get(node.depth as usize)
                && on_chain == current
            {
                return self.finalized_chain.get(depth as usize).copied();
            }
            current = node.parent?;
            node = self.blocks.get(&current)?;
        }
    }

    /// `B ⪯ C`: `B = C` or `B` is an ancestor of `C`. Unknown blocks are
    /// ancestors of nothing.
    pub fn is_ancestor(&self, ancestor: &H256, descendant: &H256) -> bool {
        let Some(depth) = self.depth(ancestor) else {
            return false;
        };
        self.ancestor_at_depth(descendant, depth) == Some(*ancestor)
    }

    /// Two blocks are compatible when one is an ancestor of the other.
    pub fn compatible(&self, a: &H256, b: &H256) -> bool {
        self.is_ancestor(a, b) || self.is_ancestor(b, a)
    }

    /// The deepest common ancestor of two processed blocks.
    pub(crate) fn meet(&self, a: &H256, b: &H256) -> Option<H256> {
        let depth_a = self.depth(a)?;
        let depth_b = self.depth(b)?;
        let mut depth = depth_a.min(depth_b);
        let mut x = self.ancestor_at_depth(a, depth)?;
        let mut y = self.ancestor_at_depth(b, depth)?;
        while x != y {
            depth = depth.checked_sub(1)?;
            x = self.blocks.get(&x)?.parent?;
            y = self.blocks.get(&y)?.parent?;
        }
        Some(x)
    }

    /// "Deepest" with the fixed tie-break: greater depth, then greater root.
    pub(crate) fn deeper(&self, a: &H256, b: &H256) -> bool {
        let (da, db) = (self.depth(a).unwrap_or(0), self.depth(b).unwrap_or(0));
        da > db || (da == db && a > b)
    }

    // ── Handlers ───────────────────────────────────────────────────────────

    /// `on_block(Σ, B)`: admit a block whose parent is held, compute its chain
    /// state, stamp it, unpack its Goldfish votes, fold its finality, refresh
    /// the fork-choice frame, and offer its attestations to the pool.
    ///
    /// The host must have checked the proposer schedule, every signature, and
    /// the committee membership of every carried vote.
    pub fn on_block(&mut self, block: &BlockInput) -> Result<(), BlockError> {
        if block.slot > self.slot {
            return Err(BlockError::FutureSlot {
                slot: block.slot,
                current: self.slot,
            });
        }
        if self.contains(&block.root) {
            return Err(BlockError::Duplicate);
        }
        let Some(parent) = self.blocks.get(&block.parent_root) else {
            return Err(BlockError::UnknownParent(block.parent_root));
        };
        if parent.slot >= block.slot {
            return Err(BlockError::SlotNotAfterParent {
                slot: block.slot,
                parent_slot: parent.slot,
            });
        }
        if let Some(vote) = block.votes.iter().find(|v| v.slot + 1 != block.slot) {
            return Err(BlockError::VoteOfWrongSlot {
                vote_slot: vote.slot,
                slot: block.slot,
            });
        }
        if block
            .support_votes
            .iter()
            .any(|support| !block.votes.contains(support))
        {
            return Err(BlockError::SupportNotSubset);
        }
        if !self.is_ancestor(&self.finalized, &block.parent_root) {
            return Err(BlockError::NotDescendantOfFinalized);
        }

        let parent_depth = parent.depth;
        let block_ref = BlockRef {
            root: block.root,
            slot: block.slot,
        };
        let state = state_transition(
            &parent.state,
            block_ref,
            &block.attestations,
            &self.params,
            &self.electorate,
        );
        let node = Node {
            parent: Some(block.parent_root),
            slot: block.slot,
            depth: parent_depth + 1,
            stamp: self.now(),
            state,
            votes: block.votes.clone(),
            support_votes: block.support_votes.clone(),
            children: Vec::new(),
        };
        self.blocks.insert(block.root, node);
        self.blocks
            .get_mut(&block.parent_root)
            .expect("parent checked above")
            .children
            .push(block.root);

        for vote in &block.votes {
            self.on_goldfish_vote(*vote);
        }
        let state = self.blocks[&block.root].state.clone();
        self.update_finality(&state);
        self.refresh_frame(Some(block.root));
        for attestation in &block.attestations {
            self.on_attestation(attestation.clone());
        }
        Ok(())
    }

    /// `on_goldfish_vote(Σ, vote)`. Returns whether the vote entered the pool.
    /// The host must have checked the committee and the signature.
    pub fn on_goldfish_vote(&mut self, vote: GoldfishVote) -> bool {
        if vote.slot < self.slot.saturating_sub(1) || vote.slot > self.slot {
            return false;
        }
        let stamp = self.now();
        let pool = self.gf_votes.entry(vote.slot).or_default();
        if pool.iter().any(|pooled| pooled.vote == vote) {
            return false;
        }
        let by_validator = pool
            .iter()
            .filter(|pooled| pooled.vote.validator == vote.validator)
            .count();
        if by_validator >= 2 {
            return false;
        }
        pool.push(PooledVote { vote, stamp });
        true
    }

    /// Admit an attestation to the pool proposals draw from, unless it says
    /// nothing, is already held, or can no longer count on any viable chain.
    /// Returns whether it entered the pool. The host must have checked the
    /// signature.
    ///
    /// Attestations never reach the fork choice from here: they count only
    /// once a block carries them, through its chain state. A node that drops
    /// network attestations still follows the chain.
    pub fn on_attestation(&mut self, attestation: Attestation) -> bool {
        if attestation.data.is_empty() || !self.attestation_is_useful(&attestation.data) {
            return false;
        }
        let pooled = self.attestations.entry(attestation.validator).or_default();
        if pooled.contains(&attestation) {
            return false;
        }
        pooled.push(attestation);
        if pooled.len() > MAX_POOLED_ATTESTATIONS_PER_VALIDATOR {
            pooled.remove(0);
        }
        true
    }

    /// `update_finality(Σ, σ)`: raise `h_max`, adopt a lex-greater
    /// justification compatible with `Σ.F`, and advance `Σ.F` to a viable
    /// proper descendant below `Σ.J`. The three statements run in order, each
    /// reading the store the previous one left.
    fn update_finality(&mut self, state: &ChainState) {
        self.max_height = self.max_height.max(state.height);
        if self.is_ancestor(&self.finalized, &state.justified.root)
            && (state.justified_height, state.justified.root)
                > (self.justified_height, self.justified)
        {
            self.justified = state.justified.root;
            self.justified_height = state.justified_height;
        }
        let candidate = state.finalized.root;
        if candidate != self.finalized
            && self.is_ancestor(&self.finalized, &candidate)
            && self.is_ancestor(&candidate, &self.justified)
            && self.is_viable(&candidate)
        {
            self.advance_finalized(candidate);
            self.finalized_height = state.finalized_height;
        }
    }

    /// Recompute the fork-choice frame after `new_block` was processed (or
    /// from scratch with `None`). See [`Frame`].
    fn refresh_frame(&mut self, new_block: Option<H256>) {
        let floor = self.max_height.saturating_sub(1);
        if self.justified_height + 1 != self.max_height {
            self.frame = Frame {
                root: self.finalized,
                floor,
            };
            return;
        }
        let key = (self.max_height, self.justified);
        let contests = |store: &Self, block: &H256| {
            store.blocks[block].state.height >= store.max_height
                && !store.is_ancestor(&store.justified, block)
        };
        let contested = self.contested == Some(key)
            || match new_block {
                // Every other block was evaluated against this key already.
                Some(block) if self.frame_key == Some(key) => contests(self, &block),
                _ => self.blocks.keys().any(|block| contests(self, block)),
            };
        self.frame_key = Some(key);
        self.frame = if contested {
            self.contested = Some(key);
            Frame {
                root: self.finalized,
                floor: self.max_height,
            }
        } else {
            Frame {
                root: self.justified,
                floor,
            }
        };
    }

    /// Move `Σ.F` to `new` and drop every branch that now conflicts with it:
    /// the admission guard refuses their children, so nothing can extend
    /// them. Locks on dropped blocks go with them at the next tick.
    fn advance_finalized(&mut self, new: H256) {
        let old = self.finalized;
        let mut path = Vec::new();
        let mut cursor = new;
        while cursor != old {
            path.push(cursor);
            cursor = self.blocks[&cursor]
                .parent
                .expect("new F descends from old F");
        }
        path.push(old);
        path.reverse();

        for pair in path.windows(2) {
            let (from, keep) = (pair[0], pair[1]);
            let siblings: Vec<H256> = self.blocks[&from]
                .children
                .iter()
                .copied()
                .filter(|child| *child != keep)
                .collect();
            for sibling in siblings {
                self.remove_subtree(sibling);
            }
            self.blocks
                .get_mut(&from)
                .expect("on the path")
                .children
                .retain(|child| *child == keep);
        }
        for root in path.into_iter().skip(1) {
            let depth = self.blocks[&root].depth as usize;
            debug_assert_eq!(depth, self.finalized_chain.len());
            self.finalized_chain.push(root);
        }
        self.finalized = new;
    }

    fn remove_subtree(&mut self, root: H256) {
        let mut stack = vec![root];
        while let Some(current) = stack.pop() {
            if let Some(node) = self.blocks.remove(&current) {
                stack.extend(node.children);
            }
        }
    }

    // ── Accessors ──────────────────────────────────────────────────────────

    /// `Σ.F`.
    pub fn finalized(&self) -> BlockRef {
        self.block_ref(&self.finalized)
            .expect("the finalized block is never pruned")
    }

    /// The height at which `Σ.F` was justified.
    pub fn finalized_height(&self) -> Height {
        self.finalized_height
    }

    /// `Σ.J`, `Σ.h_j`.
    pub fn justified(&self) -> (BlockRef, Height) {
        let block = self
            .block_ref(&self.justified)
            .expect("the justified block descends from the finalized block");
        (block, self.justified_height)
    }

    /// `Σ.h_max`.
    pub fn max_height(&self) -> Height {
        self.max_height
    }

    /// The fork-choice frame.
    pub fn frame(&self) -> Frame {
        self.frame
    }

    /// The deepest block the latest confirmation update fast locked, if it is
    /// still in the tree.
    pub fn fg_confirmed(&self) -> Option<BlockRef> {
        self.fg_confirmed.and_then(|root| self.block_ref(&root))
    }

    /// The Goldfish votes held for `slot`, in arrival order.
    pub fn goldfish_votes(&self, slot: Slot) -> Vec<GoldfishVote> {
        self.gf_votes
            .get(&slot)
            .map(|pool| pool.iter().map(|pooled| pooled.vote).collect())
            .unwrap_or_default()
    }

    /// Whether attestation data can still count on some viable chain: what
    /// the pool keeps. Hosts holding signatures beside the pool prune them
    /// with this.
    pub fn attestation_is_useful(&self, data: &AttestationData) -> bool {
        useful(data, self.max_height, self.finalized_height)
    }

    /// Every pooled attestation, by validator and then arrival.
    pub fn pooled_attestations(&self) -> Vec<Attestation> {
        let mut validators: Vec<&ValidatorIndex> = self.attestations.keys().collect();
        validators.sort();
        validators
            .into_iter()
            .flat_map(|validator| self.attestations[validator].iter().cloned())
            .collect()
    }

    /// Every processed block as `(root, parent, slot)`, for diagnostics.
    pub fn blocks(&self) -> impl Iterator<Item = (H256, Option<H256>, Slot)> + '_ {
        self.blocks
            .iter()
            .map(|(root, node)| (*root, node.parent, node.slot))
    }

    /// `Σ.resolution_time(vote)` for a Goldfish vote: `+∞` (`None`) while the
    /// head is unknown or of a later slot, else the later of the two stamps.
    pub(crate) fn vote_resolution(&self, vote: &GoldfishVote, stamp: Tick) -> Option<Tick> {
        let head = self.blocks.get(&vote.head)?;
        (head.slot <= vote.slot).then(|| stamp.max(head.stamp))
    }

    /// Whether a vote's head resolves in the tree at all (finite resolution).
    pub(crate) fn vote_resolves(&self, vote: &GoldfishVote) -> bool {
        self.blocks
            .get(&vote.head)
            .is_some_and(|head| head.slot <= vote.slot)
    }

    pub(crate) fn confirmation_window(&self, slot: Slot) -> (Tick, Tick) {
        (support_cutoff(slot), confirmation_time(slot))
    }
}

/// Whether attestation data can still count on some viable chain: a height
/// pair at the band of viable heights or above, or a finality pair for a
/// justification above `Σ.h_F`.
fn useful(data: &AttestationData, max_height: Height, finalized_height: Height) -> bool {
    let height = data
        .height_pair()
        .is_some_and(|pair| pair.height + 1 >= max_height);
    let finality = data
        .finality_pair()
        .is_some_and(|pair| pair.height > finalized_height);
    height || finality
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::slot_start;
    use crate::types::HeightVote;

    fn root(byte: u8) -> H256 {
        H256([byte; 32])
    }

    fn height_votes(height: Height, entry: H256, timeout: bool) -> Vec<Attestation> {
        (0..3)
            .map(|validator| Attestation {
                validator,
                data: AttestationData::new(
                    Some(HeightVote {
                        height,
                        entry,
                        timeout,
                    }),
                    None,
                ),
            })
            .collect()
    }

    fn block(
        store: &mut Store,
        byte: u8,
        slot: Slot,
        parent: H256,
        attestations: Vec<Attestation>,
    ) -> H256 {
        let input = BlockInput {
            root: root(byte),
            parent_root: parent,
            slot,
            proposer: 0,
            votes: Vec::new(),
            support_votes: Vec::new(),
            attestations,
        };
        store.on_block(&input).expect("admitted");
        input.root
    }

    #[test]
    fn a_justification_at_h_max_minus_one_is_the_root_until_contested() {
        let params = Params {
            timeout_delay: 2,
            ..Params::default()
        };
        let genesis = H256::ZERO;
        let mut store = Store::from_genesis(params, Electorate::uniform(4), genesis);
        store.advance_to(slot_start(10));

        // G ← A1 justifies G at height 1; A1 ← B justifies A1 at height 2.
        let a1 = block(&mut store, 1, 1, genesis, height_votes(1, genesis, false));
        let b = block(&mut store, 2, 2, a1, height_votes(2, a1, false));
        assert_eq!((store.max_height(), store.justified().1), (3, 2));
        assert_eq!(store.frame(), Frame { root: a1, floor: 2 });

        // G ← C1 reaches height 2 on its own justification of G: a branch
        // at h_max − 1 that J revealed late pulls the root away from.
        let c1 = block(&mut store, 3, 3, genesis, height_votes(1, genesis, false));
        assert_eq!(store.frame(), Frame { root: a1, floor: 2 });
        assert!(!store.filtered_block_tree().contains(&c1));

        // C1 ← C2 times out of height 2 into h_max without A1: a contest. The
        // root falls back to F and the floor rises to h_max.
        let c2 = block(&mut store, 4, 5, c1, height_votes(2, c1, true));
        assert_eq!(store.chain_state(&c2).unwrap().height, 3);
        assert_eq!(
            store.frame(),
            Frame {
                root: genesis,
                floor: 3
            }
        );
        let tree = store.filtered_block_tree();
        assert!(tree.contains(&b) && tree.contains(&c2));

        // The contest is spent for this (h_max, J): it stays whatever comes.
        block(&mut store, 5, 6, b, Vec::new());
        assert_eq!(
            store.frame(),
            Frame {
                root: genesis,
                floor: 3
            }
        );
    }

    #[test]
    fn the_pool_keeps_only_attestations_that_can_still_count() {
        let genesis = H256::ZERO;
        let mut store = Store::from_genesis(Params::default(), Electorate::uniform(4), genesis);
        store.advance_to(slot_start(4));
        let a1 = block(&mut store, 1, 1, genesis, height_votes(1, genesis, false));
        block(&mut store, 2, 2, a1, height_votes(2, a1, false));
        // h_max = 3: a target at height 1 can no longer count anywhere.
        let stale = height_votes(1, genesis, false).remove(0);
        assert!(!store.on_attestation(stale));
        let current = Attestation {
            validator: 3,
            data: AttestationData::new(
                Some(HeightVote {
                    height: 3,
                    entry: root(2),
                    timeout: false,
                }),
                None,
            ),
        };
        assert!(store.on_attestation(current.clone()));
        assert!(!store.on_attestation(current), "already held");
        assert!(!store.on_attestation(Attestation {
            validator: 3,
            data: AttestationData::default(),
        }));
    }
}
