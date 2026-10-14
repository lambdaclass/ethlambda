//! The node store: the FG state Σ, the AC state 𝒜, and their handlers.
//!
//! The store keeps the processed block tree with every block's chain state
//! and receipt stamp, the finality caches and the attestation pool (Σ), and
//! the Goldfish votes, saved confirmations, lock entries, fast set and
//! confirmation record of the available chain (𝒜). The FG frame, viable
//! trees and scores are derived when used, from stamps compared against past
//! instants.
//!
//! # Trust boundary
//!
//! The engine checks what the protocol's handlers check. It does not verify
//! signatures, committee membership or the proposer schedule: those depend on
//! each chain's keys and shuffling, so the host checks them before it calls a
//! handler.

use std::collections::{BTreeMap, HashMap, HashSet};

use ethlambda_types::primitives::H256;

use crate::chain_state::{ChainState, InvalidAttestation, state_transition};
use crate::locks::CommitteeSizes;
use crate::params::{Params, slot_of, slot_start, support_cutoff, vote_time};
use crate::types::{
    Attestation, AttestationData, BlockInput, BlockRef, Electorate, GoldfishVote, Height, Slot,
    Tick, ValidatorIndex,
};

/// The stamp of the anchor block: `𝒜.timestamp[B_gen] = −∞`.
pub const ANCHOR_STAMP: Tick = Tick::MIN;

/// Attestations the pool keeps per validator, a resource bound the
/// specification does not have. An honest validator sends at most one target
/// per height and one timeout per entry at a height, and the pool drops what
/// can no longer count on a viable chain, so a handful covers every
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
    /// `𝒜.timestamp[B]`.
    pub(crate) stamp: Tick,
    /// `Σ.σ[B]`.
    pub(crate) state: ChainState,
    pub(crate) votes: Vec<GoldfishVote>,
    pub(crate) support_votes: Vec<GoldfishVote>,
    /// `B.attestations`, so a proposal can leave out what its parent's chain
    /// already carries.
    pub(crate) attestations: Vec<Attestation>,
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
    #[error("carried attestation {0} is not well formed")]
    MalformedAttestation(usize),
    #[error(transparent)]
    InvalidAttestation(#[from] InvalidAttestation),
}

/// What a tick asks the host to do. The store side of the tick (clock,
/// expiry, revocation, the confirmation update) has already run when this is
/// returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TickEvents {
    pub tick: Tick,
    pub slot: Slot,
    /// `t = t_s`, `s > 0`: the slot's proposer builds its block now.
    pub propose: bool,
    /// `t = t_s + Δ`: committee members cast their Goldfish vote, after the
    /// locks were revoked against the previous slot's votes.
    pub vote: bool,
    /// `t = a_r`, the action time of the round, right after the confirmation
    /// update of its first slot: every validator runs the FG action
    /// (`ATTEST`).
    pub attest: bool,
}

/// The fork-choice frame the finality gadget imposes on the available chain
/// (`Φ.fc_root` and the head height floor that defines `Φ.viable_heads`).
///
/// ```text
/// h_max = h_j + 1?   a block at h_max not on J?   root   floor
/// no                 —                            F      h_max − 1
/// yes                no                           J      h_max − 1
/// yes                yes (a contest)              F      h_max
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame {
    pub root: H256,
    pub floor: Height,
}

/// The decoupled-consensus store.
#[derive(Debug, Clone)]
pub struct Store {
    pub(crate) params: Params,
    pub(crate) electorate: Electorate,
    /// The clock `t`: the last tick run, `None` before the first.
    pub(crate) time: Option<Tick>,
    /// `slot(t)`.
    pub(crate) slot: Slot,
    pub(crate) anchor: H256,
    /// `Σ.𝒯` with `Σ.σ[·]` and `𝒜.timestamp[·]` of blocks.
    pub(crate) blocks: HashMap<H256, Node>,
    /// The finalized block's ancestors, indexed by depth, for O(1) ancestry
    /// below `Σ.F`.
    pub(crate) finalized_chain: Vec<H256>,
    /// `𝒜.gf_votes[·]` with `𝒜.timestamp[·]` of votes.
    pub(crate) gf_votes: BTreeMap<Slot, Vec<PooledVote>>,
    /// `Σ.attestations`, in the order of first acceptance. They feed
    /// proposals only: the fork choice reads attestations through the chain
    /// states of blocks, never from the network.
    pub(crate) attestations: Vec<Attestation>,
    pub(crate) pooled: HashSet<Attestation>,
    pub(crate) pooled_per_validator: HashMap<ValidatorIndex, usize>,
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
    /// The FG frame, refreshed whenever the FG state changes.
    pub(crate) frame: Frame,
    /// The `(h_max, J, F)` whose contest the frame last evaluated in full,
    /// and the answer: the tree only grows while they stay, so only a new
    /// block can start a contest.
    pub(crate) frame_key: Option<(Height, H256, H256)>,
    pub(crate) contested: bool,
    /// `𝒜.lock_entries`: locked blocks and their deadlines. Entries on one
    /// block keep the latest deadline, which locks exactly what the separate
    /// entries would.
    pub(crate) lock_entries: HashMap<H256, Tick>,
    /// `𝒜.saved_confirmation[·]` of the slots the slow test can still read.
    pub(crate) saved_confirmation: BTreeMap<Slot, Option<H256>>,
    /// `𝒜.fast_blocks`.
    pub(crate) fast_blocks: Vec<H256>,
    /// `𝒜.latest_confirmed`.
    pub(crate) latest_confirmed: H256,
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
            attestations: Vec::new(),
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
            attestations: Vec::new(),
            pooled: HashSet::new(),
            pooled_per_validator: HashMap::new(),
            committee_sizes,
            finalized: root,
            finalized_height: 0,
            justified: root,
            justified_height: 0,
            max_height: 1,
            frame: Frame { root, floor: 0 },
            frame_key: None,
            contested: false,
            lock_entries: HashMap::new(),
            saved_confirmation: BTreeMap::new(),
            fast_blocks: Vec::new(),
            latest_confirmed: root,
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

    /// The clock `t`, the last tick run.
    pub fn time(&self) -> Option<Tick> {
        self.time
    }

    /// `slot(t)`.
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

    /// `on_tick(t)`, store side: advance the clock and run `AC_ON_TICK`
    /// (expiry, then at `t_s + Δ` the revocation against the slot-`(s − 1)`
    /// votes, and at `t_s + 2Δ` the confirmation update of slot `s − 1`).
    /// The proposal, the vote and the FG action need the host's keys, so
    /// they come back as [`TickEvents`]; the host runs them against the
    /// store as this call leaves it.
    pub fn on_tick(&mut self, t: Tick) -> TickEvents {
        let slot = slot_of(t);
        self.time = Some(t);
        self.slot = slot;
        self.prune();

        // An entry expires at the first tick at or after its deadline.
        self.lock_entries.retain(|_, deadline| *deadline > t);
        let vote = t == vote_time(slot);
        if vote {
            self.revoke_locks(slot);
        }
        if t == support_cutoff(slot) {
            self.update_confirmation(slot);
        }
        TickEvents {
            tick: t,
            slot,
            propose: slot > 0 && t == slot_start(slot),
            vote,
            attest: self.params.is_action_time(t),
        }
    }

    /// Discard what no rule can read any more: Goldfish votes older than the
    /// previous slot (votes that old are refused on arrival and read by no
    /// duty), saved confirmations older than the slow window, lock entries
    /// whose block left the tree, and attestations that can no longer count
    /// on any viable chain.
    fn prune(&mut self) {
        let oldest_vote_slot = self.slot.saturating_sub(1);
        self.gf_votes = self.gf_votes.split_off(&oldest_vote_slot);
        let oldest_saved = self.slot.saturating_sub(self.params.lock_period + 1);
        self.saved_confirmation = self.saved_confirmation.split_off(&oldest_saved);
        let blocks = &self.blocks;
        self.lock_entries
            .retain(|block, _| blocks.contains_key(block));

        let (max_height, finalized_height) = (self.max_height, self.finalized_height);
        let stale =
            |attestation: &Attestation| !useful(&attestation.data, max_height, finalized_height);
        if self.attestations.iter().any(stale) {
            let (keep, drop): (Vec<_>, Vec<_>) = std::mem::take(&mut self.attestations)
                .into_iter()
                .partition(|attestation| !stale(attestation));
            self.attestations = keep;
            for attestation in drop {
                self.forget_pooled(&attestation);
            }
        }
    }

    fn forget_pooled(&mut self, attestation: &Attestation) {
        self.pooled.remove(attestation);
        if let Some(count) = self.pooled_per_validator.get_mut(&attestation.validator) {
            *count -= 1;
            if *count == 0 {
                self.pooled_per_validator.remove(&attestation.validator);
            }
        }
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

    /// "Deepest" with the fixed tie-break: greater depth, then greater root.
    pub(crate) fn deeper(&self, a: &H256, b: &H256) -> bool {
        let (da, db) = (self.depth(a).unwrap_or(0), self.depth(b).unwrap_or(0));
        da > db || (da == db && a > b)
    }

    // ── Handlers ───────────────────────────────────────────────────────────

    /// `on_block(B)`: `FG_ON_BLOCK` (admit a block whose parent is held and
    /// that extends `Σ.F`, compute its chain state, fold its finality, offer
    /// its attestations to the pool), then `AC_ON_BLOCK` (stamp it and
    /// unpack its Goldfish votes). A refused block changes nothing.
    ///
    /// The host must have checked the proposer schedule, every signature, the
    /// committee membership of every carried vote, and the form of every
    /// carried attestation.
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
        // `AC_VALID_PAYLOAD(B)`.
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
        // The forms of section 2, which a handler requires of every
        // attestation a block carries.
        if let Some(index) = block
            .attestations
            .iter()
            .position(|attestation| !attestation.data.is_well_formed())
        {
            return Err(BlockError::MalformedAttestation(index));
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
        )?;
        let node = Node {
            parent: Some(block.parent_root),
            slot: block.slot,
            depth: parent_depth + 1,
            stamp: self.now(),
            state: state.clone(),
            votes: block.votes.clone(),
            support_votes: block.support_votes.clone(),
            attestations: block.attestations.clone(),
            children: Vec::new(),
        };
        self.blocks.insert(block.root, node);
        self.blocks
            .get_mut(&block.parent_root)
            .expect("parent checked above")
            .children
            .push(block.root);

        self.update_finality(&state, block.root);
        for attestation in &block.attestations {
            self.on_attestation(attestation.clone());
        }
        for vote in &block.votes {
            self.on_goldfish_vote(*vote);
        }
        Ok(())
    }

    /// `on_goldfish_vote(𝒜, t, vote)`. Returns whether the vote entered the
    /// pool. The host must have checked the committee and the signature.
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

    /// `FG_ON_ATTESTATION(Σ, a)`: add a well-formed attestation to the pool
    /// proposals draw from, one copy of each. Returns whether it entered the
    /// pool. The host must have checked the signature.
    ///
    /// Two resource bounds the specification does not have: an attestation
    /// that can no longer count on any viable chain is not kept, and each
    /// validator keeps at most [`MAX_POOLED_ATTESTATIONS_PER_VALIDATOR`].
    pub fn on_attestation(&mut self, attestation: Attestation) -> bool {
        if !attestation.data.is_well_formed()
            || !self.attestation_is_useful(&attestation.data)
            || self.pooled.contains(&attestation)
        {
            return false;
        }
        let validator = attestation.validator;
        let count = self.pooled_per_validator.entry(validator).or_default();
        *count += 1;
        let evict = *count > MAX_POOLED_ATTESTATIONS_PER_VALIDATOR;
        self.pooled.insert(attestation.clone());
        self.attestations.push(attestation);
        if evict
            && let Some(oldest) = self
                .attestations
                .iter()
                .position(|pooled| pooled.validator == validator)
        {
            let oldest = self.attestations.remove(oldest);
            self.forget_pooled(&oldest);
        }
        true
    }

    /// `update_finality(Σ, σ)`: raise `h_max`, adopt a lex-greater
    /// justification compatible with `Σ.F`, and advance `Σ.F` to a proper
    /// descendant at or below `Σ.J` with a viable descendant. Each statement
    /// reads the store the previous one left, so the viability test reads
    /// the frame of the new `h_max` and `J`.
    fn update_finality(&mut self, state: &ChainState, new_block: H256) {
        self.max_height = self.max_height.max(state.height);
        if self.is_ancestor(&self.finalized, &state.justified.root)
            && (state.justified_height, state.justified.root)
                > (self.justified_height, self.justified)
        {
            self.justified = state.justified.root;
            self.justified_height = state.justified_height;
        }
        self.refresh_frame(Some(new_block));
        let candidate = state.finalized.root;
        if candidate != self.finalized
            && self.is_ancestor(&self.finalized, &candidate)
            && self.is_ancestor(&candidate, &self.justified)
            && self.has_viable_descendant(&candidate)
        {
            self.advance_finalized(candidate);
            self.finalized_height = state.finalized_height;
            self.refresh_frame(None);
        }
    }

    /// Recompute the frame (`fg_contest`, `head_height_floor`,
    /// `get_fc_root`) after `new_block` was added, or from scratch with
    /// `None`. See [`Frame`].
    fn refresh_frame(&mut self, new_block: Option<H256>) {
        let floor = self.max_height.saturating_sub(1);
        if self.justified_height + 1 != self.max_height {
            self.frame_key = None;
            self.contested = false;
            self.frame = Frame {
                root: self.finalized,
                floor,
            };
            return;
        }
        // Every accepted block extends `Σ.F` or is one of its ancestors, and
        // an ancestor of `F ⪯ J` is below `h_j`, so the whole tree can be
        // read in place of `Φ.tree`.
        let key = (self.max_height, self.justified, self.finalized);
        let contests = |store: &Self, block: &H256| {
            store.blocks[block].state.height == store.max_height
                && !store.is_ancestor(&store.justified, block)
        };
        self.contested = match new_block {
            // The tree only grew by this block since the key was evaluated.
            Some(block) if self.frame_key == Some(key) => self.contested || contests(self, &block),
            _ => self.blocks.keys().any(|block| contests(self, block)),
        };
        self.frame_key = Some(key);
        self.frame = if self.contested {
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
    /// them. Lock entries on dropped blocks go with them at the next tick.
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

    /// The FG frame.
    pub fn frame(&self) -> Frame {
        self.frame
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

    /// `Σ.attestations`, in the order of first acceptance.
    pub fn pooled_attestations(&self) -> &[Attestation] {
        &self.attestations
    }

    /// Every processed block as `(root, parent, slot)`, for diagnostics.
    pub fn blocks(&self) -> impl Iterator<Item = (H256, Option<H256>, Slot)> + '_ {
        self.blocks
            .iter()
            .map(|(root, node)| (*root, node.parent, node.slot))
    }

    /// `resolution_time(𝒜, Φ, vote)`: `+∞` (`None`) while the head is
    /// unknown or of a later slot, else the later of the two stamps.
    pub(crate) fn vote_resolution(&self, vote: &GoldfishVote, stamp: Tick) -> Option<Tick> {
        let head = self.blocks.get(&vote.head)?;
        (head.slot <= vote.slot).then(|| stamp.max(head.stamp))
    }

    /// Whether a vote is resolved (finite resolution time).
    pub(crate) fn vote_resolves(&self, vote: &GoldfishVote) -> bool {
        self.blocks
            .get(&vote.head)
            .is_some_and(|head| head.slot <= vote.slot)
    }
}

/// Whether attestation data can still be valid against the state of a
/// viable head. Every viable head has state height at least `h_max − 1`, so
/// its own entry is at `h_max − 1` or above, and its pending pairs are above
/// its finalized height and below `h_max`. Reading `Σ.h_F` for the chain's
/// finalized height drops finality pairs at or below `Σ.F`, which no chain
/// extending `Σ.F` needs.
fn useful(data: &AttestationData, max_height: Height, finalized_height: Height) -> bool {
    let height = data.height_pair().height;
    height + 1 >= max_height
        || (height < max_height
            && data
                .finality_pair()
                .is_some_and(|pair| pair.height > finalized_height))
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
                    HeightVote {
                        height,
                        entry,
                        timeout,
                    },
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
        // at h_max − 1, below the floor once J is the root.
        let c1 = block(&mut store, 3, 3, genesis, height_votes(1, genesis, false));
        assert_eq!(store.frame(), Frame { root: a1, floor: 2 });
        assert!(!store.viable_block_tree().contains(&c1));

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
        let tree = store.viable_block_tree();
        assert!(tree.contains(&b) && tree.contains(&c2));

        // The contest lasts while its witness is in the tree.
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
    fn a_block_carrying_an_invalid_attestation_is_refused() {
        let genesis = H256::ZERO;
        let mut store = Store::from_genesis(Params::default(), Electorate::uniform(4), genesis);
        store.advance_to(slot_start(4));
        let input = BlockInput {
            root: root(1),
            parent_root: genesis,
            slot: 1,
            proposer: 0,
            votes: Vec::new(),
            support_votes: Vec::new(),
            attestations: height_votes(1, root(9), false),
        };
        assert!(matches!(
            store.on_block(&input),
            Err(BlockError::InvalidAttestation(_))
        ));
        assert!(!store.contains(&input.root));
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
                HeightVote {
                    height: 3,
                    entry: root(2),
                    timeout: false,
                },
                None,
            ),
        };
        assert!(store.on_attestation(current.clone()));
        assert!(!store.on_attestation(current), "already held");
        let malformed = Attestation {
            validator: 3,
            data: AttestationData::new(
                HeightVote {
                    height: 0,
                    entry: root(2),
                    timeout: false,
                },
                None,
            ),
        };
        assert!(!store.on_attestation(malformed));
    }
}
