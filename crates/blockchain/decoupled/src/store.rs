//! The cumulative node store Σ and its handlers (PROTOCOL.md §1.1, §1.4,
//! figure `alg:store`).
//!
//! The store keeps messages and their receipt stamps, the processed block tree
//! with every block's chain state, the finality caches and the three
//! confirmation records. Everything else (views, viable and filtered trees,
//! scores, grades, the SG root) is derived when used, from stamps compared
//! against past instants; the only cached derived values are the saved grades.
//!
//! # Trust boundary
//!
//! The engine checks what the protocol's handlers check. It does not verify
//! signatures, committee membership or the proposer schedule: those depend on
//! each chain's keys and shuffling, so the host checks them before it calls a
//! handler (MODELING_CHOICES §1.3 puts the committee test at the gate too).

use std::collections::{BTreeMap, HashMap};

use ethlambda_types::primitives::H256;

use crate::chain_state::{ChainState, state_transition};
use crate::grades::GradeCache;
use crate::params::{Params, confirmation_time, slot_of, support_cutoff};
use crate::types::{
    Attestation, BlockInput, BlockRef, Electorate, GoldfishVote, Height, Round, Slot, Tick,
};

/// The stamp of the anchor block: `Σ.timestamp(B_gen) = −∞`.
pub const ANCHOR_STAMP: Tick = Tick::MIN;

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
    pub(crate) attestations: Vec<Attestation>,
    pub(crate) children: Vec<H256>,
}

#[derive(Debug, Clone)]
pub(crate) struct PooledVote {
    pub(crate) vote: GoldfishVote,
    pub(crate) stamp: Tick,
}

#[derive(Debug, Clone)]
pub(crate) struct PooledAttestation {
    pub(crate) attestation: Attestation,
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
    #[error("carried attestation of round {round} after the block's round {block_round}")]
    AttestationFromFuture { round: Round, block_round: Round },
}

/// What a tick asks the host to do (`on_tick`, §2.1). The store side of the
/// tick (grades, clock, confirmation) has already run when this is returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TickEvents {
    pub tick: Tick,
    pub slot: Slot,
    /// `t = t_s`, `s > 0`: the slot's proposer builds its block now.
    pub propose: bool,
    /// `t = t_s + Δ`, `s > 0`: committee members cast their Goldfish vote.
    pub vote: bool,
    /// `t = a_r`: every awake validator attests for this round.
    pub attest: Option<Round>,
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
    /// `Σ.attestations[·]`.
    pub(crate) attestations: BTreeMap<Round, Vec<PooledAttestation>>,
    /// `Σ.G2`, `Σ.G1`, `Σ.G0` for the current and the next round.
    pub(crate) grades: GradeCache,
    /// `Σ.F`, and the height at which it was justified (`σ.h_F` of the
    /// chain state that finalized it).
    pub(crate) finalized: H256,
    pub(crate) finalized_height: Height,
    /// `Σ.J`, `Σ.h_j`.
    pub(crate) justified: H256,
    pub(crate) justified_height: Height,
    /// `Σ.h_max`.
    pub(crate) max_height: Height,
    pub(crate) live_confirmed: H256,
    pub(crate) latest_confirmed: H256,
    pub(crate) latest_stable: H256,
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
        Self {
            params,
            electorate,
            time: None,
            slot: anchor.slot,
            anchor: root,
            blocks: HashMap::from([(root, node)]),
            finalized_chain: vec![root],
            gf_votes: BTreeMap::new(),
            attestations: BTreeMap::new(),
            grades: GradeCache::initial(params.round_of(anchor.slot)),
            finalized: root,
            finalized_height: 0,
            justified: root,
            justified_height: 0,
            max_height: 1,
            live_confirmed: root,
            latest_confirmed: root,
            latest_stable: root,
        }
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

    pub fn current_round(&self) -> Round {
        self.params.round_of(self.slot)
    }

    /// The stamp an object processed now receives.
    pub(crate) fn now(&self) -> Tick {
        self.time.unwrap_or(ANCHOR_STAMP)
    }

    // ── Clock ──────────────────────────────────────────────────────────────

    /// Run every public tick up to and including `now`, in order, and return
    /// the duties each one asks for. A store that has never ticked runs only
    /// `now`: a node that joins does not replay the past (§6.2, "a node that
    /// joins starts with empty fields").
    ///
    /// Call this before every handler, with the current wall-clock tick, so an
    /// object is stamped after the tick of its own instant (§2: "the tick at a
    /// public time runs once, before the objects processed at that time").
    pub fn advance_to(&mut self, now: Tick) -> Vec<TickEvents> {
        let first = match self.time {
            Some(last) if now <= last => return Vec::new(),
            Some(last) => last + 1,
            None => now,
        };
        (first..=now).map(|t| self.on_tick(t)).collect()
    }

    /// `on_tick(Σ, Λ, t)` (§2.1), store side.
    ///
    /// Completes the grades whose completion time this is (from the store as
    /// it stands, before the clock moves), advances the clock, and runs the
    /// slot-`(s−1)` confirmation at `t_s + 2Δ`. Proposals, votes and
    /// attestations need the host's keys, so they come back as
    /// [`TickEvents`]; the host runs them, in that order, against the store as
    /// this call leaves it.
    pub fn on_tick(&mut self, t: Tick) -> TickEvents {
        self.update_grades(t);
        let slot = slot_of(t);
        self.time = Some(t);
        self.slot = slot;
        self.prune_pools();

        let start = crate::params::slot_start(slot);
        let propose = slot > 0 && t == start;
        let vote = slot > 0 && t == start + 1;
        if slot > 0 && t == support_cutoff(slot) {
            self.update_confirmation(slot - 1);
        }
        let round = self.params.round_of(slot);
        let attest = (t == self.params.attestation_time(round)).then_some(round);
        TickEvents {
            tick: t,
            slot,
            propose,
            vote,
            attest,
        }
    }

    /// Discard pool entries no rule can read any more (appendix A.3 and A.7:
    /// "expired pool entries may be discarded"). Goldfish votes older than the
    /// previous slot are refused on arrival and read by no duty; attestations
    /// older than the SG window are read by no grade.
    fn prune_pools(&mut self) {
        let oldest_vote_slot = self.slot.saturating_sub(1);
        self.gf_votes = self.gf_votes.split_off(&oldest_vote_slot);
        let oldest_round = self.current_round().saturating_sub(self.params.eta_sg);
        self.attestations = self.attestations.split_off(&oldest_round);
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

    /// The deepest ancestor of `g` compatible with `Σ.F`.
    ///
    /// A block that conflicts with `Σ.F` was pruned when `Σ.F` moved past it,
    /// and its clip is then a strict ancestor of `Σ.F`. Every reader treats all
    /// strict ancestors of `Σ.F` alike (none is in the filtered tree, all are
    /// compatible with every block that is), so the anchor stands in for it.
    pub(crate) fn clip_to_finalized(&self, g: &H256) -> H256 {
        if !self.contains(g) {
            return self.anchor;
        }
        if self.compatible(g, &self.finalized) {
            return *g;
        }
        self.meet(g, &self.finalized).unwrap_or(self.anchor)
    }

    // ── Handlers ───────────────────────────────────────────────────────────

    /// `on_block(Σ, B)` (§2.1): admit a block whose parent is held, compute
    /// its chain state, stamp it, unpack its Goldfish votes, fold its
    /// finality, and offer its attestations to the SG pool.
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
        let block_round = self.params.round_of(block.slot);
        if let Some(att) = block.attestations.iter().find(|a| a.round() > block_round) {
            return Err(BlockError::AttestationFromFuture {
                round: att.round(),
                block_round,
            });
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
            attestations: block.attestations.clone(),
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
        for attestation in &block.attestations {
            self.on_sg_vote(attestation.clone());
        }
        Ok(())
    }

    /// `on_goldfish_vote(Σ, vote)` (§2.1). Returns whether the vote entered
    /// the pool. The host must have checked the committee and the signature.
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

    /// `on_sg_vote(Σ, a)` (§2.1): admit a combined attestation whose round is
    /// in the SG window, unless its SG projection is already held or its
    /// validator already has two distinct safe blocks in the round. Returns
    /// whether it entered the pool.
    pub fn on_sg_vote(&mut self, attestation: Attestation) -> bool {
        let round = attestation.round();
        if !self.params.admits_round(self.current_round(), round) {
            return false;
        }
        let stamp = self.now();
        let pool = self.attestations.entry(round).or_default();
        let safe = attestation.data.safe();
        let mut round_votes: Vec<Option<H256>> = pool
            .iter()
            .filter(|pooled| pooled.attestation.validator == attestation.validator)
            .map(|pooled| pooled.attestation.data.safe())
            .collect();
        round_votes.sort();
        round_votes.dedup();
        if round_votes.contains(&safe) || round_votes.len() >= 2 {
            return false;
        }
        pool.push(PooledAttestation { attestation, stamp });
        true
    }

    /// `update_finality(Σ, σ)` (§2.1): raise `h_max`, adopt a lex-greater
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

    /// Move `Σ.F` to `new` and drop every branch that now conflicts with it:
    /// the admission guard refuses their children, so nothing can extend them
    /// (appendix A.10, "its branch freezes"). The saved grades need no
    /// rewrite; every reader clips them (`clip_to_finalized`).
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

    /// `Σ.live_confirmed`: the protocol-facing confirmation.
    pub fn live_confirmed(&self) -> H256 {
        self.live_confirmed
    }

    /// `get_stable(Σ)`: `Σ.latest_stable` when it extends `Σ.F`, else `Σ.F`.
    pub fn stable(&self) -> BlockRef {
        let root = if self.is_ancestor(&self.finalized, &self.latest_stable) {
            self.latest_stable
        } else {
            self.finalized
        };
        self.block_ref(&root).expect("stable tip is processed")
    }

    /// `get_confirmed(Σ)`: `Σ.latest_confirmed` when it extends the stable
    /// tip, else the stable tip. `Σ.F ⪯ stable ⪯ confirmed` always holds.
    pub fn confirmed(&self) -> BlockRef {
        let stable = self.stable();
        if self.is_ancestor(&stable.root, &self.latest_confirmed) {
            self.block_ref(&self.latest_confirmed)
                .expect("checked by is_ancestor")
        } else {
            stable
        }
    }

    /// The Goldfish votes held for `slot`, in arrival order.
    pub fn goldfish_votes(&self, slot: Slot) -> Vec<GoldfishVote> {
        self.gf_votes
            .get(&slot)
            .map(|pool| pool.iter().map(|pooled| pooled.vote).collect())
            .unwrap_or_default()
    }

    /// The attestations held for `round`, in arrival order.
    pub fn round_attestations(&self, round: Round) -> Vec<Attestation> {
        self.attestations
            .get(&round)
            .map(|pool| pool.iter().map(|p| p.attestation.clone()).collect())
            .unwrap_or_default()
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
