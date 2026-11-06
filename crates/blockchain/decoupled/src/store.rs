//! The fork choice store and its handlers (fork-choice.md: `Store`,
//! `get_forkchoice_store`, `on_tick`, `on_block`,
//! `on_execution_payload_envelope`, `on_head_vote_message`, `update_finality`
//! and the receipt-time and committee recorders).
//!
//! # Trust boundary
//!
//! The engine checks what the fork choice handlers check. It does not run the
//! state transition, verify signatures or compute committees: those depend on
//! each chain's state and keys, so the host does them before it calls a
//! handler and hands the results in ([`BlockInput::fg`], recorded committees).

use std::collections::{BTreeMap, HashMap, HashSet};

use ethlambda_types::primitives::H256;

use crate::params::{
    GENESIS_SLOT, HEAD_VOTE_DUE, Params, SUPPORT_CUTOFF, slot_of, slot_start, time_into_slot,
};
use crate::types::{
    Anchor, BlockInput, FgCheckpoints, ForkChoiceNode, HeadVote, HeadVoteCommittee,
    HeadVoteCommittees, HeadVoteMessage, Height, HeightCheckpoint, PayloadStatus, Slot, Tick,
    ValidatorIndex,
};

/// One processed block: `store.blocks[root]`, `store.block_states[root]`'s
/// finality gadget checkpoints, and `store.block_receipt_times[root]`.
#[derive(Debug, Clone)]
pub(crate) struct Block {
    pub(crate) parent: Option<H256>,
    pub(crate) slot: Slot,
    /// Parent edges from the anchor.
    pub(crate) depth: u64,
    /// `get_parent_payload_status(store, block)`.
    pub(crate) parent_payload_status: PayloadStatus,
    pub(crate) fg: FgCheckpoints,
    pub(crate) receipt_time: Tick,
    pub(crate) head_votes: Vec<HeadVote>,
    pub(crate) head_vote_support: Vec<Vec<bool>>,
    pub(crate) children: Vec<H256>,
}

/// A verified execution payload: `store.payloads[root]` is present,
/// `store.payload_receipt_times[root]` and
/// `store.payload_inclusion_list_satisfaction[root]`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Payload {
    pub(crate) receipt_time: Tick,
    pub(crate) inclusion_list_satisfied: bool,
}

/// A head vote message in the pool with its receipt time
/// (`store.head_vote_message_receipt_times`).
#[derive(Debug, Clone, Copy)]
pub(crate) struct PooledHeadVote {
    pub(crate) message: HeadVoteMessage,
    pub(crate) receipt_time: Tick,
}

/// Why `on_block` refused a block. Only [`BlockError::FutureSlot`],
/// [`BlockError::UnknownParent`] and [`BlockError::ParentPayloadNotVerified`]
/// are transient: the same block can be offered again once the clock, the
/// tree or the payloads have moved.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BlockError {
    #[error("block slot {slot} is after the current slot {current}")]
    FutureSlot { slot: Slot, current: Slot },
    #[error("block already processed")]
    Duplicate,
    #[error("parent {0:?} not processed")]
    UnknownParent(H256),
    #[error("block builds on its parent's full payload, which is not verified")]
    ParentPayloadNotVerified,
    #[error("a block builds on its parent's empty or full branch, not on a pending one")]
    PendingParentStatus,
    #[error("block does not descend from the finalized block")]
    NotDescendantOfFinalized,
    #[error("block slot {slot} is not after its parent's slot {parent_slot}")]
    SlotNotAfterParent { slot: Slot, parent_slot: Slot },
    #[error("head vote support does not have one bit per voter")]
    MalformedSupport,
}

/// Why `on_head_vote_message` refused a message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HeadVoteError {
    #[error("head vote already seen")]
    Duplicate,
    #[error("head vote of slot {slot} outside the previous and current slots")]
    WrongSlot { slot: Slot },
    #[error("head vote payload status {0} is not a payload status")]
    InvalidPayloadStatus(u8),
    #[error("the head vote committee of slot {0} is not recorded")]
    UnknownCommittee(Slot),
    #[error("validator {validator} is not in the head vote committee of slot {slot}")]
    NotInCommittee {
        slot: Slot,
        validator: ValidatorIndex,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CommitteeError {
    #[error("slot {0}'s head vote committee differs from the one recorded")]
    Mismatch(Slot),
    #[error("this store gives every validator a seat; it records no committees")]
    NotRecorded,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PayloadError {
    #[error("payload for an unknown block {0:?}")]
    UnknownBlock(H256),
}

/// What a tick asks the host to do. The store side of the tick (`unlock`,
/// `update_confirmation`) has already run when this is returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TickEvents {
    pub tick: Tick,
    pub slot: Slot,
    /// The slot's start, `slot > 0`: its proposer builds on
    /// `get_ac_proposal`.
    pub propose: bool,
    /// The head vote deadline, `slot > 0`: committee members vote for
    /// `get_ac_vote_head`, after this tick's `unlock`.
    pub head_vote: bool,
    /// The support cutoff: this tick's `update_confirmation` has run, and
    /// `get_ac_frame` may be read for FG attestations.
    pub support_cutoff: bool,
}

/// The EIP-8453 fork choice store.
#[derive(Debug, Clone)]
pub struct Store {
    pub(crate) params: Params,
    pub(crate) committees: HeadVoteCommittees,
    /// `store.time_ms`, in ticks.
    pub(crate) time: Tick,
    /// Whether `on_tick` has run: a store that has never ticked jumps to the
    /// first time it is given instead of replaying the past.
    pub(crate) ticked: bool,
    /// The finalized block's subtree, plus blocks that conflict with it until
    /// the next slot starts (their carried votes still count for the current
    /// slot's views, as in the spec, where nothing is ever pruned).
    pub(crate) blocks: HashMap<H256, Block>,
    pub(crate) blocks_by_slot: BTreeMap<Slot, Vec<H256>>,
    /// Strict ancestors of the finalized block that were pruned, so a child of
    /// one is refused as not descending from it rather than fetched.
    pub(crate) finalized_ancestors: HashSet<H256>,
    pub(crate) payloads: HashMap<H256, Payload>,
    pub(crate) justified_checkpoint: HeightCheckpoint,
    pub(crate) finalized_checkpoint: HeightCheckpoint,
    pub(crate) max_height: Height,
    pub(crate) fast_confirmed_path: HashSet<ForkChoiceNode>,
    pub(crate) latest_confirmed: ForkChoiceNode,
    pub(crate) saved_confirmations: BTreeMap<Slot, ForkChoiceNode>,
    /// `store.locks`, keyed by deadline.
    pub(crate) locks: BTreeMap<Tick, ForkChoiceNode>,
    pub(crate) head_vote_messages: BTreeMap<Slot, Vec<PooledHeadVote>>,
}

impl Store {
    /// `get_forkchoice_store`: a store anchored at `anchor`, trusted as
    /// justified and finalized at its post-state's target height, with the
    /// clock at the anchor's slot.
    pub fn new(params: Params, committees: HeadVoteCommittees, anchor: Anchor) -> Self {
        let anchor_height = anchor.fg.target.height;
        let checkpoint = HeightCheckpoint::new(anchor_height, anchor.root);
        let time = slot_start(anchor.slot);
        let block = Block {
            parent: None,
            slot: anchor.slot,
            depth: 0,
            parent_payload_status: PayloadStatus::Empty,
            fg: FgCheckpoints {
                target: HeightCheckpoint::new(anchor_height, anchor.root),
                ..anchor.fg
            },
            receipt_time: time,
            head_votes: Vec::new(),
            head_vote_support: Vec::new(),
            children: Vec::new(),
        };
        Self {
            params,
            committees,
            time,
            ticked: false,
            blocks: HashMap::from([(anchor.root, block)]),
            blocks_by_slot: BTreeMap::from([(anchor.slot, vec![anchor.root])]),
            finalized_ancestors: HashSet::new(),
            payloads: HashMap::new(),
            justified_checkpoint: checkpoint,
            finalized_checkpoint: checkpoint,
            max_height: anchor_height,
            fast_confirmed_path: HashSet::new(),
            latest_confirmed: ForkChoiceNode::pending(anchor.root),
            saved_confirmations: BTreeMap::new(),
            locks: BTreeMap::new(),
            head_vote_messages: BTreeMap::new(),
        }
    }

    pub fn params(&self) -> &Params {
        &self.params
    }

    pub fn committees(&self) -> &HeadVoteCommittees {
        &self.committees
    }

    /// `store.time_ms`, in ticks.
    pub fn time(&self) -> Tick {
        self.time
    }

    /// `get_current_slot(store)`.
    pub fn current_slot(&self) -> Slot {
        slot_of(self.time)
    }

    pub fn current_round(&self) -> u64 {
        self.params.round_of(self.current_slot())
    }

    // ── Clock ──────────────────────────────────────────────────────────────

    /// Run `on_tick` for every tick after the last one up to and including
    /// `now`, in order, and return what each asks of the host. A store that
    /// has never ticked runs `now` only: a node that joins does not replay the
    /// duties of the past.
    ///
    /// Call this before every handler with the current wall-clock tick, so an
    /// object is stamped after the tick of its own instant ("callers must
    /// process this tick before other events at the same timestamp").
    pub fn advance_to(&mut self, now: Tick) -> Vec<TickEvents> {
        let first = if !self.ticked {
            now
        } else if now <= self.time {
            return Vec::new();
        } else {
            self.time + 1
        };
        (first..=now).map(|t| self.on_tick(t)).collect()
    }

    /// `on_tick(store, time)`: `unlock` at the head vote deadline and
    /// `update_confirmation` at the support cutoff, both of the previous slot
    /// and both before the clock moves; then the clock moves.
    pub fn on_tick(&mut self, t: Tick) -> TickEvents {
        let slot = slot_of(t);
        let into_slot = time_into_slot(t);
        if slot > GENESIS_SLOT && into_slot == HEAD_VOTE_DUE {
            self.unlock(slot - 1, t);
        }
        if slot > GENESIS_SLOT && into_slot == SUPPORT_CUTOFF {
            self.update_confirmation(slot - 1);
        }
        self.time = t;
        self.ticked = true;
        if into_slot == 0 {
            self.prune();
        }
        TickEvents {
            tick: t,
            slot,
            propose: slot > GENESIS_SLOT && into_slot == 0,
            head_vote: slot > GENESIS_SLOT && into_slot == HEAD_VOTE_DUE,
            support_cutoff: into_slot == SUPPORT_CUTOFF,
        }
    }

    /// Discard what no rule reads any more, at a slot's start.
    ///
    /// * Blocks outside the finalized block's subtree: from this slot on, the
    ///   views read votes only from blocks of the current slot, and every walk
    ///   stays inside the finalized subtree. Strict ancestors of the finalized
    ///   block are remembered by root only.
    /// * Head vote messages and committees of slots before the previous one.
    /// * Saved confirmations older than the slow lock window reads.
    /// * Expired locks (a live lock's deadline is later than the store time).
    fn prune(&mut self) {
        let current = self.current_slot();
        let finalized = self.finalized_checkpoint.root;
        let mut keep = HashSet::new();
        let mut stack = vec![finalized];
        while let Some(root) = stack.pop() {
            if let Some(block) = self.blocks.get(&root) {
                keep.insert(root);
                stack.extend(block.children.iter().copied());
            }
        }
        let mut cursor = self.blocks.get(&finalized).and_then(|block| block.parent);
        while let Some(root) = cursor {
            self.finalized_ancestors.insert(root);
            cursor = self.blocks.get(&root).and_then(|block| block.parent);
        }
        if keep.len() < self.blocks.len() {
            self.blocks.retain(|root, _| keep.contains(root));
            for roots in self.blocks_by_slot.values_mut() {
                roots.retain(|root| keep.contains(root));
            }
            self.blocks_by_slot.retain(|_, roots| !roots.is_empty());
            for block in self.blocks.values_mut() {
                block.children.retain(|child| keep.contains(child));
            }
            self.payloads.retain(|root, _| keep.contains(root));
        }

        let previous = current.saturating_sub(1);
        self.head_vote_messages = self.head_vote_messages.split_off(&previous);
        if let HeadVoteCommittees::Recorded { by_slot, .. } = &mut self.committees {
            *by_slot = by_slot.split_off(&previous);
        }
        let oldest_saved = current.saturating_sub(self.params.slow_lock_window + 1);
        self.saved_confirmations = self.saved_confirmations.split_off(&oldest_saved);
        self.locks = self.locks.split_off(&(self.time + 1));
    }

    // ── Ancestry over blocks ───────────────────────────────────────────────

    pub fn contains(&self, root: &H256) -> bool {
        self.blocks.contains_key(root)
    }

    pub(crate) fn block(&self, root: &H256) -> Option<&Block> {
        self.blocks.get(root)
    }

    pub fn block_slot(&self, root: &H256) -> Option<Slot> {
        self.blocks.get(root).map(|block| block.slot)
    }

    /// The post-state checkpoints of a held block.
    pub fn block_checkpoints(&self, root: &H256) -> Option<FgCheckpoints> {
        self.blocks.get(root).map(|block| block.fg)
    }

    /// The ancestor of `root` at `depth`, or `None` when `root` is unknown,
    /// shallower than `depth`, or its chain leaves the held blocks first.
    pub(crate) fn ancestor_at_depth(&self, root: &H256, depth: u64) -> Option<H256> {
        let mut current = *root;
        let mut block = self.blocks.get(&current)?;
        while block.depth > depth {
            current = block.parent?;
            block = self.blocks.get(&current)?;
        }
        (block.depth == depth).then_some(current)
    }

    /// `is_ancestor_root(store, root, ancestor)`: `ancestor` is `root` or one
    /// of its ancestors, ignoring payload status.
    pub fn is_ancestor_root(&self, root: &H256, ancestor: &H256) -> bool {
        let Some(depth) = self.blocks.get(ancestor).map(|block| block.depth) else {
            return false;
        };
        self.ancestor_at_depth(root, depth) == Some(*ancestor)
    }

    /// `is_strict_ancestor_root(store, root, ancestor)`.
    pub fn is_strict_ancestor_root(&self, root: &H256, ancestor: &H256) -> bool {
        root != ancestor && self.is_ancestor_root(root, ancestor)
    }

    // ── Handlers ───────────────────────────────────────────────────────────

    /// `on_block(store, signed_block)`, fork-choice part: admit a block whose
    /// parent is held and descends from the finalized block, run
    /// `update_finality` on its post-state, and record its receipt time.
    ///
    /// The host must have run the block's state transition and recorded the
    /// head vote committees of its carried votes (`record_head_vote_committee`).
    pub fn on_block(&mut self, block: &BlockInput) -> Result<(), BlockError> {
        if self.contains(&block.root) {
            return Err(BlockError::Duplicate);
        }
        let Some(parent) = self.blocks.get(&block.parent_root) else {
            if self.finalized_ancestors.contains(&block.parent_root) {
                return Err(BlockError::NotDescendantOfFinalized);
            }
            return Err(BlockError::UnknownParent(block.parent_root));
        };
        match block.parent_payload_status {
            PayloadStatus::Pending => return Err(BlockError::PendingParentStatus),
            PayloadStatus::Full if !self.is_payload_verified(&block.parent_root) => {
                return Err(BlockError::ParentPayloadNotVerified);
            }
            _ => {}
        }
        let current = self.current_slot();
        if block.slot > current {
            return Err(BlockError::FutureSlot {
                slot: block.slot,
                current,
            });
        }
        if parent.slot >= block.slot {
            return Err(BlockError::SlotNotAfterParent {
                slot: block.slot,
                parent_slot: parent.slot,
            });
        }
        if !self.is_ancestor_root(&block.parent_root, &self.finalized_checkpoint.root) {
            return Err(BlockError::NotDescendantOfFinalized);
        }
        let well_formed = block.head_vote_support.len() == block.head_votes.len()
            && block
                .head_votes
                .iter()
                .zip(&block.head_vote_support)
                .all(|(vote, bits)| bits.len() == vote.voter_indices.len());
        if !well_formed {
            return Err(BlockError::MalformedSupport);
        }

        let mut fg = block.fg;
        if fg.target.root == H256::ZERO {
            // `process_slot` fills the root of a target the block entered.
            fg.target.root = block.root;
        }
        let node = Block {
            parent: Some(block.parent_root),
            slot: block.slot,
            depth: parent.depth + 1,
            parent_payload_status: block.parent_payload_status,
            fg,
            receipt_time: self.time,
            head_votes: block.head_votes.clone(),
            head_vote_support: block.head_vote_support.clone(),
            children: Vec::new(),
        };
        self.blocks.insert(block.root, node);
        self.blocks
            .get_mut(&block.parent_root)
            .expect("parent checked above")
            .children
            .push(block.root);
        self.blocks_by_slot
            .entry(block.slot)
            .or_default()
            .push(block.root);
        self.update_finality(&fg);
        Ok(())
    }

    /// `on_execution_payload_envelope`, fork-choice part: record that the
    /// payload of `root` is verified, when it arrived, and whether it satisfies
    /// the inclusion list constraints (`record_payload_inclusion_list_
    /// satisfaction`). The host has checked data availability and verified the
    /// envelope. A payload already verified is left as it is.
    pub fn on_execution_payload_envelope(
        &mut self,
        root: &H256,
        inclusion_list_satisfied: bool,
    ) -> Result<(), PayloadError> {
        if self.is_payload_verified(root) {
            return Ok(());
        }
        if !self.contains(root) {
            return Err(PayloadError::UnknownBlock(*root));
        }
        self.payloads.insert(
            *root,
            Payload {
                receipt_time: self.time,
                inclusion_list_satisfied,
            },
        );
        Ok(())
    }

    /// Update a verified payload's inclusion list satisfaction, as optimistic
    /// sync does when a `NOT_VALIDATED` payload becomes `VALID`.
    pub fn set_payload_inclusion_list_satisfaction(&mut self, root: &H256, satisfied: bool) {
        if let Some(payload) = self.payloads.get_mut(root) {
            payload.inclusion_list_satisfied = satisfied;
        }
    }

    /// `is_payload_verified(store, root)`.
    pub fn is_payload_verified(&self, root: &H256) -> bool {
        self.payloads.contains_key(root)
    }

    /// `record_head_vote_committee`: keep the committee of a vote of the
    /// previous or current slot; a committee recorded before must agree.
    pub fn record_head_vote_committee(
        &mut self,
        slot: Slot,
        committee: Vec<ValidatorIndex>,
    ) -> Result<(), CommitteeError> {
        let current = self.current_slot();
        let HeadVoteCommittees::Recorded { by_slot, .. } = &mut self.committees else {
            return Err(CommitteeError::NotRecorded);
        };
        if slot + 1 < current {
            return Ok(());
        }
        match by_slot.get(&slot) {
            Some(recorded) if recorded.members() == committee.as_slice() => Ok(()),
            Some(_) => Err(CommitteeError::Mismatch(slot)),
            None => {
                by_slot.insert(slot, HeadVoteCommittee::new(committee));
                Ok(())
            }
        }
    }

    /// `on_head_vote_message(store, message)`, after the host checked the
    /// signature and recorded the committee: a message not yet seen, of the
    /// previous or current slot, with a payload status and a validator in the
    /// slot's committee (`is_valid_head_vote_message`), enters the pool with
    /// its receipt time.
    pub fn on_head_vote_message(&mut self, message: HeadVoteMessage) -> Result<(), HeadVoteError> {
        let current = self.current_slot();
        let previous = current.saturating_sub(1);
        let slot = message.data.slot;
        if self
            .head_vote_messages
            .get(&slot)
            .is_some_and(|pool| pool.iter().any(|pooled| pooled.message == message))
        {
            return Err(HeadVoteError::Duplicate);
        }
        if slot != previous && slot != current {
            return Err(HeadVoteError::WrongSlot { slot });
        }
        if message.data.payload_status().is_none() {
            return Err(HeadVoteError::InvalidPayloadStatus(
                message.data.payload_status,
            ));
        }
        if !self.committees.is_recorded(slot) {
            return Err(HeadVoteError::UnknownCommittee(slot));
        }
        if self.committees.seats(slot, message.validator_index) == 0 {
            return Err(HeadVoteError::NotInCommittee {
                slot,
                validator: message.validator_index,
            });
        }
        let receipt_time = self.time;
        self.head_vote_messages
            .entry(slot)
            .or_default()
            .push(PooledHeadVote {
                message,
                receipt_time,
            });
        Ok(())
    }

    /// `update_finality(store, state)`: raise `max_height`, adopt a
    /// lexicographically greater justification that descends from the
    /// finalized block, then adopt a higher finalization that strictly
    /// descends from the finalized block, is an ancestor of the (updated)
    /// justified block, and has a viable descendant.
    pub(crate) fn update_finality(&mut self, fg: &FgCheckpoints) {
        self.max_height = self.max_height.max(fg.target.height);

        let store_justification = (
            self.justified_checkpoint.height,
            self.justified_checkpoint.root,
        );
        let state_justification = (fg.justified.height, fg.justified.root);
        if state_justification > store_justification
            && self.is_ancestor_root(&fg.justified.root, &self.finalized_checkpoint.root)
        {
            self.justified_checkpoint = fg.justified;
        }

        if fg.finalized.height > self.finalized_checkpoint.height
            && self.is_strict_ancestor_root(&fg.finalized.root, &self.finalized_checkpoint.root)
            && self.is_ancestor_root(&self.justified_checkpoint.root, &fg.finalized.root)
            && self.has_viable_descendant(&fg.finalized.root)
        {
            self.finalized_checkpoint = fg.finalized;
        }
    }

    // ── Accessors ──────────────────────────────────────────────────────────

    /// `store.finalized_checkpoint`.
    pub fn finalized_checkpoint(&self) -> HeightCheckpoint {
        self.finalized_checkpoint
    }

    /// `store.justified_checkpoint`.
    pub fn justified_checkpoint(&self) -> HeightCheckpoint {
        self.justified_checkpoint
    }

    /// `store.max_height`.
    pub fn max_height(&self) -> Height {
        self.max_height
    }

    /// `store.latest_confirmed`.
    pub fn latest_confirmed(&self) -> ForkChoiceNode {
        self.latest_confirmed
    }

    /// `store.fast_confirmed_path`.
    pub fn fast_confirmed_path(&self) -> &HashSet<ForkChoiceNode> {
        &self.fast_confirmed_path
    }

    /// `store.saved_confirmations`.
    pub fn saved_confirmations(&self) -> &BTreeMap<Slot, ForkChoiceNode> {
        &self.saved_confirmations
    }

    /// `store.locks`, by deadline (expired ones may linger until the next
    /// slot's start).
    pub fn locks(&self) -> &BTreeMap<Tick, ForkChoiceNode> {
        &self.locks
    }

    /// The head vote messages held for `slot`, in arrival order.
    pub fn head_vote_messages(&self, slot: Slot) -> Vec<HeadVoteMessage> {
        self.head_vote_messages
            .get(&slot)
            .map(|pool| pool.iter().map(|pooled| pooled.message).collect())
            .unwrap_or_default()
    }

    /// Every processed block as `(root, parent, slot)`, for diagnostics.
    pub fn blocks(&self) -> impl Iterator<Item = (H256, Option<H256>, Slot)> + '_ {
        self.blocks
            .iter()
            .map(|(root, block)| (*root, block.parent, block.slot))
    }

    /// The roots of held blocks of `slot`.
    pub(crate) fn blocks_at_slot(&self, slot: Slot) -> &[H256] {
        self.blocks_by_slot
            .get(&slot)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }
}
