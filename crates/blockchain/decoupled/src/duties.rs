//! The fork choice's internal API for validator duties and its external API
//! (fork-choice.md: `get_ac_proposal`, `get_ac_vote_head`, `get_ac_frame`,
//! `get_confirmed_node`, `get_head`), plus the reads validator.md makes of the
//! source and head states to build FG attestation data.
//!
//! Duties are store reads: the engine computes what an honest validator would
//! emit, and the host signs it, broadcasts it, and feeds it back through the
//! ordinary handlers.

use crate::fork_choice::View;
use crate::params::{GENESIS_SLOT, HEAD_VOTE_DUE, SUPPORT_CUTOFF, time_into_slot, view_freeze};
use crate::store::Store;
use crate::types::{
    ForkChoiceNode, HeadVoteData, HeadVoteMessage, Height, HeightCheckpoint, INFINITE_TIME,
    PayloadStatus, Slot,
};
use crate::views::compute_merged_view;

/// `get_ac_proposal`'s result: the head to build on (never `Pending`), and the
/// previous slot's p2p head votes with the indices of those the proposer
/// counts as support (the block's `head_votes` and `head_vote_support`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcProposal {
    pub head: ForkChoiceNode,
    pub vote_messages: Vec<HeadVoteMessage>,
    pub support_indices: Vec<usize>,
}

/// `get_ac_frame`'s result: the FG source (the deepest viable node of the
/// fast-confirmed path, if any) and the head of the current slot's votes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcFrame {
    pub fg_confirmed: Option<ForkChoiceNode>,
    pub head: ForkChoiceNode,
}

/// What validator.md reads from the source and head states to build FG
/// attestation data: `target` from the source's state (its root filled when
/// the source entered the height), `justified` and `finalized_height` from the
/// head's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalityAttestationInput {
    pub target: HeightCheckpoint,
    pub justified: HeightCheckpoint,
    pub finalized_height: Height,
}

/// The head vote data of a committee member of `slot` voting for `head`
/// (validator.md, "Head vote data"): `Pending` when the head is the slot's own
/// block, the head's payload status otherwise.
pub fn head_vote_data(store: &Store, slot: Slot, head: ForkChoiceNode) -> HeadVoteData {
    let status = if store.block_slot(&head.root) == Some(slot) {
        PayloadStatus::Pending
    } else {
        head.payload_status
    };
    HeadVoteData::new(
        slot,
        ForkChoiceNode {
            root: head.root,
            payload_status: status,
        },
    )
}

impl Store {
    /// `get_ac_proposal(store)`, at a slot's start: the head over the previous
    /// slot's p2p votes, every received one counted and the resolved ones
    /// supporting.
    pub fn get_ac_proposal(&self) -> AcProposal {
        debug_assert_eq!(time_into_slot(self.time), 0);
        let current = self.current_slot();
        debug_assert!(current > GENESIS_SLOT);
        let previous = current.saturating_sub(1);
        let frame = self.get_fg_frame();
        let (vote_messages, support_indices) =
            self.get_local_view_from_p2p_messages(previous, INFINITE_TIME, INFINITE_TIME);
        let view = compute_merged_view(
            &(vote_messages.clone(), support_indices.clone()),
            &(Vec::new(), Vec::new()),
        );
        let mut head = self.get_head_in_tree(&frame, &frame.tree, &view, previous);
        if head.payload_status == PayloadStatus::Pending {
            head.payload_status = PayloadStatus::Empty;
        }
        AcProposal {
            head,
            vote_messages,
            support_indices,
        }
    }

    /// `get_ac_vote_head(store)`, at the head vote deadline: the previous
    /// slot's p2p view frozen at its view freeze, merged with the current
    /// slot's proposals' views, walked over the voter's subtree.
    ///
    /// Sign [`head_vote_data`] of the result, not the node itself: for the
    /// current slot's block the walk may end on its `Empty` node, and the vote
    /// names it `Pending`.
    pub fn get_ac_vote_head(&self) -> ForkChoiceNode {
        debug_assert_eq!(time_into_slot(self.time), HEAD_VOTE_DUE);
        let current = self.current_slot();
        if current == GENESIS_SLOT {
            return ForkChoiceNode::empty(self.finalized_checkpoint.root);
        }
        let frame = self.get_fg_frame();
        let freeze = view_freeze(current - 1);
        let local = self.get_local_view_from_p2p_messages(current - 1, freeze, freeze);
        let proposer = self.get_proposer_view(current, current - 1);
        let view = compute_merged_view(&local, &proposer);
        let voter_subtree = self.get_voter_subtree(&frame.tree, current);
        let head = self.get_head_in_tree(&frame, &voter_subtree, &view, current - 1);
        if self
            .block_slot(&head.root)
            .is_some_and(|slot| slot < current)
            && head.payload_status == PayloadStatus::Pending
        {
            ForkChoiceNode::empty(head.root)
        } else {
            head
        }
    }

    /// `get_ac_frame(store)`, at or after the support cutoff.
    pub fn get_ac_frame(&self) -> AcFrame {
        debug_assert!(time_into_slot(self.time) >= SUPPORT_CUTOFF);
        let current = self.current_slot();
        let frame = self.get_fg_frame();
        let view = self.get_combined_local_view(current, INFINITE_TIME, INFINITE_TIME);
        let head = self.get_head_in_tree(&frame, &frame.tree, &view, current);
        let viable_subtree = self.get_viable_subtree(&frame, &frame.tree);
        let fast_confirmed_viable: Vec<ForkChoiceNode> = self
            .fast_confirmed_path
            .iter()
            .filter(|node| viable_subtree.contains(node))
            .copied()
            .collect();
        AcFrame {
            fg_confirmed: self.get_deepest_node(&fast_confirmed_viable),
            head,
        }
    }

    /// The source and head state reads of validator.md's "Attestation data",
    /// from one `get_ac_frame` observation. `None` when there is no FG source,
    /// in which case the validator does not attest.
    pub fn finality_attestation_input(&self, frame: &AcFrame) -> Option<FinalityAttestationInput> {
        let source = frame.fg_confirmed?;
        let source_state = self.block_checkpoints(&source.root)?;
        let head_state = self.block_checkpoints(&frame.head.root)?;
        Some(FinalityAttestationInput {
            target: source_state.target,
            justified: head_state.justified,
            finalized_height: head_state.finalized.height,
        })
    }

    /// `get_confirmed_node(store)`: `latest_confirmed`, falling back to the
    /// finalized node when it left the frame, is the finalized node, or
    /// conflicts with the head. This is what an execution layer's safe block
    /// follows (`get_confirmed_execution_block_hash` maps it to the bid's
    /// block hash when `Full`, its parent block hash otherwise).
    pub fn get_confirmed_node(&self) -> ForkChoiceNode {
        let frame = self.get_fg_frame();
        if !frame.tree.contains(&self.latest_confirmed)
            || self.latest_confirmed == frame.finalized_node
        {
            return frame.finalized_node;
        }
        let head = self.get_head();
        if !self.is_compatible(&head, &self.latest_confirmed) {
            return frame.finalized_node;
        }
        self.latest_confirmed
    }

    /// `get_head(store)`: the walk over the current slot's votes at or after
    /// its support cutoff, the previous slot's before; never `Pending`.
    pub fn get_head(&self) -> ForkChoiceNode {
        let current = self.current_slot();
        if current == GENESIS_SLOT {
            return ForkChoiceNode::empty(self.finalized_checkpoint.root);
        }
        let slot = if time_into_slot(self.time) >= SUPPORT_CUTOFF {
            current
        } else {
            current - 1
        };
        let frame = self.get_fg_frame();
        let view: View = self.get_combined_local_view(slot, INFINITE_TIME, INFINITE_TIME);
        let mut head = self.get_head_in_tree(&frame, &frame.tree, &view, slot);
        if head.payload_status == PayloadStatus::Pending {
            head.payload_status = PayloadStatus::Empty;
        }
        head
    }
}
