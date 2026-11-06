//! The available chain's vote views (fork-choice.md, "Available chain"):
//! which head votes a walk reads, and which of them count as support, from the
//! p2p pool and from the votes blocks carry.

use std::collections::HashSet;

use crate::fork_choice::View;
use crate::store::Store;
use crate::types::{
    AcVote, ForkChoiceNode, HeadVote, HeadVoteData, HeadVoteMessage, INFINITE_TIME, PayloadStatus,
    Slot, Tick, ValidatorIndex,
};

/// Votes read from blocks, and for each the positions of its voters that
/// support (`get_view_from_blocks`'s return).
pub(crate) type BlockVotes = (Vec<HeadVote>, Vec<HashSet<usize>>);

/// Messages read from the pool, and the indices of those that support
/// (`get_local_view_from_p2p_messages`'s return).
pub(crate) type MessageVotes = (Vec<HeadVoteMessage>, Vec<usize>);

/// `get_ac_vote(validator_index, data)`. `None` for a payload status outside
/// the three; such votes are refused at the gate, so none reach a view.
pub fn get_ac_vote(validator_index: ValidatorIndex, data: &HeadVoteData) -> Option<AcVote> {
    Some(AcVote {
        slot: data.slot,
        validator_index,
        supported_node: data.supported_node()?,
    })
}

/// `compute_merged_view(votes_from_messages, votes_from_blocks)`.
pub(crate) fn compute_merged_view(messages: &MessageVotes, blocks: &BlockVotes) -> View {
    let mut view = View::default();
    let support_indices: HashSet<usize> = messages.1.iter().copied().collect();
    for (index, message) in messages.0.iter().enumerate() {
        let Some(vote) = get_ac_vote(message.validator_index, &message.data) else {
            continue;
        };
        view.votes.insert(vote);
        if support_indices.contains(&index) {
            view.support_votes.insert(vote);
        }
    }
    for (head_vote, positions) in blocks.0.iter().zip(&blocks.1) {
        for (position, voter) in head_vote.voter_indices.iter().enumerate() {
            let Some(vote) = get_ac_vote(*voter, &head_vote.data) else {
                continue;
            };
            view.votes.insert(vote);
            if positions.contains(&position) {
                view.support_votes.insert(vote);
            }
        }
    }
    view
}

impl Store {
    /// `get_vote_resolution_time(store, supported_node, vote_slot,
    /// vote_receipt_time)`: when the vote's node became locally known, or
    /// [`INFINITE_TIME`] for a vote that does not resolve.
    pub(crate) fn get_vote_resolution_time(
        &self,
        supported: &ForkChoiceNode,
        vote_slot: Slot,
        vote_receipt_time: Tick,
    ) -> Tick {
        let Some(block_slot) = self.block_slot(&supported.root) else {
            return INFINITE_TIME;
        };
        if block_slot > vote_slot {
            return INFINITE_TIME;
        }
        if block_slot == vote_slot && supported.payload_status != PayloadStatus::Pending {
            return INFINITE_TIME;
        }
        if supported.payload_status == PayloadStatus::Full
            && !self.is_payload_verified(&supported.root)
        {
            return INFINITE_TIME;
        }
        if !self.is_ancestor_root(&supported.root, &self.finalized_checkpoint.root) {
            return INFINITE_TIME;
        }
        vote_receipt_time.max(self.get_block_and_payload_receipt_time(supported))
    }

    /// `get_local_view_from_p2p_messages(store, vote_slot,
    /// receipt_threshold_ms, resolution_threshold_ms)`.
    pub(crate) fn get_local_view_from_p2p_messages(
        &self,
        vote_slot: Slot,
        receipt_threshold: Tick,
        resolution_threshold: Tick,
    ) -> MessageVotes {
        let mut messages = Vec::new();
        let mut support = Vec::new();
        for pooled in self
            .head_vote_messages
            .get(&vote_slot)
            .into_iter()
            .flatten()
        {
            if pooled.receipt_time >= receipt_threshold {
                continue;
            }
            let index = messages.len();
            messages.push(pooled.message);
            let data = pooled.message.data;
            let resolved = data.supported_node().is_some_and(|node| {
                self.get_vote_resolution_time(&node, data.slot, pooled.receipt_time)
                    < resolution_threshold
            });
            if resolved {
                support.push(index);
            }
        }
        (messages, support)
    }

    /// `get_view_from_blocks(store, block_slot, vote_slot, block_predicate,
    /// get_supporting_indices)`.
    pub(crate) fn get_view_from_blocks(
        &self,
        block_slot: Slot,
        vote_slot: Slot,
        block_predicate: impl Fn(&ethlambda_types::primitives::H256) -> bool,
        get_supporting_indices: impl Fn(
            &ethlambda_types::primitives::H256,
            &HeadVote,
            &[bool],
        ) -> HashSet<usize>,
    ) -> BlockVotes {
        let mut votes = Vec::new();
        let mut positions = Vec::new();
        for root in self.blocks_at_slot(block_slot) {
            if !block_predicate(root) {
                continue;
            }
            let Some(block) = self.block(root) else {
                continue;
            };
            for (head_vote, bits) in block.head_votes.iter().zip(&block.head_vote_support) {
                if head_vote.data.slot != vote_slot {
                    continue;
                }
                votes.push(head_vote.clone());
                positions.push(get_supporting_indices(root, head_vote, bits));
            }
        }
        (votes, positions)
    }

    /// `get_local_view_from_blocks(store, vote_slot, receipt_threshold_ms,
    /// resolution_threshold_ms)`: votes of `vote_slot` in blocks of the next
    /// slot received before the receipt threshold; every voter of a vote
    /// supports when the vote resolves, from the block's receipt time, before
    /// the resolution threshold. The proposer's support bits are not read.
    pub(crate) fn get_local_view_from_blocks(
        &self,
        vote_slot: Slot,
        receipt_threshold: Tick,
        resolution_threshold: Tick,
    ) -> BlockVotes {
        self.get_view_from_blocks(
            vote_slot + 1,
            vote_slot,
            |root| {
                self.block(root)
                    .is_some_and(|block| block.receipt_time < receipt_threshold)
            },
            |root, head_vote, _bits| {
                let receipt = self.block(root).map_or(INFINITE_TIME, |b| b.receipt_time);
                let data = head_vote.data;
                let resolved = data.supported_node().is_some_and(|node| {
                    self.get_vote_resolution_time(&node, data.slot, receipt) < resolution_threshold
                });
                if resolved {
                    (0..head_vote.voter_indices.len()).collect()
                } else {
                    HashSet::new()
                }
            },
        )
    }

    /// `get_proposer_view(store, block_slot, vote_slot)`: votes of
    /// `vote_slot` in blocks of `block_slot` that descend from the finalized
    /// block, supporting where the proposer set the bit and the vote names a
    /// known block it could support.
    pub(crate) fn get_proposer_view(&self, block_slot: Slot, vote_slot: Slot) -> BlockVotes {
        let finalized = self.finalized_checkpoint.root;
        self.get_view_from_blocks(
            block_slot,
            vote_slot,
            |root| self.is_ancestor_root(root, &finalized),
            |_root, head_vote, bits| {
                let data = head_vote.data;
                let Some(status) = data.payload_status() else {
                    return HashSet::new();
                };
                let Some(supported_slot) = self.block_slot(&data.block_root) else {
                    return HashSet::new();
                };
                let supportable = (supported_slot < vote_slot || status == PayloadStatus::Pending)
                    && supported_slot <= vote_slot
                    && (status != PayloadStatus::Full
                        || self.is_payload_verified(&data.block_root));
                if supportable {
                    bits.iter()
                        .enumerate()
                        .filter(|(_, bit)| **bit)
                        .map(|(position, _)| position)
                        .collect()
                } else {
                    HashSet::new()
                }
            },
        )
    }

    /// `get_combined_local_view(store, slot, receipt_threshold_ms,
    /// resolution_threshold_ms)`.
    pub(crate) fn get_combined_local_view(
        &self,
        slot: Slot,
        receipt_threshold: Tick,
        resolution_threshold: Tick,
    ) -> View {
        let messages =
            self.get_local_view_from_p2p_messages(slot, receipt_threshold, resolution_threshold);
        let blocks = self.get_local_view_from_blocks(slot, receipt_threshold, resolution_threshold);
        compute_merged_view(&messages, &blocks)
    }
}
