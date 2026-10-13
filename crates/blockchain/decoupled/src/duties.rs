//! Validator duties and the confirmation update.
//!
//! Duties are store reads: the engine computes what an honest validator would
//! emit, and the host signs it, broadcasts it, and feeds it back through the
//! ordinary handlers (`on_block`, `on_goldfish_vote`, `on_attestation`). Only
//! the confirmation update and the fast unlocks write the store, and they run
//! inside `on_tick`.

use std::collections::{HashMap, HashSet};

use ethlambda_types::primitives::H256;

use crate::fork_choice::VoteView;
use crate::locks::at_least_half;
use crate::params::view_freeze;
use crate::store::Store;
use crate::types::{Attestation, GoldfishVote, Slot, ValidatorIndex};
use crate::validator_client::{AttestationInput, SourceFields};

/// The protocol content of an honest proposal (`propose_block`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    pub slot: Slot,
    /// `H`: the head to build on.
    pub parent_root: H256,
    /// `B.votes`: every previous-slot vote held.
    pub votes: Vec<GoldfishVote>,
    /// `B.support_votes`: the members resolved at proposal time.
    pub support_votes: Vec<GoldfishVote>,
    /// `B.attestations`: the pooled attestations that count on `H`'s chain.
    pub attestations: Vec<Attestation>,
}

impl Store {
    /// `propose_block(Σ)`, store side: what the slot-`Σ.s` proposer builds.
    /// Runs at `t_s`.
    pub fn proposal(&self) -> Proposal {
        let slot = self.slot;
        let previous = slot.saturating_sub(1);
        let view = self.pool_view(previous);
        let parent_root = self.head_with(&view, previous);
        let attestations = self.proposal_attestations(&parent_root);
        Proposal {
            slot,
            parent_root,
            votes: self.goldfish_votes(previous),
            support_votes: view.support_votes,
            attestations,
        }
    }

    /// The pooled attestations a block on `parent` should carry: those that
    /// set a bit `σ[parent]` does not have yet. A block's attestations are
    /// all counted against its parent's height, entry and justification (the
    /// height events run once, after them), so this is exact: a height pair
    /// naming the chain's current height and entry from a validator whose
    /// target (or, for a timeout, progress) bit is clear, or a finality pair
    /// naming the pending justification from a validator whose finality bit
    /// is clear. At most one attestation per validator and kind of bit.
    pub fn proposal_attestations(&self, parent: &H256) -> Vec<Attestation> {
        let Some(state) = self.chain_state(parent) else {
            return Vec::new();
        };
        let bit = |bits: &crate::chain_state::ValidatorBits, validator: ValidatorIndex| {
            usize::try_from(validator)
                .ok()
                .and_then(|index| bits.get(index))
                .unwrap_or(false)
        };
        let pending = state.justified_height > state.finalized_height;
        let mut targeted: HashSet<ValidatorIndex> = HashSet::new();
        let mut progressed: HashSet<ValidatorIndex> = HashSet::new();
        let mut finalizing: HashSet<ValidatorIndex> = HashSet::new();
        let mut selected = Vec::new();
        for attestation in self.pooled_attestations() {
            let validator = attestation.validator;
            let mut adds = false;
            if let Some(vote) = attestation.data.height_pair()
                && vote.height == state.height
                && vote.entry == state.entry.root
            {
                if vote.timeout {
                    adds |= !bit(&state.progress, validator)
                        && !progressed.contains(&validator)
                        && !targeted.contains(&validator);
                } else {
                    adds |= !bit(&state.target_participation, validator)
                        && !targeted.contains(&validator);
                }
            }
            if let Some(pair) = attestation.data.finality_pair()
                && pending
                && pair.height == state.justified_height
                && pair.target == state.justified.root
            {
                adds |= !bit(&state.finalize, validator) && !finalizing.contains(&validator);
            }
            if !adds {
                continue;
            }
            if let Some(vote) = attestation.data.height_pair()
                && vote.height == state.height
                && vote.entry == state.entry.root
            {
                progressed.insert(validator);
                if !vote.timeout {
                    targeted.insert(validator);
                }
            }
            if let Some(pair) = attestation.data.finality_pair()
                && pending
                && pair.height == state.justified_height
                && pair.target == state.justified.root
            {
                finalizing.insert(validator);
            }
            selected.push(attestation);
        }
        selected
    }

    /// The vote view of a slot-`slot` committee member at `t_s + Δ`: the
    /// previous-slot pool frozen at `t_{s−1} + 3Δ`, merged with the votes
    /// carried by every held slot-`s` proposal.
    pub(crate) fn voter_view(&self, slot: Slot) -> VoteView {
        let previous = slot.saturating_sub(1);
        let freeze = view_freeze(previous);
        let mut votes = Vec::new();
        let mut support = Vec::new();
        if let Some(pool) = self.gf_votes.get(&previous) {
            for pooled in pool {
                if pooled.stamp < freeze {
                    votes.push(pooled.vote);
                }
                if self
                    .vote_resolution(&pooled.vote, pooled.stamp)
                    .is_some_and(|resolution| resolution < freeze)
                {
                    support.push(pooled.vote);
                }
            }
        }
        for proposal in self.proposals_of(slot) {
            let node = &self.blocks[&proposal];
            votes.extend(node.votes.iter().filter(|v| v.slot == previous).copied());
            support.extend(
                node.support_votes
                    .iter()
                    .filter(|v| v.slot == previous && self.vote_resolves(v))
                    .copied(),
            );
        }
        VoteView::new(votes, support)
    }

    fn proposals_of(&self, slot: Slot) -> Vec<H256> {
        self.blocks
            .iter()
            .filter(|(_, node)| node.slot == slot)
            .map(|(root, _)| *root)
            .collect()
    }

    /// `goldfish_vote(Σ)`: the head a slot-`Σ.s` committee member votes for.
    /// Runs at `t_s + Δ`, after the tick stepped the locks back over the same
    /// view.
    ///
    /// The walk runs over the voter's processed-block view, which keeps only
    /// blocks processed before the freeze plus the ancestors of current
    /// proposals, with viability recomputed inside it.
    pub fn goldfish_vote_head(&self) -> H256 {
        let slot = self.slot;
        let previous = slot.saturating_sub(1);
        let view = self.voter_view(slot);
        let tree = self.voter_filtered_tree(slot);
        self.head_in_tree(&tree, &view, previous)
    }

    /// `voter_filtered_block_tree(Σ, s)`.
    fn voter_filtered_tree(&self, slot: Slot) -> HashSet<H256> {
        let freeze = view_freeze(slot.saturating_sub(1));
        let mut blocks: HashSet<H256> = self
            .blocks
            .iter()
            .filter(|(_, node)| node.stamp < freeze)
            .map(|(root, _)| *root)
            .collect();
        for proposal in self.proposals_of(slot) {
            let mut cursor = Some(proposal);
            while let Some(root) = cursor {
                if !blocks.insert(root) {
                    break;
                }
                cursor = self.node(&root).and_then(|node| node.parent);
            }
        }
        self.filtered_tree(Some(&blocks))
    }

    /// The confirmation update of slot `s`, at `t_s + 6Δ` (= `t_{s+1} + 2Δ`).
    ///
    /// Reads the slot's votes with the time-shifted quorum: support from the
    /// votes resolved before the support cutoff `t_s + 2Δ` whose voter cast
    /// nothing else before `t_s + 6Δ`, participation from every vote received
    /// before `t_s + 6Δ`. Then, in order:
    ///
    /// 1. fast unlock over the late votes, so the voters of a new fast lock
    ///    unlock whatever conflicts with it;
    /// 2. fast lock: the deepest block of the filtered tree that at least
    ///    half of the whole committee supports becomes `fg_confirmed` and is
    ///    locked;
    /// 3. the Goldfish confirmation: the majority walk from the anchor,
    ///    which confirms its end block when that block holds a majority of
    ///    the participants;
    /// 4. slow lock: when this and the previous `k − 1` slots each confirmed
    ///    a block, their deepest common ancestor is locked.
    pub(crate) fn update_confirmation(&mut self, slot: Slot) {
        let (support_cutoff, confirmation_time) = self.confirmation_window(slot);
        let pool: Vec<(GoldfishVote, i64)> = self
            .gf_votes
            .get(&slot)
            .map(|pool| pool.iter().map(|p| (p.vote, p.stamp)).collect())
            .unwrap_or_default();
        let early: Vec<GoldfishVote> = pool
            .iter()
            .filter(|(vote, stamp)| {
                self.vote_resolution(vote, *stamp)
                    .is_some_and(|resolution| resolution < support_cutoff)
            })
            .map(|(vote, _)| *vote)
            .collect();
        let late: Vec<GoldfishVote> = pool
            .iter()
            .filter(|(_, stamp)| *stamp < confirmation_time)
            .map(|(vote, _)| *vote)
            .collect();
        let support: Vec<GoldfishVote> = early
            .iter()
            .filter(|vote| {
                !late
                    .iter()
                    .any(|other| other.validator == vote.validator && other != *vote)
            })
            .copied()
            .collect();
        let voters: HashSet<ValidatorIndex> = late.iter().map(|vote| vote.validator).collect();

        // 1. Fast unlock.
        self.step_back_locks(&late, slot);

        // 2. Fast lock.
        let tree = self.filtered_tree(None);
        let committee = self.committee_size(slot);
        let mut supporters: HashMap<ValidatorIndex, H256> = HashMap::new();
        for vote in &support {
            supporters.insert(vote.validator, vote.head);
        }
        let tips: Vec<H256> = supporters.into_values().collect();
        let fast = self
            .support_counts(&tips)
            .into_iter()
            .filter(|(block, count)| tree.contains(block) && at_least_half(*count, committee))
            .map(|(block, _)| block)
            .reduce(|a, b| if self.deeper(&a, &b) { a } else { b });
        if let Some(block) = fast {
            self.form_lock(block, slot);
        }
        self.fg_confirmed = fast;

        // 3. The Goldfish confirmation, from the (possibly new) anchor.
        let anchor = self.anchor_in(&tree, slot);
        let view = VoteView::new(support.clone(), support);
        let mut scores = self.scores(&view, slot, &anchor);
        // `voters_count` is the late participants, not the support set's.
        scores.voters = voters.len() as u64;
        let head = self.ghost(anchor, &tree, &scores, |block| scores.majority(block));
        let confirmed = scores.majority(&head).then_some(head);

        // 4. Slow lock.
        let period = self.params.lock_period as usize;
        self.confirmations.push_back((slot, confirmed));
        while self.confirmations.len() > period {
            self.confirmations.pop_front();
        }
        if let Some(meet) = self.streak_meet(slot) {
            self.form_lock(meet, slot);
        }
    }

    /// The deepest common ancestor of the last `k` confirmations, when they
    /// are of the `k` consecutive slots ending at `slot` and each confirmed a
    /// block.
    fn streak_meet(&self, slot: Slot) -> Option<H256> {
        let period = self.params.lock_period;
        if self.confirmations.len() as u64 != period || slot + 1 < period {
            return None;
        }
        let first = slot + 1 - period;
        let mut meet: Option<H256> = None;
        for (offset, (confirmed_slot, confirmed)) in self.confirmations.iter().enumerate() {
            if *confirmed_slot != first + offset as u64 {
                return None;
            }
            let block = (*confirmed)?;
            meet = Some(match meet {
                None => block,
                Some(previous) => self.meet(&previous, &block)?,
            });
        }
        meet
    }

    /// The store side of the attestation duty at `t_s + 2Δ`, right after the
    /// confirmation update of slot `s − 1`: the height fields of
    /// `fg_confirmed`'s state (none when that update fast locked nothing), and
    /// the finality fields of the head's state.
    pub fn attestation_input(&self) -> AttestationInput {
        let source = self
            .fg_confirmed
            .and_then(|root| self.chain_state(&root))
            .map(|state| SourceFields {
                height: state.height,
                entry: state.entry.root,
                nonjustifiable: state.nonjustifiable,
            });
        let head = self.head();
        let head_state = &self.blocks[&head].state;
        AttestationInput {
            slot: self.slot,
            source,
            justified_height: head_state.justified_height,
            justified: head_state.justified.root,
            finalized_height: head_state.finalized_height,
        }
    }
}
