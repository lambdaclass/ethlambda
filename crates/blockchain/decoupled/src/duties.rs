//! Validator duties and available confirmation (PROTOCOL.md figures
//! `alg:store` and `alg:duties`).
//!
//! Duties are store reads: the engine computes what an honest validator would
//! emit, and the host signs it, broadcasts it, and feeds it back through the
//! ordinary handlers (`on_block`, `on_goldfish_vote`, `on_sg_vote`). Only the
//! confirmation update writes the store, and it runs inside `on_tick`.

use std::collections::{HashMap, HashSet};

use ethlambda_types::primitives::H256;

use crate::fork_choice::VoteView;
use crate::params::{slot_start, view_freeze};
use crate::store::Store;
use crate::types::{Attestation, GoldfishVote, Round, Slot, ValidatorIndex};
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
    /// `B.attestations` (`proposal_attestations`).
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

    /// `proposal_attestations(Σ, H)`: the pool's attestations in the inclusive
    /// window `[max(0, r − η_SG), r]`, plus those carried by held blocks of a
    /// slot in that window, minus every attestation already on `H`'s chain,
    /// with at most two attestations per validator and round (the first two
    /// in this order, as the formalization fixes).
    pub fn proposal_attestations(&self, head: &H256) -> Vec<Attestation> {
        let round = self.current_round();
        let in_window = |r: Round| self.params.admits_round(round, r);

        let mut candidates: Vec<Attestation> = Vec::new();
        for (pool_round, pool) in &self.attestations {
            if in_window(*pool_round) {
                candidates.extend(pool.iter().map(|p| p.attestation.clone()));
            }
        }
        let mut held: Vec<(&H256, &crate::store::Node)> = self
            .blocks
            .iter()
            .filter(|(_, node)| in_window(self.params.round_of(node.slot)))
            .collect();
        held.sort_by_key(|(root, _)| **root);
        for (_, node) in held {
            candidates.extend(
                node.attestations
                    .iter()
                    .filter(|a| in_window(a.round()))
                    .cloned(),
            );
        }

        let on_chain = self.attestations_on_chain(head, round.saturating_sub(self.params.eta_sg));
        let mut seen: HashSet<Attestation> = HashSet::new();
        let mut per_signer: HashMap<(ValidatorIndex, Round), usize> = HashMap::new();
        let mut selected = Vec::new();
        for attestation in candidates {
            if on_chain.contains(&attestation) || seen.contains(&attestation) {
                continue;
            }
            let count = per_signer
                .entry((attestation.validator, attestation.round()))
                .or_default();
            if *count >= 2 {
                continue;
            }
            *count += 1;
            seen.insert(attestation.clone());
            selected.push(attestation);
        }
        selected
    }

    /// The attestations carried by `head` and its ancestors of a round at or
    /// after `from_round`. An attestation of round `k` can only sit in a
    /// block of round at least `k`, so older blocks cannot hold a window row.
    fn attestations_on_chain(&self, head: &H256, from_round: Round) -> HashSet<Attestation> {
        let mut found = HashSet::new();
        let mut cursor = Some(*head);
        while let Some(root) = cursor {
            let Some(node) = self.node(&root) else {
                break;
            };
            if self.params.round_of(node.slot) < from_round {
                break;
            }
            found.extend(node.attestations.iter().cloned());
            cursor = node.parent;
        }
        found
    }

    /// `goldfish_vote(Σ)`: the head a slot-`Σ.s` committee member votes for.
    /// Runs at `t_s + Δ`.
    ///
    /// The vote view merges the previous-slot pool frozen at
    /// `t_{s−1} + 3Δ` with the votes carried by every held slot-`s` proposal;
    /// the walk runs over the voter's processed-block view, which keeps only
    /// blocks processed before the freeze plus the ancestors of current
    /// proposals, with viability recomputed inside it.
    pub fn goldfish_vote_head(&self) -> H256 {
        let slot = self.slot;
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
        let proposals: Vec<H256> = self
            .blocks
            .iter()
            .filter(|(_, node)| node.slot == slot)
            .map(|(root, _)| *root)
            .collect();
        for proposal in &proposals {
            let node = &self.blocks[proposal];
            votes.extend(node.votes.iter().filter(|v| v.slot == previous).copied());
            support.extend(
                node.support_votes
                    .iter()
                    .filter(|v| v.slot == previous && self.vote_resolves(v))
                    .copied(),
            );
        }
        let view = VoteView::new(votes, support);
        let tree = self.voter_filtered_tree(slot, freeze, &proposals);
        self.head_in_tree(&tree, &view, previous)
    }

    /// `voter_filtered_block_tree(Σ, s)`.
    fn voter_filtered_tree(&self, _slot: Slot, freeze: i64, proposals: &[H256]) -> HashSet<H256> {
        let mut blocks: HashSet<H256> = self
            .blocks
            .iter()
            .filter(|(_, node)| node.stamp < freeze)
            .map(|(root, _)| *root)
            .collect();
        for proposal in proposals {
            let mut cursor = Some(*proposal);
            while let Some(root) = cursor {
                if !blocks.insert(root) {
                    break;
                }
                cursor = self.node(&root).and_then(|node| node.parent);
            }
        }
        self.filtered_tree(Some(&blocks))
    }

    /// `update_confirmation(Σ, s)` at `t_s + 6Δ` (= `t_{s+1} + 2Δ`): run the
    /// composed walk over the confirmation window's votes, write
    /// `Σ.live_confirmed`, and update the two user-facing records.
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

        let tree = self.filtered_tree(None);
        let root = self.fg_root();
        let anchor = self.sg_root();
        let view = VoteView::new(support.clone(), support);
        let mut scores = self.scores(&view, slot, &anchor);
        // `voters_count` is the late participants, not the support set's.
        scores.voters = voters.len() as u64;
        let head = self.ghost(anchor, &tree, &scores, |block| scores.majority(block));

        let candidate = if scores.majority(&head) {
            self.live_confirmed = head;
            Some(head)
        } else {
            self.live_confirmed = root;
            // The saved grade-2 block stands in for the walk.
            let frame = self.read_frame(self.current_round());
            self.active_prefix(frame.g2.flatten())
        };
        self.update_user_confirmation_records(candidate);
    }

    /// `update_user_confirmation_records(Σ, C)`.
    fn update_user_confirmation_records(&mut self, candidate: Option<H256>) {
        let confirmed = self.advance(self.latest_confirmed, candidate);
        let stable_root = self.stable_root();
        self.latest_stable = self.advance(self.latest_stable, Some(stable_root));
        if self.is_ancestor(&self.latest_stable, &confirmed) {
            // The candidate extends the new stable record.
            self.latest_confirmed = confirmed;
        } else if !self.is_ancestor(&self.latest_stable, &self.latest_confirmed) {
            // The old record has left the stable chain.
            self.latest_confirmed = self.latest_stable;
        }
    }

    /// `advance(old, C)`: no candidate, or an ancestor, leaves the record.
    fn advance(&self, old: H256, candidate: Option<H256>) -> H256 {
        match candidate {
            Some(c) if !self.is_ancestor(&c, &old) => c,
            _ => old,
        }
    }

    /// `attest(Σ, Λ)`, store side: the vote information the validator client
    /// turns into a combined attestation at `a_r`. Run after the tick at
    /// `a_r`, which has already run that instant's confirmation.
    pub fn attestation_input(&self) -> AttestationInput {
        let round = self.current_round();
        let frame = self.read_frame(round);
        let grade2 = self.grade2_block(&frame);
        let anchor = self.sg_root();
        let live = self.live_confirmed;

        // `get_sg_vote(Σ, A_G2)`.
        let safe = self
            .deepest_clear(&anchor, &live, &frame)
            .or(grade2)
            .unwrap_or_else(|| match frame.g2 {
                // Grade 2 exists, but the root has passed it.
                Some(Some(_)) => self.fg_root(),
                // The anchor fallback keeps voting total.
                _ => anchor,
            });

        // `get_fg_vote(Σ, A_G2)`.
        let view = self.pool_view(self.slot);
        let head = self.head_with(&view, self.slot);
        let head_state = &self.blocks[&head].state;
        let source = grade2.map(|g2| {
            let source = self.deepest_clear(&g2, &live, &frame).unwrap_or(g2);
            let state = &self.blocks[&source].state;
            SourceFields {
                height: state.height,
                entry: state.entry.root,
                nonjustifiable: state.nonjustifiable,
            }
        });
        AttestationInput {
            round,
            safe,
            source,
            justified_height: head_state.justified_height,
            justified: head_state.justified.root,
            finalized_height: head_state.finalized_height,
        }
    }

    /// Whether `t` is a slot's proposal instant, for hosts that schedule
    /// their own timers.
    pub fn is_proposal_time(t: i64) -> bool {
        t >= 0 && t == slot_start(crate::params::slot_of(t)) && t > 0
    }
}
