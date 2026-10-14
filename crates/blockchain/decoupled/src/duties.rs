//! Validator duties, the confirmation update and the FG action's inputs (the
//! specification's figures 2, 6 and 7).
//!
//! Duties are store reads: the engine computes what an honest validator would
//! emit, and the host signs it, broadcasts it, and feeds it back through the
//! ordinary handlers (`on_block`, `on_goldfish_vote`, `on_attestation`). Only
//! the confirmation update and the revocation write the store, and they run
//! inside `on_tick`.

use std::collections::HashSet;

use ethlambda_types::primitives::H256;

use crate::chain_state::valid_attestation;
use crate::fork_choice::VoteView;
use crate::params::{confirmation_time, support_cutoff, view_freeze};
use crate::store::Store;
use crate::types::{Attestation, GoldfishVote, Slot, ValidatorIndex};
use crate::validator_client::{AttestationInput, SourceFields};

/// The protocol content of an honest proposal (`propose_block`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    pub slot: Slot,
    /// `H`: the head to build on.
    pub parent_root: H256,
    /// `B.votes`: every previous-slot vote held, in the order of the pool.
    pub votes: Vec<GoldfishVote>,
    /// `B.support_votes`: the members resolved at proposal time, in the same
    /// order.
    pub support_votes: Vec<GoldfishVote>,
    /// `B.attestations`: `proposal_attestations(Σ, H)`.
    pub attestations: Vec<Attestation>,
}

impl Store {
    /// `propose_block`, store side: `AC_PROPOSAL` for the parent and the
    /// payload, then `PROPOSAL_ATTESTATIONS`. Runs at `t_s`.
    pub fn proposal(&self) -> Proposal {
        let slot = self.slot;
        let previous = slot.saturating_sub(1);
        let votes = self.goldfish_votes(previous);
        let support_votes: Vec<GoldfishVote> = votes
            .iter()
            .filter(|vote| self.vote_resolves(vote))
            .copied()
            .collect();
        let view = VoteView::new(votes.clone(), support_votes.clone());
        let parent_root = self.head_with(&view, previous);
        let attestations = self.proposal_attestations(&parent_root);
        Proposal {
            slot,
            parent_root,
            votes,
            support_votes,
            attestations,
        }
    }

    /// `proposal_attestations(Σ, H)`: the pooled attestations that are valid
    /// against `σ[H]` and not already on `H`'s chain, in the order of the
    /// pool.
    pub fn proposal_attestations(&self, parent: &H256) -> Vec<Attestation> {
        let Some(state) = self.chain_state(parent) else {
            return Vec::new();
        };
        let carried = self.carried_on_chain(parent);
        self.attestations
            .iter()
            .filter(|attestation| {
                valid_attestation(state, attestation) && !carried.contains(attestation)
            })
            .cloned()
            .collect()
    }

    /// The attestations carried by `head`'s chain that could still be valid
    /// against `σ[head]`.
    ///
    /// A block on the chain could carry one only if its parent's state was
    /// at least as high as the lowest height such an attestation can need:
    /// `σ[head].h` for the chain's own entry, `j + 1` for a pending pair
    /// `(j, T)`. Heights only grow along a chain, so the walk stops at the
    /// first parent below that.
    fn carried_on_chain(&self, head: &H256) -> HashSet<&Attestation> {
        let mut carried = HashSet::new();
        let Some(state) = self.chain_state(head) else {
            return carried;
        };
        let lowest = state
            .pending_finality
            .iter()
            .map(|pending| pending.height + 1)
            .min()
            .unwrap_or(state.height)
            .min(state.height);
        let mut cursor = *head;
        while let Some(node) = self.node(&cursor) {
            let Some(parent) = node.parent.and_then(|p| self.node(&p).map(|n| (p, n))) else {
                break;
            };
            if parent.1.state.height < lowest {
                break;
            }
            carried.extend(node.attestations.iter());
            cursor = parent.0;
        }
        carried
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

    /// `goldfish_vote(𝒜, Φ, t)`: the head a slot-`slot(t)` committee member
    /// votes for. Runs at `t_s + Δ`, after the tick revoked the locks.
    ///
    /// The walk runs over the viable tree of the voter block tree, which
    /// keeps only blocks received before the freeze plus the ancestors of
    /// current proposals; it starts at the anchor of the full viable tree.
    pub fn goldfish_vote_head(&self) -> H256 {
        let slot = self.slot;
        let previous = slot.saturating_sub(1);
        let view = self.voter_view(slot);
        let tree = self.viable_tree(Some(&self.voter_block_tree(slot)));
        self.head_in_tree(&tree, &view, previous)
    }

    /// `voter_block_tree(𝒜, Φ, s)`: the blocks of `Φ.tree` received before
    /// the freeze `t_{s−1} + 3Δ`, and every ancestor of a slot-`s` proposal.
    fn voter_block_tree(&self, slot: Slot) -> HashSet<H256> {
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
        blocks
    }

    /// `update_confirmation(𝒜, Φ, t, s)` at `t_s + 2Δ`: the confirmation
    /// update of slot `s' = s − 1`, at its `t_{s'} + 6Δ`.
    ///
    /// Support counts only the votes resolved before `t_{s'} + 2Δ` of
    /// validators with no second vote before `t_{s'} + 6Δ`, and the
    /// participants are the validators with a vote before `t_{s'} + 6Δ`. The
    /// walk starts at `Φ.F` and descends in `Φ.tree` through children that
    /// hold a strict majority of the participants. Its end, when it holds the
    /// majority, is the result `C`; a live lock that conflicts with `C`
    /// vetoes it. Otherwise the update advances the confirmation record and
    /// writes at most one entry: the deepest block on the path to `C` that
    /// passes the fast test or the slow test.
    pub(crate) fn update_confirmation(&mut self, slot: Slot) {
        let Some(evaluated) = slot.checked_sub(1) else {
            return;
        };
        let (cutoff, update_time) = (support_cutoff(evaluated), confirmation_time(evaluated));
        let pool: Vec<(GoldfishVote, i64)> = self
            .gf_votes
            .get(&evaluated)
            .map(|pool| pool.iter().map(|p| (p.vote, p.stamp)).collect())
            .unwrap_or_default();
        let early: Vec<GoldfishVote> = pool
            .iter()
            .filter(|(vote, stamp)| {
                self.vote_resolution(vote, *stamp)
                    .is_some_and(|resolution| resolution < cutoff)
            })
            .map(|(vote, _)| *vote)
            .collect();
        let late: Vec<GoldfishVote> = pool
            .iter()
            .filter(|(_, stamp)| *stamp < update_time)
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

        // `score = goldfish_score(support_votes, support_votes, s', ·)`, and
        // `voters_count` is the late participants, not the support set's.
        let finalized = self.finalized;
        let view = VoteView::new(support.clone(), support);
        let mut scores = self.scores(&view, evaluated, &finalized);
        scores.voters = voters.len() as u64;
        // `Φ.tree` is every block extending `Φ.F`, which is everything a walk
        // from `Φ.F` can reach.
        let end = self.ghost(finalized, |_| true, &scores, |block| scores.majority(block));
        let confirmed = scores.majority(&end).then_some(end);

        self.saved_confirmation.insert(evaluated, confirmed);
        self.fast_blocks.clear();
        let Some(confirmed) = confirmed else {
            return;
        };
        let vetoed = self
            .live_entries()
            .any(|(block, _)| !self.compatible(&block, &confirmed));
        if vetoed {
            return;
        }
        self.latest_confirmed = self.advance_record(confirmed);

        // The path from `Φ.F` to `C`, without the genesis block, deepest
        // first. The fast test and the slow test only get easier towards the
        // root.
        let committee = self.committee_size(evaluated);
        // The saved confirmations of the slots `j` with `s' − k < j < s'`,
        // when every one is a block of `Φ.tree`. Slots before the first one
        // (negative slots too) saved `⊥`.
        let lock_period = self.params.lock_period;
        let slow_window: Option<Vec<H256>> = (evaluated + 1 >= lock_period)
            .then(|| evaluated + 1 - lock_period..evaluated)
            .and_then(|slots| {
                slots
                    .map(|j| {
                        self.saved_confirmation
                            .get(&j)
                            .copied()
                            .flatten()
                            .filter(|saved| self.is_ancestor(&self.finalized, saved))
                    })
                    .collect()
            });
        let fast = |block: &H256| 2 * scores.score(block) >= committee;
        let slow = |block: &H256| {
            slow_window
                .as_ref()
                .is_some_and(|saved| saved.iter().all(|saved| self.is_ancestor(block, saved)))
        };
        let mut lock_block = None;
        let mut fast_blocks = Vec::new();
        let mut cursor = Some(confirmed);
        while let Some(block) = cursor {
            if block == self.anchor || !self.is_ancestor(&self.finalized, &block) {
                break;
            }
            let passes_fast = fast(&block);
            if passes_fast {
                fast_blocks.push(block);
            }
            if lock_block.is_none() && (passes_fast || slow(&block)) {
                lock_block = Some(block);
            }
            cursor = self.parent(&block);
        }
        self.fast_blocks = fast_blocks;
        if let Some(block) = lock_block {
            let deadline = self.params.lock_deadline(evaluated);
            self.add_lock_entry(block, deadline);
        }
    }

    /// `advance(Φ, old, C)`: an ancestor candidate leaves the record
    /// unchanged, an extension or a conflicting candidate replaces it.
    fn advance_record(&self, candidate: H256) -> H256 {
        let old = self.latest_confirmed;
        let old_in_tree = self.is_ancestor(&self.finalized, &old);
        if old_in_tree && self.is_ancestor(&candidate, &old) {
            old
        } else {
            candidate
        }
    }

    /// The source of the FG action: the deepest block of `𝒜.fast_blocks`
    /// that is in the full viable tree, if any.
    pub fn source(&self) -> Option<H256> {
        let viable = self.viable_tree(None);
        self.fast_blocks
            .iter()
            .filter(|block| viable.contains(*block))
            .copied()
            .reduce(|a, b| if self.deeper(&a, &b) { a } else { b })
    }

    /// `AC_TO_FG` and the reads of `FG_ATTEST`, for the FG action at `a_r`
    /// (after the confirmation update of the round's first slot): the height
    /// fields of the source's state (none without a source), and the
    /// finality fields of the head's state, where the head is the walk over
    /// the full viable tree with the current slot's votes.
    pub fn attestation_input(&self) -> AttestationInput {
        let source = self
            .source()
            .and_then(|root| self.chain_state(&root))
            .map(|state| SourceFields {
                height: state.height,
                entry: state.entry.root,
            });
        let slot = self.slot;
        let head = self.head_with(&self.pool_view(slot), slot);
        let head_state = &self.blocks[&head].state;
        AttestationInput {
            slot,
            source,
            justified_height: head_state.justified_height,
            justified: head_state.justified.root,
            finalized_height: head_state.finalized_height,
        }
    }
}
