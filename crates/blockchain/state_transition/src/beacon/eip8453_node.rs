//! A beacon node's EIP-8453 fork choice, shared by the chain actor, the p2p
//! layer and the Beacon API.
//!
//! [`SharedEip8453Node`] wraps the engine (`ethlambda_decoupled::Store`) with
//! what the beacon wire needs around it:
//!
//! * the gossip `Seen` sets p2p-interface.md adds
//!   (`head_vote_validator_slots`, `attestation_validator_rounds`), so a
//!   message is accepted once whether it came from gossip or from this node's
//!   validator client;
//! * the signed head vote messages and single attestations behind what the
//!   engine holds, which a proposal aggregates into its body;
//! * the validator duty inputs computed at the protocol instant each belongs to
//!   (`get_ac_proposal` at a slot's start, `get_ac_vote_head` at its head vote
//!   deadline), so a validator client asking a moment later reads the value the
//!   protocol prescribes for that instant rather than one from a store that has
//!   moved on.
//!
//! Who does what: the chain actor installs the node at the fork transition (or
//! at startup past it), ticks it every `Δ`, and feeds it every imported block
//! and verified payload; the p2p layer and the Beacon API validate head votes
//! and attestations (`gossip::head_vote`, `gossip::fg_attestation`) and hand the
//! accepted ones to [`Eip8453Node::accept_head_vote`] and
//! [`Eip8453Node::accept_attestation`]. Every entry point takes the current
//! time and advances the engine to it first, so an object is stamped after the
//! tick of its own instant (fork-choice.md's `on_tick` note).
//!
//! The lock is a `std::sync::Mutex`: every call is short and synchronous, and
//! no caller may hold it across an `.await`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};

use ethlambda_decoupled::{
    AcFrame, AcProposal, BlockError, BlockInput, CommitteeError, FinalityAttestationInput,
    HeadVoteError, PayloadError, PayloadInvalidation, Store as Engine, TickEvents, head_vote_data,
};
use ethlambda_types::decoupled::{
    BlockRef, DecoupledStatus, ForkChoiceNode, HeadVoteData, HeightCheckpoint,
};
use libssz_types::ProgressiveBitlist;

use crate::beacon::config::Config;
use crate::beacon::containers::eip8453;
use crate::beacon::eip8453_fork_choice::tick_at_ms;
use crate::beacon::helpers::eip8453::compute_round_at_slot;
use crate::beacon::primitives::{Root, Slot, ValidatorIndex};

/// How many slots of signed head votes are kept for proposals: the previous
/// slot's are what a proposal at a slot's start carries.
const HEAD_VOTE_SLOTS_KEPT: u64 = 2;

/// How many rounds of single attestations are kept for proposals. An
/// attestation stays includable while its target is the state's or a pending
/// finality's, which the gadget moves through in a few rounds.
const ATTESTATION_ROUNDS_KEPT: u64 = 4;

/// Why a duty input is not available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DutyError {
    #[error("the EIP-8453 fork choice is not running yet")]
    Inactive,
    #[error("slot {asked} is not the current slot {current}")]
    WrongSlot { asked: Slot, current: Slot },
    #[error("slot {slot}'s {duty} instant has not been reached")]
    NotYet { slot: Slot, duty: &'static str },
    #[error("slot {slot}'s {duty} instant passed before this node computed it")]
    Missed { slot: Slot, duty: &'static str },
}

/// What a proposer reads at its slot's start: `get_ac_proposal`'s head (never
/// `Pending`), and the previous slot's head votes the block carries, already
/// grouped into `HeadVote` aggregates with their support bits (the body's
/// `head_votes` and `head_vote_support`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eip8453Proposal {
    pub slot: Slot,
    pub head: ForkChoiceNode,
    pub head_votes: Vec<eip8453::HeadVote>,
    pub head_vote_support: Vec<ProgressiveBitlist>,
}

/// The shared handle: the node once the fork choice runs, `None` before.
#[derive(Debug, Clone, Default)]
pub struct SharedEip8453Node(Arc<Mutex<Option<Eip8453Node>>>);

impl SharedEip8453Node {
    pub fn new() -> Self {
        Self::default()
    }

    /// Put `node` in place, replacing any node before it.
    pub fn install(&self, node: Eip8453Node) {
        *self.lock() = Some(node);
    }

    /// Whether the fork choice runs.
    pub fn is_active(&self) -> bool {
        self.lock().is_some()
    }

    /// The node, locked. `None` inside before the fork choice runs.
    pub fn lock(&self) -> MutexGuard<'_, Option<Eip8453Node>> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Run `f` on the node, or answer [`DutyError::Inactive`].
    pub fn with<R>(&self, f: impl FnOnce(&mut Eip8453Node) -> R) -> Result<R, DutyError> {
        self.lock().as_mut().map(f).ok_or(DutyError::Inactive)
    }
}

/// The engine and what the beacon wire keeps around it.
#[derive(Debug, Clone)]
pub struct Eip8453Node {
    engine: Engine,
    config: Config,
    /// `seen.head_vote_validator_slots`.
    seen_head_votes: HashSet<(Slot, ValidatorIndex)>,
    /// `seen.attestation_validator_rounds`.
    seen_attestations: HashSet<(u64, ValidatorIndex)>,
    /// The signed head vote messages behind the engine's pool, by slot, in
    /// arrival order.
    head_votes: BTreeMap<Slot, Vec<eip8453::HeadVoteMessage>>,
    /// Accepted single attestations, by the round they were cast in.
    attestations: BTreeMap<u64, Vec<eip8453::SingleAttestation>>,
    /// `get_ac_proposal` at each slot's start.
    proposals: BTreeMap<Slot, ethlambda_decoupled::AcProposal>,
    /// `get_ac_vote_head` at each slot's head vote deadline.
    vote_heads: BTreeMap<Slot, ForkChoiceNode>,
}

impl Eip8453Node {
    pub fn new(config: Config, engine: Engine) -> Self {
        Self {
            engine,
            config,
            seen_head_votes: HashSet::new(),
            seen_attestations: HashSet::new(),
            head_votes: BTreeMap::new(),
            attestations: BTreeMap::new(),
            proposals: BTreeMap::new(),
            vote_heads: BTreeMap::new(),
        }
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    pub fn engine_mut(&mut self) -> &mut Engine {
        &mut self.engine
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Run every engine tick up to `now_ms`, one at a time, recording the duty
    /// inputs of the instants it passes, and return what each tick asks of the
    /// host. A node that has never ticked jumps to `now_ms` (the engine's own
    /// rule), so it records nothing for the past.
    pub fn advance_to_ms(&mut self, now_ms: u64) -> Vec<TickEvents> {
        let now = tick_at_ms(&self.config, now_ms);
        let mut events = Vec::new();
        loop {
            let target = if self.engine.has_ticked() && self.engine.time() < now {
                self.engine.time() + 1
            } else {
                now
            };
            let step = self.engine.advance_to(target);
            if step.is_empty() {
                break;
            }
            for event in &step {
                self.on_tick_event(event);
            }
            events.extend(step);
            if self.engine.time() >= now {
                break;
            }
        }
        if !events.is_empty() {
            self.prune();
        }
        events
    }

    fn on_tick_event(&mut self, event: &TickEvents) {
        if event.tick != self.engine.time() {
            return;
        }
        if event.propose {
            let proposal = self.engine.get_ac_proposal();
            self.proposals.insert(event.slot, proposal);
        }
        if event.head_vote {
            let head = self.engine.get_ac_vote_head();
            self.vote_heads.insert(event.slot, head);
        }
    }

    /// Record the duty input of the engine's current instant again, if it is
    /// one: for a host that changed the store within the tick that recorded
    /// it (a node built by jumping to the present, then given its blocks and
    /// any seeded lock).
    pub fn record_current_duties(&mut self) {
        let time = self.engine.time();
        let slot = self.engine.current_slot();
        let into_slot = ethlambda_decoupled::params::time_into_slot(time);
        let event = TickEvents {
            tick: time,
            slot,
            propose: slot > 0 && into_slot == 0,
            head_vote: slot > 0 && into_slot == ethlambda_decoupled::params::HEAD_VOTE_DUE,
            support_cutoff: into_slot == ethlambda_decoupled::params::SUPPORT_CUTOFF,
        };
        self.on_tick_event(&event);
    }

    fn prune(&mut self) {
        let slot = self.engine.current_slot();
        let oldest_slot = slot.saturating_sub(HEAD_VOTE_SLOTS_KEPT);
        self.head_votes = self.head_votes.split_off(&oldest_slot);
        self.proposals = self.proposals.split_off(&oldest_slot);
        self.vote_heads = self.vote_heads.split_off(&oldest_slot);
        self.seen_head_votes
            .retain(|(vote_slot, _)| *vote_slot + 1 >= slot);
        let round = compute_round_at_slot(slot);
        let oldest_round = round.saturating_sub(ATTESTATION_ROUNDS_KEPT);
        self.attestations = self.attestations.split_off(&oldest_round);
        self.seen_attestations
            .retain(|(attestation_round, _)| *attestation_round + 1 >= round);
    }

    /// `record_head_vote_committee(slot, committee)`, after advancing to
    /// `now_ms`. A committee recorded before must agree.
    pub fn record_committee(
        &mut self,
        slot: Slot,
        committee: Vec<ValidatorIndex>,
        now_ms: u64,
    ) -> Result<(), CommitteeError> {
        self.advance_to_ms(now_ms);
        self.engine.record_head_vote_committee(slot, committee)
    }

    /// `on_block`'s fork-choice part for an imported block, after advancing
    /// to `now_ms`. The caller recorded the committees of its head votes.
    pub fn on_block(&mut self, input: &BlockInput, now_ms: u64) -> Result<(), BlockError> {
        self.advance_to_ms(now_ms);
        self.engine.on_block(input)
    }

    /// `on_execution_payload_envelope`'s fork-choice part for a verified
    /// payload, after advancing to `now_ms`.
    pub fn on_payload(
        &mut self,
        root: &Root,
        inclusion_list_satisfied: bool,
        now_ms: u64,
    ) -> Result<(), PayloadError> {
        self.advance_to_ms(now_ms);
        self.engine
            .on_execution_payload_envelope(root, inclusion_list_satisfied)
    }

    /// The execution client found `root`'s payload invalid: the engine's
    /// `invalidate_payload`, after advancing to `now_ms`, and the duty inputs
    /// recorded before it moved off what it removed.
    ///
    /// A proposal or head vote recorded at its instant that names the
    /// payload's `Full` node or a block built on it is moved to the block's
    /// `Empty` node, the deepest node left on that path, and a recorded
    /// proposal stops counting votes for removed nodes as support. The
    /// recorded instant is past and cannot be recomputed; what a validator
    /// reads from now on names a viable node.
    pub fn invalidate_payload(&mut self, root: &Root, now_ms: u64) -> PayloadInvalidation {
        self.advance_to_ms(now_ms);
        let outcome = self.engine.invalidate_payload(root);
        if let PayloadInvalidation::Invalidated { removed_blocks } = &outcome {
            let removed: HashSet<Root> = removed_blocks.iter().copied().collect();
            let full = ForkChoiceNode::full(*root);
            let is_gone = |node: &ForkChoiceNode| *node == full || removed.contains(&node.root);
            let fallback = ForkChoiceNode::empty(*root);
            for head in self.vote_heads.values_mut() {
                if is_gone(head) {
                    *head = fallback;
                }
            }
            for proposal in self.proposals.values_mut() {
                if is_gone(&proposal.head) {
                    proposal.head = fallback;
                }
                let messages = &proposal.vote_messages;
                proposal.support_indices.retain(|&index| {
                    messages
                        .get(index)
                        .and_then(|message| message.data.supported_node())
                        .is_some_and(|node| !is_gone(&node))
                });
            }
        }
        outcome
    }

    /// Whether `root`'s payload envelope has been "seen and verified", as the
    /// head vote gossip rule asks: verified, or verified and since invalidated,
    /// so a vote for an invalidated payload reaches the rule that rejects it
    /// rather than being ignored as unseen.
    pub fn payload_envelope_seen(&self, root: &Root) -> bool {
        self.engine.is_payload_verified(root) || self.engine.is_payload_invalidated(root)
    }

    // ── Head votes and attestations ───────────────────────────────────────

    /// Whether a head vote of `validator` for `slot` was already accepted.
    pub fn head_vote_seen(&self, slot: Slot, validator: ValidatorIndex) -> bool {
        self.seen_head_votes.contains(&(slot, validator))
    }

    /// Whether an attestation of `validator` in `round` was already accepted.
    pub fn attestation_seen(&self, round: u64, validator: ValidatorIndex) -> bool {
        self.seen_attestations.contains(&(round, validator))
    }

    /// Apply a head vote message that passed `validate_head_vote_gossip`:
    /// record its slot's committee (read from the head state by the
    /// validation), then `on_head_vote_message`, then mark it seen and keep the
    /// signed message for proposals.
    ///
    /// A vote of a slot other than the previous or the current one is refused
    /// by the engine ("delay consideration until their slot is in the past"
    /// applies only to the gossip rule's current-slot vote, which is never
    /// early here) and is not marked seen.
    pub fn accept_head_vote(
        &mut self,
        message: eip8453::HeadVoteMessage,
        committee: Vec<ValidatorIndex>,
        now_ms: u64,
    ) -> Result<(), HeadVoteError> {
        self.advance_to_ms(now_ms);
        let slot = message.data.slot;
        // Two messages of one validator can pass validation concurrently; the
        // first applied is the one gossip forwards.
        if self.head_vote_seen(slot, message.validator_index) {
            return Err(HeadVoteError::Duplicate);
        }
        if let Err(err) = self.engine.record_head_vote_committee(slot, committee) {
            tracing::warn!(slot, %err, "Head vote committee disagrees with the recorded one");
        }
        self.engine
            .on_head_vote_message(ethlambda_types::decoupled::HeadVoteMessage::from(&message))?;
        self.seen_head_votes.insert((slot, message.validator_index));
        self.head_votes.entry(slot).or_default().push(message);
        Ok(())
    }

    /// Keep a single attestation that passed `validate_attestation_gossip`,
    /// cast in `round`, for proposals, and mark it seen. Attestations are not
    /// fork choice inputs: the gadget counts them through the blocks that
    /// carry them. `false`, keeping nothing, when one of the attester's for the
    /// round was accepted first.
    pub fn accept_attestation(
        &mut self,
        attestation: eip8453::SingleAttestation,
        round: u64,
    ) -> bool {
        if !self
            .seen_attestations
            .insert((round, attestation.attester_index))
        {
            return false;
        }
        self.attestations
            .entry(round)
            .or_default()
            .push(attestation);
        true
    }

    /// The single attestations accepted for `round`.
    pub fn pooled_attestations(&self, round: u64) -> &[eip8453::SingleAttestation] {
        self.attestations
            .get(&round)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// Every pooled single attestation, oldest round first.
    pub fn all_pooled_attestations(&self) -> impl Iterator<Item = &eip8453::SingleAttestation> {
        self.attestations.values().flatten()
    }

    /// The signed head vote messages accepted for `slot`, in arrival order.
    pub fn pooled_head_votes(&self, slot: Slot) -> &[eip8453::HeadVoteMessage] {
        self.head_votes
            .get(&slot)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    // ── Duty inputs ────────────────────────────────────────────────────────

    fn current_slot_is(&self, slot: Slot) -> Result<(), DutyError> {
        let current = self.engine.current_slot();
        if slot != current {
            return Err(DutyError::WrongSlot {
                asked: slot,
                current,
            });
        }
        Ok(())
    }

    /// The head vote data of a committee member of `slot` (validator.md,
    /// "Head vote data"): `get_ac_vote_head` as of the slot's head vote
    /// deadline, `Pending` when it names the slot's own block.
    pub fn vote_head(&mut self, slot: Slot, now_ms: u64) -> Result<HeadVoteData, DutyError> {
        self.advance_to_ms(now_ms);
        self.current_slot_is(slot)?;
        let into_slot = ethlambda_decoupled::params::time_into_slot(self.engine.time());
        if into_slot < ethlambda_decoupled::params::HEAD_VOTE_DUE {
            return Err(DutyError::NotYet {
                slot,
                duty: "head vote",
            });
        }
        let head = self
            .vote_heads
            .get(&slot)
            .copied()
            .ok_or(DutyError::Missed {
                slot,
                duty: "head vote",
            })?;
        Ok(head_vote_data(&self.engine, slot, head))
    }

    /// `get_ac_frame` for `slot`, at or after its support cutoff.
    pub fn ac_frame(&mut self, slot: Slot, now_ms: u64) -> Result<AcFrame, DutyError> {
        self.advance_to_ms(now_ms);
        self.current_slot_is(slot)?;
        let into_slot = ethlambda_decoupled::params::time_into_slot(self.engine.time());
        if into_slot < ethlambda_decoupled::params::SUPPORT_CUTOFF {
            return Err(DutyError::NotYet {
                slot,
                duty: "support cutoff",
            });
        }
        Ok(self.engine.get_ac_frame())
    }

    /// The source and head state reads of validator.md's "Attestation data"
    /// for an attester of `slot`, from one `get_ac_frame` observation. `None`
    /// when there is no FG source, or the source predates the gadget (a
    /// height-0 target, which no attestation may name): the validator does not
    /// attest.
    pub fn finality_attestation_input(
        &mut self,
        slot: Slot,
        now_ms: u64,
    ) -> Result<Option<FinalityAttestationInput>, DutyError> {
        let frame = self.ac_frame(slot, now_ms)?;
        Ok(self
            .engine
            .finality_attestation_input(&frame)
            .filter(|input| input.target.height > 0))
    }

    /// The proposal of `slot`, as of its start: `get_ac_proposal`'s head and
    /// the previous slot's head votes it saw, grouped into the body's
    /// aggregates ([`aggregate_head_votes`]).
    pub fn proposal(&mut self, slot: Slot, now_ms: u64) -> Result<Eip8453Proposal, DutyError> {
        self.advance_to_ms(now_ms);
        self.current_slot_is(slot)?;
        let proposal = self.proposals.get(&slot).ok_or(DutyError::Missed {
            slot,
            duty: "proposal",
        })?;
        let previous = slot.saturating_sub(1);
        let signed = self.pooled_head_votes(previous);
        let (head_votes, head_vote_support) = aggregate_head_votes(proposal, signed);
        Ok(Eip8453Proposal {
            slot,
            head: proposal.head,
            head_votes,
            head_vote_support,
        })
    }

    /// The node's view for operators and the Beacon API.
    pub fn status(&self) -> DecoupledStatus {
        let engine = &self.engine;
        let block_ref = |root: Root| BlockRef {
            root,
            slot: engine.block_slot(&root).unwrap_or_default(),
        };
        let head = engine.get_head();
        let finalized = engine.finalized_checkpoint();
        let justified = engine.justified_checkpoint();
        DecoupledStatus {
            slot: engine.current_slot(),
            round: engine.current_round(),
            head: block_ref(head.root),
            head_payload_status: head.payload_status,
            confirmed: block_ref(engine.get_confirmed_node().root),
            latest_confirmed: block_ref(engine.latest_confirmed().root),
            finalized,
            finalized_slot: engine.block_slot(&finalized.root).unwrap_or_default(),
            justified,
            justified_slot: engine.block_slot(&justified.root).unwrap_or_default(),
            max_height: engine.max_height(),
            fg_contest: engine.is_fg_contest(),
            live_locks: engine.live_locks().len() as u64,
            blocks: engine.blocks().count() as u64,
        }
    }

    /// The engine's finalized and justified checkpoints.
    pub fn checkpoints(&self) -> (HeightCheckpoint, HeightCheckpoint) {
        (
            self.engine.justified_checkpoint(),
            self.engine.finalized_checkpoint(),
        )
    }
}

/// Group a proposal's head votes into the body's aggregates: one `HeadVote`
/// per distinct `HeadVoteData`, its voters sorted and deduplicated
/// (`process_head_vote` asserts both), its signature the aggregate of theirs,
/// and one support bit per voter, set when `get_ac_proposal` counted that
/// voter's message as resolved.
///
/// `signed` is the slot's pool of signed messages; a message the engine
/// counted but this pool lacks the signature of is left out. At most
/// `MAX_HEAD_VOTES` aggregates are kept, the most supported first.
pub fn aggregate_head_votes(
    proposal: &AcProposal,
    signed: &[eip8453::HeadVoteMessage],
) -> (Vec<eip8453::HeadVote>, Vec<ProgressiveBitlist>) {
    let signatures: HashMap<(ValidatorIndex, eip8453::HeadVoteData), _> = signed
        .iter()
        .map(|message| ((message.validator_index, message.data), message.signature))
        .collect();
    let supporting: HashSet<usize> = proposal.support_indices.iter().copied().collect();
    // data -> voter -> (signature, supports)
    type Voters = BTreeMap<ValidatorIndex, (crate::beacon::primitives::BlsSignature, bool)>;
    let mut groups: BTreeMap<(u64, Root, u8), Voters> = BTreeMap::new();
    for (index, message) in proposal.vote_messages.iter().enumerate() {
        let data: eip8453::HeadVoteData = message.data.into();
        let Some(signature) = signatures.get(&(message.validator_index, data)) else {
            continue;
        };
        let supports = supporting.contains(&index);
        let voters = groups
            .entry((data.slot, data.beacon_block_root, data.payload_status))
            .or_default();
        let entry = voters
            .entry(message.validator_index)
            .or_insert((*signature, supports));
        entry.1 |= supports;
    }
    let mut aggregates: Vec<(usize, eip8453::HeadVote, ProgressiveBitlist)> = Vec::new();
    for ((slot, beacon_block_root, payload_status), voters) in groups {
        let signatures: Vec<_> = voters.values().map(|(signature, _)| *signature).collect();
        let Ok(signature) = crate::beacon::bls::aggregate(&signatures) else {
            continue;
        };
        let voter_indices: Vec<ValidatorIndex> = voters.keys().copied().collect();
        let Ok(voter_indices) = voter_indices.try_into() else {
            continue;
        };
        let mut bits = ProgressiveBitlist::default();
        let mut supported = 0;
        for (_, supports) in voters.values() {
            bits.push(*supports);
            supported += usize::from(*supports);
        }
        let vote = eip8453::HeadVote {
            voter_indices,
            data: eip8453::HeadVoteData {
                slot,
                beacon_block_root,
                payload_status,
            },
            signature,
        };
        aggregates.push((supported, vote, bits));
    }
    aggregates.sort_by_key(|(supported, vote, _)| {
        (
            std::cmp::Reverse(*supported),
            std::cmp::Reverse(vote.voter_indices.len()),
        )
    });
    aggregates.truncate(crate::beacon::preset::MAX_HEAD_VOTES as usize);
    aggregates
        .into_iter()
        .map(|(_, vote, bits)| (vote, bits))
        .unzip()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::eip8453_test_support::scene;
    use ethlambda_types::decoupled::PayloadStatus;

    /// Duty inputs recorded before an invalidation, at their instants, move to
    /// the invalidated block's EMPTY node: a validator reading them later signs
    /// nothing on the invalid payload.
    #[test]
    fn recorded_duty_inputs_move_off_an_invalidated_payload() {
        let scene = scene(16);
        let anchor = scene.anchor_root;
        let slot = scene.anchor_slot + 1;
        let quarter_ms = scene.config.slot_duration_ms_at_slot(slot) / 4;
        let (proposal, vote) = scene
            .node
            .with(|n| {
                // The anchor's payload arrives early in its own slot, so it is
                // in the next slot's voter subtree.
                n.on_payload(&anchor, true, scene.at(scene.anchor_slot, 0))
                    .unwrap();
                let proposal = n.proposal(slot, scene.at(slot, 0)).unwrap();
                let vote = n.vote_head(slot, scene.at(slot, quarter_ms)).unwrap();
                (proposal.head, vote)
            })
            .unwrap();
        assert_eq!(proposal, ForkChoiceNode::full(anchor));
        assert_eq!(vote.payload_status(), Some(PayloadStatus::Full));

        let now = scene.at(slot, quarter_ms + 1);
        let (outcome, proposal, vote) = scene
            .node
            .with(|n| {
                let outcome = n.invalidate_payload(&anchor, now);
                let proposal = n.proposal(slot, now).unwrap();
                let vote = n.vote_head(slot, now).unwrap();
                (outcome, proposal.head, vote)
            })
            .unwrap();
        assert_eq!(
            outcome,
            PayloadInvalidation::Invalidated {
                removed_blocks: Vec::new()
            }
        );
        assert_eq!(proposal, ForkChoiceNode::empty(anchor));
        assert_eq!(vote.supported_node(), Some(ForkChoiceNode::empty(anchor)));
    }
}
