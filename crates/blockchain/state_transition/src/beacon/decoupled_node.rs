//! A beacon node's decoupled consensus state, shared by the chain actor, the
//! Beacon API and the p2p layer.
//!
//! The protocol engine (`ethlambda_decoupled::Store`) plus what the beacon
//! wire needs around it: the BLS signatures behind every pooled vote and
//! attestation (so a proposal can aggregate them), and the duty outputs
//! computed at their protocol instants (so a validator client asking a moment
//! later reads the value the protocol prescribes for that instant, not one
//! computed from a store that has moved on).
//!
//! Who does what:
//!
//! * the chain actor ticks it every `Δ` and imports every decoupled block the
//!   beacon state transition accepted;
//! * the p2p layer and the Beacon API validate gossip and validator-client
//!   submissions (`validate_*` below) and add them;
//! * block production asks for the parent and the protocol fields of a
//!   proposal;
//! * every reader advances the clock first, so a duty read at its instant
//!   sees the tick of that instant.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use crate::beacon::config::Config;
use crate::beacon::constants::{DOMAIN_COMBINED_ATTESTATION, DOMAIN_GOLDFISH_VOTE};
use crate::beacon::containers::BeaconState;
use crate::beacon::containers::decoupled::{
    CombinedAttestationAggregate, GoldfishVoteAggregate, GoldfishVoteData,
    MAX_COMBINED_ATTESTATION_AGGREGATES, MAX_GOLDFISH_VOTE_AGGREGATES, SignedCombinedAttestation,
    SignedGoldfishVote,
};
use crate::beacon::helpers::misc::{compute_epoch_at_slot, compute_signing_root};
use crate::beacon::primitives::{BlsSignature, Root, Slot, ValidatorIndex};
use ethlambda_decoupled::{
    AttestationInput, BlockError, BlockInput, Electorate, Params, Proposal, Store as Engine,
};
use ethlambda_types::decoupled::{
    Attestation, AttestationData, BlockRef, DecoupledStatus, GoldfishVote, Round,
};
use ethlambda_types::primitives::HashTreeRoot as _;
use ethlambda_types::time::unix_now_ms;
use libssz_types::{SszBitlist, SszList};

use crate::beacon::bls;
use crate::beacon::decoupled::{DecoupledBodyFields, params, slot_committee};
use crate::beacon::helpers::accessors::{CommitteeCache, get_domain_from_schedule};

/// The shared handle.
pub type SharedDecoupledNode = Arc<Mutex<DecoupledNode>>;

/// Why a vote or an attestation was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecoupledMessageError {
    #[error("unknown validator {0}")]
    UnknownValidator(ValidatorIndex),
    #[error("validator {validator} is not in slot {slot}'s committee")]
    NotInCommittee {
        validator: ValidatorIndex,
        slot: Slot,
    },
    #[error("invalid signature")]
    BadSignature,
    #[error("committee lookup failed: {0}")]
    Committee(String),
    #[error("not admitted: outside the window or a duplicate")]
    NotAdmitted,
}

/// What a request for a duty input can fail with.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DutyError {
    #[error("slot {asked} is not the current slot {current}")]
    WrongSlot { asked: Slot, current: Slot },
    #[error("round {asked} is not the current round {current}")]
    WrongRound { asked: Round, current: Round },
    #[error("the decoupled clock has not reached genesis")]
    BeforeGenesis,
}

pub struct DecoupledNode {
    engine: Engine,
    params: Params,
    genesis_time_ms: u64,
    delta_ms: u64,
    /// Individual signatures behind pooled votes, by slot and data.
    vote_signatures:
        BTreeMap<Slot, HashMap<GoldfishVoteData, BTreeMap<ValidatorIndex, BlsSignature>>>,
    /// Individual signatures behind pooled attestations, by round and data.
    attestation_signatures:
        BTreeMap<Round, HashMap<AttestationData, BTreeMap<ValidatorIndex, BlsSignature>>>,
    /// Aggregates carried by imported blocks, by round, for attestations this
    /// node never saw individually: an aggregate can only be included whole.
    carried_attestations: BTreeMap<Round, Vec<CombinedAttestationAggregate>>,
    /// `goldfish_vote_head()` as of each slot's vote instant.
    vote_heads: BTreeMap<Slot, Root>,
    /// `attestation_input()` as of each round's attestation instant.
    attestation_inputs: BTreeMap<Round, AttestationInput>,
}

impl DecoupledNode {
    /// A node anchored at the genesis block, for a chain that runs the
    /// decoupled fork from genesis. `weights` are the validators' effective
    /// balances (in increments), fixed for the execution.
    pub fn new(config: &Config, genesis_block_root: Root, weights: Vec<u64>) -> Self {
        let params = params(config);
        Self {
            engine: Engine::from_genesis(params, Electorate::new(weights), genesis_block_root),
            params,
            genesis_time_ms: config.genesis_time * 1000,
            delta_ms: config.slot_duration_ms / 4,
            vote_signatures: BTreeMap::new(),
            attestation_signatures: BTreeMap::new(),
            carried_attestations: BTreeMap::new(),
            vote_heads: BTreeMap::new(),
            attestation_inputs: BTreeMap::new(),
        }
    }

    pub fn shared(self) -> SharedDecoupledNode {
        Arc::new(Mutex::new(self))
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    pub fn params(&self) -> &Params {
        &self.params
    }

    fn now_tick(&self) -> Option<i64> {
        let elapsed = unix_now_ms().checked_sub(self.genesis_time_ms)?;
        Some((elapsed / self.delta_ms) as i64)
    }

    /// Run every protocol tick up to now. At a vote or attestation instant,
    /// record the node-wide duty input of that instant. Returns whether any
    /// tick ran, which is when the head may have moved.
    pub fn sync(&mut self) -> bool {
        let Some(now) = self.now_tick() else {
            return false;
        };
        let events = self.engine.advance_to(now);
        let ran = !events.is_empty();
        for event in events {
            if event.vote {
                let head = self.engine.goldfish_vote_head();
                self.vote_heads.insert(event.slot, head);
            }
            if let Some(round) = event.attest {
                let input = self.engine.attestation_input();
                self.attestation_inputs.insert(round, input);
            }
        }
        if ran {
            self.prune();
        }
        ran
    }

    fn prune(&mut self) {
        let slot = self.engine.current_slot();
        let round = self.engine.current_round();
        let oldest_round = round.saturating_sub(self.params.eta_sg);
        self.vote_signatures = self.vote_signatures.split_off(&slot.saturating_sub(1));
        self.attestation_signatures = self.attestation_signatures.split_off(&oldest_round);
        self.carried_attestations = self.carried_attestations.split_off(&oldest_round);
        self.vote_heads = self.vote_heads.split_off(&slot.saturating_sub(2));
        self.attestation_inputs = self.attestation_inputs.split_off(&round.saturating_sub(1));
    }

    // ── Duties ─────────────────────────────────────────────────────────────

    /// The Goldfish vote of `slot`: the head as of `t_s + Δ`.
    pub fn goldfish_vote_data(&mut self, slot: Slot) -> Result<GoldfishVoteData, DutyError> {
        self.sync();
        let current = self.engine.current_slot();
        if slot != current {
            return Err(DutyError::WrongSlot {
                asked: slot,
                current,
            });
        }
        let head = match self.vote_heads.get(&slot) {
            Some(head) => *head,
            // Asked before the vote instant, or by a node that started after
            // it: the head the vote duty would compute now.
            None => self.engine.goldfish_vote_head(),
        };
        Ok(GoldfishVoteData { slot, head })
    }

    /// The attestation input of `round`, as of `a_r`.
    pub fn attestation_input(&mut self, round: Round) -> Result<AttestationInput, DutyError> {
        self.sync();
        let current = self.engine.current_round();
        if round != current {
            return Err(DutyError::WrongRound {
                asked: round,
                current,
            });
        }
        Ok(match self.attestation_inputs.get(&round) {
            Some(input) => *input,
            None => self.engine.attestation_input(),
        })
    }

    /// The engine's proposal for `slot`: the parent to build on and the
    /// votes and attestations to carry (`propose_block`). Read once, at the
    /// proposal instant, so the parent and the body come from one store.
    pub fn proposal(&mut self, slot: Slot) -> Result<Proposal, DutyError> {
        self.sync();
        let current = self.engine.current_slot();
        if slot != current {
            return Err(DutyError::WrongSlot {
                asked: slot,
                current,
            });
        }
        Ok(self.engine.proposal())
    }

    /// The protocol fields of `proposal`'s block: its votes and attestations
    /// aggregated per identical data from their individual signatures.
    ///
    /// `previous_committee` is `𝒦_{slot−1}` in the bit order a
    /// `GoldfishVoteAggregate` uses; `validator_count` sizes attestation bits.
    /// An attestation known only from another block's aggregate is carried by
    /// including that aggregate whole.
    pub fn body_fields(
        &self,
        proposal: &Proposal,
        previous_committee: &[ValidatorIndex],
        validator_count: usize,
    ) -> DecoupledBodyFields {
        let slot = proposal.slot;

        // Votes: one aggregate per head.
        let position: HashMap<ValidatorIndex, usize> = previous_committee
            .iter()
            .enumerate()
            .map(|(i, v)| (*v, i))
            .collect();
        let previous = slot.saturating_sub(1);
        let mut by_head: BTreeMap<Root, Vec<GoldfishVote>> = BTreeMap::new();
        for vote in &proposal.votes {
            by_head.entry(vote.head).or_default().push(*vote);
        }
        let mut goldfish_votes = Vec::new();
        let mut support = Vec::new();
        for (head, votes) in by_head {
            let data = GoldfishVoteData {
                slot: previous,
                head,
            };
            let Some(signatures) = self
                .vote_signatures
                .get(&previous)
                .and_then(|pool| pool.get(&data))
            else {
                continue;
            };
            let mut bits = vec![false; previous_committee.len()];
            let mut parts = Vec::new();
            for vote in &votes {
                if let (Some(&i), Some(signature)) = (
                    position.get(&vote.validator),
                    signatures.get(&vote.validator),
                ) {
                    bits[i] = true;
                    parts.push(*signature);
                }
            }
            let Ok(signature) = bls::aggregate(&parts) else {
                continue;
            };
            let resolved = votes
                .iter()
                .all(|vote| proposal.support_votes.contains(vote));
            goldfish_votes.push(GoldfishVoteAggregate {
                aggregation_bits: SszBitlist::try_from(bits).expect("committee within bounds"),
                data,
                signature,
            });
            support.push(resolved);
            if goldfish_votes.len() == MAX_GOLDFISH_VOTE_AGGREGATES {
                break;
            }
        }

        // Attestations: one aggregate per data from individual signatures.
        let mut by_data: Vec<(AttestationData, Vec<ValidatorIndex>)> = Vec::new();
        for attestation in &proposal.attestations {
            match by_data
                .iter_mut()
                .find(|(data, _)| *data == attestation.data)
            {
                Some((_, validators)) => validators.push(attestation.validator),
                None => by_data.push((attestation.data.clone(), vec![attestation.validator])),
            }
        }
        let mut combined_attestations = Vec::new();
        let mut uncovered: Vec<Attestation> = Vec::new();
        for (data, validators) in by_data {
            let signatures = self
                .attestation_signatures
                .get(&data.round)
                .and_then(|pool| pool.get(&data));
            let mut bits = vec![false; validator_count];
            let mut parts = Vec::new();
            for validator in validators {
                match signatures.and_then(|s| s.get(&validator)) {
                    Some(signature) if (validator as usize) < validator_count => {
                        bits[validator as usize] = true;
                        parts.push(*signature);
                    }
                    _ => uncovered.push(Attestation {
                        validator,
                        data: data.clone(),
                    }),
                }
            }
            if parts.is_empty() {
                continue;
            }
            if let Ok(signature) = bls::aggregate(&parts) {
                combined_attestations.push(CombinedAttestationAggregate {
                    aggregation_bits: SszBitlist::try_from(bits).expect("registry within bounds"),
                    data,
                    signature,
                });
            }
        }
        // Rows only another block's aggregate can vouch for.
        for attestation in uncovered {
            let carrier = self
                .carried_attestations
                .get(&attestation.data.round)
                .and_then(|aggregates| {
                    aggregates.iter().find(|aggregate| {
                        aggregate.data == attestation.data
                            && aggregate
                                .aggregation_bits
                                .get(attestation.validator as usize)
                                == Some(true)
                    })
                });
            if let Some(aggregate) = carrier
                && !combined_attestations.contains(aggregate)
            {
                combined_attestations.push(aggregate.clone());
            }
        }
        combined_attestations.truncate(MAX_COMBINED_ATTESTATION_AGGREGATES);

        DecoupledBodyFields {
            goldfish_votes: SszList::try_from(goldfish_votes).expect("capped above"),
            goldfish_support: SszBitlist::try_from(support).expect("one bit per aggregate"),
            combined_attestations: SszList::try_from(combined_attestations)
                .expect("truncated above"),
        }
    }

    // ── Imports ────────────────────────────────────────────────────────────

    /// Admit a vote that passed [`validate_goldfish_vote`].
    pub fn add_vote(&mut self, vote: &SignedGoldfishVote) -> bool {
        self.sync();
        let admitted = self.engine.on_goldfish_vote(GoldfishVote {
            validator: vote.validator_index,
            slot: vote.data.slot,
            head: vote.data.head,
        });
        if admitted {
            self.vote_signatures
                .entry(vote.data.slot)
                .or_default()
                .entry(vote.data)
                .or_default()
                .insert(vote.validator_index, vote.signature);
        }
        admitted
    }

    /// Admit an attestation that passed [`validate_combined_attestation`].
    pub fn add_attestation(&mut self, attestation: &SignedCombinedAttestation) -> bool {
        self.sync();
        let admitted = self.engine.on_sg_vote(Attestation {
            validator: attestation.validator_index,
            data: attestation.data.clone(),
        });
        if admitted {
            self.attestation_signatures
                .entry(attestation.data.round)
                .or_default()
                .entry(attestation.data.clone())
                .or_default()
                .insert(attestation.validator_index, attestation.signature);
        }
        admitted
    }

    /// Import a decoupled block the beacon state transition accepted.
    pub fn import_block(
        &mut self,
        input: &BlockInput,
        attestations: &[CombinedAttestationAggregate],
    ) -> Result<(), BlockError> {
        self.sync();
        self.engine.on_block(input)?;
        for aggregate in attestations {
            self.carried_attestations
                .entry(aggregate.data.round)
                .or_default()
                .push(aggregate.clone());
        }
        Ok(())
    }

    // ── Reads ──────────────────────────────────────────────────────────────

    pub fn head(&self) -> Root {
        self.engine.head()
    }

    pub fn status(&self) -> DecoupledStatus {
        let engine = &self.engine;
        let head = engine.head();
        let (justified, justified_height) = engine.justified();
        DecoupledStatus {
            slot: engine.current_slot(),
            round: engine.current_round(),
            head: engine.block_ref(&head).unwrap_or(BlockRef {
                root: head,
                slot: 0,
            }),
            confirmed: engine.confirmed(),
            stable: engine.stable(),
            finalized: engine.finalized(),
            finalized_height: engine.finalized_height(),
            justified,
            justified_height,
            max_height: engine.max_height(),
            live_confirmed: engine.live_confirmed(),
            blocks: engine.blocks().count() as u64,
        }
    }
}

/// Check a Goldfish vote's committee membership and signature against
/// `state`, whose shuffling must cover the vote's slot.
pub fn validate_goldfish_vote(
    state: &BeaconState,
    config: &Config,
    committees: &CommitteeCache,
    vote: &SignedGoldfishVote,
) -> Result<(), DecoupledMessageError> {
    let committee = slot_committee(state, vote.data.slot, committees)
        .map_err(|err| DecoupledMessageError::Committee(err.to_string()))?;
    if !committee.contains(&vote.validator_index) {
        return Err(DecoupledMessageError::NotInCommittee {
            validator: vote.validator_index,
            slot: vote.data.slot,
        });
    }
    let pubkey = state
        .validator(vote.validator_index)
        .map(|validator| validator.pubkey)
        .map_err(|_| DecoupledMessageError::UnknownValidator(vote.validator_index))?;
    let epoch = compute_epoch_at_slot(vote.data.slot);
    let domain = get_domain_from_schedule(config, state, DOMAIN_GOLDFISH_VOTE, epoch);
    let root = compute_signing_root(vote.data.hash_tree_root(), domain);
    bls::verify(&pubkey, root, &vote.signature)
        .then_some(())
        .ok_or(DecoupledMessageError::BadSignature)
}

/// Check a combined attestation's signature against `state`.
pub fn validate_combined_attestation(
    state: &BeaconState,
    config: &Config,
    attestation: &SignedCombinedAttestation,
) -> Result<(), DecoupledMessageError> {
    let pubkey = state
        .validator(attestation.validator_index)
        .map(|validator| validator.pubkey)
        .map_err(|_| DecoupledMessageError::UnknownValidator(attestation.validator_index))?;
    let opening = params(config).opening_slot(attestation.data.round);
    let epoch = compute_epoch_at_slot(opening);
    let domain = get_domain_from_schedule(config, state, DOMAIN_COMBINED_ATTESTATION, epoch);
    let root = compute_signing_root(attestation.data.hash_tree_root(), domain);
    bls::verify(&pubkey, root, &attestation.signature)
        .then_some(())
        .ok_or(DecoupledMessageError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::containers::decoupled::{BeaconBlock, BeaconBlockBody};
    use crate::beacon::decoupled::{process_decoupled_body, upgrade_to_decoupled};
    use crate::beacon::fork::ForkName;
    use crate::beacon::helpers::test_state::{sign_for, with_signing_validators_at};
    use crate::beacon::preset::SLOTS_PER_EPOCH;
    use ethlambda_types::decoupled::{FinalityVote, HeightVote};

    const VALIDATORS: usize = 64;

    /// A decoupled state at the first slot of epoch 1, with real keys.
    fn decoupled_state(config: &Config) -> BeaconState {
        let state = with_signing_validators_at(ForkName::Fulu, VALIDATORS);
        let BeaconState::Fulu(inner) = state else {
            unreachable!("built as fulu")
        };
        BeaconState::Decoupled(upgrade_to_decoupled(inner, config))
    }

    /// A config whose wall clock puts the current slot at `slot`: genesis
    /// is set back by `slot` slots and half a slot.
    fn config_at(slot: Slot) -> Config {
        let mut config = Config::mainnet().with_fork_epoch(ForkName::Decoupled, 0);
        let now = unix_now_ms() / 1000;
        let slot_seconds = config.slot_duration_ms / 1000;
        config.genesis_time = now - slot * slot_seconds - slot_seconds / 2;
        config
    }

    #[test]
    fn pooled_signatures_aggregate_into_a_body_the_state_transition_accepts() {
        let slot = SLOTS_PER_EPOCH;
        let config = config_at(slot);
        let state = decoupled_state(&config);
        let committees = CommitteeCache::default();
        let genesis_root = Root::repeat_byte(0x11);
        let mut node = DecoupledNode::new(&config, genesis_root, vec![32; VALIDATORS]);
        node.sync();
        assert_eq!(node.engine().current_slot(), slot);

        // Every member of the previous slot's committee votes for genesis.
        let previous = slot - 1;
        let committee = slot_committee(&state, previous, &committees).unwrap();
        assert!(!committee.is_empty());
        let data = GoldfishVoteData {
            slot: previous,
            head: genesis_root,
        };
        let domain = get_domain_from_schedule(
            &config,
            &state,
            DOMAIN_GOLDFISH_VOTE,
            compute_epoch_at_slot(previous),
        );
        let root = compute_signing_root(data.hash_tree_root(), domain);
        for &validator in &committee {
            let vote = SignedGoldfishVote {
                validator_index: validator,
                data,
                signature: sign_for(validator as usize, root),
            };
            validate_goldfish_vote(&state, &config, &committees, &vote).unwrap();
            assert!(node.add_vote(&vote));
        }

        // Three validators attest for the current round with one data.
        let round = node.params().round_of(slot);
        let attestation_data = AttestationData::new(
            round,
            Some(genesis_root),
            Some(HeightVote {
                height: 1,
                entry: genesis_root,
                timeout: false,
            }),
            Some(FinalityVote {
                height: 1,
                target: genesis_root,
            }),
        );
        let domain = get_domain_from_schedule(
            &config,
            &state,
            DOMAIN_COMBINED_ATTESTATION,
            compute_epoch_at_slot(node.params().opening_slot(round)),
        );
        let root = compute_signing_root(attestation_data.hash_tree_root(), domain);
        for validator in [1u64, 4, 9] {
            let attestation = SignedCombinedAttestation {
                validator_index: validator,
                data: attestation_data.clone(),
                signature: sign_for(validator as usize, root),
            };
            validate_combined_attestation(&state, &config, &attestation).unwrap();
            assert!(node.add_attestation(&attestation));
        }
        // A repeat is not admitted twice.
        let repeat = SignedCombinedAttestation {
            validator_index: 1,
            data: attestation_data.clone(),
            signature: sign_for(1, root),
        };
        assert!(!node.add_attestation(&repeat));

        let proposal = node.proposal(slot).unwrap();
        assert_eq!(proposal.parent_root, genesis_root);
        let fields = node.body_fields(&proposal, &committee, state.validator_count());
        assert_eq!(fields.goldfish_votes.len(), 1);
        assert_eq!(fields.goldfish_support.get(0), Some(true));
        assert_eq!(fields.combined_attestations.len(), 1);

        let mut body = BeaconBlockBody::empty();
        body.goldfish_votes = fields.goldfish_votes;
        body.goldfish_support = fields.goldfish_support;
        body.combined_attestations = fields.combined_attestations;
        let block = BeaconBlock {
            slot,
            proposer_index: 0,
            parent_root: genesis_root,
            state_root: Root::ZERO,
            body,
        };
        process_decoupled_body(&state, &block, &config, &committees, true)
            .expect("aggregated signatures verify");
    }

    #[test]
    fn a_vote_from_outside_the_committee_is_refused() {
        let slot = SLOTS_PER_EPOCH;
        let config = config_at(slot);
        let state = decoupled_state(&config);
        let committees = CommitteeCache::default();
        let committee = slot_committee(&state, slot, &committees).unwrap();
        let outsider = (0..VALIDATORS as u64)
            .find(|v| !committee.contains(v))
            .expect("64 validators do not all sit in one slot");
        let vote = SignedGoldfishVote {
            validator_index: outsider,
            data: GoldfishVoteData {
                slot,
                head: Root::ZERO,
            },
            signature: BlsSignature::default(),
        };
        assert!(matches!(
            validate_goldfish_vote(&state, &config, &committees, &vote),
            Err(DecoupledMessageError::NotInCommittee { .. })
        ));
    }
}
