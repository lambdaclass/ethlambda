//! Block body proofs: candidate bodies a proposer can adopt instead of
//! building one itself.
//!
//! A [`BlockBodyProof`] pairs a candidate [`BlockBody`] with the Type-2
//! aggregate binding its attestations. Since the proposer signature now sits
//! outside that aggregate (`BlockProof`), the aggregate no longer depends on
//! the block root, so any node can build one before the block exists — and the
//! merge, which is the expensive part of proposing, moves off the proposer's
//! critical path onto the aggregation worker and the gossip layer.
//!
//! This module owns both halves. [`build_body_proof`] is what the aggregation
//! worker runs during the head-update interval; [`BodyProofBuffer`] is the
//! bounded set of candidates a node collects each slot, from its own worker and
//! from gossip, and [`choose_body`] is how the slot's proposer picks one — or
//! decides an empty body is worth more.

use std::collections::{HashSet, VecDeque};

use ethlambda_crypto::signature::ValidatorPublicKey;
use ethlambda_state_transition::attestation_data_matches_chain;
use ethlambda_storage::Store;
use ethlambda_types::{
    attestation::validator_indices,
    block::{
        Block, BlockBody, BlockBodyProof, ByteList512KiB, MultiMessageAggregate,
        MultiMessageAggregateError, SingleMessageAggregate,
    },
    primitives::{H256, HashTreeRoot as _},
    state::{State, Validator},
};
use spawned_concurrency::message::Message;
use tracing::{info, trace, warn};

use crate::block_builder::{self, PostBlockCheckpoints, ProposerConfig};
use crate::metrics;
use crate::store::StoreError;

/// Maximum candidates kept at once. One body proof per aggregator per slot
/// reaches a node, and only the freshest batch is worth anything to the next
/// proposer, so the buffer is a small ring rather than a growing pool.
pub(crate) const MAX_BODY_PROOF_CANDIDATES: usize = 8;

/// Build a candidate body for `slot` off the store, and the Type-2 aggregate
/// binding its attestations.
///
/// Runs on the aggregation worker, which is not the proposer and must not
/// mutate the store: unlike `produce_block_with_signatures` it takes the
/// current fork-choice head as the parent instead of advancing the store's
/// clock to `slot`, and it assembles no block — a body proof commits to no
/// parent, no state root and no proposer, which is exactly why it can be built
/// by a node that will not propose. Whoever adopts it re-validates the body
/// against its own state.
///
/// Returns `None` when the pool yields no attestations: an empty body needs no
/// proof, and the proposer's empty-block fallback covers that case for free.
pub(crate) fn build_body_proof(
    store: &Store,
    slot: u64,
    config: ProposerConfig,
) -> Option<BlockBodyProof> {
    let parent_root = store.head().expect("head read works");
    let head_state = store
        .get_state(&parent_root)
        .expect("head state read works")?;
    let aggregated_payloads = store.known_aggregated_payloads();
    let known_block_roots = store.get_block_roots().expect("block roots read works");

    let (attestations, aggregates) = block_builder::select_and_compact(
        &head_state,
        slot,
        parent_root,
        &known_block_roots,
        &aggregated_payloads,
        config,
    )
    .inspect_err(|err| warn!(%slot, %err, "Failed to select attestations for a body proof"))
    .ok()?;

    if aggregates.is_empty() {
        trace!(%slot, "No attestations to build a body proof from");
        return None;
    }

    let proof = merge_attestation_aggregates(&head_state.validators, &aggregates)
        .inspect_err(|err| warn!(%slot, %err, "Failed to build a body proof aggregate"))
        .ok()?;

    Some(BlockBodyProof {
        block_body: BlockBody { attestations },
        proof,
    })
}

/// Merge per-attestation single-message aggregates into the one Type-2 a block
/// body carries.
///
/// The components are the body's attestations and nothing else — with the
/// proposer signature outside the proof, no block root enters here, which is
/// what lets this run before the block exists.
fn merge_attestation_aggregates(
    validators: &[Validator],
    aggregates: &[SingleMessageAggregate],
) -> Result<MultiMessageAggregate, BodyProofError> {
    let mut merge_inputs: Vec<(Vec<ValidatorPublicKey>, ByteList512KiB)> =
        Vec::with_capacity(aggregates.len());

    for aggregate in aggregates {
        let mut pubkeys = Vec::new();
        for vid in aggregate.participant_indices() {
            let validator = validators
                .get(vid as usize)
                .ok_or(BodyProofError::ParticipantOutOfRange(vid))?;
            let pubkey = ValidatorPublicKey::from_bytes(&validator.attestation_pubkey)
                .map_err(|_| BodyProofError::PubkeyDecoding(vid))?;
            pubkeys.push(pubkey);
        }
        merge_inputs.push((pubkeys, aggregate.proof.clone()));
    }

    let merged = ethlambda_crypto::merge_type_1s_into_type_2(merge_inputs)
        .map_err(|err| BodyProofError::Merge(err.to_string()))?;

    Ok(MultiMessageAggregate::from_bytes(merged.iter().as_slice())?)
}

/// Why a body proof could not be built. Every variant means "propose without
/// this candidate": the proposer's own fallback still produces a valid block.
#[derive(Debug, thiserror::Error)]
pub(crate) enum BodyProofError {
    #[error("attestation participant {0} is beyond the validator registry")]
    ParticipantOutOfRange(u64),
    #[error("could not decode the attestation pubkey of validator {0}")]
    PubkeyDecoding(u64),
    #[error("could not merge the attestation Type-1s into a Type-2: {0}")]
    Merge(String),
    #[error("merged attestation proof does not fit the block proof: {0}")]
    ProofTooLarge(#[from] MultiMessageAggregateError),
}

/// Self-message that assembles and publishes `slot`'s block.
///
/// Scheduled by the block-publication tick when the candidate buffer is still
/// empty: the merge that produces a candidate spans the interval boundary, so
/// the batch for this slot often lands a couple of hundred milliseconds into
/// it. A message rather than an in-handler wait, because the actor has to keep
/// processing gossip in the meantime — that is what it is waiting for.
pub(crate) struct AssembleProposal {
    pub(crate) slot: u64,
    pub(crate) validator_id: u64,
}
impl Message for AssembleProposal {
    type Result = ();
}

/// A candidate body the proposer may adopt.
pub(crate) struct BodyProofCandidate {
    pub(crate) body_proof: BlockBodyProof,
    /// Whether the aggregate has already been established as valid: true for
    /// one our own worker built, false for one that arrived on gossip.
    ///
    /// A proposer signs the block root exactly once per slot — the XMSS key is
    /// one-time — so a candidate's proof has to be verified *before* signing,
    /// not by importing the signed block and seeing whether it sticks. This
    /// flag is what spares us that verification on our own proofs.
    pub(crate) verified: bool,
}

/// The body a proposer decided to build its block around, sealed and ready to
/// sign.
pub(crate) struct ChosenBody {
    /// The block, `state_root` sealed by the state transition.
    pub(crate) block: Block,
    /// The aggregate binding the block's attestations: the adopted candidate's
    /// proof, or an empty one for an empty body.
    pub(crate) attestation_proof: MultiMessageAggregate,
    /// Whether a candidate body proof was adopted (as opposed to falling back
    /// to an empty body).
    pub(crate) adopted: bool,
}

/// How a sealed candidate compares to another. Higher is better:
/// finalization first, then justification, then how many voters the body adds
/// that the pre-state did not already have, then — all else equal — the
/// smaller body.
///
/// The new-voter term is what keeps a stale candidate out: its attestations
/// are already reflected in the state, so it adds nothing and loses to the
/// empty body it ties on checkpoints.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct BodyValue {
    finalized_slot: u64,
    justified_slot: u64,
    new_voters: usize,
    /// Negated so that fewer attestations sorts higher.
    fewer_attestations: isize,
}

/// Choose the body for a block at `slot` from the buffered candidates,
/// falling back to an empty body.
///
/// Each candidate is screened against the chain the block would extend, sealed
/// against `head_state` — the state transition both applies its attestations
/// and computes the state root — and scored by [`BodyValue`]. The best
/// candidate that beats the empty body is adopted, with three caveats:
///
/// - a candidate carrying a vote that does not sit on that chain is dropped.
///   The state transition does not check those roots, so a body packed against
///   another node's view would otherwise be carried verbatim — valid, and
///   worthless;
/// - a candidate that arrived on gossip has its aggregate verified before it
///   is adopted, since the proposer signs the block root only once (XMSS keys
///   are one-time) and so cannot discover a bad proof by trying to import the
///   signed block;
/// - a candidate whose state transition or verification fails is dropped and
///   the next-best one considered.
///
/// The empty-body fallback always succeeds and needs no prover work at all:
/// with the proposer signature outside the proof, an attestation-less block
/// carries no aggregate.
pub(crate) fn choose_body(
    head_state: &State,
    slot: u64,
    proposer_index: u64,
    parent_root: H256,
    candidates: &BodyProofBuffer,
) -> Result<ChosenBody, StoreError> {
    metrics::observe_body_proof_candidates(candidates.len());

    let chain_view = block_builder::extended_chain_view(head_state, slot, parent_root);

    let (empty_block, empty_post) = block_builder::seal_block(
        head_state,
        slot,
        proposer_index,
        parent_root,
        BlockBody::default(),
    )?;
    let empty_value = BodyValue {
        finalized_slot: empty_post.finalized.slot,
        justified_slot: empty_post.justified.slot,
        new_voters: 0,
        fewer_attestations: 0,
    };

    let validator_count = head_state.validators.len();
    let mut ranked: Vec<(BodyValue, &BodyProofCandidate, Block, PostBlockCheckpoints)> = Vec::new();

    for candidate in candidates.iter() {
        let body = candidate.body_proof.block_body.clone();
        let attestation_count = body.attestations.len();
        if !body_votes_on_chain(&body, &chain_view) {
            trace!(
                %slot,
                attestation_count,
                "Rejected a candidate body proof: it votes off our chain"
            );
            metrics::inc_body_proof_rejected("off_chain_vote");
            continue;
        }
        let new_voters = count_new_voters(head_state, &body, validator_count);
        let sealed = block_builder::seal_block(head_state, slot, proposer_index, parent_root, body);
        let (block, post) = match sealed {
            Ok(sealed) => sealed,
            Err(err) => {
                // Expected, not exceptional: the candidate was packed against
                // another node's view of the chain.
                trace!(%slot, attestation_count, %err, "Rejected a candidate body proof");
                metrics::inc_body_proof_rejected("state_transition");
                continue;
            }
        };
        let value = BodyValue {
            finalized_slot: post.finalized.slot,
            justified_slot: post.justified.slot,
            new_voters,
            fewer_attestations: -(attestation_count as isize),
        };
        if value <= empty_value {
            trace!(
                %slot,
                attestation_count,
                new_voters,
                "Candidate body proof is worth no more than an empty body"
            );
            continue;
        }
        ranked.push((value, candidate, block, post));
    }

    ranked.sort_by(|a, b| b.0.cmp(&a.0));

    for (value, candidate, block, _post) in ranked {
        if !candidate.verified
            && let Err(err) = verify_body_proof(head_state, &candidate.body_proof)
        {
            warn!(%slot, %err, "Candidate body proof failed verification");
            metrics::inc_body_proof_rejected("verification");
            continue;
        }

        info!(
            %slot,
            attestation_count = block.body.attestations.len(),
            new_voters = value.new_voters,
            justified_slot = value.justified_slot,
            finalized_slot = value.finalized_slot,
            from_gossip = !candidate.verified,
            "Adopted a candidate body proof"
        );
        metrics::inc_block_body_from_proof();
        return Ok(ChosenBody {
            block,
            attestation_proof: candidate.body_proof.proof.clone(),
            adopted: true,
        });
    }

    info!(
        %slot,
        candidates = candidates.len(),
        "No usable candidate body proof; proposing an empty block"
    );
    metrics::inc_block_body_empty();
    Ok(ChosenBody {
        block: empty_block,
        attestation_proof: MultiMessageAggregate::default(),
        adopted: false,
    })
}

/// Whether every vote in a body sits on the chain the block would extend:
/// each one's source, target and head root found at its own slot in
/// `chain_view`.
///
/// Deliberately narrower than the block builder's `entry_passes_filters`,
/// which also drops entries that are merely unhelpful — a target already
/// justified, a source not yet justified. Those are per-entry verdicts, and a
/// body is all-or-nothing: its proof binds exactly these attestations, so one
/// stale entry would cost the whole candidate and, often, leave the slot with
/// an empty block. A stale vote is already discounted by the new-voter score;
/// an off-chain vote is the one a proposer must not carry, and the state
/// transition would carry it happily.
fn body_votes_on_chain(body: &BlockBody, chain_view: &[H256]) -> bool {
    body.attestations
        .iter()
        .all(|attestation| attestation_data_matches_chain(chain_view, &attestation.data))
}

/// Count the validators a body's attestations add on top of `head_state`.
///
/// Uses the block builder's projection so the count means the same thing it
/// does during selection: per target root, voters the running set does not
/// already hold.
fn count_new_voters(head_state: &State, body: &BlockBody, validator_count: usize) -> usize {
    let mut projected = block_builder::ProjectedState::from_head_state(head_state);
    let mut total = 0usize;

    for attestation in body.attestations.iter() {
        let coverage: HashSet<u64> = validator_indices(&attestation.aggregation_bits).collect();
        let Some((score, new_voters)) =
            projected.score_entry(&attestation.data, &coverage, validator_count)
        else {
            continue;
        };
        total += new_voters.len();
        projected.advance(score.tier, &attestation.data, new_voters);
    }

    total
}

/// Verify a candidate's aggregate against the body it claims to bind: one
/// Type-2 component per attestation, each bound to that attestation's data
/// root and slot.
///
/// The same check `verify_block_signatures` runs on import, minus the proposer
/// signature (which does not exist yet).
fn verify_body_proof(head_state: &State, body_proof: &BlockBodyProof) -> Result<(), StoreError> {
    let attestations = &body_proof.block_body.attestations;
    let validators = &head_state.validators;
    let num_validators = validators.len() as u64;

    let mut pubkeys_per_component: Vec<Vec<ValidatorPublicKey>> =
        Vec::with_capacity(attestations.len());
    let mut expected_bindings: Vec<(H256, u32)> = Vec::with_capacity(attestations.len());

    for attestation in attestations.iter() {
        let mut pubkeys = Vec::new();
        for vid in validator_indices(&attestation.aggregation_bits) {
            let validator =
                validators
                    .get(vid as usize)
                    .ok_or(StoreError::AttesterIndexOutOfRange {
                        validator_index: vid,
                        num_validators,
                    })?;
            let pubkey = ValidatorPublicKey::from_bytes(&validator.attestation_pubkey)
                .map_err(|_| StoreError::PubkeyDecodingFailed(vid))?;
            pubkeys.push(pubkey);
        }
        pubkeys_per_component.push(pubkeys);
        let slot = u32::try_from(attestation.data.slot)
            .map_err(|_| StoreError::SlotOutOfRange(attestation.data.slot))?;
        expected_bindings.push((attestation.data.hash_tree_root(), slot));
    }

    let _timing = metrics::time_pq_sig_aggregated_signatures_verification();
    ethlambda_crypto::verify_type_2_signature(
        body_proof.proof.proof_bytes(),
        pubkeys_per_component,
        &expected_bindings,
    )
    .map_err(StoreError::BlockProofVerificationFailed)
}

/// Bounded, newest-first buffer of proposal candidates.
#[derive(Default)]
pub(crate) struct BodyProofBuffer {
    candidates: VecDeque<BodyProofCandidate>,
}

impl BodyProofBuffer {
    /// Record a candidate built by our own aggregation worker.
    pub(crate) fn push_local(&mut self, body_proof: BlockBodyProof) {
        self.push(BodyProofCandidate {
            body_proof,
            verified: true,
        });
    }

    /// Record a candidate that arrived on gossip. Its aggregate is not
    /// verified here: verification costs a full Type-2 check, and only the
    /// slot's proposer ever needs the answer.
    pub(crate) fn push_gossip(&mut self, body_proof: BlockBodyProof) {
        self.push(BodyProofCandidate {
            body_proof,
            verified: false,
        });
    }

    fn push(&mut self, candidate: BodyProofCandidate) {
        self.candidates.push_front(candidate);
        while self.candidates.len() > MAX_BODY_PROOF_CANDIDATES {
            let dropped = self.candidates.pop_back();
            trace!(
                dropped_attestations = dropped.map(|c| c.body_proof.block_body.attestations.len()),
                "Evicted the oldest block body proof candidate"
            );
        }
    }

    /// Candidates newest first.
    ///
    /// Nothing is aged out by slot, and the buffer is never cleared on a tick.
    /// Two reasons. A clear at an interval boundary races the batch it is
    /// making room for, since our own worker's candidate can land either side
    /// of it. And a candidate is not worthless for being a slot or two old:
    /// the merge that produces one takes seconds, so candidates routinely
    /// arrive a slot late, and while the blocks in between were empty their
    /// votes are still the newest anyone has. What a stale candidate cannot do
    /// is win: it adds no voters the state lacks, so `choose_body` scores it
    /// below an empty body. The ring bound is what keeps this finite.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &BodyProofCandidate> {
        self.candidates.iter()
    }

    pub(crate) fn len(&self) -> usize {
        self.candidates.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_types::{
        attestation::{AggregatedAttestation, AggregationBits, AttestationData},
        block::{BlockHeader, MultiMessageAggregate},
        checkpoint::Checkpoint,
        state::{ChainConfig, JustificationValidators, JustifiedSlots, Validator},
    };
    use libssz_types::SszList;

    const NUM_VALIDATORS: usize = 4;
    /// Slot of the head the candidates are packed on top of; the block under
    /// construction is the next one.
    const HEAD_SLOT: u64 = 1;
    const BLOCK_SLOT: u64 = HEAD_SLOT + 1;
    /// Round-robin proposer for [`BLOCK_SLOT`]; the state transition rejects
    /// any other index.
    const PROPOSER: u64 = BLOCK_SLOT % NUM_VALIDATORS as u64;

    fn genesis_root() -> H256 {
        H256([1u8; 32])
    }

    /// The head block's root, as the state transition derives it: the hash of
    /// `latest_block_header` once `process_slots` has filled in its state
    /// root. Deriving it the same way the transition does is the only way a
    /// fixture parent root matches.
    fn head_root() -> H256 {
        let mut state = head_state();
        ethlambda_state_transition::process_slots(&mut state, BLOCK_SLOT)
            .expect("advancing one slot works");
        state.latest_block_header.hash_tree_root()
    }

    /// A chain of two blocks: genesis at slot 0 and the head at [`HEAD_SLOT`].
    /// `historical_block_hashes` covers `[0, HEAD_SLOT - 1]` — the header push
    /// records the parent, never the block's own root — so the head root lands
    /// there only once a block builds on it.
    fn head_state() -> State {
        State {
            config: ChainConfig { genesis_time: 1000 },
            slot: HEAD_SLOT,
            latest_block_header: BlockHeader {
                slot: HEAD_SLOT,
                proposer_index: 0,
                parent_root: genesis_root(),
                state_root: H256::ZERO,
                body_root: H256::ZERO,
            },
            latest_justified: Checkpoint::default(),
            latest_finalized: Checkpoint::default(),
            historical_block_hashes: SszList::try_from(vec![genesis_root()]).unwrap(),
            justified_slots: JustifiedSlots::new(),
            validators: SszList::try_from(
                (0..NUM_VALIDATORS)
                    .map(|i| Validator {
                        attestation_pubkey: [i as u8; 52],
                        proposal_pubkey: [i as u8; 52],
                        index: i as u64,
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap(),
            justifications_roots: Default::default(),
            justifications_validators: JustificationValidators::new(),
        }
    }

    fn bits(indices: &[usize]) -> AggregationBits {
        let max = indices.iter().copied().max().unwrap_or(0);
        let mut bits = AggregationBits::with_length(max + 1).unwrap();
        for &i in indices {
            bits.set(i, true).unwrap();
        }
        bits
    }

    /// A vote for the head, sourced at genesis: valid on top of
    /// [`head_state`] and worth new voters.
    fn head_vote(voters: &[usize]) -> AggregatedAttestation {
        AggregatedAttestation {
            aggregation_bits: bits(voters),
            data: AttestationData {
                slot: HEAD_SLOT,
                head: Checkpoint {
                    root: head_root(),
                    slot: HEAD_SLOT,
                },
                target: Checkpoint {
                    root: head_root(),
                    slot: HEAD_SLOT,
                },
                source: Checkpoint {
                    root: genesis_root(),
                    slot: 0,
                },
            },
        }
    }

    /// A vote naming a head that is not on this chain, which the state
    /// transition rejects.
    fn off_chain_vote() -> AggregatedAttestation {
        let mut attestation = head_vote(&[0]);
        attestation.data.head.root = H256([9u8; 32]);
        attestation.data.target.root = H256([9u8; 32]);
        attestation
    }

    fn candidate(attestations: Vec<AggregatedAttestation>) -> BlockBodyProof {
        BlockBodyProof {
            block_body: BlockBody {
                attestations: attestations.try_into().unwrap(),
            },
            proof: MultiMessageAggregate::default(),
        }
    }

    fn choose(candidates: &BodyProofBuffer) -> ChosenBody {
        choose_body(&head_state(), BLOCK_SLOT, PROPOSER, head_root(), candidates)
            .expect("sealing an empty body always works")
    }

    #[test]
    fn choose_body_falls_back_to_an_empty_body() {
        let chosen = choose(&BodyProofBuffer::default());

        assert!(!chosen.adopted);
        assert_eq!(chosen.block.body.attestations.len(), 0);
        assert!(
            chosen.attestation_proof.proof_bytes().is_empty(),
            "an attestation-less block carries no aggregate"
        );
    }

    #[test]
    fn choose_body_adopts_a_candidate_that_adds_voters() {
        let mut candidates = BodyProofBuffer::default();
        candidates.push_local(candidate(vec![head_vote(&[0, 1])]));

        let chosen = choose(&candidates);

        assert!(chosen.adopted);
        assert_eq!(chosen.block.body.attestations.len(), 1);
    }

    /// The state transition would carry a vote for an unknown root happily, so
    /// this is the screen that keeps a body packed against another node's view
    /// out of our block.
    #[test]
    fn choose_body_rejects_a_candidate_voting_off_chain() {
        let mut candidates = BodyProofBuffer::default();
        candidates.push_local(candidate(vec![off_chain_vote()]));

        let chosen = choose(&candidates);

        assert!(!chosen.adopted);
    }

    /// A body that adds no voters is worth no more than an empty one, so it
    /// loses the tie rather than bloating the block.
    #[test]
    fn choose_body_ignores_a_candidate_with_no_new_voters() {
        let mut candidates = BodyProofBuffer::default();
        candidates.push_local(candidate(vec![head_vote(&[])]));

        let chosen = choose(&candidates);

        assert!(!chosen.adopted);
    }

    #[test]
    fn choose_body_prefers_the_candidate_with_more_new_voters() {
        let mut candidates = BodyProofBuffer::default();
        candidates.push_local(candidate(vec![head_vote(&[0])]));
        candidates.push_local(candidate(vec![head_vote(&[0, 1, 2])]));

        let chosen = choose(&candidates);

        assert!(chosen.adopted);
        let adopted = chosen
            .block
            .body
            .attestations
            .iter()
            .next()
            .expect("the adopted body carries its attestation");
        assert_eq!(
            validator_indices(&adopted.aggregation_bits).count(),
            3,
            "the wider candidate wins"
        );
    }

    #[test]
    fn buffer_keeps_the_newest_candidates() {
        let mut buffer = BodyProofBuffer::default();
        for _ in 0..MAX_BODY_PROOF_CANDIDATES {
            buffer.push_gossip(candidate(Vec::new()));
        }
        buffer.push_local(candidate(Vec::new()));

        assert_eq!(buffer.len(), MAX_BODY_PROOF_CANDIDATES);
        assert!(
            buffer.iter().next().expect("non-empty").verified,
            "the newest candidate is at the front"
        );
        assert_eq!(
            buffer.iter().filter(|c| c.verified).count(),
            1,
            "only the locally built candidate counts as verified"
        );
    }
}
