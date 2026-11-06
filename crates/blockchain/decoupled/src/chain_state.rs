//! The finality gadget's chain state, for a host without a `BeaconState`.
//!
//! EIP-8453 keeps the finality gadget in the beacon state
//! (`target_checkpoint`, `justified_checkpoint`, `finalized_checkpoint`,
//! `target_slot`, `finalized_slot`, `target_participation`,
//! `progress_participation`, `pending_finality`) and updates it in
//! `process_attestation` and `process_height_events` (beacon-chain.md). A
//! beacon host reads those fields from its own state. Lean has no such state,
//! so this module is lean's: the same fields and the same rules, minus what
//! only the beacon chain has (rewards, participation flags, the inactivity
//! leak, committees and attestation epochs), with weights supplied by an
//! [`Electorate`].
//!
//! Every block's chain state is a pure function of its parent's and the
//! block's attestations: `state_transition(parent, block, attestations)`.

use std::collections::HashMap;

use ethlambda_types::primitives::H256;

use crate::params::Params;
use crate::types::{
    AttestationData, BlockRef, Electorate, FgCheckpoints, HeightCheckpoint, Slot, ValidatorIndex,
};

/// One validator bit per registry entry (`HeightParticipation`).
pub type Participation = Vec<bool>;

/// `PendingFinality`: a justification on the chain not yet finalized, and who
/// has cast a finality pair for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingFinality {
    pub checkpoint: HeightCheckpoint,
    pub slot: Slot,
    pub participation: Participation,
}

/// The finality gadget fields of the beacon state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainState {
    /// `state.slot`: the latest block's slot.
    pub slot: Slot,
    pub target_checkpoint: HeightCheckpoint,
    pub target_slot: Slot,
    pub justified_checkpoint: HeightCheckpoint,
    pub finalized_checkpoint: HeightCheckpoint,
    pub finalized_slot: Slot,
    pub target_participation: Participation,
    pub progress_participation: Participation,
    /// In increasing order of height, at most `PENDING_FINALITY_WINDOW`.
    pub pending_finality: Vec<PendingFinality>,
}

/// Why an attestation cannot be processed. `process_attestation` asserts each
/// of these, so a block carrying such an attestation is invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AttestationError {
    #[error("attestation data is not well formed")]
    NotWellFormed,
    #[error("attestation names neither the current target nor a pending finality")]
    Invalid,
    #[error("attester {0} is not a validator")]
    UnknownValidator(ValidatorIndex),
}

impl ChainState {
    /// The chain state at the start of the finality gadget, as
    /// `upgrade_to_eip8453` builds it: height 1 targets the anchor, and the
    /// anchor is justified and finalized at height 0.
    pub fn initial(anchor: BlockRef, validator_count: usize) -> Self {
        Self {
            slot: anchor.slot,
            target_checkpoint: HeightCheckpoint::new(1, anchor.root),
            target_slot: anchor.slot,
            justified_checkpoint: HeightCheckpoint::new(0, anchor.root),
            finalized_checkpoint: HeightCheckpoint::new(0, anchor.root),
            finalized_slot: anchor.slot,
            target_participation: vec![false; validator_count],
            progress_participation: vec![false; validator_count],
            pending_finality: Vec::new(),
        }
    }

    /// The checkpoints the fork choice reads.
    pub fn checkpoints(&self) -> FgCheckpoints {
        FgCheckpoints {
            target: self.target_checkpoint,
            justified: self.justified_checkpoint,
            finalized: self.finalized_checkpoint,
        }
    }

    fn validator_count(&self) -> usize {
        self.target_participation.len()
    }
}

/// `is_well_formed_attestation_data`.
pub fn is_well_formed_attestation_data(data: &AttestationData) -> bool {
    if data.target.height == 0 || data.target.root == H256::ZERO {
        return false;
    }
    if data.finality.is_empty() {
        return true;
    }
    data.finality.root != H256::ZERO && data.finality.height < data.target.height
}

/// `is_valid_attestation_data`: `data` names the state's target checkpoint, or
/// is a vote below the current height whose finality pair is pending.
pub fn is_valid_attestation_data(state: &ChainState, data: &AttestationData) -> bool {
    if data.target == state.target_checkpoint {
        return true;
    }
    state
        .pending_finality
        .iter()
        .any(|pending| pending.checkpoint == data.finality)
        && data.finality.height < data.target.height
        && data.target.height < state.target_checkpoint.height
}

/// `has_quorum`: the marked validators hold at least two thirds of the total
/// weight, and some weight at all.
pub fn has_quorum(participation: &[bool], electorate: &Electorate) -> bool {
    let participating: u128 = participation
        .iter()
        .enumerate()
        .filter(|(_, marked)| **marked)
        .map(|(index, _)| u128::from(electorate.weight(index as ValidatorIndex)))
        .sum();
    participating > 0 && participating * 3 >= electorate.total() * 2
}

/// `process_attestation`, finality gadget part: credit each attester to every
/// pending justification its finality pair names, and to progress (and, for a
/// target vote, target) participation when it names the current target.
pub fn process_attestation(
    state: &mut ChainState,
    attesters: &[ValidatorIndex],
    data: &AttestationData,
) -> Result<(), AttestationError> {
    if !is_well_formed_attestation_data(data) {
        return Err(AttestationError::NotWellFormed);
    }
    if !is_valid_attestation_data(state, data) {
        return Err(AttestationError::Invalid);
    }
    let count = state.validator_count();
    if let Some(&unknown) = attesters.iter().find(|&&v| v as usize >= count) {
        return Err(AttestationError::UnknownValidator(unknown));
    }
    for &validator in attesters {
        let index = validator as usize;
        for pending in &mut state.pending_finality {
            if pending.checkpoint == data.finality {
                pending.participation[index] = true;
            }
        }
        if data.target == state.target_checkpoint {
            state.progress_participation[index] = true;
            if !data.timeout {
                state.target_participation[index] = true;
            }
        }
    }
    Ok(())
}

/// `process_height_events`: finalize the highest pending justification with a
/// quorum, then justify the target and advance on a target quorum, or advance
/// on a progress quorum once the timeout delay has passed.
pub fn process_height_events(
    state: &mut ChainState,
    block: BlockRef,
    params: &Params,
    electorate: &Electorate,
) {
    for pending in &state.pending_finality {
        if has_quorum(&pending.participation, electorate) {
            state.finalized_checkpoint = pending.checkpoint;
            state.finalized_slot = pending.slot;
        }
    }
    let finalized_height = state.finalized_checkpoint.height;
    state
        .pending_finality
        .retain(|pending| pending.checkpoint.height > finalized_height);

    if has_quorum(&state.target_participation, electorate) {
        state.justified_checkpoint = state.target_checkpoint;
        // Keep only the newest pending justifications.
        if state.pending_finality.len() as u64 >= params.pending_finality_window {
            state.pending_finality.remove(0);
        }
        state.pending_finality.push(PendingFinality {
            checkpoint: state.target_checkpoint,
            slot: state.target_slot,
            participation: vec![false; state.validator_count()],
        });
        advance_height(state, block);
    } else if has_quorum(&state.progress_participation, electorate)
        // Timeouts count only after the delay.
        && state.slot >= state.target_slot + params.timeout_delay_slots()
    {
        advance_height(state, block);
    }
}

/// `advance_height`. The spec leaves the new target's root empty for the next
/// `process_slot` to fill with this block's root; lean's chain state is never
/// committed to by its own block, so the root is filled in here.
pub fn advance_height(state: &mut ChainState, block: BlockRef) {
    state.target_checkpoint = HeightCheckpoint::new(state.target_checkpoint.height + 1, block.root);
    state.target_slot = block.slot;
    let count = state.validator_count();
    state.target_participation = vec![false; count];
    state.progress_participation = vec![false; count];
}

/// The chain state after `block`, from its parent's: `process_attestation`
/// for every carried attestation, then `process_height_events` once.
pub fn state_transition<'a>(
    parent: &ChainState,
    block: BlockRef,
    attestations: impl IntoIterator<Item = (ValidatorIndex, &'a AttestationData)>,
    params: &Params,
    electorate: &Electorate,
) -> Result<ChainState, AttestationError> {
    let mut state = parent.clone();
    state.slot = block.slot;
    for (validator, data) in attestations {
        process_attestation(&mut state, &[validator], data)?;
    }
    process_height_events(&mut state, block, params, electorate);
    Ok(state)
}

/// The proposer's attestation choice: the candidates, in order, that
/// `process_attestation` accepts against `state` and that add target,
/// progress or pending-finality participation (validator.md, "Attestations").
/// Returns their indices.
pub fn select_attestations(
    state: &ChainState,
    candidates: &[(ValidatorIndex, AttestationData)],
) -> Vec<usize> {
    let mut scratch = state.clone();
    let mut selected = Vec::new();
    for (i, (validator, data)) in candidates.iter().enumerate() {
        let index = *validator as usize;
        if index >= scratch.validator_count() {
            continue;
        }
        let adds_progress = data.target == scratch.target_checkpoint
            && (!scratch.progress_participation[index]
                || (!data.timeout && !scratch.target_participation[index]));
        let adds_finality = scratch
            .pending_finality
            .iter()
            .any(|pending| pending.checkpoint == data.finality && !pending.participation[index]);
        if !(adds_progress || adds_finality) {
            continue;
        }
        if process_attestation(&mut scratch, &[*validator], data).is_ok() {
            selected.push(i);
        }
    }
    selected
}

/// Every held block's chain state, for a host that derives them (lean).
#[derive(Debug, Clone, Default)]
pub struct ChainStates {
    states: HashMap<H256, ChainState>,
}

/// Why a block's chain state could not be derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ChainStateError {
    #[error("the parent's chain state is unknown")]
    UnknownParent,
    #[error(transparent)]
    Attestation(#[from] AttestationError),
}

impl ChainStates {
    /// The states of a chain anchored at `anchor`, whose state is `state`.
    pub fn new(anchor: BlockRef, state: ChainState) -> Self {
        Self {
            states: HashMap::from([(anchor.root, state)]),
        }
    }

    pub fn get(&self, root: &H256) -> Option<&ChainState> {
        self.states.get(root)
    }

    /// Derive and keep `block`'s chain state; returns its checkpoints.
    pub fn import<'a>(
        &mut self,
        parent_root: &H256,
        block: BlockRef,
        attestations: impl IntoIterator<Item = (ValidatorIndex, &'a AttestationData)>,
        params: &Params,
        electorate: &Electorate,
    ) -> Result<FgCheckpoints, ChainStateError> {
        let parent = self
            .states
            .get(parent_root)
            .ok_or(ChainStateError::UnknownParent)?;
        let state = state_transition(parent, block, attestations, params, electorate)?;
        let checkpoints = state.checkpoints();
        self.states.insert(block.root, state);
        Ok(checkpoints)
    }

    /// Drop the states of blocks `keep` refuses.
    pub fn retain(&mut self, keep: impl Fn(&H256) -> bool) {
        self.states.retain(|root, _| keep(root));
    }

    pub fn len(&self) -> usize {
        self.states.len()
    }

    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(byte: u8, slot: Slot) -> BlockRef {
        BlockRef {
            root: H256([byte; 32]),
            slot,
        }
    }

    fn vote(
        target: HeightCheckpoint,
        timeout: bool,
        finality: HeightCheckpoint,
    ) -> AttestationData {
        AttestationData {
            target,
            timeout,
            finality,
        }
    }

    fn apply(
        state: &ChainState,
        at: BlockRef,
        votes: &[(ValidatorIndex, AttestationData)],
    ) -> ChainState {
        let params = Params::minimal();
        let electorate = Electorate::uniform(state.validator_count());
        state_transition(
            state,
            at,
            votes.iter().map(|(v, data)| (*v, data)),
            &params,
            &electorate,
        )
        .expect("valid attestations")
    }

    #[test]
    fn has_quorum_needs_two_thirds_and_never_the_empty_set() {
        let electorate = Electorate::uniform(4);
        assert!(!has_quorum(&[false; 4], &electorate));
        assert!(!has_quorum(&[true, true, false, false], &electorate));
        // 3 · 3 ≥ 2 · 4.
        assert!(has_quorum(&[true, true, true, false], &electorate));
        // A zero-weight electorate never has a quorum, not even trivially.
        assert!(!has_quorum(&[], &Electorate::uniform(0)));
        let weighted = Electorate::new(vec![0, 0, 5]);
        assert!(!has_quorum(&[true, true, false], &weighted));
        assert!(has_quorum(&[false, false, true], &weighted));
    }

    #[test]
    fn a_target_quorum_justifies_the_target_and_advances() {
        let genesis = block(0xaa, 0);
        let state = ChainState::initial(genesis, 4);
        let target = state.target_checkpoint;
        let votes: Vec<_> = (0..3)
            .map(|v| (v, vote(target, false, HeightCheckpoint::empty())))
            .collect();
        let next = apply(&state, block(1, 4), &votes);
        assert_eq!(next.justified_checkpoint, target);
        assert_eq!(
            next.target_checkpoint,
            HeightCheckpoint::new(2, block(1, 4).root)
        );
        assert_eq!(next.target_slot, 4);
        assert_eq!(next.pending_finality.len(), 1);
        assert_eq!(next.pending_finality[0].checkpoint, target);
        assert!(next.target_participation.iter().all(|bit| !bit));

        // Two votes are not a quorum.
        let short = apply(&state, block(1, 4), &votes[..2]);
        assert_eq!(short.target_checkpoint, target);
        assert_eq!(short.justified_checkpoint.height, 0);
    }

    #[test]
    fn finality_pairs_finalize_a_pending_justification() {
        let genesis = block(0xaa, 0);
        let state = ChainState::initial(genesis, 4);
        let h1 = state.target_checkpoint;
        let justify: Vec<_> = (0..3)
            .map(|v| (v, vote(h1, false, HeightCheckpoint::empty())))
            .collect();
        let justified = apply(&state, block(1, 4), &justify);
        let h2 = justified.target_checkpoint;
        // Target votes at height 2 carrying the finality pair of height 1.
        let finalize: Vec<_> = (0..3).map(|v| (v, vote(h2, false, h1))).collect();
        let next = apply(&justified, block(2, 8), &finalize);
        assert_eq!(next.finalized_checkpoint, h1);
        assert_eq!(next.finalized_slot, 0);
        // Height 1 left the window; height 2 was justified and joined it.
        assert_eq!(
            next.pending_finality
                .iter()
                .map(|p| p.checkpoint)
                .collect::<Vec<_>>(),
            vec![h2]
        );
        assert_eq!(next.justified_checkpoint, h2);
    }

    #[test]
    fn the_highest_pending_justification_with_a_quorum_is_finalized() {
        let genesis = block(0xaa, 0);
        let mut state = ChainState::initial(genesis, 3);
        let mut checkpoints = Vec::new();
        // Justify heights 1, 2, 3 with no finality pairs.
        for i in 1..=3u8 {
            let target = state.target_checkpoint;
            checkpoints.push(target);
            let votes: Vec<_> = (0..2)
                .map(|v| (v, vote(target, false, HeightCheckpoint::empty())))
                .collect();
            state = apply(&state, block(i, u64::from(i) * 4), &votes);
        }
        assert_eq!(state.pending_finality.len(), 3);
        // Finality pairs for height 1 from two and for height 3 from two, in
        // one block, as votes below the current height (height 4).
        let h1 = checkpoints[0];
        let h3 = checkpoints[2];
        let current = state.target_checkpoint;
        let votes = vec![
            (0, vote(current, false, h1)),
            (1, vote(current, false, h1)),
            (0, vote(current, true, h3)),
            (1, vote(current, true, h3)),
        ];
        let next = apply(&state, block(9, 20), &votes);
        assert_eq!(next.finalized_checkpoint, h3);
        assert_eq!(next.finalized_slot, 8);
        // Everything at or below the finalized height leaves the window; the
        // two target votes justified height 4, which joined it.
        let heights: Vec<_> = next
            .pending_finality
            .iter()
            .map(|p| p.checkpoint.height)
            .collect();
        assert_eq!(heights, vec![4]);
    }

    #[test]
    fn the_pending_window_keeps_only_the_newest() {
        let genesis = block(0xaa, 0);
        let mut state = ChainState::initial(genesis, 3);
        for i in 1..=6u8 {
            let target = state.target_checkpoint;
            let votes: Vec<_> = (0..2)
                .map(|v| (v, vote(target, false, HeightCheckpoint::empty())))
                .collect();
            state = apply(&state, block(i, u64::from(i)), &votes);
        }
        let heights: Vec<_> = state
            .pending_finality
            .iter()
            .map(|p| p.checkpoint.height)
            .collect();
        assert_eq!(heights, vec![3, 4, 5, 6]);
    }

    #[test]
    fn timeouts_advance_only_after_the_delay_and_never_justify() {
        let genesis = block(0xaa, 0);
        let state = ChainState::initial(genesis, 4);
        let target = state.target_checkpoint;
        let timeouts: Vec<_> = (0..3)
            .map(|v| (v, vote(target, true, HeightCheckpoint::empty())))
            .collect();
        // TIMEOUT_DELAY_SLOTS = SLOTS_PER_ROUND = 4 slots after the target.
        let early = apply(&state, block(1, 3), &timeouts);
        assert_eq!(early.target_checkpoint, target);
        assert_eq!(
            early.progress_participation.iter().filter(|b| **b).count(),
            3
        );
        let late = apply(&early, block(2, 4), &[]);
        assert_eq!(late.target_checkpoint.height, 2);
        assert_eq!(
            late.justified_checkpoint.height, 0,
            "a timeout never justifies"
        );
    }

    #[test]
    fn attestations_are_validated_as_process_attestation_asserts() {
        let genesis = block(0xaa, 0);
        let state = ChainState::initial(genesis, 4);
        let target = state.target_checkpoint;
        let mut scratch = state.clone();
        // Height 0, an empty root, a finality pair at or above the target.
        for bad in [
            vote(
                HeightCheckpoint::new(0, genesis.root),
                false,
                HeightCheckpoint::empty(),
            ),
            vote(
                HeightCheckpoint::new(1, H256::ZERO),
                false,
                HeightCheckpoint::empty(),
            ),
            vote(target, false, HeightCheckpoint::new(1, genesis.root)),
        ] {
            assert_eq!(
                process_attestation(&mut scratch, &[0], &bad),
                Err(AttestationError::NotWellFormed)
            );
        }
        // Another root at the current height.
        let other = vote(
            HeightCheckpoint::new(1, H256([9; 32])),
            false,
            HeightCheckpoint::empty(),
        );
        assert_eq!(
            process_attestation(&mut scratch, &[0], &other),
            Err(AttestationError::Invalid)
        );
        assert_eq!(
            process_attestation(
                &mut scratch,
                &[7],
                &vote(target, false, HeightCheckpoint::empty())
            ),
            Err(AttestationError::UnknownValidator(7))
        );
        assert_eq!(scratch, state, "a refused attestation records nothing");
    }

    #[test]
    fn the_proposer_selects_only_attestations_that_add_participation() {
        let genesis = block(0xaa, 0);
        let state = ChainState::initial(genesis, 4);
        let target = state.target_checkpoint;
        let good = vote(target, false, HeightCheckpoint::empty());
        let timeout = vote(target, true, HeightCheckpoint::empty());
        let invalid = vote(
            HeightCheckpoint::new(5, H256([9; 32])),
            false,
            HeightCheckpoint::empty(),
        );
        let candidates = vec![
            (0, good),
            (0, good),
            (0, timeout),
            (1, invalid),
            (1, timeout),
        ];
        // The duplicate adds nothing, the timeout after a target vote adds
        // nothing, the invalid one is refused.
        assert_eq!(select_attestations(&state, &candidates), vec![0, 4]);
    }
}
