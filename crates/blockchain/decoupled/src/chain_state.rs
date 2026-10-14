//! The finality gadget's chain state σ and its state transition (the
//! specification's figure 5): on chain, 2/3 target votes for `(h, T_h)`
//! justify `T_h` and advance the height, 2/3 targets plus timeouts advance
//! it after a delay, and 2/3 finality votes for one of the pending
//! justifications finalize it.
//!
//! Every block's post-state is a pure function of its parent's post-state and
//! the block's carried attestations: `σ[B] = state_transition(σ[B.parent], B)`.

pub use ethlambda_types::decoupled::{ChainState, PendingFinality, ValidatorBits};

use crate::params::Params;
use crate::types::{Attestation, BlockRef, Electorate};

fn empty_bits(validator_count: usize) -> ValidatorBits {
    ValidatorBits::with_length(validator_count).expect("validator count within the registry limit")
}

fn insert(bits: &mut ValidatorBits, validator: u64) {
    // A validator outside the electorate has no weight; it cannot reach a
    // quorum, so dropping its bit changes no decision.
    if let Ok(index) = usize::try_from(validator) {
        let _ = bits.set(index, true);
    }
}

fn clear(bits: &mut ValidatorBits) {
    *bits = empty_bits(bits.len());
}

/// `w({i : bits[i]})`.
pub fn weight_of(bits: &ValidatorBits, electorate: &Electorate) -> u64 {
    (0..bits.len())
        .filter(|&i| bits.get(i) == Some(true))
        .map(|i| electorate.weight(i as u64))
        .sum()
}

fn is_quorum(bits: &ValidatorBits, electorate: &Electorate) -> bool {
    weight_of(bits, electorate) >= electorate.quorum()
}

/// A carried attestation that is not valid against the parent's state: the
/// block that carries it is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("carried attestation {index} is not valid against the parent state")]
pub struct InvalidAttestation {
    pub index: usize,
}

/// `valid_attestation(σ, a)`: the attestation names the chain's own entry at
/// the current height, or it is a vote below the current height whose
/// finality pair is a pending pair of the chain.
pub fn valid_attestation(state: &ChainState, attestation: &Attestation) -> bool {
    let vote = attestation.data.height_pair();
    if vote.height == state.height && vote.entry == state.entry.root {
        return true;
    }
    attestation.data.finality_pair().is_some_and(|pair| {
        state.pending(&pair).is_some() && pair.height < vote.height && vote.height < state.height
    })
}

/// `state_transition(σ, B)`, minus the assertions `B.proposer =
/// proposer(B.slot)` and `B.parent.slot < B.slot`, which the host and the
/// store's admission guard check before calling it. A carried attestation
/// that is not [valid](valid_attestation) against the parent's state fails
/// the assertion, and the block is refused before any write.
pub fn state_transition(
    parent_state: &ChainState,
    block: BlockRef,
    attestations: &[Attestation],
    params: &Params,
    electorate: &Electorate,
) -> Result<ChainState, InvalidAttestation> {
    if let Some(index) = attestations
        .iter()
        .position(|attestation| !valid_attestation(parent_state, attestation))
    {
        return Err(InvalidAttestation { index });
    }
    let mut state = parent_state.clone();
    state.slot = block.slot;
    for attestation in attestations {
        process_attestation(&mut state, attestation);
    }
    state.latest = block;
    process_height_events(&mut state, params, electorate);
    Ok(state)
}

/// `process_attestation(σ, a)`.
///
/// The finality pair counts when it names a pending pair. The height pair
/// counts only when it names the chain's own entry at the current height,
/// for a target vote and a timeout alike.
pub fn process_attestation(state: &mut ChainState, attestation: &Attestation) {
    let validator = attestation.validator;
    if let Some(pair) = attestation.data.finality_pair()
        && let Some(pending) = state
            .pending_finality
            .iter_mut()
            .find(|pending| pending.height == pair.height && pending.target.root == pair.target)
    {
        insert(&mut pending.participation, validator);
    }
    let vote = attestation.data.height_pair();
    if vote.height == state.height && vote.entry == state.entry.root {
        insert(&mut state.progress, validator);
        if !vote.timeout {
            insert(&mut state.target_participation, validator);
        }
    }
}

/// `process_height_events(σ)`: finalize the greatest pending justification
/// with a finality quorum, then justify-and-advance or advance on progress.
/// At most one height event per block.
pub fn process_height_events(state: &mut ChainState, params: &Params, electorate: &Electorate) {
    if let Some(pending) = state
        .pending_finality
        .iter()
        .rev()
        .find(|pending| is_quorum(&pending.participation, electorate))
    {
        state.finalized = pending.target;
        state.finalized_height = pending.height;
    }
    let finalized_height = state.finalized_height;
    state
        .pending_finality
        .retain(|pending| pending.height > finalized_height);

    if is_quorum(&state.target_participation, electorate) {
        state.justified = state.entry;
        state.justified_height = state.height;
        state.pending_finality.push(PendingFinality {
            height: state.height,
            target: state.entry,
            participation: empty_bits(state.target_participation.len()),
        });
        let window = usize::try_from(params.pending_window).unwrap_or(usize::MAX);
        let excess = state.pending_finality.len().saturating_sub(window);
        state.pending_finality.drain(..excess);
        advance_height(state);
        return;
    }
    // Timeouts count only after the delay: a progress quorum that needs them
    // is consumed only by a block at least `δ_t` slots after the entry.
    if state.slot >= state.entry.slot + params.timeout_delay
        && is_quorum(&state.progress, electorate)
    {
        advance_height(state);
    }
}

/// `advance_height(σ)`.
fn advance_height(state: &mut ChainState) {
    state.height += 1;
    state.entry = state.latest;
    clear(&mut state.target_participation);
    clear(&mut state.progress);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AttestationData, FinalityVote, Height, HeightVote, Slot};
    use ethlambda_types::primitives::H256;

    fn block(byte: u8, slot: Slot) -> BlockRef {
        BlockRef {
            root: H256([byte; 32]),
            slot,
        }
    }

    fn attestation(
        validator: u64,
        height: Height,
        entry: H256,
        timeout: bool,
        finality: Option<(Height, H256)>,
    ) -> Attestation {
        Attestation {
            validator,
            data: AttestationData::new(
                HeightVote {
                    height,
                    entry,
                    timeout,
                },
                finality.map(|(height, target)| FinalityVote { height, target }),
            ),
        }
    }

    fn targets(height: Height, entry: H256, finality: Option<(Height, H256)>) -> Vec<Attestation> {
        (0..3)
            .map(|v| attestation(v, height, entry, false, finality))
            .collect()
    }

    fn apply(state: &ChainState, block: BlockRef, attestations: &[Attestation]) -> ChainState {
        state_transition(
            state,
            block,
            attestations,
            &Params::default(),
            &Electorate::uniform(4),
        )
        .expect("valid attestations")
    }

    #[test]
    fn a_target_quorum_justifies_the_entry_and_advances() {
        let genesis = block(0, 0);
        let state = ChainState::initial(genesis, 4);

        // Three of four target votes reach q = ⌈8/3⌉ = 3.
        let votes = targets(1, genesis.root, None);
        let next = apply(&state, block(1, 4), &votes);
        assert_eq!(next.justified, genesis);
        assert_eq!(next.justified_height, 1);
        assert_eq!(next.height, 2);
        assert_eq!(next.entry, block(1, 4));
        assert_eq!(next.pending_finality.len(), 1);

        // Two votes are not a quorum.
        let short = apply(&state, block(1, 4), &votes[..2]);
        assert_eq!(short.height, 1);
        assert_eq!(short.justified_height, 0);
    }

    #[test]
    fn a_finality_quorum_finalizes_a_pending_justification() {
        let genesis = block(0, 0);
        let a = block(1, 4);
        let justified = apply(
            &ChainState::initial(genesis, 4),
            a,
            &targets(1, genesis.root, None),
        );
        // Height 2, entry A: targets for (2, A) carrying the finality pair
        // (1, G) finalize G and justify A in one block.
        let both = targets(2, a.root, Some((1, genesis.root)));
        let next = apply(&justified, block(2, 8), &both);
        assert_eq!(next.finalized, genesis);
        assert_eq!(next.finalized_height, 1);
        assert_eq!((next.justified, next.justified_height), (a, 2));
        assert_eq!(
            next.pending_finality
                .iter()
                .map(|p| p.height)
                .collect::<Vec<_>>(),
            vec![2]
        );
    }

    #[test]
    fn an_older_pending_justification_stays_finalizable() {
        let genesis = block(0, 0);
        let (a, b) = (block(1, 4), block(2, 8));
        let state = apply(
            &ChainState::initial(genesis, 4),
            a,
            &targets(1, genesis.root, None),
        );
        // Height 2 is justified without finality votes for height 1.
        let state = apply(&state, b, &targets(2, a.root, None));
        assert_eq!(state.pending_finality.len(), 2);
        // Late finality votes for (1, G), riding on stale height pairs
        // below the current height 3, still finalize G.
        let late = targets(2, a.root, Some((1, genesis.root)));
        let next = apply(&state, block(3, 12), &late);
        assert_eq!((next.finalized, next.finalized_height), (genesis, 1));
        assert_eq!(next.pending_finality.len(), 1);
    }

    #[test]
    fn the_window_keeps_the_newest_justifications() {
        let params = Params {
            pending_window: 2,
            ..Params::default()
        };
        let electorate = Electorate::uniform(4);
        let mut state = ChainState::initial(block(0, 0), 4);
        for byte in 1..=3u8 {
            let votes = targets(state.height, state.entry.root, None);
            state = state_transition(
                &state,
                block(byte, 4 * byte as u64),
                &votes,
                &params,
                &electorate,
            )
            .unwrap();
        }
        let heights: Vec<Height> = state.pending_finality.iter().map(|p| p.height).collect();
        assert_eq!(heights, vec![2, 3]);
    }

    #[test]
    fn timeouts_wait_for_the_delay() {
        let params = Params {
            timeout_delay: 6,
            ..Params::default()
        };
        let electorate = Electorate::uniform(4);
        let genesis = block(0, 0);
        let state = ChainState::initial(genesis, 4);
        let timeouts: Vec<_> = (0..3)
            .map(|v| attestation(v, 1, genesis.root, true, None))
            .collect();
        // δ_t = 6 slots after the entry (slot 0).
        let early = state_transition(&state, block(1, 5), &timeouts, &params, &electorate).unwrap();
        assert_eq!(early.height, 1);
        assert_eq!(weight_of(&early.progress, &electorate), 3);
        let late = state_transition(&early, block(2, 6), &[], &params, &electorate).unwrap();
        assert_eq!(late.height, 2);
        assert_eq!(late.justified_height, 0, "a timeout never justifies");
    }

    #[test]
    fn a_block_with_an_invalid_attestation_is_refused() {
        let genesis = block(0, 0);
        let state = ChainState::initial(genesis, 4);
        let other = H256([9; 32]);
        // Another entry at the current height.
        let wrong_entry = attestation(0, 1, other, false, None);
        // A finality pair that is not pending.
        let not_pending = attestation(0, 2, other, false, Some((1, genesis.root)));
        let electorate = Electorate::uniform(4);
        for bad in [wrong_entry, not_pending] {
            let result = state_transition(
                &state,
                block(1, 4),
                std::slice::from_ref(&bad),
                &Params::default(),
                &electorate,
            );
            assert_eq!(result, Err(InvalidAttestation { index: 0 }));
        }
    }

    #[test]
    fn a_finality_pair_counts_only_below_the_height_pair_and_the_chain() {
        let genesis = block(0, 0);
        let a = block(1, 4);
        let state = apply(
            &ChainState::initial(genesis, 4),
            a,
            &targets(1, genesis.root, None),
        );
        // σ.h = 2, (1, G) pending. A vote at height 3 is above the chain.
        let above = attestation(0, 3, a.root, false, Some((1, genesis.root)));
        assert!(!valid_attestation(&state, &above));
        // The chain's own entry is valid whatever the finality pair says.
        let own = attestation(0, 2, a.root, false, Some((1, genesis.root)));
        assert!(valid_attestation(&state, &own));
    }
}
