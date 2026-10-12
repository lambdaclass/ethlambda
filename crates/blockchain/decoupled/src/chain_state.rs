//! The finality gadget's chain state σ and its state transition
//! (PROTOCOL.md §1.3, figure `alg:chain-full`, appendix A.9).
//!
//! Every block's post-state is a pure function of its parent's post-state and
//! the block's carried attestations: `σ[B] = state_transition(σ[B.parent], B)`.

pub use ethlambda_types::decoupled::{ChainState, ValidatorBits};

use crate::params::Params;
use crate::types::{Attestation, BlockRef, Electorate, Height};

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

/// `state_transition(σ, B)` (§2.5), minus the two assertions
/// (`B.proposer = proposer(B.slot)`, `B.parent.slot < B.slot`), which the host
/// and the store's admission guard check before calling it.
pub fn state_transition(
    parent_state: &ChainState,
    block: BlockRef,
    attestations: &[Attestation],
    params: &Params,
    electorate: &Electorate,
) -> ChainState {
    let mut state = parent_state.clone();
    state.slot = block.slot;
    for attestation in attestations {
        process_attestation(&mut state, attestation);
    }
    state.latest = block;
    process_height_events(&mut state, params, electorate);
    state
}

/// `process_attestation(σ, a)` (§2.5).
///
/// A height pair counts only when it names the chain's own entry at the
/// current height, for a target vote and a timeout alike; a pair naming
/// another entry records nothing, while the finality pair is folded
/// regardless.
pub fn process_attestation(state: &mut ChainState, attestation: &Attestation) {
    let validator = attestation.validator;
    if state.justified_height > state.finalized_height
        && attestation.data.finality_pair().is_some_and(|pair| {
            pair.height == state.justified_height && pair.target == state.justified.root
        })
    {
        insert(&mut state.finalize, validator);
    }
    if let Some(vote) = attestation.data.height_pair()
        && vote.height == state.height
        && vote.entry == state.entry.root
    {
        insert(&mut state.progress, validator);
        if !vote.timeout {
            insert(&mut state.target_participation, validator);
        }
    }
}

/// `process_height_events(σ)` (§2.5): finalize, then justify-and-advance or
/// advance on progress. At most one height event per block.
pub fn process_height_events(state: &mut ChainState, params: &Params, electorate: &Electorate) {
    if state.justified_height > state.finalized_height && is_quorum(&state.finalize, electorate) {
        state.finalized = state.justified;
        state.finalized_height = state.justified_height;
    }
    let target_quorum = is_quorum(&state.target_participation, electorate);
    if target_quorum {
        if !state.nonjustifiable {
            state.justified = state.entry;
            state.justified_height = state.height;
            clear(&mut state.finalize);
        }
        advance_height(state, params);
        return;
    }
    // Timeouts count only after the delay: a progress quorum that needs them
    // is consumed only by a block at least `δ_t` slots after the entry.
    if state.slot >= state.entry.slot + params.timeout_delay
        && is_quorum(&state.progress, electorate)
    {
        advance_height(state, params);
    }
}

/// `advance_height(σ)` (§2.5). `finalize` is deliberately kept: only a new
/// justification clears it.
fn advance_height(state: &mut ChainState, params: &Params) {
    state.height += 1;
    state.entry = state.latest;
    state.nonjustifiable = nonjustifiable(params, state.height, state.finalized_height);
    clear(&mut state.target_participation);
    clear(&mut state.progress);
}

/// `nj ← (K | h) ∧ (h − h_F > D)`.
pub fn nonjustifiable(params: &Params, height: Height, finalized_height: Height) -> bool {
    height.is_multiple_of(params.k) && height.saturating_sub(finalized_height) > params.d
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AttestationData, FinalityVote, HeightVote, Slot};
    use ethlambda_types::primitives::H256;

    fn block(byte: u8, slot: Slot) -> BlockRef {
        BlockRef {
            root: H256([byte; 32]),
            slot,
        }
    }

    fn target_vote(validator: u64, height: Height, entry: H256) -> Attestation {
        Attestation {
            validator,
            data: AttestationData::new(
                0,
                Some(entry),
                Some(HeightVote {
                    height,
                    entry,
                    timeout: false,
                }),
                None,
            ),
        }
    }

    #[test]
    fn a_target_quorum_justifies_the_entry_and_advances() {
        let params = Params::with_round_length(3);
        let electorate = Electorate::uniform(4);
        let genesis = block(0, 0);
        let state = ChainState::initial(genesis, 4);

        // Three of four target votes reach q = ⌈8/3⌉ = 3.
        let votes: Vec<_> = (0..3).map(|v| target_vote(v, 1, genesis.root)).collect();
        let next = state_transition(&state, block(1, 4), &votes, &params, &electorate);
        assert_eq!(next.justified, genesis);
        assert_eq!(next.justified_height, 1);
        assert_eq!(next.height, 2);
        assert_eq!(next.entry, block(1, 4));

        // Two votes are not a quorum.
        let short = state_transition(&state, block(1, 4), &votes[..2], &params, &electorate);
        assert_eq!(short.height, 1);
        assert_eq!(short.justified_height, 0);
    }

    #[test]
    fn a_finality_quorum_finalizes_the_justification() {
        let params = Params::with_round_length(3);
        let electorate = Electorate::uniform(4);
        let genesis = block(0, 0);
        let votes: Vec<_> = (0..3).map(|v| target_vote(v, 1, genesis.root)).collect();
        let justified = state_transition(
            &ChainState::initial(genesis, 4),
            block(1, 4),
            &votes,
            &params,
            &electorate,
        );
        let finality: Vec<_> = (0..3)
            .map(|v| Attestation {
                validator: v,
                data: AttestationData::new(
                    1,
                    Some(H256([1; 32])),
                    None,
                    Some(FinalityVote {
                        height: 1,
                        target: genesis.root,
                    }),
                ),
            })
            .collect();
        let finalized = state_transition(&justified, block(2, 8), &finality, &params, &electorate);
        assert_eq!(finalized.finalized, genesis);
        assert_eq!(finalized.finalized_height, 1);
    }

    #[test]
    fn timeouts_wait_for_the_delay() {
        let params = Params::with_round_length(3);
        let electorate = Electorate::uniform(4);
        let genesis = block(0, 0);
        let state = ChainState::initial(genesis, 4);
        let timeouts: Vec<_> = (0..3)
            .map(|v| Attestation {
                validator: v,
                data: AttestationData::new(
                    0,
                    Some(genesis.root),
                    Some(HeightVote {
                        height: 1,
                        entry: genesis.root,
                        timeout: true,
                    }),
                    None,
                ),
            })
            .collect();
        // δ_t = 6 slots after the entry (slot 0).
        let early = state_transition(&state, block(1, 5), &timeouts, &params, &electorate);
        assert_eq!(early.height, 1);
        assert_eq!(weight_of(&early.progress, &electorate), 3);
        let late = state_transition(&early, block(2, 6), &[], &params, &electorate);
        assert_eq!(late.height, 2);
        assert_eq!(late.justified_height, 0, "a timeout never justifies");
    }

    #[test]
    fn a_pair_naming_another_entry_records_nothing() {
        let params = Params::with_round_length(3);
        let electorate = Electorate::uniform(4);
        let genesis = block(0, 0);
        let state = ChainState::initial(genesis, 4);
        let wrong: Vec<_> = (0..4).map(|v| target_vote(v, 1, H256([9; 32]))).collect();
        let next = state_transition(&state, block(1, 4), &wrong, &params, &electorate);
        assert_eq!(next.height, 1);
        assert_eq!(weight_of(&next.progress, &electorate), 0);
    }

    #[test]
    fn nonjustifiable_heights_need_debt() {
        let params = Params::with_round_length(3); // K = 5, D = 2
        assert!(!nonjustifiable(&params, 5, 3));
        assert!(nonjustifiable(&params, 5, 2));
        assert!(!nonjustifiable(&params, 6, 0));
    }
}
