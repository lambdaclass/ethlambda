//! Deterministic mock chain for driving the zkVM prover end-to-end without a live
//! node or the spec-fixtures (similiar to zeam's)

use ethlambda_state_transition::{process_block, process_slots};
use ethlambda_types::{
    attestation::{AggregatedAttestation, AggregationBits, AttestationData},
    block::{Block, BlockBody},
    checkpoint::Checkpoint,
    primitives::{H256, HashTreeRoot as _},
    state::{State, Validator},
};

use crate::StfInput;

pub struct MockTransition {
    pub input: StfInput,
    pub pre_state_root: H256,
    pub block_root: H256,
    pub post_state_root: H256,
    pub justified_slot: u64,
    pub finalized_slot: u64,
}

/// Build a chain of transitions(includes attestations) from 
/// genesis with dummy validators. Guarantees the state transition 
/// is accurate and (for `num_blocks >= 2`) that the 
/// justification/finalization advance across the chain.
pub fn gen_mock_chain(num_blocks: u64, num_validators: u64) -> Vec<MockTransition> {
    assert!(num_validators > 0, "need at least one validator");

    let validators = (0..num_validators)
        .map(|index| Validator {
            attestation_pubkey: [0u8; 52],
            proposal_pubkey: [0u8; 52],
            index,
        })
        .collect();
    let mut state = State::from_genesis(0, validators);

    let mut chain = Vec::with_capacity(num_blocks as usize);
    for slot in 1..=num_blocks {
        // parent_root as `process_slots` will leave it: prior header, state_root sealed.
        // This is the header root recorded in `historical_block_hashes`, so votes
        // that reference it match the chain.
        let mut parent_header = state.latest_block_header.clone();
        parent_header.state_root = state.hash_tree_root();
        let parent_root = parent_header.hash_tree_root();

        // From the second block on, every validator votes the parent as target
        // (source = the current latest justified checkpoint). Both roots already
        // live in `historical_block_hashes`, so the votes are valid and the 2/3
        // threshold is crossed, justifying the parent.
        let attestations: Vec<AggregatedAttestation> = if slot >= 2 {
            let target = Checkpoint {
                slot: slot - 1,
                root: parent_root,
            };
            vec![AggregatedAttestation {
                aggregation_bits: all_validators_bits(num_validators),
                data: AttestationData {
                    slot: slot - 1,
                    head: target,
                    target,
                    source: state.latest_justified,
                },
            }]
        } else {
            Vec::new()
        };
        let body = BlockBody {
            attestations: attestations
                .try_into()
                .expect("attestation count within block limit"),
        };

        let mut block = Block {
            slot,
            proposer_index: slot % num_validators, // round-robin
            parent_root,
            state_root: H256::ZERO,
            body,
        };

        // Seal `state_root` by running the transition on a scratch copy
        // (`process_block` does not check state_root; only the `state_transition`
        // wrapper does). This also advances justification/finalization.
        let mut scratch = state.clone();
        process_slots(&mut scratch, slot).expect("process_slots");
        process_block(&mut scratch, &block).expect("process_block");
        block.state_root = scratch.hash_tree_root();

        chain.push(MockTransition {
            pre_state_root: state.hash_tree_root(),
            block_root: block.hash_tree_root(),
            post_state_root: block.state_root,
            justified_slot: scratch.latest_justified.slot,
            finalized_slot: scratch.latest_finalized.slot,
            input: StfInput::new(state.clone(), block),
        });
        
        // advance real state for the next block
        state = scratch; 
    }
    chain
}

/// An `AggregationBits` with every validator's bit set.
fn all_validators_bits(num_validators: u64) -> AggregationBits {
    let n = num_validators as usize;
    let mut bits = AggregationBits::with_length(n).expect("valid bitlist length");
    for i in 0..n {
        bits.set(i, true).expect("in-bounds bit");
    }
    bits
}
