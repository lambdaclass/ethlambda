use std::path::Path;
use std::sync::Arc;

use ethlambda_blockchain::{SECONDS_PER_SLOT, store};
use ethlambda_storage::{Store, backend::InMemoryBackend};
use ethlambda_types::{
    block::{Block, SignedBlockWithAttestation},
    primitives::ssz::TreeHash,
    state::State,
};

mod signature_types;
use signature_types::VerifySignaturesTestVector;

const SUPPORTED_FIXTURE_FORMAT: &str = "verify_signatures_test";

fn run(path: &Path) -> datatest_stable::Result<()> {
    let tests = VerifySignaturesTestVector::from_file(path)?;

    for (name, test) in tests.tests {
        if test.info.fixture_format != SUPPORTED_FIXTURE_FORMAT {
            return Err(format!(
                "Unsupported fixture format: {} (expected {})",
                test.info.fixture_format, SUPPORTED_FIXTURE_FORMAT
            )
            .into());
        }

        println!("Running test: {}", name);

        // Step 1: Populate the pre-state with the test fixture
        let anchor_state: State = test.anchor_state.into();

        // Create anchor block from the state's latest block header
        let anchor_block = Block {
            slot: anchor_state.latest_block_header.slot,
            proposer_index: anchor_state.latest_block_header.proposer_index,
            parent_root: anchor_state.latest_block_header.parent_root,
            state_root: anchor_state.tree_hash_root(),
            body: Default::default(),
        };

        // Initialize the store with the anchor state and block
        let genesis_time = anchor_state.config.genesis_time;
        let backend = Arc::new(InMemoryBackend::new());
        let mut st = Store::get_forkchoice_store(backend, anchor_state, anchor_block);

        // Step 2: Run the state transition function with the block fixture
        let signed_block: SignedBlockWithAttestation = test.signed_block_with_attestation.into();

        // Advance time to the block's slot
        let block_time_ms = (signed_block.message.block.slot * SECONDS_PER_SLOT + genesis_time) * 1000;
        store::on_tick(&mut st, block_time_ms, true, false);

        // Process the block (this includes signature verification)
        let result = store::on_block(&mut st, signed_block);

        // Step 3: Check that it succeeded or failed as expected
        match (result.is_ok(), test.expect_exception.as_ref()) {
            (true, None) => {
                // Expected success, got success
            }
            (true, Some(expected_err)) => {
                return Err(format!(
                    "Test '{}' failed: expected exception '{}' but got success",
                    name, expected_err
                )
                .into());
            }
            (false, None) => {
                return Err(format!(
                    "Test '{}' failed: expected success but got failure: {:?}",
                    name,
                    result.err()
                )
                .into());
            }
            (false, Some(_)) => {
                // Expected failure, got failure
            }
        }
    }

    Ok(())
}

datatest_stable::harness!({
    test = run,
    root = "../../../ethlambda/leanSpec/fixtures/consensus/verify_signatures",
    pattern = r".*\.json"
});
