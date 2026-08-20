use std::path::Path;
use std::sync::Arc;

use ethlambda_blockchain::{MILLISECONDS_PER_SLOT, spec_test_runner, store};
use ethlambda_storage::{Store, backend::InMemoryBackend};
use ethlambda_types::{
    block::{Block, SignedBlock},
    primitives::HashTreeRoot as _,
    state::State,
};

use ethlambda_test_fixtures::{
    rejection::check_rejection_reason, verify_signatures::VerifySignaturesTestVector,
};

const SUPPORTED_FIXTURE_FORMAT: &str = "verify_signatures_test";

/// Tests that require cryptographic signature verification at block level.
///
/// Block-level crypto verification is now wired through lean-multisig devnet5's
/// `verify_type_2`, so every fixture is exercised against the real primitive.
const SKIP_TESTS: &[&str] = &[];

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

        if SKIP_TESTS.iter().any(|skip| name.contains(skip)) {
            println!("Skipping test (Phase-3 crypto stub): {name}");
            continue;
        }

        println!("Running test: {}", name);

        // Read before the fixture is consumed field by field below.
        let expected_reason = test.rejection_reason.clone();

        // Step 1: Populate the pre-state with the test fixture
        let anchor_state: State = test.anchor_state.into();

        // Create anchor block from the state's latest block header
        let anchor_block = Block {
            slot: anchor_state.latest_block_header.slot,
            proposer_index: anchor_state.latest_block_header.proposer_index,
            parent_root: anchor_state.latest_block_header.parent_root,
            state_root: anchor_state.hash_tree_root(),
            body: Default::default(),
        };

        // Initialize the store with the anchor state and block
        let genesis_time = anchor_state.config.genesis_time;
        let backend = Arc::new(InMemoryBackend::new());
        let mut st = Store::get_forkchoice_store(backend, anchor_state, anchor_block)
            .expect("anchor state and block must match");

        // Step 2: Run the state transition function with the block fixture
        let signed_block: SignedBlock = test.signed_block.into();

        // Advance time to the block's slot
        let block_time_ms = genesis_time * 1000 + signed_block.message.slot * MILLISECONDS_PER_SLOT;
        store::on_tick(&mut st, block_time_ms, true);

        // Process the block (this includes signature verification)
        let result = store::on_block(&mut st, signed_block);

        // Step 3: Check that it succeeded or failed as expected, and that a
        // rejection is the one the fixture named rather than any failure at all.
        match (result, expected_reason.as_ref()) {
            (Ok(_), None) => {
                // Expected success, got success
            }
            (Ok(_), Some(expected)) => {
                return Err(format!(
                    "Test '{name}' failed: expected rejection {expected} but got success"
                )
                .into());
            }
            (Err(err), None) => {
                return Err(format!(
                    "Test '{name}' failed: expected success but got failure: {err:?}"
                )
                .into());
            }
            (Err(err), Some(expected)) => {
                let actual = spec_test_runner::rejection_reason(&err);
                check_rejection_reason(&name, expected, actual.as_ref(), &err)?;
            }
        }
    }

    Ok(())
}

datatest_stable::harness!({
    test = run,
    root = "../../leanSpec/fixtures/consensus/verify_signatures",
    pattern = r".*\.json"
});
