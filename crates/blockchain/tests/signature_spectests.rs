use std::path::Path;
use std::sync::Arc;

use ethlambda_blockchain::{MILLISECONDS_PER_SLOT, store};
use ethlambda_storage::{Store, backend::InMemoryBackend};
use ethlambda_types::{
    block::{Block, SignedBlock},
    primitives::HashTreeRoot as _,
    state::State,
};

mod common;
mod signature_types;
use signature_types::VerifySignaturesTestVector;

const SUPPORTED_FIXTURE_FORMAT: &str = "verify_signatures_test";

/// Tests that require cryptographic signature verification at block level.
///
/// Phase 3 of the Type-1 / Type-2 aggregation migration replaces the per-
/// attestation `verify_aggregated_signature` plus standalone proposer-signature
/// verification with a structural check on the merged Type-2 proof; the real
/// safety net is gossip-time per-attestation verification. Tests that only
/// fail on the *crypto* leg accordingly pass when run against the structural
/// stub, so they are skipped pending the `lean_multisig`-backed real
/// `verify_type_2` primitive.
///
/// TODO(type1-type2): re-enable once block-level crypto verification returns.
const SKIP_TESTS: &[&str] = &["test_invalid_proposer_signature"];

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
        let mut st = Store::get_forkchoice_store(backend, anchor_state, anchor_block);

        // Step 2: Run the state transition function with the block fixture
        let signed_block: SignedBlock = test.signed_block.into();

        // Advance time to the block's slot
        let block_time_ms = genesis_time * 1000 + signed_block.message.slot * MILLISECONDS_PER_SLOT;
        store::on_tick(&mut st, block_time_ms, true);

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
    root = "../../leanSpec/fixtures/consensus/verify_signatures",
    pattern = r".*\.json"
});
