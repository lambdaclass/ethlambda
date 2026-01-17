use std::path::Path;

use ethlambda_blockchain::{store::Store, SECONDS_PER_SLOT};
use ethlambda_types::{
    block::{Block, SignedBlockWithAttestation},
    primitives::TreeHash,
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
        let mut store = Store::get_forkchoice_store(anchor_state, anchor_block);

        // Step 2: Run the state transition function with the block fixture
        let signed_block: SignedBlockWithAttestation = test.signed_block_with_attestation.into();

        // Debug: print details for specific test
        if name.contains("test_proposer_signature[") && !name.contains("attester") {
            let proposer_att_data = &signed_block.message.proposer_attestation.data;
            let message_hash = proposer_att_data.tree_hash_root();
            println!("[test_proposer_signature] AttestationData tree hash: 0x{}", hex::encode(message_hash));
            println!(
                "[test_proposer_signature] Slot (epoch): {}",
                signed_block.message.proposer_attestation.data.slot
            );
            println!(
                "[test_proposer_signature] Proposer validator_id: {}",
                signed_block.message.proposer_attestation.validator_id
            );

            // Print signature bytes (first 64 bytes)
            let sig_bytes: &[u8] = signed_block.signature.proposer_signature.as_ref();
            println!(
                "[test_proposer_signature] Signature bytes (first 64): {}",
                hex::encode(&sig_bytes[..64.min(sig_bytes.len())])
            );
            println!("[test_proposer_signature] Signature total length: {}", sig_bytes.len());
        }

        // Advance time to the block's slot
        let block_time = signed_block.message.block.slot * SECONDS_PER_SLOT + genesis_time;
        store.on_tick(block_time, true);

        // Process the block (this includes signature verification)
        let result = store.on_block(signed_block);

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
    root = "../../../../ethlambda/leanSpec/fixtures/consensus/verify_signatures",
    pattern = r".*\.json"
});
