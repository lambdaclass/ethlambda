use std::time::Duration;

use ethlambda_types::block::{Block, BlockBody};
use ethlambda_types::primitives::ssz::{Decode, TreeHash};
use ethlambda_types::state::{State, Validator};
use reqwest::Client;

/// Timeout for establishing the HTTP connection to the checkpoint peer.
/// Fail fast if the peer is unreachable.
const CHECKPOINT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Timeout for reading data during body download.
/// This is an inactivity timeout - it resets on each successful read.
const CHECKPOINT_READ_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, thiserror::Error)]
pub enum CheckpointSyncError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("SSZ deserialization failed: {0}")]
    Ssz(String),
    #[error("Verification failed: {0}")]
    Verification(String),
}

/// Fetch finalized state from checkpoint sync URL.
///
/// Uses two-phase timeout strategy:
/// - Connect timeout (15s): Fails quickly if peer is unreachable
/// - Read timeout (15s): Inactivity timeout that resets on each read
///
/// Note: We use a read timeout (via `.read_timeout()`) instead of a total download
/// timeout to automatically detect stalled downloads. This allows large states
/// to be downloaded successfully as long as data keeps flowing, while still
/// failing fast if the connection stalls. A plain total timeout would
/// disconnect even for valid downloads if the state is simply too large to
/// transfer within the time limit.
pub async fn fetch_checkpoint_state(base_url: &str) -> Result<State, CheckpointSyncError> {
    let base_url = base_url.trim_end_matches('/');
    let url = format!("{base_url}/lean/v0/states/finalized");
    // Use .read_timeout() to detect stalled downloads (inactivity timer).
    // This allows large states to complete as long as data keeps flowing.
    let client = Client::builder()
        .connect_timeout(CHECKPOINT_CONNECT_TIMEOUT)
        .read_timeout(CHECKPOINT_READ_TIMEOUT)
        .build()?;

    let response = client
        .get(&url)
        .header("Accept", "application/octet-stream")
        .send()
        .await?
        .error_for_status()?;

    let bytes = response.bytes().await?;
    State::from_ssz_bytes(&bytes).map_err(|e| CheckpointSyncError::Ssz(format!("{:?}", e)))
}

/// Verify checkpoint state is structurally valid.
///
/// Arguments:
/// - state: The downloaded checkpoint state
/// - expected_genesis_time: Genesis time from local config
/// - expected_validators: Validator pubkeys from local genesis config
pub fn verify_checkpoint_state(
    state: &State,
    expected_genesis_time: u64,
    expected_validators: &[Validator],
) -> Result<(), CheckpointSyncError> {
    // Slot sanity check
    if state.slot == 0 {
        return Err(CheckpointSyncError::Verification("slot cannot be 0".into()));
    }

    // Validators exist
    if state.validators.is_empty() {
        return Err(CheckpointSyncError::Verification("no validators".into()));
    }

    // Genesis time matches
    if state.config.genesis_time != expected_genesis_time {
        return Err(CheckpointSyncError::Verification(format!(
            "genesis time mismatch: expected {}, got {}",
            expected_genesis_time, state.config.genesis_time
        )));
    }

    // Validator count matches
    if state.validators.len() != expected_validators.len() {
        return Err(CheckpointSyncError::Verification(format!(
            "validator count mismatch: expected {}, got {}",
            expected_validators.len(),
            state.validators.len()
        )));
    }

    // Validator indices are sequential (0, 1, 2, ...)
    for (position, validator) in state.validators.iter().enumerate() {
        if validator.index != position as u64 {
            return Err(CheckpointSyncError::Verification(format!(
                "validator at position {} has index {} (expected {})",
                position, validator.index, position
            )));
        }
    }

    // Validator pubkeys match (critical security check)
    for (i, (state_val, expected_val)) in state
        .validators
        .iter()
        .zip(expected_validators.iter())
        .enumerate()
    {
        if state_val.pubkey != expected_val.pubkey {
            return Err(CheckpointSyncError::Verification(format!(
                "validator {} pubkey mismatch",
                i
            )));
        }
    }

    // Finalized slot sanity
    if state.latest_finalized.slot > state.slot {
        return Err(CheckpointSyncError::Verification(
            "finalized slot cannot exceed state slot".into(),
        ));
    }

    // Justified must be at or after finalized
    if state.latest_justified.slot < state.latest_finalized.slot {
        return Err(CheckpointSyncError::Verification(
            "justified slot cannot precede finalized slot".into(),
        ));
    }

    // If justified and finalized are at same slot, roots must match
    if state.latest_justified.slot == state.latest_finalized.slot
        && state.latest_justified.root != state.latest_finalized.root
    {
        return Err(CheckpointSyncError::Verification(
            "justified and finalized at same slot must have matching roots".into(),
        ));
    }

    // Block header slot consistency
    if state.latest_block_header.slot > state.slot {
        return Err(CheckpointSyncError::Verification(
            "block header slot exceeds state slot".into(),
        ));
    }

    // If block header matches checkpoint slots, roots must match
    let block_root = state.latest_block_header.tree_hash_root();

    if state.latest_block_header.slot == state.latest_finalized.slot
        && block_root != state.latest_finalized.root.0
    {
        return Err(CheckpointSyncError::Verification(
            "block header at finalized slot must match finalized root".into(),
        ));
    }

    if state.latest_block_header.slot == state.latest_justified.slot
        && block_root != state.latest_justified.root.0
    {
        return Err(CheckpointSyncError::Verification(
            "block header at justified slot must match justified root".into(),
        ));
    }

    Ok(())
}

/// Construct anchor block from checkpoint state.
///
/// IMPORTANT: This creates a block with default body. The block's tree_hash_root()
/// will only match the original block if the original also had an empty body.
/// For most checkpoint states, this is acceptable because fork choice uses the
/// anchor checkpoint, not individual block lookups.
pub fn construct_anchor_block(state: &State) -> Block {
    Block {
        slot: state.latest_block_header.slot,
        parent_root: state.latest_block_header.parent_root,
        proposer_index: state.latest_block_header.proposer_index,
        state_root: state.latest_block_header.state_root,
        body: BlockBody::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_types::block::BlockHeader;
    use ethlambda_types::primitives::VariableList;
    use ethlambda_types::state::{ChainConfig, Checkpoint};

    // Helper to create valid test state
    fn create_test_state(slot: u64, validators: Vec<Validator>, genesis_time: u64) -> State {
        use ethlambda_types::primitives::H256;
        use ethlambda_types::state::{JustificationValidators, JustifiedSlots};

        State {
            slot,
            validators: VariableList::new(validators).unwrap(),
            latest_block_header: BlockHeader {
                slot,
                parent_root: H256::ZERO,
                state_root: H256::ZERO,
                body_root: H256::ZERO,
                proposer_index: 0,
            },
            latest_justified: Checkpoint {
                slot: slot.saturating_sub(10),
                root: H256::ZERO,
            },
            latest_finalized: Checkpoint {
                slot: slot.saturating_sub(20),
                root: H256::ZERO,
            },
            config: ChainConfig { genesis_time },
            historical_block_hashes: Default::default(),
            justified_slots: JustifiedSlots::with_capacity(0).unwrap(),
            justifications_roots: Default::default(),
            justifications_validators: JustificationValidators::with_capacity(0).unwrap(),
        }
    }

    fn create_test_validator() -> Validator {
        Validator {
            pubkey: [1u8; 52],
            index: 0,
        }
    }

    fn create_different_validator() -> Validator {
        Validator {
            pubkey: [2u8; 52],
            index: 0,
        }
    }

    fn create_validators_with_indices(count: usize) -> Vec<Validator> {
        (0..count)
            .map(|i| Validator {
                pubkey: [i as u8 + 1; 52],
                index: i as u64,
            })
            .collect()
    }

    #[test]
    fn verify_accepts_valid_state() {
        let validators = vec![create_test_validator()];
        let state = create_test_state(100, validators.clone(), 1000);
        assert!(verify_checkpoint_state(&state, 1000, &validators).is_ok());
    }

    #[test]
    fn verify_rejects_slot_zero() {
        let validators = vec![create_test_validator()];
        let state = create_test_state(0, validators.clone(), 1000);
        assert!(verify_checkpoint_state(&state, 1000, &validators).is_err());
    }

    #[test]
    fn verify_rejects_empty_validators() {
        let state = create_test_state(100, vec![], 1000);
        assert!(verify_checkpoint_state(&state, 1000, &[]).is_err());
    }

    #[test]
    fn verify_rejects_genesis_time_mismatch() {
        let validators = vec![create_test_validator()];
        let state = create_test_state(100, validators.clone(), 1000);
        // State has genesis_time=1000, we pass expected=9999
        assert!(verify_checkpoint_state(&state, 9999, &validators).is_err());
    }

    #[test]
    fn verify_rejects_validator_count_mismatch() {
        let validators = vec![create_test_validator()];
        let state = create_test_state(100, validators.clone(), 1000);
        let extra_validators = create_validators_with_indices(2);
        assert!(verify_checkpoint_state(&state, 1000, &extra_validators).is_err());
    }

    #[test]
    fn verify_accepts_multiple_validators_with_sequential_indices() {
        let validators = create_validators_with_indices(3);
        let state = create_test_state(100, validators.clone(), 1000);
        assert!(verify_checkpoint_state(&state, 1000, &validators).is_ok());
    }

    #[test]
    fn verify_rejects_non_sequential_validator_indices() {
        let mut validators = create_validators_with_indices(3);
        validators[1].index = 5; // Wrong index at position 1
        let state = create_test_state(100, validators.clone(), 1000);
        let expected_validators = create_validators_with_indices(3);
        assert!(verify_checkpoint_state(&state, 1000, &expected_validators).is_err());
    }

    #[test]
    fn verify_rejects_duplicate_validator_indices() {
        let mut validators = create_validators_with_indices(3);
        validators[2].index = 0; // Duplicate index
        let state = create_test_state(100, validators.clone(), 1000);
        let expected_validators = create_validators_with_indices(3);
        assert!(verify_checkpoint_state(&state, 1000, &expected_validators).is_err());
    }

    #[test]
    fn verify_rejects_validator_pubkey_mismatch() {
        let validators = vec![create_test_validator()];
        let state = create_test_state(100, validators.clone(), 1000);
        let different_validators = vec![create_different_validator()];
        assert!(verify_checkpoint_state(&state, 1000, &different_validators).is_err());
    }

    #[test]
    fn verify_rejects_finalized_after_state_slot() {
        let validators = vec![create_test_validator()];
        let mut state = create_test_state(100, validators.clone(), 1000);
        state.latest_finalized.slot = 101; // Finalized after state slot
        assert!(verify_checkpoint_state(&state, 1000, &validators).is_err());
    }

    #[test]
    fn verify_rejects_justified_before_finalized() {
        let validators = vec![create_test_validator()];
        let mut state = create_test_state(100, validators.clone(), 1000);
        state.latest_finalized.slot = 50;
        state.latest_justified.slot = 40; // Justified before finalized
        assert!(verify_checkpoint_state(&state, 1000, &validators).is_err());
    }

    #[test]
    fn verify_accepts_justified_equals_finalized_with_matching_roots() {
        use ethlambda_types::primitives::H256;
        let validators = vec![create_test_validator()];
        let mut state = create_test_state(100, validators.clone(), 1000);
        let common_root = H256::from([42u8; 32]);
        state.latest_finalized.slot = 50;
        state.latest_finalized.root = common_root;
        state.latest_justified.slot = 50; // Same slot
        state.latest_justified.root = common_root; // Same root
        assert!(verify_checkpoint_state(&state, 1000, &validators).is_ok());
    }

    #[test]
    fn verify_rejects_justified_equals_finalized_with_different_roots() {
        use ethlambda_types::primitives::H256;
        let validators = vec![create_test_validator()];
        let mut state = create_test_state(100, validators.clone(), 1000);
        state.latest_finalized.slot = 50;
        state.latest_finalized.root = H256::from([1u8; 32]);
        state.latest_justified.slot = 50; // Same slot
        state.latest_justified.root = H256::from([2u8; 32]); // Different root - conflict!
        assert!(verify_checkpoint_state(&state, 1000, &validators).is_err());
    }

    #[test]
    fn verify_rejects_block_header_slot_exceeds_state() {
        let validators = vec![create_test_validator()];
        let mut state = create_test_state(100, validators.clone(), 1000);
        state.latest_block_header.slot = 101; // Block header slot exceeds state slot
        assert!(verify_checkpoint_state(&state, 1000, &validators).is_err());
    }

    #[test]
    fn verify_accepts_block_header_matches_finalized_with_correct_root() {
        let validators = vec![create_test_validator()];
        let mut state = create_test_state(100, validators.clone(), 1000);
        state.latest_block_header.slot = 50;
        let block_root = state.latest_block_header.tree_hash_root();
        state.latest_finalized.slot = 50;
        state.latest_finalized.root = block_root;
        assert!(verify_checkpoint_state(&state, 1000, &validators).is_ok());
    }

    #[test]
    fn verify_rejects_block_header_matches_finalized_with_wrong_root() {
        use ethlambda_types::primitives::H256;
        let validators = vec![create_test_validator()];
        let mut state = create_test_state(100, validators.clone(), 1000);
        state.latest_block_header.slot = 50;
        state.latest_finalized.slot = 50;
        state.latest_finalized.root = H256::from([99u8; 32]); // Wrong root
        assert!(verify_checkpoint_state(&state, 1000, &validators).is_err());
    }

    #[test]
    fn verify_accepts_block_header_matches_justified_with_correct_root() {
        let validators = vec![create_test_validator()];
        let mut state = create_test_state(100, validators.clone(), 1000);
        state.latest_block_header.slot = 90;
        let block_root = state.latest_block_header.tree_hash_root();
        state.latest_justified.slot = 90;
        state.latest_justified.root = block_root;
        assert!(verify_checkpoint_state(&state, 1000, &validators).is_ok());
    }

    #[test]
    fn verify_rejects_block_header_matches_justified_with_wrong_root() {
        use ethlambda_types::primitives::H256;
        let validators = vec![create_test_validator()];
        let mut state = create_test_state(100, validators.clone(), 1000);
        state.latest_block_header.slot = 90;
        state.latest_justified.slot = 90;
        state.latest_justified.root = H256::from([99u8; 32]); // Wrong root
        assert!(verify_checkpoint_state(&state, 1000, &validators).is_err());
    }
}
