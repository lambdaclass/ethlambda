use std::time::Duration;

use ethlambda_types::block::{Block, BlockBody};
use ethlambda_types::primitives::ssz::Decode;
use ethlambda_types::state::{State, Validator};
use reqwest::Client;

const CHECKPOINT_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_STATE_SIZE: u64 = 100 * 1024 * 1024; // 100 MB limit

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
pub async fn fetch_checkpoint_state(base_url: &str) -> Result<State, CheckpointSyncError> {
    let url = format!(
        "{}/lean/v0/states/finalized",
        base_url.trim_end_matches('/')
    );
    let client = Client::builder().timeout(CHECKPOINT_TIMEOUT).build()?;

    let response = client
        .get(&url)
        .header("Accept", "application/octet-stream")
        .send()
        .await?
        .error_for_status()?;

    // DoS protection: Check Content-Length before reading
    if let Some(content_length) = response.content_length()
        && content_length > MAX_STATE_SIZE
    {
        return Err(CheckpointSyncError::Verification(format!(
            "state too large: {} bytes (max {})",
            content_length, MAX_STATE_SIZE
        )));
    }

    let bytes = response.bytes().await?;
    if bytes.len() as u64 > MAX_STATE_SIZE {
        return Err(CheckpointSyncError::Verification(
            "state exceeds size limit".into(),
        ));
    }

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

    // Block header slot consistency
    if state.latest_block_header.slot > state.slot {
        return Err(CheckpointSyncError::Verification(
            "block header slot exceeds state slot".into(),
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
        let extra_validators = vec![create_test_validator(), create_test_validator()];
        assert!(verify_checkpoint_state(&state, 1000, &extra_validators).is_err());
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
    fn verify_rejects_block_header_slot_exceeds_state() {
        let validators = vec![create_test_validator()];
        let mut state = create_test_state(100, validators.clone(), 1000);
        state.latest_block_header.slot = 101; // Block header slot exceeds state slot
        assert!(verify_checkpoint_state(&state, 1000, &validators).is_err());
    }

    #[test]
    fn construct_anchor_block_copies_header_fields() {
        let validators = vec![create_test_validator()];
        let state = create_test_state(100, validators, 1000);
        let block = construct_anchor_block(&state);
        assert_eq!(block.slot, state.latest_block_header.slot);
        assert_eq!(block.parent_root, state.latest_block_header.parent_root);
        assert_eq!(
            block.proposer_index,
            state.latest_block_header.proposer_index
        );
        assert_eq!(block.state_root, state.latest_block_header.state_root);
    }
}
