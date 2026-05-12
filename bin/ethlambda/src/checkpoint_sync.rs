use std::time::Duration;

use ethlambda_types::block::SignedBlock;
use ethlambda_types::primitives::{H256, HashTreeRoot as _};
use ethlambda_types::state::{State, Validator};
use libssz::{DecodeError, SszDecode};
use reqwest::Client;

/// Timeout for establishing the HTTP connection to the checkpoint peer.
/// Fail fast if the peer is unreachable.
const CHECKPOINT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Timeout for reading data during body download.
/// This is an inactivity timeout - it resets on each successful read.
const CHECKPOINT_READ_TIMEOUT: Duration = Duration::from_secs(15);

/// Path of the finalized-state endpoint (relative to the peer's API base URL).
const FINALIZED_STATE_PATH: &str = "/lean/v0/states/finalized";

/// Path of the finalized-block endpoint (relative to the peer's API base URL).
const FINALIZED_BLOCK_PATH: &str = "/lean/v0/blocks/finalized";

#[derive(Debug, thiserror::Error)]
pub enum CheckpointSyncError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("SSZ deserialization failed: {0:?}")]
    SszDecode(DecodeError),
    #[error("checkpoint state slot cannot be 0")]
    SlotIsZero,
    #[error("checkpoint state has no validators")]
    NoValidators,
    #[error("genesis time mismatch: expected {expected}, got {got}")]
    GenesisTimeMismatch { expected: u64, got: u64 },
    #[error("validator count mismatch: expected {expected}, got {got}")]
    ValidatorCountMismatch { expected: usize, got: usize },
    #[error(
        "validator at position {position} has non-sequential index (expected {expected}, got {got})"
    )]
    NonSequentialValidatorIndex {
        position: usize,
        expected: u64,
        got: u64,
    },
    #[error("validator {index} pubkey mismatch (attestation or proposal key)")]
    ValidatorPubkeyMismatch { index: usize },
    #[error("finalized slot cannot exceed state slot")]
    FinalizedExceedsStateSlot,
    #[error("justified slot cannot precede finalized slot")]
    JustifiedPrecedesFinalized,
    #[error("justified and finalized at same slot must have matching roots")]
    JustifiedFinalizedRootMismatch,
    #[error("block header slot exceeds state slot")]
    BlockHeaderSlotExceedsState,
    #[error("block header at finalized slot must match finalized root")]
    BlockHeaderFinalizedRootMismatch,
    #[error("block header at justified slot must match justified root")]
    BlockHeaderJustifiedRootMismatch,
    #[error(
        "anchor block does not match anchor state: block.state_root={block_state_root}, computed state root={computed_state_root}"
    )]
    AnchorPairingMismatch {
        block_state_root: H256,
        computed_state_root: H256,
    },
}

/// Build the HTTP client used for checkpoint sync fetches.
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
fn build_client() -> Result<Client, CheckpointSyncError> {
    Ok(Client::builder()
        .connect_timeout(CHECKPOINT_CONNECT_TIMEOUT)
        .read_timeout(CHECKPOINT_READ_TIMEOUT)
        .build()?)
}

/// Fetch and SSZ-decode an `application/octet-stream` body from `url`.
async fn fetch_ssz<T: SszDecode>(client: &Client, url: &str) -> Result<T, CheckpointSyncError> {
    let bytes = client
        .get(url)
        .header("Accept", "application/octet-stream")
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    T::from_ssz_bytes(&bytes).map_err(CheckpointSyncError::SszDecode)
}

/// Normalize a checkpoint-sync URL to a base URL.
///
/// Operators historically pass the full state URL (e.g.
/// `http://peer:5052/lean/v0/states/finalized`) via `--checkpoint-sync-url`.
/// The new contract is a base URL (`http://peer:5052`) so we can derive both
/// the state and block endpoints. To avoid breaking existing devnet scripts,
/// strip a trailing legacy path if present and also trim any trailing slash.
fn normalize_base_url(url: &str) -> &str {
    url.strip_suffix(FINALIZED_STATE_PATH)
        .unwrap_or(url)
        .trim_end_matches('/')
}

/// Fetch the finalized state from a checkpoint peer and verify it
/// against the local genesis configuration.
pub async fn fetch_finalized_state(
    client: &Client,
    base_url: &str,
    expected_genesis_time: u64,
    expected_validators: &[Validator],
) -> Result<State, CheckpointSyncError> {
    let url = format!("{base_url}{FINALIZED_STATE_PATH}");
    let state: State = fetch_ssz(client, &url).await?;
    verify_checkpoint_state(&state, expected_genesis_time, expected_validators)?;
    Ok(state)
}

/// Fetch the finalized signed block from a checkpoint peer.
///
/// Unlike the state, the block is not validated standalone here — pairing
/// against the finalized state is enforced by [`fetch_finalized_anchor`].
pub async fn fetch_finalized_block(
    client: &Client,
    base_url: &str,
) -> Result<SignedBlock, CheckpointSyncError> {
    let url = format!("{base_url}{FINALIZED_BLOCK_PATH}");
    fetch_ssz(client, &url).await
}

/// Fetch the finalized state and signed block in parallel and verify they pair.
///
/// Pairing is the spec assertion that `signed_block.message.state_root` equals
/// `hash_tree_root(state)` after the state has been canonicalized (i.e. with
/// `latest_block_header.state_root` zeroed, mirroring what the peer serves on
/// `/lean/v0/states/finalized`).
///
/// If the peer advances finalization between the two requests the pairing will
/// not hold; the caller is expected to retry.
pub async fn fetch_finalized_anchor(
    url: &str,
    expected_genesis_time: u64,
    expected_validators: &[Validator],
) -> Result<(State, SignedBlock), CheckpointSyncError> {
    let base_url = normalize_base_url(url);
    let client = build_client()?;

    // Issue both fetches concurrently; either failure cancels the pair.
    let (state, signed_block) = tokio::try_join!(
        fetch_finalized_state(
            &client,
            base_url,
            expected_genesis_time,
            expected_validators
        ),
        fetch_finalized_block(&client, base_url),
    )?;

    verify_anchor_pairing(&state, &signed_block)?;

    Ok((state, signed_block))
}

/// Verify that the signed block's `state_root` matches the canonical hash
/// of the state served by `/lean/v0/states/finalized`.
///
/// The state served by that endpoint has `latest_block_header.state_root`
/// zeroed so that the resulting `hash_tree_root` is stable across the
/// chicken-and-egg between header and state root. We must match the same
/// canonical form when hashing locally.
fn verify_anchor_pairing(
    state: &State,
    signed_block: &SignedBlock,
) -> Result<(), CheckpointSyncError> {
    let mut canonical = state.clone();
    canonical.latest_block_header.state_root = H256::ZERO;
    let computed_state_root = canonical.hash_tree_root();

    if signed_block.message.state_root != computed_state_root {
        return Err(CheckpointSyncError::AnchorPairingMismatch {
            block_state_root: signed_block.message.state_root,
            computed_state_root,
        });
    }

    Ok(())
}

/// Verify checkpoint state is structurally valid.
///
/// Arguments:
/// - state: The downloaded checkpoint state
/// - expected_genesis_time: Genesis time from local config
/// - expected_validators: Validator pubkeys from local genesis config
fn verify_checkpoint_state(
    state: &State,
    expected_genesis_time: u64,
    expected_validators: &[Validator],
) -> Result<(), CheckpointSyncError> {
    // Slot sanity check
    if state.slot == 0 {
        return Err(CheckpointSyncError::SlotIsZero);
    }

    // Validators exist
    if state.validators.is_empty() {
        return Err(CheckpointSyncError::NoValidators);
    }

    // Genesis time matches
    if state.config.genesis_time != expected_genesis_time {
        return Err(CheckpointSyncError::GenesisTimeMismatch {
            expected: expected_genesis_time,
            got: state.config.genesis_time,
        });
    }

    // Validator count matches
    if state.validators.len() != expected_validators.len() {
        return Err(CheckpointSyncError::ValidatorCountMismatch {
            expected: expected_validators.len(),
            got: state.validators.len(),
        });
    }

    // Validator indices are sequential (0, 1, 2, ...)
    for (position, validator) in state.validators.iter().enumerate() {
        if validator.index != position as u64 {
            return Err(CheckpointSyncError::NonSequentialValidatorIndex {
                position,
                expected: position as u64,
                got: validator.index,
            });
        }
    }

    // Validator pubkeys match (critical security check)
    for (i, (state_val, expected_val)) in state
        .validators
        .iter()
        .zip(expected_validators.iter())
        .enumerate()
    {
        if state_val.attestation_pubkey != expected_val.attestation_pubkey
            || state_val.proposal_pubkey != expected_val.proposal_pubkey
        {
            return Err(CheckpointSyncError::ValidatorPubkeyMismatch { index: i });
        }
    }

    // Finalized slot sanity
    if state.latest_finalized.slot > state.slot {
        return Err(CheckpointSyncError::FinalizedExceedsStateSlot);
    }

    // Justified must be at or after finalized
    if state.latest_justified.slot < state.latest_finalized.slot {
        return Err(CheckpointSyncError::JustifiedPrecedesFinalized);
    }

    // If justified and finalized are at same slot, roots must match
    if state.latest_justified.slot == state.latest_finalized.slot
        && state.latest_justified.root != state.latest_finalized.root
    {
        return Err(CheckpointSyncError::JustifiedFinalizedRootMismatch);
    }

    // Block header slot consistency
    if state.latest_block_header.slot > state.slot {
        return Err(CheckpointSyncError::BlockHeaderSlotExceedsState);
    }

    // If block header matches checkpoint slots, roots must match
    let block_root = state.latest_block_header.hash_tree_root();

    if state.latest_block_header.slot == state.latest_finalized.slot
        && block_root != state.latest_finalized.root
    {
        return Err(CheckpointSyncError::BlockHeaderFinalizedRootMismatch);
    }

    if state.latest_block_header.slot == state.latest_justified.slot
        && block_root != state.latest_justified.root
    {
        return Err(CheckpointSyncError::BlockHeaderJustifiedRootMismatch);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_types::block::BlockHeader;
    use ethlambda_types::checkpoint::Checkpoint;
    use ethlambda_types::primitives::H256;
    use ethlambda_types::state::{ChainConfig, JustificationValidators, JustifiedSlots};
    use libssz_types::SszList;

    // Helper to create valid test state
    fn create_test_state(slot: u64, validators: Vec<Validator>, genesis_time: u64) -> State {
        State {
            slot,
            validators: SszList::try_from(validators).unwrap(),
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
            justified_slots: JustifiedSlots::new(),
            justifications_roots: Default::default(),
            justifications_validators: JustificationValidators::new(),
        }
    }

    fn create_test_validator() -> Validator {
        Validator {
            attestation_pubkey: [1u8; 52],
            proposal_pubkey: [11u8; 52],
            index: 0,
        }
    }

    fn create_different_validator() -> Validator {
        Validator {
            attestation_pubkey: [2u8; 52],
            proposal_pubkey: [22u8; 52],
            index: 0,
        }
    }

    fn create_validators_with_indices(count: usize) -> Vec<Validator> {
        (0..count)
            .map(|i| Validator {
                attestation_pubkey: [i as u8 + 1; 52],
                proposal_pubkey: [i as u8 + 101; 52],
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
        let block_root = state.latest_block_header.hash_tree_root();
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
        let block_root = state.latest_block_header.hash_tree_root();
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

    // --- normalize_base_url ---

    #[test]
    fn normalize_strips_legacy_state_path() {
        assert_eq!(
            normalize_base_url("http://peer:5052/lean/v0/states/finalized"),
            "http://peer:5052"
        );
    }

    #[test]
    fn normalize_passes_through_base_url() {
        assert_eq!(normalize_base_url("http://peer:5052"), "http://peer:5052");
    }

    #[test]
    fn normalize_strips_trailing_slash() {
        assert_eq!(normalize_base_url("http://peer:5052/"), "http://peer:5052");
    }

    // --- verify_anchor_pairing ---

    /// Build a SignedBlock whose header matches `state.latest_block_header`
    /// (with the canonical zero state_root) and whose state_root is
    /// `state_root_field`.
    fn build_signed_block_for(state: &State, state_root_field: H256) -> SignedBlock {
        use ethlambda_types::attestation::XmssSignature;
        use ethlambda_types::block::{Block, BlockBody, BlockSignatures, SignedBlock};
        use ethlambda_types::signature::SIGNATURE_SIZE;

        let header = &state.latest_block_header;
        let block = Block {
            slot: header.slot,
            proposer_index: header.proposer_index,
            parent_root: header.parent_root,
            state_root: state_root_field,
            body: BlockBody::default(),
        };
        SignedBlock {
            message: block,
            signature: BlockSignatures {
                attestation_signatures: Default::default(),
                proposer_signature: XmssSignature::try_from(vec![0u8; SIGNATURE_SIZE]).unwrap(),
            },
        }
    }

    /// Compute the canonical state root the way `/lean/v0/states/finalized`
    /// serves it: with `latest_block_header.state_root` zeroed.
    fn canonical_state_root(state: &State) -> H256 {
        let mut clone = state.clone();
        clone.latest_block_header.state_root = H256::ZERO;
        clone.hash_tree_root()
    }

    #[test]
    fn pairing_accepts_matching_state_root() {
        let validators = vec![create_test_validator()];
        let mut state = create_test_state(100, validators, 1000);
        // Match the body_root in the header to BlockBody::default(), so the
        // signed block we build below shares the same header shape.
        use ethlambda_types::block::BlockBody;
        state.latest_block_header.body_root = BlockBody::default().hash_tree_root();
        let expected = canonical_state_root(&state);
        let signed_block = build_signed_block_for(&state, expected);

        assert!(verify_anchor_pairing(&state, &signed_block).is_ok());
    }

    #[test]
    fn pairing_rejects_mismatched_state_root() {
        let validators = vec![create_test_validator()];
        let state = create_test_state(100, validators, 1000);
        // Use a bogus state_root in the block.
        let signed_block = build_signed_block_for(&state, H256::from([0xaau8; 32]));

        let err = verify_anchor_pairing(&state, &signed_block).unwrap_err();
        assert!(matches!(
            err,
            CheckpointSyncError::AnchorPairingMismatch { .. }
        ));
    }

    #[test]
    fn pairing_independent_of_state_root_field_in_header() {
        // The pairing check zeroes latest_block_header.state_root before
        // hashing, so the same block must pair regardless of whatever value
        // was already stored there.
        let validators = vec![create_test_validator()];
        let mut state = create_test_state(100, validators, 1000);
        use ethlambda_types::block::BlockBody;
        state.latest_block_header.body_root = BlockBody::default().hash_tree_root();
        let canonical = canonical_state_root(&state);
        let signed_block = build_signed_block_for(&state, canonical);

        // Inject a non-zero state_root into the header: must still verify.
        state.latest_block_header.state_root = H256::from([0xffu8; 32]);
        assert!(verify_anchor_pairing(&state, &signed_block).is_ok());
    }
}
