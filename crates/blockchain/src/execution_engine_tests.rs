//! Mock-EL tests for the actor's execution-layer hooks (`el_integration`).
//!
//! Lives in its own file so the EL integration keeps its footprint out of
//! the core actor in `lib.rs`. `use super::*` resolves to the crate root,
//! same as when this was an inline `mod`.

use super::*;
use crate::key_manager::KeyManager;
use ethlambda_ethrex_client::{
    EngineClientError, ForkChoiceState, ForkChoiceUpdatedResponse, PayloadAttributesV3,
    PayloadStatus, PayloadStatusKind,
};
use ethlambda_storage::backend::InMemoryBackend;
use ethlambda_types::attestation::blank_xmss_signature;
use ethlambda_types::block::{AttestationSignatures, Block, BlockBody};
use ethlambda_types::state::State;

/// Outcome the mock EL returns from `new_payload`, covering both the
/// EL's typed verdicts and a non-fatal roundtrip failure.
enum NewPayloadOutcome {
    Status(PayloadStatusKind),
    Error,
}

/// Mock execution engine. `forkchoice_updated_v3` and `get_payload`
/// return innocuous defaults; only `new_payload` is configurable since
/// that is the call whose verdict gates block import. The
/// `parent_beacon_block_root` passed to `new_payload` is recorded so
/// tests can assert the lean-parent-root convention.
struct MockEngine {
    new_payload: NewPayloadOutcome,
    seen_beacon_root: std::sync::Mutex<Option<H256>>,
}

fn ok_status(status: PayloadStatusKind) -> PayloadStatus {
    PayloadStatus {
        status,
        latest_valid_hash: None,
        validation_error: None,
    }
}

#[async_trait::async_trait]
impl ExecutionEngine for MockEngine {
    async fn forkchoice_updated_v3(
        &self,
        _state: ForkChoiceState,
        _payload_attributes: Option<PayloadAttributesV3>,
    ) -> Result<ForkChoiceUpdatedResponse, EngineClientError> {
        Ok(ForkChoiceUpdatedResponse {
            payload_status: ok_status(PayloadStatusKind::Valid),
            payload_id: None,
        })
    }

    async fn get_payload(
        &self,
        _payload_id: PayloadId,
    ) -> Result<ExecutionPayloadV3, EngineClientError> {
        Ok(ExecutionPayloadV3::default())
    }

    async fn new_payload(
        &self,
        _payload: &ExecutionPayloadV3,
        parent_beacon_block_root: H256,
    ) -> Result<PayloadStatus, EngineClientError> {
        *self.seen_beacon_root.lock().unwrap() = Some(parent_beacon_block_root);
        match &self.new_payload {
            NewPayloadOutcome::Status(kind) => Ok(ok_status(*kind)),
            NewPayloadOutcome::Error => Err(EngineClientError::EmptyResponse),
        }
    }
}

fn mock(outcome: NewPayloadOutcome) -> Arc<MockEngine> {
    Arc::new(MockEngine {
        new_payload: outcome,
        seen_beacon_root: std::sync::Mutex::new(None),
    })
}

fn test_store() -> Store {
    let genesis_state = State::from_genesis(1000, vec![]);
    let backend = Arc::new(InMemoryBackend::new());
    Store::from_anchor_state(backend, genesis_state)
}

fn test_server(store: Store, engine: Option<Arc<dyn ExecutionEngine>>) -> BlockChainServer {
    BlockChainServer {
        store,
        p2p: None,
        key_manager: KeyManager::new(HashMap::new()),
        pending_blocks: HashMap::new(),
        pending_block_parents: HashMap::new(),
        aggregator: AggregatorController::new(false),
        current_aggregation: None,
        last_tick_instant: None,
        attestation_committee_count: 1,
        pre_merge_coverage: None,
        execution_client: engine,
        suggested_fee_recipient: [0u8; 20],
        pending_payload_id: None,
    }
}

/// Insert a block whose execution payload carries `block_hash`, so
/// `el_hash_at` has a real (non-zero) value to resolve.
fn insert_block_with_payload_hash(
    store: &mut Store,
    root: H256,
    slot: u64,
    parent_root: H256,
    block_hash: H256,
) {
    let signed_block = SignedBlock {
        message: Block {
            slot,
            proposer_index: 0,
            parent_root,
            state_root: H256::ZERO,
            body: BlockBody {
                attestations: Default::default(),
                execution_payload: ExecutionPayloadV3 {
                    block_hash,
                    ..Default::default()
                },
            },
        },
        signature: BlockSignatures {
            attestation_signatures: AttestationSignatures::try_from(vec![]).unwrap(),
            proposer_signature: blank_xmss_signature(),
        },
    };
    store.insert_signed_block(root, signed_block);
}

#[tokio::test]
async fn validate_payload_rejects_invalid_verdict() {
    for verdict in [
        PayloadStatusKind::Invalid,
        PayloadStatusKind::InvalidBlockHash,
    ] {
        let server = test_server(test_store(), Some(mock(NewPayloadOutcome::Status(verdict))));
        let accepted = server
            .validate_payload_with_el(&ExecutionPayloadV3::default(), H256::ZERO)
            .await;
        assert!(!accepted, "EL verdict {verdict:?} must drop the block");
    }
}

#[tokio::test]
async fn validate_payload_accepts_non_invalid_verdicts() {
    for verdict in [
        PayloadStatusKind::Valid,
        PayloadStatusKind::Syncing,
        PayloadStatusKind::Accepted,
    ] {
        let server = test_server(test_store(), Some(mock(NewPayloadOutcome::Status(verdict))));
        let accepted = server
            .validate_payload_with_el(&ExecutionPayloadV3::default(), H256::ZERO)
            .await;
        assert!(
            accepted,
            "EL verdict {verdict:?} must let the block proceed"
        );
    }
}

#[tokio::test]
async fn validate_payload_is_permissive_on_el_roundtrip_failure() {
    // A failed EL roundtrip must not block consensus: import proceeds.
    let server = test_server(test_store(), Some(mock(NewPayloadOutcome::Error)));
    let accepted = server
        .validate_payload_with_el(&ExecutionPayloadV3::default(), H256::ZERO)
        .await;
    assert!(accepted, "EL roundtrip failure must be permissive");
}

#[tokio::test]
async fn validate_payload_accepts_when_no_el_configured() {
    let server = test_server(test_store(), None);
    let accepted = server
        .validate_payload_with_el(&ExecutionPayloadV3::default(), H256::ZERO)
        .await;
    assert!(accepted, "no EL configured must always accept");
}

#[tokio::test]
async fn validate_payload_passes_parent_root_as_beacon_root() {
    // The lean-parent-root convention: whatever the caller resolves as the
    // block's parent_root must reach the EL verbatim as
    // parent_beacon_block_root.
    let engine = mock(NewPayloadOutcome::Status(PayloadStatusKind::Valid));
    let server = test_server(test_store(), Some(engine.clone()));

    let parent_root = H256([0x42; 32]);
    let accepted = server
        .validate_payload_with_el(&ExecutionPayloadV3::default(), parent_root)
        .await;

    assert!(accepted);
    assert_eq!(*engine.seen_beacon_root.lock().unwrap(), Some(parent_root));
}

#[tokio::test]
async fn take_prepared_payload_discards_on_head_change() {
    // Stash a payload_id built on a head that no longer matches the
    // store's: the id must be discarded (caller falls back to synthetic).
    let engine = mock(NewPayloadOutcome::Status(PayloadStatusKind::Valid));
    let store = test_store();
    let mut server = test_server(store, Some(engine));

    let stale_root = H256([0x77; 32]);
    assert_ne!(stale_root, server.store.head());
    server.pending_payload_id = Some((5, stale_root, PayloadId([7u8; 8])));

    assert!(server.take_prepared_payload(5).await.is_none());
    assert!(
        server.pending_payload_id.is_none(),
        "stash must be consumed"
    );
}

#[tokio::test]
async fn take_prepared_payload_fetches_when_head_unchanged() {
    // Happy path: slot and build-head both match → the EL payload is
    // fetched and returned.
    let engine = mock(NewPayloadOutcome::Status(PayloadStatusKind::Valid));
    let store = test_store();
    let head_root = store.head();
    let mut server = test_server(store, Some(engine));
    server.pending_payload_id = Some((5, head_root, PayloadId([7u8; 8])));

    assert!(server.take_prepared_payload(5).await.is_some());
}

#[tokio::test]
async fn take_prepared_payload_discards_on_slot_mismatch() {
    let engine = mock(NewPayloadOutcome::Status(PayloadStatusKind::Valid));
    let store = test_store();
    let head_root = store.head();
    let mut server = test_server(store, Some(engine));
    server.pending_payload_id = Some((5, head_root, PayloadId([7u8; 8])));

    assert!(server.take_prepared_payload(6).await.is_none());
    assert!(
        server.pending_payload_id.is_none(),
        "stash must be consumed"
    );
}

#[test]
fn el_hash_at_resolves_real_payload_hash_after_block_import() {
    let mut store = test_store();
    let genesis_root = store.head();
    let block_root = H256([1u8; 32]);
    let payload_hash = H256([0xAB; 32]);
    insert_block_with_payload_hash(&mut store, block_root, 1, genesis_root, payload_hash);

    let server = test_server(store, None);

    // After import the EL hash is the block's real payload block_hash...
    assert_eq!(server.el_hash_at(block_root), payload_hash);
    // ...while the zero root and unknown roots fall back to ZERO.
    assert_eq!(server.el_hash_at(H256::ZERO), H256::ZERO);
    assert_eq!(server.el_hash_at(H256([0x99; 32])), H256::ZERO);
}
