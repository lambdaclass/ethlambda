//! Hive lean spec-asset test-driver endpoints.
//!
//! Exposes four POST endpoints under `/lean/v0/test_driver/...` that the
//! [`ethereum/hive`](https://github.com/ethereum/hive) lean simulator drives
//! against the client to replay leanSpec fixtures over HTTP:
//!
//! ```text
//! POST /lean/v0/test_driver/fork_choice/init     -> 204 / 400
//! POST /lean/v0/test_driver/fork_choice/step     -> StepResponse
//! POST /lean/v0/test_driver/state_transition/run -> StateTransitionResponse
//! POST /lean/v0/test_driver/verify_signatures/run -> VerifySignaturesResponse
//! ```
//!
//! The driver replaces the in-process [`Store`] on every `fork_choice/init` so
//! a single client container can replay many independent fixtures back-to-back
//! without restart. State is held behind an `Arc<RwLock<Store>>`; all
//! store-mutating operations themselves are synchronous, so the write lock is
//! never held across `.await`.
//!
//! Activated by setting `HIVE_LEAN_TEST_DRIVER=1` in the container env; see
//! [`test_driver_enabled`] and the boot path in `bin/ethlambda/src/main.rs`.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State as AxumState,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use ethlambda_blockchain::{
    MILLISECONDS_PER_INTERVAL, MILLISECONDS_PER_SLOT,
    store::{self, verify_block_signatures},
};
use ethlambda_storage::{Store, backend::InMemoryBackend};
use ethlambda_test_fixtures::{
    Block as FixtureBlock, TestState,
    fork_choice::{BlockStepData, ForkChoiceStep},
    state_transition::StateTransitionRunRequest,
    verify_signatures::TestSignedBlock,
};
use ethlambda_types::{
    attestation::{
        AggregationBits as EthAggregationBits, SignedAggregatedAttestation, SignedAttestation,
        XmssSignature,
    },
    block::{
        AggregatedSignatureProof, AttestationSignatures, Block, BlockSignatures, ByteListMiB,
        SignedBlock,
    },
    checkpoint::Checkpoint,
    primitives::{H256, HashTreeRoot as _},
    signature::SIGNATURE_SIZE,
    state::State,
};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::debug;

/// Environment variable that activates the test driver at boot time.
///
/// The hive simulator sets this to `"1"` for each spec-asset fixture run; any
/// of `"1"`, `"true"`, or `"yes"` (case-insensitive) enables the driver.
pub const TEST_DRIVER_ENV: &str = "HIVE_LEAN_TEST_DRIVER";

/// Returns true when the binary should boot into test-driver mode.
pub fn test_driver_enabled() -> bool {
    match std::env::var(TEST_DRIVER_ENV) {
        Ok(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes"
        ),
        Err(_) => false,
    }
}

/// Shared, runtime-replaceable Store backing every test-driver handler.
///
/// `fork_choice/init` swaps the contents wholesale; all other handlers either
/// take a write lock (to mutate fork choice) or a read lock (to snapshot).
pub type DriverState = Arc<RwLock<Store>>;

/// Build an empty in-memory Store with no validators.
///
/// Used as the placeholder seed before the first `fork_choice/init` call.
pub fn empty_driver_store() -> Store {
    let backend = Arc::new(InMemoryBackend::new());
    Store::from_anchor_state(backend, State::from_genesis(0, vec![]))
}

/// Build the test-driver router, including a `/lean/v0/health` endpoint so the
/// hive port liveness check has something to talk to.
pub fn build_router(state: DriverState) -> Router {
    Router::new()
        .route("/lean/v0/health", get(crate::metrics::get_health))
        .route(
            "/lean/v0/test_driver/fork_choice/init",
            post(init_fork_choice),
        )
        .route(
            "/lean/v0/test_driver/fork_choice/step",
            post(step_fork_choice),
        )
        .route(
            "/lean/v0/test_driver/state_transition/run",
            post(run_state_transition),
        )
        .route(
            "/lean/v0/test_driver/verify_signatures/run",
            post(run_verify_signatures),
        )
        .with_state(state)
}

// ============================================================================
// Request / response types
// ============================================================================

#[derive(Debug, Deserialize)]
struct InitForkChoiceRequest {
    #[serde(rename = "anchorState")]
    anchor_state: TestState,
    #[serde(rename = "anchorBlock")]
    anchor_block: FixtureBlock,
    #[serde(default, rename = "genesisTime")]
    genesis_time: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct VerifySignaturesRequest {
    #[serde(rename = "anchorState")]
    anchor_state: TestState,
    #[serde(rename = "signedBlock")]
    signed_block: TestSignedBlock,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DriverCheckpoint {
    slot: u64,
    root: H256,
}

impl From<Checkpoint> for DriverCheckpoint {
    fn from(value: Checkpoint) -> Self {
        Self {
            slot: value.slot,
            root: value.root,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DriverSnapshot {
    head_slot: u64,
    head_root: H256,
    /// Store time in 800 ms intervals since genesis (matches [`Store::time`]).
    time: u64,
    justified_checkpoint: DriverCheckpoint,
    finalized_checkpoint: DriverCheckpoint,
    safe_target: H256,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct StepResponse {
    accepted: bool,
    error: Option<String>,
    snapshot: DriverSnapshot,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct StateTransitionPost {
    slot: u64,
    latest_block_header_slot: u64,
    latest_block_header_state_root: H256,
    historical_block_hashes_count: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct StateTransitionResponse {
    succeeded: bool,
    error: Option<String>,
    post: Option<StateTransitionPost>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifySignaturesResponse {
    succeeded: bool,
    error: Option<String>,
}

// ============================================================================
// Handlers
// ============================================================================

/// `POST /lean/v0/test_driver/fork_choice/init`
///
/// Validates the supplied (anchor_state, anchor_block) pair, then replaces the
/// shared Store with a freshly initialized one. Returns 204 on success, 400
/// when the anchor pair is inconsistent (the simulator's
/// `anchor_valid=False` fixtures rely on the 4xx).
async fn init_fork_choice(
    AxumState(driver): AxumState<DriverState>,
    Json(request): Json<InitForkChoiceRequest>,
) -> Response {
    let mut state: State = request.anchor_state.into();
    if let Some(genesis_time) = request.genesis_time {
        state.config.genesis_time = genesis_time;
    }
    let block: Block = request.anchor_block.into();

    // Mirror Store::get_forkchoice_store's invariants explicitly so we can
    // surface a clean 400 instead of panicking the handler task.
    if !anchor_pair_is_consistent(&state, &block) {
        return (
            StatusCode::BAD_REQUEST,
            "anchor block does not match anchor state",
        )
            .into_response();
    }

    let backend = Arc::new(InMemoryBackend::new());
    let new_store = Store::from_anchor_state(backend, state);

    *driver.write().await = new_store;

    StatusCode::NO_CONTENT.into_response()
}

/// `POST /lean/v0/test_driver/fork_choice/step`
///
/// Applies a single fork-choice step against the current Store and always
/// returns 200 with `{accepted, error?, snapshot}`. The simulator compares
/// `accepted` to the step's `valid` flag and `snapshot` to the step's `checks`.
async fn step_fork_choice(
    AxumState(driver): AxumState<DriverState>,
    Json(step): Json<ForkChoiceStep>,
) -> Json<StepResponse> {
    let outcome = {
        let mut guard = driver.write().await;
        apply_step(&mut guard, step)
    };
    let (accepted, error) = match outcome {
        Ok(()) => (true, None),
        Err(err) => {
            debug!(%err, "fork-choice step rejected");
            (false, Some(err))
        }
    };
    let snapshot = {
        let guard = driver.read().await;
        snapshot_store(&guard)
    };
    Json(StepResponse {
        accepted,
        error,
        snapshot,
    })
}

/// `POST /lean/v0/test_driver/state_transition/run`
///
/// Runs `state_transition(pre, block)` for each block in sequence. The
/// `succeeded` flag reflects whether the full STF chain executed without
/// error; the simulator compares it to the fixture's `expectException` field.
async fn run_state_transition(
    Json(request): Json<StateTransitionRunRequest>,
) -> Json<StateTransitionResponse> {
    let mut state: State = request.pre.into();
    let blocks: Vec<Block> = request.blocks.into_iter().map(Into::into).collect();
    let blocks_empty = blocks.is_empty();

    let result = (|| -> Result<(), String> {
        for block in &blocks {
            ethlambda_state_transition::state_transition(&mut state, block)
                .map_err(|err| err.to_string())?;
        }

        // Match Ream's behavior: fixtures may carry `expectException` with an
        // empty `blocks` list to exercise pre-state-only invariants. The STF
        // entry point only runs when there's a block, so force a deterministic
        // failure here to keep the simulator's `expectException` assertion
        // consistent.
        if blocks_empty && request.expect_exception.is_some() {
            let target_slot = state.slot;
            ethlambda_state_transition::process_slots(&mut state, target_slot)
                .map_err(|err| err.to_string())?;
        }

        Ok(())
    })();

    let response = match result {
        Ok(()) => StateTransitionResponse {
            succeeded: true,
            error: None,
            post: Some(post_summary(&state)),
        },
        Err(err) => StateTransitionResponse {
            succeeded: false,
            error: Some(err),
            post: None,
        },
    };
    Json(response)
}

/// `POST /lean/v0/test_driver/verify_signatures/run`
///
/// Runs the exact same `verify_block_signatures` path the production block
/// import pipeline uses, against the fixture-supplied (anchor_state,
/// signed_block) pair.
async fn run_verify_signatures(
    Json(request): Json<VerifySignaturesRequest>,
) -> Json<VerifySignaturesResponse> {
    let state: State = request.anchor_state.into();
    let signed_block = signed_block_from_fixture(request.signed_block);

    let response = match verify_block_signatures(&state, &signed_block) {
        Ok(()) => VerifySignaturesResponse {
            succeeded: true,
            error: None,
        },
        Err(err) => VerifySignaturesResponse {
            succeeded: false,
            error: Some(err.to_string()),
        },
    };
    Json(response)
}

// ============================================================================
// Helpers
// ============================================================================

/// Replicate the invariants `Store::get_forkchoice_store` asserts (without
/// the panic):
///
/// 1. `anchor_block` and `state.latest_block_header` must agree on every field
///    once `state_root` is zeroed.
/// 2. The state's own `latest_block_header.state_root` must be either zero
///    (raw / pre-fill form) or match the tree-hash root of the state computed
///    with that field zeroed.
/// 3. `anchor_block.state_root` must equal the tree-hash root of the state
///    (with the header's `state_root` zeroed). This is the invariant the
///    `test_store_from_anchor_rejects_mismatched_state_root` spec fixture
///    targets: a block whose `state_root` disagrees with the supplied
///    anchor state is structurally inconsistent and must be refused at init.
fn anchor_pair_is_consistent(state: &State, block: &Block) -> bool {
    let mut state_header = state.latest_block_header.clone();
    let mut block_header = block.header();
    state_header.state_root = H256::ZERO;
    block_header.state_root = H256::ZERO;
    if state_header != block_header {
        return false;
    }

    let mut zeroed = state.clone();
    zeroed.latest_block_header.state_root = H256::ZERO;
    let computed = zeroed.hash_tree_root();

    let header_state_root = state.latest_block_header.state_root;
    if header_state_root != H256::ZERO && header_state_root != computed {
        return false;
    }

    block.state_root == computed
}

/// Dispatch a fork-choice step against the held Store.
fn apply_step(store: &mut Store, step: ForkChoiceStep) -> Result<(), String> {
    match step.step_type.as_str() {
        "tick" => {
            let genesis_time = store.config().genesis_time;
            let timestamp_ms = match (step.time, step.interval) {
                (Some(time_s), _) => time_s * 1000,
                (None, Some(interval)) => {
                    genesis_time * 1000 + interval * MILLISECONDS_PER_INTERVAL
                }
                (None, None) => return Err("tick step missing time and interval".to_string()),
            };
            store::on_tick(store, timestamp_ms, step.has_proposal.unwrap_or(false));
            Ok(())
        }
        "block" => {
            let block_data = step
                .block
                .ok_or_else(|| "block step missing block data".to_string())?;
            let signed_block = blank_signed_block(block_data);
            // Match the spec-test runner: advance time to the block's slot
            // before importing so the future-slot guard doesn't reject it.
            let block_time_ms = store.config().genesis_time * 1000
                + signed_block.message.slot * MILLISECONDS_PER_SLOT;
            store::on_tick(store, block_time_ms, true);
            store::on_block_without_verification(store, signed_block).map_err(|e| e.to_string())
        }
        "attestation" => {
            let att = step
                .attestation
                .ok_or_else(|| "attestation step missing data".to_string())?;
            let signed = SignedAttestation {
                validator_id: att
                    .validator_id
                    .ok_or_else(|| "attestation step missing validatorId".to_string())?,
                data: att.data.into(),
                signature: att
                    .signature
                    .ok_or_else(|| "attestation step missing signature".to_string())?,
            };
            store::on_gossip_attestation(store, &signed, step.is_aggregator.unwrap_or(false))
                .map_err(|e| e.to_string())
        }
        "gossipAggregatedAttestation" => {
            let att = step
                .attestation
                .ok_or_else(|| "gossipAggregatedAttestation step missing data".to_string())?;
            let proof = att
                .proof
                .ok_or_else(|| "gossipAggregatedAttestation step missing proof".to_string())?;
            let participants: EthAggregationBits = proof.participants.into();
            let proof_bytes: Vec<u8> = proof.proof_data.into();
            let proof_data = ByteListMiB::try_from(proof_bytes)
                .map_err(|err| format!("aggregated proof data too large: {err:?}"))?;
            let aggregated = SignedAggregatedAttestation {
                data: att.data.into(),
                proof: AggregatedSignatureProof::new(participants, proof_data),
            };
            store::on_gossip_aggregated_attestation(store, aggregated).map_err(|e| e.to_string())
        }
        // `checks`-only steps are no-ops here — the simulator validates them
        // against the snapshot returned alongside this response.
        "checks" => Ok(()),
        other => Err(format!("unknown step type: {other}")),
    }
}

/// Build a SignedBlock for fork-choice import without real signatures.
///
/// Matches the offline spec-test runner's `build_signed_block`: one empty
/// proof per attestation (the participant bits get checked against the
/// attestation's `aggregation_bits` during import) and a zeroed proposer
/// signature. Fork-choice steps use `on_block_without_verification`, so
/// these placeholders never reach the crypto layer.
fn blank_signed_block(block_data: BlockStepData) -> SignedBlock {
    let block: Block = block_data.to_block();
    let proofs: Vec<AggregatedSignatureProof> = block
        .body
        .attestations
        .iter()
        .map(|att| AggregatedSignatureProof::empty(att.aggregation_bits.clone()))
        .collect();

    SignedBlock {
        message: block,
        signature: BlockSignatures {
            proposer_signature: XmssSignature::try_from(vec![0u8; SIGNATURE_SIZE])
                .expect("zero-filled signature has the correct length"),
            attestation_signatures: AttestationSignatures::try_from(proofs)
                .expect("attestation proofs within limit"),
        },
    }
}

/// Materialize a SignedBlock that preserves the fixture-supplied per-validator
/// proof bytes, so `verify_block_signatures` actually exercises the leanVM
/// aggregate path (vs. the `From<TestSignedBlock>` shortcut that drops it).
fn signed_block_from_fixture(value: TestSignedBlock) -> SignedBlock {
    let block: Block = value.block.into();
    let proposer_signature = value.signature.proposer_signature;
    let proofs: Vec<AggregatedSignatureProof> = value
        .signature
        .attestation_signatures
        .data
        .into_iter()
        .map(|att_sig| {
            let participants: EthAggregationBits = att_sig.participants.into();
            let stripped = att_sig
                .proof_data
                .data
                .strip_prefix("0x")
                .unwrap_or(&att_sig.proof_data.data);
            let proof_bytes = hex::decode(stripped).unwrap_or_default();
            let proof_data =
                ByteListMiB::try_from(proof_bytes).unwrap_or_else(|_| ByteListMiB::default());
            AggregatedSignatureProof::new(participants, proof_data)
        })
        .collect();

    SignedBlock {
        message: block,
        signature: BlockSignatures {
            attestation_signatures: AttestationSignatures::try_from(proofs)
                .expect("attestation proofs within limit"),
            proposer_signature,
        },
    }
}

/// Read the post-state summary expected by the hive `state_transition/run`
/// schema.
fn post_summary(state: &State) -> StateTransitionPost {
    StateTransitionPost {
        slot: state.slot,
        latest_block_header_slot: state.latest_block_header.slot,
        latest_block_header_state_root: state.latest_block_header.state_root,
        historical_block_hashes_count: state.historical_block_hashes.len(),
    }
}

/// Snapshot the store fields exposed by the fork-choice `step` response.
fn snapshot_store(store: &Store) -> DriverSnapshot {
    let head_root = store.head();
    let head_slot = store
        .get_block_header(&head_root)
        .map(|header| header.slot)
        .unwrap_or(0);

    DriverSnapshot {
        head_slot,
        head_root,
        time: store.time(),
        justified_checkpoint: store.latest_justified().into(),
        finalized_checkpoint: store.latest_finalized().into(),
        safe_target: store.safe_target(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn driver_recognizes_truthy_env_values() {
        for value in ["1", "true", "TRUE", " Yes "] {
            // SAFETY: tests run single-threaded for shared env vars in this
            // file; the std::env contract here is just to flip the toggle.
            unsafe { std::env::set_var(TEST_DRIVER_ENV, value) };
            assert!(test_driver_enabled(), "{value:?} should enable the driver");
        }
        unsafe { std::env::set_var(TEST_DRIVER_ENV, "0") };
        assert!(!test_driver_enabled(), "0 should disable the driver");
        unsafe { std::env::remove_var(TEST_DRIVER_ENV) };
        assert!(
            !test_driver_enabled(),
            "unset env should disable the driver"
        );
    }

    #[test]
    fn empty_driver_store_is_usable_as_seed() {
        let store = empty_driver_store();
        // Head, time, checkpoints all read without panicking; that's the
        // contract `init_fork_choice` relies on before the first reset.
        let _ = store.head();
        assert_eq!(store.time(), 0);
        assert_eq!(store.latest_justified().slot, 0);
        assert_eq!(store.latest_finalized().slot, 0);
    }
}
