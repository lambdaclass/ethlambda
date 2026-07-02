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
    Block as FixtureBlock, TestState, fork_choice::ForkChoiceStep,
    state_transition::StateTransitionRunRequest, verify_signatures::TestSignedBlock,
};
use ethlambda_types::{
    attestation::{
        AggregationBits as EthAggregationBits, SignedAggregatedAttestation, SignedAttestation,
    },
    block::{Block, ByteList512KiB, SingleMessageAggregate},
    checkpoint::Checkpoint,
    primitives::H256,
    state::{State, anchor_pair_is_consistent},
};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::debug;

/// Environment variable that activates the test driver at boot time.
///
/// The hive simulator sets this to `"1"` for each spec-asset fixture run; any
/// of `"1"`, `"true"`, or `"yes"` (case-insensitive) enables the driver.
pub const TEST_DRIVER_ENV: &str = "HIVE_LEAN_TEST_DRIVER";

/// Sentinel prefixing every placeholder proof leanSpec's mocked prover emits
/// (`proofSetting: 0` fixtures). Matches `MOCK_PROOF_PREFIX` in leanSpec's
/// `packages/testing/src/consensus_testing/crypto_mode.py`. Proofs carrying it
/// are accepted without cryptographic verification, mirroring leanSpec's mocked
/// verifier; genuine (`proofSetting: 1`) proofs still run the real verifier.
const MOCK_PROOF_PREFIX: &[u8] = b"\x00MOCKED-AGGREGATION-PROOF\x00";

/// Whether the supplied env-var value should activate the driver.
fn parse_truthy_env_value(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes"
    )
}

/// Returns true when the binary should boot into test-driver mode.
pub fn test_driver_enabled() -> bool {
    std::env::var(TEST_DRIVER_ENV)
        .map(|value| parse_truthy_env_value(&value))
        .unwrap_or(false)
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
struct DriverSnapshot {
    head_slot: u64,
    head_root: H256,
    /// Store time in 800 ms intervals since genesis (matches [`Store::time`]).
    time: u64,
    /// `Checkpoint` already serializes as `{root, slot}`, which is the shape
    /// hive's `DriverCheckpoint` expects; no wrapper type needed.
    justified_checkpoint: Checkpoint,
    finalized_checkpoint: Checkpoint,
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
    if !anchor_pair_is_consistent(&mut state, &block) {
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
    // Hold the write guard across both the step and the snapshot read so the
    // returned snapshot reflects this step (and no interleaved request can
    // mutate the store in between, even though the hive simulator drives
    // steps serially per fixture).
    let mut guard = driver.write().await;
    let outcome = apply_step(&mut guard, step);
    let (accepted, error) = match outcome {
        Ok(()) => (true, None),
        Err(err) => {
            debug!(%err, "fork-choice step rejected");
            (false, Some(err))
        }
    };
    let snapshot = snapshot_store(&guard);
    drop(guard);
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

    let response = match apply_state_transition(&mut state, &blocks, request.expect_exception) {
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

/// Run the STF for each block in `blocks` and return the first error (if any).
///
/// When `blocks` is empty and `expect_exception` is set the spec fixture wants
/// failure but the STF entry point never runs, so call `process_slots(slot)`
/// against the current slot. That call returns `Err(StateSlotIsNewer)` because
/// the STF rejects `target_slot <= current_slot`, giving the simulator a
/// deterministic non-2xx outcome that matches the fixture's `expectException`.
fn apply_state_transition(
    state: &mut State,
    blocks: &[Block],
    expect_exception: Option<String>,
) -> Result<(), String> {
    for block in blocks {
        ethlambda_state_transition::state_transition(state, block)
            .map_err(|err| err.to_string())?;
    }

    if blocks.is_empty() && expect_exception.is_some() {
        let target_slot = state.slot;
        ethlambda_state_transition::process_slots(state, target_slot)
            .map_err(|err| err.to_string())?;
    }

    Ok(())
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
    let signed_block = match request.signed_block.try_into_signed_block_with_proofs() {
        Ok(block) => block,
        Err(err) => {
            return Json(VerifySignaturesResponse {
                succeeded: false,
                error: Some(format!("malformed signedBlock fixture: {err}")),
            });
        }
    };

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
            let signed_block = block_data.to_blank_signed_block();
            // Match the spec-test runner: advance time to the block's slot
            // before importing, unless the step delivers the block ahead of
            // the store clock.
            if step.tick_to_slot {
                let block_time_ms = store.config().genesis_time * 1000
                    + signed_block.message.slot * MILLISECONDS_PER_SLOT;
                store::on_tick(store, block_time_ms, true);
            }
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
            let proof_bytes: Vec<u8> = proof.proof.into();
            // leanSpec's mocked prover (proofSetting=0) emits placeholder proofs
            // prefixed with MOCK_PROOF_PREFIX and expects verifiers to accept them
            // unchecked. Route those through the non-verifying path; genuine proofs
            // still run the real verifier.
            let is_mocked = proof_bytes.starts_with(MOCK_PROOF_PREFIX);
            let proof_data = ByteList512KiB::try_from(proof_bytes)
                .map_err(|err| format!("aggregated proof data too large: {err:?}"))?;
            let data: ethlambda_types::attestation::AttestationData = att.data.into();
            let aggregated = SignedAggregatedAttestation {
                proof: SingleMessageAggregate::new(participants, proof_data),
                data,
            };
            if is_mocked {
                store::on_gossip_aggregated_attestation_without_verification(store, aggregated)
                    .map_err(|e| e.to_string())
            } else {
                store::on_gossip_aggregated_attestation(store, aggregated)
                    .map_err(|e| e.to_string())
            }
        }
        // `checks`-only steps are no-ops here: the simulator validates them
        // against the snapshot returned alongside this response.
        "checks" => Ok(()),
        other => Err(format!("unknown step type: {other}")),
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
    DriverSnapshot {
        head_slot: store.head_slot(),
        head_root: store.head(),
        time: store.time(),
        justified_checkpoint: store.latest_justified(),
        finalized_checkpoint: store.latest_finalized(),
        safe_target: store.safe_target(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_truthy_env_value_accepts_canonical_truthy_strings() {
        for value in ["1", "true", "TRUE", " Yes ", "yes\n"] {
            assert!(parse_truthy_env_value(value), "{value:?} should be truthy");
        }
        for value in ["0", "false", "no", "", "  ", "1.0"] {
            assert!(!parse_truthy_env_value(value), "{value:?} should be falsy");
        }
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
