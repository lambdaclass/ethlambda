//! The validator-facing endpoints under `/eth/v1/validator/`: what a validator
//! client asks a beacon node for in order to do its duties.
//!
//! Every answer is computed from the fork-choice head's post-state, read off
//! the shared `Store` the chain actor writes: the head row is refreshed on each
//! import and tick, so no message to the actor is needed.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use ethlambda_storage::Store;
use ethlambda_types::{
    beacon::{
        containers::{
            BeaconState,
            shared::{AttestationData, Checkpoint},
        },
        preset,
        primitives::{BlsPubkey, CommitteeIndex, Epoch, Slot, ValidatorIndex},
        signing::{compute_epoch_at_slot, compute_start_slot_at_epoch},
    },
    primitives::H256,
};
use serde::{Deserialize, Serialize};

use ethlambda_state_transition::beacon::{
    fork_choice::checkpoint_state,
    helpers::accessors::{CommitteeCacheExt as _, get_block_root_at_slot},
};

use crate::beacon::ApiError;

pub(crate) fn routes() -> Router<Store> {
    Router::new()
        .route(
            "/eth/v1/validator/duties/proposer/{epoch}",
            get(get_proposer_duties),
        )
        .route(
            "/eth/v1/validator/duties/attester/{epoch}",
            post(post_attester_duties),
        )
        .route(
            "/eth/v1/validator/attestation_data",
            get(get_attestation_data),
        )
        .route(
            "/eth/v1/validator/beacon_committee_subscriptions",
            post(post_committee_subscriptions),
        )
        .route(
            "/eth/v1/validator/prepare_beacon_proposer",
            post(post_prepare_beacon_proposer),
        )
        // Block production and aggregation are not served yet. Named here so a
        // validator client gets an explicit 501 it can fail over on, rather
        // than a bare 404 that reads like a wrong URL.
        .route("/eth/v3/validator/blocks/{slot}", get(not_yet_served))
        .route("/eth/v2/beacon/blocks", post(not_yet_served))
        .route(
            "/eth/v2/validator/aggregate_attestation",
            get(not_yet_served),
        )
        .route(
            "/eth/v2/validator/aggregate_and_proofs",
            post(not_yet_served),
        )
}

async fn not_yet_served() -> Response {
    ApiError::NotImplemented("block production and aggregation are not served by this node yet")
        .into_response()
}

/// One entry of `beacon_committee_subscriptions`. Parsed so a malformed body
/// is refused, though nothing is read from it yet.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CommitteeSubscription {
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    validator_index: ValidatorIndex,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    committee_index: CommitteeIndex,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    committees_at_slot: u64,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    slot: Slot,
    is_aggregator: bool,
}

/// `POST /eth/v1/validator/beacon_committee_subscriptions`.
///
/// Acknowledged and otherwise ignored. The request asks the node to join the
/// attestation subnets its validators' committees gossip on, which matters
/// for aggregation (an aggregator has to hear its committee's attestations);
/// publishing needs no subscription, since gossipsub fanout reaches the
/// subnet's subscribers. This node joins no attestation subnet until it
/// aggregates.
async fn post_committee_subscriptions(
    Json(subscriptions): Json<Vec<CommitteeSubscription>>,
) -> Response {
    tracing::debug!(
        count = subscriptions.len(),
        "Committee subscriptions acknowledged; attestation subnets are not joined yet"
    );
    axum::http::StatusCode::OK.into_response()
}

/// One entry of `prepare_beacon_proposer`. Parsed so a malformed body is
/// refused, though nothing is read from it yet.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ProposerPreparation {
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    validator_index: ValidatorIndex,
    fee_recipient: String,
}

/// `POST /eth/v1/validator/prepare_beacon_proposer`.
///
/// Acknowledged and otherwise ignored: the fee recipient is an input to
/// building an execution payload, which this node does not do yet.
async fn post_prepare_beacon_proposer(
    Json(preparations): Json<Vec<ProposerPreparation>>,
) -> Response {
    tracing::debug!(
        count = preparations.len(),
        "Proposer preparations acknowledged; block production is not served yet"
    );
    axum::http::StatusCode::OK.into_response()
}

fn parse_epoch(epoch: &str) -> Result<Epoch, ApiError> {
    epoch
        .parse()
        .map_err(|_| ApiError::BadRequest("invalid epoch"))
}

/// The fork-choice head's block root and post-state.
pub(crate) fn head(store: &Store) -> Result<(H256, Arc<BeaconState>), ApiError> {
    let (_slot, root) = store
        .beacon_head()
        .ok_or(ApiError::Internal("no head block"))?;
    let state = store
        .get_state(&root)
        .map_err(|_| ApiError::Internal("store read failed"))?
        .ok_or(ApiError::Internal("head state not found"))?;
    Ok((root, state))
}

/// The root of the latest block at or before `slot`, on the chain ending in
/// `head_root`, whose post-state is `head_state`.
///
/// The Beacon API defines each duty's `dependent_root` as
/// `get_block_root_at_slot(state, slot)`, which only answers for a slot before
/// the state's own. A slot at or past the head's is one no block has filled
/// since the head, so the head itself is the latest block at or before it.
///
/// A slot older than the state's retained root window is an error rather than
/// a guess: a wrong `dependent_root` would let a validator client keep duties
/// a reorg has invalidated. A duty's dependent slot is at most two epochs back,
/// far inside the window, so this should never fire.
fn block_root_at_or_before(
    head_state: &BeaconState,
    head_root: H256,
    slot: Slot,
) -> Result<H256, ApiError> {
    if slot >= head_state.slot() {
        return Ok(head_root);
    }
    get_block_root_at_slot(head_state, slot)
        .map_err(|_| ApiError::Internal("dependent slot is outside the state's root window"))
}

#[derive(Debug, Serialize)]
struct ProposerDuty {
    pubkey: BlsPubkey,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    validator_index: ValidatorIndex,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    slot: Slot,
}

/// `GET /eth/v1/validator/duties/proposer/{epoch}`.
///
/// Read from fulu's `proposer_lookahead`, which the state keeps for its own
/// epoch and the next `MIN_SEED_LOOKAHEAD` epochs, so any epoch in that window
/// is answered without advancing a state. Any other epoch is refused.
///
/// `dependent_root` is v1's definition, the block root at
/// `compute_start_slot_at_epoch(epoch) - 1` (the genesis block's at epoch 0).
/// It is what `ethlambda validator` compares across fetches to notice a reorg.
async fn get_proposer_duties(Path(epoch): Path<String>, State(store): State<Store>) -> Response {
    match proposer_duties(&store, &epoch) {
        Ok(body) => crate::json_response(body),
        Err(err) => err.into_response(),
    }
}

fn proposer_duties(store: &Store, epoch: &str) -> Result<serde_json::Value, ApiError> {
    let epoch = parse_epoch(epoch)?;
    let (head_root, state) = head(store)?;

    let BeaconState::Fulu(fulu) = state.as_ref() else {
        return Err(ApiError::BadRequest(
            "proposer duties are served from fulu's proposer lookahead only",
        ));
    };
    let state_epoch = compute_epoch_at_slot(state.slot());
    let offset = epoch
        .checked_sub(state_epoch)
        .filter(|offset| *offset <= preset::MIN_SEED_LOOKAHEAD)
        .ok_or(ApiError::BadRequest(
            "epoch is outside the head state's proposer lookahead",
        ))?;

    let first_slot = compute_start_slot_at_epoch(epoch);
    let window_start = (offset * preset::SLOTS_PER_EPOCH) as usize;
    let proposers = &fulu.proposer_lookahead[window_start..][..preset::SLOTS_PER_EPOCH as usize];
    let duties = proposers
        .iter()
        .zip(first_slot..)
        .map(|(&validator_index, slot)| {
            let validator = state
                .validator(validator_index)
                .map_err(|_| ApiError::Internal("lookahead names an unknown validator"))?;
            Ok(ProposerDuty {
                pubkey: validator.pubkey,
                validator_index,
                slot,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;

    let dependent_root = block_root_at_or_before(&state, head_root, first_slot.saturating_sub(1))?;
    Ok(serde_json::json!({
        "dependent_root": dependent_root,
        "execution_optimistic": store.is_beacon_optimistic(head_root),
        "data": duties,
    }))
}

#[derive(Debug, Serialize)]
struct AttesterDuty {
    pubkey: BlsPubkey,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    validator_index: ValidatorIndex,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    committee_index: CommitteeIndex,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    committee_length: u64,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    committees_at_slot: u64,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    validator_committee_index: u64,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    slot: Slot,
}

/// `POST /eth/v1/validator/duties/attester/{epoch}`, with the validator
/// indices to report on as a JSON array of decimal strings.
///
/// The head state answers for its previous, current and next epoch as it is:
/// an epoch's committees depend only on its seed, whose RANDAO mix is fixed a
/// full epoch earlier, and on which validators are active in it, which the
/// registry records `MAX_SEED_LOOKAHEAD` epochs ahead. Any other epoch is
/// refused rather than computed from an advanced state.
///
/// `dependent_root` is the block root at
/// `compute_start_slot_at_epoch(epoch - 1) - 1` (the genesis block's on
/// underflow), per the endpoint's definition: the last block that could still
/// change this epoch's shuffling.
///
/// Every committee of the epoch is derived to find the requested validators,
/// which on a small registry is nothing but on mainnet is a full shuffle per
/// request. Caching the epoch's shuffle is a later optimization.
async fn post_attester_duties(
    Path(epoch): Path<String>,
    State(store): State<Store>,
    Json(indices): Json<Vec<String>>,
) -> Response {
    match attester_duties(&store, &epoch, &indices) {
        Ok(body) => crate::json_response(body),
        Err(err) => err.into_response(),
    }
}

fn attester_duties(
    store: &Store,
    epoch: &str,
    indices: &[String],
) -> Result<serde_json::Value, ApiError> {
    let epoch = parse_epoch(epoch)?;
    let wanted = indices
        .iter()
        .map(|index| index.parse::<ValidatorIndex>())
        .collect::<Result<std::collections::HashSet<_>, _>>()
        .map_err(|_| ApiError::BadRequest("invalid validator index"))?;
    let (head_root, state) = head(store)?;

    let state_epoch = compute_epoch_at_slot(state.slot());
    if epoch + 1 < state_epoch || epoch > state_epoch + 1 {
        return Err(ApiError::BadRequest(
            "epoch is not within one epoch of the head state's",
        ));
    }

    let committees = store.committee_cache().committees(&state, epoch);
    let committees_at_slot = committees.committees_per_slot();
    let first_slot = compute_start_slot_at_epoch(epoch);
    let mut duties = Vec::new();
    for slot in first_slot..first_slot + preset::SLOTS_PER_EPOCH {
        for committee_index in 0..committees_at_slot {
            let committee = committees
                .committee(slot, committee_index)
                .map_err(|_| ApiError::Internal("committee computation failed"))?;
            for (position, &validator_index) in committee.iter().enumerate() {
                if !wanted.contains(&validator_index) {
                    continue;
                }
                let validator = state
                    .validator(validator_index)
                    .map_err(|_| ApiError::Internal("committee names an unknown validator"))?;
                duties.push(AttesterDuty {
                    pubkey: validator.pubkey,
                    validator_index,
                    committee_index,
                    committee_length: committee.len() as u64,
                    committees_at_slot,
                    validator_committee_index: position as u64,
                    slot,
                });
            }
        }
    }

    let dependent_slot = compute_start_slot_at_epoch(epoch.saturating_sub(1)).saturating_sub(1);
    let dependent_root = block_root_at_or_before(&state, head_root, dependent_slot)?;
    Ok(serde_json::json!({
        "dependent_root": dependent_root,
        "execution_optimistic": store.is_beacon_optimistic(head_root),
        "data": duties,
    }))
}

#[derive(Debug, Deserialize)]
struct AttestationDataQuery {
    slot: Slot,
    /// Required by the endpoint, and ignored: from electra on the committee
    /// travels outside `AttestationData`, whose `index` is always zero, so
    /// every committee of a slot attests to the same data.
    #[allow(dead_code)]
    committee_index: CommitteeIndex,
}

/// `GET /eth/v1/validator/attestation_data?slot&committee_index`.
///
/// Built as phase0's `validator.md` ("Attestation data") describes, with the
/// fork-choice head as `head_block` and `head_state` its post-state advanced
/// through empty slots to `slot`:
///
/// - `beacon_block_root` is the head block's root.
/// - `source` is that advanced state's `current_justified_checkpoint`. It can
///   only change at an epoch boundary, so the state is advanced no further
///   than the start of `slot`'s epoch, through fork choice's cached
///   `checkpoint_state`, and only when the head sits in an earlier epoch.
/// - `target` is `slot`'s epoch and its boundary block: the head itself when
///   no block has filled the boundary slot since, else the root the state
///   recorded there.
/// - `index` is zero, as electra requires.
///
/// A slot before the head's, or more than one slot past the wall clock, is
/// refused: neither is a slot a validator is asked to attest to.
async fn get_attestation_data(
    Query(query): Query<AttestationDataQuery>,
    State(store): State<Store>,
) -> Response {
    match attestation_data(&store, query.slot) {
        Ok(data) => crate::json_response(serde_json::json!({ "data": data })),
        Err(err) => err.into_response(),
    }
}

fn attestation_data(store: &Store, slot: Slot) -> Result<AttestationData, ApiError> {
    let (head_root, state) = head(store)?;
    if slot < state.slot() {
        return Err(ApiError::BadRequest("slot is before the head block"));
    }
    if slot > crate::beacon::node::wall_slot(store) + 1 {
        return Err(ApiError::BadRequest("slot is in the future"));
    }

    let epoch = compute_epoch_at_slot(slot);
    let epoch_start = compute_start_slot_at_epoch(epoch);
    let source = if compute_epoch_at_slot(state.slot()) == epoch {
        state.current_justified_checkpoint()
    } else {
        let boundary = Checkpoint {
            epoch,
            root: head_root,
        };
        checkpoint_state(store, &boundary, &store.config())
            .map_err(|_| ApiError::Internal("advancing the head state failed"))?
            .current_justified_checkpoint()
    };
    let target = Checkpoint {
        epoch,
        root: block_root_at_or_before(&state, head_root, epoch_start)?,
    };

    Ok(AttestationData {
        slot,
        index: 0,
        beacon_block_root: head_root,
        source,
        target,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::beacon_store_at;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use ethlambda_state_transition::beacon::helpers::{
        fulu::{get_beacon_proposer_indices, initialize_proposer_lookahead},
        test_state::with_signing_validators_at,
    };
    use ethlambda_types::beacon::fork::ForkName;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    const COUNT: usize = 64;

    /// A fulu state one epoch past genesis with its lookahead filled in, as
    /// every real fulu state has it, and distinct block roots per slot so a
    /// `dependent_root` taken from the wrong slot shows up.
    fn fulu_state() -> BeaconState {
        let mut state = with_signing_validators_at(ForkName::Fulu, COUNT);
        let lookahead = initialize_proposer_lookahead(&state).unwrap();
        let BeaconState::Fulu(fulu) = &mut state else {
            unreachable!("built as fulu")
        };
        fulu.proposer_lookahead = lookahead.try_into().unwrap();
        for (slot, root) in fulu.block_roots.iter_mut().enumerate() {
            *root = H256::repeat_byte(slot as u8 + 1);
        }
        state
    }

    async fn get(state: BeaconState, uri: &str) -> (StatusCode, serde_json::Value) {
        let (store, _root) = beacon_store_at(state);
        let request = Request::get(uri).body(Body::empty()).unwrap();
        let response = routes().with_state(store).oneshot(request).await.unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn proposers_match_the_spec_computation_for_both_lookahead_epochs() {
        let state = fulu_state();
        let state_epoch = compute_epoch_at_slot(state.slot());
        for epoch in [state_epoch, state_epoch + 1] {
            let expected = get_beacon_proposer_indices(&state, epoch).unwrap();
            let (status, json) = get(
                state.clone(),
                &format!("/eth/v1/validator/duties/proposer/{epoch}"),
            )
            .await;
            assert_eq!(status, StatusCode::OK);

            let duties = json["data"].as_array().unwrap();
            assert_eq!(duties.len(), preset::SLOTS_PER_EPOCH as usize);
            for (offset, duty) in duties.iter().enumerate() {
                let index = expected[offset];
                let slot = compute_start_slot_at_epoch(epoch) + offset as u64;
                assert_eq!(duty["validator_index"], index.to_string());
                assert_eq!(duty["slot"], slot.to_string());
                let pubkey = state.validator(index).unwrap().pubkey;
                assert_eq!(duty["pubkey"], format!("0x{}", hex::encode(pubkey.0)));
            }
        }
    }

    #[tokio::test]
    async fn the_dependent_root_is_the_block_before_the_epoch() {
        let state = fulu_state();
        let state_epoch = compute_epoch_at_slot(state.slot());
        let (_, json) = get(
            state.clone(),
            &format!("/eth/v1/validator/duties/proposer/{state_epoch}"),
        )
        .await;
        // The state sits at the first slot of its epoch, so the slot before it
        // is still in its root window.
        let before = compute_start_slot_at_epoch(state_epoch) - 1;
        let expected = get_block_root_at_slot(&state, before).unwrap();
        assert_eq!(json["dependent_root"], format!("{expected}"));
    }

    #[tokio::test]
    async fn the_next_epochs_dependent_block_is_the_head_itself() {
        // The last slot of the head's epoch has not happened yet, so the latest
        // block at or before it is the head.
        let state = fulu_state();
        let next = compute_epoch_at_slot(state.slot()) + 1;
        let (store, head_root) = beacon_store_at(state);
        let request = Request::get(format!("/eth/v1/validator/duties/proposer/{next}"))
            .body(Body::empty())
            .unwrap();
        let response = routes().with_state(store).oneshot(request).await.unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["dependent_root"], format!("{head_root}"));
    }

    async fn post(
        state: BeaconState,
        uri: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let (store, _root) = beacon_store_at(state);
        let request = Request::post(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = routes().with_state(store).oneshot(request).await.unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn attester_duties_match_get_beacon_committee() {
        use ethlambda_state_transition::beacon::helpers::accessors::get_beacon_committee;

        let state = fulu_state();
        let epoch = compute_epoch_at_slot(state.slot());
        let (status, json) = post(
            state.clone(),
            &format!("/eth/v1/validator/duties/attester/{epoch}"),
            serde_json::json!(["3", "17"]),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let duties = json["data"].as_array().unwrap();
        // Every active validator attests exactly once per epoch.
        assert_eq!(duties.len(), 2);
        for duty in duties {
            let slot: u64 = duty["slot"].as_str().unwrap().parse().unwrap();
            let index: u64 = duty["committee_index"].as_str().unwrap().parse().unwrap();
            let position: usize = duty["validator_committee_index"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap();
            let committee = get_beacon_committee(&state, slot, index).unwrap();
            assert_eq!(
                committee[position].to_string(),
                duty["validator_index"].as_str().unwrap()
            );
            assert_eq!(duty["committee_length"], committee.len().to_string());
            assert_eq!(compute_epoch_at_slot(slot), epoch);
        }
    }

    #[tokio::test]
    async fn an_unknown_validator_has_no_duty() {
        let state = fulu_state();
        let epoch = compute_epoch_at_slot(state.slot());
        let (status, json) = post(
            state,
            &format!("/eth/v1/validator/duties/attester/{epoch}"),
            serde_json::json!(["100000"]),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(json["data"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_attester_dependent_root_is_the_block_before_the_previous_epoch() {
        // For the next epoch, the dependent slot is the one before the head's
        // own epoch, which is inside the state's root window.
        let state = fulu_state();
        let next = compute_epoch_at_slot(state.slot()) + 1;
        let (_, json) = post(
            state.clone(),
            &format!("/eth/v1/validator/duties/attester/{next}"),
            serde_json::json!(["0"]),
        )
        .await;
        let before = compute_start_slot_at_epoch(next - 1) - 1;
        let expected = get_block_root_at_slot(&state, before).unwrap();
        assert_eq!(json["dependent_root"], format!("{expected}"));
    }

    #[tokio::test]
    async fn attester_duties_two_epochs_ahead_are_a_400() {
        let state = fulu_state();
        let too_far = compute_epoch_at_slot(state.slot()) + 2;
        let (status, _) = post(
            state,
            &format!("/eth/v1/validator/duties/attester/{too_far}"),
            serde_json::json!(["0"]),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// `fulu_state` moved `slots_past_boundary` slots into its epoch, with a
    /// current justified checkpoint distinct from the default so a source read
    /// from anywhere else shows up.
    fn fulu_state_at(slots_past_boundary: u64) -> BeaconState {
        let mut state = fulu_state();
        let BeaconState::Fulu(fulu) = &mut state else {
            unreachable!("built as fulu")
        };
        fulu.slot += slots_past_boundary;
        fulu.current_justified_checkpoint = Checkpoint {
            epoch: 1,
            root: H256::repeat_byte(0xaa),
        };
        state
    }

    async fn attestation_data_for(
        state: BeaconState,
        slot: Slot,
    ) -> (StatusCode, serde_json::Value, H256) {
        let (store, head_root) = beacon_store_at(state);
        let uri = format!("/eth/v1/validator/attestation_data?slot={slot}&committee_index=0");
        let request = Request::get(uri).body(Body::empty()).unwrap();
        let response = routes().with_state(store).oneshot(request).await.unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&body).unwrap(), head_root)
    }

    #[tokio::test]
    async fn at_the_boundary_the_head_is_the_target() {
        let state = fulu_state_at(0);
        let slot = state.slot();
        let (status, json, head_root) = attestation_data_for(state, slot).await;
        assert_eq!(status, StatusCode::OK);
        let data = &json["data"];
        assert_eq!(data["slot"], slot.to_string());
        assert_eq!(data["index"], "0");
        assert_eq!(data["beacon_block_root"], format!("{head_root}"));
        assert_eq!(
            data["target"]["epoch"],
            compute_epoch_at_slot(slot).to_string()
        );
        assert_eq!(data["target"]["root"], format!("{head_root}"));
        assert_eq!(data["source"]["epoch"], "1");
        assert_eq!(
            data["source"]["root"],
            format!("{}", H256::repeat_byte(0xaa))
        );
    }

    #[tokio::test]
    async fn past_the_boundary_the_target_is_the_recorded_boundary_block() {
        let state = fulu_state_at(3);
        let slot = state.slot() + 1;
        let boundary = compute_start_slot_at_epoch(compute_epoch_at_slot(slot));
        let expected = get_block_root_at_slot(&state, boundary).unwrap();
        let (status, json, head_root) = attestation_data_for(state, slot).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["data"]["target"]["root"], format!("{expected}"));
        assert_eq!(json["data"]["beacon_block_root"], format!("{head_root}"));
    }

    #[tokio::test]
    async fn a_head_in_the_previous_epoch_is_advanced_for_the_source() {
        // The head sits late in its epoch and the attestation is for the next
        // epoch's first slot, whose boundary no block has filled: the target is
        // the head, and the source comes from the head state advanced across
        // the boundary (unchanged here, since epoch processing leaves the
        // current justified checkpoint alone without votes).
        let state = fulu_state_at(preset::SLOTS_PER_EPOCH - 1);
        let slot = state.slot() + 1;
        let (status, json, head_root) = attestation_data_for(state, slot).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(
            json["data"]["target"]["epoch"],
            compute_epoch_at_slot(slot).to_string()
        );
        assert_eq!(json["data"]["target"]["root"], format!("{head_root}"));
        assert_eq!(
            json["data"]["source"]["root"],
            format!("{}", H256::repeat_byte(0xaa))
        );
    }

    #[tokio::test]
    async fn a_slot_before_the_head_is_a_400() {
        let state = fulu_state_at(3);
        let slot = state.slot() - 1;
        let (status, _, _) = attestation_data_for(state, slot).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn subscriptions_and_preparations_are_acknowledged() {
        let subscription = serde_json::json!([{
            "validator_index": "1", "committee_index": "0", "committees_at_slot": "1",
            "slot": "33", "is_aggregator": false
        }]);
        let (status, _) = post_raw(
            "/eth/v1/validator/beacon_committee_subscriptions",
            subscription,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let preparation = serde_json::json!([{
            "validator_index": "1",
            "fee_recipient": "0x000000000000000000000000000000000000dead"
        }]);
        let (status, _) = post_raw("/eth/v1/validator/prepare_beacon_proposer", preparation).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn block_and_aggregate_routes_answer_501() {
        let (store, _) = beacon_store_at(fulu_state());
        let app = routes().with_state(store);
        let requests = [
            Request::get("/eth/v3/validator/blocks/40").body(Body::empty()),
            Request::post("/eth/v2/beacon/blocks").body(Body::empty()),
            Request::get("/eth/v2/validator/aggregate_attestation?slot=1").body(Body::empty()),
            Request::post("/eth/v2/validator/aggregate_and_proofs").body(Body::empty()),
        ];
        for request in requests {
            let response = app.clone().oneshot(request.unwrap()).await.unwrap();
            assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        }
    }

    async fn post_raw(uri: &str, body: serde_json::Value) -> (StatusCode, axum::body::Bytes) {
        let (store, _) = beacon_store_at(fulu_state());
        let request = Request::post(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = routes().with_state(store).oneshot(request).await.unwrap();
        let status = response.status();
        (
            status,
            response.into_body().collect().await.unwrap().to_bytes(),
        )
    }

    #[tokio::test]
    async fn an_epoch_outside_the_lookahead_is_a_400() {
        let state = fulu_state();
        let too_far = compute_epoch_at_slot(state.slot()) + 2;
        let (status, _) = get(
            state,
            &format!("/eth/v1/validator/duties/proposer/{too_far}"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}
