//! The validator-facing endpoints under `/eth/v1/validator/`: what a validator
//! client asks a beacon node for in order to do its duties.
//!
//! Every answer is computed from the fork-choice head's post-state, read off
//! the shared `Store` the chain actor writes: the head row is refreshed on each
//! import and tick, so no message to the actor is needed.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use ethlambda_blockchain::{SyncStatusController, metrics::SyncStatus};
use ethlambda_storage::Store;
use ethlambda_types::{
    beacon::{
        containers::{
            BeaconState,
            shared::{AttestationData, Checkpoint},
        },
        preset,
        primitives::{BlsPubkey, CommitteeIndex, Epoch, ExecutionAddress, Slot, ValidatorIndex},
        signing::{compute_epoch_at_slot, compute_start_slot_at_epoch},
    },
    primitives::H256,
};
use serde::{Deserialize, Serialize};

use ethlambda_network_api::RpcToP2PRef;
use ethlambda_state_transition::beacon::{
    fork_choice::checkpoint_state,
    gossip::attestation::compute_subnet_for_attestation,
    helpers::accessors::{CommitteeCacheExt as _, get_block_root_at_slot},
    helpers::altair::compute_sync_committee_period,
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
            "/eth/v1/validator/duties/sync/{epoch}",
            post(post_sync_duties),
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
}

#[derive(Debug, Serialize)]
struct SyncDuty {
    pubkey: BlsPubkey,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    validator_index: ValidatorIndex,
    /// Every position the validator holds in the committee, quoted. A
    /// validator can hold more than one, since the committee is drawn with
    /// replacement.
    validator_sync_committee_indices: Vec<String>,
}

/// `POST /eth/v1/validator/duties/sync/{epoch}`.
///
/// Answered from the head state: its `current_sync_committee` for an epoch in
/// the head's own sync committee period, its `next_sync_committee` for the
/// period after, which is as far ahead as the Beacon API allows. An earlier
/// period is refused rather than answered from a historical state, since a
/// validator client only ever asks about the current and next period.
///
/// A requested validator that holds no seat is left out of `data`. The
/// answer is `503` while the node is syncing: the head state's committees are
/// not yet the chain's.
async fn post_sync_duties(
    Path(epoch): Path<String>,
    State(store): State<Store>,
    Extension(sync_status): Extension<SyncStatusController>,
    Json(indices): Json<Vec<String>>,
) -> Response {
    if sync_status.get() == SyncStatus::Syncing {
        return ApiError::ServiceUnavailable("the node is syncing").into_response();
    }
    match sync_duties(&store, &epoch, &indices) {
        Ok(body) => crate::json_response(body),
        Err(err) => err.into_response(),
    }
}

fn sync_duties(
    store: &Store,
    epoch: &str,
    indices: &[String],
) -> Result<serde_json::Value, ApiError> {
    let epoch = parse_epoch(epoch)?;
    let indices = indices
        .iter()
        .map(|index| index.parse::<ValidatorIndex>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ApiError::BadRequest("invalid validator index"))?;
    let (head_root, state) = head(store)?;

    let (current, next) = state
        .sync_committees()
        .map_err(|_| ApiError::BadRequest("sync committees start at altair"))?;
    let head_period = compute_sync_committee_period(compute_epoch_at_slot(state.slot()));
    let requested_period = compute_sync_committee_period(epoch);
    let committee = if requested_period == head_period {
        current
    } else if requested_period == head_period + 1 {
        next
    } else {
        return Err(ApiError::BadRequest(
            "epoch is not in the head state's current or next sync committee period",
        ));
    };

    // One pass over the committee rather than one per requested validator:
    // the committee stores pubkeys, so that is what a validator is matched by.
    let mut positions: HashMap<BlsPubkey, Vec<String>> = HashMap::new();
    for (position, pubkey) in committee.pubkeys.iter().enumerate() {
        positions
            .entry(*pubkey)
            .or_default()
            .push(position.to_string());
    }

    let mut duties = Vec::new();
    for validator_index in indices {
        let validator = state
            .validator(validator_index)
            .map_err(|_| ApiError::BadRequest("unknown validator index"))?;
        if let Some(held) = positions.get(&validator.pubkey) {
            duties.push(SyncDuty {
                pubkey: validator.pubkey,
                validator_index,
                validator_sync_committee_indices: held.clone(),
            });
        }
    }

    Ok(serde_json::json!({
        "execution_optimistic": store.is_beacon_optimistic(head_root),
        "data": duties,
    }))
}

/// One entry of `beacon_committee_subscriptions`. Parsed so a malformed body
/// is refused, though `validator_index` is never read.
#[derive(Debug, Deserialize)]
struct CommitteeSubscription {
    #[allow(dead_code)]
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
/// Each aggregator's entry has the node join its committee's attestation
/// subnet until the end of that slot, so the committee's votes reach the pool
/// the aggregate endpoint answers from (phase0 `validator.md`, "Attestation
/// subnet subscription"). Non-aggregators' entries need nothing: publishing
/// reaches a subnet through gossipsub fanout without joining it.
async fn post_committee_subscriptions(
    State(store): State<Store>,
    Extension(p2p): Extension<RpcToP2PRef>,
    Json(subscriptions): Json<Vec<CommitteeSubscription>>,
) -> Response {
    let config = store.config();
    let subnets: Vec<(u64, Slot)> = subscriptions
        .iter()
        .filter(|entry| entry.is_aggregator)
        .map(|entry| {
            let subnet_id = compute_subnet_for_attestation(
                entry.committees_at_slot,
                entry.slot,
                entry.committee_index,
                &config,
            );
            (subnet_id, entry.slot)
        })
        .collect();
    if !subnets.is_empty() && p2p.subscribe_attestation_subnets(subnets).is_err() {
        return ApiError::Internal("the network actor is not running").into_response();
    }
    axum::http::StatusCode::OK.into_response()
}

/// Each validator's execution-layer fee recipient, as its validator client
/// last named it. Read by block production, which puts the proposer's into
/// the payload attributes. In memory only: a validator client repeats the call
/// every epoch, so a restarted node relearns the map within one.
pub(crate) type FeeRecipients = Arc<std::sync::Mutex<HashMap<ValidatorIndex, ExecutionAddress>>>;

/// One entry of `prepare_beacon_proposer`.
#[derive(Debug, Deserialize)]
struct ProposerPreparation {
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    validator_index: ValidatorIndex,
    fee_recipient: ExecutionAddress,
}

/// `POST /eth/v1/validator/prepare_beacon_proposer`: record where each
/// validator's block rewards should be paid.
async fn post_prepare_beacon_proposer(
    Extension(fee_recipients): Extension<FeeRecipients>,
    Json(preparations): Json<Vec<ProposerPreparation>>,
) -> Response {
    let mut map = fee_recipients.lock().expect("fee recipient lock poisoned");
    for preparation in preparations {
        map.insert(preparation.validator_index, preparation.fee_recipient);
    }
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
    async fn a_preparation_records_the_validators_fee_recipient() {
        let (store, _) = beacon_store_at(fulu_state());
        let fee_recipients = FeeRecipients::default();
        let app = routes()
            .with_state(store)
            .layer(Extension(fee_recipients.clone()));
        let body = serde_json::json!([
            { "validator_index": "7", "fee_recipient": format!("0x{}", "ab".repeat(20)) }
        ]);
        let request = Request::post("/eth/v1/validator/prepare_beacon_proposer")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        assert_eq!(app.oneshot(request).await.unwrap().status(), StatusCode::OK);
        assert_eq!(
            fee_recipients.lock().unwrap().get(&7),
            Some(&ExecutionAddress::from_slice(&[0xab; 20]))
        );
    }

    async fn post_raw(uri: &str, body: serde_json::Value) -> (StatusCode, axum::body::Bytes) {
        let (store, _) = beacon_store_at(fulu_state());
        let request = Request::post(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let network: RpcToP2PRef = Arc::new(crate::test_utils::RecordingNetwork::default());
        let app = routes()
            .with_state(store)
            .layer(Extension(network))
            .layer(Extension(FeeRecipients::default()));
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        (
            status,
            response.into_body().collect().await.unwrap().to_bytes(),
        )
    }

    /// An aggregator's entry joins its committee's subnet until its slot; a
    /// plain attester's joins nothing.
    #[tokio::test]
    async fn only_aggregators_join_their_committee_subnet() {
        let (store, _) = beacon_store_at(fulu_state());
        let network = Arc::new(crate::test_utils::RecordingNetwork::default());
        let p2p: RpcToP2PRef = network.clone();
        let app = routes().with_state(store).layer(Extension(p2p));
        let body = serde_json::json!([
            { "validator_index": "1", "committee_index": "3", "committees_at_slot": "4",
              "slot": "34", "is_aggregator": true },
            { "validator_index": "2", "committee_index": "0", "committees_at_slot": "4",
              "slot": "34", "is_aggregator": false },
        ]);
        let request = Request::post("/eth/v1/validator/beacon_committee_subscriptions")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        // Slot 34 is offset 2 in its epoch: committee 3 of 4 per slot is the
        // epoch's committee 11.
        assert_eq!(*network.subscriptions.lock().unwrap(), vec![(11, 34)]);
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

    // --- duties/sync -----------------------------------------------------

    mod sync_duties {
        use super::*;
        use ethlambda_types::beacon::containers::altair::SyncCommittee;

        /// A committee whose seat `i` belongs to validator `first + i % 8`, so
        /// each of those eight holds `SYNC_COMMITTEE_SIZE / 8` seats and every
        /// other validator holds none.
        fn committee_of(state: &BeaconState, first: u64) -> SyncCommittee {
            let pubkeys: Vec<BlsPubkey> = (0..preset::SYNC_COMMITTEE_SIZE as u64)
                .map(|seat| state.validator(first + seat % 8).unwrap().pubkey)
                .collect();
            SyncCommittee {
                aggregate_pubkey: pubkeys[0],
                pubkeys: pubkeys.try_into().unwrap(),
            }
        }

        /// A fulu state whose current committee is validators 0-7 and whose
        /// next committee is validators 8-15, so an answer drawn from the
        /// wrong one shows up.
        fn state_with_committees() -> BeaconState {
            let mut state = fulu_state();
            let current = committee_of(&state, 0);
            let next = committee_of(&state, 8);
            let BeaconState::Fulu(fulu) = &mut state else {
                unreachable!("built as fulu")
            };
            fulu.current_sync_committee = current;
            fulu.next_sync_committee = next;
            state
        }

        async fn post_sync(
            state: BeaconState,
            epoch: u64,
            indices: &[&str],
            sync_status: SyncStatusController,
        ) -> (StatusCode, serde_json::Value) {
            let (store, _root) = beacon_store_at(state);
            let request = Request::post(format!("/eth/v1/validator/duties/sync/{epoch}"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!(indices).to_string()))
                .unwrap();
            let app = routes().with_state(store).layer(Extension(sync_status));
            let response = app.oneshot(request).await.unwrap();
            let status = response.status();
            let body = response.into_body().collect().await.unwrap().to_bytes();
            (status, serde_json::from_slice(&body).unwrap_or_default())
        }

        /// The seats `validator` holds in [`committee_of`]`(_, first)`.
        fn seats(validator: u64, first: u64) -> Vec<String> {
            (0..preset::SYNC_COMMITTEE_SIZE as u64)
                .filter(|seat| first + seat % 8 == validator)
                .map(|seat| seat.to_string())
                .collect()
        }

        #[tokio::test]
        async fn the_current_period_reads_the_current_committee() {
            let state = state_with_committees();
            let epoch = compute_epoch_at_slot(state.slot());
            let (status, json) =
                post_sync(state.clone(), epoch, &["3", "9", "20"], Default::default()).await;
            assert_eq!(status, StatusCode::OK);

            // Validator 3 sits in the current committee; 9 only in the next;
            // 20 in neither, so only 3 is listed.
            let duties = json["data"].as_array().unwrap();
            assert_eq!(duties.len(), 1);
            assert_eq!(duties[0]["validator_index"], "3");
            let pubkey = state.validator(3).unwrap().pubkey;
            assert_eq!(duties[0]["pubkey"], format!("0x{}", hex::encode(pubkey.0)));
            assert_eq!(
                duties[0]["validator_sync_committee_indices"],
                serde_json::json!(seats(3, 0))
            );
            assert!(json["execution_optimistic"].is_boolean());
        }

        #[tokio::test]
        async fn the_next_period_reads_the_next_committee() {
            let state = state_with_committees();
            let next_period_epoch = preset::EPOCHS_PER_SYNC_COMMITTEE_PERIOD
                * (compute_sync_committee_period(compute_epoch_at_slot(state.slot())) + 1);
            let (status, json) =
                post_sync(state, next_period_epoch, &["3", "9"], Default::default()).await;
            assert_eq!(status, StatusCode::OK);

            let duties = json["data"].as_array().unwrap();
            assert_eq!(duties.len(), 1);
            assert_eq!(duties[0]["validator_index"], "9");
            assert_eq!(
                duties[0]["validator_sync_committee_indices"],
                serde_json::json!(seats(9, 8))
            );
        }

        #[tokio::test]
        async fn the_period_after_next_is_a_400() {
            let state = state_with_committees();
            let period = compute_sync_committee_period(compute_epoch_at_slot(state.slot()));
            let epoch = preset::EPOCHS_PER_SYNC_COMMITTEE_PERIOD * (period + 2);
            let (status, _) = post_sync(state, epoch, &["3"], Default::default()).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }

        /// An earlier period would need a historical state, which a validator
        /// client never asks for; refused rather than answered wrongly.
        #[tokio::test]
        async fn an_earlier_period_is_a_400() {
            let mut state = state_with_committees();
            let BeaconState::Fulu(fulu) = &mut state else {
                unreachable!("built as fulu")
            };
            fulu.slot = preset::EPOCHS_PER_SYNC_COMMITTEE_PERIOD * preset::SLOTS_PER_EPOCH;
            let (status, _) = post_sync(state, 0, &["3"], Default::default()).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn an_unknown_validator_is_a_400() {
            let state = state_with_committees();
            let epoch = compute_epoch_at_slot(state.slot());
            let unknown = (COUNT as u64).to_string();
            let (status, _) = post_sync(state, epoch, &[&unknown], Default::default()).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn a_syncing_node_answers_503() {
            let state = state_with_committees();
            let epoch = compute_epoch_at_slot(state.slot());
            let syncing = SyncStatusController::new(SyncStatus::Syncing);
            let (status, _) = post_sync(state, epoch, &["3"], syncing).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        }
    }
}
