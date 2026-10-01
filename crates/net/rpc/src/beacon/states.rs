//! `/eth/v2/debug/beacon/states/{state_id}`,
//! `/eth/v1/beacon/states/{state_id}/finality_checkpoints` and
//! `/eth/v1/beacon/states/{state_id}/validators`.
//!
//! Serving the first makes this client checkpoint-syncable from itself:
//! `bin/ethlambda/src/checkpoint_sync.rs` fetches exactly that path, as SSZ,
//! from whichever Beacon API server `--checkpoint-sync-url` names.

use axum::{
    Router,
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, header},
    response::{IntoResponse, Response},
    routing::get,
};
use ethlambda_storage::Store;
use ethlambda_types::{
    beacon::{
        constants::FAR_FUTURE_EPOCH,
        containers::{BeaconState, shared::Validator},
        primitives::{BlsPubkey, Epoch, Gwei, ValidatorIndex},
        signing::compute_epoch_at_slot,
    },
    primitives::H256,
};
use serde::{Deserialize, Serialize};

use crate::{
    beacon::{ApiError, Envelope, blocks::is_finalized},
    shared::{
        block_id::BlockId,
        content::{Encoding, ssz_response, with_consensus_version},
    },
};

pub(crate) fn routes() -> Router<Store> {
    Router::new()
        .route("/eth/v2/debug/beacon/states/{state_id}", get(get_state))
        .route("/eth/v1/beacon/states/{state_id}/fork", get(get_fork))
        .route(
            "/eth/v1/beacon/states/{state_id}/finality_checkpoints",
            get(get_finality_checkpoints),
        )
        .route(
            "/eth/v1/beacon/states/{state_id}/validators",
            get(get_validators).post(post_validators),
        )
}

/// Resolve a `state_id` to the block root its state is stored under.
///
/// A `0x…` id is a *state* root in this API, and states here are keyed by
/// block root with no reverse index. Rather than return the wrong state, or
/// quietly treat the id as a block root and be right only by coincidence,
/// refuse it and say which ids do work.
fn resolve_state_id(store: &Store, state_id: &str) -> Result<H256, ApiError> {
    match BlockId::parse(state_id)? {
        BlockId::Root(_) => Err(ApiError::NotFound(
            "lookup by state root is not indexed; use head, finalized, justified or a slot",
        )),
        id => Ok(id.resolve_beacon(store)?),
    }
}

/// Load the state a `state_id` names, or the response explaining why not.
fn load(store: &Store, state_id: &str) -> Result<(H256, std::sync::Arc<BeaconState>), ApiError> {
    let root = resolve_state_id(store, state_id)?;
    let state = store
        .get_state(&root)
        .map_err(|_| ApiError::Internal("store read failed"))?
        .ok_or(ApiError::NotFound("state not found"))?;
    Ok((root, state))
}

async fn get_state(
    Path(state_id): Path<String>,
    State(store): State<Store>,
    headers: HeaderMap,
) -> Response {
    let (root, state) = match load(&store, &state_id) {
        Ok(found) => found,
        Err(err) => return err.into_response(),
    };
    let fork = state.fork_name();

    let accept = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok());
    let response = match Encoding::from_accept(accept) {
        Encoding::Ssz => ssz_response(state.to_ssz()),
        // `state.as_ref()` rather than a clone: a mainnet state runs to
        // hundreds of megabytes, and serde serializes happily through the
        // borrow.
        Encoding::Json => crate::json_response(Envelope {
            version: fork.as_str(),
            execution_optimistic: crate::shared::optimistic::block_is_optimistic(&store, root),
            finalized: is_finalized(&store, state.slot()),
            data: state.as_ref(),
        }),
    };

    with_consensus_version(response, fork)
}

/// `GET /eth/v1/beacon/states/{state_id}/fork`: the `Fork` the state carries,
/// which is what a validator client builds its signing domains from.
async fn get_fork(Path(state_id): Path<String>, State(store): State<Store>) -> Response {
    let (root, state) = match load(&store, &state_id) {
        Ok(found) => found,
        Err(err) => return err.into_response(),
    };
    crate::json_response(serde_json::json!({
        "execution_optimistic": crate::shared::optimistic::block_is_optimistic(&store, root),
        "finalized": is_finalized(&store, state.slot()),
        "data": state.fork(),
    }))
}

async fn get_finality_checkpoints(
    Path(state_id): Path<String>,
    State(store): State<Store>,
) -> Response {
    let (root, state) = match load(&store, &state_id) {
        Ok(found) => found,
        Err(err) => return err.into_response(),
    };

    // The state's own three checkpoints, not the store's fork-choice view.
    // This endpoint is defined as a read of the state `state_id` names, and
    // the state is the only place a *previous* justified checkpoint is kept
    // at all: the store keeps one justified row and one finalized row.
    crate::json_response(serde_json::json!({
        "execution_optimistic": crate::shared::optimistic::block_is_optimistic(&store, root),
        "finalized": is_finalized(&store, state.slot()),
        "data": {
            "previous_justified": state.previous_justified_checkpoint(),
            "current_justified": state.current_justified_checkpoint(),
            "finalized": state.finalized_checkpoint(),
        }
    }))
}

/// A validator's lifecycle status, as the Beacon API's `ValidatorStatus` names
/// it: the nine fine-grained statuses, each belonging to one of the four
/// coarse ones (`pending`, `active`, `exited`, `withdrawal`) a filter may also
/// name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValidatorStatus {
    PendingInitialized,
    PendingQueued,
    ActiveOngoing,
    ActiveExiting,
    ActiveSlashed,
    ExitedUnslashed,
    ExitedSlashed,
    WithdrawalPossible,
    WithdrawalDone,
}

impl ValidatorStatus {
    /// The status of `validator` as of `epoch`, per the beacon-APIs
    /// validator-status definitions. The cases are tested in epoch order, so
    /// each arm can rely on every earlier one having failed.
    fn of(validator: &Validator, balance: Gwei, epoch: Epoch) -> Self {
        if validator.activation_epoch > epoch {
            return if validator.activation_eligibility_epoch == FAR_FUTURE_EPOCH {
                Self::PendingInitialized
            } else {
                Self::PendingQueued
            };
        }
        if epoch < validator.exit_epoch {
            return if validator.exit_epoch == FAR_FUTURE_EPOCH {
                Self::ActiveOngoing
            } else if validator.slashed {
                Self::ActiveSlashed
            } else {
                Self::ActiveExiting
            };
        }
        if epoch < validator.withdrawable_epoch {
            return if validator.slashed {
                Self::ExitedSlashed
            } else {
                Self::ExitedUnslashed
            };
        }
        if balance == 0 {
            Self::WithdrawalDone
        } else {
            Self::WithdrawalPossible
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::PendingInitialized => "pending_initialized",
            Self::PendingQueued => "pending_queued",
            Self::ActiveOngoing => "active_ongoing",
            Self::ActiveExiting => "active_exiting",
            Self::ActiveSlashed => "active_slashed",
            Self::ExitedUnslashed => "exited_unslashed",
            Self::ExitedSlashed => "exited_slashed",
            Self::WithdrawalPossible => "withdrawal_possible",
            Self::WithdrawalDone => "withdrawal_done",
        }
    }

    /// Whether a `statuses` filter entry selects this status: its own name, or
    /// the coarse status it belongs to.
    fn matches(self, filter: &str) -> bool {
        let name = self.name();
        name == filter || name.split('_').next() == Some(filter)
    }
}

/// A `validator_id`: an index into the registry, or a public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValidatorId {
    Index(ValidatorIndex),
    Pubkey(BlsPubkey),
}

impl ValidatorId {
    fn parse(text: &str) -> Result<Self, ApiError> {
        if let Some(hex_digits) = text.strip_prefix("0x") {
            let mut bytes = [0u8; 48];
            return hex::decode_to_slice(hex_digits, &mut bytes)
                .map(|()| Self::Pubkey(BlsPubkey(bytes)))
                .map_err(|_| ApiError::BadRequest("invalid validator id"));
        }
        text.parse()
            .map(Self::Index)
            .map_err(|_| ApiError::BadRequest("invalid validator id"))
    }
}

/// The body of `POST .../validators`. Both fields are optional, and an absent,
/// `null` or empty one does not filter.
///
/// `null` is spelled out in the Beacon API ("Either or both may be `null` to
/// signal that no filtering on that attribute is desired"), and `default`
/// alone covers only an absent field: serde reads an explicit `null` as the
/// wrong type for a `Vec` and fails the whole body.
#[derive(Debug, Default, Deserialize)]
struct ValidatorsRequest {
    #[serde(default, deserialize_with = "null_as_empty")]
    ids: Vec<String>,
    #[serde(default, deserialize_with = "null_as_empty")]
    statuses: Vec<String>,
}

fn null_as_empty<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<Vec<String>>::deserialize(deserializer)?.unwrap_or_default())
}

#[derive(Debug, Serialize)]
struct ValidatorEntry<'a> {
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    index: ValidatorIndex,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    balance: Gwei,
    status: &'static str,
    validator: &'a Validator,
}

/// `GET .../validators?id=…&status=…`. Each parameter may repeat, and each
/// value may itself be a comma-separated list.
async fn get_validators(
    Path(state_id): Path<String>,
    State(store): State<Store>,
    Query(pairs): Query<Vec<(String, String)>>,
) -> Response {
    let mut request = ValidatorsRequest::default();
    for (key, value) in pairs {
        let values = value.split(',').map(str::to_owned);
        match key.as_str() {
            "id" => request.ids.extend(values),
            "status" => request.statuses.extend(values),
            _ => {}
        }
    }
    validators_response(&store, &state_id, request)
}

/// `POST .../validators`, the form a validator client uses: a long list of
/// public keys does not fit in a query string.
async fn post_validators(
    Path(state_id): Path<String>,
    State(store): State<Store>,
    body: Bytes,
) -> Response {
    let request = if body.is_empty() {
        ValidatorsRequest::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(_) => return ApiError::BadRequest("invalid request body").into_response(),
        }
    };
    validators_response(&store, &state_id, request)
}

/// The registry entries of the state `state_id` names that match `request`,
/// in registry order. An id naming no validator is omitted rather than failing
/// the request, as the Beacon API specifies.
fn validators_response(store: &Store, state_id: &str, request: ValidatorsRequest) -> Response {
    let ids = match request
        .ids
        .iter()
        .map(|id| ValidatorId::parse(id))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(ids) => ids,
        Err(err) => return err.into_response(),
    };
    let (root, state) = match load(store, state_id) {
        Ok(found) => found,
        Err(err) => return err.into_response(),
    };

    let epoch = compute_epoch_at_slot(state.slot());
    let selected = |index: ValidatorIndex, validator: &Validator| {
        ids.is_empty()
            || ids.iter().any(|id| match id {
                ValidatorId::Index(wanted) => *wanted == index,
                ValidatorId::Pubkey(wanted) => *wanted == validator.pubkey,
            })
    };
    let entries: Vec<ValidatorEntry> = state
        .iter_validators()
        .zip(state.iter_balances())
        .enumerate()
        .filter(|(index, (validator, _))| selected(*index as ValidatorIndex, validator))
        .map(|(index, (validator, balance))| {
            let status = ValidatorStatus::of(validator, balance, epoch);
            (index as ValidatorIndex, balance, status, validator)
        })
        .filter(|(_, _, status, _)| {
            request.statuses.is_empty()
                || request.statuses.iter().any(|filter| status.matches(filter))
        })
        .map(|(index, balance, status, validator)| ValidatorEntry {
            index,
            balance,
            status: status.name(),
            validator,
        })
        .collect();

    crate::json_response(serde_json::json!({
        "execution_optimistic": crate::shared::optimistic::block_is_optimistic(store, root),
        "finalized": is_finalized(store, state.slot()),
        "data": entries,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::beacon_fixture;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    const ANCHOR_SLOT: u64 = 64;

    async fn get(uri: &str, accept: Option<&str>) -> axum::response::Response {
        let fixture = beacon_fixture(ANCHOR_SLOT);
        let app = routes().with_state(fixture.store);
        let mut request = Request::builder().uri(uri);
        if let Some(accept) = accept {
            request = request.header("accept", accept);
        }
        app.oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    async fn body_json(response: axum::response::Response) -> serde_json::Value {
        let body = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&body).unwrap()
    }

    /// Exactly what `bin/ethlambda/src/checkpoint_sync.rs` asks other clients
    /// for, so serving it makes this client checkpoint-syncable from itself.
    #[tokio::test]
    async fn the_finalized_state_comes_back_as_ssz_for_checkpoint_sync() {
        let response = get(
            "/eth/v2/debug/beacon/states/finalized",
            Some("application/octet-stream"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            crate::SSZ_CONTENT_TYPE
        );
        assert_eq!(
            response.headers().get("eth-consensus-version").unwrap(),
            "phase0"
        );

        // The bytes have to decode back into the state they came from, since
        // checkpoint sync's whole job is to do exactly that.
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let slot = ethlambda_types::beacon::containers::BeaconState::slot_from_ssz(&body)
            .expect("the body is a beacon state");
        assert_eq!(slot, ANCHOR_SLOT);
    }

    #[tokio::test]
    async fn a_state_comes_back_as_json_by_default() {
        let json = body_json(get("/eth/v2/debug/beacon/states/head", None).await).await;
        assert_eq!(json["version"], "phase0");
        assert_eq!(json["data"]["slot"], "65", "integers are quoted");
        assert!(
            json["data"]["genesis_validators_root"]
                .as_str()
                .unwrap()
                .starts_with("0x")
        );
    }

    #[tokio::test]
    async fn a_state_root_id_is_refused_because_states_are_indexed_by_block_root() {
        let id = format!("0x{}", "cd".repeat(32));
        let response = get(&format!("/eth/v2/debug/beacon/states/{id}"), None).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let json = body_json(response).await;
        assert!(
            json["message"].as_str().unwrap().contains("state root"),
            "the refusal has to say why, got {}",
            json["message"]
        );
    }

    #[tokio::test]
    async fn finality_checkpoints_report_all_three() {
        let response = get("/eth/v1/beacon/states/head/finality_checkpoints", None).await;
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;

        for field in ["previous_justified", "current_justified", "finalized"] {
            assert!(
                json["data"][field]["epoch"].is_string(),
                "{field} epoch must be quoted, got {}",
                json["data"][field]["epoch"]
            );
            assert!(
                json["data"][field]["root"]
                    .as_str()
                    .unwrap()
                    .starts_with("0x")
            );
        }
    }

    #[tokio::test]
    async fn the_fork_is_the_one_the_state_carries() {
        let fixture = beacon_fixture(ANCHOR_SLOT);
        let head_state = fixture
            .store
            .get_state(&fixture.head_root)
            .unwrap()
            .unwrap();
        let expected = serde_json::to_value(head_state.fork()).unwrap();

        let response = get("/eth/v1/beacon/states/head/fork", None).await;
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["data"], expected);
        assert!(
            json["data"]["epoch"].is_string(),
            "the epoch must be quoted"
        );
        assert!(json["execution_optimistic"].is_boolean());
        assert!(json["finalized"].is_boolean());
    }

    #[tokio::test]
    async fn the_finalized_states_fork_is_marked_finalized() {
        let response = get("/eth/v1/beacon/states/finalized/fork", None).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_json(response).await["finalized"], true);
    }

    /// The same refusal every other state endpoint gives: state roots are not
    /// indexed, so a `0x` id is a 404 rather than a guess.
    #[tokio::test]
    async fn a_fork_by_state_root_is_a_404() {
        let root = format!("0x{}", "ab".repeat(32));
        let response = get(&format!("/eth/v1/beacon/states/{root}/fork"), None).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    mod validators {
        use super::*;
        use crate::test_utils::beacon_store_at;
        use ethlambda_state_transition::beacon::helpers::test_state::with_signing_validators_at;
        use ethlambda_types::beacon::fork::ForkName;

        const COUNT: usize = 8;

        fn app() -> (Router, BeaconState) {
            let state = with_signing_validators_at(ForkName::Fulu, COUNT);
            let (store, _root) = beacon_store_at(state.clone());
            (routes().with_state(store), state)
        }

        async fn post(body: serde_json::Value) -> axum::response::Response {
            let (app, _) = app();
            let request = Request::post("/eth/v1/beacon/states/head/validators")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap();
            app.oneshot(request).await.unwrap()
        }

        fn pubkey_hex(state: &BeaconState, index: usize) -> String {
            format!(
                "0x{}",
                hex::encode(state.validator(index as u64).unwrap().pubkey.0)
            )
        }

        /// What `ethlambda validator` sends: its keys, to learn their indices.
        #[tokio::test]
        async fn a_pubkey_resolves_to_its_index() {
            let (_, state) = app();
            let json =
                body_json(post(serde_json::json!({ "ids": [pubkey_hex(&state, 5)] })).await).await;
            let data = json["data"].as_array().unwrap();
            assert_eq!(data.len(), 1);
            assert_eq!(data[0]["index"], "5");
            assert_eq!(data[0]["status"], "active_ongoing");
            assert_eq!(data[0]["validator"]["pubkey"], pubkey_hex(&state, 5));
            assert!(data[0]["balance"].is_string(), "integers are quoted");
        }

        /// A `null` filter is the Beacon API's "no filtering on that
        /// attribute", not a malformed body.
        #[tokio::test]
        async fn a_null_filter_does_not_filter() {
            let (_, state) = app();
            let body = serde_json::json!({ "ids": [pubkey_hex(&state, 5)], "statuses": null });
            let response = post(body).await;
            assert_eq!(response.status(), StatusCode::OK);
            let json = body_json(response).await;
            assert_eq!(json["data"].as_array().unwrap().len(), 1);

            let response = post(serde_json::json!({ "ids": null, "statuses": null })).await;
            assert_eq!(response.status(), StatusCode::OK);
            let json = body_json(response).await;
            assert_eq!(json["data"].as_array().unwrap().len(), COUNT);
        }

        #[tokio::test]
        async fn an_unknown_id_is_omitted_not_an_error() {
            let unknown = format!("0x{}", "ab".repeat(48));
            let json =
                body_json(post(serde_json::json!({ "ids": ["2", unknown, "999"] })).await).await;
            let data = json["data"].as_array().unwrap();
            assert_eq!(data.len(), 1);
            assert_eq!(data[0]["index"], "2");
        }

        #[tokio::test]
        async fn no_ids_means_every_validator() {
            let json = body_json(post(serde_json::json!({})).await).await;
            assert_eq!(json["data"].as_array().unwrap().len(), COUNT);
        }

        #[tokio::test]
        async fn a_malformed_id_is_a_400() {
            let response = post(serde_json::json!({ "ids": ["0x1234"] })).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn a_coarse_status_filter_selects_its_fine_statuses() {
            let active = body_json(post(serde_json::json!({ "statuses": ["active"] })).await).await;
            assert_eq!(active["data"].as_array().unwrap().len(), COUNT);
            let exited = body_json(post(serde_json::json!({ "statuses": ["exited"] })).await).await;
            assert!(exited["data"].as_array().unwrap().is_empty());
        }

        #[tokio::test]
        async fn get_takes_repeated_and_comma_separated_ids() {
            let (app, _) = app();
            let request = Request::get("/eth/v1/beacon/states/head/validators?id=1,3&id=4")
                .body(Body::empty())
                .unwrap();
            let json = body_json(app.oneshot(request).await.unwrap()).await;
            let indices: Vec<&str> = json["data"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| entry["index"].as_str().unwrap())
                .collect();
            assert_eq!(indices, ["1", "3", "4"]);
        }

        #[test]
        fn status_follows_the_lifecycle() {
            let epoch = 10;
            let validator = |eligibility, activation, exit, withdrawable, slashed| Validator {
                activation_eligibility_epoch: eligibility,
                activation_epoch: activation,
                exit_epoch: exit,
                withdrawable_epoch: withdrawable,
                slashed,
                ..Default::default()
            };
            let far = FAR_FUTURE_EPOCH;
            let cases = [
                (
                    validator(far, far, far, far, false),
                    0,
                    "pending_initialized",
                ),
                (validator(5, far, far, far, false), 0, "pending_queued"),
                (validator(0, 1, far, far, false), 1, "active_ongoing"),
                (validator(0, 1, 20, 30, false), 1, "active_exiting"),
                (validator(0, 1, 20, 30, true), 1, "active_slashed"),
                (validator(0, 1, 5, 30, false), 1, "exited_unslashed"),
                (validator(0, 1, 5, 30, true), 1, "exited_slashed"),
                (validator(0, 1, 5, 8, false), 1, "withdrawal_possible"),
                (validator(0, 1, 5, 8, false), 0, "withdrawal_done"),
            ];
            for (validator, balance, expected) in cases {
                assert_eq!(
                    ValidatorStatus::of(&validator, balance, epoch).name(),
                    expected
                );
            }
        }
    }

    #[tokio::test]
    async fn a_malformed_id_is_a_400_and_an_absent_one_a_404() {
        assert_eq!(
            get("/eth/v2/debug/beacon/states/nope", None).await.status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            get("/eth/v2/debug/beacon/states/999999", None)
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
    }
}
