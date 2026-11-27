//! The state endpoints gloas adds: a slot's payload timeliness committee and
//! the two builder payment queues.
//!
//! | Route | Answer |
//! |---|---|
//! | `GET /eth/v1/beacon/states/{state_id}/ptc` | `get_ptc` for `?slot` (default: the state's slot) |
//! | `GET /eth/v1/beacon/states/{state_id}/builder_pending_payments` | the state's `builder_pending_payments` |
//! | `GET /eth/v1/beacon/states/{state_id}/builder_pending_withdrawals` | the state's `builder_pending_withdrawals` |
//!
//! Each answers JSON by default and SSZ on `Accept: application/octet-stream`,
//! and a state before gloas is a `400`, as the Beacon API requires.

use axum::{
    Router,
    extract::{Path, Query, State},
    http::{HeaderMap, header},
    response::{IntoResponse, Response},
    routing::get,
};
use ethlambda_state_transition::beacon::helpers::gloas::get_ptc;
use ethlambda_storage::Store;
use ethlambda_types::{
    beacon::{
        containers::{BeaconState, gloas},
        fork::ForkName,
        primitives::Slot,
    },
    primitives::H256,
};
use libssz::SszEncode as _;
use serde::Deserialize;

use crate::beacon::{ApiError, blocks::is_finalized, states::load};
use crate::shared::content::{Encoding, ssz_response, with_consensus_version};

pub(crate) fn routes() -> Router<Store> {
    Router::new()
        .route("/eth/v1/beacon/states/{state_id}/ptc", get(get_state_ptc))
        .route(
            "/eth/v1/beacon/states/{state_id}/builder_pending_payments",
            get(get_builder_pending_payments),
        )
        .route(
            "/eth/v1/beacon/states/{state_id}/builder_pending_withdrawals",
            get(get_builder_pending_withdrawals),
        )
}

const PRE_GLOAS: ApiError = ApiError::BadRequest("the requested state is prior to Gloas");

/// The gloas state `state_id` names, with its block root, or the error the
/// Beacon API gives for one that does not resolve or is older than gloas.
fn load_gloas(
    store: &Store,
    state_id: &str,
) -> Result<(H256, std::sync::Arc<BeaconState>), ApiError> {
    let (root, state) = load(store, state_id)?;
    if !matches!(state.as_ref(), BeaconState::Gloas(_)) {
        return Err(PRE_GLOAS);
    }
    Ok((root, state))
}

fn encoding(headers: &HeaderMap) -> Encoding {
    Encoding::from_accept(headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()))
}

#[derive(Debug, Deserialize)]
struct PtcQuery {
    slot: Option<String>,
}

/// `GET /eth/v1/beacon/states/{state_id}/ptc`.
///
/// The committee comes from the state's cached `ptc_window` through
/// `get_ptc`, so the slot's epoch must be the state's previous, current or
/// lookahead epoch, and at or past the gloas fork; any other slot is a `400`.
/// The SSZ form is `Container{slot, validators: Vector[ValidatorIndex,
/// PTC_SIZE]}`, both fixed-size, so its bytes are the two encodings in order.
async fn get_state_ptc(
    Path(state_id): Path<String>,
    Query(query): Query<PtcQuery>,
    State(store): State<Store>,
    headers: HeaderMap,
) -> Response {
    let slot = match query.slot.as_deref().map(str::parse::<Slot>) {
        None => None,
        Some(Ok(slot)) => Some(slot),
        Some(Err(_)) => return ApiError::BadRequest("invalid slot").into_response(),
    };
    let (root, state) = match load_gloas(&store, &state_id) {
        Ok(found) => found,
        Err(err) => return err.into_response(),
    };
    let slot = slot.unwrap_or_else(|| state.slot());
    let config = store.config();
    let Ok(committee) = get_ptc(&state, slot, &config) else {
        return ApiError::BadRequest(
            "the slot is prior to Gloas or outside the state's PTC window",
        )
        .into_response();
    };
    match encoding(&headers) {
        Encoding::Ssz => {
            let mut bytes = slot.to_ssz();
            bytes.extend(committee.to_ssz());
            ssz_response(bytes)
        }
        Encoding::Json => {
            let validators: Vec<String> = committee.iter().map(u64::to_string).collect();
            crate::json_response(serde_json::json!({
                "execution_optimistic": crate::shared::optimistic::block_is_optimistic(&store, root),
                "finalized": is_finalized(&store, state.slot()),
                "data": { "slot": slot.to_string(), "validators": validators },
            }))
        }
    }
}

/// One of the gloas state's fields, versioned as the Beacon API asks: `ssz`
/// and `json` read it off the state for the encoding the caller chose.
fn versioned_field(
    store: &Store,
    state_id: &str,
    headers: &HeaderMap,
    ssz: impl FnOnce(&gloas::BeaconState) -> Vec<u8>,
    json: impl FnOnce(&gloas::BeaconState) -> serde_json::Value,
) -> Response {
    let (root, state) = match load_gloas(store, state_id) {
        Ok(found) => found,
        Err(err) => return err.into_response(),
    };
    let BeaconState::Gloas(inner) = state.as_ref() else {
        return PRE_GLOAS.into_response();
    };
    let response = match encoding(headers) {
        Encoding::Ssz => ssz_response(ssz(inner)),
        Encoding::Json => crate::json_response(serde_json::json!({
            "version": ForkName::Gloas.as_str(),
            "execution_optimistic": crate::shared::optimistic::block_is_optimistic(store, root),
            "finalized": is_finalized(store, state.slot()),
            "data": json(inner),
        })),
    };
    with_consensus_version(response, ForkName::Gloas)
}

/// `GET /eth/v1/beacon/states/{state_id}/builder_pending_payments`: the
/// `2 * SLOTS_PER_EPOCH` payment slots, empty ones included.
async fn get_builder_pending_payments(
    Path(state_id): Path<String>,
    State(store): State<Store>,
    headers: HeaderMap,
) -> Response {
    versioned_field(
        &store,
        &state_id,
        &headers,
        |state| state.builder_pending_payments.to_ssz(),
        |state| {
            let payments: Vec<_> = state.builder_pending_payments.iter().collect();
            serde_json::json!(payments)
        },
    )
}

/// `GET /eth/v1/beacon/states/{state_id}/builder_pending_withdrawals`.
async fn get_builder_pending_withdrawals(
    Path(state_id): Path<String>,
    State(store): State<Store>,
    headers: HeaderMap,
) -> Response {
    versioned_field(
        &store,
        &state_id,
        &headers,
        |state| state.builder_pending_withdrawals.to_ssz(),
        |state| {
            let withdrawals: Vec<_> = state.builder_pending_withdrawals.iter().collect();
            serde_json::json!(withdrawals)
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::beacon_store_with_config;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use ethlambda_state_transition::beacon::helpers::test_state::with_signing_validators_at;
    use ethlambda_types::beacon::{
        config::Config,
        containers::gloas::{BuilderPendingPayment, BuilderPendingWithdrawal},
        primitives::ExecutionAddress,
    };
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    /// A gloas head state, on a schedule that puts gloas at genesis, with one
    /// pending payment in slot 3 and one pending withdrawal.
    fn gloas_store() -> (Store, BeaconState) {
        let mut state = with_signing_validators_at(ForkName::Gloas, 64);
        let BeaconState::Gloas(inner) = &mut state else {
            unreachable!("built as gloas")
        };
        let withdrawal = BuilderPendingWithdrawal {
            fee_recipient: ExecutionAddress::ZERO,
            amount: 7,
            builder_index: 2,
        };
        inner.builder_pending_payments[3] = BuilderPendingPayment {
            weight: 5,
            withdrawal: withdrawal.clone(),
            proposer_index: 9,
        };
        inner.builder_pending_withdrawals.push(withdrawal);
        let config = Config::mainnet().with_fork_epoch(ForkName::Gloas, 0);
        let store = beacon_store_with_config(state.clone(), config).0;
        (store, state)
    }

    async fn get(
        store: Store,
        uri: &str,
        accept: Option<&str>,
    ) -> (StatusCode, HeaderMap, Vec<u8>) {
        let mut request = Request::get(uri);
        if let Some(accept) = accept {
            request = request.header(header::ACCEPT, accept);
        }
        let response = routes()
            .with_state(store)
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, headers, body.to_vec())
    }

    fn json(body: &[u8]) -> serde_json::Value {
        serde_json::from_slice(body).unwrap()
    }

    #[tokio::test]
    async fn the_ptc_defaults_to_the_states_slot_and_quotes_its_numbers() {
        let (store, state) = gloas_store();
        let expected = get_ptc(&state, state.slot(), &store.config()).unwrap();
        let (status, _, body) = get(store, "/eth/v1/beacon/states/head/ptc", None).await;
        assert_eq!(status, StatusCode::OK);
        let json = json(&body);
        assert_eq!(json["data"]["slot"], state.slot().to_string());
        let validators: Vec<String> = expected.iter().map(u64::to_string).collect();
        assert_eq!(json["data"]["validators"], serde_json::json!(validators));
        assert_eq!(json["execution_optimistic"], false);
    }

    #[tokio::test]
    async fn the_ptc_in_ssz_is_the_slot_then_the_committee() {
        let (store, state) = gloas_store();
        let expected = get_ptc(&state, state.slot(), &store.config()).unwrap();
        let (status, _, body) = get(
            store,
            "/eth/v1/beacon/states/head/ptc",
            Some("application/octet-stream"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let mut want = state.slot().to_ssz();
        want.extend(expected.to_ssz());
        assert_eq!(body, want);
    }

    #[tokio::test]
    async fn a_ptc_slot_outside_the_window_or_unparseable_is_a_400() {
        let (store, _) = gloas_store();
        for uri in [
            "/eth/v1/beacon/states/head/ptc?slot=999999",
            "/eth/v1/beacon/states/head/ptc?slot=soon",
        ] {
            let (status, _, _) = get(store.clone(), uri, None).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
        }
    }

    #[tokio::test]
    async fn the_builder_queues_are_versioned_and_quoted() {
        let (store, state) = gloas_store();
        let (status, headers, body) = get(
            store.clone(),
            "/eth/v1/beacon/states/head/builder_pending_payments",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers["eth-consensus-version"], "gloas");
        let payments = json(&body);
        assert_eq!(payments["version"], "gloas");
        let BeaconState::Gloas(inner) = &state else {
            unreachable!("built as gloas")
        };
        assert_eq!(
            payments["data"].as_array().unwrap().len(),
            inner.builder_pending_payments.len()
        );
        assert_eq!(payments["data"][3]["weight"], "5");
        assert_eq!(payments["data"][3]["withdrawal"]["builder_index"], "2");

        let (status, _, body) = get(
            store,
            "/eth/v1/beacon/states/head/builder_pending_withdrawals",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let withdrawals = json(&body);
        assert_eq!(withdrawals["data"][0]["amount"], "7");
    }

    #[tokio::test]
    async fn the_builder_queues_in_ssz_are_the_states_own_encodings() {
        let (store, state) = gloas_store();
        let BeaconState::Gloas(inner) = &state else {
            unreachable!("built as gloas")
        };
        let ssz = Some("application/octet-stream");
        let (_, _, payments) = get(
            store.clone(),
            "/eth/v1/beacon/states/head/builder_pending_payments",
            ssz,
        )
        .await;
        assert_eq!(payments, inner.builder_pending_payments.to_ssz());
        let (_, headers, withdrawals) = get(
            store,
            "/eth/v1/beacon/states/head/builder_pending_withdrawals",
            ssz,
        )
        .await;
        assert_eq!(withdrawals, inner.builder_pending_withdrawals.to_ssz());
        assert_eq!(headers["eth-consensus-version"], "gloas");
    }

    #[tokio::test]
    async fn a_pre_gloas_state_is_a_400() {
        let state = with_signing_validators_at(ForkName::Fulu, 64);
        let (store, _) = beacon_store_with_config(state, Config::mainnet());
        for uri in [
            "/eth/v1/beacon/states/head/ptc",
            "/eth/v1/beacon/states/head/builder_pending_payments",
            "/eth/v1/beacon/states/head/builder_pending_withdrawals",
        ] {
            let (status, _, _) = get(store.clone(), uri, None).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
        }
    }
}
