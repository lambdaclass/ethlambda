//! `POST /eth/v1/validator/register_validator`: a validator client's builder
//! registrations, checked against the head state and forwarded to the
//! builder `--builder` names.
//!
//! Validators that the head state does not hold, or holds as exited, are
//! dropped and counted rather than refused: the beacon-APIs say they must
//! not reach the builder, not that the request fails. Each kept
//! registration also becomes its validator's fee recipient, as
//! `prepare_beacon_proposer` would make it, so a block built locally after
//! all still pays the address the validator registered.

use std::collections::{HashMap, HashSet};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Extension, Router};
use ethlambda_storage::Store;
use ethlambda_types::beacon::builder::{
    SignedValidatorRegistrationV1, SignedValidatorRegistrations,
};
use ethlambda_types::beacon::containers::BeaconState;
use ethlambda_types::beacon::primitives::{BlsPubkey, ValidatorIndex};
use ethlambda_types::beacon::signing::compute_epoch_at_slot;
use libssz::SszDecode as _;
use tracing::warn;

use super::builder_client::{BuilderClient, BuilderError};
use super::validator::{FeeRecipients, head};
use super::{ApiError, BodyEncoding};
use crate::metrics::inc_builder_registrations;

pub(crate) fn routes() -> Router<Store> {
    Router::new().route(
        "/eth/v1/validator/register_validator",
        post(post_register_validator),
    )
}

async fn post_register_validator(
    State(store): State<Store>,
    Extension(builder): Extension<Option<BuilderClient>>,
    Extension(fee_recipients): Extension<FeeRecipients>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    register(&store, builder.as_ref(), &fee_recipients, &headers, &body)
        .await
        .map_or_else(IntoResponse::into_response, |()| {
            axum::http::StatusCode::OK.into_response()
        })
}

async fn register(
    store: &Store,
    builder: Option<&BuilderClient>,
    fee_recipients: &FeeRecipients,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(), ApiError> {
    let builder =
        builder.ok_or(ApiError::Internal("no builder is configured (--builder)"))?;
    let registrations = decode(headers, body)?;
    let (_, state) = head(store)?;

    let submitted = registrations.len();
    let kept = active_or_pending(&state, registrations);
    inc_builder_registrations("dropped", (submitted - kept.len()) as u64);
    if kept.is_empty() {
        return Ok(());
    }

    {
        let mut recipients = fee_recipients.lock().expect("fee recipient lock poisoned");
        for (index, registration) in &kept {
            recipients.insert(*index, registration.message.fee_recipient);
        }
    }
    let kept: Vec<SignedValidatorRegistrationV1> =
        kept.into_iter().map(|(_, registration)| registration).collect();
    match builder.register_validators(&kept).await {
        Ok(()) => {
            inc_builder_registrations("forwarded", kept.len() as u64);
            Ok(())
        }
        Err(err) => {
            inc_builder_registrations("refused", kept.len() as u64);
            warn!(%err, count = kept.len(), "Builder did not take the registrations");
            Err(match err {
                BuilderError::BadRequest(message) => ApiError::BadRequestDetail(message),
                _ => ApiError::Internal("the builder did not take the registrations"),
            })
        }
    }
}

/// The request body: a JSON array, or the SSZ list builder-specs defines.
fn decode(headers: &HeaderMap, body: &[u8]) -> Result<Vec<SignedValidatorRegistrationV1>, ApiError> {
    match BodyEncoding::from_headers(headers)? {
        BodyEncoding::Ssz => SignedValidatorRegistrations::from_ssz_bytes(body)
            .map(|list| list.to_vec())
            .map_err(|_| ApiError::BadRequest("invalid SSZ registrations")),
        BodyEncoding::Json => serde_json::from_slice(body)
            .map_err(|_| ApiError::BadRequest("invalid JSON registrations")),
    }
}

/// The registrations whose validator `state` holds as active or pending at
/// its own epoch, each with its validator index. One pass over the registry,
/// whatever the number of registrations.
fn active_or_pending(
    state: &BeaconState,
    registrations: Vec<SignedValidatorRegistrationV1>,
) -> Vec<(ValidatorIndex, SignedValidatorRegistrationV1)> {
    let epoch = compute_epoch_at_slot(state.slot());
    let wanted: HashSet<BlsPubkey> = registrations
        .iter()
        .map(|registration| registration.message.pubkey)
        .collect();
    // Active or pending is exactly "not yet exited": a pending validator's
    // exit epoch is still FAR_FUTURE_EPOCH.
    let indices: HashMap<BlsPubkey, ValidatorIndex> = state
        .iter_validators()
        .enumerate()
        .filter(|(_, validator)| wanted.contains(&validator.pubkey) && epoch < validator.exit_epoch)
        .map(|(index, validator)| (validator.pubkey, index as ValidatorIndex))
        .collect();
    registrations
        .into_iter()
        .filter_map(|registration| {
            let index = indices.get(&registration.message.pubkey)?;
            Some((*index, registration))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use ethlambda_state_transition::beacon::helpers::test_state::with_signing_validators_at;
    use ethlambda_types::beacon::fork::ForkName;
    use ethlambda_types::beacon::primitives::{ExecutionAddress, Version};
    use http_body_util::BodyExt as _;
    use libssz::SszEncode as _;
    use tower::ServiceExt as _;

    use super::*;
    use crate::beacon::builder_client::mock_relay::{MockRelay, signed_registration};
    use crate::test_utils::beacon_store_at;

    const VALIDATORS: usize = 8;

    /// A store whose head state holds `VALIDATORS` active validators, minus
    /// the indices in `exited`, which have already left.
    fn store_with_exited(exited: &[usize]) -> Store {
        let mut state = with_signing_validators_at(ForkName::Fulu, VALIDATORS);
        for &index in exited {
            state.validator_mut(index as ValidatorIndex).unwrap().exit_epoch = 0;
        }
        state.apply_pending_mutations();
        beacon_store_at(state).0
    }

    fn genesis_fork_version(store: &Store) -> Version {
        store.config().genesis_fork_version
    }

    async fn post(
        store: Store,
        builder: Option<BuilderClient>,
        fee_recipients: FeeRecipients,
        request: Request<Body>,
    ) -> (StatusCode, String) {
        let app = routes()
            .with_state(store)
            .layer(Extension(builder))
            .layer(Extension(fee_recipients));
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    fn json_request(registrations: &[SignedValidatorRegistrationV1]) -> Request<Body> {
        Request::post("/eth/v1/validator/register_validator")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(registrations).unwrap()))
            .unwrap()
    }

    fn client_for(relay: &MockRelay) -> Option<BuilderClient> {
        Some(BuilderClient::new(relay.url.clone(), Duration::from_secs(1), "ethlambda/test").unwrap())
    }

    #[tokio::test]
    async fn known_validators_reach_the_builder_and_set_their_fee_recipients() {
        let store = store_with_exited(&[]);
        let relay = MockRelay::start(genesis_fork_version(&store)).await;
        let registrations = vec![
            signed_registration(0, genesis_fork_version(&store)),
            signed_registration(1, genesis_fork_version(&store)),
        ];
        let fee_recipients = FeeRecipients::default();

        let (status, body) = post(
            store,
            client_for(&relay),
            fee_recipients.clone(),
            json_request(&registrations),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(relay.registrations(), registrations);
        let recipients = fee_recipients.lock().unwrap();
        assert_eq!(recipients.get(&0), Some(&ExecutionAddress::repeat_byte(0x11)));
        assert_eq!(recipients.get(&1), Some(&ExecutionAddress::repeat_byte(0x11)));
    }

    #[tokio::test]
    async fn unknown_and_exited_validators_are_dropped() {
        let store = store_with_exited(&[2]);
        let relay = MockRelay::start(genesis_fork_version(&store)).await;
        let kept = signed_registration(0, genesis_fork_version(&store));
        let exited = signed_registration(2, genesis_fork_version(&store));
        let unknown = signed_registration(VALIDATORS + 10, genesis_fork_version(&store));
        let fee_recipients = FeeRecipients::default();

        let (status, body) = post(
            store,
            client_for(&relay),
            fee_recipients.clone(),
            json_request(&[kept.clone(), exited, unknown]),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(relay.registrations(), [kept]);
        assert_eq!(fee_recipients.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn nothing_left_to_forward_is_a_success_without_a_call() {
        let store = store_with_exited(&[]);
        let relay = MockRelay::start(genesis_fork_version(&store)).await;
        let unknown = signed_registration(VALIDATORS + 10, genesis_fork_version(&store));

        let (status, body) = post(
            store,
            client_for(&relay),
            FeeRecipients::default(),
            json_request(&[unknown]),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(relay.registration_calls(), 0);
    }

    #[tokio::test]
    async fn without_a_builder_the_request_is_a_server_error() {
        let store = store_with_exited(&[]);
        let registration = signed_registration(0, genesis_fork_version(&store));
        let (status, _) = post(
            store,
            None,
            FeeRecipients::default(),
            json_request(&[registration]),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn a_builders_refusal_is_passed_through_as_a_400() {
        let store = store_with_exited(&[]);
        let relay = MockRelay::start(genesis_fork_version(&store)).await;
        let mut forged = signed_registration(0, genesis_fork_version(&store));
        forged.signature = signed_registration(1, genesis_fork_version(&store)).signature;

        let (status, body) = post(
            store,
            client_for(&relay),
            FeeRecipients::default(),
            json_request(&[forged]),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("invalid signature"), "{body}");
    }

    #[tokio::test]
    async fn an_unreachable_builder_is_a_server_error() {
        let store = store_with_exited(&[]);
        let registration = signed_registration(0, genesis_fork_version(&store));
        let builder =
            BuilderClient::new("http://127.0.0.1:1", Duration::from_secs(1), "ethlambda/test").unwrap();
        let (status, _) = post(
            store,
            Some(builder),
            FeeRecipients::default(),
            json_request(&[registration]),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn an_ssz_body_is_accepted() {
        let store = store_with_exited(&[]);
        let relay = MockRelay::start(genesis_fork_version(&store)).await;
        let registrations = vec![signed_registration(3, genesis_fork_version(&store))];
        let list = SignedValidatorRegistrations::try_from(registrations.clone()).unwrap();
        let request = Request::post("/eth/v1/validator/register_validator")
            .header("content-type", "application/octet-stream")
            .body(Body::from(list.to_ssz()))
            .unwrap();

        let (status, body) = post(store, client_for(&relay), FeeRecipients::default(), request).await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(relay.registrations(), registrations);
    }
}
