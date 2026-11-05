//! `POST /eth/v1/validator/register_validator`: a validator client's builder
//! registrations, checked against the head state and forwarded to the
//! builder `--builder` names.
//!
//! Validators that the head state does not hold, or holds as exited, are
//! dropped and counted rather than refused. Exit is judged at the later of
//! the head's epoch and the wall clock's, so a lagging head cannot let an
//! exited validator through: the beacon-APIs say they must
//! not reach the builder, not that the request fails. Each kept
//! registration also becomes its validator's fee recipient, as
//! `prepare_beacon_proposer` would make it, so a block built locally after
//! all still pays the address the validator registered. As in Lighthouse,
//! that holds with no builder configured (the answer is still a 500) and
//! whatever the builder answers. Signatures are not verified here, also as
//! in Lighthouse: the builder verifies them. So only once the builder accepts
//! them are the kept registrations remembered for block production, which
//! asks the builder only for proposers that registered.
//!
//! A validator registered more than once in one request keeps only its
//! newest registration, and an empty request is answered without reading
//! the head state.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Extension, Router};
use ethlambda_storage::Store;
use ethlambda_types::beacon::builder::{
    SignedValidatorRegistrationV1, SignedValidatorRegistrations,
};
use ethlambda_types::beacon::containers::BeaconState;
use ethlambda_types::beacon::primitives::{BlsPubkey, Epoch, ValidatorIndex};
use ethlambda_types::beacon::signing::compute_epoch_at_slot;
use libssz::SszDecode as _;
use tracing::warn;

use super::builder_client::BuilderError;
use super::builder_flow::Builder;
use super::validator::{FeeRecipients, head};
use super::{ApiError, BodyEncoding};
use crate::metrics::inc_builder_registrations;

pub(crate) fn routes() -> Router<Store> {
    // A validator client may send every key it holds at once, which is more
    // than axum's default body limit takes.
    Router::new().route(
        "/eth/v1/validator/register_validator",
        post(post_register_validator).layer(DefaultBodyLimit::max(super::MAX_PUBLISH_BODY_BYTES)),
    )
}

async fn post_register_validator(
    State(store): State<Store>,
    builder: Option<Extension<Arc<Builder>>>,
    Extension(fee_recipients): Extension<FeeRecipients>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let builder = builder.map(|Extension(builder)| builder);
    register(store, builder, fee_recipients, &headers, &body)
        .await
        .map_or_else(IntoResponse::into_response, |()| {
            axum::http::StatusCode::OK.into_response()
        })
}

/// What a validator client hears when this node has no builder to forward to.
const NO_BUILDER: &str = "no builder is configured (--builder)";

async fn register(
    store: Store,
    builder: Option<Arc<Builder>>,
    fee_recipients: FeeRecipients,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(), ApiError> {
    // Decoded first, so a malformed body is a 400 whether or not a builder is
    // configured.
    let registrations = decode(headers, body)?;
    // Nothing to record or forward, so no registry walk: a stream of empty
    // bodies would otherwise tie up the blocking pool the duty endpoints
    // share. Still a 500 without a builder, as any other body is.
    if registrations.is_empty() {
        builder.ok_or(ApiError::Internal(NO_BUILDER))?;
        return Ok(());
    }

    let submitted = registrations.len();
    let registrations = newest_per_validator(registrations);
    inc_builder_registrations("duplicate", (submitted - registrations.len()) as u64);

    // The head-state read and the walk over the whole registry are blocking
    // work, as the duty endpoints' walks are.
    let candidates = registrations.len();
    let (kept, epoch) = tokio::task::spawn_blocking(move || {
        let (_, state) = head(&store)?;
        // Judged at the later of the head's epoch and the wall clock's, so a
        // lagging head cannot let an exited validator through.
        let wall_epoch = compute_epoch_at_slot(super::node::wall_slot(&store));
        let epoch = compute_epoch_at_slot(state.slot()).max(wall_epoch);
        Ok::<_, ApiError>((active_or_pending(&state, registrations, epoch), epoch))
    })
    .await
    .map_err(|_| ApiError::Internal("checking the registrations failed"))??;
    inc_builder_registrations("dropped", (candidates - kept.len()) as u64);

    // Recorded before the builder is even looked for, as Lighthouse records
    // them: they hold with no builder configured and whatever the builder
    // answers.
    {
        let mut recipients = fee_recipients.lock().expect("fee recipient lock poisoned");
        for (index, registration) in &kept {
            recipients.insert(*index, registration.message.fee_recipient);
        }
    }
    let builder = builder.ok_or(ApiError::Internal(NO_BUILDER))?;
    if kept.is_empty() {
        return Ok(());
    }

    let kept: Vec<SignedValidatorRegistrationV1> = kept
        .into_iter()
        .map(|(_, registration)| registration)
        .collect();
    // On its own task: a validator client that hangs up drops this handler,
    // and the forward, its count, its log and the record must complete
    // regardless.
    let forwarded = tokio::spawn(async move {
        let count = kept.len() as u64;
        let result = builder.client.register_validators(&kept).await;
        match &result {
            Ok(()) => {
                inc_builder_registrations("forwarded", count);
                // Remembered only once the builder took them: it verifies
                // their signatures and this node does not, so one it refused
                // (a forged gas limit, say) must not steer this node's bids.
                // At the epoch the filter judged them at, so block production
                // sees them for as long as the validator client keeps sending
                // them.
                builder
                    .registrations
                    .record(kept.iter().map(|registration| &registration.message), epoch);
            }
            Err(err) => {
                inc_builder_registrations("failed", count);
                warn!(%err, count, "Builder did not take the registrations");
            }
        }
        result
    })
    .await
    .map_err(|_| ApiError::Internal("forwarding the registrations failed"))?;
    forwarded.map_err(|err| match err {
        BuilderError::BadRequest(message) => ApiError::BadRequestDetail(message),
        _ => ApiError::Internal("the builder did not take the registrations"),
    })
}

/// The request body: a JSON array, or the SSZ list builder-specs defines.
fn decode(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Vec<SignedValidatorRegistrationV1>, ApiError> {
    match BodyEncoding::from_headers(headers)? {
        BodyEncoding::Ssz => SignedValidatorRegistrations::from_ssz_bytes(body)
            .map(|list| list.to_vec())
            .map_err(|_| ApiError::BadRequest("invalid SSZ registrations")),
        BodyEncoding::Json => serde_json::from_slice(body)
            .map_err(|_| ApiError::BadRequest("invalid JSON registrations")),
    }
}

/// One registration per validator: its newest by `timestamp`, the later one
/// in the request on a tie, which is the one a builder keeps (builder-specs'
/// `process_registration` takes any registration not older than the one it
/// holds). The kept ones stay in request order.
///
/// So one validator repeated many times in a large body is forwarded once,
/// and its fee recipient is the newest registration's, whatever the order.
fn newest_per_validator(
    registrations: Vec<SignedValidatorRegistrationV1>,
) -> Vec<SignedValidatorRegistrationV1> {
    let mut newest: HashMap<BlsPubkey, usize> = HashMap::with_capacity(registrations.len());
    for (position, registration) in registrations.iter().enumerate() {
        let message = &registration.message;
        newest
            .entry(message.pubkey)
            .and_modify(|held| {
                if message.timestamp >= registrations[*held].message.timestamp {
                    *held = position;
                }
            })
            .or_insert(position);
    }
    let mut keep = vec![false; registrations.len()];
    for position in newest.into_values() {
        keep[position] = true;
    }
    registrations
        .into_iter()
        .zip(keep)
        .filter_map(|(registration, keep)| keep.then_some(registration))
        .collect()
}

/// The registrations whose validator `state` holds as active or pending at
/// `epoch` (the later of the head's epoch and the wall clock's), each with its
/// validator index. One pass over the registry, whatever the number of
/// registrations.
///
/// Future improvement: that pass happens on every call, over the whole
/// registry, with nothing bounding how many run at once. A pubkey-to-index
/// map kept beside the head state would make it one lookup per registration.
fn active_or_pending(
    state: &BeaconState,
    registrations: Vec<SignedValidatorRegistrationV1>,
    epoch: Epoch,
) -> Vec<(ValidatorIndex, SignedValidatorRegistrationV1)> {
    let wanted: HashSet<BlsPubkey> = registrations
        .iter()
        .map(|registration| registration.message.pubkey)
        .collect();
    // Active or pending is exactly "not yet exited": a pending validator's
    // exit epoch is still FAR_FUTURE_EPOCH.
    let indices: HashMap<BlsPubkey, ValidatorIndex> = state
        .iter_validators()
        .enumerate()
        .filter(|(_, validator)| epoch < validator.exit_epoch && wanted.contains(&validator.pubkey))
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
    use ethlambda_blockchain::SyncStatusController;
    use ethlambda_blockchain::metrics::SyncStatus;
    use ethlambda_state_transition::beacon::helpers::test_state::with_signing_validators_at;
    use ethlambda_types::beacon::constants::FAR_FUTURE_EPOCH;
    use ethlambda_types::beacon::fork::ForkName;
    use ethlambda_types::beacon::primitives::{ExecutionAddress, Version};
    use http_body_util::BodyExt as _;
    use libssz::SszEncode as _;
    use tower::ServiceExt as _;

    use super::*;
    use crate::FallbackThresholds;
    use crate::beacon::builder_client::BuilderClient;
    use crate::beacon::builder_client::mock_relay::{
        MockRelay, sign_registration, signed_registration, unreachable_url,
    };
    use crate::test_utils::{beacon_store_at, beacon_store_at_clock};

    const VALIDATORS: usize = 8;

    /// A store whose head state holds `VALIDATORS` active validators, minus
    /// the indices in `exited`, which have already left.
    fn store_with_exited(exited: &[usize]) -> Store {
        let mut state = with_signing_validators_at(ForkName::Fulu, VALIDATORS);
        for &index in exited {
            state
                .validator_mut(index as ValidatorIndex)
                .unwrap()
                .exit_epoch = 0;
        }
        state.apply_pending_mutations();
        beacon_store_at(state).0
    }

    fn genesis_fork_version(store: &Store) -> Version {
        store.config().genesis_fork_version
    }

    async fn post(
        store: Store,
        builder: Option<Arc<Builder>>,
        fee_recipients: FeeRecipients,
        request: Request<Body>,
    ) -> (StatusCode, String) {
        let app = routes().with_state(store).layer(Extension(fee_recipients));
        let app = match builder {
            Some(builder) => app.layer(Extension(builder)),
            None => app,
        };
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

    fn builder_for(client: BuilderClient) -> Arc<Builder> {
        Arc::new(Builder::new(
            client,
            FallbackThresholds::DEFAULT,
            SyncStatusController::new(SyncStatus::Synced),
        ))
    }

    /// A builder on a local port nothing listens on.
    fn unreachable_builder() -> Arc<Builder> {
        let client =
            BuilderClient::new(unreachable_url(), Duration::from_secs(1), "ethlambda/test")
                .unwrap();
        builder_for(client)
    }

    fn client_for(relay: &MockRelay) -> Option<Arc<Builder>> {
        let client =
            BuilderClient::new(relay.url.clone(), Duration::from_secs(1), "ethlambda/test")
                .unwrap();
        Some(builder_for(client))
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
        assert_eq!(
            recipients.get(&0),
            Some(&ExecutionAddress::repeat_byte(0x11))
        );
        assert_eq!(
            recipients.get(&1),
            Some(&ExecutionAddress::repeat_byte(0x11))
        );
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
        let builder = unreachable_builder();
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

        let (status, body) =
            post(store, client_for(&relay), FeeRecipients::default(), request).await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(relay.registrations(), registrations);
    }

    /// A store whose validator `index` is pending: its activation is in the
    /// future and its exit is `FAR_FUTURE_EPOCH`.
    ///
    /// The wall clock is pinned to slot 0, as the head is. `beacon_store_at`
    /// puts it at mainnet's current epoch instead, where an activation at
    /// epoch 1000 is long past and the validator would be active, not
    /// pending.
    fn store_with_pending(index: usize) -> Store {
        let mut state = with_signing_validators_at(ForkName::Fulu, VALIDATORS);
        let validator = state.validator_mut(index as ValidatorIndex).unwrap();
        validator.activation_epoch = 1_000;
        validator.exit_epoch = FAR_FUTURE_EPOCH;
        state.apply_pending_mutations();
        beacon_store_at_clock(state, 0).0
    }

    #[tokio::test]
    async fn a_pending_validator_is_kept() {
        let store = store_with_pending(4);
        let relay = MockRelay::start(genesis_fork_version(&store)).await;
        let pending = signed_registration(4, genesis_fork_version(&store));

        let (status, body) = post(
            store,
            client_for(&relay),
            FeeRecipients::default(),
            json_request(std::slice::from_ref(&pending)),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(relay.registrations(), [pending]);
    }

    #[tokio::test]
    async fn fee_recipients_are_set_even_when_the_builder_refuses() {
        let store = store_with_exited(&[]);
        let relay = MockRelay::start(genesis_fork_version(&store)).await;
        let mut forged = signed_registration(0, genesis_fork_version(&store));
        forged.signature = signed_registration(1, genesis_fork_version(&store)).signature;
        let fee_recipients = FeeRecipients::default();

        let (status, _) = post(
            store,
            client_for(&relay),
            fee_recipients.clone(),
            json_request(&[forged]),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            fee_recipients.lock().unwrap().get(&0),
            Some(&ExecutionAddress::repeat_byte(0x11))
        );
    }

    #[tokio::test]
    async fn fee_recipients_are_set_even_when_the_builder_is_unreachable() {
        let store = store_with_exited(&[]);
        let registration = signed_registration(0, genesis_fork_version(&store));
        let builder = unreachable_builder();
        let fee_recipients = FeeRecipients::default();

        let (status, _) = post(
            store,
            Some(builder.clone()),
            fee_recipients.clone(),
            json_request(std::slice::from_ref(&registration)),
        )
        .await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            fee_recipients.lock().unwrap().get(&0),
            Some(&ExecutionAddress::repeat_byte(0x11))
        );
        // The builder never took it, so block production never asks for it.
        assert_eq!(
            builder.registrations.get(&registration.message.pubkey, 0),
            None
        );
    }

    /// The review's attack: a registration under a later timestamp with a
    /// forged gas limit, which the builder refuses since its signature does
    /// not verify. It must not replace the one the builder accepted, or every
    /// real bid would fail the gas-limit check.
    #[tokio::test]
    async fn a_registration_the_builder_refuses_is_not_remembered() {
        let store = store_with_exited(&[]);
        let relay = MockRelay::start(genesis_fork_version(&store)).await;
        let builder = client_for(&relay).unwrap();
        let genuine = signed_registration(0, genesis_fork_version(&store));
        let (status, body) = post(
            store.clone(),
            Some(builder.clone()),
            FeeRecipients::default(),
            json_request(std::slice::from_ref(&genuine)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let mut forged = genuine.clone();
        forged.message.gas_limit = 1;
        forged.message.timestamp += 1;
        let (status, _) = post(
            store,
            Some(builder.clone()),
            FeeRecipients::default(),
            json_request(&[forged]),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            builder.registrations.get(&genuine.message.pubkey, 0),
            Some(genuine.message)
        );
    }

    #[tokio::test]
    async fn kept_registrations_are_remembered_for_block_production() {
        let store = store_with_exited(&[]);
        let relay = MockRelay::start(genesis_fork_version(&store)).await;
        let builder = client_for(&relay).unwrap();
        let kept = signed_registration(0, genesis_fork_version(&store));
        let unknown = signed_registration(VALIDATORS + 10, genesis_fork_version(&store));

        let (status, body) = post(
            store,
            Some(builder.clone()),
            FeeRecipients::default(),
            json_request(&[kept.clone(), unknown.clone()]),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            builder.registrations.get(&kept.message.pubkey, 0),
            Some(kept.message)
        );
        assert_eq!(builder.registrations.get(&unknown.message.pubkey, 0), None);
    }

    #[tokio::test]
    async fn fee_recipients_are_set_even_without_a_builder() {
        let store = store_with_exited(&[]);
        let registration = signed_registration(0, genesis_fork_version(&store));
        let fee_recipients = FeeRecipients::default();

        let (status, _) = post(
            store,
            None,
            fee_recipients.clone(),
            json_request(&[registration]),
        )
        .await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            fee_recipients.lock().unwrap().get(&0),
            Some(&ExecutionAddress::repeat_byte(0x11))
        );
    }

    #[tokio::test]
    async fn a_malformed_body_is_a_400() {
        let store = store_with_exited(&[]);
        let request = Request::post("/eth/v1/validator/register_validator")
            .header("content-type", "application/json")
            .body(Body::from("not json"))
            .unwrap();

        let (status, body) = post(store, None, FeeRecipients::default(), request).await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    }

    #[tokio::test]
    async fn a_content_type_other_than_json_or_ssz_is_a_415() {
        let store = store_with_exited(&[]);
        let request = Request::post("/eth/v1/validator/register_validator")
            .header("content-type", "text/plain")
            .body(Body::from("[]"))
            .unwrap();

        let (status, body) = post(store, None, FeeRecipients::default(), request).await;

        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{body}");
    }

    #[tokio::test]
    async fn an_exit_the_wall_clock_has_passed_drops_the_validator() {
        // The head is at epoch 0 and the clock at epoch 10: an exit at epoch
        // 5 is in the future for the head and in the past for the clock.
        let mut state = with_signing_validators_at(ForkName::Fulu, VALIDATORS);
        state.validator_mut(2).unwrap().exit_epoch = 5;
        state.apply_pending_mutations();
        let (store, _) = crate::test_utils::beacon_store_at_clock(state, 32 * 10);
        let relay = MockRelay::start(genesis_fork_version(&store)).await;
        let kept = signed_registration(0, genesis_fork_version(&store));
        let exited = signed_registration(2, genesis_fork_version(&store));

        let (status, body) = post(
            store,
            client_for(&relay),
            FeeRecipients::default(),
            json_request(&[kept.clone(), exited]),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(relay.registrations(), [kept]);
    }

    /// Validator `index`'s registration at `timestamp`, paying an address of
    /// `fee_byte` repeated, signed so the relay takes it.
    fn registration_at(
        store: &Store,
        index: usize,
        timestamp: u64,
        fee_byte: u8,
    ) -> SignedValidatorRegistrationV1 {
        let version = genesis_fork_version(store);
        let mut message = signed_registration(index, version).message;
        message.timestamp = timestamp;
        message.fee_recipient = ExecutionAddress::repeat_byte(fee_byte);
        sign_registration(index, message, version)
    }

    #[tokio::test]
    async fn only_the_newest_registration_of_a_validator_is_kept() {
        let store = store_with_exited(&[]);
        let relay = MockRelay::start(genesis_fork_version(&store)).await;
        let oldest = registration_at(&store, 0, 100, 0x22);
        let newest = registration_at(&store, 0, 300, 0x33);
        let older = registration_at(&store, 0, 200, 0x44);
        let other = signed_registration(1, genesis_fork_version(&store));
        let fee_recipients = FeeRecipients::default();

        let (status, body) = post(
            store,
            client_for(&relay),
            fee_recipients.clone(),
            json_request(&[oldest, newest.clone(), older, other.clone()]),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(relay.registrations(), [newest, other]);
        assert_eq!(
            fee_recipients.lock().unwrap().get(&0),
            Some(&ExecutionAddress::repeat_byte(0x33))
        );
    }

    #[tokio::test]
    async fn on_a_timestamp_tie_the_later_registration_wins() {
        let store = store_with_exited(&[]);
        let relay = MockRelay::start(genesis_fork_version(&store)).await;
        let first = registration_at(&store, 0, 100, 0x22);
        let second = registration_at(&store, 0, 100, 0x33);

        let (status, body) = post(
            store,
            client_for(&relay),
            FeeRecipients::default(),
            json_request(&[first, second.clone()]),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(relay.registrations(), [second]);
    }

    #[tokio::test]
    async fn an_empty_list_is_a_success_without_a_call() {
        let store = store_with_exited(&[]);
        let relay = MockRelay::start(genesis_fork_version(&store)).await;

        let (status, body) = post(
            store,
            client_for(&relay),
            FeeRecipients::default(),
            json_request(&[]),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(relay.registration_calls(), 0);
    }

    #[tokio::test]
    async fn an_empty_list_without_a_builder_is_a_server_error() {
        let store = store_with_exited(&[]);
        let (status, _) = post(store, None, FeeRecipients::default(), json_request(&[])).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn a_slashed_validator_that_has_not_exited_is_kept() {
        // Slashing sets an exit epoch; until the clock reaches it the
        // validator is `active_slashed`, which builder-specs counts as active.
        let mut state = with_signing_validators_at(ForkName::Fulu, VALIDATORS);
        let validator = state.validator_mut(5).unwrap();
        validator.slashed = true;
        validator.exit_epoch = 10;
        validator.withdrawable_epoch = 8_192;
        state.apply_pending_mutations();
        let (store, _) = beacon_store_at_clock(state, 0);
        let relay = MockRelay::start(genesis_fork_version(&store)).await;
        let slashed = signed_registration(5, genesis_fork_version(&store));

        let (status, body) = post(
            store,
            client_for(&relay),
            FeeRecipients::default(),
            json_request(std::slice::from_ref(&slashed)),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(relay.registrations(), [slashed]);
    }

    #[tokio::test]
    async fn the_last_fee_recipient_written_wins() {
        let store = store_with_exited(&[]);
        let relay = MockRelay::start(genesis_fork_version(&store)).await;
        let registration = signed_registration(0, genesis_fork_version(&store));
        let fee_recipients = FeeRecipients::default();
        let app = crate::beacon::validator::routes()
            .merge(routes())
            .with_state(store)
            .layer(Extension(client_for(&relay).unwrap()))
            .layer(Extension(fee_recipients.clone()));
        let prepare = || {
            let body = serde_json::json!([
                { "validator_index": "0", "fee_recipient": format!("0x{}", "ab".repeat(20)) }
            ]);
            Request::post("/eth/v1/validator/prepare_beacon_proposer")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        };
        let recipient = || fee_recipients.lock().unwrap().get(&0).copied();
        let prepared = ExecutionAddress::repeat_byte(0xab);
        let registered = ExecutionAddress::repeat_byte(0x11);

        let response = app.clone().oneshot(prepare()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(recipient(), Some(prepared));

        let request = json_request(&[registration]);
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(recipient(), Some(registered));

        let response = app.oneshot(prepare()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(recipient(), Some(prepared));
    }
}
