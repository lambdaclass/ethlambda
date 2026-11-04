//! The sync committee endpoints of the Beacon API:
//! `POST /eth/v1/beacon/pool/sync_committees` (`submitPoolSyncCommitteeSignatures`),
//! `GET /eth/v1/validator/sync_committee_contribution`
//! (`produceSyncCommitteeContribution`),
//! `POST /eth/v1/validator/contribution_and_proofs` (`publishContributionAndProofs`)
//! and `POST /eth/v1/validator/sync_committee_subscriptions`
//! (`prepareSyncCommitteeSubnets`).
//!
//! All four are JSON only: beacon-APIs lists no SSZ body for any of them.
//!
//! Submissions are checked with the same rules this node applies to its peers'
//! gossip (`gossip::sync_committee`) before they are published, since a peer
//! that relays invalid messages is scored down. They are also pooled here,
//! because gossip never echoes a node its own messages and a block this node
//! proposes, or a contribution it serves, must include its validators' own.
//! None of it reaches the chain actor: sync committee votes have no
//! fork-choice effect.

use std::collections::BTreeMap;

use axum::{
    Extension, Router,
    body::Bytes,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use ethlambda_blockchain::{SyncStatusController, metrics::SyncStatus};
use ethlambda_network_api::RpcToP2PRef;
use ethlambda_state_transition::beacon::{
    gossip::{
        Outcome,
        sync_committee::{
            SeenSyncContributions, check_contribution, check_submitted_message,
            contribution_cheap_checks,
        },
    },
    helpers::altair::compute_sync_committee_period,
    sync_committee_pool::SharedSyncCommitteePool,
};
use ethlambda_storage::Store;
use ethlambda_types::beacon::{
    constants::SYNC_COMMITTEE_SUBNET_COUNT,
    containers::altair::{
        SYNC_SUBCOMMITTEE_SIZE, SignedContributionAndProof, SyncCommitteeMessage,
    },
    preset,
    primitives::{Epoch, Root, Slot},
    signing::compute_epoch_at_slot,
};
use serde::{Deserialize, Deserializer, Serialize};
use tracing::{debug, warn};

use crate::beacon::{ApiError, node::wall_slot, validator::head};
use crate::shared::optimistic::block_is_optimistic;

pub(crate) fn routes() -> Router<Store> {
    Router::new()
        .route(
            "/eth/v1/beacon/pool/sync_committees",
            post(post_pool_sync_committees),
        )
        .route(
            "/eth/v1/validator/sync_committee_contribution",
            get(get_sync_committee_contribution),
        )
        .route(
            "/eth/v1/validator/contribution_and_proofs",
            post(post_contribution_and_proofs),
        )
        .route(
            "/eth/v1/validator/sync_committee_subscriptions",
            post(post_sync_committee_subscriptions),
        )
}

/// One rejected item, in the Beacon API's `IndexedErrorMessage` shape: its
/// position in the submitted array, and why.
#[derive(Debug, Serialize)]
struct Failure {
    index: usize,
    message: String,
}

/// `200` when nothing failed, else the Beacon API's `IndexedErrorMessage`
/// naming each failed item by position; the rest were still published.
fn batch_response(failures: Vec<Failure>, message: &'static str) -> Response {
    if failures.is_empty() {
        return StatusCode::OK.into_response();
    }
    let body = serde_json::json!({ "code": 400, "message": message, "failures": failures });
    let mut response = crate::json_response(body);
    *response.status_mut() = StatusCode::BAD_REQUEST;
    response
}

/// An outcome's `"{outcome}: {reason}"` text, for a failure entry.
fn describe(outcome: &Outcome) -> String {
    let (kind, reason) = outcome.labels();
    format!("{kind}: {reason}")
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

/// `POST /eth/v1/beacon/pool/sync_committees`.
///
/// Every message is checked against the head state (the clock, the validator's
/// seats in the committee its slot names, its signature), pooled, then
/// published on each subnet its validator sits on. Not gated on syncing, like
/// the attestation submission: a node that is behind simply refuses what it
/// cannot check. The checks run on a blocking thread, one BLS verification
/// per message.
async fn post_pool_sync_committees(
    State(store): State<Store>,
    Extension(p2p): Extension<RpcToP2PRef>,
    Extension(pool): Extension<SharedSyncCommitteePool>,
    body: Bytes,
) -> Response {
    let Ok(messages) = serde_json::from_slice::<Vec<SyncCommitteeMessage>>(&body) else {
        return ApiError::BadRequest("invalid request body").into_response();
    };
    let batch = tokio::task::spawn_blocking(move || -> Result<Vec<Failure>, ApiError> {
        let (_head_root, state) = head(&store)?;
        let config = store.config();
        let now_ms = now_ms();
        let mut failures = Vec::new();
        for (index, message) in messages.into_iter().enumerate() {
            let (slot, validator) = (message.slot, message.validator_index);
            let seats = match check_submitted_message(&state, &config, &message, now_ms) {
                Ok(seats) => seats,
                Err(outcome) => {
                    let reason = describe(&outcome);
                    warn!(%slot, validator, %reason, "Refused a submitted sync committee message");
                    failures.push(Failure {
                        index,
                        message: reason,
                    });
                    continue;
                }
            };
            pool.lock()
                .expect("sync committee pool lock poisoned")
                .insert_message(&message, &seats);
            // Every distinct subnet the validator sits on, ascending.
            let mut subnets: Vec<u64> = seats.iter().map(|&(subnet, _)| subnet).collect();
            subnets.sort_unstable();
            subnets.dedup();
            match p2p.publish_sync_committee_message(subnets, message) {
                Ok(()) => debug!(%slot, validator, "Accepted sync committee message for gossip"),
                Err(_) => failures.push(Failure {
                    index,
                    message: "the network actor is not running".to_owned(),
                }),
            }
        }
        Ok(failures)
    })
    .await;
    match batch {
        Ok(Ok(failures)) => batch_response(
            failures,
            "some sync committee messages failed validation and were not published",
        ),
        Ok(Err(err)) => err.into_response(),
        Err(_) => ApiError::Internal("checking the messages failed").into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct ContributionQuery {
    slot: Slot,
    subcommittee_index: u64,
    beacon_block_root: Root,
}

/// `GET /eth/v1/validator/sync_committee_contribution`: the best contribution
/// this node can assemble from what it has pooled for `(slot,
/// beacon_block_root)` on one subcommittee, a 404 when it has nothing.
///
/// `503` while syncing or when the voted block is optimistic: an aggregator
/// must not sign over a contribution this node cannot vouch for (optimistic
/// sync's "Participating in Sync Committees" rule), and a validator client
/// reads the status as "try the next node".
async fn get_sync_committee_contribution(
    State(store): State<Store>,
    Extension(pool): Extension<SharedSyncCommitteePool>,
    Extension(sync_status): Extension<SyncStatusController>,
    Query(query): Query<ContributionQuery>,
) -> Response {
    if query.subcommittee_index >= SYNC_COMMITTEE_SUBNET_COUNT as u64 {
        return ApiError::BadRequest("subcommittee_index is out of range").into_response();
    }
    if sync_status.get() == SyncStatus::Syncing {
        return ApiError::ServiceUnavailable("node is syncing").into_response();
    }
    if block_is_optimistic(&store, query.beacon_block_root) {
        return ApiError::ServiceUnavailable("the block is unknown or optimistic").into_response();
    }
    let contribution = pool
        .lock()
        .expect("sync committee pool lock poisoned")
        .contribution(
            query.slot,
            query.beacon_block_root,
            query.subcommittee_index,
        );
    match contribution {
        Some(contribution) => crate::json_response(serde_json::json!({ "data": contribution })),
        None => ApiError::NotFound("no sync committee messages to aggregate").into_response(),
    }
}

/// `POST /eth/v1/validator/contribution_and_proofs`: signed contributions,
/// validated with the `sync_committee_contribution_and_proof` gossip rules
/// (`gossip::sync_committee`), pooled for block production, then gossiped.
///
/// Each is checked against a fresh seen cache rather than P2P's, which holds
/// what peers sent: a node never receives its own messages, so it would say
/// nothing about these, and the validator client already signs one
/// contribution per aggregator and subnet.
async fn post_contribution_and_proofs(
    State(store): State<Store>,
    Extension(p2p): Extension<RpcToP2PRef>,
    Extension(pool): Extension<SharedSyncCommitteePool>,
    body: Bytes,
) -> Response {
    let Ok(contributions) = serde_json::from_slice::<Vec<SignedContributionAndProof>>(&body) else {
        return ApiError::BadRequest("invalid request body").into_response();
    };
    let batch = tokio::task::spawn_blocking(move || -> Result<Vec<Failure>, ApiError> {
        let (_head_root, state) = head(&store)?;
        let config = store.config();
        let now_ms = now_ms();
        let capacity = std::num::NonZeroUsize::MIN;
        let mut failures = Vec::new();
        for (index, signed) in contributions.into_iter().enumerate() {
            let slot = signed.message.contribution.slot;
            let aggregator = signed.message.aggregator_index;
            let seen = SeenSyncContributions::new(capacity, capacity);
            let outcome = contribution_cheap_checks(&seen, &store, &signed, now_ms).map_or_else(
                |outcome| outcome,
                |()| check_contribution(&state, &config, &signed),
            );
            if outcome != Outcome::Accept {
                let reason = describe(&outcome);
                warn!(%slot, aggregator, %reason, "Refused a submitted sync contribution");
                failures.push(Failure {
                    index,
                    message: reason,
                });
                continue;
            }
            pool.lock()
                .expect("sync committee pool lock poisoned")
                .insert_contribution(signed.message.contribution.clone());
            match p2p.publish_sync_committee_contribution(signed) {
                Ok(()) => debug!(%slot, aggregator, "Accepted sync contribution for gossip"),
                Err(_) => failures.push(Failure {
                    index,
                    message: "the network actor is not running".to_owned(),
                }),
            }
        }
        Ok(failures)
    })
    .await;
    match batch {
        Ok(Ok(failures)) => batch_response(
            failures,
            "some sync contributions failed validation and were not published",
        ),
        Ok(Err(err)) => err.into_response(),
        Err(_) => ApiError::Internal("checking the contributions failed").into_response(),
    }
}

/// An integer the validator client may quote or not. beacon-APIs quotes
/// every integer, and clients differ in how strictly they follow it.
#[derive(Debug, Clone, Copy)]
struct Flexible(u64);

impl<'de> Deserialize<'de> for Flexible {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = Flexible;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an unsigned integer, quoted or not")
            }
            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Flexible, E> {
                Ok(Flexible(value))
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Flexible, E> {
                value.trim().parse().map(Flexible).map_err(E::custom)
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

/// One entry of `prepareSyncCommitteeSubnets`' body. `validator_index` is
/// part of the request but this node has no use for it: the positions say
/// which subnets to join.
#[derive(Debug, Deserialize)]
struct SyncCommitteeSubscription {
    sync_committee_indices: Vec<Flexible>,
    until_epoch: Flexible,
}

/// `POST /eth/v1/validator/sync_committee_subscriptions`: join the subnets a
/// validator's committee positions sit on, until the epoch given.
///
/// The subnet of a position is `index / SYNC_SUBCOMMITTEE_SIZE`. Entries are
/// grouped by subnet keeping the latest `until_epoch`, which is clamped to the
/// end of the next sync committee period: a longer request would keep the node
/// validating a subnet's gossip well past anything a duty lookahead can need.
/// A position outside the committee is a `400` and nothing is joined.
async fn post_sync_committee_subscriptions(
    State(store): State<Store>,
    Extension(p2p): Extension<RpcToP2PRef>,
    body: Bytes,
) -> Response {
    let Ok(subscriptions) = serde_json::from_slice::<Vec<SyncCommitteeSubscription>>(&body) else {
        return ApiError::BadRequest("invalid request body").into_response();
    };
    let wall_epoch: Epoch = compute_epoch_at_slot(wall_slot(&store));
    let clamp = (compute_sync_committee_period(wall_epoch) + 2)
        .saturating_mul(preset::EPOCHS_PER_SYNC_COMMITTEE_PERIOD);

    let mut until_by_subnet: BTreeMap<u64, Epoch> = BTreeMap::new();
    for subscription in subscriptions {
        let until = subscription.until_epoch.0.min(clamp);
        for Flexible(position) in subscription.sync_committee_indices {
            if position >= preset::SYNC_COMMITTEE_SIZE as u64 {
                return ApiError::BadRequest("sync committee index is out of range")
                    .into_response();
            }
            let subnet = position / SYNC_SUBCOMMITTEE_SIZE as u64;
            let held = until_by_subnet.entry(subnet).or_insert(until);
            *held = (*held).max(until);
        }
    }
    if until_by_subnet.is_empty() {
        return StatusCode::OK.into_response();
    }
    let pairs: Vec<(u64, u64)> = until_by_subnet.into_iter().collect();
    match p2p.subscribe_sync_committee_subnets(pairs) {
        Ok(()) => StatusCode::OK.into_response(),
        Err(_) => ApiError::Internal("the network actor is not running").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::test_utils::RecordingNetwork;
    use axum::{body::Body, http::Request};
    use ethlambda_state_transition::beacon::{
        bls,
        helpers::{
            sync_committee::{
                contribution_and_proof_signing_root, is_sync_committee_aggregator,
                sync_committee_for_slot, sync_committee_message_signing_root, sync_committee_seats,
                sync_selection_proof_signing_root,
            },
            test_state::{secret_key_for, sign_for, with_signing_validators_at},
        },
    };
    use ethlambda_types::beacon::{
        config::Config,
        containers::{
            BeaconState,
            altair::{ContributionAndProof, SyncCommittee, SyncCommitteeContribution},
        },
        fork::ForkName,
        primitives::{BlsPubkey, ValidatorIndex},
        signing::compute_start_slot_at_epoch,
    };
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    /// The registry is larger than the 64 validators the committees are drawn
    /// from, so the rest are not members.
    const VALIDATORS: usize = 80;
    const MEMBERS: usize = 64;

    struct Fixture {
        store: Store,
        state: BeaconState,
        head_root: Root,
        network: Arc<RecordingNetwork>,
        pool: SharedSyncCommitteePool,
        sync_status: SyncStatusController,
    }

    /// A fulu head in the current wall-clock epoch with real sync committees:
    /// position `p` of the current committee is validator `p % MEMBERS`, of the
    /// next one validator `(p + 1) % MEMBERS`. Each member therefore holds
    /// several seats, spread over every subnet.
    fn fixture() -> Fixture {
        let mut state = with_signing_validators_at(ForkName::Fulu, VALIDATORS);
        let committee = |shift: usize| SyncCommittee {
            pubkeys: (0..preset::SYNC_COMMITTEE_SIZE)
                .map(|position| {
                    let index = (position + shift) % MEMBERS;
                    BlsPubkey(secret_key_for(index).sk_to_pk().to_bytes())
                })
                .collect::<Vec<_>>()
                .try_into()
                .expect("built at the committee's exact length"),
            aggregate_pubkey: Default::default(),
        };
        let (current, next) = state.sync_committees_mut().expect("fulu has committees");
        *current = committee(0);
        *next = committee(1);
        state.apply_pending_mutations();

        let config = Config::mainnet();
        let (probe, _) = crate::test_utils::beacon_store_with_config(state.clone(), config.clone());
        let wall_epoch = compute_epoch_at_slot(wall_slot(&probe));
        let BeaconState::Fulu(fulu) = &mut state else {
            unreachable!("built as fulu")
        };
        fulu.slot = compute_start_slot_at_epoch(wall_epoch);
        let (store, head_root) = crate::test_utils::beacon_store_with_config(state.clone(), config);
        Fixture {
            store,
            state,
            head_root,
            network: Arc::new(RecordingNetwork::default()),
            pool: SharedSyncCommitteePool::default(),
            sync_status: SyncStatusController::new(SyncStatus::Synced),
        }
    }

    /// The wall slot, once at least a second of it is left, so a request does
    /// not straddle a slot boundary.
    async fn current_slot(store: &Store) -> Slot {
        let config = store.config();
        let into_slot_ms =
            now_ms().saturating_sub(config.genesis_time_ms()) % config.slot_duration_ms;
        if into_slot_ms + 1_000 > config.slot_duration_ms {
            tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
        }
        wall_slot(store)
    }

    fn app(fixture: &Fixture) -> Router {
        let network: RpcToP2PRef = fixture.network.clone();
        routes()
            .with_state(fixture.store.clone())
            .layer(Extension(network))
            .layer(Extension(fixture.pool.clone()))
            .layer(Extension(fixture.sync_status.clone()))
    }

    async fn send(app: Router, request: Request<Body>) -> (StatusCode, serde_json::Value) {
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json = if body.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&body).unwrap()
        };
        (status, json)
    }

    async fn post_json(
        fixture: &Fixture,
        uri: &str,
        body: Vec<u8>,
    ) -> (StatusCode, serde_json::Value) {
        let request = Request::post(uri)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        send(app(fixture), request).await
    }

    async fn submit(
        fixture: &Fixture,
        messages: &[SyncCommitteeMessage],
    ) -> (StatusCode, serde_json::Value) {
        let body = serde_json::to_vec(messages).unwrap();
        post_json(fixture, "/eth/v1/beacon/pool/sync_committees", body).await
    }

    /// `validator`'s correctly signed message for `slot` over the head.
    fn message(fixture: &Fixture, validator: ValidatorIndex, slot: Slot) -> SyncCommitteeMessage {
        let signing_root = sync_committee_message_signing_root(
            &fixture.store.config(),
            fixture.state.genesis_validators_root(),
            slot,
            fixture.head_root,
        );
        SyncCommitteeMessage {
            slot,
            beacon_block_root: fixture.head_root,
            validator_index: validator,
            signature: sign_for(validator as usize, signing_root),
        }
    }

    /// Every seat `validator` holds in the committee that signs at `slot`.
    fn seats_of(fixture: &Fixture, validator: ValidatorIndex, slot: Slot) -> Vec<(u64, usize)> {
        let pubkey = fixture.state.validator(validator).unwrap().pubkey;
        let committee = sync_committee_for_slot(&fixture.state, slot).unwrap();
        sync_committee_seats(committee, &pubkey)
    }

    fn subnets_of(seats: &[(u64, usize)]) -> Vec<u64> {
        let mut subnets: Vec<u64> = seats.iter().map(|&(subnet, _)| subnet).collect();
        subnets.dedup();
        subnets
    }

    #[tokio::test]
    async fn a_valid_message_is_pooled_and_published_on_every_subnet_of_its_seats() {
        let fixture = fixture();
        let slot = current_slot(&fixture.store).await;
        let message = message(&fixture, 3, slot);
        let (status, _) = submit(&fixture, std::slice::from_ref(&message)).await;
        assert_eq!(status, StatusCode::OK);

        let seats = seats_of(&fixture, 3, slot);
        let published = fixture.network.sync_messages.lock().unwrap();
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].0, subnets_of(&seats));
        assert!(
            published[0].0.len() > 1,
            "the fixture spreads seats over subnets"
        );
        assert_eq!(published[0].1, message);

        let pool = fixture.pool.lock().unwrap();
        for &(subnet, position) in &seats {
            let held = pool
                .contribution(slot, fixture.head_root, subnet)
                .expect("the message is pooled on every subnet it sits on");
            assert!(held.aggregation_bits.get(position).unwrap());
        }
    }

    #[tokio::test]
    async fn refused_messages_are_reported_by_position_and_not_published() {
        let fixture = fixture();
        let slot = current_slot(&fixture.store).await;
        let mut forged = message(&fixture, 3, slot);
        forged.signature = message(&fixture, 4, slot).signature;
        let stale = message(&fixture, 5, slot - 3);
        let outsider = message(&fixture, MEMBERS as u64 + 1, slot);

        for (refused, expected) in [
            (forged, "bad_signature"),
            (stale, "not_current_slot"),
            (outsider, "not_in_committee"),
        ] {
            let (status, json) = submit(&fixture, &[refused]).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(json["code"], 400);
            assert_eq!(json["failures"][0]["index"], 0);
            let text = json["failures"][0]["message"].as_str().unwrap();
            assert!(text.contains(expected), "{text} should name {expected}");
        }
        assert!(fixture.network.sync_messages.lock().unwrap().is_empty());
        assert!(
            fixture
                .pool
                .lock()
                .unwrap()
                .contribution(slot, fixture.head_root, 0)
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_malformed_body_is_a_400_without_failures() {
        let fixture = fixture();
        let (status, json) = post_json(
            &fixture,
            "/eth/v1/beacon/pool/sync_committees",
            b"{\"not\": \"a list\"}".to_vec(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["code"], 400);
        assert!(json.get("failures").is_none());
    }

    #[tokio::test]
    async fn a_mixed_batch_publishes_only_the_valid_entries() {
        let fixture = fixture();
        let slot = current_slot(&fixture.store).await;
        let mut bad = message(&fixture, 1, slot);
        bad.signature = message(&fixture, 2, slot).signature;
        let good = message(&fixture, 6, slot);
        let (status, json) = submit(&fixture, &[bad, good.clone()]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let failures = json["failures"].as_array().unwrap();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0]["index"], 0);
        let published = fixture.network.sync_messages.lock().unwrap();
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].1, good);
    }

    async fn get_contribution(
        fixture: &Fixture,
        slot: Slot,
        subcommittee: u64,
        root: Root,
    ) -> (StatusCode, serde_json::Value) {
        let uri = format!(
            "/eth/v1/validator/sync_committee_contribution?slot={slot}&subcommittee_index={subcommittee}&beacon_block_root={root}"
        );
        send(app(fixture), Request::get(uri).body(Body::empty()).unwrap()).await
    }

    #[tokio::test]
    async fn a_contribution_is_built_from_pooled_messages_and_verifies() {
        let fixture = fixture();
        let slot = current_slot(&fixture.store).await;
        let validators = [3u64, 9, 20];
        let messages: Vec<_> = validators
            .iter()
            .map(|&validator| message(&fixture, validator, slot))
            .collect();
        let (status, _) = submit(&fixture, &messages).await;
        assert_eq!(status, StatusCode::OK);

        let subnet = 1;
        let (status, json) = get_contribution(&fixture, slot, subnet, fixture.head_root).await;
        assert_eq!(status, StatusCode::OK);
        assert!(json.get("version").is_none());
        let contribution: SyncCommitteeContribution =
            serde_json::from_value(json["data"].clone()).unwrap();
        assert_eq!(contribution.slot, slot);
        assert_eq!(contribution.subcommittee_index, subnet);
        assert_eq!(contribution.beacon_block_root, fixture.head_root);

        let mut expected: Vec<usize> = validators
            .iter()
            .flat_map(|&validator| seats_of(&fixture, validator, slot))
            .filter(|&(seat_subnet, _)| seat_subnet == subnet)
            .map(|(_, position)| position)
            .collect();
        expected.sort_unstable();
        let set: Vec<usize> = (0..SYNC_SUBCOMMITTEE_SIZE)
            .filter(|&position| contribution.aggregation_bits.get(position).unwrap())
            .collect();
        assert_eq!(set, expected);

        let committee = sync_committee_for_slot(&fixture.state, slot).unwrap();
        let participants: Vec<_> = set
            .iter()
            .map(|&position| committee.pubkeys[subnet as usize * SYNC_SUBCOMMITTEE_SIZE + position])
            .collect();
        let signing_root = sync_committee_message_signing_root(
            &fixture.store.config(),
            fixture.state.genesis_validators_root(),
            slot,
            fixture.head_root,
        );
        assert!(bls::eth_fast_aggregate_verify(
            &participants,
            signing_root,
            &contribution.signature
        ));
    }

    #[tokio::test]
    async fn a_contribution_with_nothing_pooled_is_a_404() {
        let fixture = fixture();
        let slot = current_slot(&fixture.store).await;
        let (status, json) = get_contribution(&fixture, slot, 0, fixture.head_root).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(json["code"], 404);
    }

    #[tokio::test]
    async fn a_contribution_for_subcommittee_four_is_a_400() {
        let fixture = fixture();
        let slot = current_slot(&fixture.store).await;
        let (status, _) = get_contribution(&fixture, slot, 4, fixture.head_root).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_contribution_while_syncing_or_for_an_unknown_block_is_a_503() {
        let mut fixture = fixture();
        let slot = current_slot(&fixture.store).await;
        let (status, _) = get_contribution(&fixture, slot, 0, Root::repeat_byte(9)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

        fixture.sync_status = SyncStatusController::new(SyncStatus::Syncing);
        let (status, _) = get_contribution(&fixture, slot, 0, fixture.head_root).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    /// A contribution from `aggregator` on `subnet`, covering the aggregator's
    /// own seats there, with every signature a real one.
    fn contribution_from(
        fixture: &Fixture,
        aggregator: ValidatorIndex,
        subnet: u64,
        slot: Slot,
    ) -> SignedContributionAndProof {
        let config = fixture.store.config();
        let gvr = fixture.state.genesis_validators_root();
        let seats: Vec<_> = seats_of(fixture, aggregator, slot)
            .into_iter()
            .filter(|&(seat_subnet, _)| seat_subnet == subnet)
            .collect();
        let mut contribution = SyncCommitteeContribution {
            slot,
            beacon_block_root: fixture.head_root,
            subcommittee_index: subnet,
            aggregation_bits: Default::default(),
            signature: Default::default(),
        };
        let message_root =
            sync_committee_message_signing_root(&config, gvr, slot, fixture.head_root);
        let signatures: Vec<_> = seats
            .iter()
            .map(|&(_, position)| {
                contribution.aggregation_bits.set(position, true).unwrap();
                sign_for(aggregator as usize, message_root)
            })
            .collect();
        contribution.signature = bls::aggregate(&signatures).unwrap();
        let selection_proof = sign_for(
            aggregator as usize,
            sync_selection_proof_signing_root(&config, gvr, slot, subnet),
        );
        let message = ContributionAndProof {
            aggregator_index: aggregator,
            contribution,
            selection_proof,
        };
        let signature = sign_for(
            aggregator as usize,
            contribution_and_proof_signing_root(&config, gvr, &message),
        );
        SignedContributionAndProof { message, signature }
    }

    /// A `(validator, subnet)` pair whose selection proof does (or does not)
    /// select it, found by search: selection is a hash of the signature.
    fn pair_where_selected(fixture: &Fixture, slot: Slot, selected: bool) -> (u64, u64) {
        let config = fixture.store.config();
        let gvr = fixture.state.genesis_validators_root();
        (0..MEMBERS as u64)
            .flat_map(|validator| {
                (0..SYNC_COMMITTEE_SUBNET_COUNT as u64).map(move |subnet| (validator, subnet))
            })
            .find(|&(validator, subnet)| {
                let proof = sign_for(
                    validator as usize,
                    sync_selection_proof_signing_root(&config, gvr, slot, subnet),
                );
                is_sync_committee_aggregator(&proof) == selected
                    && seats_of(fixture, validator, slot)
                        .iter()
                        .any(|&(seat_subnet, _)| seat_subnet == subnet)
            })
            .expect("an eighth of the pairs are selected and most are not")
    }

    async fn post_contributions(
        fixture: &Fixture,
        contributions: &[SignedContributionAndProof],
    ) -> (StatusCode, serde_json::Value) {
        let body = serde_json::to_vec(contributions).unwrap();
        post_json(fixture, "/eth/v1/validator/contribution_and_proofs", body).await
    }

    #[tokio::test]
    async fn a_valid_contribution_is_pooled_and_published() {
        let fixture = fixture();
        let slot = current_slot(&fixture.store).await;
        let (aggregator, subnet) = pair_where_selected(&fixture, slot, true);
        let signed = contribution_from(&fixture, aggregator, subnet, slot);
        let (status, json) = post_contributions(&fixture, std::slice::from_ref(&signed)).await;
        assert_eq!(status, StatusCode::OK, "{json}");

        assert_eq!(
            *fixture.network.sync_contributions.lock().unwrap(),
            vec![signed.clone()]
        );
        let pooled = fixture
            .pool
            .lock()
            .unwrap()
            .contribution(slot, fixture.head_root, subnet)
            .unwrap();
        assert_eq!(
            pooled.aggregation_bits,
            signed.message.contribution.aggregation_bits
        );
    }

    #[tokio::test]
    async fn an_unselected_aggregator_and_a_forged_signature_are_refused() {
        let fixture = fixture();
        let slot = current_slot(&fixture.store).await;

        let (aggregator, subnet) = pair_where_selected(&fixture, slot, false);
        let unselected = contribution_from(&fixture, aggregator, subnet, slot);
        let (status, json) = post_contributions(&fixture, &[unselected]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["failures"][0]["index"], 0);
        assert!(
            json["failures"][0]["message"]
                .as_str()
                .unwrap()
                .contains("not_aggregator")
        );

        let (aggregator, subnet) = pair_where_selected(&fixture, slot, true);
        let mut forged = contribution_from(&fixture, aggregator, subnet, slot);
        forged.message.contribution.signature = sign_for(0, Root::repeat_byte(1));
        // The envelope covers the contribution, so re-sign it: only the
        // aggregate signature is wrong.
        forged.signature = sign_for(
            aggregator as usize,
            contribution_and_proof_signing_root(
                &fixture.store.config(),
                fixture.state.genesis_validators_root(),
                &forged.message,
            ),
        );
        let (status, json) = post_contributions(&fixture, &[forged]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            json["failures"][0]["message"]
                .as_str()
                .unwrap()
                .contains("aggregate_signature")
        );
        assert!(
            fixture
                .network
                .sync_contributions
                .lock()
                .unwrap()
                .is_empty()
        );
    }

    async fn subscribe(
        fixture: &Fixture,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        post_json(
            fixture,
            "/eth/v1/validator/sync_committee_subscriptions",
            serde_json::to_vec(&body).unwrap(),
        )
        .await
    }

    #[tokio::test]
    async fn subscriptions_group_by_subnet_keep_the_latest_epoch_and_clamp_it() {
        let fixture = fixture();
        let size = SYNC_SUBCOMMITTEE_SIZE;
        let wall_epoch = compute_epoch_at_slot(wall_slot(&fixture.store));
        let clamp = (compute_sync_committee_period(wall_epoch) + 2)
            * preset::EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
        let body = serde_json::json!([
            { "validator_index": "1", "sync_committee_indices": ["0", (size + 5).to_string()], "until_epoch": "100" },
            { "validator_index": "2", "sync_committee_indices": ["3"], "until_epoch": "250" },
            { "validator_index": "3", "sync_committee_indices": [(3 * size).to_string()], "until_epoch": (clamp + 1000).to_string() },
        ]);
        let (status, _) = subscribe(&fixture, body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            *fixture.network.sync_subscriptions.lock().unwrap(),
            vec![(0, 250.min(clamp)), (1, 100.min(clamp)), (3, clamp)]
        );
    }

    #[tokio::test]
    async fn a_subscription_past_the_committee_is_a_400_and_joins_nothing() {
        let fixture = fixture();
        let past = preset::SYNC_COMMITTEE_SIZE;
        let body = serde_json::json!([
            { "validator_index": "1", "sync_committee_indices": ["0", past.to_string()], "until_epoch": "100" },
        ]);
        let (status, _) = subscribe(&fixture, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            fixture
                .network
                .sync_subscriptions
                .lock()
                .unwrap()
                .is_empty()
        );
    }
}
