//! The operation pool endpoints: how a validator client or an operator hands
//! this node a slashing, a voluntary exit or a BLS-to-execution change, and
//! how either reads the pool back.
//!
//! | Route | GET | POST |
//! |---|---|---|
//! | `/eth/v1/beacon/pool/proposer_slashings` | pool list | one `ProposerSlashing` |
//! | `/eth/v2/beacon/pool/attester_slashings` | pool list, with `version` and `Eth-Consensus-Version` | one electra `AttesterSlashing` |
//! | `/eth/v1/beacon/pool/voluntary_exits` | pool list | one `SignedVoluntaryExit` |
//! | `/eth/v1/beacon/pool/bls_to_execution_changes` | pool list | array of `SignedBLSToExecutionChange` |
//!
//! These are the routes Lighthouse and Prysm both serve. The v1 attester
//! slashings route is omitted: Prysm removed it, and fulu only has
//! electra-shaped slashings.
//!
//! A POSTed operation is checked with the same rules gossip applies to a
//! peer's (`gossip::operations::validate`), against a fresh seen set: the
//! node's own gossip seen set holds what peers sent, and a node never receives
//! its own messages. An accepted operation is pooled, for block production,
//! and published. Validating first is not optional: a peer that relays invalid
//! operations has its gossipsub score cut.

use axum::{
    Extension, Router,
    body::Bytes,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use ethlambda_network_api::RpcToP2PRef;
use ethlambda_state_transition::beacon::gossip::{
    Outcome,
    operations::{SeenOperations, validate},
};
use ethlambda_storage::Store;
use ethlambda_types::beacon::{
    containers::{capella::SignedBLSToExecutionChange, electra, shared},
    operation::BeaconOperation,
    signing::compute_epoch_at_slot,
};
use serde::de::DeserializeOwned;
use tracing::{debug, error, warn};

use crate::beacon::{
    ApiError,
    pool::{Failure, batch_response},
};
use crate::shared::content::with_consensus_version;

pub(crate) fn routes() -> Router<Store> {
    Router::new()
        .route(
            "/eth/v1/beacon/pool/proposer_slashings",
            get(get_proposer_slashings).post(post_proposer_slashing),
        )
        .route(
            "/eth/v2/beacon/pool/attester_slashings",
            get(get_attester_slashings).post(post_attester_slashing),
        )
        .route(
            "/eth/v1/beacon/pool/voluntary_exits",
            get(get_voluntary_exits).post(post_voluntary_exit),
        )
        .route(
            "/eth/v1/beacon/pool/bls_to_execution_changes",
            get(get_bls_to_execution_changes).post(post_bls_to_execution_changes),
        )
}

async fn get_proposer_slashings(State(store): State<Store>) -> Response {
    let data = store.operation_pool().proposer_slashings();
    crate::json_response(serde_json::json!({ "data": data }))
}

/// The pool's attester slashings, versioned by the fork of the wall clock's
/// current epoch, as the Beacon API's "active consensus version" means. The
/// head's fork lags the clock at a fork boundary whose block is late or
/// missing, and a validator client would then decode the list as the wrong
/// fork's container.
///
/// The pool holds electra-shaped slashings. Their JSON is the same for every
/// fork (the containers differ only in the SSZ list bound of the attesting
/// indices), so no conversion is needed for the version to be honest.
async fn get_attester_slashings(State(store): State<Store>) -> Response {
    let fork = store
        .config()
        .fork_at_epoch(compute_epoch_at_slot(crate::beacon::node::wall_slot(
            &store,
        )));
    let data = store.operation_pool().attester_slashings();
    let response = crate::json_response(serde_json::json!({
        "version": fork.as_str(),
        "data": data,
    }));
    with_consensus_version(response, fork)
}

async fn get_voluntary_exits(State(store): State<Store>) -> Response {
    let data = store.operation_pool().voluntary_exits();
    crate::json_response(serde_json::json!({ "data": data }))
}

async fn get_bls_to_execution_changes(State(store): State<Store>) -> Response {
    let data = store.operation_pool().bls_to_execution_changes();
    crate::json_response(serde_json::json!({ "data": data }))
}

async fn post_proposer_slashing(
    State(store): State<Store>,
    Extension(p2p): Extension<RpcToP2PRef>,
    body: Bytes,
) -> Response {
    submit::<shared::ProposerSlashing>(&store, &p2p, &body, "proposer slashing", |op| {
        BeaconOperation::ProposerSlashing(op)
    })
    .await
}

async fn post_attester_slashing(
    State(store): State<Store>,
    Extension(p2p): Extension<RpcToP2PRef>,
    body: Bytes,
) -> Response {
    submit::<electra::AttesterSlashing>(&store, &p2p, &body, "attester slashing", |op| {
        BeaconOperation::AttesterSlashing(op)
    })
    .await
}

async fn post_voluntary_exit(
    State(store): State<Store>,
    Extension(p2p): Extension<RpcToP2PRef>,
    body: Bytes,
) -> Response {
    submit::<shared::SignedVoluntaryExit>(&store, &p2p, &body, "voluntary exit", |op| {
        BeaconOperation::VoluntaryExit(op)
    })
    .await
}

async fn post_bls_to_execution_changes(
    State(store): State<Store>,
    Extension(p2p): Extension<RpcToP2PRef>,
    body: Bytes,
) -> Response {
    let Ok(changes) = serde_json::from_slice::<Vec<SignedBLSToExecutionChange>>(&body) else {
        return ApiError::BadRequest("invalid request body").into_response();
    };
    let mut failures = Vec::new();
    for (index, change) in changes.into_iter().enumerate() {
        let validator = change.message.validator_index;
        let operation = BeaconOperation::BlsToExecutionChange(change);
        if let Err(rejection) = accept(&store, &p2p, operation, "BLS to execution change").await {
            // An internal failure stays a failure entry, as a publish failure
            // does for the attestation pool.
            let message = rejection.message();
            warn!(validator, reason = %message, "Refused a submitted BLS to execution change");
            failures.push(Failure {
                index,
                message: message.to_string().into(),
            });
        }
    }
    batch_response(
        failures,
        "some BLS to execution changes failed validation and were not published",
    )
}

/// Parses one operation of type `T`, then validates, pools and publishes it.
async fn submit<T: DeserializeOwned>(
    store: &Store,
    p2p: &RpcToP2PRef,
    body: &[u8],
    kind: &'static str,
    wrap: fn(T) -> BeaconOperation,
) -> Response {
    let Ok(operation) = serde_json::from_slice::<T>(body) else {
        return ApiError::BadRequest("invalid request body").into_response();
    };
    match accept(store, p2p, wrap(operation), kind).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(Rejection::Refused(message)) => {
            warn!(kind, reason = %message, "Refused a submitted operation");
            bad_request(message)
        }
        Err(Rejection::Internal(message)) => ApiError::Internal(message).into_response(),
    }
}

/// Why `accept` did not take an operation.
enum Rejection {
    /// The operation failed validation: the caller's fault, a 400.
    Refused(String),
    /// The node could not finish the job: a 500.
    Internal(&'static str),
}

impl Rejection {
    fn message(&self) -> &str {
        match self {
            Self::Refused(message) => message,
            Self::Internal(message) => message,
        }
    }
}

/// Validates `operation` under the gossip rules, then pools and publishes it.
async fn accept(
    store: &Store,
    p2p: &RpcToP2PRef,
    operation: BeaconOperation,
    kind: &'static str,
) -> Result<(), Rejection> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0);
    // The signature checks are pairings, so they run off the async threads.
    let outcome = {
        let store = store.clone();
        let operation = operation.clone();
        tokio::task::spawn_blocking(move || {
            validate(&SeenOperations::default(), &store, &operation, now_ms)
        })
        .await
        .map_err(|err| {
            error!(%err, kind, "Operation validation task failed");
            Rejection::Internal("validation did not complete")
        })?
    };
    if outcome != Outcome::Accept {
        let (verdict, reason) = outcome.labels();
        return Err(Rejection::Refused(format!(
            "{kind} refused: {verdict}: {reason}"
        )));
    }
    // Pooled as well as published: gossip never delivers a node its own
    // messages, so without this a block this node proposes would miss it.
    store.operation_pool().insert(operation.clone());
    p2p.publish_beacon_operation(operation)
        .map_err(|_| Rejection::Internal("the network actor is not running"))?;
    debug!(kind, "Accepted operation for gossip");
    Ok(())
}

/// The Beacon API's error body, with a message built at run time.
fn bad_request(message: String) -> Response {
    let body = serde_json::json!({ "code": 400, "message": message });
    let mut response = crate::json_response(body);
    *response.status_mut() = StatusCode::BAD_REQUEST;
    response
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::test_utils::{RecordingNetwork, beacon_store_at};
    use axum::{body::Body, http::Request};
    use ethlambda_state_transition::beacon::{
        hash::hash,
        helpers::{
            accessors::get_domain,
            misc::compute_domain,
            test_state::{sign_for, with_signing_validators_at},
        },
    };
    use ethlambda_types::{
        beacon::{
            constants::{
                DOMAIN_BEACON_PROPOSER, DOMAIN_BLS_TO_EXECUTION_CHANGE, DOMAIN_VOLUNTARY_EXIT,
            },
            containers::{BeaconState, capella::BLSToExecutionChange},
            fork::ForkName,
            primitives::ExecutionAddress,
            signing::{compute_epoch_at_slot, compute_signing_root, compute_start_slot_at_epoch},
        },
        primitives::HashTreeRoot as _,
    };
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    struct Fixture {
        store: Store,
        state: BeaconState,
        network: Arc<RecordingNetwork>,
    }

    /// A fulu head state at the first slot of the wall clock's epoch, so the
    /// epochs the operations name are not in the future. Its validators are
    /// all active since epoch 0 and the wall epoch is far past
    /// `SHARD_COMMITTEE_PERIOD`, so any of them may exit. Validators 0 and 1
    /// hold BLS withdrawal credentials derived from their own key.
    fn fixture() -> Fixture {
        let mut state = with_signing_validators_at(ForkName::Fulu, 64);
        let (probe, _) = beacon_store_at(state.clone());
        let wall_epoch = compute_epoch_at_slot(crate::beacon::node::wall_slot(&probe));
        let BeaconState::Fulu(fulu) = &mut state else {
            unreachable!("built as fulu")
        };
        fulu.slot = compute_start_slot_at_epoch(wall_epoch);
        for index in 0..2u64 {
            let validator = state.validator_mut(index).unwrap();
            let mut credentials = hash(&validator.pubkey.0);
            credentials.0[0] = ethlambda_types::beacon::constants::BLS_WITHDRAWAL_PREFIX;
            validator.withdrawal_credentials = credentials;
        }
        let (store, _root) = beacon_store_at(state.clone());
        Fixture {
            store,
            state,
            network: Arc::new(RecordingNetwork::default()),
        }
    }

    fn signed_exit(fixture: &Fixture, validator_index: u64) -> shared::SignedVoluntaryExit {
        let exit = shared::VoluntaryExit {
            epoch: compute_epoch_at_slot(fixture.state.slot()),
            validator_index,
        };
        let domain = compute_domain(
            DOMAIN_VOLUNTARY_EXIT,
            fixture.store.config().capella_fork_version,
            fixture.state.genesis_validators_root(),
        );
        let signature = sign_for(
            validator_index as usize,
            compute_signing_root(exit.hash_tree_root(), domain),
        );
        shared::SignedVoluntaryExit {
            message: exit,
            signature,
        }
    }

    /// A change for `validator_index`, signed by `signer`'s key.
    fn signed_change(
        fixture: &Fixture,
        validator_index: u64,
        signer: usize,
    ) -> SignedBLSToExecutionChange {
        let message = BLSToExecutionChange {
            validator_index,
            from_bls_pubkey: fixture.state.validator(validator_index).unwrap().pubkey,
            to_execution_address: ExecutionAddress::ZERO,
        };
        let domain = compute_domain(
            DOMAIN_BLS_TO_EXECUTION_CHANGE,
            fixture.store.config().genesis_fork_version,
            fixture.state.genesis_validators_root(),
        );
        let signature = sign_for(
            signer,
            compute_signing_root(message.hash_tree_root(), domain),
        );
        SignedBLSToExecutionChange { message, signature }
    }

    async fn send(
        fixture: &Fixture,
        request: Request<Body>,
    ) -> (StatusCode, axum::http::HeaderMap, serde_json::Value) {
        let network: RpcToP2PRef = fixture.network.clone();
        let app = routes()
            .with_state(fixture.store.clone())
            .layer(Extension(network));
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json = if body.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null)
        };
        (status, headers, json)
    }

    async fn post(fixture: &Fixture, uri: &str, body: Vec<u8>) -> (StatusCode, serde_json::Value) {
        let request = Request::post(uri)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let (status, _, json) = send(fixture, request).await;
        (status, json)
    }

    async fn get(
        fixture: &Fixture,
        uri: &str,
    ) -> (StatusCode, axum::http::HeaderMap, serde_json::Value) {
        send(fixture, Request::get(uri).body(Body::empty()).unwrap()).await
    }

    const EXITS: &str = "/eth/v1/beacon/pool/voluntary_exits";
    const CHANGES: &str = "/eth/v1/beacon/pool/bls_to_execution_changes";

    #[tokio::test]
    async fn a_valid_exit_is_pooled_and_published() {
        let fixture = fixture();
        let exit = signed_exit(&fixture, 3);
        let body = serde_json::to_vec(&exit).unwrap();
        let (status, _) = post(&fixture, EXITS, body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            fixture.store.operation_pool().voluntary_exits(),
            vec![exit.clone()]
        );
        assert_eq!(
            *fixture.network.operations.lock().unwrap(),
            vec![BeaconOperation::VoluntaryExit(exit)]
        );
    }

    #[tokio::test]
    async fn a_valid_proposer_slashing_is_pooled_and_published() {
        let fixture = fixture();
        let proposer = 5u64;
        let slot = fixture.state.slot();
        let domain = get_domain(
            &fixture.state,
            DOMAIN_BEACON_PROPOSER,
            Some(compute_epoch_at_slot(slot)),
        );
        let signed_header = |parent_byte: u8| {
            let header = shared::BeaconBlockHeader {
                slot,
                proposer_index: proposer,
                parent_root: ethlambda_types::primitives::H256([parent_byte; 32]),
                ..Default::default()
            };
            let signature = sign_for(
                proposer as usize,
                compute_signing_root(header.hash_tree_root(), domain),
            );
            shared::SignedBeaconBlockHeader {
                message: header,
                signature,
            }
        };
        let slashing = shared::ProposerSlashing {
            signed_header_1: signed_header(1),
            signed_header_2: signed_header(2),
        };
        let body = serde_json::to_vec(&slashing).unwrap();
        let (status, json) = post(&fixture, "/eth/v1/beacon/pool/proposer_slashings", body).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(
            fixture.store.operation_pool().proposer_slashings(),
            vec![slashing.clone()]
        );
        assert_eq!(
            *fixture.network.operations.lock().unwrap(),
            vec![BeaconOperation::ProposerSlashing(slashing)]
        );
    }

    #[tokio::test]
    async fn a_down_network_actor_is_a_500() {
        let fixture = fixture();
        fixture
            .network
            .fail_operations
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let exit = signed_exit(&fixture, 3);
        let body = serde_json::to_vec(&exit).unwrap();
        let (status, _) = post(&fixture, EXITS, body).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn an_exit_with_a_bad_signature_is_refused() {
        let fixture = fixture();
        let mut exit = signed_exit(&fixture, 3);
        exit.signature = sign_for(4, ethlambda_types::beacon::primitives::Root::ZERO);
        let body = serde_json::to_vec(&exit).unwrap();
        let (status, json) = post(&fixture, EXITS, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(json["message"].as_str().unwrap().contains("voluntary exit"));
        assert!(fixture.store.operation_pool().voluntary_exits().is_empty());
        assert!(fixture.network.operations.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn malformed_json_is_a_400() {
        let fixture = fixture();
        for uri in [
            EXITS,
            "/eth/v1/beacon/pool/proposer_slashings",
            "/eth/v2/beacon/pool/attester_slashings",
            CHANGES,
        ] {
            let (status, _) = post(&fixture, uri, b"{not json".to_vec()).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
        }
        assert!(fixture.network.operations.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn get_returns_what_was_inserted() {
        let fixture = fixture();
        let exit = signed_exit(&fixture, 3);
        let change = signed_change(&fixture, 0, 0);
        let indexed = electra::IndexedAttestation {
            attesting_indices: vec![5u64].try_into().unwrap(),
            data: shared::AttestationData::default(),
            signature: Default::default(),
        };
        let slashing = electra::AttesterSlashing {
            attestation_1: indexed.clone(),
            attestation_2: indexed,
        };
        let proposer_slashing = shared::ProposerSlashing::default();
        {
            let mut pool = fixture.store.operation_pool();
            pool.insert(BeaconOperation::VoluntaryExit(exit.clone()));
            pool.insert(BeaconOperation::BlsToExecutionChange(change.clone()));
            pool.insert(BeaconOperation::AttesterSlashing(slashing.clone()));
            pool.insert(BeaconOperation::ProposerSlashing(proposer_slashing.clone()));
        }

        let (status, _, json) = get(&fixture, EXITS).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["data"], serde_json::to_value([&exit]).unwrap());

        let (_, _, json) = get(&fixture, CHANGES).await;
        assert_eq!(json["data"], serde_json::to_value([&change]).unwrap());

        let (_, _, json) = get(&fixture, "/eth/v1/beacon/pool/proposer_slashings").await;
        assert_eq!(
            json["data"],
            serde_json::to_value([&proposer_slashing]).unwrap()
        );

        let (status, headers, json) = get(&fixture, "/eth/v2/beacon/pool/attester_slashings").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers["eth-consensus-version"], "fulu");
        assert_eq!(json["version"], "fulu");
        assert_eq!(json["data"], serde_json::to_value([&slashing]).unwrap());
    }

    /// The head is before the fork boundary and the wall clock after it: the
    /// version is the clock's fork, not the head's.
    #[tokio::test]
    async fn the_attester_slashings_version_follows_the_wall_clock_not_the_head() {
        let mut fixture = fixture();
        let state = with_signing_validators_at(ForkName::Fulu, 64);
        let config = fixture.store.config();
        let head_fork = config.fork_at_epoch(compute_epoch_at_slot(state.slot()));
        let wall_epoch = compute_epoch_at_slot(crate::beacon::node::wall_slot(&fixture.store));
        let wall_fork = config.fork_at_epoch(wall_epoch);
        assert_ne!(
            head_fork, wall_fork,
            "the head must sit before a fork boundary the clock is past"
        );
        fixture.store = beacon_store_at(state).0;

        let (status, headers, json) = get(&fixture, "/eth/v2/beacon/pool/attester_slashings").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers["eth-consensus-version"], wall_fork.as_str());
        assert_eq!(json["version"], wall_fork.as_str());
    }

    #[tokio::test]
    async fn a_mixed_bls_change_batch_pools_the_valid_one_and_reports_the_other() {
        let fixture = fixture();
        let good = signed_change(&fixture, 0, 0);
        // Validator 1's change signed by validator 2's key.
        let bad = signed_change(&fixture, 1, 2);
        let body = serde_json::to_vec(&[good.clone(), bad]).unwrap();
        let (status, json) = post(&fixture, CHANGES, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let failures = json["failures"].as_array().unwrap();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0]["index"], 1);
        assert_eq!(
            fixture.store.operation_pool().bls_to_execution_changes(),
            vec![good.clone()]
        );
        assert_eq!(
            *fixture.network.operations.lock().unwrap(),
            vec![BeaconOperation::BlsToExecutionChange(good)]
        );
    }
}
