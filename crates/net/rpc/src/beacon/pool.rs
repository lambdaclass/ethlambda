//! `POST /eth/v2/beacon/pool/attestations`: how a validator client hands this
//! node its attestations to gossip.
//!
//! Each attestation is checked against the electra `beacon_attestation_{subnet_id}`
//! gossip conditions (p2p-interface) that can be evaluated here, then
//! published on its subnet. Validating before publishing is not optional: a
//! peer that relays invalid attestations has its gossipsub score cut, and
//! enough of that disconnects it.
//!
//! Conditions not checked, each because it needs state this node does not
//! keep: the "first valid attestation from this validator for this target
//! epoch" deduplication (no seen cache; the validator client already signs at
//! most once per slot), and "the target is a descendant of the finalized
//! checkpoint" (the voted block being in the store already implies it, since
//! only blocks descending from finalization are imported).

use axum::{
    Extension, Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use ethlambda_network_api::RpcToP2PRef;
use ethlambda_state_transition::beacon::{
    bls,
    gossip::attestation::compute_subnet_for_attestation,
    helpers::accessors::{CommitteeCacheExt as _, get_domain},
};
use ethlambda_storage::Store;
use ethlambda_types::{
    beacon::{
        constants::{DOMAIN_BEACON_ATTESTER, MAXIMUM_GOSSIP_CLOCK_DISPARITY},
        containers::{BeaconState, electra::SingleAttestation},
        fork::ForkName,
        primitives::{Epoch, Root},
        signing::{compute_epoch_at_slot, compute_signing_root, compute_start_slot_at_epoch},
    },
    primitives::HashTreeRoot as _,
};
use serde::Serialize;
use tracing::{debug, warn};

use crate::beacon::{ApiError, validator::head};

pub(crate) fn routes() -> Router<Store> {
    Router::new().route(
        "/eth/v2/beacon/pool/attestations",
        post(post_pool_attestations),
    )
}

/// One rejected attestation, in the Beacon API's `IndexedErrorMessage` shape:
/// its position in the submitted array, and why.
#[derive(Debug, Serialize)]
struct Failure {
    index: usize,
    message: &'static str,
}

async fn post_pool_attestations(
    State(store): State<Store>,
    Extension(p2p): Extension<RpcToP2PRef>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let fork = headers
        .get("eth-consensus-version")
        .and_then(|value| value.to_str().ok())
        .and_then(ForkName::parse);
    if !fork.is_some_and(|fork| fork >= ForkName::Electra) {
        return ApiError::BadRequest("Eth-Consensus-Version must name electra or a later fork")
            .into_response();
    }
    let Ok(attestations) = serde_json::from_slice::<Vec<SingleAttestation>>(&body) else {
        return ApiError::BadRequest("invalid request body").into_response();
    };
    let (_head_root, state) = match head(&store) {
        Ok(found) => found,
        Err(err) => return err.into_response(),
    };

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0);
    let mut failures = Vec::new();
    for (index, attestation) in attestations.into_iter().enumerate() {
        let slot = attestation.data.slot;
        let validator = attestation.attester_index;
        let checked = validate(&store, &state, &attestation, now_ms);
        let published = checked.and_then(|subnet_id| {
            p2p.publish_beacon_attestation(subnet_id, attestation)
                .map_err(|_| "the network actor is not running")
        });
        match published {
            Ok(()) => debug!(%slot, validator, "Accepted attestation for gossip"),
            Err(message) => {
                warn!(%slot, validator, reason = message, "Refused a submitted attestation");
                failures.push(Failure { index, message });
            }
        }
    }

    if failures.is_empty() {
        return StatusCode::OK.into_response();
    }
    let body = serde_json::json!({
        "code": 400,
        "message": "some attestations failed validation and were not published",
        "failures": failures,
    });
    let mut response = crate::json_response(body);
    *response.status_mut() = StatusCode::BAD_REQUEST;
    response
}

/// The subnet `attestation` belongs on, if it passes every gossip condition
/// this node can check, or the first one it fails.
///
/// `state` is the fork-choice head's post-state, whose shuffling is the
/// attestation's for any target epoch from the head's previous to its next.
/// The committees come from the store's shared cache, which the chain actor
/// fills too, so a batch of one slot's attestations derives its shuffling at
/// most once.
fn validate(
    store: &Store,
    state: &BeaconState,
    attestation: &SingleAttestation,
    now_ms: u64,
) -> Result<u64, &'static str> {
    let data = &attestation.data;
    let config = store.config();

    // [IGNORE] Not from the future, and from the current or previous epoch,
    // both with MAXIMUM_GOSSIP_CLOCK_DISPARITY of allowance (deneb's form).
    let slot_start_ms = config
        .genesis_time_ms()
        .saturating_add(data.slot.saturating_mul(config.slot_duration_ms));
    if slot_start_ms > now_ms + MAXIMUM_GOSSIP_CLOCK_DISPARITY {
        return Err("attestation slot is in the future");
    }
    let clock_epoch = |ms: u64| {
        let slot = ms.saturating_sub(config.genesis_time_ms()) / config.slot_duration_ms.max(1);
        compute_epoch_at_slot(slot)
    };
    let earliest_epoch = clock_epoch(now_ms.saturating_sub(MAXIMUM_GOSSIP_CLOCK_DISPARITY));
    let attestation_epoch = compute_epoch_at_slot(data.slot);
    if attestation_epoch + 1 < earliest_epoch {
        return Err("attestation is older than the previous epoch");
    }

    // [REJECT] data.index == 0, and the target epoch is the slot's.
    if data.index != 0 {
        return Err("data.index must be zero from electra on");
    }
    if data.target.epoch != attestation_epoch {
        return Err("target epoch does not match the attestation slot");
    }

    // The head state's shuffling covers its previous, current and next epoch.
    let state_epoch = compute_epoch_at_slot(state.slot());
    if data.target.epoch + 1 < state_epoch || data.target.epoch > state_epoch + 1 {
        return Err("target epoch is too far from this node's head to check");
    }

    // [IGNORE] The voted block has been seen. [REJECT] The target is that
    // block's checkpoint for the target epoch.
    if !store.has_block(&data.beacon_block_root) {
        return Err("the voted block is unknown to this node");
    }
    if checkpoint_block(store, data.beacon_block_root, data.target.epoch) != Some(data.target.root)
    {
        return Err("target root is not the voted block's checkpoint");
    }

    // [REJECT] The committee index is in range, and the attester is in it.
    let epoch_committees = store.committee_cache().committees(state, data.target.epoch);
    let committees_per_slot = epoch_committees.committees_per_slot();
    if attestation.committee_index >= committees_per_slot {
        return Err("committee index is out of range");
    }
    let committee = epoch_committees
        .committee(data.slot, attestation.committee_index)
        .map_err(|_| "committee computation failed")?;
    if !committee.contains(&attestation.attester_index) {
        return Err("attester is not in the named committee");
    }

    // [REJECT] The signature is valid, under the attester domain at the target
    // epoch.
    let pubkey = state
        .validator(attestation.attester_index)
        .map_err(|_| "attester index is unknown")?
        .pubkey;
    let domain = get_domain(state, DOMAIN_BEACON_ATTESTER, Some(data.target.epoch));
    let signing_root = compute_signing_root(data.hash_tree_root(), domain);
    if !bls::verify(&pubkey, signing_root, &attestation.signature) {
        return Err("invalid signature");
    }

    Ok(compute_subnet_for_attestation(
        committees_per_slot,
        data.slot,
        attestation.committee_index,
        &config,
    ))
}

/// The root of the latest block at or before `epoch`'s first slot on the chain
/// ending in `root`: the spec's `get_checkpoint_block`, walked through the
/// store's block index. `None` if the walk leaves the stored chain.
fn checkpoint_block(store: &Store, mut root: Root, epoch: Epoch) -> Option<Root> {
    let boundary = compute_start_slot_at_epoch(epoch);
    loop {
        let (slot, parent) = store.block_entry(&root)?;
        if slot <= boundary {
            return Some(root);
        }
        root = parent;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::test_utils::{RecordingNetwork, beacon_store_at};
    use axum::{body::Body, http::Request};
    use ethlambda_state_transition::beacon::helpers::{
        accessors::get_beacon_committee,
        test_state::{sign_for, with_signing_validators_at},
    };
    use ethlambda_types::beacon::containers::shared::{AttestationData, Checkpoint};
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    struct Fixture {
        store: Store,
        state: BeaconState,
        head_root: Root,
        network: Arc<RecordingNetwork>,
    }

    /// A fulu head state, stored in the current wall-clock epoch so the
    /// submitted attestations are neither future nor stale.
    fn fixture() -> Fixture {
        let mut state = with_signing_validators_at(ForkName::Fulu, 64);
        let BeaconState::Fulu(fulu) = &mut state else {
            unreachable!("built as fulu")
        };
        // At the first slot of the wall clock's epoch, so the head is its own
        // epoch's checkpoint block and the attestation's target root.
        let (probe, _) = beacon_store_at(BeaconState::Fulu(fulu.clone()));
        let wall_epoch = compute_epoch_at_slot(crate::beacon::node::wall_slot(&probe));
        fulu.slot = compute_start_slot_at_epoch(wall_epoch);
        let (store, head_root) = beacon_store_at(state.clone());
        Fixture {
            store,
            state,
            head_root,
            network: Arc::new(RecordingNetwork::default()),
        }
    }

    /// A correctly signed attestation from `committee`'s member at `position`,
    /// voting for the head at the head's own slot.
    fn attestation(fixture: &Fixture, committee_index: u64, position: usize) -> SingleAttestation {
        let slot = fixture.state.slot();
        let epoch = compute_epoch_at_slot(slot);
        let data = AttestationData {
            slot,
            index: 0,
            beacon_block_root: fixture.head_root,
            source: fixture.state.current_justified_checkpoint(),
            target: Checkpoint {
                epoch,
                root: fixture.head_root,
            },
        };
        let committee = get_beacon_committee(&fixture.state, slot, committee_index).unwrap();
        let attester_index = committee[position];
        let domain = get_domain(&fixture.state, DOMAIN_BEACON_ATTESTER, Some(epoch));
        let signing_root = compute_signing_root(data.hash_tree_root(), domain);
        SingleAttestation {
            committee_index,
            attester_index,
            data,
            signature: sign_for(attester_index as usize, signing_root),
        }
    }

    async fn submit(
        fixture: &Fixture,
        attestations: &[SingleAttestation],
    ) -> (StatusCode, serde_json::Value) {
        let network: RpcToP2PRef = fixture.network.clone();
        let app = routes()
            .with_state(fixture.store.clone())
            .layer(Extension(network));
        let request = Request::post("/eth/v2/beacon/pool/attestations")
            .header("content-type", "application/json")
            .header("eth-consensus-version", "fulu")
            .body(Body::from(serde_json::to_vec(attestations).unwrap()))
            .unwrap();
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

    #[tokio::test]
    async fn a_valid_attestation_is_published_on_its_subnet() {
        let fixture = fixture();
        let attestation = attestation(&fixture, 0, 0);
        let (status, _) = submit(&fixture, std::slice::from_ref(&attestation)).await;
        assert_eq!(status, StatusCode::OK);

        let published = fixture.network.published.lock().unwrap();
        assert_eq!(published.len(), 1);
        let epoch = attestation.data.target.epoch;
        let committees_per_slot = fixture
            .store
            .committee_cache()
            .committees(&fixture.state, epoch)
            .committees_per_slot();
        let expected_subnet = compute_subnet_for_attestation(
            committees_per_slot,
            attestation.data.slot,
            0,
            &fixture.store.config(),
        );
        assert_eq!(published[0], (expected_subnet, attestation));
    }

    #[tokio::test]
    async fn a_bad_signature_is_refused_and_not_published() {
        let fixture = fixture();
        let mut forged = attestation(&fixture, 0, 0);
        forged.signature = attestation(&fixture, 0, 1).signature;
        let (status, json) = submit(&fixture, &[forged]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["failures"][0]["index"], 0);
        assert_eq!(json["failures"][0]["message"], "invalid signature");
        assert!(fixture.network.published.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_attester_outside_its_committee_is_refused() {
        let fixture = fixture();
        let mut wrong = attestation(&fixture, 0, 0);
        let outsider = (0..64u64)
            .find(|index| {
                !get_beacon_committee(&fixture.state, wrong.data.slot, 0)
                    .unwrap()
                    .contains(index)
            })
            .expect("a 64-validator epoch spreads validators over several slots");
        wrong.attester_index = outsider;
        let (status, json) = submit(&fixture, &[wrong]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            json["failures"][0]["message"],
            "attester is not in the named committee"
        );
    }

    #[tokio::test]
    async fn a_mixed_batch_publishes_the_valid_and_reports_the_rest_by_position() {
        let fixture = fixture();
        let good = attestation(&fixture, 0, 0);
        let mut bad = attestation(&fixture, 0, 1);
        bad.data.index = 1;
        let (status, json) = submit(&fixture, &[bad, good.clone()]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let failures = json["failures"].as_array().unwrap();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0]["index"], 0);
        let published = fixture.network.published.lock().unwrap();
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].1, good);
    }

    #[tokio::test]
    async fn a_pre_electra_fork_header_is_refused() {
        let fixture = fixture();
        let network: RpcToP2PRef = fixture.network.clone();
        let app = routes()
            .with_state(fixture.store.clone())
            .layer(Extension(network));
        let request = Request::post("/eth/v2/beacon/pool/attestations")
            .header("eth-consensus-version", "deneb")
            .body(Body::from("[]"))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
