//! `POST /eth/v2/beacon/pool/attestations`, how a validator client hands this
//! node its attestations to gossip; `GET /eth/v2/validator/aggregate_attestation`,
//! how an aggregator gets them back combined; and
//! `POST /eth/v2/validator/aggregate_and_proofs`, how it publishes the result.
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
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use ethlambda_network_api::RpcToP2PRef;
use ethlambda_state_transition::beacon::{
    attestation_pool::SharedAttestationPool,
    bls,
    gossip::attestation::compute_subnet_for_attestation,
    gossip::{Outcome, aggregate},
    helpers::accessors::{CommitteeCacheExt as _, get_domain},
};
use ethlambda_storage::Store;
use ethlambda_types::{
    beacon::{
        constants::{DOMAIN_BEACON_ATTESTER, MAXIMUM_GOSSIP_CLOCK_DISPARITY},
        containers::{
            BeaconState, SignedAggregateAndProof,
            electra::{self, SingleAttestation},
        },
        fork::ForkName,
        primitives::{CommitteeIndex, Epoch, Root, Slot},
        signing::{compute_epoch_at_slot, compute_signing_root, compute_start_slot_at_epoch},
    },
    primitives::HashTreeRoot as _,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::beacon::{ApiError, validator::head};

pub(crate) fn routes() -> Router<Store> {
    Router::new()
        .route(
            "/eth/v2/beacon/pool/attestations",
            post(post_pool_attestations),
        )
        .route(
            "/eth/v2/validator/aggregate_attestation",
            get(get_aggregate_attestation),
        )
        .route(
            "/eth/v2/validator/aggregate_and_proofs",
            post(post_aggregate_and_proofs),
        )
}

/// What validating a submitted attestation establishes about it: where it is
/// published, and where it sits in its committee, which the pool needs.
struct Checked {
    subnet_id: u64,
    committee_position: usize,
    committee_len: usize,
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
    Extension(pool): Extension<SharedAttestationPool>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(err) = require_electra_or_later(&headers) {
        return err.into_response();
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
        // Pooled as well as published: gossip never delivers a node its own
        // messages, so without this an aggregator served by this node would
        // be missing its own validator client's votes.
        let published = checked.and_then(|checked| {
            // Live for liveness too: gossip never delivers this node its own
            // validator clients' messages, so this is where it sees them.
            store
                .observed_liveness()
                .record(attestation.data.target.epoch, validator);
            pool.lock().expect("attestation pool lock poisoned").insert(
                &attestation,
                checked.committee_position,
                checked.committee_len,
            );
            p2p.publish_beacon_attestation(checked.subnet_id, attestation)
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

    batch_response(
        failures,
        "some attestations failed validation and were not published",
    )
}

/// Where `attestation` belongs, if it passes every gossip condition
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
) -> Result<Checked, &'static str> {
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
    let committee_position = committee
        .iter()
        .position(|&member| member == attestation.attester_index)
        .ok_or("attester is not in the named committee")?;
    let committee_len = committee.len();

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

    Ok(Checked {
        subnet_id: compute_subnet_for_attestation(
            committees_per_slot,
            data.slot,
            attestation.committee_index,
            &config,
        ),
        committee_position,
        committee_len,
    })
}

/// The endpoints here take electra's containers, which exist only from that
/// fork on; `Eth-Consensus-Version` is required to say so.
fn require_electra_or_later(headers: &HeaderMap) -> Result<(), ApiError> {
    let fork = headers
        .get("eth-consensus-version")
        .and_then(|value| value.to_str().ok())
        .and_then(ForkName::parse);
    if fork.is_some_and(|fork| fork >= ForkName::Electra) {
        Ok(())
    } else {
        Err(ApiError::BadRequest(
            "Eth-Consensus-Version must name electra or a later fork",
        ))
    }
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

/// `POST /eth/v2/validator/aggregate_and_proofs`: a validator client's signed
/// aggregates, validated with the same `beacon_aggregate_and_proof` gossip
/// conditions this node applies to its peers' (`gossip::aggregate`), then
/// gossiped.
///
/// Each is checked against a fresh seen-cache rather than P2P's: that cache
/// holds what peers sent, and a node never receives its own messages, so it
/// would say nothing about these; what it guards against, a second aggregate
/// for one aggregator and epoch, the validator client already guards against
/// by signing one per duty.
async fn post_aggregate_and_proofs(
    State(store): State<Store>,
    Extension(p2p): Extension<RpcToP2PRef>,
    Extension(pool): Extension<SharedAttestationPool>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(err) = require_electra_or_later(&headers) {
        return err.into_response();
    }
    let Ok(aggregates) = serde_json::from_slice::<Vec<electra::SignedAggregateAndProof>>(&body)
    else {
        return ApiError::BadRequest("invalid request body").into_response();
    };

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0);
    let capacity = std::num::NonZeroUsize::MIN;
    let mut failures = Vec::new();
    for (index, aggregate) in aggregates.into_iter().enumerate() {
        let inner = aggregate.message.aggregate.clone();
        let aggregate = SignedAggregateAndProof::Electra(aggregate);
        let slot = aggregate.slot();
        let aggregator = aggregate.aggregator_index();
        let seen = aggregate::SeenAggregates::new(capacity, capacity);
        // The stateful checks resolve the aggregate's bits to the validators
        // behind them, which the chain actor applies to fork choice once the
        // network actor hands it over.
        let checked = aggregate::cheap_checks(&seen, &store, &aggregate, now_ms)
            .and_then(|()| aggregate::stateful_checks(&store, &aggregate));
        let published = checked
            .map_err(|outcome: Outcome| {
                warn!(%slot, aggregator, ?outcome, "Refused a submitted aggregate");
                "aggregate failed validation"
            })
            .and_then(|attesting_indices| {
                // The aggregator and every attester its signature verified are
                // live, as when P2P accepts a gossip aggregate.
                let (epoch, _root) = aggregate.target();
                let live = std::iter::once(aggregator).chain(attesting_indices.iter().copied());
                store.observed_liveness().record_all(epoch, live);
                // Recorded for block production, which packs the aggregates
                // this node has validated.
                pool.lock()
                    .expect("attestation pool lock poisoned")
                    .insert_aggregate(inner);
                p2p.publish_beacon_aggregate(aggregate, attesting_indices)
                    .map_err(|_| "the network actor is not running")
            });
        match published {
            Ok(()) => debug!(%slot, aggregator, "Accepted aggregate for gossip"),
            Err(message) => failures.push(Failure { index, message }),
        }
    }
    batch_response(
        failures,
        "some aggregates failed validation and were not published",
    )
}

#[derive(Debug, Deserialize)]
struct AggregateQuery {
    attestation_data_root: Root,
    slot: Slot,
    committee_index: CommitteeIndex,
}

/// `GET /eth/v2/validator/aggregate_attestation`: every vote this node holds
/// for `attestation_data_root` from `committee_index`'s committee at `slot`,
/// aggregated. A 404 when it holds none, which is what the endpoint specifies
/// and what an aggregator reads as "nothing to publish".
async fn get_aggregate_attestation(
    State(store): State<Store>,
    Extension(pool): Extension<SharedAttestationPool>,
    Query(query): Query<AggregateQuery>,
) -> Response {
    let aggregate = pool
        .lock()
        .expect("attestation pool lock poisoned")
        .aggregate(
            query.attestation_data_root,
            query.slot,
            query.committee_index,
        );
    let Some(aggregate) = aggregate else {
        return ApiError::NotFound("no matching attestations to aggregate").into_response();
    };
    let fork = store
        .config()
        .fork_at_epoch(compute_epoch_at_slot(query.slot));
    let response = crate::json_response(serde_json::json!({
        "version": fork.as_str(),
        "data": aggregate,
    }));
    crate::shared::content::with_consensus_version(response, fork)
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
        pool: SharedAttestationPool,
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
            pool: SharedAttestationPool::default(),
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
            .layer(Extension(network))
            .layer(Extension(fixture.pool.clone()));
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

    async fn get_aggregate(
        fixture: &Fixture,
        data_root: Root,
        slot: u64,
        committee: u64,
    ) -> (StatusCode, serde_json::Value) {
        let app = routes()
            .with_state(fixture.store.clone())
            .layer(Extension(fixture.pool.clone()));
        let uri = format!(
            "/eth/v2/validator/aggregate_attestation?attestation_data_root={data_root}&slot={slot}&committee_index={committee}"
        );
        let response = app
            .oneshot(Request::get(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
        )
    }

    /// The aggregator's round trip: its committee's submitted votes come back
    /// combined, with a signature that verifies over the attesters' keys.
    #[tokio::test]
    async fn submitted_attestations_come_back_aggregated() {
        let fixture = fixture();
        let committee = get_beacon_committee(&fixture.state, fixture.state.slot(), 0).unwrap();
        let votes: Vec<SingleAttestation> = (0..committee.len())
            .map(|position| attestation(&fixture, 0, position))
            .collect();
        let (status, _) = submit(&fixture, &votes).await;
        assert_eq!(status, StatusCode::OK);

        let data = votes[0].data;
        let (status, json) = get_aggregate(&fixture, data.hash_tree_root(), data.slot, 0).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["version"], "fulu");

        let bits_hex = json["data"]["aggregation_bits"].as_str().unwrap();
        let bits = hex::decode(bits_hex.trim_start_matches("0x")).unwrap();
        let set: u32 = bits.iter().map(|byte| byte.count_ones()).sum();
        // Every member's bit, plus the bitlist's length-marker bit.
        assert_eq!(set as usize, committee.len() + 1);

        let pubkeys: Vec<_> = committee
            .iter()
            .map(|&index| fixture.state.validator(index).unwrap().pubkey)
            .collect();
        let signature: ethlambda_types::beacon::primitives::BlsSignature =
            serde_json::from_value(json["data"]["signature"].clone()).unwrap();
        let domain = get_domain(
            &fixture.state,
            DOMAIN_BEACON_ATTESTER,
            Some(data.target.epoch),
        );
        let signing_root = compute_signing_root(data.hash_tree_root(), domain);
        assert!(
            ethlambda_state_transition::beacon::bls::fast_aggregate_verify(
                &pubkeys,
                signing_root,
                &signature
            )
        );
    }

    #[tokio::test]
    async fn an_aggregate_with_no_votes_is_a_404() {
        let fixture = fixture();
        let (status, _) =
            get_aggregate(&fixture, Root::repeat_byte(7), fixture.state.slot(), 0).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// A `SignedAggregateAndProof` from `aggregator` over `aggregate`, signed
    /// the way phase0's `validator.md` ("Construct aggregate") says.
    fn signed_aggregate(
        fixture: &Fixture,
        aggregator: u64,
        aggregate: electra::Attestation,
    ) -> electra::SignedAggregateAndProof {
        use ethlambda_types::beacon::constants::{
            DOMAIN_AGGREGATE_AND_PROOF, DOMAIN_SELECTION_PROOF,
        };
        let slot = aggregate.data.slot;
        let epoch = compute_epoch_at_slot(slot);
        let selection_domain = get_domain(&fixture.state, DOMAIN_SELECTION_PROOF, Some(epoch));
        let selection_proof = sign_for(
            aggregator as usize,
            compute_signing_root(slot.hash_tree_root(), selection_domain),
        );
        let message = electra::AggregateAndProof {
            aggregator_index: aggregator,
            aggregate,
            selection_proof,
        };
        let domain = get_domain(&fixture.state, DOMAIN_AGGREGATE_AND_PROOF, Some(epoch));
        let signature = sign_for(
            aggregator as usize,
            compute_signing_root(message.hash_tree_root(), domain),
        );
        electra::SignedAggregateAndProof { message, signature }
    }

    async fn submit_aggregates(
        fixture: &Fixture,
        aggregates: &[electra::SignedAggregateAndProof],
    ) -> (StatusCode, serde_json::Value) {
        let network: RpcToP2PRef = fixture.network.clone();
        let app = routes()
            .with_state(fixture.store.clone())
            .layer(Extension(network))
            .layer(Extension(fixture.pool.clone()));
        let request = Request::post("/eth/v2/validator/aggregate_and_proofs")
            .header("content-type", "application/json")
            .header("eth-consensus-version", "fulu")
            .body(Body::from(serde_json::to_vec(aggregates).unwrap()))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
        )
    }

    /// An aggregator's whole slot through this node: its committee's votes in,
    /// the aggregate back out, and the signed aggregate published.
    #[tokio::test]
    async fn an_aggregator_can_publish_what_it_aggregated() {
        let fixture = fixture();
        let slot = fixture.state.slot();
        let committee = get_beacon_committee(&fixture.state, slot, 0).unwrap();
        let votes: Vec<SingleAttestation> = (0..committee.len())
            .map(|position| attestation(&fixture, 0, position))
            .collect();
        submit(&fixture, &votes).await;
        let aggregate = fixture
            .pool
            .lock()
            .unwrap()
            .aggregate(votes[0].data.hash_tree_root(), slot, 0)
            .unwrap();

        // With 64 validators a committee has two members, fewer than
        // TARGET_AGGREGATORS_PER_COMMITTEE, so every member is an aggregator.
        let signed = signed_aggregate(&fixture, committee[0], aggregate);
        let (status, json) = submit_aggregates(&fixture, std::slice::from_ref(&signed)).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        let published = fixture.network.aggregates.lock().unwrap();
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].0, SignedAggregateAndProof::Electra(signed));
        // Every member voted, so the indices handed on for the chain actor to
        // apply are the whole committee.
        let mut attesting = published[0].1.clone();
        attesting.sort_unstable();
        let mut members = committee.clone();
        members.sort_unstable();
        assert_eq!(attesting, members);
    }

    #[tokio::test]
    async fn an_aggregate_signed_by_someone_else_is_refused() {
        let fixture = fixture();
        let slot = fixture.state.slot();
        let committee = get_beacon_committee(&fixture.state, slot, 0).unwrap();
        let votes: Vec<SingleAttestation> = (0..committee.len())
            .map(|position| attestation(&fixture, 0, position))
            .collect();
        submit(&fixture, &votes).await;
        let aggregate = fixture
            .pool
            .lock()
            .unwrap()
            .aggregate(votes[0].data.hash_tree_root(), slot, 0)
            .unwrap();

        let mut forged = signed_aggregate(&fixture, committee[0], aggregate.clone());
        forged.signature = signed_aggregate(&fixture, committee[1], aggregate).signature;
        let (status, json) = submit_aggregates(&fixture, &[forged]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["failures"][0]["index"], 0);
        assert!(fixture.network.aggregates.lock().unwrap().is_empty());
    }

    /// Gossip never delivers a node its own validator clients' messages, so a
    /// submission through this API is where the node sees them act.
    #[tokio::test]
    async fn a_published_attestation_marks_its_attester_live() {
        let fixture = fixture();
        let attestation = attestation(&fixture, 0, 0);
        let epoch = attestation.data.target.epoch;
        submit(&fixture, std::slice::from_ref(&attestation)).await;
        let observed = fixture.store.observed_liveness();
        assert!(observed.is_live(epoch, attestation.attester_index));
    }

    #[tokio::test]
    async fn a_refused_attestation_marks_nobody_live() {
        let fixture = fixture();
        let mut forged = attestation(&fixture, 0, 0);
        forged.signature = attestation(&fixture, 0, 1).signature;
        let epoch = forged.data.target.epoch;
        submit(&fixture, std::slice::from_ref(&forged)).await;
        assert!(
            !fixture
                .store
                .observed_liveness()
                .is_live(epoch, forged.attester_index)
        );
    }

    /// The aggregate is built on one node and submitted to a fresh one, so its
    /// attesters can only have been marked live by the aggregate itself, not
    /// by their own votes.
    #[tokio::test]
    async fn a_published_aggregate_marks_its_aggregator_and_attesters_live() {
        let builder = fixture();
        let slot = builder.state.slot();
        let committee = get_beacon_committee(&builder.state, slot, 0).unwrap();
        let votes: Vec<SingleAttestation> = (0..committee.len())
            .map(|position| attestation(&builder, 0, position))
            .collect();
        submit(&builder, &votes).await;
        let aggregate = builder
            .pool
            .lock()
            .unwrap()
            .aggregate(votes[0].data.hash_tree_root(), slot, 0)
            .unwrap();

        let fresh = fixture();
        let signed = signed_aggregate(&fresh, committee[0], aggregate);
        let (status, json) = submit_aggregates(&fresh, std::slice::from_ref(&signed)).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        let epoch = compute_epoch_at_slot(slot);
        let observed = fresh.store.observed_liveness();
        for validator in &committee {
            assert!(observed.is_live(epoch, *validator), "{validator}");
        }
    }

    #[tokio::test]
    async fn a_pre_electra_fork_header_is_refused() {
        let fixture = fixture();
        let network: RpcToP2PRef = fixture.network.clone();
        let app = routes()
            .with_state(fixture.store.clone())
            .layer(Extension(network))
            .layer(Extension(fixture.pool.clone()));
        let request = Request::post("/eth/v2/beacon/pool/attestations")
            .header("eth-consensus-version", "deneb")
            .body(Body::from("[]"))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
