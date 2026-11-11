//! The EIP-8453 validator endpoints against a store anchored at an EIP-8453
//! block (the first slot of epoch 1, the fork epoch), with the shared fork
//! choice node installed at it and a fixed clock the tests move.

use super::*;
use crate::test_utils::{RecordingNetwork, idle_engine};
use axum::body::Body;
use axum::http::Request;
use ethlambda_state_transition::beacon::eip8453_fork_choice::tick_start_ms;
use ethlambda_state_transition::beacon::eip8453_test_support::{Scene, scene};
use ethlambda_state_transition::beacon::helpers::eip8453::{
    compute_round_at_slot, get_attestation_committee,
};
use ethlambda_types::beacon::constants::PAYLOAD_STATUS_EMPTY;
use http_body_util::BodyExt as _;
use tower::ServiceExt as _;

const VALIDATORS: usize = 64;

struct Harness {
    scene: Scene,
    clock: NodeClock,
    network: Arc<RecordingNetwork>,
}

impl Harness {
    fn new() -> Self {
        let scene = scene(VALIDATORS);
        let clock = NodeClock::fixed(scene.at(scene.anchor_slot, 0));
        Self {
            scene,
            clock,
            network: Arc::new(RecordingNetwork::default()),
        }
    }

    /// Every EIP-8453 endpoint, the attestation pool, the states and the
    /// legacy validator endpoints, with the node, the network and the clock.
    fn router(&self) -> Router {
        self.router_with(self.scene.node.clone())
    }

    fn router_with(&self, node: SharedEip8453Node) -> Router {
        let p2p: RpcToP2PRef = self.network.clone();
        routes()
            .merge(crate::beacon::pool::routes())
            .merge(crate::beacon::states::routes())
            .merge(crate::beacon::validator::routes())
            .with_state(self.scene.store.clone())
            .layer(Extension(node))
            .layer(Extension(p2p))
            .layer(Extension(self.clock.clone()))
            .layer(Extension(idle_engine()))
            .layer(Extension(ethlambda_blockchain::SyncStatusController::new(
                ethlambda_blockchain::metrics::SyncStatus::Synced,
            )))
    }

    /// The instant `quarter` quarters into `slot`, where the engine's ticks
    /// fall.
    fn quarter(&self, slot: Slot, quarter: u64) -> u64 {
        tick_start_ms(&self.scene.config, (4 * slot + quarter) as i64)
    }

    /// Move the clock to `now` and run the node's ticks up to it, as the chain
    /// actor would have.
    fn set_time(&self, now: u64) {
        self.clock.set(now);
        self.scene
            .node
            .with(|node| {
                node.advance_to_ms(now);
            })
            .expect("the node runs");
    }

    async fn send(&self, router: Router, request: Request<Body>) -> (StatusCode, HeaderMap, Value) {
        let response = router.oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            headers,
            serde_json::from_slice(&body).unwrap_or_default(),
        )
    }

    async fn get(&self, uri: &str) -> (StatusCode, HeaderMap, Value) {
        let request = Request::get(uri).body(Body::empty()).unwrap();
        self.send(self.router(), request).await
    }

    async fn post(&self, uri: &str, fork: Option<&str>, body: Value) -> (StatusCode, Value) {
        let mut request = Request::post(uri).header("content-type", "application/json");
        if let Some(fork) = fork {
            request = request.header("eth-consensus-version", fork);
        }
        let request = request.body(Body::from(body.to_string())).unwrap();
        let (status, _, body) = self.send(self.router(), request).await;
        (status, body)
    }
}

use serde_json::Value;

fn all_indices() -> Value {
    serde_json::json!((0..VALIDATORS).map(|i| i.to_string()).collect::<Vec<_>>())
}

fn quoted(values: &[u64]) -> Vec<String> {
    values.iter().map(u64::to_string).collect()
}

fn decimal(value: &Value) -> u64 {
    value.as_str().expect("a quoted integer").parse().unwrap()
}

// ── Duties ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn attestation_committee_duties_name_each_validators_committee_and_slots() {
    let h = Harness::new();
    let epoch = compute_epoch_at_slot(h.scene.anchor_slot);
    let uri = format!("/eth/v1/validator/duties/attestation_committee/{epoch}");
    let (status, body) = h.post(&uri, None, all_indices()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let duties = body["data"].as_array().unwrap();
    // Every active validator sits on exactly one committee an epoch.
    assert_eq!(duties.len(), VALIDATORS);
    for duty in duties {
        let validator = decimal(&duty["validator_index"]);
        let committee_index = decimal(&duty["committee_index"]);
        let committee = get_attestation_committee(&h.scene.state, epoch, committee_index).unwrap();
        assert_eq!(decimal(&duty["committee_length"]), committee.len() as u64);
        let position = decimal(&duty["validator_committee_index"]) as usize;
        assert_eq!(committee[position], validator);
        let slots = attestation_committee_slots(epoch, committee_index).unwrap();
        assert_eq!(
            slots.len() as u64,
            preset::SLOTS_PER_EPOCH / preset::SLOTS_PER_ROUND
        );
        assert_eq!(duty["slots"], serde_json::json!(quoted(&slots)));
        let pubkey = h.scene.state.validator(validator).unwrap().pubkey;
        assert_eq!(duty["pubkey"], serde_json::to_value(pubkey).unwrap());
    }
    assert!(body["dependent_root"].is_string());

    // Only the validators asked about.
    let (_, body) = h.post(&uri, None, serde_json::json!(["3"])).await;
    assert_eq!(body["data"].as_array().unwrap().len(), 1);

    // The epoch before the fork has no attestation committees.
    let uri = format!(
        "/eth/v1/validator/duties/attestation_committee/{}",
        epoch - 1
    );
    let (status, _) = h.post(&uri, None, all_indices()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn head_vote_duties_name_the_slots_each_validator_votes_in() {
    let h = Harness::new();
    let epoch = compute_epoch_at_slot(h.scene.anchor_slot);
    let uri = format!("/eth/v1/validator/duties/head_vote/{epoch}");
    let (status, body) = h.post(&uri, None, all_indices()).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // The answer is exactly the committees of the epoch's slots, each member
    // once per slot however many seats it holds.
    let mut expected: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    let start = compute_start_slot_at_epoch(epoch);
    for slot in start..start + preset::SLOTS_PER_EPOCH {
        for member in h.scene.committee(slot) {
            let slots = expected.entry(member).or_default();
            if slots.last() != Some(&slot) {
                slots.push(slot);
            }
        }
    }
    let answered: BTreeMap<u64, Value> = body["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|duty| (decimal(&duty["validator_index"]), duty["slots"].clone()))
        .collect();
    assert_eq!(answered.len(), expected.len());
    for (validator, slots) in expected {
        assert_eq!(answered[&validator], serde_json::json!(quoted(&slots)));
    }

    // Also the next epoch, from the same state's window.
    let uri = format!("/eth/v1/validator/duties/head_vote/{}", epoch + 1);
    assert_eq!(h.post(&uri, None, all_indices()).await.0, StatusCode::OK);

    // Not before the fork.
    let uri = format!("/eth/v1/validator/duties/head_vote/{}", epoch - 1);
    assert_eq!(
        h.post(&uri, None, all_indices()).await.0,
        StatusCode::BAD_REQUEST
    );
    let uri = format!("/eth/v1/validator/duties/head_vote/{epoch}");
    assert_eq!(
        h.post(&uri, None, serde_json::json!(["x"])).await.0,
        StatusCode::BAD_REQUEST
    );
}

#[test]
fn the_head_vote_committees_of_the_fork_epoch_depend_on_the_last_pre_fork_block() {
    let config = ethlambda_state_transition::beacon::eip8453_test_support::config();
    let fork = config.eip8453_fork_epoch;
    let last_slot_of = |epoch: Epoch| compute_start_slot_at_epoch(epoch + 1) - 1;
    // Drawn by `upgrade_to_eip8453` at the fork's first slot.
    assert_eq!(dependent_slot(&config, fork, true), last_slot_of(fork - 1));
    // Every later epoch's at the transition into the epoch before it, as the
    // attestation committees' (conservatively) are throughout.
    assert_eq!(
        dependent_slot(&config, fork + 1, true),
        last_slot_of(fork - 1)
    );
    assert_eq!(dependent_slot(&config, fork + 2, true), last_slot_of(fork));
    assert_eq!(dependent_slot(&config, fork + 2, false), last_slot_of(fork));
    assert_eq!(dependent_slot(&config, fork, false), 0);
}

#[tokio::test]
async fn proposer_duties_are_read_off_the_eip8453_lookahead() {
    let h = Harness::new();
    let epoch = compute_epoch_at_slot(h.scene.anchor_slot);
    let uri = format!("/eth/v1/validator/duties/proposer/{epoch}");
    let (status, _, body) = h.get(&uri).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let BeaconState::Eip8453(inner) = h.scene.state.as_ref() else {
        unreachable!("the scene is anchored at an EIP-8453 state")
    };
    let duties = body["data"].as_array().unwrap();
    assert_eq!(duties.len() as u64, preset::SLOTS_PER_EPOCH);
    for (duty, proposer) in duties.iter().zip(inner.proposer_lookahead.iter()) {
        assert_eq!(decimal(&duty["validator_index"]), *proposer);
    }
}

#[tokio::test]
async fn the_legacy_attester_endpoints_refuse_an_eip8453_epoch() {
    let h = Harness::new();
    let slot = h.scene.anchor_slot;
    let epoch = compute_epoch_at_slot(slot);
    let uri = format!("/eth/v1/validator/duties/attester/{epoch}");
    let (status, body) = h.post(&uri, None, all_indices()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("attestation_committee")
    );
    let uri = format!("/eth/v1/validator/attestation_data?slot={slot}");
    let (status, _, body) = h.get(&uri).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["message"].as_str().unwrap().contains("head_vote_data"));
}

// ── Duty data ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn head_vote_data_is_the_vote_head_at_the_slots_deadline() {
    let h = Harness::new();
    let slot = h.scene.anchor_slot + 1;
    let uri = format!("/eth/v1/validator/head_vote_data?slot={slot}");

    // Before the deadline the input is not there yet.
    h.set_time(h.quarter(slot, 0));
    assert_eq!(h.get(&uri).await.0, StatusCode::SERVICE_UNAVAILABLE);

    h.set_time(h.quarter(slot, 1));
    let (status, headers, body) = h.get(&uri).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(headers["eth-consensus-version"], "eip8453");
    assert_eq!(body["version"], "eip8453");
    let expected: eip8453::HeadVoteData = h
        .scene
        .node
        .with(|n| n.vote_head(slot, h.quarter(slot, 1)))
        .unwrap()
        .unwrap()
        .into();
    assert_eq!(body["data"], serde_json::to_value(expected).unwrap());
    // No block of its own slot: the anchor, on its EMPTY branch.
    assert_eq!(expected.beacon_block_root, h.scene.anchor_root);
    assert_eq!(expected.payload_status, PAYLOAD_STATUS_EMPTY);
    assert_eq!(decimal(&body["data"]["slot"]), slot);

    // Another slot than the current one, and a pre-fork one, are the
    // caller's mistakes.
    let uri = format!("/eth/v1/validator/head_vote_data?slot={}", slot + 1);
    assert_eq!(h.get(&uri).await.0, StatusCode::BAD_REQUEST);
    let uri = format!("/eth/v1/validator/head_vote_data?slot={}", slot - 2);
    assert_eq!(h.get(&uri).await.0, StatusCode::BAD_REQUEST);

    // A node whose fork choice does not run yet cannot answer.
    let uri = format!("/eth/v1/validator/head_vote_data?slot={slot}");
    let request = Request::get(&uri).body(Body::empty()).unwrap();
    let (status, _, _) = h
        .send(h.router_with(SharedEip8453Node::new()), request)
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn the_finality_attestation_input_is_served_from_the_support_cutoff() {
    let h = Harness::new();
    let slot = h.scene.anchor_slot + 1;
    let uri = format!("/eth/v1/validator/finality_attestation_input?slot={slot}");

    h.set_time(h.quarter(slot, 1));
    assert_eq!(h.get(&uri).await.0, StatusCode::SERVICE_UNAVAILABLE);

    // No head vote has confirmed anything: there is no FG source, and the
    // validator must not attest.
    h.set_time(h.quarter(slot, 2));
    let (status, _, _) = h.get(&uri).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The next slot's whole committee votes for the anchor; at the support
    // cutoff of the slot after, which confirms it, the anchor passes the fast
    // test and is the source.
    let voted = slot + 1;
    h.set_time(h.scene.at(voted, 1_000));
    let mut voters = h.scene.committee(voted);
    voters.sort_unstable();
    voters.dedup();
    for voter in voters {
        let message = h
            .scene
            .head_vote(voter, head_vote_data(voted, h.scene.anchor_root));
        let outcome = head_vote::submit(&h.scene.store, &h.scene.node, &message, h.clock.now_ms());
        assert_eq!(outcome, Outcome::Accept);
    }
    let slot = voted + 1;
    let uri = format!("/eth/v1/validator/finality_attestation_input?slot={slot}");
    h.set_time(h.quarter(slot, 2));
    let (status, headers, body) = h.get(&uri).await;
    let expected = h
        .scene
        .node
        .with(|n| n.finality_attestation_input(slot, h.quarter(slot, 2)))
        .unwrap()
        .unwrap()
        .expect("the anchor is the FG source");
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(headers["eth-consensus-version"], "eip8453");
    let target: eip8453::HeightCheckpoint = expected.target.into();
    let justified: eip8453::HeightCheckpoint = expected.justified.into();
    assert_eq!(
        body["data"]["target"],
        serde_json::to_value(target).unwrap()
    );
    assert_eq!(
        body["data"]["justified"],
        serde_json::to_value(justified).unwrap()
    );
    assert_eq!(
        decimal(&body["data"]["finalized_height"]),
        expected.finalized_height
    );
    assert_eq!(target.height, 1);
    assert_eq!(target.root, h.scene.anchor_root);

    let uri = format!(
        "/eth/v1/validator/finality_attestation_input?slot={}",
        slot - 2
    );
    assert_eq!(h.get(&uri).await.0, StatusCode::BAD_REQUEST);
}

// ── Submissions ─────────────────────────────────────────────────────────────

fn head_vote_data(slot: Slot, root: ethlambda_types::primitives::H256) -> eip8453::HeadVoteData {
    eip8453::HeadVoteData {
        slot,
        beacon_block_root: root,
        payload_status: PAYLOAD_STATUS_EMPTY,
    }
}

#[tokio::test]
async fn a_submitted_head_vote_reaches_the_fork_choice_and_is_gossiped_once() {
    let h = Harness::new();
    let slot = h.scene.anchor_slot + 1;
    h.set_time(h.scene.at(slot, 1_000));
    let voter = h.scene.committee(slot)[0];
    let message = h
        .scene
        .head_vote(voter, head_vote_data(slot, h.scene.anchor_root));
    let body = serde_json::json!([message]);

    let (status, response) = h
        .post("/eth/v1/beacon/pool/head_votes", None, body.clone())
        .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(*h.network.head_votes.lock().unwrap(), vec![message.clone()]);
    h.scene
        .node
        .with(|n| assert_eq!(n.pooled_head_votes(slot), std::slice::from_ref(&message)))
        .unwrap();

    // A resubmission is not a failure, and is not gossiped again.
    let (status, _) = h.post("/eth/v1/beacon/pool/head_votes", None, body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h.network.head_votes.lock().unwrap().len(), 1);

    // A forged signature is refused by index; the batch's other votes apply.
    let other = h
        .scene
        .committee(slot)
        .into_iter()
        .find(|&member| member != voter)
        .expect("a second committee member");
    let mut forged = h
        .scene
        .head_vote(other, head_vote_data(slot, h.scene.anchor_root));
    forged.signature = message.signature;
    let (status, response) = h
        .post(
            "/eth/v1/beacon/pool/head_votes",
            None,
            serde_json::json!([forged]),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(response["failures"][0]["index"], 0);
    assert_eq!(h.network.head_votes.lock().unwrap().len(), 1);
}

fn fg_data(root: ethlambda_types::primitives::H256) -> eip8453::AttestationData {
    eip8453::AttestationData {
        target: eip8453::HeightCheckpoint { height: 1, root },
        timeout: false,
        finality: eip8453::HeightCheckpoint::empty(),
    }
}

#[tokio::test]
async fn a_submitted_fg_attestation_is_pooled_and_gossiped_on_its_subnet() {
    let h = Harness::new();
    let slot = h.scene.anchor_slot;
    h.set_time(h.scene.at(slot, 1_000));
    let (committee_index, members) = h.scene.attestation_committee_at(slot);
    let epoch = compute_epoch_at_slot(slot);
    let attestation = h.scene.attestation(
        members[0],
        committee_index,
        epoch,
        fg_data(h.scene.anchor_root),
    );
    let uri = "/eth/v2/beacon/pool/attestations";

    let (status, response) = h
        .post(uri, Some("eip8453"), serde_json::json!([attestation]))
        .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let subnet = fg_attestation::compute_subnet_for_attestation(&h.scene.config, committee_index);
    assert_eq!(
        *h.network.fg_attestations.lock().unwrap(),
        vec![(subnet, attestation.clone())]
    );
    let round = compute_round_at_slot(slot);
    h.scene
        .node
        .with(|n| {
            assert_eq!(
                n.pooled_attestations(round),
                std::slice::from_ref(&attestation)
            )
        })
        .unwrap();

    // An attestation naming a pre-fork epoch is refused by index.
    let mut early = attestation.clone();
    early.epoch = epoch - 1;
    let (status, response) = h
        .post(uri, Some("eip8453"), serde_json::json!([early]))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(response["failures"][0]["index"], 0);
    assert_eq!(h.network.fg_attestations.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_legacy_attestation_header_is_refused_at_an_eip8453_slot() {
    let h = Harness::new();
    let slot = h.scene.anchor_slot;
    // An electra `SingleAttestation` for the slot, under heze's header.
    let attestation = serde_json::json!([{
        "committee_index": "0",
        "attester_index": "0",
        "data": {
            "slot": slot.to_string(),
            "index": "0",
            "beacon_block_root": h.scene.anchor_root,
            "source": {"epoch": "0", "root": h.scene.anchor_root},
            "target": {"epoch": "1", "root": h.scene.anchor_root},
        },
        "signature": ethlambda_types::beacon::primitives::BlsSignature::default(),
    }]);
    let (status, response) = h
        .post(
            "/eth/v2/beacon/pool/attestations",
            Some("heze"),
            attestation,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        response["failures"][0]["message"]
            .as_str()
            .unwrap()
            .contains("Eth-Consensus-Version")
    );
}

// ── States ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn finality_checkpoints_of_an_eip8453_state_are_the_gadgets_heights() {
    let h = Harness::new();
    let (status, headers, body) = h
        .get("/eth/v1/beacon/states/head/finality_checkpoints")
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(headers["eth-consensus-version"], "eip8453");
    let BeaconState::Eip8453(inner) = h.scene.state.as_ref() else {
        unreachable!("the scene is anchored at an EIP-8453 state")
    };
    let data = &body["data"];
    assert_eq!(
        data["target"],
        serde_json::to_value(inner.target_checkpoint).unwrap()
    );
    assert_eq!(
        data["current_justified"],
        serde_json::to_value(inner.justified_checkpoint).unwrap()
    );
    assert_eq!(
        data["finalized"],
        serde_json::to_value(inner.finalized_checkpoint).unwrap()
    );
    assert_eq!(decimal(&data["finalized_slot"]), inner.finalized_slot);
    assert_eq!(decimal(&data["target_slot"]), inner.target_slot);
    assert!(data.get("previous_justified").is_none());
    // Heights, not epochs.
    assert!(data["finalized"].get("height").is_some());
}
