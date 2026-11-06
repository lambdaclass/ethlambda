//! The decoupled fork's validator-facing endpoints.
//!
//! - `GET /eth/v1/validator/decoupled/goldfish_vote_data?slot=`: the head a
//!   slot-`s` committee member votes for, as of `t_s + Δ`.
//! - `POST /eth/v1/beacon/pool/goldfish_votes`: signed votes, checked as
//!   gossip would, pooled for proposals and gossiped.
//! - `GET /eth/v1/validator/decoupled/attestation_input?round=`: what the
//!   validator client's anti-slashing record turns into a combined
//!   attestation, as of the round's attestation time `a_r`.
//! - `POST /eth/v1/beacon/pool/combined_attestations`: signed attestations,
//!   checked, pooled and gossiped.
//! - `GET /eth/v1/decoupled/status`: the node's head, confirmed, stable,
//!   justified and finalized blocks and heights.
//!
//! The record Λ stays in the validator client, as the protocol puts it: the
//! node hands out the store-derived inputs and never sees the record.

use axum::{
    Extension, Router,
    body::Bytes,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use ethlambda_blockchain::SyncStatusController;
use ethlambda_blockchain::metrics::SyncStatus;
use ethlambda_network_api::RpcToP2PRef;
use ethlambda_state_transition::beacon::decoupled_node::{
    SharedDecoupledNode, validate_combined_attestation, validate_goldfish_vote,
};
use ethlambda_storage::Store;
use ethlambda_types::beacon::containers::decoupled::{
    SignedCombinedAttestation, SignedGoldfishVote,
};
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::primitives::Slot;
use ethlambda_types::beacon::signing::compute_epoch_at_slot;
use serde::Deserialize;
use tracing::{debug, warn};

use crate::beacon::pool::{Failure, batch_response};
use crate::beacon::{ApiError, decode_list, validator::head};

pub(crate) fn routes() -> Router<Store> {
    Router::new()
        .route(
            "/eth/v1/validator/decoupled/goldfish_vote_data",
            get(get_goldfish_vote_data),
        )
        .route(
            "/eth/v1/validator/decoupled/attestation_input",
            get(get_attestation_input),
        )
        .route(
            "/eth/v1/beacon/pool/goldfish_votes",
            post(post_goldfish_votes),
        )
        .route(
            "/eth/v1/beacon/pool/combined_attestations",
            post(post_combined_attestations),
        )
        .route("/eth/v1/decoupled/status", get(get_status))
}

/// The decoupled node, or a 400 on a node whose network does not schedule
/// the fork.
fn node(node: &Option<SharedDecoupledNode>) -> Result<&SharedDecoupledNode, ApiError> {
    node.as_ref().ok_or(ApiError::BadRequest(
        "this network does not run the decoupled fork",
    ))
}

fn require_decoupled_slot(store: &Store, slot: Slot) -> Result<(), ApiError> {
    let config = store.config();
    if config.fork_at_epoch(compute_epoch_at_slot(slot)) != ForkName::Decoupled {
        return Err(ApiError::BadRequest("slot is not in the decoupled fork"));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct SlotQuery {
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    slot: Slot,
}

#[derive(Debug, Deserialize)]
struct RoundQuery {
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    round: u64,
}

async fn get_goldfish_vote_data(
    Query(query): Query<SlotQuery>,
    State(store): State<Store>,
    Extension(decoupled): Extension<Option<SharedDecoupledNode>>,
    Extension(sync_status): Extension<SyncStatusController>,
) -> Response {
    let result = (|| {
        let node = node(&decoupled)?;
        require_decoupled_slot(&store, query.slot)?;
        if sync_status.get() == SyncStatus::Syncing {
            return Err(ApiError::ServiceUnavailable("node is syncing"));
        }
        node.lock()
            .expect("decoupled node lock poisoned")
            .goldfish_vote_data(query.slot)
            .map_err(|_| ApiError::BadRequest("slot is not the current slot"))
    })();
    match result {
        Ok(data) => crate::json_response(serde_json::json!({ "data": data })),
        Err(err) => err.into_response(),
    }
}

async fn get_attestation_input(
    Query(query): Query<RoundQuery>,
    State(store): State<Store>,
    Extension(decoupled): Extension<Option<SharedDecoupledNode>>,
    Extension(sync_status): Extension<SyncStatusController>,
) -> Response {
    let result = (|| {
        let node = node(&decoupled)?;
        if sync_status.get() == SyncStatus::Syncing {
            return Err(ApiError::ServiceUnavailable("node is syncing"));
        }
        let mut node = node.lock().expect("decoupled node lock poisoned");
        let opening = node.params().opening_slot(query.round);
        require_decoupled_slot(&store, opening)?;
        node.attestation_input(query.round)
            .map_err(|_| ApiError::BadRequest("round is not the current round"))
    })();
    match result {
        Ok(input) => crate::json_response(serde_json::json!({ "data": input })),
        Err(err) => err.into_response(),
    }
}

/// Each vote is checked against the head state (committee membership and
/// signature), offered to the engine, and gossiped when the engine admitted
/// it. One the engine refused (out of window, a repeat, a third vote) is
/// reported and not gossiped.
async fn post_goldfish_votes(
    State(store): State<Store>,
    Extension(decoupled): Extension<Option<SharedDecoupledNode>>,
    Extension(p2p): Extension<RpcToP2PRef>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let node = match node(&decoupled) {
        Ok(node) => node,
        Err(err) => return err.into_response(),
    };
    let votes = match decode_list::<SignedGoldfishVote>(&headers, &body) {
        Ok(votes) => votes,
        Err(err) => return err.into_response(),
    };
    let (_, state) = match head(&store) {
        Ok(head) => head,
        Err(err) => return err.into_response(),
    };
    let config = store.config();
    let committees = store.committee_cache();
    let mut failures = Vec::new();
    for (index, vote) in votes.into_iter().enumerate() {
        if let Err(err) = validate_goldfish_vote(&state, &config, &committees, &vote) {
            warn!(slot = vote.data.slot, validator = vote.validator_index, %err, "Refused a submitted Goldfish vote");
            failures.push(Failure {
                index,
                message: err.to_string().into(),
            });
            continue;
        }
        let admitted = node
            .lock()
            .expect("decoupled node lock poisoned")
            .add_vote(&vote);
        if !admitted {
            failures.push(Failure {
                index,
                message: "not admitted: outside the slot window or a repeat".into(),
            });
            continue;
        }
        debug!(
            slot = vote.data.slot,
            validator = vote.validator_index,
            "Accepted Goldfish vote"
        );
        if p2p.publish_goldfish_vote(vote).is_err() {
            failures.push(Failure {
                index,
                message: "the network actor is not running".into(),
            });
        }
    }
    batch_response(failures, "some Goldfish votes were refused")
}

async fn post_combined_attestations(
    State(store): State<Store>,
    Extension(decoupled): Extension<Option<SharedDecoupledNode>>,
    Extension(p2p): Extension<RpcToP2PRef>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let node = match node(&decoupled) {
        Ok(node) => node,
        Err(err) => return err.into_response(),
    };
    let attestations = match decode_list::<SignedCombinedAttestation>(&headers, &body) {
        Ok(attestations) => attestations,
        Err(err) => return err.into_response(),
    };
    let (_, state) = match head(&store) {
        Ok(head) => head,
        Err(err) => return err.into_response(),
    };
    let config = store.config();
    let mut failures = Vec::new();
    for (index, attestation) in attestations.into_iter().enumerate() {
        if let Err(err) = validate_combined_attestation(&state, &config, &attestation) {
            warn!(round = attestation.data.round, validator = attestation.validator_index, %err, "Refused a submitted combined attestation");
            failures.push(Failure {
                index,
                message: err.to_string().into(),
            });
            continue;
        }
        let admitted = node
            .lock()
            .expect("decoupled node lock poisoned")
            .add_attestation(&attestation);
        if !admitted {
            failures.push(Failure {
                index,
                message: "not admitted: outside the round window or a repeat".into(),
            });
            continue;
        }
        debug!(
            round = attestation.data.round,
            validator = attestation.validator_index,
            "Accepted combined attestation"
        );
        if p2p.publish_combined_attestation(attestation).is_err() {
            failures.push(Failure {
                index,
                message: "the network actor is not running".into(),
            });
        }
    }
    batch_response(failures, "some combined attestations were refused")
}

async fn get_status(Extension(decoupled): Extension<Option<SharedDecoupledNode>>) -> Response {
    match node(&decoupled) {
        Ok(node) => {
            let mut node = node.lock().expect("decoupled node lock poisoned");
            node.sync();
            crate::json_response(serde_json::json!({ "data": node.status() }))
        }
        Err(_) => (
            StatusCode::NOT_FOUND,
            "this network does not run the decoupled fork",
        )
            .into_response(),
    }
}
