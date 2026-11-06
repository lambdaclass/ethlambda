//! `POST /eth/v1/validator/proposer_preferences`: signed proposer preferences
//! from a validator client, validated with the gossip rules, cached in the
//! shared `BuilderMarket` and gossiped on `proposer_preferences`.
//!
//! Not gated on the sync status: the specification lists no 503, and a node
//! that lacks the dependent block simply answers `ignore: unknown_block` per
//! entry.

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
    builder_market::SharedBuilderMarket,
    gossip::{IgnoreReason, Outcome, proposer_preferences::validate},
    preset,
};
use ethlambda_storage::Store;
use ethlambda_types::beacon::{containers::gloas::SignedProposerPreferences, fork::ForkName};
use serde::Serialize;
use tracing::{debug, warn};

use crate::beacon::{
    ApiError,
    bids::{describe, require_version, unix_ms},
    decode_list,
};

/// The most entries one request may carry: the SSZ list's bound,
/// `(MIN_SEED_LOOKAHEAD + 1) * SLOTS_PER_EPOCH`.
const MAX_ENTRIES: usize = preset::PROPOSER_LOOKAHEAD_LENGTH;

pub(crate) fn routes() -> Router<Store> {
    Router::new().route(
        "/eth/v1/validator/proposer_preferences",
        post(post_proposer_preferences),
    )
}

/// One refused entry, in the Beacon API's `IndexedErrorMessage` shape.
#[derive(Debug, Serialize)]
struct Failure {
    index: usize,
    message: String,
}

/// `POST /eth/v1/validator/proposer_preferences`.
///
/// Each entry goes through the topic's rules (current slot window, a known
/// dependent block, the proposer the lookahead names, the signature), since a
/// message that fails them is one every peer would score this node down for
/// relaying. Valid ones are cached for block production and for the bids judged
/// against them, then gossiped; the others are reported by position and the
/// rest still go out. An entry already cached, identical, is a success that is
/// not republished.
async fn post_proposer_preferences(
    State(store): State<Store>,
    Extension(p2p): Extension<RpcToP2PRef>,
    Extension(market): Extension<SharedBuilderMarket>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // A validator client submits during the epoch before gloas, when the
    // consensus version it names is still fulu.
    if let Err(err) = require_version(&headers, &[ForkName::Fulu, ForkName::Gloas, ForkName::Heze])
    {
        return err.into_response();
    }
    let preferences = match decode_list::<SignedProposerPreferences>(&headers, &body) {
        Ok(preferences) => preferences,
        Err(err) => return err.into_response(),
    };
    if preferences.len() > MAX_ENTRIES {
        return ApiError::BadRequest("too many signed proposer preferences").into_response();
    }

    let validated =
        tokio::task::spawn_blocking(move || submit(&store, &p2p, &market, preferences)).await;
    let failures = match validated {
        Ok(failures) => failures,
        Err(_) => return ApiError::Internal("validating the preferences failed").into_response(),
    };
    if failures.is_empty() {
        return StatusCode::OK.into_response();
    }
    let body = serde_json::json!({
        "code": 400,
        "message": "some signed proposer preferences failed validation and were not published",
        "failures": failures,
    });
    let mut response = crate::json_response(body);
    *response.status_mut() = StatusCode::BAD_REQUEST;
    response
}

/// Validate, record and publish each entry, in order.
fn submit(
    store: &Store,
    p2p: &RpcToP2PRef,
    market: &SharedBuilderMarket,
    preferences: Vec<SignedProposerPreferences>,
) -> Vec<Failure> {
    let now_ms = unix_ms();
    let wall_slot = crate::beacon::node::wall_slot(store);
    let mut failures = Vec::new();
    for (index, signed) in preferences.into_iter().enumerate() {
        let slot = signed.message.proposal_slot;
        let validator = signed.message.validator_index;
        let held = market.preferences(slot, signed.message.dependent_root);
        if held.as_ref() == Some(&signed) {
            debug!(%slot, validator, "Proposer preferences already cached; not republishing");
            continue;
        }
        let verdict = validate(market, store, &signed, now_ms);
        if verdict != Outcome::Accept {
            let (outcome, reason) = verdict.labels();
            warn!(%slot, validator, outcome, reason, "Refused submitted proposer preferences");
            failures.push(Failure {
                index,
                message: describe(&verdict),
            });
            continue;
        }
        if !market.record_preferences(signed.clone(), wall_slot) {
            failures.push(Failure {
                index,
                message: describe(&Outcome::Ignore(IgnoreReason::AlreadySeen)),
            });
            continue;
        }
        match p2p.publish_proposer_preferences(signed) {
            Ok(()) => debug!(%slot, validator, "Accepted proposer preferences for gossip"),
            Err(_) => failures.push(Failure {
                index,
                message: "the network actor is not running".to_string(),
            }),
        }
    }
    failures
}
