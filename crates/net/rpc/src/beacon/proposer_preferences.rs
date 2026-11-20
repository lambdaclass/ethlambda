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
use ethlambda_blockchain::EventBus;
use ethlambda_network_api::{GossipEvent, PqGossipObject, RpcToP2PRef};
use ethlambda_state_transition::beacon::{
    builder_market::{
        BuilderMarket, SharedBuilderMarket, SharedPqBuilderMarket, SignedBid, SignedPreferences,
    },
    gossip::{
        IgnoreReason, Outcome,
        proposer_preferences::{PreferencesRules, validate},
    },
    preset,
};
use ethlambda_storage::Store;
use ethlambda_types::beacon::{
    containers::{gloas::SignedProposerPreferences, pq},
    fork::ForkName,
};
use serde::Serialize;
use tracing::{debug, warn};

use crate::beacon::{
    ApiError,
    bids::{describe, require_version, unix_ms},
    copy_if_listened, decode_list, emit_accepted,
};

/// The most entries one request may carry: the SSZ list's bound,
/// `(MIN_SEED_LOOKAHEAD + 1) * SLOTS_PER_EPOCH`.
fn max_entries() -> usize {
    preset::proposer_lookahead_length()
}

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
///
/// Under `Eth-Consensus-Version: pq` the entries are PQ's container, signed
/// with leanXMSS, judged by the same rules over the PQ builder market gossip
/// validates against.
async fn post_proposer_preferences(
    State(store): State<Store>,
    Extension(p2p): Extension<RpcToP2PRef>,
    Extension(market): Extension<SharedBuilderMarket>,
    pq_market: Option<Extension<SharedPqBuilderMarket>>,
    events: Option<Extension<EventBus>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Every validator client names gloas, even during the epoch before it:
    // Prysm hardcodes it, the others (this one's too) take the fork of the
    // preference's slot. Fulu is still accepted, as leniency towards a client
    // that names the fork of its wall clock instead.
    if let Err(err) = require_version(&headers, &[ForkName::Fulu, ForkName::Gloas, ForkName::Pq]) {
        return err.into_response();
    }
    let is_pq = headers
        .get("eth-consensus-version")
        .and_then(|value| value.to_str().ok())
        .and_then(ForkName::parse)
        == Some(ForkName::Pq);
    let events = events.map(|Extension(events)| events);
    let validated = if is_pq {
        let Some(Extension(market)) = pq_market else {
            return ApiError::Internal("no PQ builder market").into_response();
        };
        let preferences = match decode_list::<pq::SignedProposerPreferences>(&headers, &body) {
            Ok(preferences) => preferences,
            Err(err) => return err.into_response(),
        };
        if preferences.len() > max_entries() {
            return ApiError::BadRequest("too many signed proposer preferences").into_response();
        }
        tokio::task::spawn_blocking(move || {
            submit(&store, &market, preferences, |signed| {
                p2p.publish_pq_gossip(PqGossipObject::ProposerPreferences(Box::new(signed)))
                    .map_err(|_| ())
            })
        })
        .await
    } else {
        let preferences = match decode_list::<SignedProposerPreferences>(&headers, &body) {
            Ok(preferences) => preferences,
            Err(err) => return err.into_response(),
        };
        if preferences.len() > max_entries() {
            return ApiError::BadRequest("too many signed proposer preferences").into_response();
        }
        tokio::task::spawn_blocking(move || {
            submit(&store, &market, preferences, |signed| {
                let for_event = copy_if_listened(events.as_ref(), &signed);
                p2p.publish_proposer_preferences(signed)
                    .map_err(|_| ())
                    .inspect(|()| {
                        if let Some(signed) = for_event {
                            emit_accepted(events.as_ref(), || {
                                GossipEvent::ProposerPreferences(Box::new(signed))
                            });
                        }
                    })
            })
        })
        .await
    };
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

/// Whether `market` holds `signed` itself for its slot and dependent root,
/// rather than another message: an identical entry is a success.
fn holds<B: SignedBid, P: SignedPreferences + PartialEq>(
    market: &BuilderMarket<B, P>,
    signed: &P,
) -> bool {
    let message = signed.message();
    let held = market.preferences(message.proposal_slot, message.dependent_root);
    held.as_ref() == Some(signed)
}

/// Validate, record and publish each entry, in order.
fn submit<B: SignedBid, P: PreferencesRules + PartialEq>(
    store: &Store,
    market: &BuilderMarket<B, P>,
    preferences: Vec<P>,
    mut publish: impl FnMut(P) -> Result<(), ()>,
) -> Vec<Failure> {
    let now_ms = unix_ms();
    let wall_slot = crate::beacon::node::wall_slot(store);
    let mut failures = Vec::new();
    for (index, signed) in preferences.into_iter().enumerate() {
        let slot = signed.message().proposal_slot;
        let validator = signed.message().validator_index;
        // An entry identical to the one held is a success, checked before
        // `validate` so no rule of it (a started slot, say) can refuse a
        // resubmission, and at no signature check's cost. Asked again after a
        // refusal and after `record_preferences` too: gossip can record the
        // same message (relayed by another node this client posted it to)
        // while this copy is being validated.
        if holds(market, &signed) {
            debug!(%slot, validator, "Proposer preferences already cached; not republishing");
            continue;
        }
        let verdict = validate(market, store, &signed, now_ms);
        if verdict != Outcome::Accept {
            // Gossip may have recorded this very message since the check
            // above, and `validate` then calls it already seen.
            if holds(market, &signed) {
                debug!(%slot, validator, "Proposer preferences cached meanwhile; not republishing");
                continue;
            }
            let (outcome, reason) = verdict.labels();
            warn!(%slot, validator, outcome, reason, "Refused submitted proposer preferences");
            failures.push(Failure {
                index,
                message: describe(&verdict),
            });
            continue;
        }
        if !market.record_preferences(signed.clone(), wall_slot) {
            if holds(market, &signed) {
                debug!(%slot, validator, "Proposer preferences cached meanwhile; not republishing");
                continue;
            }
            failures.push(Failure {
                index,
                message: describe(&Outcome::Ignore(IgnoreReason::AlreadySeen)),
            });
            continue;
        }
        match publish(signed) {
            Ok(()) => debug!(%slot, validator, "Accepted proposer preferences for gossip"),
            Err(()) => failures.push(Failure {
                index,
                message: "the network actor is not running".to_string(),
            }),
        }
    }
    failures
}
