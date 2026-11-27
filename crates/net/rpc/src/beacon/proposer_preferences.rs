//! `POST /eth/v1/validator/proposer_preferences`: signed proposer preferences
//! from a validator client, validated with the gossip rules, cached in the
//! shared `BuilderMarket` and gossiped on `proposer_preferences`. Preferences
//! for the next fork digest's slots are held back by p2p until a slot and a
//! half before its boundary, and a re-send of cached preferences whose
//! publish reached no peer is gossiped again.
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
use ethlambda_network_api::{GossipEvent, RpcToP2PRef};
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
/// against them, then gossiped (those for the next fork digest's slots only a
/// slot and a half before its boundary, which the answer does not reflect); the others
/// are reported by position and the rest still go out. An entry already
/// cached, identical, is a success that is not republished, unless this node
/// still owes it a publish and its slot is still ahead: then the re-send is
/// handed to p2p again.
async fn post_proposer_preferences(
    State(store): State<Store>,
    Extension(p2p): Extension<RpcToP2PRef>,
    Extension(market): Extension<SharedBuilderMarket>,
    events: Option<Extension<EventBus>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Every validator client names gloas, even during the epoch before it:
    // Prysm hardcodes it, the others (this one's too) take the fork of the
    // preference's slot. Fulu is still accepted, as leniency towards a client
    // that names the fork of its wall clock instead.
    if let Err(err) = require_version(&headers, &[ForkName::Fulu, ForkName::Gloas]) {
        return err.into_response();
    }
    let preferences = match decode_list::<SignedProposerPreferences>(&headers, &body) {
        Ok(preferences) => preferences,
        Err(err) => return err.into_response(),
    };
    if preferences.len() > max_entries() {
        return ApiError::BadRequest("too many signed proposer preferences").into_response();
    }

    let events = events.map(|Extension(events)| events);
    let validated = tokio::task::spawn_blocking(move || {
        submit(&store, &p2p, &market, events.as_ref(), preferences)
    })
    .await;
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
fn holds(market: &SharedBuilderMarket, signed: &SignedProposerPreferences) -> bool {
    let message = &signed.message;
    let held = market.preferences(message.proposal_slot, message.dependent_root);
    held.as_ref() == Some(signed)
}

/// Validate, record and publish each entry, in order.
fn submit(
    store: &Store,
    p2p: &RpcToP2PRef,
    market: &SharedBuilderMarket,
    events: Option<&EventBus>,
    preferences: Vec<SignedProposerPreferences>,
) -> Vec<Failure> {
    let now_ms = unix_ms();
    let wall_slot = crate::beacon::node::wall_slot(store);
    let mut failures = Vec::new();
    for (index, signed) in preferences.into_iter().enumerate() {
        let slot = signed.message.proposal_slot;
        let validator = signed.message.validator_index;
        // An entry identical to the one held is a success, checked before
        // `validate` so no rule of it (a started slot, say) can refuse a
        // resubmission, and at no signature check's cost. Asked again after a
        // refusal and after `record_preferences` too: gossip can record the
        // same message (relayed by another node this client posted it to)
        // while this copy is being validated.
        if holds(market, &signed) {
            // This node still owes it a publish: its publish reached no peer
            // (none had joined the topic yet, say), or p2p is holding it back
            // for the next fork digest, in which case p2p holds it again. The
            // re-send is a chance to publish it before the next release or
            // digest switch. Not recorded again, and no second event.
            if market.preferences_publish_owed(&signed) && slot > wall_slot {
                match p2p.republish_proposer_preferences(signed) {
                    Ok(()) => debug!(
                        %slot,
                        validator,
                        "Proposer preferences cached but not gossiped yet; handing them to p2p again"
                    ),
                    Err(_) => failures.push(Failure {
                        index,
                        message: "the network actor is not running".to_string(),
                    }),
                }
            } else {
                debug!(%slot, validator, "Proposer preferences already cached; not republishing");
            }
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
        let for_event = copy_if_listened(events, &signed);
        match p2p.publish_proposer_preferences(signed) {
            Ok(()) => {
                if let Some(signed) = for_event {
                    emit_accepted(events, || {
                        GossipEvent::ProposerPreferences(Box::new(signed))
                    });
                }
                debug!(%slot, validator, "Accepted proposer preferences for gossip")
            }
            Err(_) => failures.push(Failure {
                index,
                message: "the network actor is not running".to_string(),
            }),
        }
    }
    failures
}
