//! `POST /eth/v1/beacon/execution_payload_bids`: a builder's bid handed to this
//! node, validated with the gossip rules, pooled in the shared
//! `BuilderMarket` and gossiped on `execution_payload_bid`.
//!
//! The rules are the topic's own (`gossip::execution_payload_bid`), so a bid
//! that would draw a peer's penalty is refused here instead of being relayed.
//! A refusal is a 400 whatever the verdict: the specification has no 202 for
//! "valid but not forwarded", and a bid this node would ignore on gossip is one
//! it cannot vouch for to the network either.

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
    gossip::{
        IgnoreReason, Outcome,
        execution_payload_bid::{
            MAX_SIGNED_EXECUTION_PAYLOAD_BID_SIZE_HEZE, cheap_checks, stateful_checks,
        },
    },
};
use ethlambda_storage::Store;
use ethlambda_types::beacon::{containers::gloas::SignedExecutionPayloadBid, fork::ForkName};
use tracing::{debug, warn};

use crate::beacon::{ApiError, BodyEncoding};

pub(crate) fn routes() -> Router<Store> {
    Router::new().route("/eth/v1/beacon/execution_payload_bids", post(post_bid))
}

/// A 400 whose message names the verdict, in the Beacon API's error shape.
pub(crate) fn bad_request(message: String) -> Response {
    let body = serde_json::json!({ "code": 400, "message": message });
    let mut response = crate::json_response(body);
    *response.status_mut() = StatusCode::BAD_REQUEST;
    response
}

/// `"{outcome}: {reason}"`, the label pair of a verdict.
pub(crate) fn describe(outcome: &Outcome) -> String {
    let (outcome, reason) = outcome.labels();
    format!("{outcome}: {reason}")
}

pub(crate) fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

/// `Eth-Consensus-Version` is optional, and must name `allowed` when given.
pub(crate) fn require_version(headers: &HeaderMap, allowed: &[ForkName]) -> Result<(), ApiError> {
    let Some(value) = headers.get("eth-consensus-version") else {
        return Ok(());
    };
    match value.to_str().ok().and_then(ForkName::parse) {
        Some(fork) if allowed.contains(&fork) => Ok(()),
        _ => Err(ApiError::BadRequest(
            "Eth-Consensus-Version names a fork this endpoint does not take",
        )),
    }
}

/// `POST /eth/v1/beacon/execution_payload_bids`.
///
/// 1. An identical bid already pooled is a success without republishing, so a
///    builder that retries does not flood the topic.
/// 2. The cheap rules run inline and the stateful ones (cached states, the
///    signature) on a blocking thread.
/// 3. An accepted bid is recorded in the market, which is where block
///    production reads it and where gossip's own seen rules look, then gossiped.
async fn post_bid(
    State(store): State<Store>,
    Extension(p2p): Extension<RpcToP2PRef>,
    Extension(market): Extension<SharedBuilderMarket>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(err) = require_version(&headers, &[ForkName::Gloas, ForkName::Heze]) {
        return err.into_response();
    }
    let encoding = match BodyEncoding::from_headers(&headers) {
        Ok(encoding) => encoding,
        Err(err) => return err.into_response(),
    };
    if encoding == BodyEncoding::Ssz && body.len() > MAX_SIGNED_EXECUTION_PAYLOAD_BID_SIZE_HEZE {
        return ApiError::BadRequest("the SignedExecutionPayloadBid exceeds its size bound")
            .into_response();
    }
    let Some(bid) = encoding.decode::<SignedExecutionPayloadBid>(&body) else {
        return ApiError::BadRequest("the body is not a gloas SignedExecutionPayloadBid")
            .into_response();
    };

    if market.contains_bid(&bid) {
        debug!(
            slot = bid.message.slot,
            builder_index = bid.message.builder_index,
            "Execution payload bid already pooled; not republishing"
        );
        return StatusCode::OK.into_response();
    }
    let verdict = match cheap_checks(&market, &store, &bid, unix_ms()) {
        Ok(()) => {
            let (store, market, bid) = (store.clone(), market.clone(), bid.clone());
            match tokio::task::spawn_blocking(move || stateful_checks(&store, &market, &bid)).await
            {
                Ok(verdict) => verdict,
                Err(_) => {
                    return ApiError::Internal("validating the bid failed").into_response();
                }
            }
        }
        Err(outcome) => outcome,
    };
    if verdict != Outcome::Accept {
        let (outcome, reason) = verdict.labels();
        warn!(
            slot = bid.message.slot,
            builder_index = bid.message.builder_index,
            outcome,
            reason,
            "Refused a submitted execution payload bid"
        );
        return bad_request(describe(&verdict));
    }
    // The state a stateful check read can have moved on, and another bid can
    // have taken the key meanwhile: recording re-runs the seen rules under the
    // market's lock.
    let slot = bid.message.slot;
    let builder_index = bid.message.builder_index;
    if !market.record_bid(bid.clone()) {
        return bad_request(describe(&Outcome::Ignore(IgnoreReason::AlreadySeen)));
    }
    match p2p.publish_execution_payload_bid(bid) {
        Ok(()) => {
            debug!(
                slot,
                builder_index, "Accepted execution payload bid for gossip"
            );
            StatusCode::OK.into_response()
        }
        Err(_) => ApiError::Internal("the network actor is not running").into_response(),
    }
}
