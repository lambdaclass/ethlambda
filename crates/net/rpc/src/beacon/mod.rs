//! The Ethereum Beacon API, served by `ethlambda beacon`.
//!
//! One file per endpoint group. Everything here reads a beacon `Store` through
//! the chain-agnostic accessors only: `Store::head_state`, `head_slot`,
//! `get_block` and `get_block_header` are lean-only and panic on a beacon
//! store, so none of them may appear below this line.

use axum::{
    Router,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use ethlambda_storage::Store;
use ethlambda_types::beacon::{config::Config, fork::ForkName, primitives::Epoch};
use serde::Serialize;

use crate::shared::block_id::IdError;

pub(crate) mod blocks;
pub(crate) mod config;
pub(crate) mod envelopes;
pub(crate) mod genesis;
pub(crate) mod headers;
pub(crate) mod node;
pub(crate) mod pool;
pub(crate) mod proposal;
pub(crate) mod states;
pub(crate) mod validator;
#[cfg(test)]
mod validator_client_tests;

/// The wrapper every fork-versioned Beacon API payload travels in.
///
/// The fork travels here rather than inside `data` because the containers are
/// serialized untagged: an `/eth/v2/beacon/blocks/{id}` body is the block
/// itself, and `version` is how a caller knows which fork's shape it just
/// parsed.
#[derive(Debug, Serialize)]
pub(crate) struct Envelope<T> {
    /// The fork the `data` container belongs to.
    pub(crate) version: &'static str,
    /// Whether the execution payload behind this block is still unverified.
    pub(crate) execution_optimistic: bool,
    /// Whether this block is at or below the finalized checkpoint.
    pub(crate) finalized: bool,
    pub(crate) data: T,
}

/// A Beacon API error body.
///
/// `{"code": …, "message": …}`, deliberately not the lean surface's
/// `{"error": …}`: they are two different APIs and each external consumer
/// parses the shape its own specification names.
#[derive(Debug)]
pub(crate) enum ApiError {
    BadRequest(&'static str),
    NotFound(&'static str),
    Internal(&'static str),
    /// A request this node cannot answer right now, typically because its
    /// execution client did not (the Beacon API's 503).
    ServiceUnavailable(&'static str),
}

/// Refuses `epoch` when the node's schedule places it at gloas: validator
/// duties are not supported from that fork.
///
/// The node follows gloas but only as a follower. It has no builder bid
/// handling, no payload-timeliness committee duty and no gloas proposer
/// flow, and its attestation pool holds electra-shaped votes. An answer for a
/// gloas epoch would carry fulu's shapes under gloas's fork (a vote a
/// validator client would sign as valid, an aggregate of the wrong shape), so
/// it is refused by name, as the submit endpoints refuse the gloas header.
/// Deliberately not [`ethlambda_types::beacon::fork::ForkName::is_followed`]:
/// following a fork and serving its validator duties are different questions.
pub(crate) fn refuse_validator_duties_from_gloas(
    config: &Config,
    epoch: Epoch,
    message: &'static str,
) -> Result<(), ApiError> {
    match config.fork_at_epoch(epoch) {
        ForkName::Phase0
        | ForkName::Altair
        | ForkName::Bellatrix
        | ForkName::Capella
        | ForkName::Deneb
        | ForkName::Electra
        | ForkName::Fulu => Ok(()),
        // `Config::fork_at_epoch` never returns Lean; refused like gloas
        // rather than answered.
        ForkName::Gloas | ForkName::Lean => Err(ApiError::BadRequest(message)),
    }
}

impl From<IdError> for ApiError {
    fn from(err: IdError) -> Self {
        match err {
            IdError::Malformed => ApiError::BadRequest("invalid block id"),
            IdError::NotFound => ApiError::NotFound("block not found"),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            ApiError::NotFound(m) => (StatusCode::NOT_FOUND, m),
            ApiError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
            ApiError::ServiceUnavailable(m) => (StatusCode::SERVICE_UNAVAILABLE, m),
        };
        let body = serde_json::json!({ "code": status.as_u16(), "message": message });
        let mut response = crate::json_response(body);
        *response.status_mut() = status;
        response
    }
}

/// Every route this surface serves.
///
/// Deliberately not a superset of [`crate::build_api_router`]: the `/lean/v0`
/// handlers read lean state variants and metadata keys a beacon directory
/// does not carry, so serving both off one store would answer lean questions
/// with beacon data, or panic trying.
pub(crate) fn routes(version: &'static str, peer_id: String) -> Router<Store> {
    Router::new()
        .merge(blocks::routes())
        .merge(envelopes::routes())
        .merge(headers::routes())
        .merge(states::routes())
        .merge(genesis::routes())
        .merge(config::routes())
        .merge(node::routes(version, peer_id))
        .merge(validator::routes())
        .merge(pool::routes())
        .merge(proposal::routes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt as _;

    #[tokio::test]
    async fn an_error_body_uses_the_beacon_shape() {
        let response = ApiError::NotFound("block not found").into_response();
        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // The Beacon API's shape, not the lean surface's `{"error": ...}`.
        assert_eq!(json["code"], 404);
        assert_eq!(json["message"], "block not found");
    }

    #[test]
    fn validator_duties_are_refused_from_the_gloas_epoch_even_though_gloas_is_followed() {
        let mut config = Config::mainnet();
        config.gloas_fork_epoch = 10;
        assert!(ForkName::Gloas.is_followed());
        let refuse = |epoch| refuse_validator_duties_from_gloas(&config, epoch, "refused");
        assert!(refuse(0).is_ok());
        assert!(refuse(9).is_ok());
        assert!(matches!(refuse(10), Err(ApiError::BadRequest("refused"))));
        assert!(matches!(refuse(11), Err(ApiError::BadRequest("refused"))));
    }

    #[test]
    fn a_malformed_id_is_a_400_and_an_absent_one_a_404() {
        assert_eq!(
            ApiError::from(IdError::Malformed).into_response().status(),
            axum::http::StatusCode::BAD_REQUEST
        );
        assert_eq!(
            ApiError::from(IdError::NotFound).into_response().status(),
            axum::http::StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn the_envelope_names_the_fork_and_the_flags() {
        let envelope = Envelope {
            version: "deneb",
            execution_optimistic: true,
            finalized: false,
            data: serde_json::json!({"slot": "1"}),
        };
        let json = serde_json::to_value(&envelope).unwrap();
        assert_eq!(json["version"], "deneb");
        assert_eq!(json["execution_optimistic"], true);
        assert_eq!(json["finalized"], false);
        assert_eq!(json["data"]["slot"], "1");
    }
}
