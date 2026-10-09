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
use serde::Serialize;

use crate::shared::block_id::IdError;

pub(crate) mod bid_selection;
pub(crate) mod bids;
pub(crate) mod blocks;
pub(crate) mod builder_config;
pub(crate) mod builders;
pub(crate) mod config;
pub(crate) mod envelopes;
pub(crate) mod events;
pub(crate) mod genesis;
pub(crate) mod gloas_proposal;
pub(crate) mod graffiti;
pub(crate) mod headers;
pub(crate) mod inclusion_list;
pub(crate) mod node;
pub(crate) mod operations;
pub(crate) mod pool;
pub(crate) mod proposal;
pub(crate) mod proposer_preferences;
pub(crate) mod ptc;
pub(crate) mod states;
pub(crate) mod sync_committee;
pub(crate) mod validator;
#[cfg(test)]
mod validator_client_tests;

/// Request-body cap for the routes that accept blocks, envelopes and blobs.
///
/// Axum's default is 2 MiB, which a fulu `SignedBlockContents` outgrows at
/// about 14 blobs (each blob is 131072 bytes, plus 128 cell proofs of 48 bytes,
/// 6144 bytes, per blob). The preset's `MAX_BLOB_COMMITMENTS_PER_BLOCK` (4096,
/// roughly 550 MB) is no practical bound, so this is sized from what the blob
/// schedule allows in practice instead: a generous 128 blobs and their cell
/// proofs come to about 17.5 MiB, a maximal execution payload (the gloas
/// envelope carries it whole) takes up to roughly 16 MiB more, and the rest is
/// margin for the block and its operations. Applied per route, never router-wide.
pub(crate) const MAX_PUBLISH_BODY_BYTES: usize = 64 * 1024 * 1024;

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
    /// A 400 whose message names the offending input, which a fixed string
    /// cannot (`Invalid topic: weather_forecast`).
    BadRequestDetail(String),
    NotFound(&'static str),
    Internal(&'static str),
    /// A request this node cannot answer right now, typically because its
    /// execution client did not (the Beacon API's 503).
    ServiceUnavailable(&'static str),
    /// A request body in an encoding this endpoint does not take (415). A
    /// client that posted SSZ and gets this one falls back to JSON.
    UnsupportedMediaType(&'static str),
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
        let (status, message): (_, std::borrow::Cow<'static, str>) = match self {
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m.into()),
            ApiError::BadRequestDetail(m) => (StatusCode::BAD_REQUEST, m.into()),
            ApiError::NotFound(m) => (StatusCode::NOT_FOUND, m.into()),
            ApiError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m.into()),
            ApiError::ServiceUnavailable(m) => (StatusCode::SERVICE_UNAVAILABLE, m.into()),
            ApiError::UnsupportedMediaType(m) => (StatusCode::UNSUPPORTED_MEDIA_TYPE, m.into()),
        };
        let body = serde_json::json!({ "code": status.as_u16(), "message": message });
        let mut response = crate::json_response(body);
        *response.status_mut() = status;
        response
    }
}

/// How a request body is encoded, from its `Content-Type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BodyEncoding {
    Json,
    Ssz,
}

impl BodyEncoding {
    /// An absent `Content-Type` is read as JSON, which is what every client
    /// that predates SSZ submission sends. Anything else is a 415 rather than a
    /// guess, so a client that tries SSZ first (prysm) learns this node wants
    /// the other.
    pub(crate) fn from_headers(headers: &axum::http::HeaderMap) -> Result<Self, ApiError> {
        let content_type = headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.split(';').next().unwrap_or("").trim());
        match content_type {
            None | Some("application/json") => Ok(Self::Json),
            Some(crate::SSZ_CONTENT_TYPE) => Ok(Self::Ssz),
            Some(_) => Err(ApiError::UnsupportedMediaType(
                "Content-Type must be application/json or application/octet-stream",
            )),
        }
    }

    /// Decode one container in this encoding, or `None` when the body is not
    /// one. JSON and SSZ go through the same type, so what follows a decode
    /// cannot depend on which one the client chose.
    pub(crate) fn decode<T>(self, body: &[u8]) -> Option<T>
    where
        T: serde::de::DeserializeOwned + libssz::SszDecode,
    {
        match self {
            Self::Json => serde_json::from_slice(body).ok(),
            Self::Ssz => T::from_ssz_bytes(body).ok(),
        }
    }
}

/// Decode the array a batch-submission endpoint takes, as JSON or as the SSZ
/// `List[T, ...]` of the same elements, by the request's `Content-Type`.
pub(crate) fn decode_list<T>(
    headers: &axum::http::HeaderMap,
    body: &[u8],
) -> Result<Vec<T>, ApiError>
where
    T: serde::de::DeserializeOwned + libssz::SszDecode,
{
    let invalid = || ApiError::BadRequest("invalid request body");
    match BodyEncoding::from_headers(headers)? {
        BodyEncoding::Json => serde_json::from_slice(body).map_err(|_| invalid()),
        BodyEncoding::Ssz => {
            <Vec<T> as libssz::SszDecode>::from_ssz_bytes(body).map_err(|_| invalid())
        }
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
        .merge(events::routes())
        .merge(envelopes::routes())
        .merge(headers::routes())
        .merge(states::routes())
        .merge(genesis::routes())
        .merge(config::routes())
        .merge(node::routes(version, peer_id))
        .merge(validator::routes())
        .merge(pool::routes())
        .merge(operations::routes())
        .merge(proposal::routes())
        .merge(gloas_proposal::routes())
        .merge(ptc::routes())
        .merge(inclusion_list::routes())
        .merge(sync_committee::routes())
        .merge(bids::routes())
        .merge(proposer_preferences::routes())
        .merge(builders::routes())
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
