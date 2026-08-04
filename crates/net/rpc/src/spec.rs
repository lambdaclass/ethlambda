use axum::{Router, extract::State as AxumState, response::IntoResponse, routing::get};
use ethlambda_blockchain::{INTERVALS_PER_SLOT, MILLISECONDS_PER_INTERVAL, MILLISECONDS_PER_SLOT};
use ethlambda_storage::Store;
use ethlambda_types::{constants::FORK_DIGEST, state::HISTORICAL_ROOTS_LIMIT};
use serde::Serialize;

use crate::json_response;

#[derive(Serialize)]
struct SpecResponse {
    #[serde(rename = "MILLISECONDS_PER_SLOT")]
    ms_per_slot: u64,
    #[serde(rename = "INTERVALS_PER_SLOT")]
    intervals_per_slot: u64,
    #[serde(rename = "MILLISECONDS_PER_INTERVAL")]
    ms_per_interval: u64,
    #[serde(rename = "HISTORICAL_ROOTS_LIMIT")]
    historical_roots_limit: u64,
    /// The network's configured heartbeat committee size, `K`.
    ///
    /// Served next to the interval constants so a devnet can be checked for
    /// agreement without reading configs: a mismatched `K` is a fork-choice
    /// divergence that produces no error, only disagreement.
    #[serde(rename = "HEARTBEAT_COMMITTEE_SIZE")]
    heartbeat_committee_size: u64,
    #[serde(rename = "FORK_DIGEST")]
    fork_digest: &'static str,
}

async fn get_spec(AxumState(store): AxumState<Store>) -> impl IntoResponse {
    json_response(SpecResponse {
        ms_per_slot: MILLISECONDS_PER_SLOT,
        intervals_per_slot: INTERVALS_PER_SLOT,
        ms_per_interval: MILLISECONDS_PER_INTERVAL,
        historical_roots_limit: HISTORICAL_ROOTS_LIMIT as u64,
        heartbeat_committee_size: store.heartbeat_committee_size(),
        fork_digest: FORK_DIGEST,
    })
}

pub(crate) fn routes() -> Router<Store> {
    Router::new().route("/lean/v0/config/spec", get(get_spec))
}

#[cfg(test)]
mod tests {
    use super::FORK_DIGEST;
    use crate::test_utils::create_test_state;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use ethlambda_blockchain::{
        INTERVALS_PER_SLOT, MILLISECONDS_PER_INTERVAL, MILLISECONDS_PER_SLOT,
    };
    use ethlambda_storage::{Store, backend::InMemoryBackend};
    use ethlambda_types::constants::DEFAULT_HEARTBEAT_COMMITTEE_SIZE;
    use ethlambda_types::state::HISTORICAL_ROOTS_LIMIT;
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    #[tokio::test]
    async fn spec_returns_lean_constants() {
        let store = Store::from_anchor_state(Arc::new(InMemoryBackend::new()), create_test_state());
        let app = crate::test_utils::test_api_router(store);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/lean/v0/config/spec")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["MILLISECONDS_PER_SLOT"], MILLISECONDS_PER_SLOT);
        assert_eq!(json["INTERVALS_PER_SLOT"], INTERVALS_PER_SLOT);
        assert_eq!(json["MILLISECONDS_PER_INTERVAL"], MILLISECONDS_PER_INTERVAL);
        assert_eq!(
            json["HISTORICAL_ROOTS_LIMIT"],
            HISTORICAL_ROOTS_LIMIT as u64
        );
        assert_eq!(
            json["HEARTBEAT_COMMITTEE_SIZE"],
            DEFAULT_HEARTBEAT_COMMITTEE_SIZE
        );
        assert_eq!(json["FORK_DIGEST"], FORK_DIGEST);
    }
}
