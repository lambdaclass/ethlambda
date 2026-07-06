use axum::{Router, response::IntoResponse, routing::get};
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
    #[serde(rename = "FORK_DIGEST")]
    fork_digest: &'static str,
}

async fn get_spec() -> impl IntoResponse {
    json_response(SpecResponse {
        ms_per_slot: MILLISECONDS_PER_SLOT,
        intervals_per_slot: INTERVALS_PER_SLOT,
        ms_per_interval: MILLISECONDS_PER_INTERVAL,
        historical_roots_limit: HISTORICAL_ROOTS_LIMIT as u64,
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
    use ethlambda_types::state::HISTORICAL_ROOTS_LIMIT;
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    #[tokio::test]
    async fn spec_returns_lean_constants() {
        let store = Store::from_anchor_state(Arc::new(InMemoryBackend::new()), create_test_state());
        let app = crate::build_api_router(store, "ethlambda/test", "test-peer".to_string());
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
        assert_eq!(json["FORK_DIGEST"], FORK_DIGEST);
    }
}
