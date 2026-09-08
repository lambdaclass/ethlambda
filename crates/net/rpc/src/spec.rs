use axum::{Router, extract::State, response::IntoResponse, routing::get};
use ethlambda_blockchain::INTERVALS_PER_SLOT;
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

/// Serve the timing parameters this node is actually running on.
///
/// The slot duration comes from the network's config file rather than a
/// compile-time constant, so it is read from the store instead of being baked
/// into the response.
async fn get_spec(State(store): State<Store>) -> impl IntoResponse {
    let config = store.config();
    json_response(SpecResponse {
        ms_per_slot: config.milliseconds_per_slot,
        intervals_per_slot: INTERVALS_PER_SLOT,
        ms_per_interval: config.milliseconds_per_interval(),
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
    use ethlambda_blockchain::INTERVALS_PER_SLOT;
    use ethlambda_storage::{Store, backend::InMemoryBackend};
    use ethlambda_types::constants::DEFAULT_MILLISECONDS_PER_SLOT;
    use ethlambda_types::state::HISTORICAL_ROOTS_LIMIT;
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    async fn spec_body(milliseconds_per_slot: u64) -> serde_json::Value {
        let store = Store::from_anchor_state(
            Arc::new(InMemoryBackend::new()),
            create_test_state(),
            milliseconds_per_slot,
        );
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
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn spec_returns_lean_constants() {
        let json = spec_body(DEFAULT_MILLISECONDS_PER_SLOT).await;

        assert_eq!(json["MILLISECONDS_PER_SLOT"], DEFAULT_MILLISECONDS_PER_SLOT);
        assert_eq!(json["INTERVALS_PER_SLOT"], INTERVALS_PER_SLOT);
        assert_eq!(
            json["MILLISECONDS_PER_INTERVAL"],
            DEFAULT_MILLISECONDS_PER_SLOT / INTERVALS_PER_SLOT
        );
        assert_eq!(
            json["HISTORICAL_ROOTS_LIMIT"],
            HISTORICAL_ROOTS_LIMIT as u64
        );
        assert_eq!(json["FORK_DIGEST"], FORK_DIGEST);
    }

    /// The endpoint is what other clients and tooling read the cadence from, so
    /// it has to follow the config file rather than a compile-time constant.
    #[tokio::test]
    async fn spec_reports_the_configured_slot_duration() {
        let json = spec_body(8_000).await;

        assert_eq!(json["MILLISECONDS_PER_SLOT"], 8_000);
        assert_eq!(json["MILLISECONDS_PER_INTERVAL"], 1_600);
        assert_eq!(json["INTERVALS_PER_SLOT"], INTERVALS_PER_SLOT);
    }
}
