use axum::{Router, extract::State, response::IntoResponse, routing::get};
use ethlambda_storage::Store;
use serde::Serialize;

use crate::json_response;

#[derive(Serialize)]
struct GenesisResponse {
    genesis_time: u64,
    validator_count: u64,
}

async fn get_genesis(State(store): State<Store>) -> impl IntoResponse {
    let genesis_time = store.config().genesis_time;
    let validator_count = store.head_state().validators.len() as u64;
    json_response(GenesisResponse {
        genesis_time,
        validator_count,
    })
}

pub(crate) fn routes() -> Router<Store> {
    Router::new().route("/lean/v0/genesis", get(get_genesis))
}

#[cfg(test)]
mod tests {
    use crate::test_utils::create_test_state;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use ethlambda_storage::{Store, backend::InMemoryBackend};
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    #[tokio::test]
    async fn genesis_returns_time_and_validator_count() {
        let state = create_test_state(); // genesis_time = 1000
        let store = Store::from_anchor_state(Arc::new(InMemoryBackend::new()), state);
        let app = crate::build_api_router(store);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/lean/v0/genesis")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["genesis_time"], 1000);
        assert_eq!(json["validator_count"], 0);
    }
}
