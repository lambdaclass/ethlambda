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
    let genesis_time = store.config().expect("config exists").genesis_time;
    // Lean validators are fixed at genesis (no churn), so the current head
    // state's validator registry always equals the genesis validator count.
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
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use ethlambda_storage::{Store, backend::InMemoryBackend};
    use ethlambda_types::state::{State, Validator};
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    #[tokio::test]
    async fn genesis_returns_time_and_validator_count() {
        // Build a state with 3 validators so the assertion is non-vacuous.
        let dummy_validator = |index: u64| Validator {
            attestation_pubkey: [0u8; 32],
            proposal_pubkey: [0u8; 32],
            index,
        };
        let validators = vec![dummy_validator(0), dummy_validator(1), dummy_validator(2)];
        let state = State::from_genesis(1000, validators);

        let store = Store::from_anchor_state(Arc::new(InMemoryBackend::new()), state);
        let app = routes().with_state(store);
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
        assert_eq!(json["validator_count"], 3);
    }
}
