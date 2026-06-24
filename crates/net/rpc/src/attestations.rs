use axum::{
    Router,
    extract::{Query, State},
    response::IntoResponse,
    routing::get,
};
use ethlambda_storage::Store;
use serde::{Deserialize, Serialize};

use crate::json_response;

#[derive(Deserialize)]
struct AttQuery {
    slot: Option<u64>,
}

#[derive(Serialize)]
struct AttestationEntry {
    validator_index: u64,
    slot: u64,
    source_slot: u64,
    target_slot: u64,
}

async fn get_attestations(
    Query(q): Query<AttQuery>,
    State(store): State<Store>,
) -> impl IntoResponse {
    let known = store.extract_latest_known_attestations();
    let mut out: Vec<AttestationEntry> = known
        .into_iter()
        .filter(|(_, data)| q.slot.is_none_or(|s| data.slot == s))
        .map(|(validator_index, data)| AttestationEntry {
            validator_index,
            slot: data.slot,
            source_slot: data.source.slot,
            target_slot: data.target.slot,
        })
        .collect();
    out.sort_by_key(|e| e.validator_index);
    json_response(out)
}

pub(crate) fn routes() -> Router<Store> {
    Router::new().route("/lean/v0/attestations", get(get_attestations))
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
    async fn attestations_returns_array() {
        let store = Store::from_anchor_state(Arc::new(InMemoryBackend::new()), create_test_state());
        let app = crate::build_api_router(store);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/lean/v0/attestations")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.is_array());
    }
}
