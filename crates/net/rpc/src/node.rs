use axum::{Router, extract::State, response::IntoResponse, routing::get};
use ethlambda_blockchain::{INTERVALS_PER_SLOT, SYNC_LAG_THRESHOLD};
use ethlambda_storage::Store;
use serde::Serialize;

use crate::json_response;

#[derive(Serialize)]
struct SyncingResponse {
    is_syncing: bool,
    head_slot: u64,
    sync_distance: u64,
}

#[derive(Serialize)]
struct IdentityResponse {
    version: &'static str,
}

/// Simplified sync status: head-vs-wall-clock lag only. Unlike `SyncStatusTracker`
/// it has no hysteresis or stall-override (it is stateless).
async fn get_syncing(State(store): State<Store>) -> impl IntoResponse {
    let head_slot = store.head_slot();
    // store.time() counts 800ms intervals from genesis; divide to get wall slot.
    let wall_slot = store.time() / INTERVALS_PER_SLOT;
    let sync_distance = wall_slot.saturating_sub(head_slot);
    json_response(SyncingResponse {
        is_syncing: sync_distance > SYNC_LAG_THRESHOLD,
        head_slot,
        sync_distance,
    })
}

async fn get_identity() -> impl IntoResponse {
    json_response(IdentityResponse {
        version: env!("CARGO_PKG_VERSION"),
    })
}

pub(crate) fn routes() -> Router<Store> {
    Router::new()
        .route("/lean/v0/node/syncing", get(get_syncing))
        .route("/lean/v0/node/identity", get(get_identity))
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use ethlambda_storage::{Store, backend::InMemoryBackend};
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    use crate::test_utils::create_test_state;

    #[tokio::test]
    async fn node_syncing_reports_head_slot() {
        let store = Store::from_anchor_state(Arc::new(InMemoryBackend::new()), create_test_state());
        let app = crate::build_api_router(store);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/lean/v0/node/syncing")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["head_slot"], 0);
        // Fresh store: time=0, head=0 → no lag, not syncing.
        assert_eq!(json["sync_distance"], 0);
        assert_eq!(json["is_syncing"], false);
    }

    #[tokio::test]
    async fn node_identity_reports_version() {
        let store = Store::from_anchor_state(Arc::new(InMemoryBackend::new()), create_test_state());
        let app = crate::build_api_router(store);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/lean/v0/node/identity")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["version"].is_string());
    }
}
