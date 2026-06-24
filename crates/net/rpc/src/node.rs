use axum::{Router, extract::State, response::IntoResponse, routing::get};
use ethlambda_blockchain::{MILLISECONDS_PER_SLOT, SYNC_LAG_THRESHOLD};
use ethlambda_storage::Store;
use serde::Serialize;

use crate::json_response;

#[derive(Serialize)]
struct SyncingResponse {
    is_syncing: bool,
    head_slot: u64,
    sync_distance: u64,
    finalized_slot: u64,
}

#[derive(Serialize)]
struct IdentityResponse {
    version: &'static str,
}

/// Simplified sync status: head-vs-wall-clock lag only. Unlike `SyncStatusTracker`
/// it has no hysteresis or stall-override (it is stateless). Sync distance is the
/// number of slots between the node's current head and the current wall-clock slot.
async fn get_syncing(State(store): State<Store>) -> impl IntoResponse {
    let genesis_ms = store.config().genesis_time.saturating_mul(1000);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(genesis_ms);
    let wall_slot = now_ms.saturating_sub(genesis_ms) / MILLISECONDS_PER_SLOT;
    let head_slot = store.head_slot();
    let sync_distance = wall_slot.saturating_sub(head_slot);
    let finalized_slot = store.latest_finalized().slot;
    json_response(SyncingResponse {
        is_syncing: sync_distance > SYNC_LAG_THRESHOLD,
        head_slot,
        sync_distance,
        finalized_slot,
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
    use ethlambda_blockchain::SYNC_LAG_THRESHOLD;
    use ethlambda_storage::{Store, backend::InMemoryBackend};
    use ethlambda_types::state::ChainConfig;
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    use crate::test_utils::create_test_state;

    /// Helper: GET /lean/v0/node/syncing and parse JSON body.
    async fn get_syncing_json(store: Store) -> serde_json::Value {
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
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn node_syncing_far_behind_wall_clock() {
        // create_test_state() has genesis_time=1000 (year 1970), so wall_slot is huge.
        // head_slot=0 → sync_distance is large → is_syncing=true.
        let store = Store::from_anchor_state(Arc::new(InMemoryBackend::new()), create_test_state());
        let json = get_syncing_json(store).await;
        assert_eq!(json["head_slot"], 0);
        assert_eq!(json["finalized_slot"], 0);
        assert!(
            json["sync_distance"].as_u64().unwrap() > SYNC_LAG_THRESHOLD,
            "expected large sync_distance, got {}",
            json["sync_distance"]
        );
        assert_eq!(json["is_syncing"], true);
    }

    #[tokio::test]
    async fn node_syncing_up_to_date() {
        // Set genesis_time to far future so wall_slot=0 and head_slot=0 → not syncing.
        let mut state = create_test_state();
        // Unix timestamp ~year 2100 (4102444800 seconds), well beyond any test run.
        state.config = ChainConfig {
            genesis_time: 4_102_444_800,
        };
        let store = Store::from_anchor_state(Arc::new(InMemoryBackend::new()), state);
        let json = get_syncing_json(store).await;
        assert_eq!(json["head_slot"], 0);
        assert_eq!(json["finalized_slot"], 0);
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
