use axum::{Router, extract::State, response::IntoResponse, routing::get};
use ethlambda_blockchain::MILLISECONDS_PER_SLOT;
use ethlambda_blockchain::metrics::{SyncStatus, node_sync_status};
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

/// Sync status for `/lean/v0/node/syncing`.
///
/// `is_syncing` mirrors the `lean_node_sync_status` metric exactly: it is the
/// blockchain actor's stateful sync decision (head-vs-wall-clock lag with
/// hysteresis and a network-stall override, updated each tick), read back from
/// the metric so the endpoint and the metric can never disagree.
///
/// `head_slot`, `finalized_slot`, and `sync_distance` are a stateless
/// per-request snapshot from the store. `sync_distance` is the raw
/// head-vs-wall-clock slot gap; because `is_syncing` carries hysteresis /
/// stall handling and is *not* recomputed from `sync_distance`, the two can
/// point different ways near the threshold or during a network stall.
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
        is_syncing: node_sync_status() == SyncStatus::Syncing,
        head_slot,
        sync_distance,
        finalized_slot,
    })
}

/// Returns the full client version string, identical to `ethlambda --version`
/// (e.g. `ethlambda/v0.1.0-main-892ad575/x86_64-unknown-linux-gnu/rustc-v1.85.0`):
/// semver, git branch and short SHA, target triple, and rustc version. Sourced
/// from `RpcConfig::version` and captured by the route in `routes`.
async fn get_identity(version: &'static str) -> impl IntoResponse {
    json_response(IdentityResponse { version })
}

pub(crate) fn routes(version: &'static str) -> Router<Store> {
    Router::new()
        .route("/lean/v0/node/syncing", get(get_syncing))
        .route("/lean/v0/node/identity", get(move || get_identity(version)))
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
        let app = crate::build_api_router(store, "ethlambda/test");
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
    async fn node_syncing_sync_distance_far_behind_wall_clock() {
        // create_test_state() has genesis_time=1000 (year 1970), so wall_slot is
        // huge and head_slot=0 → sync_distance is large. (is_syncing is driven by
        // the metric, not sync_distance; see node_syncing_is_syncing_mirrors_metric.)
        let store = Store::from_anchor_state(Arc::new(InMemoryBackend::new()), create_test_state());
        let json = get_syncing_json(store).await;
        assert_eq!(json["head_slot"], 0);
        assert_eq!(json["finalized_slot"], 0);
        assert!(
            json["sync_distance"].as_u64().unwrap() > SYNC_LAG_THRESHOLD,
            "expected large sync_distance, got {}",
            json["sync_distance"]
        );
    }

    #[tokio::test]
    async fn node_syncing_sync_distance_up_to_date() {
        // Set genesis_time to far future so wall_slot=0 and head_slot=0 → sync_distance=0.
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
    }

    #[tokio::test]
    async fn node_syncing_is_syncing_mirrors_metric() {
        use ethlambda_blockchain::metrics::{SyncStatus, set_node_sync_status};

        // is_syncing reflects the lean_node_sync_status metric (the actor's real
        // sync decision), not the raw wall-clock sync_distance. Drive the metric
        // and confirm the endpoint follows it. This is the only test in this
        // binary that writes the process-global gauge, so the set→read sequence
        // is race-free.
        let store = Store::from_anchor_state(Arc::new(InMemoryBackend::new()), create_test_state());

        set_node_sync_status(SyncStatus::Syncing);
        assert_eq!(get_syncing_json(store.clone()).await["is_syncing"], true);

        set_node_sync_status(SyncStatus::Synced);
        assert_eq!(get_syncing_json(store).await["is_syncing"], false);
    }

    #[tokio::test]
    async fn node_identity_reports_version() {
        // The binary injects the real `CLIENT_VERSION` via `RpcConfig::version`;
        // here we inject a sentinel and assert it round-trips verbatim.
        const VERSION: &str =
            "ethlambda/v9.9.9-test-deadbeef/x86_64-unknown-linux-gnu/rustc-v1.92.0";
        let store = Store::from_anchor_state(Arc::new(InMemoryBackend::new()), create_test_state());
        let app = crate::build_api_router(store, VERSION);
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
        assert_eq!(json["version"], VERSION);
    }
}
