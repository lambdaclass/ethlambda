use axum::{Extension, Router, extract::State, response::IntoResponse, routing::get};
use ethlambda_blockchain::metrics::SyncStatus;
use ethlambda_blockchain::{MILLISECONDS_PER_SLOT, SyncStatusController};
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
    /// This node's libp2p peer ID (base58), as it appears to peers on the wire.
    peer_id: String,
}

/// Sync status for `/lean/v0/node/syncing`.
///
/// `is_syncing` reads the node's own sync decision from the shared
/// [`SyncStatusController`]: head-vs-wall-clock lag with hysteresis and a
/// network-stall override, updated each tick by the blockchain actor. It is the
/// same signal that gates validator duties and drives the `lean_node_sync_status`
/// metric, so the endpoint agrees with both.
///
/// `head_slot`, `finalized_slot`, and `sync_distance` are a stateless
/// per-request snapshot from the store. `sync_distance` is the raw
/// head-vs-wall-clock slot gap; because `is_syncing` carries hysteresis /
/// stall handling and is *not* recomputed from `sync_distance`, the two can
/// point different ways near the threshold or during a network stall.
async fn get_syncing(
    State(store): State<Store>,
    Extension(sync_status): Extension<SyncStatusController>,
) -> impl IntoResponse {
    let genesis_ms = store
        .config()
        .expect("config exists")
        .genesis_time
        .saturating_mul(1000);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(genesis_ms);
    let wall_slot = now_ms.saturating_sub(genesis_ms) / MILLISECONDS_PER_SLOT;
    let head_slot = store.head_slot();
    let sync_distance = wall_slot.saturating_sub(head_slot);
    let finalized_slot = store
        .latest_finalized()
        .expect("finalized block exists")
        .slot;
    json_response(SyncingResponse {
        is_syncing: sync_status.get() == SyncStatus::Syncing,
        head_slot,
        sync_distance,
        finalized_slot,
    })
}

/// Reports node identity: the full client version string (identical to
/// `ethlambda --version`: semver, git branch and short SHA, target triple, and
/// rustc version) and the node's libp2p peer ID. Both are fixed at startup and
/// captured by the route in `routes`.
async fn get_identity(version: &'static str, peer_id: String) -> impl IntoResponse {
    json_response(IdentityResponse { version, peer_id })
}

pub(crate) fn routes(version: &'static str, peer_id: String) -> Router<Store> {
    Router::new()
        .route("/lean/v0/node/syncing", get(get_syncing))
        .route(
            "/lean/v0/node/identity",
            get(move || get_identity(version, peer_id.clone())),
        )
}

#[cfg(test)]
mod tests {
    use axum::{
        Extension,
        body::Body,
        http::{Request, StatusCode},
    };
    use ethlambda_blockchain::SyncStatusController;
    use ethlambda_blockchain::metrics::SyncStatus;
    use ethlambda_storage::{Store, backend::InMemoryBackend};
    use ethlambda_types::state::ChainConfig;
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    use crate::test_utils::create_test_state;

    /// Helper: GET /lean/v0/node/syncing (with the given sync controller) and
    /// parse the JSON body.
    async fn get_syncing_json(store: Store, sync: SyncStatusController) -> serde_json::Value {
        let app = crate::test_utils::test_api_router(store).layer(Extension(sync));
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
        // huge and head_slot=0 → sync_distance is hundreds of millions of slots.
        // Assert it's clearly far behind, not a small transient lag. (is_syncing
        // comes from the controller, not sync_distance; see
        // node_syncing_reflects_controller.)
        let store = Store::from_anchor_state(Arc::new(InMemoryBackend::new()), create_test_state());
        let json = get_syncing_json(store, SyncStatusController::default()).await;
        assert_eq!(json["head_slot"], 0);
        assert_eq!(json["finalized_slot"], 0);
        assert!(
            json["sync_distance"].as_u64().unwrap() > 1_000_000,
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
        let json = get_syncing_json(store, SyncStatusController::default()).await;
        assert_eq!(json["head_slot"], 0);
        assert_eq!(json["finalized_slot"], 0);
        assert_eq!(json["sync_distance"], 0);
    }

    #[tokio::test]
    async fn node_syncing_reflects_controller() {
        // is_syncing comes from the shared SyncStatusController (the actor's sync
        // decision), not the raw wall-clock sync_distance. It follows the
        // controller and updates through the shared handle without rebuilding it.
        let store = Store::from_anchor_state(Arc::new(InMemoryBackend::new()), create_test_state());
        let sync = SyncStatusController::new(SyncStatus::Syncing);

        assert_eq!(
            get_syncing_json(store.clone(), sync.clone()).await["is_syncing"],
            true
        );

        sync.set(SyncStatus::Synced);
        assert_eq!(get_syncing_json(store, sync).await["is_syncing"], false);
    }

    #[tokio::test]
    async fn node_identity_reports_version_and_peer_id() {
        // The binary injects the real `CLIENT_VERSION` and local peer ID; here we
        // inject sentinels and assert they round-trip verbatim.
        const VERSION: &str =
            "ethlambda/v9.9.9-test-deadbeef/x86_64-unknown-linux-gnu/rustc-v1.92.0";
        const PEER_ID: &str = "16Uiu2HAmTestPeerIdSentinel";
        let store = Store::from_anchor_state(Arc::new(InMemoryBackend::new()), create_test_state());
        let app = crate::build_api_router(store, VERSION, PEER_ID.to_string());
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
        assert_eq!(json["peer_id"], PEER_ID);
    }
}
