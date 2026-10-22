//! `/eth/v1/node/{syncing,identity,version,health}`.

use axum::{
    Extension, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use ethlambda_blockchain::{SyncStatusController, metrics::SyncStatus};
use ethlambda_storage::Store;

pub(crate) fn routes(version: &'static str, peer_id: String) -> Router<Store> {
    Router::new()
        .route("/eth/v1/node/syncing", get(get_syncing))
        .route("/eth/v1/node/health", get(get_health))
        .route("/eth/v1/node/version", get(move || get_version(version)))
        .route(
            "/eth/v1/node/identity",
            get(move || get_identity(peer_id.clone())),
        )
}

/// The wall-clock slot, from genesis and the configured slot duration.
///
/// Millisecond-denominated, the way `/lean/v0/node/syncing` computes the same
/// number: `slot_duration_ms` is the value a loaded network can actually
/// change, and `seconds_per_slot` would truncate a sub-second cadence to zero.
pub(crate) fn wall_slot(store: &Store) -> u64 {
    let config = store.config();
    let genesis_ms = config.genesis_time_ms();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(genesis_ms);
    now_ms.saturating_sub(genesis_ms) / config.slot_duration_ms.max(1)
}

/// Whether the fork-choice head was imported on a payload the execution client
/// has not validated: the Beacon API's "optimistically tracking head".
///
/// The head, not any root in the optimistic set. An unvalidated block on a
/// branch fork choice did not pick says nothing about what this node would
/// have a validator sign, and reporting it would have a validator client stand
/// down while every answer it could get is sound.
fn head_is_optimistic(store: &Store) -> bool {
    store
        .beacon_head()
        .is_some_and(|(_slot, root)| store.is_beacon_optimistic(root))
}

async fn get_syncing(
    State(store): State<Store>,
    Extension(sync_status): Extension<SyncStatusController>,
) -> Response {
    // `beacon_head`, not `head_slot`: the latter is lean-only and panics here.
    let head_slot = store.beacon_head().map(|(slot, _root)| slot).unwrap_or(0);
    let sync_distance = wall_slot(&store).saturating_sub(head_slot);

    crate::json_response(serde_json::json!({
        "data": {
            "head_slot": head_slot.to_string(),
            "sync_distance": sync_distance.to_string(),
            "is_syncing": sync_status.get() == SyncStatus::Syncing,
            "is_optimistic": head_is_optimistic(&store),
            "el_offline": false,
        }
    }))
}

async fn get_health(
    State(store): State<Store>,
    Extension(sync_status): Extension<SyncStatusController>,
) -> Response {
    // 206 while syncing or tracking an optimistic head, 200 otherwise: the
    // Beacon API's 206 is "syncing, or its execution node is optimistic or
    // offline, so data served may be incorrect". The offline half is not
    // detected: nothing tracks the execution client's liveness, which is also
    // why `/node/syncing` reports `el_offline` as false. 503 would mean
    // uninitialized, and a store that answers at all is initialized.
    let degraded = sync_status.get() == SyncStatus::Syncing || head_is_optimistic(&store);
    let status = if degraded {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    };
    status.into_response()
}

async fn get_version(version: &'static str) -> Response {
    crate::json_response(serde_json::json!({ "data": { "version": version } }))
}

async fn get_identity(peer_id: String) -> Response {
    // `enr` and the two address lists are empty, which is not spec-valid: the
    // ENR is built for discv5 and owned by the P2P actor, and `BuiltSwarm`
    // hands `run_node` only a `local_peer_id`. Serving the record means
    // widening the `ethlambda-p2p` surface and threading it through startup,
    // which is a change of its own. Recorded in docs/spec_deviations.md.
    crate::json_response(serde_json::json!({
        "data": {
            "peer_id": peer_id,
            "enr": "",
            "p2p_addresses": [],
            "discovery_addresses": [],
            "metadata": {
                "seq_number": "0",
                "attnets": "0x0000000000000000",
                "syncnets": "0x00",
            },
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::beacon_fixture;
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    const ANCHOR_SLOT: u64 = 64;

    async fn get_from(
        store: Store,
        uri: &str,
        sync: SyncStatusController,
    ) -> axum::response::Response {
        let app = routes("ethlambda/test", "test-peer".to_string())
            .with_state(store)
            .layer(Extension(sync));
        app.oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    async fn get_with(uri: &str, sync: SyncStatusController) -> axum::response::Response {
        get_from(beacon_fixture(ANCHOR_SLOT).store, uri, sync).await
    }

    async fn get(uri: &str) -> axum::response::Response {
        get_with(uri, SyncStatusController::default()).await
    }

    async fn body_json(response: axum::response::Response) -> serde_json::Value {
        let body = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn syncing_quotes_its_numbers_and_reads_the_beacon_head() {
        let response = get("/eth/v1/node/syncing").await;
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;

        // The fixture's head is the child block, one slot above the anchor.
        assert_eq!(json["data"]["head_slot"], "65");
        assert!(json["data"]["sync_distance"].is_string());
        assert_eq!(json["data"]["is_syncing"], false);
        assert_eq!(json["data"]["is_optimistic"], false);
        assert_eq!(json["data"]["el_offline"], false);
    }

    #[tokio::test]
    async fn syncing_follows_the_controller() {
        let syncing = SyncStatusController::new(SyncStatus::Syncing);
        let json = body_json(get_with("/eth/v1/node/syncing", syncing).await).await;
        assert_eq!(json["data"]["is_syncing"], true);
    }

    /// `is_optimistic` and the health code follow the head alone: an
    /// unvalidated block on a branch fork choice did not pick is not
    /// "optimistically tracking head".
    #[tokio::test]
    async fn only_an_optimistic_head_makes_the_node_optimistic() {
        let fixture = beacon_fixture(ANCHOR_SLOT);
        let mut store = fixture.store;
        let report = |store: &Store| {
            let store = store.clone();
            async move {
                let syncing = get_from(
                    store.clone(),
                    "/eth/v1/node/syncing",
                    SyncStatusController::default(),
                );
                let json = body_json(syncing.await).await;
                let health = get_from(store, "/eth/v1/node/health", Default::default()).await;
                (json["data"]["is_optimistic"].clone(), health.status())
            }
        };

        let side_branch = ethlambda_types::primitives::H256::repeat_byte(0x42);
        store.insert_beacon_optimistic_root(side_branch, fixture.head_slot);
        assert_eq!(report(&store).await, (false.into(), StatusCode::OK));

        store.insert_beacon_optimistic_root(fixture.head_root, fixture.head_slot);
        assert_eq!(
            report(&store).await,
            (true.into(), StatusCode::PARTIAL_CONTENT)
        );
    }

    #[tokio::test]
    async fn version_reports_the_client_string() {
        let json = body_json(get("/eth/v1/node/version").await).await;
        assert_eq!(json["data"]["version"], "ethlambda/test");
    }

    #[tokio::test]
    async fn health_is_200_when_caught_up_and_206_while_syncing() {
        assert_eq!(get("/eth/v1/node/health").await.status(), StatusCode::OK);

        let syncing = SyncStatusController::new(SyncStatus::Syncing);
        assert_eq!(
            get_with("/eth/v1/node/health", syncing).await.status(),
            StatusCode::PARTIAL_CONTENT
        );
    }

    #[tokio::test]
    async fn identity_carries_the_peer_id_and_empty_network_fields() {
        let json = body_json(get("/eth/v1/node/identity").await).await;
        assert_eq!(json["data"]["peer_id"], "test-peer");
        // Deliberately empty, and not spec-valid; see docs/spec_deviations.md.
        assert_eq!(json["data"]["enr"], "");
        assert_eq!(json["data"]["p2p_addresses"], serde_json::json!([]));
        assert_eq!(json["data"]["discovery_addresses"], serde_json::json!([]));
        assert_eq!(json["data"]["metadata"]["seq_number"], "0");
    }
}
