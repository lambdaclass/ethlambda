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
            get(move |identity: Option<Extension<crate::BeaconIdentity>>| {
                get_identity(
                    peer_id.clone(),
                    identity.map(|Extension(identity)| identity),
                )
            }),
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
            "is_optimistic": store.has_beacon_optimistic_roots(),
            "el_offline": false,
        }
    }))
}

async fn get_health(Extension(sync_status): Extension<SyncStatusController>) -> Response {
    // 206 while syncing, 200 once caught up. 503 would mean uninitialized, and
    // a store that answers at all is initialized.
    let status = match sync_status.get() {
        SyncStatus::Syncing => StatusCode::PARTIAL_CONTENT,
        _ => StatusCode::OK,
    };
    status.into_response()
}

async fn get_version(version: &'static str) -> Response {
    crate::json_response(serde_json::json!({ "data": { "version": version } }))
}

/// `GET /eth/v1/node/identity`: the peer id, the node's ENR, and the
/// multiaddrs it listens on, which is how a peer that reads this endpoint (a
/// devnet orchestrator wiring bootnodes, say) dials it.
///
/// The addresses are only as good as `--discovery.advertise-ip`: without it the
/// node does not know the address peers reach it on, so the lists are empty and
/// the ENR carries no IP. `metadata` is still a placeholder.
async fn get_identity(peer_id: String, identity: Option<crate::BeaconIdentity>) -> Response {
    let identity = identity.unwrap_or_default();
    crate::json_response(serde_json::json!({
        "data": {
            "peer_id": peer_id,
            "enr": identity.enr,
            "p2p_addresses": identity.p2p_addresses,
            "discovery_addresses": identity.discovery_addresses,
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

    async fn get_with(uri: &str, sync: SyncStatusController) -> axum::response::Response {
        let fixture = beacon_fixture(ANCHOR_SLOT);
        let app = routes("ethlambda/test", "test-peer".to_string())
            .with_state(fixture.store)
            .layer(Extension(sync));
        app.oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap()
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
    async fn identity_without_an_identity_carries_the_peer_id_and_empty_network_fields() {
        let json = body_json(get("/eth/v1/node/identity").await).await;
        assert_eq!(json["data"]["peer_id"], "test-peer");
        assert_eq!(json["data"]["enr"], "");
        assert_eq!(json["data"]["p2p_addresses"], serde_json::json!([]));
        assert_eq!(json["data"]["metadata"]["seq_number"], "0");
    }

    #[tokio::test]
    async fn identity_reports_the_enr_and_listen_addresses() {
        let fixture = beacon_fixture(ANCHOR_SLOT);
        let identity = crate::BeaconIdentity {
            enr: "enr:-abc".to_string(),
            p2p_addresses: vec!["/ip4/10.0.0.1/tcp/9001/p2p/test-peer".to_string()],
            discovery_addresses: vec!["/ip4/10.0.0.1/udp/9000/p2p/test-peer".to_string()],
        };
        let app = routes("ethlambda/test", "test-peer".into())
            .with_state(fixture.store)
            .layer(Extension(identity));
        let request = Request::builder()
            .uri("/eth/v1/node/identity")
            .body(Body::empty())
            .unwrap();
        let json = body_json(app.oneshot(request).await.unwrap()).await;
        assert_eq!(json["data"]["enr"], "enr:-abc");
        assert_eq!(
            json["data"]["p2p_addresses"][0],
            "/ip4/10.0.0.1/tcp/9001/p2p/test-peer"
        );
        assert_eq!(
            json["data"]["discovery_addresses"][0],
            "/ip4/10.0.0.1/udp/9000/p2p/test-peer"
        );
    }
}
