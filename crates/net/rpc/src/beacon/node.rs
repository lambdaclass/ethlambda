//! `/eth/v1/node/{syncing,identity,version,health,peers,peers/{peer_id},peer_count}`.

use axum::{
    Extension, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use ethlambda_blockchain::{SyncStatusController, metrics::SyncStatus};
use ethlambda_network_api::{ConnectedPeer, PeerDirection, PeerTableController};
use ethlambda_storage::Store;

use super::ApiError;

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
        .route("/eth/v1/node/peers", get(get_peers))
        .route("/eth/v1/node/peers/{peer_id}", get(get_peer))
        .route("/eth/v1/node/peer_count", get(get_peer_count))
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
        .is_some_and(|(_slot, root)| crate::shared::optimistic::block_is_optimistic(store, root))
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

/// `GET /eth/v1/node/identity`: the peer id, the node's ENR, and the
/// multiaddrs it listens on, which is how a peer that reads this endpoint (a
/// devnet orchestrator wiring bootnodes, say) dials it.
///
/// The addresses are only as good as `--discovery.advertise-ip`: without it the
/// node does not know the address peers reach it on, so the lists are empty and
/// the ENR carries no IP.
///
/// `metadata` is the `MetaData` peers get over req/resp, read at request time.
/// Its `seq_number` versions that `MetaData` alone, so it is not the ENR's
/// `seq`: the p2p specification counts the two separately.
async fn get_identity(peer_id: String, identity: Option<crate::BeaconIdentity>) -> Response {
    let identity = identity.unwrap_or_default();
    let metadata = match identity.metadata {
        Some(metadata) => {
            let metadata = metadata.get();
            serde_json::json!({
                "seq_number": metadata.seq_number.to_string(),
                "attnets": format!("0x{}", hex::encode(&metadata.attnets)),
                "syncnets": format!("0x{}", hex::encode(&metadata.syncnets)),
            })
        }
        None => serde_json::json!({
            "seq_number": "0",
            "attnets": "0x0000000000000000",
            "syncnets": "0x00",
        }),
    };
    crate::json_response(serde_json::json!({
        "data": {
            "peer_id": peer_id,
            "enr": identity.enr,
            "p2p_addresses": identity.p2p_addresses,
            "discovery_addresses": identity.discovery_addresses,
            "metadata": metadata,
        }
    }))
}

/// The `PeerConnectionState` values the Beacon API names. A node tracks only
/// connected peers, so `connected` is the one state that can match anything.
const PEER_STATES: [&str; 4] = ["disconnected", "connecting", "connected", "disconnecting"];
/// The `direction` values, spelled by the enum the table stores so the two
/// cannot drift apart.
const PEER_DIRECTIONS: [&str; 2] = [
    PeerDirection::Inbound.as_str(),
    PeerDirection::Outbound.as_str(),
];

/// The p2p layer's peer table, `None` without a p2p layer to ask.
fn peer_table(identity: Option<Extension<crate::BeaconIdentity>>) -> Option<PeerTableController> {
    identity.and_then(|Extension(identity)| identity.peers)
}

/// The connected peers, empty without a p2p layer to ask.
fn connected_peers(identity: Option<Extension<crate::BeaconIdentity>>) -> Vec<ConnectedPeer> {
    peer_table(identity)
        .map(|peers| peers.snapshot())
        .unwrap_or_default()
}

fn peer_json(peer: &ConnectedPeer) -> serde_json::Value {
    serde_json::json!({
        "peer_id": peer.peer_id,
        "enr": peer.enr,
        "last_seen_p2p_address": peer.last_seen_p2p_address,
        "state": "connected",
        "direction": peer.direction.as_str(),
    })
}

/// Every value a repeatable query parameter names, each checked against
/// `allowed`. Values may also be comma-separated, which some clients send in
/// place of repeating the parameter. Empty values (`?state=`, a trailing
/// comma) are skipped rather than refused, so `?state=` filters nothing.
fn filter_values(
    query: &[(String, String)],
    name: &str,
    allowed: &[&str],
) -> Result<Vec<String>, ApiError> {
    let mut values = Vec::new();
    for (key, raw) in query {
        if key != name {
            continue;
        }
        for value in raw.split(',').filter(|value| !value.is_empty()) {
            if !allowed.contains(&value) {
                return Err(ApiError::BadRequestDetail(format!(
                    "Invalid {name}: {value}"
                )));
            }
            values.push(value.to_string());
        }
    }
    Ok(values)
}

/// `GET /eth/v1/node/peers`: the connected peers, filtered by the optional
/// `state` and `direction` parameters (AND-combined; values within one
/// parameter are alternatives).
///
/// Only connected peers are tracked, so every peer reported is `connected` and
/// a `state` filter naming any other state matches nothing.
async fn get_peers(
    Query(query): Query<Vec<(String, String)>>,
    identity: Option<Extension<crate::BeaconIdentity>>,
) -> Response {
    let (states, directions) = match (
        filter_values(&query, "state", &PEER_STATES),
        filter_values(&query, "direction", &PEER_DIRECTIONS),
    ) {
        (Ok(states), Ok(directions)) => (states, directions),
        (Err(err), _) | (_, Err(err)) => return err.into_response(),
    };
    let state_matches = states.is_empty() || states.iter().any(|state| state == "connected");
    let data: Vec<_> = connected_peers(identity)
        .iter()
        .filter(|peer| {
            state_matches
                && (directions.is_empty()
                    || directions.iter().any(|d| d == peer.direction.as_str()))
        })
        .map(peer_json)
        .collect();
    crate::json_response(serde_json::json!({
        "data": data,
        "meta": { "count": data.len() },
    }))
}

/// Whether `peer_id` is one libp2p's `PeerId::from_str` would accept: base58
/// text of a multihash that is either sha2-256 (code `0x12`, a digest of at
/// most 64 bytes) or an inlined key (identity, code `0x00`, at most 42 bytes),
/// with exactly the digest length its header declares and nothing after it.
/// Checked by hand, since this crate has no libp2p. A well-formed id that is
/// not connected is a 404.
fn is_well_formed_peer_id(peer_id: &str) -> bool {
    /// libp2p's `MAX_INLINE_KEY_LENGTH`: the longest key an id inlines.
    const MAX_INLINE_KEY_LENGTH: usize = 42;
    /// The largest digest libp2p's multihash holds.
    const MAX_DIGEST_LENGTH: usize = 64;
    const IDENTITY: u8 = 0x00;
    const SHA2_256: u8 = 0x12;
    let Ok(bytes) = bs58::decode(peer_id).into_vec() else {
        return false;
    };
    // Both codes and every length allowed are below 0x80, so each varint is
    // a single byte; a longer one names another code or too long a digest.
    let [code, length, digest @ ..] = bytes.as_slice() else {
        return false;
    };
    let length = usize::from(*length);
    let longest = match *code {
        SHA2_256 => MAX_DIGEST_LENGTH,
        IDENTITY => MAX_INLINE_KEY_LENGTH,
        _ => return false,
    };
    length <= longest && digest.len() == length
}

/// `GET /eth/v1/node/peers/{peer_id}`: one connected peer. `400` for a
/// malformed id, `404` for one that is not connected.
async fn get_peer(
    Path(peer_id): Path<String>,
    identity: Option<Extension<crate::BeaconIdentity>>,
) -> Response {
    if !is_well_formed_peer_id(&peer_id) {
        return ApiError::BadRequestDetail(format!("Invalid peer id: {peer_id}")).into_response();
    }
    match peer_table(identity).and_then(|peers| peers.get(&peer_id)) {
        Some(peer) => crate::json_response(serde_json::json!({ "data": peer_json(&peer) })),
        None => ApiError::NotFound("peer not found").into_response(),
    }
}

/// `GET /eth/v1/node/peer_count`: peers per state, as quoted integers. Only
/// `connected` is ever non-zero.
async fn get_peer_count(identity: Option<Extension<crate::BeaconIdentity>>) -> Response {
    let connected = peer_table(identity).map_or(0, |peers| peers.len());
    crate::json_response(serde_json::json!({
        "data": {
            "disconnected": "0",
            "connecting": "0",
            "connected": connected.to_string(),
            "disconnecting": "0",
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
            metadata: None,
            peers: None,
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

    /// `metadata` is read from the p2p layer's handle on each request, so a
    /// change published after the router was built is what the next answer
    /// reports.
    #[tokio::test]
    async fn identity_reports_the_metadata_peers_are_told() {
        let fixture = beacon_fixture(ANCHOR_SLOT);
        let metadata = ethlambda_network_api::MetaDataController::default();
        let identity = crate::BeaconIdentity {
            metadata: Some(metadata.clone()),
            ..Default::default()
        };
        let app = routes("ethlambda/test", "test-peer".into())
            .with_state(fixture.store)
            .layer(Extension(identity));

        metadata.set(ethlambda_network_api::AdvertisedMetaData {
            seq_number: 3,
            attnets: vec![0x00, 0x10, 0, 0, 0, 0, 0, 0x01],
            syncnets: vec![0x04],
        });
        let request = Request::builder()
            .uri("/eth/v1/node/identity")
            .body(Body::empty())
            .unwrap();
        let json = body_json(app.oneshot(request).await.unwrap()).await;
        assert_eq!(json["data"]["metadata"]["seq_number"], "3");
        assert_eq!(json["data"]["metadata"]["attnets"], "0x0010000000000001");
        assert_eq!(json["data"]["metadata"]["syncnets"], "0x04");
    }

    fn peer(
        id: &str,
        direction: ethlambda_network_api::PeerDirection,
        enr: Option<&str>,
    ) -> ConnectedPeer {
        ConnectedPeer {
            peer_id: id.to_string(),
            direction,
            last_seen_p2p_address: format!("/ip4/10.0.0.1/tcp/9000/p2p/{id}"),
            enr: enr.map(str::to_string),
        }
    }

    /// Two inbound peers and one outbound, the outbound one with an ENR. The
    /// ids only need to sort; the endpoints that list peers never parse them.
    async fn get_from_table(uri: &str) -> axum::response::Response {
        use ethlambda_network_api::PeerDirection::{Inbound, Outbound};
        let table = ethlambda_network_api::PeerTableController::default();
        table.insert(peer("16Uiua", Inbound, None));
        table.insert(peer("16Uiub", Outbound, Some("enr:-abc")));
        table.insert(peer("16Uiuc", Inbound, None));
        get_with_peers(table, uri).await
    }

    async fn get_with_peers(
        table: ethlambda_network_api::PeerTableController,
        uri: &str,
    ) -> axum::response::Response {
        let identity = crate::BeaconIdentity {
            peers: Some(table),
            ..Default::default()
        };
        let app = routes("ethlambda/test", "test-peer".into())
            .with_state(beacon_fixture(ANCHOR_SLOT).store)
            .layer(Extension(identity));
        app.oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    /// A peer id libp2p would produce: base58 of a multihash with code `code`
    /// and `digest`, its length declared in the header.
    fn multihash_id(code: u8, digest: &[u8]) -> String {
        let length = u8::try_from(digest.len()).unwrap();
        bs58::encode([&[code, length][..], digest].concat()).into_string()
    }

    /// A secp256k1 key inlined the way libp2p does it (identity multihash of
    /// the protobuf-encoded key), which is what a beacon node's id looks like.
    fn inlined_key_id(byte: u8) -> String {
        let mut key = vec![0x08, 0x02, 0x12, 0x21, 0x02];
        key.extend([byte; 32]);
        multihash_id(0x00, &key)
    }

    fn ids(json: &serde_json::Value) -> Vec<&str> {
        json["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|peer| peer["peer_id"].as_str().unwrap())
            .collect()
    }

    #[tokio::test]
    async fn peers_lists_everyone_with_a_count_and_a_null_enr_when_unknown() {
        let json = body_json(get_from_table("/eth/v1/node/peers").await).await;
        assert_eq!(ids(&json), ["16Uiua", "16Uiub", "16Uiuc"]);
        assert_eq!(json["meta"]["count"], 3);
        assert!(json["data"][0]["enr"].is_null());
        assert_eq!(json["data"][1]["enr"], "enr:-abc");
        assert_eq!(json["data"][0]["state"], "connected");
        assert_eq!(json["data"][0]["direction"], "inbound");
        assert_eq!(
            json["data"][0]["last_seen_p2p_address"],
            "/ip4/10.0.0.1/tcp/9000/p2p/16Uiua"
        );
    }

    #[tokio::test]
    async fn peers_filter_by_direction_and_state_together() {
        let json = body_json(get_from_table("/eth/v1/node/peers?direction=outbound").await).await;
        assert_eq!(ids(&json), ["16Uiub"]);
        assert_eq!(json["meta"]["count"], 1);

        let json =
            body_json(get_from_table("/eth/v1/node/peers?state=connected&direction=inbound").await)
                .await;
        assert_eq!(ids(&json), ["16Uiua", "16Uiuc"]);

        // Repeated and comma-separated values are alternatives.
        let json = body_json(
            get_from_table("/eth/v1/node/peers?direction=inbound&direction=outbound").await,
        )
        .await;
        assert_eq!(json["meta"]["count"], 3);
        let json =
            body_json(get_from_table("/eth/v1/node/peers?direction=inbound,outbound").await).await;
        assert_eq!(json["meta"]["count"], 3);
    }

    #[tokio::test]
    async fn empty_filter_values_are_skipped_rather_than_refused() {
        // `?state=` names no state, so it filters nothing.
        let response = get_from_table("/eth/v1/node/peers?state=").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_json(response).await["meta"]["count"], 3);

        // A trailing comma leaves the one real value.
        let json = body_json(get_from_table("/eth/v1/node/peers?direction=inbound,").await).await;
        assert_eq!(ids(&json), ["16Uiua", "16Uiuc"]);
    }

    #[tokio::test]
    async fn a_state_other_than_connected_matches_nothing() {
        let json = body_json(get_from_table("/eth/v1/node/peers?state=disconnected").await).await;
        assert_eq!(json["data"], serde_json::json!([]));
        assert_eq!(json["meta"]["count"], 0);

        // `connected` among alternatives still matches.
        let json =
            body_json(get_from_table("/eth/v1/node/peers?state=connecting&state=connected").await)
                .await;
        assert_eq!(json["meta"]["count"], 3);
    }

    #[tokio::test]
    async fn an_unknown_filter_value_is_a_400() {
        for uri in [
            "/eth/v1/node/peers?state=sleeping",
            "/eth/v1/node/peers?direction=sideways",
            "/eth/v1/node/peers?state=connected&direction=sideways",
        ] {
            let response = get_from_table(uri).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
            let json = body_json(response).await;
            assert_eq!(json["code"], 400);
            assert!(json["message"].as_str().unwrap().starts_with("Invalid "));
        }
    }

    #[tokio::test]
    async fn peers_without_a_peer_table_is_empty() {
        let json = body_json(get("/eth/v1/node/peers").await).await;
        assert_eq!(json["data"], serde_json::json!([]));
        assert_eq!(json["meta"]["count"], 0);
        let json = body_json(get("/eth/v1/node/peer_count").await).await;
        assert_eq!(json["data"]["connected"], "0");
    }

    #[test]
    fn a_peer_id_is_well_formed_only_as_a_whole_libp2p_multihash() {
        // What libp2p produces: an inlined secp256k1 key, and a sha2-256 hash.
        assert!(is_well_formed_peer_id(&inlined_key_id(1)));
        assert!(is_well_formed_peer_id(&multihash_id(0x12, &[7; 32])));

        // Base58 throughout, yet not a peer id.
        let malformed = [
            // Too short for a multihash header.
            "1".to_string(),
            // Header promises 32 bytes, 31 follow.
            bs58::encode([&[0x12, 32][..], &[7; 31]].concat()).into_string(),
            // 32 bytes declared, 33 present.
            bs58::encode([&[0x12, 32][..], &[7; 33]].concat()).into_string(),
            // A code that is neither sha2-256 nor identity.
            multihash_id(0x13, &[7; 32]),
            // An inlined key longer than libp2p inlines.
            multihash_id(0x00, &[7; 43]),
        ];
        for id in &malformed {
            assert!(!is_well_formed_peer_id(id), "{id}");
        }

        // Outside the base58 alphabet (`-`, `0`).
        assert!(!is_well_formed_peer_id("not-a-peer"));
        assert!(!is_well_formed_peer_id("16Uiu0"));
        assert!(!is_well_formed_peer_id(""));
    }

    #[tokio::test]
    async fn one_peer_is_found_missed_or_rejected_as_malformed() {
        use ethlambda_network_api::PeerDirection::Outbound;
        let connected = inlined_key_id(1);
        let table = ethlambda_network_api::PeerTableController::default();
        table.insert(peer(&connected, Outbound, Some("enr:-abc")));

        let uri = format!("/eth/v1/node/peers/{connected}");
        let response = get_with_peers(table.clone(), &uri).await;
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["data"]["peer_id"], connected.as_str());
        assert_eq!(json["data"]["direction"], "outbound");
        assert_eq!(json["data"]["enr"], "enr:-abc");

        // Well-formed but not connected.
        let uri = format!("/eth/v1/node/peers/{}", inlined_key_id(2));
        let response = get_with_peers(table.clone(), &uri).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Base58, but not a peer id (an unknown multihash code): a 400, not a
        // 404.
        let uri = format!("/eth/v1/node/peers/{}", multihash_id(0x13, &[7; 32]));
        let response = get_with_peers(table.clone(), &uri).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let response = get_with_peers(table, "/eth/v1/node/peers/not-a-peer").await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn peer_count_quotes_every_state_and_counts_only_connected() {
        let json = body_json(get_from_table("/eth/v1/node/peer_count").await).await;
        assert_eq!(
            json["data"],
            serde_json::json!({
                "disconnected": "0",
                "connecting": "0",
                "connected": "3",
                "disconnecting": "0",
            })
        );
    }
}
