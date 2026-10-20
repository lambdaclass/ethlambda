//! `/eth/v2/beacon/blocks/{block_id}` and its `/root` sibling.

use axum::{
    Router,
    extract::{Path, State},
    http::{HeaderMap, header},
    response::{IntoResponse, Response},
    routing::get,
};
use ethlambda_storage::Store;
use ethlambda_types::{beacon::containers::SignedBeaconBlock, primitives::H256};

use crate::{
    beacon::{ApiError, Envelope},
    shared::{
        block_id::BlockId,
        content::{Encoding, ssz_response, with_consensus_version},
    },
};

pub(crate) fn routes() -> Router<Store> {
    Router::new()
        .route("/eth/v2/beacon/blocks/{block_id}", get(get_block))
        .route("/eth/v1/beacon/blocks/{block_id}/root", get(get_block_root))
}

/// Resolve `block_id` and load the block it names.
///
/// Shared by both handlers here and by `headers.rs`, so the id semantics are
/// written once.
pub(crate) fn load(store: &Store, block_id: &str) -> Result<(H256, SignedBeaconBlock), ApiError> {
    let id = BlockId::parse(block_id)?;
    let root = id.resolve_beacon(store)?;
    let block = store
        .get_signed_block(&root)
        .map_err(|_| ApiError::Internal("store read failed"))?
        .ok_or(ApiError::NotFound("block not found"))?;
    Ok((root, block))
}

async fn get_block(
    Path(block_id): Path<String>,
    State(store): State<Store>,
    headers: HeaderMap,
) -> Response {
    let (root, block) = match load(&store, &block_id) {
        Ok(found) => found,
        Err(err) => return err.into_response(),
    };
    let fork = block.fork_name();

    let accept = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok());
    let response = match Encoding::from_accept(accept) {
        Encoding::Ssz => ssz_response(block.to_ssz()),
        Encoding::Json => crate::json_response(Envelope {
            version: fork.as_str(),
            execution_optimistic: store.is_beacon_optimistic(root),
            finalized: is_finalized(&store, block.slot()),
            data: block,
        }),
    };

    with_consensus_version(response, fork)
}

async fn get_block_root(Path(block_id): Path<String>, State(store): State<Store>) -> Response {
    let (root, block) = match load(&store, &block_id) {
        Ok(found) => found,
        Err(err) => return err.into_response(),
    };

    crate::json_response(serde_json::json!({
        "execution_optimistic": store.is_beacon_optimistic(root),
        "finalized": is_finalized(&store, block.slot()),
        "data": { "root": root },
    }))
}

/// Whether a block at `slot` is at or below the finalized checkpoint.
///
/// `latest_finalized` is slot-denominated on both chains: a beacon
/// checkpoint's epoch is stored as that epoch's own start slot, which is what
/// `Store::as_beacon_checkpoint` converts back from.
pub(crate) fn is_finalized(store: &Store, slot: u64) -> bool {
    store
        .latest_finalized()
        .map(|finalized| slot <= finalized.slot)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::beacon_fixture;
    use axum::{body::Body, http::Request, http::StatusCode};
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    const ANCHOR_SLOT: u64 = 64;

    async fn get(uri: &str, accept: Option<&str>) -> axum::response::Response {
        let fixture = beacon_fixture(ANCHOR_SLOT);
        let app = routes().with_state(fixture.store);
        let mut request = Request::builder().uri(uri);
        if let Some(accept) = accept {
            request = request.header("accept", accept);
        }
        app.oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_block_by_slot_comes_back_as_json_by_default() {
        let response = get("/eth/v2/beacon/blocks/65", None).await;
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["data"]["message"]["slot"], "65", "integers are quoted");
        assert_eq!(json["execution_optimistic"], false);
        assert_eq!(json["version"], "phase0");
    }

    #[tokio::test]
    async fn the_same_block_comes_back_as_ssz_on_request() {
        let response = get("/eth/v2/beacon/blocks/65", Some("application/octet-stream")).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            crate::SSZ_CONTENT_TYPE
        );
        assert_eq!(
            response.headers().get("eth-consensus-version").unwrap(),
            "phase0"
        );
    }

    #[tokio::test]
    async fn named_ids_resolve() {
        // `head` is the child; `finalized` and `justified` are the anchor,
        // which is what `init_beacon` seeds both checkpoints with.
        let head = get("/eth/v2/beacon/blocks/head", None).await;
        assert_eq!(head.status(), StatusCode::OK);
        let body = head.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["data"]["message"]["slot"], "65");

        let finalized = get("/eth/v2/beacon/blocks/finalized", None).await;
        assert_eq!(finalized.status(), StatusCode::OK);
        let body = finalized.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["data"]["message"]["slot"], "64");
        assert_eq!(json["finalized"], true, "the anchor is the finalized block");
    }

    #[tokio::test]
    async fn a_malformed_id_is_a_400_and_an_absent_one_a_404() {
        assert_eq!(
            get("/eth/v2/beacon/blocks/nope", None).await.status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            get("/eth/v2/beacon/blocks/999999", None).await.status(),
            StatusCode::NOT_FOUND
        );
    }

    /// The anchor's own slot resolves, even though `BlockRoots` never holds it.
    ///
    /// This is the slot `bin/ethlambda/src/checkpoint_sync.rs` asks a peer for
    /// right after reading its finalized state, so a 404 here makes this node
    /// unusable as a checkpoint-sync source. Found against a real mainnet
    /// pair: before the fallback in `resolve_beacon`, a second node syncing
    /// from a first died with "peer served no block at the anchor slot".
    #[tokio::test]
    async fn the_anchors_own_slot_resolves_through_the_named_roots() {
        let response = get("/eth/v2/beacon/blocks/64", None).await;
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["data"]["message"]["slot"], "64");
    }

    /// A slot the store genuinely has nothing at is still a 404. The fallback
    /// accepts a named root only when that root's block really sits at the
    /// slot asked for, so it cannot answer with the anchor for another slot.
    #[tokio::test]
    async fn a_slot_below_the_anchor_is_still_absent() {
        assert_eq!(
            get("/eth/v2/beacon/blocks/63", None).await.status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn a_block_by_root_resolves() {
        let fixture = beacon_fixture(ANCHOR_SLOT);
        let uri = format!("/eth/v2/beacon/blocks/0x{:x}", fixture.anchor_root);
        let app = routes().with_state(fixture.store);
        let response = app
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["data"]["message"]["slot"], "64");
    }

    #[tokio::test]
    async fn the_root_endpoint_returns_the_resolved_root() {
        let response = get("/eth/v1/beacon/blocks/65/root", None).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["data"]["root"].as_str().unwrap().starts_with("0x"));
    }
}
