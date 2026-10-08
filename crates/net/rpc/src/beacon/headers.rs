//! `/eth/v1/beacon/headers/{block_id}`.
//!
//! The one endpoint here that is genuinely shared with lean: every field of
//! the message comes from `SignedBeaconBlock`'s accessors, which dispatch
//! including lean, plus `body_root()`. Only the envelope and the signature
//! are beacon-specific.

use axum::{
    Router,
    extract::{Path, State},
    response::{IntoResponse, Response},
    routing::get,
};
use ethlambda_storage::Store;
use ethlambda_types::primitives::H256;
use serde::Serialize;

use crate::beacon::blocks::{is_finalized, load};

pub(crate) fn routes() -> Router<Store> {
    Router::new().route("/eth/v1/beacon/headers/{block_id}", get(get_header))
}

/// The five fields of a `BeaconBlockHeader`, in the Beacon API's encoding.
///
/// Spelled out here rather than built from the stored
/// `containers::BeaconBlockHeader`, because a beacon store keeps the whole
/// signed block rather than a separate header row, and lean's header carries
/// a different set of fields.
#[derive(Serialize)]
struct HeaderMessage {
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    slot: u64,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    proposer_index: u64,
    parent_root: H256,
    state_root: H256,
    body_root: H256,
}

async fn get_header(Path(block_id): Path<String>, State(store): State<Store>) -> Response {
    let (root, block) = match load(&store, &block_id) {
        Ok(found) => found,
        Err(err) => return err.into_response(),
    };

    let message = HeaderMessage {
        slot: block.slot(),
        proposer_index: block.proposer_index(),
        parent_root: block.parent_root(),
        state_root: block.state_root(),
        body_root: block.body_root(),
    };

    // Asked of the index rather than assumed, even for a block reached by
    // root: `BlockRoots` holds one root per slot on the branch ending at the
    // head, so a sibling, or a block at a slot the index does not cover,
    // answers `false` rather than being taken on trust.
    let canonical = store
        .canonical_root_at_slot(block.slot())
        .ok()
        .flatten()
        .is_some_and(|canonical| canonical == root);

    // `signature()` panics on a lean block by design (`dispatch_block!`),
    // which is unreachable here: this router is only ever mounted on a beacon
    // store.
    crate::json_response(serde_json::json!({
        "execution_optimistic": store.is_beacon_optimistic(root),
        "finalized": is_finalized(&store, block.slot()),
        "data": {
            "root": root,
            "canonical": canonical,
            "header": {
                "message": message,
                "signature": block.signature(),
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::beacon_fixture;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    const ANCHOR_SLOT: u64 = 64;

    async fn get(uri: String) -> axum::response::Response {
        let fixture = beacon_fixture(ANCHOR_SLOT);
        let app = routes().with_state(fixture.store);
        app.oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    async fn body_json(response: axum::response::Response) -> serde_json::Value {
        let body = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn a_header_carries_the_five_fields_and_the_signature() {
        let response = get("/eth/v1/beacon/headers/head".to_string()).await;
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;

        let header = &json["data"]["header"]["message"];
        assert_eq!(header["slot"], "65", "integers are quoted");
        assert_eq!(header["proposer_index"], "0");
        assert!(header["parent_root"].as_str().unwrap().starts_with("0x"));
        assert!(header["state_root"].as_str().unwrap().starts_with("0x"));
        assert!(header["body_root"].as_str().unwrap().starts_with("0x"));
        assert!(
            json["data"]["header"]["signature"]
                .as_str()
                .unwrap()
                .starts_with("0x")
        );
        assert!(json["data"]["root"].as_str().unwrap().starts_with("0x"));
    }

    /// `body_root` is the field no other accessor can produce, so it has to be
    /// the body's own merkle root rather than, say, the block's.
    #[tokio::test]
    async fn the_body_root_is_the_bodys_own_merkle_root() {
        let json = body_json(get("/eth/v1/beacon/headers/head".to_string()).await).await;

        let expected = ethlambda_types::primitives::HashTreeRoot::hash_tree_root(
            &ethlambda_types::beacon::containers::phase0::BeaconBlockBody::default(),
        );
        assert_eq!(
            json["data"]["header"]["message"]["body_root"],
            format!("0x{expected:x}")
        );
    }

    /// `canonical` is read off the index rather than assumed. The anchor is
    /// reachable by root but is not in `BlockRoots`, so it answers `false`
    /// while the head answers `true`.
    #[tokio::test]
    async fn canonical_is_checked_against_the_index() {
        let head = body_json(get("/eth/v1/beacon/headers/head".to_string()).await).await;
        assert_eq!(head["data"]["canonical"], true);

        let fixture = beacon_fixture(ANCHOR_SLOT);
        let uri = format!("/eth/v1/beacon/headers/0x{:x}", fixture.anchor_root);
        let app = routes().with_state(fixture.store);
        let response = app
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let anchor = body_json(response).await;
        assert_eq!(
            anchor["data"]["canonical"], false,
            "the anchor's slot is not in BlockRoots, so the index cannot vouch for it"
        );
    }

    #[tokio::test]
    async fn a_malformed_id_is_a_400_and_an_absent_one_a_404() {
        assert_eq!(
            get("/eth/v1/beacon/headers/nope".to_string())
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            get("/eth/v1/beacon/headers/999999".to_string())
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
    }
}
