//! `/eth/v1/beacon/execution_payload_envelopes/{block_id}`.
//!
//! Gloas moves a block's execution payload out of the block into a separate
//! signed envelope. This serves the one the node verified, which is also what
//! makes the node usable as a checkpoint-sync source for the payload of its
//! finalized block.

use axum::{
    Router,
    extract::{Path, State},
    http::{HeaderMap, header},
    response::{IntoResponse, Response},
    routing::get,
};
use ethlambda_storage::Store;
use ethlambda_types::beacon::fork::ForkName;
use libssz::SszEncode;

use crate::{
    beacon::{ApiError, Envelope as ResponseEnvelope, blocks::is_finalized},
    shared::{
        block_id::{BlockId, IdError},
        content::{Encoding, ssz_response, with_consensus_version},
        optimistic::envelope_is_optimistic,
    },
};

pub(crate) fn routes() -> Router<Store> {
    Router::new().route(
        "/eth/v1/beacon/execution_payload_envelopes/{block_id}",
        get(get_envelope),
    )
}

/// The envelope for `block_id`.
///
/// 404 covers an unknown block and a block with no stored envelope alike: the
/// store holds verified envelopes only, so a pre-gloas block, a withheld
/// payload and a payload not yet received are indistinguishable here, and the
/// specification names no other status for them.
async fn get_envelope(
    Path(block_id): Path<String>,
    State(store): State<Store>,
    headers: HeaderMap,
) -> Response {
    let not_found = ApiError::NotFound("Execution payload envelope not found");
    let root = match BlockId::parse(&block_id).and_then(|id| id.resolve_beacon(&store)) {
        Ok(root) => root,
        Err(IdError::Malformed) => return ApiError::BadRequest("invalid block id").into_response(),
        Err(IdError::NotFound) => return not_found.into_response(),
    };
    let envelope = match store.get_execution_payload_envelope(&root) {
        Ok(Some(envelope)) => envelope,
        Ok(None) => return not_found.into_response(),
        Err(_) => return ApiError::Internal("store read failed").into_response(),
    };
    let slot = match store.get_signed_block(&root) {
        Ok(Some(block)) => block.slot(),
        Ok(None) => return not_found.into_response(),
        Err(_) => return ApiError::Internal("store read failed").into_response(),
    };

    let accept = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok());
    let response = match Encoding::from_accept(accept) {
        Encoding::Ssz => ssz_response(envelope.to_ssz()),
        Encoding::Json => crate::json_response(ResponseEnvelope {
            version: ForkName::Gloas.as_str(),
            execution_optimistic: envelope_is_optimistic(&store, root),
            finalized: is_finalized(&store, slot),
            data: envelope,
        }),
    };

    with_consensus_version(response, ForkName::Gloas)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{beacon_fixture, gloas_envelope, gloas_fixture};
    use axum::{body::Body, http::Request, http::StatusCode};
    use ethlambda_types::{beacon::fork_choice::PayloadStatusEnum, primitives::H256};
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    async fn get(store: Store, uri: &str, accept: Option<&str>) -> axum::response::Response {
        let mut request = Request::builder().uri(uri);
        if let Some(accept) = accept {
            request = request.header("accept", accept);
        }
        routes()
            .with_state(store)
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    fn url(root: H256) -> String {
        format!("/eth/v1/beacon/execution_payload_envelopes/0x{root:x}")
    }

    async fn json_of(response: axum::response::Response) -> serde_json::Value {
        let body = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn a_stored_envelope_is_served_as_json_with_the_flags() {
        let mut fixture = gloas_fixture();
        let (root, slot) = fixture.g1;
        fixture
            .store
            .insert_verified_payload(slot, &gloas_envelope(root));

        // No verdict recorded: NOT_VALIDATED, so optimistic.
        let response = get(fixture.store.clone(), &url(root), None).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("eth-consensus-version").unwrap(),
            "gloas"
        );
        let json = json_of(response).await;
        assert_eq!(json["version"], "gloas");
        assert_eq!(json["execution_optimistic"], true);
        assert_eq!(json["finalized"], false);
        assert_eq!(json["data"]["message"]["builder_index"], "3");

        fixture
            .store
            .insert_beacon_block_payload_status(root, slot, PayloadStatusEnum::Valid);
        let json = json_of(get(fixture.store, &url(root), None).await).await;
        assert_eq!(json["execution_optimistic"], false);
    }

    #[tokio::test]
    async fn a_stored_envelope_is_served_as_ssz_on_request() {
        let mut fixture = gloas_fixture();
        let (root, slot) = fixture.g1;
        let envelope = gloas_envelope(root);
        fixture.store.insert_verified_payload(slot, &envelope);

        let response = get(fixture.store, &url(root), Some("application/octet-stream")).await;
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
            "gloas"
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), envelope.to_ssz().as_slice());
    }

    #[tokio::test]
    async fn a_gloas_block_without_a_stored_envelope_is_a_404() {
        let fixture = gloas_fixture();
        let response = get(fixture.store, &url(fixture.g1.0), None).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let json = json_of(response).await;
        assert_eq!(json["message"], "Execution payload envelope not found");
    }

    #[tokio::test]
    async fn an_unknown_block_is_a_404_and_a_malformed_id_a_400() {
        let fixture = beacon_fixture(64);
        let unknown = url(H256::from([0xee; 32]));
        assert_eq!(
            get(fixture.store.clone(), &unknown, None).await.status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            get(
                fixture.store,
                "/eth/v1/beacon/execution_payload_envelopes/nope",
                None
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
    }

    /// The specification's error list has no status for a pre-gloas block, and
    /// such a block has no envelope, so it reads as not found.
    #[tokio::test]
    async fn a_pre_gloas_block_has_no_envelope() {
        let fixture = gloas_fixture();
        let response = get(fixture.store, &url(fixture.head_root), None).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
