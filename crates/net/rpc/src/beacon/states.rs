//! `/eth/v2/debug/beacon/states/{state_id}` and
//! `/eth/v1/beacon/states/{state_id}/finality_checkpoints`.
//!
//! Serving the first makes this client checkpoint-syncable from itself:
//! `bin/ethlambda/src/checkpoint_sync.rs` fetches exactly that path, as SSZ,
//! from whichever Beacon API server `--checkpoint-sync-url` names.

use axum::{
    Router,
    extract::{Path, State},
    http::{HeaderMap, header},
    response::{IntoResponse, Response},
    routing::get,
};
use ethlambda_storage::Store;
use ethlambda_types::{beacon::containers::BeaconState, primitives::H256};

use crate::{
    beacon::{ApiError, Envelope, blocks::is_finalized},
    shared::{
        block_id::BlockId,
        content::{Encoding, ssz_response, with_consensus_version},
    },
};

pub(crate) fn routes() -> Router<Store> {
    Router::new()
        .route("/eth/v2/debug/beacon/states/{state_id}", get(get_state))
        .route(
            "/eth/v1/beacon/states/{state_id}/finality_checkpoints",
            get(get_finality_checkpoints),
        )
}

/// Resolve a `state_id` to the block root its state is stored under.
///
/// A `0x…` id is a *state* root in this API, and states here are keyed by
/// block root with no reverse index. Rather than return the wrong state, or
/// quietly treat the id as a block root and be right only by coincidence,
/// refuse it and say which ids do work.
fn resolve_state_id(store: &Store, state_id: &str) -> Result<H256, ApiError> {
    match BlockId::parse(state_id)? {
        BlockId::Root(_) => Err(ApiError::NotFound(
            "lookup by state root is not indexed; use head, finalized, justified or a slot",
        )),
        id => Ok(id.resolve_beacon(store)?),
    }
}

/// Load the state a `state_id` names, or the response explaining why not.
fn load(store: &Store, state_id: &str) -> Result<(H256, std::sync::Arc<BeaconState>), ApiError> {
    let root = resolve_state_id(store, state_id)?;
    let state = store
        .get_state(&root)
        .map_err(|_| ApiError::Internal("store read failed"))?
        .ok_or(ApiError::NotFound("state not found"))?;
    Ok((root, state))
}

async fn get_state(
    Path(state_id): Path<String>,
    State(store): State<Store>,
    headers: HeaderMap,
) -> Response {
    let (root, state) = match load(&store, &state_id) {
        Ok(found) => found,
        Err(err) => return err.into_response(),
    };
    let fork = state.fork_name();

    let accept = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok());
    let response = match Encoding::from_accept(accept) {
        Encoding::Ssz => ssz_response(state.to_ssz()),
        // `state.as_ref()` rather than a clone: a mainnet state runs to
        // hundreds of megabytes, and serde serializes happily through the
        // borrow.
        Encoding::Json => crate::json_response(Envelope {
            version: fork.as_str(),
            execution_optimistic: store.is_beacon_optimistic(root),
            finalized: is_finalized(&store, state.slot()),
            data: state.as_ref(),
        }),
    };

    with_consensus_version(response, fork)
}

async fn get_finality_checkpoints(
    Path(state_id): Path<String>,
    State(store): State<Store>,
) -> Response {
    let (root, state) = match load(&store, &state_id) {
        Ok(found) => found,
        Err(err) => return err.into_response(),
    };

    // The state's own three checkpoints, not the store's fork-choice view.
    // This endpoint is defined as a read of the state `state_id` names, and
    // the state is the only place a *previous* justified checkpoint is kept
    // at all: the store keeps one justified row and one finalized row.
    crate::json_response(serde_json::json!({
        "execution_optimistic": store.is_beacon_optimistic(root),
        "finalized": is_finalized(&store, state.slot()),
        "data": {
            "previous_justified": state.previous_justified_checkpoint(),
            "current_justified": state.current_justified_checkpoint(),
            "finalized": state.finalized_checkpoint(),
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

    async fn body_json(response: axum::response::Response) -> serde_json::Value {
        let body = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&body).unwrap()
    }

    /// Exactly what `bin/ethlambda/src/checkpoint_sync.rs` asks other clients
    /// for, so serving it makes this client checkpoint-syncable from itself.
    #[tokio::test]
    async fn the_finalized_state_comes_back_as_ssz_for_checkpoint_sync() {
        let response = get(
            "/eth/v2/debug/beacon/states/finalized",
            Some("application/octet-stream"),
        )
        .await;
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

        // The bytes have to decode back into the state they came from, since
        // checkpoint sync's whole job is to do exactly that.
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let slot = ethlambda_types::beacon::containers::BeaconState::slot_from_ssz(&body)
            .expect("the body is a beacon state");
        assert_eq!(slot, ANCHOR_SLOT);
    }

    #[tokio::test]
    async fn a_state_comes_back_as_json_by_default() {
        let json = body_json(get("/eth/v2/debug/beacon/states/head", None).await).await;
        assert_eq!(json["version"], "phase0");
        assert_eq!(json["data"]["slot"], "65", "integers are quoted");
        assert!(
            json["data"]["genesis_validators_root"]
                .as_str()
                .unwrap()
                .starts_with("0x")
        );
    }

    #[tokio::test]
    async fn a_state_root_id_is_refused_because_states_are_indexed_by_block_root() {
        let id = format!("0x{}", "cd".repeat(32));
        let response = get(&format!("/eth/v2/debug/beacon/states/{id}"), None).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let json = body_json(response).await;
        assert!(
            json["message"].as_str().unwrap().contains("state root"),
            "the refusal has to say why, got {}",
            json["message"]
        );
    }

    #[tokio::test]
    async fn finality_checkpoints_report_all_three() {
        let response = get("/eth/v1/beacon/states/head/finality_checkpoints", None).await;
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;

        for field in ["previous_justified", "current_justified", "finalized"] {
            assert!(
                json["data"][field]["epoch"].is_string(),
                "{field} epoch must be quoted, got {}",
                json["data"][field]["epoch"]
            );
            assert!(
                json["data"][field]["root"]
                    .as_str()
                    .unwrap()
                    .starts_with("0x")
            );
        }
    }

    #[tokio::test]
    async fn a_malformed_id_is_a_400_and_an_absent_one_a_404() {
        assert_eq!(
            get("/eth/v2/debug/beacon/states/nope", None).await.status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            get("/eth/v2/debug/beacon/states/999999", None)
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
    }
}
