use axum::{http::HeaderValue, http::header, response::IntoResponse};
use ethlambda_storage::Store;
use ethlambda_types::{checkpoint::Checkpoint, primitives::H256};
use serde::Serialize;

use crate::json_response;

const HTML_CONTENT_TYPE: &str = "text/html; charset=utf-8";
const FORK_CHOICE_HTML: &str = include_str!("../static/fork_choice.html");

#[derive(Serialize)]
pub struct ForkChoiceResponse {
    nodes: Vec<ForkChoiceNode>,
    head: H256,
    justified: Checkpoint,
    finalized: Checkpoint,
    safe_target: H256,
    validator_count: u64,
}

#[derive(Serialize)]
pub struct ForkChoiceNode {
    root: H256,
    slot: u64,
    parent_root: H256,
    proposer_index: u64,
    weight: u64,
}

pub async fn get_fork_choice(
    axum::extract::State(store): axum::extract::State<Store>,
) -> impl IntoResponse {
    let blocks = store.get_live_chain();
    let attestations = store.extract_latest_known_attestations();

    let justified = store.latest_justified();
    let finalized = store.latest_finalized();
    let start_slot = finalized.slot;

    let weights = ethlambda_fork_choice::compute_block_weights(start_slot, &blocks, &attestations);

    let head = store.head();
    let safe_target = store.safe_target();

    let head_state = store.head_state();
    let validator_count = head_state.validators.len() as u64;

    let nodes: Vec<ForkChoiceNode> = blocks
        .iter()
        .map(|(root, &(slot, parent_root))| {
            let proposer_index = store
                .get_block_header(root)
                .map(|h| h.proposer_index)
                .unwrap_or(0);

            ForkChoiceNode {
                root: *root,
                slot,
                parent_root,
                proposer_index,
                weight: weights.get(root).copied().unwrap_or(0),
            }
        })
        .collect();

    let response = ForkChoiceResponse {
        nodes,
        head,
        justified,
        finalized,
        safe_target,
        validator_count,
    };

    json_response(response)
}

pub async fn get_fork_choice_ui() -> impl IntoResponse {
    let mut response = FORK_CHOICE_HTML.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(HTML_CONTENT_TYPE),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, http::Request, http::StatusCode, routing::get};
    use ethlambda_storage::{Store, backend::InMemoryBackend};
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    use crate::test_utils::create_test_state;

    fn build_test_router(store: Store) -> Router {
        Router::new()
            .route("/lean/v0/fork_choice", get(get_fork_choice))
            .route("/lean/v0/fork_choice/ui", get(get_fork_choice_ui))
            .with_state(store)
    }

    #[tokio::test]
    async fn test_get_fork_choice_returns_json() {
        let state = create_test_state();
        let backend = Arc::new(InMemoryBackend::new());
        let store = Store::from_anchor_state(backend, state);

        let app = build_test_router(store);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/lean/v0/fork_choice")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            crate::JSON_CONTENT_TYPE
        );

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(json["nodes"].is_array());
        assert!(json["head"].is_string());
        assert!(json["justified"]["root"].is_string());
        assert!(json["justified"]["slot"].is_number());
        assert!(json["finalized"]["root"].is_string());
        assert!(json["finalized"]["slot"].is_number());
        assert!(json["safe_target"].is_string());
        assert!(json["validator_count"].is_number());
    }

    #[tokio::test]
    async fn test_get_fork_choice_ui_returns_html() {
        let state = create_test_state();
        let backend = Arc::new(InMemoryBackend::new());
        let store = Store::from_anchor_state(backend, state);

        let app = build_test_router(store);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/lean/v0/fork_choice/ui")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            HTML_CONTENT_TYPE
        );

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("d3"));
    }
}
