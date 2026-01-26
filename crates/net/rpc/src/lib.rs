use std::net::SocketAddr;

use axum::{Json, Router, http::HeaderValue, http::header, response::IntoResponse, routing::get};
use ethlambda_storage::Store;

const JSON_CONTENT_TYPE: &str = "application/json; charset=utf-8";

pub mod metrics;

pub async fn start_rpc_server(address: SocketAddr, store: Store) -> Result<(), std::io::Error> {
    let metrics_router = metrics::start_prometheus_metrics_api();
    let api_router = build_api_router(store);

    let app = Router::new().merge(metrics_router).merge(api_router);

    let listener = tokio::net::TcpListener::bind(address).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Build the API router with the given store.
fn build_api_router(store: Store) -> Router {
    Router::new()
        .route("/lean/v0/states/finalized", get(get_latest_finalized_state))
        .route(
            "/lean/v0/checkpoints/justified",
            get(get_latest_justified_state),
        )
        .with_state(store)
}

async fn get_latest_finalized_state(
    axum::extract::State(store): axum::extract::State<Store>,
) -> impl IntoResponse {
    let finalized = store.latest_finalized();
    let state = store
        .get_state(&finalized.root)
        .expect("finalized state exists");
    json_response(state)
}

async fn get_latest_justified_state(
    axum::extract::State(store): axum::extract::State<Store>,
) -> impl IntoResponse {
    let checkpoint = store.latest_justified();
    json_response(checkpoint)
}

fn json_response<T: serde::Serialize>(value: T) -> axum::response::Response {
    let mut response = Json(value).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(JSON_CONTENT_TYPE),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use ethlambda_storage::Store;
    use ethlambda_types::{
        block::{BlockBody, BlockHeader},
        primitives::TreeHash,
        state::{ChainConfig, Checkpoint, JustificationValidators, JustifiedSlots, State},
    };
    use http_body_util::BodyExt;
    use serde_json::json;
    use tower::ServiceExt;

    /// Create a minimal test state for testing.
    fn create_test_state() -> State {
        let genesis_header = BlockHeader {
            slot: 0,
            proposer_index: 0,
            parent_root: ethlambda_types::primitives::H256::ZERO,
            state_root: ethlambda_types::primitives::H256::ZERO,
            body_root: BlockBody::default().tree_hash_root(),
        };

        let genesis_checkpoint = Checkpoint {
            root: ethlambda_types::primitives::H256::ZERO,
            slot: 0,
        };

        State {
            config: ChainConfig { genesis_time: 1000 },
            slot: 0,
            latest_block_header: genesis_header,
            latest_justified: genesis_checkpoint,
            latest_finalized: genesis_checkpoint,
            historical_block_hashes: Default::default(),
            justified_slots: JustifiedSlots::with_capacity(0).unwrap(),
            validators: Default::default(),
            justifications_roots: Default::default(),
            justifications_validators: JustificationValidators::with_capacity(0).unwrap(),
        }
    }

    #[tokio::test]
    async fn test_get_latest_justified_checkpoint() {
        let state = create_test_state();
        let store = Store::from_genesis(state);

        let app = build_api_router(store.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/lean/v0/checkpoints/justified")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let checkpoint: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // The justified checkpoint should match the store's latest justified
        let expected = store.latest_justified();
        assert_eq!(
            checkpoint,
            json!({
                "slot": expected.slot,
                "root": format!("{:#x}", expected.root)
            })
        );
    }

    #[tokio::test]
    async fn test_get_latest_finalized_state() {
        let state = create_test_state();
        let store = Store::from_genesis(state);

        // Get the expected state from the store to build expected JSON
        let finalized = store.latest_finalized();
        let expected_state = store.get_state(&finalized.root).unwrap();

        let app = build_api_router(store);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/lean/v0/states/finalized")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let returned_state: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let header = &expected_state.latest_block_header;
        assert_eq!(
            returned_state,
            json!({
                "config": {
                    "genesis_time": expected_state.config.genesis_time
                },
                "slot": expected_state.slot,
                "latest_block_header": {
                    "slot": header.slot,
                    "proposer_index": header.proposer_index,
                    "parent_root": format!("{:#x}", header.parent_root),
                    "state_root": format!("{:#x}", header.state_root),
                    "body_root": format!("{:#x}", header.body_root)
                },
                "latest_justified": {
                    "slot": expected_state.latest_justified.slot,
                    "root": format!("{:#x}", expected_state.latest_justified.root)
                },
                "latest_finalized": {
                    "slot": expected_state.latest_finalized.slot,
                    "root": format!("{:#x}", expected_state.latest_finalized.root)
                },
                "historical_block_hashes": [],
                "justified_slots": "0x01",
                "validators": [],
                "justifications_roots": [],
                "justifications_validators": "0x01"
            })
        );
    }
}
