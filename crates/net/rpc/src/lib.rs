use std::net::SocketAddr;

use axum::{
    Extension, Json, Router, http::HeaderValue, http::header, response::IntoResponse, routing::get,
};
use ethlambda_storage::Store;
use ethlambda_types::aggregator::AggregatorController;
use ethlambda_types::primitives::H256;
use libssz::SszEncode;
use tokio_util::sync::CancellationToken;

pub(crate) const JSON_CONTENT_TYPE: &str = "application/json; charset=utf-8";
pub(crate) const SSZ_CONTENT_TYPE: &str = "application/octet-stream";

mod admin;
mod fork_choice;
mod heap_profiling;
pub mod metrics;

pub async fn start_api_server(
    address: SocketAddr,
    store: Store,
    aggregator: AggregatorController,
    shutdown: CancellationToken,
) -> Result<(), std::io::Error> {
    let api_router = build_api_router(store).layer(Extension(aggregator));

    let listener = tokio::net::TcpListener::bind(address).await?;
    axum::serve(listener, api_router)
        .with_graceful_shutdown(async move {
            shutdown.cancelled().await;
        })
        .await?;

    Ok(())
}

pub async fn start_metrics_server(
    address: SocketAddr,
    shutdown: CancellationToken,
) -> Result<(), std::io::Error> {
    let metrics_router = metrics::start_prometheus_metrics_api();
    let debug_router = build_debug_router();

    let app = Router::new().merge(metrics_router).merge(debug_router);

    let listener = tokio::net::TcpListener::bind(address).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown.cancelled().await;
        })
        .await?;

    Ok(())
}

/// Build the API router with the given store.
///
/// The aggregator controller is threaded in via `Extension` by the caller
/// (see `start_api_server`) so existing store-backed handlers don't need to
/// know about it and admin handlers extract it independently.
fn build_api_router(store: Store) -> Router {
    Router::new()
        .route("/lean/v0/health", get(metrics::get_health))
        .route("/lean/v0/states/finalized", get(get_latest_finalized_state))
        .route(
            "/lean/v0/checkpoints/justified",
            get(get_latest_justified_state),
        )
        .route("/lean/v0/fork_choice", get(fork_choice::get_fork_choice))
        .route(
            "/lean/v0/fork_choice/ui",
            get(fork_choice::get_fork_choice_ui),
        )
        .route(
            "/lean/v0/admin/aggregator",
            get(admin::get_aggregator).post(admin::post_aggregator),
        )
        .with_state(store)
}

/// Build the debug router for profiling endpoints.
fn build_debug_router() -> Router {
    Router::new()
        .route("/debug/pprof/allocs", get(heap_profiling::handle_get_heap))
        .route(
            "/debug/pprof/allocs/flamegraph",
            get(heap_profiling::handle_get_heap_flamegraph),
        )
}

async fn get_latest_finalized_state(
    axum::extract::State(store): axum::extract::State<Store>,
) -> impl IntoResponse {
    let finalized = store.latest_finalized();
    let mut state = store
        .get_state(&finalized.root)
        .expect("finalized state exists");

    // Zero state_root to match the canonical post-state representation.
    // The spec's state_transition sets state_root to zero during process_block_header,
    // and only fills it in lazily at the next slot's process_slots.
    // Serving the canonical form ensures checkpoint sync interoperability.
    state.latest_block_header.state_root = H256::ZERO;

    ssz_response(state.to_ssz())
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

fn ssz_response(bytes: Vec<u8>) -> axum::response::Response {
    let mut response = bytes.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(SSZ_CONTENT_TYPE),
    );
    response
}

#[cfg(test)]
pub(crate) mod test_utils {
    use ethlambda_types::{
        block::{BlockBody, BlockHeader},
        checkpoint::Checkpoint,
        primitives::{H256, HashTreeRoot as _},
        state::{ChainConfig, JustificationValidators, JustifiedSlots, State},
    };

    /// Create a minimal test state for testing.
    pub(crate) fn create_test_state() -> State {
        let genesis_header = BlockHeader {
            slot: 0,
            proposer_index: 0,
            parent_root: H256::ZERO,
            state_root: H256::ZERO,
            body_root: BlockBody::default().hash_tree_root(),
        };

        let genesis_checkpoint = Checkpoint {
            root: H256::ZERO,
            slot: 0,
        };

        State {
            config: ChainConfig { genesis_time: 1000 },
            slot: 0,
            latest_block_header: genesis_header,
            latest_justified: genesis_checkpoint,
            latest_finalized: genesis_checkpoint,
            historical_block_hashes: Default::default(),
            justified_slots: JustifiedSlots::new(),
            validators: Default::default(),
            justifications_roots: Default::default(),
            justifications_validators: JustificationValidators::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use ethlambda_storage::{Store, backend::InMemoryBackend};
    use http_body_util::BodyExt;
    use serde_json::json;
    use std::sync::Arc;
    use tower::ServiceExt;

    use super::test_utils::create_test_state;

    #[tokio::test]
    async fn test_get_latest_justified_checkpoint() {
        let state = create_test_state();
        let backend = Arc::new(InMemoryBackend::new());
        let store = Store::from_anchor_state(backend, state);

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
                "root": format!("{}", expected.root)
            })
        );
    }

    #[tokio::test]
    async fn test_get_latest_finalized_state() {
        use ethlambda_types::primitives::H256;
        use libssz::SszEncode;
        let state = create_test_state();
        let backend = Arc::new(InMemoryBackend::new());
        let store = Store::from_anchor_state(backend, state);

        // Build expected SSZ with zeroed state_root (canonical post-state form)
        let finalized = store.latest_finalized();
        let mut expected_state = store.get_state(&finalized.root).unwrap();
        expected_state.latest_block_header.state_root = H256::ZERO;
        let expected_ssz = expected_state.to_ssz();

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
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            SSZ_CONTENT_TYPE
        );

        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), expected_ssz.as_slice());
    }
}
