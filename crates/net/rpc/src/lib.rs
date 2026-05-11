use std::net::{IpAddr, SocketAddr};

use axum::{
    Extension, Json, Router,
    http::{HeaderValue, StatusCode, header},
    response::IntoResponse,
    routing::get,
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
pub mod test_driver;

#[derive(Debug, Clone)]
pub struct RpcConfig {
    pub http_address: IpAddr,
    pub api_port: u16,
    pub metrics_port: u16,
}

/// Start the RPC server in Hive test-driver mode.
///
/// Exposes only the `/lean/v0/test_driver/...` endpoints plus a `/lean/v0/health`
/// stub. The driver swaps its own `Store` on every `fork_choice/init`, so we
/// don't share state with the regular consensus path (which isn't running in
/// driver mode anyway — see `bin/ethlambda/src/main.rs`).
pub async fn start_test_driver_rpc_server(
    config: RpcConfig,
    driver: test_driver::DriverState,
    shutdown: CancellationToken,
) -> Result<(), std::io::Error> {
    let app = test_driver::build_router(driver);
    let addr = SocketAddr::new(config.http_address, config.api_port);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown.cancelled().await;
        })
        .await?;
    Ok(())
}

pub async fn start_rpc_server(
    config: RpcConfig,
    store: Store,
    aggregator: AggregatorController,
    shutdown: CancellationToken,
) -> Result<(), std::io::Error> {
    let api_router = build_api_router(store).layer(Extension(aggregator));
    let metrics_router = metrics::start_prometheus_metrics_api();
    let debug_router = build_debug_router();

    if config.api_port == config.metrics_port {
        let app = Router::new()
            .merge(api_router)
            .merge(metrics_router)
            .merge(debug_router);
        let addr = SocketAddr::new(config.http_address, config.api_port);
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                shutdown.cancelled().await;
            })
            .await?;
    } else {
        let api_addr = SocketAddr::new(config.http_address, config.api_port);
        let metrics_addr = SocketAddr::new(config.http_address, config.metrics_port);
        let api_listener = tokio::net::TcpListener::bind(api_addr).await?;
        let metrics_listener = tokio::net::TcpListener::bind(metrics_addr).await?;
        let metrics_app = Router::new().merge(metrics_router).merge(debug_router);
        let metrics_shutdown = shutdown.clone();
        tokio::try_join!(
            axum::serve(api_listener, api_router).with_graceful_shutdown(async move {
                shutdown.cancelled().await;
            }),
            axum::serve(metrics_listener, metrics_app).with_graceful_shutdown(async move {
                metrics_shutdown.cancelled().await;
            }),
        )?;
    }

    Ok(())
}

/// Build the API router with the given store.
///
/// The aggregator controller is threaded in via `Extension` by the caller
/// (see `start_rpc_server`) so existing store-backed handlers don't need to
/// know about it and admin handlers extract it independently.
fn build_api_router(store: Store) -> Router {
    Router::new()
        .route("/lean/v0/health", get(metrics::get_health))
        .route("/lean/v0/states/finalized", get(get_latest_finalized_state))
        .route("/lean/v0/blocks/finalized", get(get_latest_finalized_block))
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

async fn get_latest_finalized_block(
    axum::extract::State(store): axum::extract::State<Store>,
) -> impl IntoResponse {
    let finalized = store.latest_finalized();
    // Returns 404 for genesis since it doesn't have a valid signature
    match store.get_signed_block(&finalized.root) {
        Some(block) => ssz_response(block.to_ssz()),
        None => StatusCode::NOT_FOUND.into_response(),
    }
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
    use axum::{body::Body, http::Request};
    use ethlambda_storage::{ForkCheckpoints, Store, backend::InMemoryBackend};
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

    #[tokio::test]
    async fn test_get_latest_finalized_block() {
        use ethlambda_types::{
            attestation::XmssSignature,
            block::{Block, BlockBody, BlockSignatures, SignedBlock},
            checkpoint::Checkpoint,
            primitives::{H256, HashTreeRoot as _},
            signature::SIGNATURE_SIZE,
        };
        use libssz::SszEncode;

        let state = create_test_state();
        let backend = Arc::new(InMemoryBackend::new());
        let mut store = Store::from_anchor_state(backend, state);

        // Build a non-genesis signed block with empty body and zero proposer signature.
        let block = Block {
            slot: 1,
            proposer_index: 0,
            parent_root: store.latest_finalized().root,
            state_root: H256::ZERO,
            body: BlockBody::default(),
        };
        let block_root = block.header().hash_tree_root();
        let signed_block = SignedBlock {
            message: block,
            signature: BlockSignatures {
                attestation_signatures: Default::default(),
                proposer_signature: XmssSignature::try_from(vec![0u8; SIGNATURE_SIZE]).unwrap(),
            },
        };

        // Persist the signed block and mark it as the latest finalized checkpoint.
        store.insert_signed_block(block_root, signed_block.clone());
        store.update_checkpoints(ForkCheckpoints::new(
            block_root,
            None,
            Some(Checkpoint {
                root: block_root,
                slot: 1,
            }),
        ));

        let expected_ssz = signed_block.to_ssz();

        let app = build_api_router(store);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/lean/v0/blocks/finalized")
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

    #[tokio::test]
    async fn test_get_latest_finalized_block_returns_404_when_absent() {
        // Genesis-anchored store: init_store writes header + state but no
        // BlockSignatures entry, so get_signed_block(genesis_root) returns None
        // and the endpoint must report 404 rather than panic.
        let state = create_test_state();
        let backend = Arc::new(InMemoryBackend::new());
        let store = Store::from_anchor_state(backend, state);

        let app = build_api_router(store);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/lean/v0/blocks/finalized")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
