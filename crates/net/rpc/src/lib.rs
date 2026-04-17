use std::net::SocketAddr;

use axum::{Json, Router, http::HeaderValue, http::header, response::IntoResponse, routing::get};
use ethlambda_storage::Store;
use ethlambda_types::primitives::H256;
use libssz::SszEncode;

pub(crate) const JSON_CONTENT_TYPE: &str = "application/json; charset=utf-8";
pub(crate) const SSZ_CONTENT_TYPE: &str = "application/octet-stream";

mod blocks;
mod fork_choice;
mod heap_profiling;
pub mod metrics;

pub async fn start_api_server(address: SocketAddr, store: Store) -> Result<(), std::io::Error> {
    let api_router = build_api_router(store);

    let listener = tokio::net::TcpListener::bind(address).await?;
    axum::serve(listener, api_router).await?;

    Ok(())
}

pub async fn start_metrics_server(address: SocketAddr) -> Result<(), std::io::Error> {
    let metrics_router = metrics::start_prometheus_metrics_api();
    let debug_router = build_debug_router();

    let app = Router::new().merge(metrics_router).merge(debug_router);

    let listener = tokio::net::TcpListener::bind(address).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Build the API router with the given store.
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
        .route("/lean/v0/blocks/{block_id}", get(blocks::get_block))
        .route(
            "/lean/v0/blocks/{block_id}/header",
            get(blocks::get_block_header),
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
    use ethlambda_storage::{StorageBackend, Table};
    use ethlambda_types::{
        block::{Block, BlockBody, BlockHeader},
        checkpoint::Checkpoint,
        primitives::{H256, HashTreeRoot as _},
        state::{ChainConfig, JustificationValidators, JustifiedSlots, State},
    };
    use libssz::SszEncode;

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

    /// Build a block at the given slot with a trivial body.
    pub(crate) fn make_block(slot: u64, parent_root: H256) -> Block {
        Block {
            slot,
            proposer_index: 0,
            parent_root,
            state_root: H256::ZERO,
            body: BlockBody::default(),
        }
    }

    /// Insert a block's header (and body, if non-empty) into the backend.
    ///
    /// This bypasses `Store::insert_signed_block`, which requires XMSS
    /// signatures that are expensive to produce in tests.
    pub(crate) fn insert_block_raw(backend: &dyn StorageBackend, block: &Block) -> H256 {
        let header = block.header();
        let root = header.hash_tree_root();

        let mut batch = backend.begin_write().expect("write batch");
        batch
            .put_batch(Table::BlockHeaders, vec![(root.to_ssz(), header.to_ssz())])
            .expect("put header");
        if header.body_root != BlockBody::default().hash_tree_root() {
            batch
                .put_batch(
                    Table::BlockBodies,
                    vec![(root.to_ssz(), block.body.to_ssz())],
                )
                .expect("put body");
        }
        batch.commit().expect("commit");

        root
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

    mod blocks {
        use super::*;
        use ethlambda_types::{
            primitives::{H256, HashTreeRoot as _},
            state::JustifiedSlots,
        };

        use crate::test_utils::{insert_block_raw, make_block};

        /// Build a store whose head state points back at `slot=1` via
        /// `historical_block_hashes`, with a real block stored at that slot.
        fn store_with_historical_block() -> (Store, H256) {
            let backend = Arc::new(InMemoryBackend::new());

            let target_block = make_block(1, H256::ZERO);
            let target_root = insert_block_raw(backend.as_ref(), &target_block);

            let mut anchor_state = create_test_state();
            anchor_state.slot = 2;
            anchor_state.latest_block_header.slot = 2;
            anchor_state.latest_block_header.parent_root = target_root;
            anchor_state.historical_block_hashes =
                vec![H256::ZERO, target_root].try_into().unwrap();
            anchor_state.justified_slots = JustifiedSlots::with_length(2).unwrap();

            let store = Store::from_anchor_state(backend, anchor_state);
            (store, target_root)
        }

        async fn send(app: axum::Router, uri: &str) -> axum::response::Response {
            app.oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap()
        }

        fn anchor_root_of(state: &ethlambda_types::state::State) -> H256 {
            let mut state = state.clone();
            state.latest_block_header.state_root = H256::ZERO;
            let state_root = state.hash_tree_root();
            state.latest_block_header.state_root = state_root;
            state.latest_block_header.hash_tree_root()
        }

        #[tokio::test]
        async fn get_block_by_root_returns_json() {
            let state = create_test_state();
            let anchor_root = anchor_root_of(&state);
            let backend = Arc::new(InMemoryBackend::new());
            let store = Store::from_anchor_state(backend, state);
            let app = build_api_router(store);

            let response = send(app, &format!("/lean/v0/blocks/0x{anchor_root:x}")).await;

            assert_eq!(response.status(), StatusCode::OK);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

            assert_eq!(json["slot"], 0);
            assert_eq!(json["proposer_index"], 0);
            assert!(json["parent_root"].is_string());
            assert!(json["state_root"].is_string());
            assert!(json["body"]["attestations"].is_array());
        }

        #[tokio::test]
        async fn get_block_header_by_root_returns_json() {
            let state = create_test_state();
            let anchor_root = anchor_root_of(&state);
            let backend = Arc::new(InMemoryBackend::new());
            let store = Store::from_anchor_state(backend, state);
            let app = build_api_router(store);

            let response = send(app, &format!("/lean/v0/blocks/0x{anchor_root:x}/header")).await;

            assert_eq!(response.status(), StatusCode::OK);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

            assert_eq!(json["slot"], 0);
            assert_eq!(json["proposer_index"], 0);
            assert!(json["body_root"].is_string());
        }

        #[tokio::test]
        async fn get_block_by_slot_returns_json() {
            let (store, _target_root) = store_with_historical_block();
            let app = build_api_router(store);

            let response = send(app, "/lean/v0/blocks/1").await;

            assert_eq!(response.status(), StatusCode::OK);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

            assert_eq!(json["slot"], 1);
            assert!(json["body"]["attestations"].is_array());
        }

        #[tokio::test]
        async fn get_block_invalid_id_returns_400() {
            let state = create_test_state();
            let backend = Arc::new(InMemoryBackend::new());
            let store = Store::from_anchor_state(backend, state);
            let app = build_api_router(store);

            let response = send(app, "/lean/v0/blocks/not-a-valid-id").await;

            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn get_block_missing_root_returns_404() {
            let state = create_test_state();
            let backend = Arc::new(InMemoryBackend::new());
            let store = Store::from_anchor_state(backend, state);
            let app = build_api_router(store);

            let missing = format!("0x{}", "aa".repeat(32));
            let response = send(app, &format!("/lean/v0/blocks/{missing}")).await;

            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        async fn get_block_missing_slot_returns_404() {
            let (store, _) = store_with_historical_block();
            let app = build_api_router(store);

            let response = send(app, "/lean/v0/blocks/999").await;

            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        async fn get_block_empty_slot_returns_404() {
            let (store, _) = store_with_historical_block();
            let app = build_api_router(store);

            // Slot 0 in the test setup is H256::ZERO (empty).
            let response = send(app, "/lean/v0/blocks/0").await;

            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }
    }
}
