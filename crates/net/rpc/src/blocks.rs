use axum::{
    Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
};
use ethlambda_storage::Store;
use ethlambda_types::primitives::H256;
use serde::Deserialize;
use serde_json::json;

use crate::json_response;

const MAX_RANGE_COUNT: u64 = 1024;

pub(crate) fn routes() -> Router<Store> {
    Router::new()
        .route("/lean/v0/blocks", get(get_blocks_by_range))
        .route("/lean/v0/blocks/{block_id}", get(get_block))
        .route("/lean/v0/blocks/{block_id}/header", get(get_block_header))
}

/// `GET /lean/v0/blocks/:block_id` — returns the block as JSON.
///
/// `block_id` can be a `0x`-prefixed 32-byte hex root or a decimal slot.
pub(crate) async fn get_block(
    Path(block_id): Path<String>,
    State(store): State<Store>,
) -> impl IntoResponse {
    let root = match resolve_block_id(&store, &block_id) {
        Ok(root) => root,
        Err(err) => return err.into_response(),
    };

    match store.get_block(&root) {
        Some(block) => json_response(block),
        None => BlockIdError::NotFound.into_response(),
    }
}

/// `GET /lean/v0/blocks/:block_id/header` — returns the block header as JSON.
pub(crate) async fn get_block_header(
    Path(block_id): Path<String>,
    State(store): State<Store>,
) -> impl IntoResponse {
    let root = match resolve_block_id(&store, &block_id) {
        Ok(root) => root,
        Err(err) => return err.into_response(),
    };

    match store.get_block_header(&root) {
        Some(header) => json_response(header),
        None => BlockIdError::NotFound.into_response(),
    }
}

/// Resolve a `block_id` (hex root or decimal slot) into a block root.
///
/// Slot lookups use the head state's `historical_block_hashes`, so only
/// canonical blocks are reachable by slot — blocks on side forks must be
/// addressed by their root.
fn resolve_block_id(store: &Store, block_id: &str) -> Result<H256, BlockIdError> {
    if let Some(hex_body) = block_id.strip_prefix("0x") {
        parse_root(hex_body)
    } else if block_id.chars().all(|c| c.is_ascii_digit()) {
        let slot: u64 = block_id.parse().map_err(|_| BlockIdError::Invalid)?;
        resolve_slot(store, slot)
    } else {
        Err(BlockIdError::Invalid)
    }
}

fn parse_root(hex_body: &str) -> Result<H256, BlockIdError> {
    let bytes = hex::decode(hex_body).map_err(|_| BlockIdError::Invalid)?;
    if bytes.len() != 32 {
        return Err(BlockIdError::Invalid);
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(H256(arr))
}

fn resolve_slot(store: &Store, slot: u64) -> Result<H256, BlockIdError> {
    let head_state = store.head_state();
    let root = head_state
        .historical_block_hashes
        .get(slot as usize)
        .ok_or(BlockIdError::NotFound)?;
    if root.is_zero() {
        return Err(BlockIdError::NotFound);
    }
    Ok(*root)
}

#[derive(Deserialize)]
pub(crate) struct BlockRangeParams {
    start_slot: u64,
    count: u64,
}

/// `GET /lean/v0/blocks?start_slot=&count=` — returns canonical blocks in the given slot range.
///
/// Returns a JSON array of blocks. Slots with no canonical block (zero root) are silently
/// skipped. `count` is capped at [`MAX_RANGE_COUNT`].
pub(crate) async fn get_blocks_by_range(
    Query(params): Query<BlockRangeParams>,
    State(store): State<Store>,
) -> impl IntoResponse {
    let count = params.count.min(MAX_RANGE_COUNT);
    let head_state = store.head_state();
    let mut blocks = Vec::new();
    for slot in params.start_slot..params.start_slot.saturating_add(count) {
        if let Some(root) = head_state.historical_block_hashes.get(slot as usize)
            && !root.is_zero()
            && let Some(block) = store.get_block(root)
        {
            blocks.push(block);
        }
    }
    json_response(blocks)
}

#[derive(Debug)]
enum BlockIdError {
    Invalid,
    NotFound,
}

impl IntoResponse for BlockIdError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            BlockIdError::Invalid => (StatusCode::BAD_REQUEST, "invalid block_id"),
            BlockIdError::NotFound => (StatusCode::NOT_FOUND, "block not found"),
        };
        let mut response = json_response(json!({ "error": message }));
        *response.status_mut() = status;
        response
    }
}

#[cfg(test)]
mod range_tests {
    use crate::test_utils::{create_test_state, insert_block_raw, make_block};
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use ethlambda_storage::{Store, backend::InMemoryBackend};
    use ethlambda_types::{primitives::H256, state::JustifiedSlots};
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    fn store_with_block_at_slot_1() -> Store {
        let backend = Arc::new(InMemoryBackend::new());
        let target = make_block(1, H256::ZERO);
        let root = insert_block_raw(backend.as_ref(), &target);
        let mut anchor = create_test_state();
        anchor.slot = 2;
        anchor.historical_block_hashes = vec![H256::ZERO, root].try_into().unwrap();
        anchor.justified_slots = JustifiedSlots::with_length(2).unwrap();
        Store::from_anchor_state(backend, anchor)
    }

    #[tokio::test]
    async fn blocks_range_returns_canonical_blocks() {
        let app = crate::build_api_router(store_with_block_at_slot_1());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/lean/v0/blocks?start_slot=1&count=2")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.as_array().unwrap().len(), 1);
        assert_eq!(json[0]["slot"], 1);
    }
}
