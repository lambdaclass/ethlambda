use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use ethlambda_storage::Store;
use ethlambda_types::primitives::H256;
use serde_json::json;

use crate::json_response;

/// `GET /lean/v0/blocks/:block_id` — returns the block as JSON.
///
/// `block_id` can be a `0x`-prefixed 32-byte hex root or a decimal slot.
pub async fn get_block(
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
pub async fn get_block_header(
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
