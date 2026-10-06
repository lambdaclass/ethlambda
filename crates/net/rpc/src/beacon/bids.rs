//! `POST /eth/v1/beacon/execution_payload_bids`: a builder's bid handed to this
//! node, validated with the gossip rules, pooled in the shared
//! `BuilderMarket` and gossiped on `execution_payload_bid`.
//!
//! Stub: no routes until filled.

use axum::Router;
use ethlambda_storage::Store;

#[allow(dead_code)] // filled by Agent C
pub(crate) fn routes() -> Router<Store> {
    Router::new()
}
