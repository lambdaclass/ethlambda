//! `POST /eth/v1/validator/proposer_preferences`: signed proposer preferences
//! from a validator client, validated with the gossip rules, cached in the
//! shared `BuilderMarket` and gossiped on `proposer_preferences`.
//!
//! Stub: no routes until filled.

use axum::Router;
use ethlambda_storage::Store;

#[allow(dead_code)] // filled by Agent C
pub(crate) fn routes() -> Router<Store> {
    Router::new()
}
