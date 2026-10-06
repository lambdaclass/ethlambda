//! `POST /eth/v1/beacon/states/{state_id}/builders`: the builder registry of a
//! gloas state, filtered by id and status.
//!
//! Stub: no routes until filled.

use axum::Router;
use ethlambda_storage::Store;

#[allow(dead_code)] // filled by Agent C
pub(crate) fn routes() -> Router<Store> {
    Router::new()
}
