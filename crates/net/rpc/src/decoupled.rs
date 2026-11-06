//! `GET /lean/v0/decoupled/status`: a lean node's decoupled consensus
//! (EIP-8453) view.
//!
//! The head, the confirmed node (`get_confirmed_node`) and `latest_confirmed`,
//! the finalized and justified checkpoints, the maximum height, whether the
//! finality gadget is in a contest, and the live lock count, as the decoupled
//! chain actor last published them. 404 on a node that does not run the
//! decoupled protocol.

use axum::{Extension, Router, http::StatusCode, response::IntoResponse, routing::get};
use ethlambda_storage::Store;
use ethlambda_types::decoupled::SharedDecoupledStatus;

use crate::json_response;

async fn get_status(Extension(status): Extension<SharedDecoupledStatus>) -> impl IntoResponse {
    let status = status
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    match status {
        Some(status) => json_response(status).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            "this node does not run the decoupled consensus protocol",
        )
            .into_response(),
    }
}

pub(crate) fn routes() -> Router<Store> {
    Router::new().route("/lean/v0/decoupled/status", get(get_status))
}
