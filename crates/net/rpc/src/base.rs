use axum::{
    Json, Router,
    http::{HeaderValue, header},
    response::IntoResponse,
    routing::get,
};
use ethlambda_storage::Store;
use ethlambda_types::primitives::H256;
use libssz::SszEncode;

pub(crate) fn routes() -> Router<Store> {
    Router::new()
        .route("/lean/v0/health", get(crate::metrics::get_health))
        .route("/lean/v0/states/finalized", get(get_latest_finalized_state))
        .route("/lean/v0/blocks/finalized", get(get_latest_finalized_block))
        .route(
            "/lean/v0/checkpoints/justified",
            get(get_latest_justified_checkpoint),
        )
}

pub(crate) async fn get_latest_finalized_state(
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

pub(crate) async fn get_latest_finalized_block(
    axum::extract::State(store): axum::extract::State<Store>,
) -> impl IntoResponse {
    let finalized = store.latest_finalized();
    // Genesis has no stored signature; `get_signed_block` synthesizes a
    // placeholder blank proof so this always returns 200.
    match store.get_signed_block(&finalized.root) {
        Some(block) => ssz_response(block.to_ssz()),
        None => axum::http::StatusCode::NOT_FOUND.into_response(),
    }
}

pub(crate) async fn get_latest_justified_checkpoint(
    axum::extract::State(store): axum::extract::State<Store>,
) -> impl IntoResponse {
    let checkpoint = store.latest_justified();
    json_response(checkpoint)
}

pub(crate) fn json_response<T: serde::Serialize>(value: T) -> axum::response::Response {
    let mut response = Json(value).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(crate::JSON_CONTENT_TYPE),
    );
    response
}

fn ssz_response(bytes: Vec<u8>) -> axum::response::Response {
    let mut response = bytes.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(crate::SSZ_CONTENT_TYPE),
    );
    response
}
