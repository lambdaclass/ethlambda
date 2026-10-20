//! `/eth/v1/beacon/genesis`.

use axum::{
    Router,
    extract::State,
    response::{IntoResponse, Response},
    routing::get,
};
use ethlambda_storage::Store;
use ethlambda_types::beacon::serde_helpers::HexPrefixed;

use crate::beacon::ApiError;

pub(crate) fn routes() -> Router<Store> {
    Router::new().route("/eth/v1/beacon/genesis", get(get_genesis))
}

async fn get_genesis(State(store): State<Store>) -> Response {
    let config = store.config();

    // `genesis_validators_root` is a property of the chain carried by every
    // state, so the finalized anchor answers it whether or not this directory
    // holds the genesis block itself. A checkpoint-synced one does not, which
    // is why this does not go looking for slot 0.
    let root = match store.latest_finalized() {
        Ok(checkpoint) => checkpoint.root,
        Err(_) => return ApiError::Internal("no anchor").into_response(),
    };
    let genesis_validators_root = match store.get_state(&root) {
        Ok(Some(state)) => state.genesis_validators_root(),
        Ok(None) => return ApiError::Internal("no anchor state").into_response(),
        Err(_) => return ApiError::Internal("store read failed").into_response(),
    };

    crate::json_response(serde_json::json!({
        "data": {
            "genesis_time": config.genesis_time.to_string(),
            "genesis_validators_root": genesis_validators_root,
            "genesis_fork_version": HexPrefixed(&config.genesis_fork_version).to_string(),
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::beacon_fixture;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    #[tokio::test]
    async fn genesis_reports_time_root_and_fork_version() {
        let fixture = beacon_fixture(64);
        let app = routes().with_state(fixture.store);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/eth/v1/beacon/genesis")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            json["data"]["genesis_time"], "1606824023",
            "quoted, and the value init_beacon was given"
        );
        assert!(
            json["data"]["genesis_validators_root"]
                .as_str()
                .unwrap()
                .starts_with("0x")
        );
        // Four bytes, so eight hex digits after the `0x`.
        assert_eq!(
            json["data"]["genesis_fork_version"].as_str().unwrap().len(),
            10
        );
    }
}
