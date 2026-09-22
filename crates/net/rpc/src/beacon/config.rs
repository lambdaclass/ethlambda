//! `/eth/v1/config/spec`.
//!
//! The values come straight off the `Config` the store was bootstrapped with,
//! so a node started with `--network <dir>` reports that network's constants
//! rather than mainnet's. `GENESIS_TIME` is absent by design: it is not a
//! `config.yaml` key, and `/eth/v1/beacon/genesis` is where it is reported.

use axum::{Router, extract::State, response::Response, routing::get};
use ethlambda_storage::Store;

pub(crate) fn routes() -> Router<Store> {
    Router::new().route("/eth/v1/config/spec", get(get_spec))
}

async fn get_spec(State(store): State<Store>) -> Response {
    // Through the `Arc` rather than cloning: `Config` carries a blob of
    // scalars plus the blob schedule, and nothing here needs to own it.
    crate::json_response(serde_json::json!({ "data": store.config().as_ref() }))
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
    async fn the_spec_is_screaming_snake_case_with_quoted_values() {
        let fixture = beacon_fixture(64);
        let app = routes().with_state(fixture.store);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/eth/v1/config/spec")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["data"]["SECONDS_PER_SLOT"], "12");
        assert!(
            json["data"]["GENESIS_FORK_VERSION"]
                .as_str()
                .unwrap()
                .starts_with("0x")
        );
        assert!(json["data"]["DEPOSIT_CHAIN_ID"].is_string());
    }
}
