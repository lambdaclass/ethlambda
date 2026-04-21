//! Admin endpoints for runtime-toggleable node roles.
//!
//! Ported from leanSpec PR #636. The POST handler strictly rejects non-boolean
//! values (including JSON integers 0/1) to match the spec's semantics.
//!
//! # Scope
//!
//! Toggling the aggregator flag at runtime does **not** change gossip subnet
//! subscriptions, which are frozen at startup. For full parity with the CLI
//! `--is-aggregator` flag, a standby node must boot with the flag enabled so
//! that subscriptions are in place, then use this endpoint to disable/enable
//! the role (hot-standby model). See leanSpec PR #636 for the full rationale.

use axum::{
    Extension, Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use ethlambda_types::aggregator::AggregatorController;
use serde::Serialize;
use serde_json::Value;
use tracing::info;

use crate::json_response;

#[derive(Serialize)]
struct StatusResponse {
    is_aggregator: bool,
}

#[derive(Serialize)]
struct ToggleResponse {
    is_aggregator: bool,
    previous: bool,
}

/// GET /lean/v0/admin/aggregator — returns current aggregator role.
///
/// Returns 503 when the controller is not wired. Kept for spec parity with
/// leanSpec, even though in ethlambda the controller is always wired when
/// the API server is started via `main.rs`.
///
/// The `Option<Extension<_>>` wrapping makes the extractor infallible: a bare
/// `Extension<T>` would cause axum to short-circuit with a 500 when the
/// extension is missing, whereas `Option` yields `None` and lets us return
/// a clean 503 with a useful message.
pub async fn get_aggregator(controller: Option<Extension<AggregatorController>>) -> Response {
    match controller {
        Some(Extension(controller)) => json_response(StatusResponse {
            is_aggregator: controller.is_enabled(),
        }),
        None => service_unavailable("Aggregator controller not available"),
    }
}

/// POST /lean/v0/admin/aggregator — toggles aggregator role at runtime.
///
/// Body: `{"enabled": bool}`. Returns `{"is_aggregator": <new>, "previous": <old>}`.
/// 400 on missing/invalid body, 503 when the controller is not wired.
///
/// The `Option<Extension<_>>` wrapping makes the extractor infallible: a bare
/// `Extension<T>` would cause axum to short-circuit with a 500 when the
/// extension is missing, whereas `Option` yields `None` and lets us return
/// a clean 503 with a useful message.
pub async fn post_aggregator(
    controller: Option<Extension<AggregatorController>>,
    body: Option<Json<Value>>,
) -> Response {
    let Some(Extension(controller)) = controller else {
        return service_unavailable("Aggregator controller not available");
    };

    // Parsing happens through `Option<Json<Value>>` so we can distinguish
    // "no body / malformed JSON" (None) from "valid JSON with wrong shape".
    let Some(Json(payload)) = body else {
        return bad_request("Invalid or missing JSON body");
    };

    let Some(enabled_value) = payload.get("enabled") else {
        return bad_request("Missing 'enabled' field in body");
    };

    let Some(enabled) = enabled_value.as_bool() else {
        return bad_request("'enabled' must be a boolean");
    };

    let previous = controller.set_enabled(enabled);
    if previous != enabled {
        info!(enabled, previous, "Aggregator role toggled via admin API");
    }

    json_response(ToggleResponse {
        is_aggregator: enabled,
        previous,
    })
}

fn bad_request(reason: &'static str) -> Response {
    (StatusCode::BAD_REQUEST, reason).into_response()
}

fn service_unavailable(reason: &'static str) -> Response {
    (StatusCode::SERVICE_UNAVAILABLE, reason).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use axum::routing::get;
    use axum::{Extension, Router};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn router(controller: Option<AggregatorController>) -> Router {
        let mut router = Router::new().route(
            "/lean/v0/admin/aggregator",
            get(get_aggregator).post(post_aggregator),
        );
        if let Some(controller) = controller {
            router = router.layer(Extension(controller));
        }
        router
    }

    async fn body_json(resp: Response) -> Value {
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn get_returns_current_state() {
        let controller = AggregatorController::new(true);
        let resp = router(Some(controller))
            .oneshot(
                Request::builder()
                    .uri("/lean/v0/admin/aggregator")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            body_json(resp).await,
            serde_json::json!({"is_aggregator": true})
        );
    }

    #[tokio::test]
    async fn get_returns_503_without_controller() {
        let resp = router(None)
            .oneshot(
                Request::builder()
                    .uri("/lean/v0/admin/aggregator")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    async fn post(controller: Option<AggregatorController>, body: &str) -> Response {
        router(controller)
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/lean/v0/admin/aggregator")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn post_activates_and_returns_previous() {
        let controller = AggregatorController::new(false);
        let resp = post(Some(controller.clone()), r#"{"enabled": true}"#).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            body_json(resp).await,
            serde_json::json!({"is_aggregator": true, "previous": false}),
        );
        assert!(controller.is_enabled());
    }

    #[tokio::test]
    async fn post_deactivates_and_returns_previous() {
        let controller = AggregatorController::new(true);
        let resp = post(Some(controller.clone()), r#"{"enabled": false}"#).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            body_json(resp).await,
            serde_json::json!({"is_aggregator": false, "previous": true}),
        );
        assert!(!controller.is_enabled());
    }

    #[tokio::test]
    async fn post_noop_when_value_matches_state() {
        let controller = AggregatorController::new(true);
        let _ = post(Some(controller.clone()), r#"{"enabled": true}"#).await;
        let resp = post(Some(controller.clone()), r#"{"enabled": true}"#).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            body_json(resp).await,
            serde_json::json!({"is_aggregator": true, "previous": true}),
        );
    }

    #[tokio::test]
    async fn post_rejects_missing_enabled_field() {
        let controller = AggregatorController::new(false);
        let resp = post(Some(controller), r#"{"other": true}"#).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn post_rejects_integer_in_place_of_bool() {
        // JSON parsers in other languages sometimes coerce 0/1 → bool; the
        // spec explicitly rejects this, so we do too.
        let controller = AggregatorController::new(false);
        let resp = post(Some(controller), r#"{"enabled": 1}"#).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn post_rejects_string_in_place_of_bool() {
        let controller = AggregatorController::new(false);
        let resp = post(Some(controller), r#"{"enabled": "true"}"#).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn post_rejects_malformed_json() {
        let controller = AggregatorController::new(false);
        let resp = post(Some(controller), "not json").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn post_returns_503_without_controller() {
        let resp = post(None, r#"{"enabled": true}"#).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
