use axum::{Router, http::HeaderValue, http::header, response::IntoResponse, routing::get};
use ethlambda_metrics::gather_default_metrics;
use tracing::warn;

pub fn start_prometheus_metrics_api() -> Router {
    Router::new()
        .route("/metrics", get(get_metrics))
        .route("/lean/v0/health", get(get_health))
}

pub(crate) async fn get_health() -> impl IntoResponse {
    let mut response = r#"{"status":"healthy","service":"lean-spec-api"}"#.into_response();
    let content_type = HeaderValue::from_static("application/json; charset=utf-8");
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, content_type);
    response
}

pub(crate) async fn get_metrics() -> impl IntoResponse {
    let mut response = gather_default_metrics()
        .inspect_err(|err| {
            warn!(%err, "Failed to gather Prometheus metrics");
        })
        .unwrap_or_default()
        .into_response();
    let content_type = HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8");
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, content_type);
    response
}
