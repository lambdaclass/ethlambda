use axum::{Router, http::HeaderValue, response::IntoResponse, routing::get};
use ethlambda_metrics::gather_default_metrics;
use tracing::warn;

pub fn start_prometheus_metrics_api() -> Router {
    Router::new()
        .route("/metrics", get(get_metrics))
        .route("/lean/v0/health", get(get_health))
}

pub(crate) async fn get_health() -> impl IntoResponse {
    r#"{"status": "healthy", "service": "lean-spec-api"}"#
}

pub(crate) async fn get_metrics() -> impl IntoResponse {
    let mut response = gather_default_metrics()
        .inspect_err(|err| {
            warn!(%err, "Failed to gather Prometheus metrics");
        })
        .unwrap_or_default()
        .into_response();
    let content_type = HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8");
    response.headers_mut().insert("content-type", content_type);
    response
}
