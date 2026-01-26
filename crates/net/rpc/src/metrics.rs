use axum::{Router, http::HeaderValue, response::IntoResponse, routing::get};
use thiserror::Error;
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

#[derive(Debug, Error)]
pub enum Error {
    #[error("Prometheus error: {0}")]
    Prometheus(#[from] prometheus::Error),
    #[error("UTF-8 conversion error: {0}")]
    FromUtf8(#[from] std::string::FromUtf8Error),
}

/// Returns all metrics currently registered in Prometheus' default registry.
///
/// Both profiling and RPC metrics register with this default registry, and the
/// metrics API surfaces them by calling this helper.
pub fn gather_default_metrics() -> Result<String, Error> {
    use prometheus::{Encoder, TextEncoder};

    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();

    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer)?;

    let res = String::from_utf8(buffer)?;

    Ok(res)
}
