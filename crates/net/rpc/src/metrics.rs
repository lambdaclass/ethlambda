use axum::{Router, http::HeaderValue, http::header, response::IntoResponse, routing::get};
use ethlambda_metrics::{Histogram, gather_default_metrics, register_histogram};
use std::{sync::LazyLock, time::Duration};
use tracing::warn;

/// Record the time a published block's cells and proofs took to compute and
/// verify, and its data column sidecars to build. At mainnet's blob cap that
/// is thousands of cells, on the proposal's critical path.
pub(crate) fn observe_publish_data_columns(elapsed: Duration) {
    static LEAN_BEACON_PUBLISH_DATA_COLUMNS_SECONDS: LazyLock<Histogram> = LazyLock::new(|| {
        register_histogram!(
            "lean_beacon_publish_data_columns_seconds",
            "Time to compute and verify a published block's cells and build its data column sidecars",
            vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5]
        )
        .unwrap()
    });
    LEAN_BEACON_PUBLISH_DATA_COLUMNS_SECONDS.observe(elapsed.as_secs_f64());
}

pub fn start_prometheus_metrics_api() -> Router {
    Router::new()
        .route("/metrics", get(get_metrics))
        .route("/health", get(get_health))
}

pub(crate) async fn get_health() -> impl IntoResponse {
    let mut response = r#"{"status":"healthy","service":"lean-rpc-api"}"#.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(crate::JSON_CONTENT_TYPE),
    );
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
