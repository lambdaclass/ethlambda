use axum::{Router, http::HeaderValue, http::header, response::IntoResponse, routing::get};
use ethlambda_metrics::{
    Histogram, HistogramVec, IntCounterVec, gather_default_metrics, register_histogram,
    register_histogram_vec, register_int_counter_vec,
};
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

/// Record one builder API call: which call, how it ended, and how long it
/// took. `getHeader` runs against the proposal's deadline, so its tail
/// matters as much as its failures.
pub(crate) fn observe_builder_request(call: &str, outcome: &str, elapsed: Duration) {
    static LEAN_BEACON_BUILDER_REQUEST_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
        register_histogram_vec!(
            "lean_beacon_builder_request_seconds",
            "Time a builder API call took, by call and outcome",
            &["call", "outcome"],
            vec![0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 0.75, 1.0, 2.0, 5.0, 10.0]
        )
        .unwrap()
    });
    LEAN_BEACON_BUILDER_REQUEST_SECONDS
        .with_label_values(&[call, outcome])
        .observe(elapsed.as_secs_f64());
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

/// Count `register_validator` entries by what became of them: forwarded to
/// the builder, failed at it, or dropped here as an unknown or exited
/// validator.
pub(crate) fn inc_builder_registrations(outcome: &str, count: u64) {
    static LEAN_BEACON_BUILDER_REGISTRATIONS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
        register_int_counter_vec!(
            "lean_beacon_builder_registrations_total",
            "Validator registrations received, by what became of them",
            &["outcome"]
        )
        .unwrap()
    });
    LEAN_BEACON_BUILDER_REGISTRATIONS_TOTAL
        .with_label_values(&[outcome])
        .inc_by(count);
}

/// Count builder bids refused before selection, by reason.
pub(crate) fn inc_bid_rejection(reason: &str) {
    static LEAN_BEACON_BUILDER_BID_REJECTIONS_TOTAL: LazyLock<IntCounterVec> =
        LazyLock::new(|| {
            register_int_counter_vec!(
                "lean_beacon_builder_bid_rejections_total",
                "Builder bids refused before selection, by reason",
                &["reason"]
            )
            .unwrap()
        });
    LEAN_BEACON_BUILDER_BID_REJECTIONS_TOTAL
        .with_label_values(&[reason])
        .inc();
}

/// Count blocks produced with a builder configured, by where the payload
/// came from.
pub(crate) fn inc_payload_source(source: &str) {
    static LEAN_BEACON_BUILDER_PAYLOAD_SOURCE_TOTAL: LazyLock<IntCounterVec> =
        LazyLock::new(|| {
            register_int_counter_vec!(
                "lean_beacon_builder_payload_source_total",
                "Blocks produced with a builder configured, by where the payload came from",
                &["source"]
            )
            .unwrap()
        });
    LEAN_BEACON_BUILDER_PAYLOAD_SOURCE_TOTAL
        .with_label_values(&[source])
        .inc();
}

/// Count proposals the circuit breaker kept from the builder, by reason.
pub(crate) fn inc_builder_fallback(reason: &str) {
    static LEAN_BEACON_BUILDER_FALLBACK_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
        register_int_counter_vec!(
            "lean_beacon_builder_fallback_total",
            "Proposals the circuit breaker kept from the builder, by reason",
            &["reason"]
        )
        .unwrap()
    });
    LEAN_BEACON_BUILDER_FALLBACK_TOTAL
        .with_label_values(&[reason])
        .inc();
}
