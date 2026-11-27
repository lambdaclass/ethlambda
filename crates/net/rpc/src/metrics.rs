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

/// One PQ committee proof this node made for an aggregator seat.
pub(crate) struct PqCommitteeProof {
    /// How long leanVM took, which includes any wait for a proof it was
    /// already making: it makes one at a time.
    pub proving: Duration,
    /// How far into the proof's slot it was ready.
    pub ready_offset: Duration,
    pub signatures: usize,
    pub proof_bytes: usize,
}

/// Record a PQ committee proof made for the aggregator seat at `position`,
/// whether it was ready before that seat's broadcast time or not.
///
/// The ready-offset bounds are a 12-second slot's seat cutoffs (4.8, 5.4, 6.0
/// and 6.6 s) and broadcast times (7.2, 7.8, 8.4 and 9.0 s), with some
/// between and below for a shorter slot.
pub(crate) fn observe_pq_committee_proof(position: u64, proof: &PqCommitteeProof) {
    static LEAN_BEACON_PQ_COMMITTEE_PROOF_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
        register_histogram_vec!(
            "lean_beacon_pq_committee_proof_seconds",
            "Time leanVM took to prove one committee's PQ aggregate, by aggregator seat",
            &["position"],
            vec![
                0.05, 0.1, 0.2, 0.3, 0.4, 0.6, 0.8, 1.0, 1.2, 1.6, 2.0, 2.4, 3.2, 4.8, 8.0
            ]
        )
        .unwrap()
    });
    static LEAN_BEACON_PQ_COMMITTEE_PROOF_READY_OFFSET_SECONDS: LazyLock<HistogramVec> =
        LazyLock::new(|| {
            register_histogram_vec!(
                "lean_beacon_pq_committee_proof_ready_offset_seconds",
                "How far into its slot a committee's PQ aggregate proof was ready, by aggregator seat",
                &["position"],
                vec![
                    1.0, 2.0, 2.4, 3.0, 3.6, 4.2, 4.8, 5.1, 5.4, 5.7, 6.0, 6.3, 6.6, 6.9, 7.2, 7.8,
                    8.4, 9.0, 10.0, 12.0
                ]
            )
            .unwrap()
        });
    static LEAN_BEACON_PQ_COMMITTEE_PROOF_SIGNATURES: LazyLock<Histogram> = LazyLock::new(|| {
        register_histogram!(
            "lean_beacon_pq_committee_proof_signatures",
            "Signatures one committee's PQ aggregate proof proves",
            vec![
                1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0, 512.0, 1024.0, 2048.0, 4096.0
            ]
        )
        .unwrap()
    });
    static LEAN_BEACON_PQ_COMMITTEE_PROOF_SIZE_BYTES: LazyLock<Histogram> = LazyLock::new(|| {
        register_histogram!(
            "lean_beacon_pq_committee_proof_size_bytes",
            "Bytes size of one committee's PQ aggregate proof",
            pq_proof_size_buckets()
        )
        .unwrap()
    });
    let position = position.to_string();
    LEAN_BEACON_PQ_COMMITTEE_PROOF_SECONDS
        .with_label_values(&[&position])
        .observe(proof.proving.as_secs_f64());
    LEAN_BEACON_PQ_COMMITTEE_PROOF_READY_OFFSET_SECONDS
        .with_label_values(&[&position])
        .observe(proof.ready_offset.as_secs_f64());
    LEAN_BEACON_PQ_COMMITTEE_PROOF_SIGNATURES.observe(proof.signatures as f64);
    LEAN_BEACON_PQ_COMMITTEE_PROOF_SIZE_BYTES.observe(proof.proof_bytes as f64);
}

/// Bounds for a committee proof's size, up to `MAX_STARK_PROOF_SIZE` (1 MiB):
/// 32 KiB apart where committee proofs fall, 160 to 200 KB.
fn pq_proof_size_buckets() -> Vec<f64> {
    vec![
        131072.0, 163840.0, 196608.0, 229376.0, 262144.0, 327680.0, 393216.0, 524288.0, 786432.0,
        1048576.0,
    ]
}

/// Count `count` committees the aggregator seat at `position` was due to
/// prove, by what became of them: `proved` before the seat's broadcast time,
/// `late` (proved after it, and not used), `failed`, `already_proven` (an
/// earlier seat of this node proved every vote collected) or `unproved` (the
/// seat's time ran out first).
pub(crate) fn inc_pq_committee_proofs(position: u64, outcome: &str, count: u64) {
    static LEAN_BEACON_PQ_COMMITTEE_PROOFS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
        register_int_counter_vec!(
            "lean_beacon_pq_committee_proofs_total",
            "Committees an aggregator seat of this node was due to prove, by seat and outcome",
            &["position", "outcome"]
        )
        .unwrap()
    });
    LEAN_BEACON_PQ_COMMITTEE_PROOFS_TOTAL
        .with_label_values(&[&position.to_string(), outcome])
        .inc_by(count);
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
/// the builder, failed at it, dropped here as an unknown or exited validator,
/// or superseded by a newer registration of the same validator in the same
/// request (`duplicate`).
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
