//! Utilities for gathering and encoding metrics.

use thiserror::Error;

use crate::{Encoder, PrometheusError, TextEncoder, gather};

#[derive(Debug, Error)]
pub enum GatherError {
    #[error("Prometheus error: {0}")]
    Prometheus(#[from] PrometheusError),
    #[error("UTF-8 conversion error: {0}")]
    FromUtf8(#[from] std::string::FromUtf8Error),
}

/// Returns all metrics currently registered in Prometheus' default registry.
///
/// Both profiling and RPC metrics register with this default registry, and the
/// metrics API surfaces them by calling this helper.
pub fn gather_default_metrics() -> Result<String, GatherError> {
    let encoder = TextEncoder::new();
    let metric_families = gather();

    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer)?;

    let res = String::from_utf8(buffer)?;

    Ok(res)
}
