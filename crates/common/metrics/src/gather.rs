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

/// The value of one series in the default registry, named as the text
/// exposition spells it: the metric's name, then its labels in alphabetical
/// order, as in `requests_total{method="get",outcome="ok"}`. A histogram's
/// are its `_count`, `_sum` and `_bucket` series. `None` for a series nothing
/// has recorded yet.
///
/// For tests that check a code path left its metrics behind: the registry is
/// the process's, so a test reads what it recorded under labels of its own,
/// or compares a reading before with one after.
pub fn series_value(series: &str) -> Option<f64> {
    let metrics = gather_default_metrics().ok()?;
    metrics.lines().find_map(|line| {
        line.strip_prefix(series)?
            .strip_prefix(' ')?
            .trim()
            .parse()
            .ok()
    })
}

#[cfg(test)]
mod series_tests {
    use super::*;
    use crate::{register_histogram_vec, register_int_counter_vec};

    #[test]
    fn a_series_is_read_by_its_exposition_name() {
        let counter = register_int_counter_vec!(
            "series_value_test_total",
            "A counter for series_value's test",
            &["outcome", "kind"]
        )
        .unwrap();
        counter.with_label_values(&["ok", "a"]).inc_by(3);
        let read = series_value(r#"series_value_test_total{kind="a",outcome="ok"}"#);
        assert_eq!(read, Some(3.0));
        // Another label set, and a name this one is only a prefix of.
        assert_eq!(
            series_value(r#"series_value_test_total{kind="b",outcome="ok"}"#),
            None
        );
        assert_eq!(series_value("series_value_test"), None);

        let histogram = register_histogram_vec!(
            "series_value_test_seconds",
            "A histogram for series_value's test",
            &["kind"],
            vec![1.0, 2.0]
        )
        .unwrap();
        histogram.with_label_values(&["a"]).observe(1.5);
        let count = series_value(r#"series_value_test_seconds_count{kind="a"}"#);
        let sum = series_value(r#"series_value_test_seconds_sum{kind="a"}"#);
        assert_eq!((count, sum), (Some(1.0), Some(1.5)));
    }
}

/// The process collector comes from the `prometheus` crate's `process`
/// feature, which registers it with the default registry on Linux only.
/// Dashboards read the node's memory from it, so dropping the feature would
/// leave them blank without any build failing.
#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn the_default_registry_serves_the_process_metrics() {
        let metrics = gather_default_metrics().unwrap();
        assert!(
            metrics.contains("process_resident_memory_bytes"),
            "{metrics}"
        );
    }
}
