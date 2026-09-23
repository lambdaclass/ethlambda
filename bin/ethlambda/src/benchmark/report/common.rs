//! Statistics and environment reporting shared by every benchmark workload.
//!
//! Raw per-iteration samples are always included in a workload's JSON report:
//! outliers are never discarded (XMSS signing and OTS window advancement
//! produce legitimate heavy tails worth inspecting), and per-iteration block
//! roots let a baseline-vs-optimized diff prove an optimization changed only
//! speed, not which attestations get selected.

use serde::Serialize;

use crate::version;

/// Coefficient-of-variation threshold above which wall-time results are
/// flagged as too noisy to compare, per the benchmarking workflow standard.
pub(crate) const CV_WARN_THRESHOLD: f64 = 0.10;

#[derive(Debug, Serialize)]
pub(crate) struct Environment {
    pub client_version: &'static str,
    /// Resolved leansig git revision from Cargo.lock. leansig is pinned to a
    /// moving branch, so results are not comparable across revisions.
    pub leansig_rev: &'static str,
    /// Resolved leanVM git revision from Cargo.lock. leanVM does the signature
    /// aggregation, so a rev bump moves the measured crypto too.
    pub leanvm_rev: &'static str,
    pub os: &'static str,
    pub arch: &'static str,
    pub available_parallelism: usize,
}

impl Environment {
    pub(crate) fn collect() -> Self {
        Self {
            client_version: version::CLIENT_VERSION,
            leansig_rev: env!("ETHLAMBDA_LEANSIG_REV"),
            leanvm_rev: env!("ETHLAMBDA_LEANVM_REV"),
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            available_parallelism: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(0),
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct Stats {
    pub count: usize,
    pub min_seconds: f64,
    pub mean_seconds: f64,
    pub p50_seconds: f64,
    pub p90_seconds: f64,
    pub max_seconds: f64,
    /// Coefficient of variation (stddev / mean); NaN-free (0 when mean is 0).
    pub cv: f64,
}

pub(crate) fn format_ms(seconds: f64) -> String {
    format!("{:.3}ms", seconds * 1e3)
}

pub(crate) fn stats(values: &[f64]) -> Stats {
    if values.is_empty() {
        return Stats {
            count: 0,
            min_seconds: 0.0,
            mean_seconds: 0.0,
            p50_seconds: 0.0,
            p90_seconds: 0.0,
            max_seconds: 0.0,
            cv: 0.0,
        };
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));
    let count = sorted.len();
    let mean = sorted.iter().sum::<f64>() / count as f64;
    let variance = sorted
        .iter()
        .map(|value| (value - mean).powi(2))
        .sum::<f64>()
        / count as f64;
    let cv = if mean > 0.0 {
        variance.sqrt() / mean
    } else {
        0.0
    };
    Stats {
        count,
        min_seconds: sorted[0],
        mean_seconds: mean,
        p50_seconds: percentile(&sorted, 0.50),
        p90_seconds: percentile(&sorted, 0.90),
        max_seconds: sorted[count - 1],
        cv,
    }
}

/// Nearest-rank percentile over a sorted slice (no interpolation; sample
/// counts are small so exact sample values are preferable to blends).
fn percentile(sorted: &[f64], q: f64) -> f64 {
    let index = ((sorted.len() - 1) as f64 * q).round() as usize;
    sorted[index]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_handles_single_sample() {
        let sorted = [7.0];
        assert_eq!(percentile(&sorted, 0.0), 7.0);
        assert_eq!(percentile(&sorted, 0.5), 7.0);
        assert_eq!(percentile(&sorted, 1.0), 7.0);
    }

    #[test]
    fn percentile_odd_and_even_lengths() {
        let odd = [1.0, 2.0, 3.0, 4.0, 5.0];
        assert_eq!(percentile(&odd, 0.5), 3.0);
        assert_eq!(percentile(&odd, 1.0), 5.0);
        let even = [1.0, 2.0, 3.0, 4.0];
        assert_eq!(percentile(&even, 0.5), 3.0);
        assert_eq!(percentile(&even, 0.0), 1.0);
    }

    #[test]
    fn stats_on_known_values() {
        let stats = stats(&[2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]);
        assert_eq!(stats.count, 8);
        assert_eq!(stats.min_seconds, 2.0);
        assert_eq!(stats.max_seconds, 9.0);
        assert_eq!(stats.mean_seconds, 5.0);
        // population stddev of this classic set is 2.0 => cv = 0.4
        assert!((stats.cv - 0.4).abs() < 1e-12);
    }

    #[test]
    fn stats_on_empty_input_is_zeroed() {
        let stats = stats(&[]);
        assert_eq!(stats.count, 0);
        assert_eq!(stats.mean_seconds, 0.0);
        assert_eq!(stats.cv, 0.0);
    }
}
