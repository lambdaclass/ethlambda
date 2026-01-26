//! Metrics utilities and prometheus re-exports for ethlambda.

use std::time::Instant;

// Re-export prometheus types and macros we use
pub use prometheus::{
    Histogram, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, register_histogram,
    register_int_counter, register_int_counter_vec, register_int_gauge, register_int_gauge_vec,
};

/// A guard that records elapsed time to a histogram when dropped.
pub struct TimingGuard {
    histogram: &'static Histogram,
    start: Instant,
}

impl TimingGuard {
    pub fn new(histogram: &'static Histogram) -> Self {
        Self {
            histogram,
            start: Instant::now(),
        }
    }
}

impl Drop for TimingGuard {
    fn drop(&mut self) {
        self.histogram.observe(self.start.elapsed().as_secs_f64());
    }
}
