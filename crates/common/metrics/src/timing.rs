//! Timing utilities for histogram metrics.

use std::time::Instant;

use crate::Histogram;

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
