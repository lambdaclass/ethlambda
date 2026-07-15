//! Timing utilities for histogram metrics.

use std::time::Instant;

use crate::Histogram;

/// A guard that records elapsed time to a histogram when dropped.
///
/// The measurement can be cancelled with [`TimingGuard::discard`] before the
/// guard drops, for a timed path that turns out to be a no-op whose duration
/// would only skew the histogram (e.g. an idempotent early return).
pub struct TimingGuard {
    histogram: &'static Histogram,
    start: Instant,
    /// When `true`, [`Drop`] does not record the elapsed time.
    disarmed: bool,
}

impl TimingGuard {
    pub fn new(histogram: &'static Histogram) -> Self {
        Self {
            histogram,
            start: Instant::now(),
            disarmed: false,
        }
    }

    /// Discard the measurement so no sample is recorded when the guard drops.
    ///
    /// Use when the timed work should not contribute a sample, such as a
    /// duplicate/idempotent request that returns early: the elapsed time is
    /// real but recording it would skew the histogram toward near-zero.
    pub fn discard(&mut self) {
        self.disarmed = true;
    }
}

impl Drop for TimingGuard {
    fn drop(&mut self) {
        if !self.disarmed {
            self.histogram.observe(self.start.elapsed().as_secs_f64());
        }
    }
}

#[cfg(test)]
mod tests {
    use prometheus::{Histogram, HistogramOpts};

    use super::TimingGuard;

    /// Build a histogram that is not registered with any registry — enough to
    /// observe samples and read `get_sample_count` without global state.
    fn unregistered_histogram() -> &'static Histogram {
        let opts = HistogramOpts::new("test_timing_guard", "test-only histogram");
        let histogram = Histogram::with_opts(opts).expect("valid histogram opts");
        Box::leak(Box::new(histogram))
    }

    #[test]
    fn records_a_sample_on_drop() {
        let histogram = unregistered_histogram();
        assert_eq!(histogram.get_sample_count(), 0);
        drop(TimingGuard::new(histogram));
        assert_eq!(histogram.get_sample_count(), 1);
    }

    #[test]
    fn discard_suppresses_the_sample() {
        let histogram = unregistered_histogram();
        {
            let mut guard = TimingGuard::new(histogram);
            guard.discard();
        }
        assert_eq!(histogram.get_sample_count(), 0);
    }
}
