//! Timing utilities for histogram metrics.

use std::time::Instant;

use crate::Histogram;

/// A guard that records elapsed time to a histogram when dropped.
///
/// The measurement can be cancelled with [`TimingGuard::discard`], which
/// consumes the guard without recording a sample, for a timed path that turns
/// out to be a no-op whose duration would only skew the histogram (e.g. an
/// idempotent early return).
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

    /// Consume the guard without recording a sample.
    ///
    /// Use when the timed work should not contribute a sample, such as a
    /// duplicate/idempotent request that returns early: the elapsed time is
    /// real but recording it would skew the histogram toward near-zero.
    ///
    /// `TimingGuard` implements [`Drop`], so its fields cannot be moved out to
    /// destructure it directly. Wrapping in [`std::mem::ManuallyDrop`] inhibits
    /// the recording `Drop`; the fields are `Copy`, so they are then read out
    /// and their copies dropped here, leaving nothing to record.
    pub fn discard(self) {
        let guard = std::mem::ManuallyDrop::new(self);
        let _histogram = guard.histogram;
        let _start = guard.start;
    }
}

impl Drop for TimingGuard {
    fn drop(&mut self) {
        self.histogram.observe(self.start.elapsed().as_secs_f64());
    }
}
