//! One run at a time for work spawned off the slot loop.
//!
//! The slot loop spawns its sends to beacon nodes rather than awaiting them, so
//! a slow node cannot delay the next slot's duties. The cost is that nothing
//! stops a new run starting while the last one still waits on that node. Each
//! run holds its own copy of the work and sends it again, so the runs pile up
//! for as long as the node stays slow. A run that finds the previous one still
//! going skips instead, as Teku's registration round does.

use std::sync::atomic::{AtomicBool, Ordering};

/// Whether a run is going.
#[derive(Debug, Default)]
pub(crate) struct InFlight(AtomicBool);

impl InFlight {
    /// The guard for a new run, or `None` when one is already going.
    pub(crate) fn enter(&self) -> Option<InFlightGuard<'_>> {
        let running = self.0.swap(true, Ordering::AcqRel);
        // The guard is built only for a run that starts: `then_some` would
        // build it either way and drop it on the refused path, and dropping
        // it clears the flag of the run that is still going.
        if running {
            None
        } else {
            Some(InFlightGuard(&self.0))
        }
    }
}

/// Ends the run on every exit from it, a panic included, so one failed run
/// cannot stop every later one.
pub(crate) struct InFlightGuard<'a>(&'a AtomicBool);

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_run_is_refused_until_the_first_ends() {
        let in_flight = InFlight::default();
        let first = in_flight.enter().expect("nothing is running");
        assert!(in_flight.enter().is_none());
        assert!(
            in_flight.enter().is_none(),
            "a refused run leaves the running one's flag set"
        );
        drop(first);
        assert!(in_flight.enter().is_some());
    }

    #[test]
    fn a_run_that_panics_still_ends() {
        let in_flight = InFlight::default();
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _run = in_flight.enter().expect("nothing is running");
            panic!("the run fails");
        }));
        assert!(unwound.is_err());
        assert!(in_flight.enter().is_some());
    }
}
