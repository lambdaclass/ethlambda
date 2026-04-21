use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Shared, runtime-mutable aggregator role flag.
#[derive(Clone, Debug)]
pub struct AggregatorController {
    flag: Arc<AtomicBool>,
}

impl AggregatorController {
    /// Construct a controller seeded with the CLI `--is-aggregator` value.
    pub fn new(initial: bool) -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(initial)),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.flag.load(Ordering::Relaxed)
    }

    /// Update the role and return the previous value.
    pub fn set_enabled(&self, enabled: bool) -> bool {
        self.flag.swap(enabled, Ordering::Relaxed)
    }
}
