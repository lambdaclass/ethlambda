//! The chain configuration behind the slot clock and every signing domain,
//! held once and swappable while the client runs.
//!
//! Both used to copy the [`Config`] they were built with, which fixed the fork
//! schedule at startup: a fork the network scheduled afterwards never reached
//! the client. They now hold one [`SharedConfig`] between them, so a single
//! [`SharedConfig::store`] moves the duty offsets and every signing domain
//! together.

use std::sync::{Arc, PoisonError, RwLock};

use ethlambda_types::beacon::config::Config;

/// A handle to the current [`Config`]. Clones share it.
///
/// The lock only guards swapping one `Arc`, so a reader takes a snapshot with
/// [`Self::load`] and releases the lock at once. A snapshot is never held
/// across an await by this type, and a caller that works from one sees a
/// single schedule for as long as it keeps it, even if a swap lands meanwhile.
#[derive(Debug, Clone)]
pub struct SharedConfig(Arc<RwLock<Arc<Config>>>);

impl SharedConfig {
    pub fn new(config: Config) -> Self {
        Self(Arc::new(RwLock::new(Arc::new(config))))
    }

    /// The configuration as of now. Cheap: a lock taken for one `Arc` clone.
    pub fn load(&self) -> Arc<Config> {
        // A poisoned lock still holds a whole `Arc`: nothing here panics with
        // the lock held halfway through an update, so the value is sound.
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Replace the configuration every holder of this handle reads.
    ///
    /// Callers that keep state derived from the old schedule go through
    /// `SigningContext::replace_config`, which clears it too.
    pub fn store(&self, config: Config) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(config);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_types::beacon::fork::ForkName;

    #[test]
    fn a_store_is_seen_through_every_clone_and_not_through_old_snapshots() {
        let shared = SharedConfig::new(Config::mainnet());
        let clone = shared.clone();
        let before = shared.load();

        clone.store(Config::mainnet().with_fork_epoch(ForkName::Gloas, 7));

        assert_eq!(shared.load().fork_epoch(ForkName::Gloas), 7);
        assert_ne!(
            before.fork_epoch(ForkName::Gloas),
            7,
            "a snapshot taken before the swap keeps the schedule it saw"
        );
    }
}
