//! The fulu builder flow's decisions: which proposers use the builder, when
//! the chain is too unhealthy to, whether a bid is acceptable, and which
//! payload goes into the block.

pub(crate) mod bid;
pub(crate) mod breaker;
pub(crate) mod cache;
pub(crate) mod choice;

use ethlambda_blockchain::SyncStatusController;

use super::builder_client::BuilderClient;
use breaker::FallbackThresholds;
use cache::BuilderRegistrations;

/// What the builder flow's handlers share. It is layered only when
/// `--builder` is set, so a handler reads it as
/// `Option<Extension<Arc<Builder>>>`. A node without a builder, or a test
/// router that never layers it, takes the local path.
pub(crate) struct Builder {
    pub(crate) client: BuilderClient,
    pub(crate) registrations: BuilderRegistrations,
    pub(crate) fallback: FallbackThresholds,
    /// The node's sync status, which the circuit breaker reads.
    pub(crate) sync_status: SyncStatusController,
}

impl Builder {
    pub(crate) fn new(
        client: BuilderClient,
        fallback: FallbackThresholds,
        sync_status: SyncStatusController,
    ) -> Self {
        Self {
            client,
            registrations: BuilderRegistrations::default(),
            fallback,
            sync_status,
        }
    }
}
