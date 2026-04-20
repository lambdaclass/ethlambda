//! Runtime-toggleable aggregator role.
//!
//! Tracks whether this node should act as a committee aggregator. Shared
//! between the blockchain actor (reads on every tick and gossip attestation)
//! and the admin API (writes when operators rotate duties). A thin wrapper
//! around [`Arc<AtomicBool>`] so reads stay cheap and writes stay atomic.
//!
//! Mirrors leanSpec's `AggregatorController` (PR #636) with the Rust analogue
//! of its asyncio lock: a single atomic cell. One flag is enough because
//! ethlambda's P2P swarm only reads `is_aggregator` at construction time;
//! runtime toggles do not (and cannot) resubscribe gossip subnets.
//!
//! # Invariants
//!
//! - The flag carries no dependent data; loads and stores use `Relaxed`.
//! - Metric updates live in the blockchain actor so the gauge reflects what
//!   the actor acted on rather than what was requested.
//! - If a P2P runtime reader is ever added, it must consult this controller
//!   instead of a stored bool. See `crates/net/p2p/src/lib.rs` `SwarmConfig`.

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
