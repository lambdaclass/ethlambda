//! No-op metrics stub for the zkVM guest (`target_os = "zkvm"`), where
//! prometheus is unavailable. Compiled in place of `metrics.rs`
//! every function mirrors its host counterpart but records nothing.

/// Zero-sized stand-in for `ethlambda_metrics::TimingGuard`; records nothing.
pub struct TimingGuard;

pub fn inc_slots_processed(_count: u64) {}
pub fn inc_attestations_processed(_count: u64) {}
pub fn inc_finalizations(_result: &str) {}

pub fn time_state_transition() -> TimingGuard {
    TimingGuard
}
pub fn time_slots_processing() -> TimingGuard {
    TimingGuard
}
pub fn time_block_processing() -> TimingGuard {
    TimingGuard
}
pub fn time_attestations_processing() -> TimingGuard {
    TimingGuard
}
