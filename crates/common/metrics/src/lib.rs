//! Metrics utilities and prometheus re-exports for ethlambda.

pub mod gather;
pub mod timing;

// Re-export prometheus types and macros we use
pub use prometheus::{
    Encoder, Error as PrometheusError, Histogram, IntCounter, IntCounterVec, IntGauge, IntGaugeVec,
    TextEncoder, gather, register_histogram, register_int_counter, register_int_counter_vec,
    register_int_gauge, register_int_gauge_vec,
};

// Re-export commonly used items
pub use gather::{GatherError, gather_default_metrics};
pub use timing::TimingGuard;
