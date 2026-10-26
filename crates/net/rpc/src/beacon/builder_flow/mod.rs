//! The fulu builder flow's decisions: which proposers use the builder, when
//! the chain is too unhealthy to, whether a bid is acceptable, and which
//! payload goes into the block.

pub(crate) mod bid;
pub(crate) mod breaker;
pub(crate) mod cache;
