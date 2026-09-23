//! Benchmark reports.
//!
//! Split by workload rather than by a tagged enum: `Report::new` builds its
//! summary from closures over fields that exist on one workload only, and
//! `human_table` reads params the other does not have, so a shared type would
//! share a name and nothing else. What is genuinely shared lives in
//! [`common`].

pub(crate) mod common;
pub(crate) mod import;
pub(crate) mod synthetic;
