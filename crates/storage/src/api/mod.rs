//! Storage backend API.
//!
//! This module defines the traits and types for pluggable storage backends.
//!
//! # Traits
//!
//! - [`StorageBackend`]: Main trait for storage implementations. Creates read views and write batches.
//! - [`StorageReadView`]: Read-only access to storage via `get` and `prefix_iterator`.
//! - [`StorageWriteBatch`]: Batched writes with atomic `commit`.
//!
//! # Tables
//!
//! Storage is organized into [`Table`]s, each storing a different type of data.
//! All keys and values are byte slices (`&[u8]` / `Vec<u8>`).

mod tables;
mod traits;

pub use tables::{ALL_TABLES, Table};
pub use traits::{Error, PrefixResult, StorageBackend, StorageReadView, StorageWriteBatch};
