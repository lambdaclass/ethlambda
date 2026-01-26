//! Storage backend implementations.
//!
//! This module provides concrete implementations of the [`crate::api::StorageBackend`] trait.
//!
//! # Backends
//!
//! - [`InMemoryBackend`]: Thread-safe in-memory storage using `RwLock<HashMap>`.
//!   Suitable for testing and ephemeral nodes. Data is lost on restart.

mod in_memory;

pub use in_memory::InMemoryBackend;
