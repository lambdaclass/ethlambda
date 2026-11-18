//! Storage backend implementations.
//!
//! This module provides concrete implementations of the [`crate::api::StorageBackend`] trait.
//!
//! # Backends
//!
//! - [`InMemoryBackend`]: Thread-safe in-memory storage using `RwLock<HashMap>`.
//!   Suitable for testing and ephemeral nodes. Data is lost on restart.
//!
//! - `RocksDBBackend` (requires the `rocksdb` feature): Persistent storage using RocksDB.
//!   Suitable for production nodes. (Not a link: without the feature the type does not
//!   exist, so the link would not resolve.)

mod in_memory;
#[cfg(feature = "rocksdb")]
mod rocksdb;
#[cfg(test)]
mod tests;

pub use in_memory::InMemoryBackend;
#[cfg(feature = "rocksdb")]
pub use rocksdb::RocksDBBackend;
