//! Storage backend implementations.
//!
//! This module provides concrete implementations of the [`crate::api::StorageBackend`] trait.
//!
//! # Backends
//!
//! - [`InMemoryBackend`]: Thread-safe in-memory storage using `RwLock<HashMap>`.
//!   Suitable for testing and ephemeral nodes. Data is lost on restart.
//!
//! - [`RocksDBBackend`] (requires `rocksdb` feature): Persistent storage using RocksDB.
//!   Suitable for production nodes.

mod in_memory;
mod rocksdb;
#[cfg(test)]
mod tests;

pub use in_memory::InMemoryBackend;
pub use rocksdb::RocksDBBackend;
