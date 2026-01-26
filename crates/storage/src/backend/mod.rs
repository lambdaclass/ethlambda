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
#[cfg(feature = "rocksdb")]
mod rocksdb;

pub use in_memory::InMemoryBackend;
#[cfg(feature = "rocksdb")]
#[allow(unused_imports)] // RocksDBBackend is not yet connected to Store
pub use rocksdb::RocksDBBackend;
