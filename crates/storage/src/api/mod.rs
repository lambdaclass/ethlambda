#![allow(dead_code, unused_imports)] // Infrastructure not yet integrated with Store

mod tables;
mod traits;

pub use tables::{Table, ALL_TABLES};
pub use traits::{Error, PrefixResult, StorageBackend, StorageReadView, StorageWriteBatch};
