mod api;
pub mod backend;
mod beacon_state_delta;
mod error;
mod state_diff;
mod store;

pub use api::{ALL_TABLES, StorageBackend, StorageReadView, StorageWriteBatch, Table};
/// Error type returned by the fallible [`Store`] operations, exported so
/// callers can match on it (e.g. to distinguish [`Error::GenesisMismatch`]).
pub use error::Error;
pub use store::{
    CacheKey, Chain, DB_VERSION, ForkCheckpoints, GetForkchoiceStoreError,
    MAX_RESUMABLE_DB_STATE_AGE, NEW_PAYLOAD_CAP, Store,
};
