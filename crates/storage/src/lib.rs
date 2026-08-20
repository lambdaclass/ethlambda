mod api;
pub mod backend;
mod beacon_store;
mod error;
mod state_diff;
mod store;

pub use api::{ALL_TABLES, StorageBackend, StorageReadView, StorageWriteBatch, Table};
pub use beacon_store::BeaconBlockIndex;
/// Error type returned by the fallible [`Store`] operations, exported so
/// callers can match on it (e.g. to distinguish [`Error::GenesisMismatch`]).
pub use error::Error;
pub use store::{
    BEACON_PINNED_STATE_CAPACITY, Chain, DB_VERSION, ForkCheckpoints, GetForkchoiceStoreError,
    MAX_RESUMABLE_DB_STATE_AGE, Store,
};
