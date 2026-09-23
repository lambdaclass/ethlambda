mod api;
pub mod backend;
mod beacon_state_delta;
mod error;
mod metrics;
mod state_codec;
mod state_diff;
mod state_writer;
mod store;

pub use api::{ALL_TABLES, StorageBackend, StorageReadView, StorageWriteBatch, Table};
/// Error type returned by the fallible [`Store`] operations, exported so
/// callers can match on it (e.g. to distinguish [`Error::DbVersionMismatch`]).
pub use error::Error;
// `CacheKey` lives in `state_writer` (beside the `StateCache` it keys), not
// `store`; re-exported here so the public path (`ethlambda_storage::CacheKey`)
// is unaffected by which module owns it.
pub use state_writer::CacheKey;
pub use store::{
    Chain, DB_VERSION, ForkCheckpoints, GetForkchoiceStoreError, MAX_RESUMABLE_DB_STATE_AGE,
    NEW_PAYLOAD_CAP, Store,
};
