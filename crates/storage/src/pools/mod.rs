//! The beacon pools a [`crate::Store`] owns and shares across its clones.
//! In memory only: nothing here is persisted, and a restart empties them.

mod attestation;
mod operation;
mod pq_aggregate;

pub use attestation::{AttestationPool, single_committee};
pub use operation::OperationPool;
pub use pq_aggregate::{PooledPqAggregate, PqAggregatePool};
