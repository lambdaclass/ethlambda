//! The beacon pools a [`crate::Store`] owns and shares across its clones.
//! In memory only: nothing here is persisted, and a restart empties them.

mod attestation;
mod inclusion_list;
mod operation;

pub use attestation::{AttestationPool, single_committee};
pub use inclusion_list::{InclusionListEntry, InclusionListStore, RETENTION_SLOTS};
pub use operation::OperationPool;
