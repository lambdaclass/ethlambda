use ethlambda_storage::Store;
use ethlambda_types::checkpoint::Checkpoint;

use super::Status;

/// Build a Status message from the current Store state.
pub fn build_status(store: &Store) -> Status {
    let finalized = store.latest_finalized();
    let head_root = store.head();
    let head_slot = store
        .get_block_header(&head_root)
        .expect("head block exists")
        .slot;
    Status {
        finalized,
        head: Checkpoint {
            root: head_root,
            slot: head_slot,
        },
    }
}
