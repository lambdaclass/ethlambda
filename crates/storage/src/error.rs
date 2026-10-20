use ethlambda_types::checkpoint::Checkpoint;
use ethlambda_types::primitives::H256;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("storage error: {0}")]
    Storage(#[from] crate::api::Error),
    #[error("unexpected missing block header for root {0}")]
    UnexpectedMissingBlockHeader(H256),
    #[error("unexpected missing state for root {0}")]
    UnexpectedMissingState(H256),
    /// The data directory was written by a build with a different on-disk
    /// format. There is no migration: the `States` value layout changed, so
    /// every state already written would decode as the wrong shape.
    ///
    /// `found` is `0` for a directory written before versioning existed.
    #[error(
        "data directory has database version {found}, this build requires {expected}; \
         wipe the data directory and resync"
    )]
    DbVersionMismatch { found: u64, expected: u64 },
    /// The data directory was written by a build compiled against the other
    /// SSZ preset. Every container bound is a compile-time constant, so the
    /// states already written have a different shape than this build would
    /// give them, and their hash tree roots differ too. There is no migration
    /// for the same reason there is none for [`Error::DbVersionMismatch`].
    ///
    /// `found` is `None` for a directory written before the preset was
    /// recorded, or carrying a selector byte this build does not know.
    #[error(
        "data directory was written against the {} preset, this build is {expected}; \
         wipe the data directory or rebuild against that preset",
        .found.unwrap_or("unknown")
    )]
    PresetMismatch {
        found: Option<&'static str>,
        expected: &'static str,
    },
    /// A directory's finalized checkpoint names no root. This is a defensive
    /// guard, not a state either bootstrap path can reach: `init_beacon`
    /// writes the anchor in the same atomic batch as the rest of the
    /// metadata, and `init_store` always anchors at a real block root, so a
    /// crash either leaves no metadata at all (later reads panic in
    /// `get_metadata` rather than returning this) or a fully anchored
    /// directory. Reaching this variant means either a store was built
    /// directly with a zero checkpoint, or the metadata value was corrupted
    /// at rest.
    #[error("data directory has no anchor; wipe it and resync")]
    UnanchoredDirectory,
    /// [`Store::repair_head`](crate::store::Store::repair_head)'s walk, looking
    /// for the newest ancestor of a stale head with a persisted state, went
    /// further back than the writer's queue could ever explain.
    ///
    /// The walk is bounded at `STATE_WRITE_QUEUE_CAPACITY + 1` blocks: the
    /// queue plus the one write the worker thread can be holding. Past that,
    /// this is not an unclean shutdown racing the writer, it is a corrupt
    /// directory.
    #[error(
        "head {start} has no persisted state {hops} blocks back (stalled at {stalled_at}), \
         more than the state writer's queue can explain; the data directory is corrupt: \
         wipe it and resync"
    )]
    HeadRepairExceededWindow {
        start: H256,
        stalled_at: H256,
        hops: usize,
    },
    /// A checkpoint (justified or finalized) names a root this directory has
    /// no state for.
    ///
    /// Unlike a stale head, [`Store::repair_head`](crate::store::Store::repair_head)
    /// never repairs this: justified and finalized are consensus statements,
    /// and inventing an earlier one to paper over a missing state is not
    /// something a storage-layer repair may do. [`Store::verify_anchor_states`](crate::store::Store::verify_anchor_states)
    /// reports it instead, for a resuming caller to treat the same way it
    /// already treats a stale directory: fall back to checkpoint sync if a
    /// URL is configured, or fail naming the remedy below if not.
    #[error(
        "the state for the checkpoint at slot {} (root {}) is missing; wipe the data \
         directory, or configure a checkpoint-sync URL to re-anchor",
        .checkpoint.slot, .checkpoint.root
    )]
    AnchorStateLost { checkpoint: Checkpoint },
}
