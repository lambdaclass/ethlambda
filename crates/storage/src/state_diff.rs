//! Parent-linked state diffs for diff-layer state storage.
//!
//! A [`StateDiff`] captures the change from a base state (the parent block's
//! post-state) to a target state, storing only what cannot be recovered from a
//! snapshot plus the parent relationship.
//!
//! Field handling:
//! - `config`, `validators`: never change; omitted (taken from the snapshot).
//! - `latest_block_header`: omitted; reconstructed from the `BlockHeaders` table.
//! - `historical_block_hashes`: pure-append in the STF, so only the appended
//!   tail (`hbh_appended`) is stored.
//! - everything else: stored verbatim (the justification fields are bounded by
//!   the non-finalized window, so they stay small under healthy finality).

use ethlambda_types::{
    block::BlockHeader,
    checkpoint::Checkpoint,
    primitives::H256,
    state::{
        HISTORICAL_ROOTS_LIMIT, JustificationRoots, JustificationValidators, JustifiedSlots, State,
    },
};
use libssz_derive::{SszDecode, SszEncode};
use libssz_types::SszList;

/// Appended tail of `historical_block_hashes`, bounded by the same limit as the
/// full list.
pub type HistoricalBlockHashesTail = SszList<H256, HISTORICAL_ROOTS_LIMIT>;

/// Describes the parent state a new state's diff is built against.
///
/// Captured by the caller before the parent is consumed into the post-state, so
/// the store can build the diff and decide anchoring without re-reading it.
/// Construct via [`DiffBase::from_state`]; fields are crate-internal.
pub struct DiffBase {
    /// Block root of the parent state (the diff's `base_root`).
    pub(crate) root: H256,
    /// Parent state's `historical_block_hashes` length.
    pub(crate) hbh_len: usize,
    /// Parent state's slot (used for the anchor-boundary check).
    pub(crate) slot: u64,
}

impl DiffBase {
    /// Build the diff base from the parent state and its block root.
    ///
    /// `root` is the parent block root (the child's `parent_root`), passed in
    /// since the caller already has it; `hbh_len` and `slot` are read from
    /// `state`. Call this before the parent is consumed into the child.
    pub fn from_state(root: H256, state: &State) -> Self {
        Self {
            root,
            hbh_len: state.historical_block_hashes.len(),
            slot: state.slot,
        }
    }
}

/// The change from a base (parent) state to a target state.
///
/// Reconstruct the target with [`StateDiff`] applied against the nearest
/// ancestor snapshot; see the storage layer's `get_state` for the walk.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode)]
pub struct StateDiff {
    /// Block root of the base state this diff is relative to (`block.parent_root`).
    pub base_root: H256,
    /// Target state's slot.
    pub slot: u64,
    /// Target state's latest justified checkpoint.
    pub latest_justified: Checkpoint,
    /// Target state's latest finalized checkpoint.
    pub latest_finalized: Checkpoint,
    /// Target state's `justified_slots` (stored in full).
    pub justified_slots: JustifiedSlots,
    /// Target state's `justifications_roots` (stored in full).
    pub justifications_roots: JustificationRoots,
    /// Target state's `justifications_validators` (stored in full).
    pub justifications_validators: JustificationValidators,
    /// Elements appended to `historical_block_hashes` relative to the base.
    pub hbh_appended: HistoricalBlockHashesTail,
}

impl StateDiff {
    /// Build a diff from a consumed target state against a base identified by its
    /// `historical_block_hashes` length.
    ///
    /// Takes `target` by value so the multi-MB justification fields are moved
    /// into the diff rather than cloned. On the block-import path the base state
    /// has already been consumed into `target`, so only its length is retained;
    /// `base_hbh_len` is that length.
    ///
    /// # Assumptions about how the base is modified into the target
    ///
    /// The diff stores only part of `target` and is lossless *only* because the
    /// state transition changes the base (parent) state in a restricted way.
    /// `reconstruct` depends on each of these; a future STF that broke one would
    /// make reconstructed states silently wrong, not just fail:
    ///
    /// - **`config` and `validators` are unchanged from base to target.** They
    ///   are not stored in the diff; reconstruction takes them from the nearest
    ///   ancestor snapshot. (The lean STF never mutates either: `validators` is
    ///   fixed at genesis and `config` is static.)
    /// - **`historical_block_hashes` only grows by appending.** The base's list
    ///   is a prefix of the target's, so only the appended tail
    ///   (`target[base_hbh_len..]`) is stored and the earlier entries are never
    ///   reordered or rewritten. (`process_slots` pushes the parent root and
    ///   zero-fills skipped slots, leaving the existing prefix intact.) This is
    ///   why `base_hbh_len` alone is enough to identify the base's contribution.
    /// - **`latest_block_header` is not stored here.** It is read back from the
    ///   `BlockHeaders` table during reconstruction; the persisted post-state
    ///   caches the real `state_root` there, so the two are byte-identical.
    ///
    /// All remaining fields (`slot`, both checkpoints, and the three
    /// justification fields) are captured verbatim, so the diff makes no
    /// assumption about how those change.
    ///
    /// # Panics
    ///
    /// Panics if `target.historical_block_hashes` is shorter than `base_hbh_len`,
    /// i.e. the append-only assumption above was violated.
    pub fn from_base(base_root: H256, base_hbh_len: usize, target: State) -> Self {
        let State {
            slot,
            latest_justified,
            latest_finalized,
            historical_block_hashes,
            justified_slots,
            justifications_roots,
            justifications_validators,
            ..
        } = target;

        let hbh = historical_block_hashes.into_inner();
        assert!(
            hbh.len() >= base_hbh_len,
            "target historical_block_hashes shorter than base: {} < {base_hbh_len}",
            hbh.len()
        );
        let hbh_appended = HistoricalBlockHashesTail::try_from(hbh[base_hbh_len..].to_vec())
            .expect("appended tail cannot exceed HISTORICAL_ROOTS_LIMIT");

        Self {
            base_root,
            slot,
            latest_justified,
            latest_finalized,
            justified_slots,
            justifications_roots,
            justifications_validators,
            hbh_appended,
        }
    }
}

/// Rebuild a state from a base snapshot and the diffs leading to the target.
///
/// `diffs` are ordered from the snapshot's child up to the target (inclusive,
/// non-empty). `latest_block_header` is the target's header (kept in the
/// `BlockHeaders` table rather than the diff). `config`/`validators` come from
/// `snapshot` (they never change), `historical_block_hashes` is replayed from
/// the appended tails, and the remaining fields come from the last diff.
///
/// # Panics
///
/// Panics if `diffs` is empty.
pub(crate) fn reconstruct(
    snapshot: State,
    diffs: &[StateDiff],
    latest_block_header: BlockHeader,
) -> State {
    let target = diffs
        .last()
        .expect("reconstruct requires at least one diff");

    let mut hbh: Vec<H256> = snapshot.historical_block_hashes.to_vec();
    for diff in diffs {
        hbh.extend_from_slice(&diff.hbh_appended);
    }
    let historical_block_hashes = hbh
        .try_into()
        .expect("reconstructed historical_block_hashes within limit");

    State {
        config: snapshot.config,
        slot: target.slot,
        latest_block_header,
        latest_justified: target.latest_justified,
        latest_finalized: target.latest_finalized,
        historical_block_hashes,
        justified_slots: target.justified_slots.clone(),
        validators: snapshot.validators,
        justifications_roots: target.justifications_roots.clone(),
        justifications_validators: target.justifications_validators.clone(),
    }
}

#[cfg(test)]
mod tests {
    use ethlambda_types::state::{State, Validator};
    use libssz::{SszDecode, SszEncode};

    use super::*;

    fn h256(byte: u8) -> H256 {
        H256::from([byte; 32])
    }

    /// A minimal genesis-like base state with two validators.
    fn base_state() -> State {
        let validators = vec![
            Validator {
                attestation_pubkey: [1u8; 52],
                proposal_pubkey: [2u8; 52],
                index: 0,
            },
            Validator {
                attestation_pubkey: [3u8; 52],
                proposal_pubkey: [4u8; 52],
                index: 1,
            },
        ];
        State::from_genesis(1_000, validators)
    }

    #[test]
    fn from_base_captures_appended_tail_and_absolute_fields() {
        let base = base_state();
        let base_len = base.historical_block_hashes.len();

        let mut target = base.clone();
        target.slot = 5;
        let expected_justified = Checkpoint {
            root: h256(7),
            slot: 4,
        };
        target.latest_justified = expected_justified;
        // Append three roots (one real parent + two zero-filled empty slots).
        let mut hbh: Vec<H256> = base.historical_block_hashes.to_vec();
        hbh.extend([h256(9), H256::ZERO, H256::ZERO]);
        target.historical_block_hashes = hbh.try_into().unwrap();

        let diff = StateDiff::from_base(h256(1), base_len, target);

        assert_eq!(diff.base_root, h256(1));
        assert_eq!(diff.slot, 5);
        assert_eq!(diff.latest_justified, expected_justified);
        assert_eq!(diff.hbh_appended.len(), 3);
        assert_eq!(diff.hbh_appended[0], h256(9));
        assert_eq!(diff.hbh_appended[1], H256::ZERO);
    }
}
