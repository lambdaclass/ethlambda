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
    /// Build a diff from a base (parent) state and the consumed target state.
    ///
    /// Takes `target` by value so its multi-MB justification fields are moved
    /// into the diff rather than cloned; `base` is read only to find the length
    /// of its `historical_block_hashes` (the diff stores just the tail `target`
    /// appended on top). `base_root` is the parent block root the diff is
    /// relative to.
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
    ///   (`target[base_len..]`) is stored and the earlier entries are never
    ///   reordered or rewritten. (`process_slots` pushes the parent root and
    ///   zero-fills skipped slots, leaving the existing prefix intact.) This is
    ///   why the base's length alone is enough to identify its contribution.
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
    /// Panics if `target.historical_block_hashes` is shorter than the base's,
    /// i.e. the append-only assumption above was violated.
    pub fn from_states(base_root: H256, base: &State, target: State) -> Self {
        let base_hbh_len = base.historical_block_hashes.len();
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

        let diff = StateDiff::from_states(h256(1), &base, target);

        assert_eq!(diff.base_root, h256(1));
        assert_eq!(diff.slot, 5);
        assert_eq!(diff.latest_justified, expected_justified);
        assert_eq!(diff.hbh_appended.len(), 3);
        assert_eq!(diff.hbh_appended[0], h256(9));
        assert_eq!(diff.hbh_appended[1], H256::ZERO);
    }

    /// A block header distinct from any snapshot/diff field, so the test can
    /// assert it is passed through `reconstruct` verbatim.
    fn header_at(slot: u64) -> BlockHeader {
        BlockHeader {
            slot,
            proposer_index: 7,
            parent_root: h256(51),
            state_root: h256(99),
            body_root: h256(88),
        }
    }

    /// Build a diff against `base_root` that appends `appended` to
    /// `historical_block_hashes`. Absolute fields default; tests override the
    /// ones they assert on.
    fn diff_at(base_root: H256, slot: u64, appended: Vec<H256>) -> StateDiff {
        StateDiff {
            base_root,
            slot,
            latest_justified: Checkpoint::default(),
            latest_finalized: Checkpoint::default(),
            justified_slots: JustifiedSlots::new(),
            justifications_roots: JustificationRoots::default(),
            justifications_validators: JustificationValidators::new(),
            hbh_appended: HistoricalBlockHashesTail::try_from(appended).unwrap(),
        }
    }

    #[test]
    fn reconstruct_merges_snapshot_with_diff_chain() {
        // Snapshot: distinctive config + validators, plus one pre-existing root.
        let mut snapshot = base_state();
        snapshot.slot = 100;
        snapshot.historical_block_hashes = vec![h256(1)].try_into().unwrap();

        // Intermediate diff (snapshot's child): appends one root, default fields.
        let intermediate = diff_at(h256(50), 101, vec![h256(2)]);

        // Target diff (last): appends two roots and carries the absolute fields
        // the reconstructed state must adopt, all different from the intermediate.
        let mut target = diff_at(h256(51), 102, vec![h256(3), h256(4)]);
        target.latest_justified = Checkpoint {
            root: h256(7),
            slot: 101,
        };
        target.latest_finalized = Checkpoint {
            root: h256(8),
            slot: 100,
        };
        target.justified_slots = JustifiedSlots::try_from(vec![true, false, true]).unwrap();
        target.justifications_roots = JustificationRoots::try_from(vec![h256(9)]).unwrap();
        target.justifications_validators = JustificationValidators::try_from(vec![true]).unwrap();

        let header = header_at(102);
        let state = reconstruct(snapshot, &[intermediate, target.clone()], header.clone());

        // Structural fields come from the snapshot (diffs never carry them).
        assert_eq!(state.config.genesis_time, 1_000);
        assert_eq!(state.validators.len(), 2);
        assert_eq!(state.validators[0].attestation_pubkey, [1u8; 52]);
        assert_eq!(state.validators[1].index, 1);

        // latest_block_header is the argument, passed through verbatim.
        assert_eq!(state.latest_block_header, header);

        // Absolute fields come from the LAST diff, not the intermediate one.
        assert_eq!(state.slot, 102);
        assert_eq!(state.latest_justified, target.latest_justified);
        assert_eq!(state.latest_finalized, target.latest_finalized);
        assert_eq!(state.justified_slots, target.justified_slots);
        assert_eq!(state.justifications_roots, target.justifications_roots);
        assert_eq!(
            state.justifications_validators,
            target.justifications_validators
        );

        // historical_block_hashes = snapshot tail ++ each diff's appended tail,
        // replayed in order.
        assert_eq!(
            state.historical_block_hashes.to_vec(),
            vec![h256(1), h256(2), h256(3), h256(4)],
        );
    }

    #[test]
    fn reconstruct_with_single_diff_uses_it_as_target() {
        let mut snapshot = base_state();
        snapshot.slot = 7;
        snapshot.historical_block_hashes = vec![h256(1)].try_into().unwrap();

        let mut diff = diff_at(h256(50), 8, vec![h256(2)]);
        diff.latest_justified = Checkpoint {
            root: h256(7),
            slot: 7,
        };

        let header = header_at(8);
        let state = reconstruct(snapshot, &[diff.clone()], header.clone());

        assert_eq!(state.slot, 8);
        assert_eq!(state.latest_justified, diff.latest_justified);
        assert_eq!(state.latest_block_header, header);
        assert_eq!(
            state.historical_block_hashes.to_vec(),
            vec![h256(1), h256(2)],
        );
    }
}
