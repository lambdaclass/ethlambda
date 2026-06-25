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
    primitives::{H256, HashTreeRoot},
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
    /// Build a diff from the pre-state (the parent block's post-state) and the
    /// consumed post-state.
    ///
    /// Takes `post_state` by value so its multi-MB justification fields are moved
    /// into the diff rather than cloned; `pre_state` is read to derive `base_root`
    /// and the length of its `historical_block_hashes` (the diff stores just the
    /// tail `post_state` appended on top).
    ///
    /// `base_root` is the parent block root, computed as the `hash_tree_root` of
    /// the pre-state's `latest_block_header`. A `Block` and its `BlockHeader`
    /// share a hash tree root (the header's `body_root` is the body's root), so
    /// this equals the key under which the parent's snapshot/diff is stored.
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
    /// Panics if `post_state.historical_block_hashes` is shorter than the
    /// pre-state's, i.e. the append-only assumption above was violated.
    pub fn from_states(pre_state: &State, post_state: State) -> Self {
        let base_root = pre_state.latest_block_header.hash_tree_root();
        let base_hbh_len = pre_state.historical_block_hashes.len();
        let State {
            slot,
            latest_justified,
            latest_finalized,
            historical_block_hashes,
            justified_slots,
            justifications_roots,
            justifications_validators,
            ..
        } = post_state;

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
    use libssz::SszEncode;

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

        let diff = StateDiff::from_states(&base, target);

        assert_eq!(diff.base_root, base.latest_block_header.hash_tree_root());
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

    /// Build the post-state of a block at `slot` whose parent post-state is
    /// `parent`, mirroring the STF: append the parent block root (the hash of
    /// `parent`'s `latest_block_header`), zero-fill skipped slots, and set the
    /// child's own header. Absolute fields are inherited; callers override what
    /// they assert on. Feeds realistic states into the production `from_states`,
    /// so the tests exercise diff creation rather than fabricating diffs by hand.
    fn child_state(parent: &State, slot: u64) -> State {
        let parent_root = parent.latest_block_header.hash_tree_root();
        let empty_slots = (slot - parent.slot - 1) as usize;

        let mut hbh = parent.historical_block_hashes.to_vec();
        hbh.push(parent_root);
        hbh.extend(std::iter::repeat_n(H256::ZERO, empty_slots));

        let mut child = parent.clone();
        child.slot = slot;
        child.historical_block_hashes = hbh.try_into().unwrap();
        child.latest_block_header = BlockHeader {
            slot,
            proposer_index: 0,
            parent_root,
            state_root: H256::ZERO,
            body_root: H256::ZERO,
        };
        child
    }

    #[test]
    fn reconstruct_round_trips_a_diff_chain() {
        // Snapshot at slot 100 with one pre-existing historical root.
        let mut snapshot = base_state();
        snapshot.slot = 100;
        snapshot.latest_block_header = header_at(100);
        snapshot.historical_block_hashes = vec![h256(1)].try_into().unwrap();

        // s1 is the snapshot's child (consecutive slot); s2 is s1's child three
        // slots later, so slots 102 and 103 are skipped and zero-filled. s2 also
        // carries distinctive absolute fields the reconstruction must adopt.
        let s1 = child_state(&snapshot, 101);
        let mut s2 = child_state(&s1, 104);
        s2.latest_justified = Checkpoint {
            root: h256(7),
            slot: 101,
        };
        s2.latest_finalized = Checkpoint {
            root: h256(8),
            slot: 100,
        };
        s2.justified_slots = JustifiedSlots::try_from(vec![true, false, true]).unwrap();
        s2.justifications_roots = JustificationRoots::try_from(vec![h256(9)]).unwrap();
        s2.justifications_validators = JustificationValidators::try_from(vec![true]).unwrap();

        // Diffs are built the production way, from each (pre, post) pair.
        let diff1 = StateDiff::from_states(&snapshot, s1.clone());
        let diff2 = StateDiff::from_states(&s1, s2.clone());

        let reconstructed = reconstruct(snapshot, &[diff1, diff2], s2.latest_block_header.clone());

        // Full round-trip: structural fields (config/validators) from the snapshot,
        // absolute fields from the last diff, and the appended-with-gaps history.
        assert_eq!(reconstructed.to_ssz(), s2.to_ssz());
    }

    #[test]
    fn reconstruct_with_single_diff_round_trips() {
        let mut snapshot = base_state();
        snapshot.slot = 7;
        snapshot.latest_block_header = header_at(7);
        snapshot.historical_block_hashes = vec![h256(1)].try_into().unwrap();

        let mut child = child_state(&snapshot, 8);
        child.latest_justified = Checkpoint {
            root: h256(7),
            slot: 7,
        };

        let diff = StateDiff::from_states(&snapshot, child.clone());
        let reconstructed = reconstruct(snapshot, &[diff], child.latest_block_header.clone());

        assert_eq!(reconstructed.to_ssz(), child.to_ssz());
    }
}
