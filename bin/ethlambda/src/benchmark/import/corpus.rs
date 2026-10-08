//! The on-disk corpus: a manifest, an anchor pair, and one SSZ file per
//! non-empty slot.
//!
//! Blocks rather than a prepared RocksDB directory, so a corpus stays
//! readable, diffable and portable across revisions of the store format.
//! Blocks are never all in memory at once: a reader takes one file per turn.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub(crate) const MANIFEST_FILE: &str = "manifest.json";
pub(crate) const ANCHOR_STATE_FILE: &str = "anchor.state.ssz";
pub(crate) const ANCHOR_BLOCK_FILE: &str = "anchor.block.ssz";
pub(crate) const BLOCKS_DIR: &str = "blocks";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Manifest {
    /// `"beacon"`. Recorded so a future lean arm cannot be replayed by the
    /// beacon one by accident.
    pub chain: String,
    /// The `--network` value the corpus was fetched against.
    pub network: String,
    pub genesis_validators_root: String,
    pub anchor_block_root: String,
    /// The first slot of an epoch; see `source::resolve_anchor` for why.
    pub anchor_slot: u64,
    /// Slots between the anchor and `range_start` that hold a block,
    /// ascending. Replay imports them before the range, since the range's
    /// first block descends from them, but takes no sample of them.
    ///
    /// Defaulted so a corpus written before this field existed still reads;
    /// whether its anchor is usable is `replay`'s to check.
    #[serde(default)]
    pub warmup_slots: Vec<u64>,
    pub range_start: u64,
    pub range_end: u64,
    /// Slots in the range that hold a block, ascending. Slots in the range but
    /// absent here were empty on the source chain.
    pub slots: Vec<u64>,
}

impl Manifest {
    pub(crate) fn write(&self, dir: &Path) -> eyre::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(dir.join(MANIFEST_FILE), json)?;
        Ok(())
    }

    pub(crate) fn read(dir: &Path) -> eyre::Result<Self> {
        let json = std::fs::read_to_string(dir.join(MANIFEST_FILE))?;
        Ok(serde_json::from_str(&json)?)
    }

    /// Slots in the range that hold no block.
    pub(crate) fn missing_slots(&self) -> Vec<u64> {
        (self.range_start..=self.range_end)
            .filter(|slot| self.slots.binary_search(slot).is_err())
            .collect()
    }
}

/// A root as a manifest spells it: `0x` plus lowercase hex.
///
/// Shared with `fetch`, which fills the manifest, and `replay`, which checks
/// the recorded root against the network it was asked to replay against.
pub(crate) fn hex_root(root: ethlambda_types::primitives::H256) -> String {
    format!("0x{}", hex::encode(root.0))
}

/// Where a block at `slot` lives inside a corpus.
///
/// Zero-padded to ten digits so a directory listing sorts, which matters when
/// a human is reading a corpus rather than its manifest.
pub(crate) fn block_path(dir: &Path, slot: u64) -> PathBuf {
    dir.join(BLOCKS_DIR).join(format!("{slot:010}.ssz"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> Manifest {
        Manifest {
            chain: "beacon".to_string(),
            network: "mainnet".to_string(),
            genesis_validators_root: "0x4b363db9".to_string(),
            anchor_block_root: "0xabcdef01".to_string(),
            anchor_slot: 9_123_424,
            warmup_slots: vec![9_123_425, 9_123_455],
            range_start: 9_123_456,
            range_end: 9_123_460,
            slots: vec![9_123_456, 9_123_458, 9_123_460],
        }
    }

    #[test]
    fn a_manifest_round_trips_through_a_corpus_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let expected = manifest();

        expected.write(dir.path()).expect("write");
        let loaded = Manifest::read(dir.path()).expect("read");

        assert_eq!(loaded, expected);
    }

    #[test]
    fn a_manifest_written_before_warm_up_slots_existed_still_reads() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut json = serde_json::to_value(manifest()).expect("to json");
        json.as_object_mut()
            .expect("an object")
            .remove("warmup_slots");
        std::fs::write(dir.path().join(MANIFEST_FILE), json.to_string()).expect("write");

        let loaded = Manifest::read(dir.path()).expect("read");

        assert!(loaded.warmup_slots.is_empty());
    }

    #[test]
    fn absent_slots_are_recorded_as_gaps_not_errors() {
        // 9_123_457 and 9_123_459 held no block. A replay must skip them
        // without treating the corpus as truncated.
        let m = manifest();
        assert_eq!(m.missing_slots(), vec![9_123_457, 9_123_459]);
    }

    #[test]
    fn a_block_path_sorts_lexically() {
        // Zero-padded so a directory listing reads in slot order, which
        // matters when a human is inspecting a corpus rather than its
        // manifest.
        let dir = std::path::Path::new("/corpus");
        let early = block_path(dir, 9_123_456);
        let late = block_path(dir, 10_000_000);

        assert!(early < late, "{early:?} must sort before {late:?}");
    }
}
