//! Pulling a range into a corpus.
//!
//! # Memory
//!
//! Nothing here scales with the length of the range. The anchor state is the
//! only state this phase ever holds: it is fetched alone, written straight to
//! disk and dropped before the block loop starts. Blocks are written as each
//! response completes, never accumulated. That is why there is no cap on the
//! range: the ceiling comes from streaming, not from refusing long runs.
//!
//! # What a 404 means
//!
//! The Beacon API answers `404` for an empty slot, for a slot past its head
//! and for one before its own history, and those look identical from here.
//! `fetch` records a 404 as an empty slot only where it can prove that is what
//! it was: `--to` may not pass the source's head, and every block must name
//! the previous one as its parent, so a block missing from the middle of the
//! range (or a reorg between two requests) stops the fetch instead of
//! surfacing later as a replay that imports onto the wrong parent.

use std::path::Path;

use ethlambda_p2p::beacon::decode;
use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::containers::BeaconState;
use ethlambda_types::beacon::preset;
use ethlambda_types::genesis::verify_state_genesis;

use super::corpus::{
    ANCHOR_BLOCK_FILE, ANCHOR_STATE_FILE, BLOCKS_DIR, MANIFEST_FILE, Manifest, block_path, hex_root,
};
use super::source::{CorpusSource, resolve_anchor};

/// Print a progress line every this many slots, so a long range does not run
/// silent: each slot is one request, which is a round trip to a remote source.
const PROGRESS_INTERVAL: u64 = 100;

/// Removes a corpus directory this fetch created, unless the fetch finished.
///
/// A failed fetch otherwise leaves a manifest-less directory behind (an empty
/// one at best, a partial set of blocks at worst) that looks like a corpus
/// and is not one. A directory that already existed is left alone: it is the
/// caller's, and might hold anything.
struct CreatedDir<'a> {
    path: Option<&'a Path>,
}

impl<'a> CreatedDir<'a> {
    fn create(path: &'a Path) -> std::io::Result<Self> {
        let created = !path.exists();
        std::fs::create_dir_all(path.join(BLOCKS_DIR))?;
        Ok(Self {
            path: created.then_some(path),
        })
    }

    /// The fetch finished: keep the directory.
    fn keep(mut self) {
        self.path = None;
    }
}

impl Drop for CreatedDir<'_> {
    fn drop(&mut self) {
        if let Some(path) = self.path {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}

/// Fetch `from..=to` into a fresh corpus at `dir`.
///
/// Refuses to run if `dir` already holds a manifest, so a caller retrying a
/// failed run does not silently blend a half-written corpus with a new one;
/// deleting an existing corpus before calling this (the `--force` flag) is
/// the caller's job, not this function's.
///
/// The corpus also holds the blocks between the anchor and `from` (see
/// [`resolve_anchor`] for why the anchor is usually before `from - 1`), as
/// warm-up blocks the replay imports without sampling.
pub(crate) async fn fetch_corpus(
    source: &impl CorpusSource,
    dir: &Path,
    from: u64,
    to: u64,
    network: &str,
    config: &Config,
    genesis: &crate::beacon::Genesis,
) -> eyre::Result<Manifest> {
    eyre::ensure!(from <= to, "--from {from} is after --to {to}");
    eyre::ensure!(
        !dir.join(MANIFEST_FILE).exists(),
        "{} already holds a corpus; pass --force to replace it",
        dir.display()
    );
    let head = source.head_slot().await?;
    eyre::ensure!(
        to <= head,
        "--to {to} is past the source's head at slot {head}; the slots after it \
         would be recorded as empty"
    );

    let anchor = resolve_anchor(source, from, preset::SLOTS_PER_EPOCH).await?;
    let created = CreatedDir::create(dir)?;

    // The one state this phase holds. Decoded to read the network
    // fingerprint, written, then dropped before any block is fetched, so the
    // peak is one state and not one state plus a range.
    let genesis_validators_root = {
        let bytes = source.state_bytes_at_slot(anchor.slot).await?;
        let slot = BeaconState::slot_from_ssz(&bytes)
            .map_err(|err| eyre::eyre!("anchor state slot does not decode: {err:?}"))?;
        let fork = decode::fork_at_slot(config, slot);
        let state = BeaconState::from_ssz(fork, &bytes)
            .map_err(|err| eyre::eyre!("anchor state does not decode as {fork:?}: {err:?}"))?;
        // Fail here rather than write a corpus that replay will refuse.
        verify_state_genesis(
            &state,
            genesis.genesis_time,
            genesis.genesis_validators_root,
        )?;
        std::fs::write(dir.join(ANCHOR_STATE_FILE), &bytes)?;
        hex_root(state.genesis_validators_root())
    };

    let anchor_block = source.block_bytes_by_root(&anchor.root).await?;
    std::fs::write(dir.join(ANCHOR_BLOCK_FILE), &anchor_block)?;

    eprintln!(
        "anchor resolved at slot {}; fetching slots {}..={to} ({} of them warm-up)",
        anchor.slot,
        anchor.slot + 1,
        from - anchor.slot - 1
    );

    let mut warmup_slots = Vec::new();
    let mut slots = Vec::new();
    let mut previous_root = anchor.root.clone();
    for slot in (anchor.slot + 1)..=to {
        if let Some((block, bytes)) = source.block_with_bytes_at_slot(slot).await? {
            eyre::ensure!(
                block.slot == slot,
                "asked for the block at slot {slot}, got one at slot {}",
                block.slot
            );
            eyre::ensure!(
                block.parent_root == previous_root,
                "the block at slot {slot} ({}) names parent {}, but the corpus's previous \
                 block is {previous_root}: the source's chain changed during the fetch, or \
                 it is missing a block between them",
                block.root,
                block.parent_root
            );
            std::fs::write(block_path(dir, slot), &bytes)?;
            previous_root = block.root;
            if slot < from {
                warmup_slots.push(slot);
            } else {
                slots.push(slot);
            }
        }

        if slot % PROGRESS_INTERVAL == 0 || slot == to {
            eprintln!(
                "fetched through slot {slot} of {to}: {} blocks",
                warmup_slots.len() + slots.len()
            );
        }
    }

    let manifest = Manifest {
        chain: "beacon".to_string(),
        network: network.to_string(),
        genesis_validators_root,
        anchor_block_root: anchor.root,
        anchor_slot: anchor.slot,
        warmup_slots,
        range_start: from,
        range_end: to,
        slots,
    };
    manifest.write(dir)?;
    created.keep();
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::benchmark::import::source::tests::FakeSource;

    fn config() -> Config {
        Config::mainnet()
    }

    fn genesis() -> crate::beacon::Genesis {
        crate::beacon::mainnet_genesis().expect("mainnet genesis fixture decodes")
    }

    async fn fetch(source: &FakeSource, dir: &Path, from: u64, to: u64) -> eyre::Result<Manifest> {
        fetch_corpus(source, dir, from, to, "mainnet", &config(), &genesis()).await
    }

    #[tokio::test]
    async fn a_gap_is_recorded_rather_than_failing_the_fetch() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = FakeSource::chain(&[64, 65, 67, 68]);

        let manifest = fetch(&source, dir.path(), 65, 68)
            .await
            .expect("a gap is not a failure");

        assert_eq!(manifest.slots, vec![65, 67, 68]);
        assert_eq!(manifest.missing_slots(), vec![66]);
        assert!(dir.path().join("blocks/0000000067.ssz").exists());
    }

    #[tokio::test]
    async fn blocks_between_the_anchor_and_from_are_warm_up_rather_than_samples() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = FakeSource::chain(&[64, 65, 66, 68, 69, 70]);

        let manifest = fetch(&source, dir.path(), 69, 70).await.expect("fetch");

        assert_eq!(manifest.anchor_slot, 64);
        assert_eq!(manifest.warmup_slots, vec![65, 66, 68]);
        assert_eq!(manifest.slots, vec![69, 70]);
        assert!(dir.path().join("blocks/0000000065.ssz").exists());
    }

    #[tokio::test]
    async fn an_existing_corpus_is_not_silently_overwritten() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("manifest.json"), "{}").expect("seed");
        let source = FakeSource::chain(&[64, 65, 66]);

        let err = fetch(&source, dir.path(), 65, 66)
            .await
            .expect_err("a half-written corpus must not be mistaken for a complete one");

        assert!(
            err.to_string().contains("--force"),
            "the error says how: {err}"
        );
    }

    #[tokio::test]
    async fn a_range_whose_first_slot_is_empty_is_rejected_and_leaves_nothing_behind() {
        let parent = tempfile::tempdir().expect("tempdir");
        let dir = parent.path().join("corpus");
        let source = FakeSource::chain(&[64, 65, 67]);

        let err = fetch(&source, &dir, 66, 67)
            .await
            .expect_err("66 holds no block");

        assert!(
            err.to_string().contains("66"),
            "the error names the slot: {err}"
        );
        assert!(!dir.exists(), "a refused fetch must not leave a directory");
    }

    #[tokio::test]
    async fn a_range_past_the_source_head_is_rejected() {
        // Every slot past the head answers 404, which would otherwise be
        // recorded as a run of empty slots.
        let dir = tempfile::tempdir().expect("tempdir");
        let source = FakeSource::chain(&[64, 65, 66]);

        let err = fetch(&source, dir.path(), 65, 70)
            .await
            .expect_err("70 is past the head");

        assert!(
            err.to_string().contains("head at slot 66"),
            "the error names the head: {err}"
        );
    }

    #[tokio::test]
    async fn a_block_that_does_not_extend_the_corpus_aborts_the_fetch_and_cleans_up() {
        let parent = tempfile::tempdir().expect("tempdir");
        let dir = parent.path().join("corpus");
        let source = FakeSource::chain(&[64, 65, 66, 67]).with_foreign_parent_at(66);

        let err = fetch(&source, &dir, 65, 67)
            .await
            .expect_err("66 does not descend from 65");

        assert!(
            err.to_string().contains("slot 66"),
            "the error names the slot: {err}"
        );
        assert!(
            !dir.exists(),
            "a fetch that created the directory removes it on failure"
        );
    }

    #[tokio::test]
    async fn a_failed_fetch_leaves_a_directory_it_did_not_create() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = FakeSource::chain(&[64, 65, 66, 67]).with_foreign_parent_at(66);

        let result = fetch(&source, dir.path(), 65, 67).await;

        assert!(result.is_err(), "66 does not descend from 65");
        assert!(
            dir.path().exists(),
            "the caller's directory is not ours to delete"
        );
    }

    #[tokio::test]
    async fn a_backwards_range_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = FakeSource::chain(&[64, 65, 66]);

        assert!(fetch(&source, dir.path(), 66, 65).await.is_err());
    }
}
