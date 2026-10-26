//! Replaying one era of blocks through the beacon state transition.
//!
//! Era file `N` holds the blocks of slots `[(N-1)*8192, N*8192)` and the state
//! at slot `N*8192`. The state stored in file `N-1` is therefore exactly the
//! state the first block of file `N` builds on. Applying every block with
//! `validate_result` on checks each proposer signature and each `state_root`
//! against what the chain committed to; the state stored in file `N` is an
//! independent end-of-era oracle.
//!
//! # The block at a state's own slot
//!
//! An era state is the state *with* the block at its slot applied, if there is
//! one, and that block is stored in the next file. So a starting state may
//! already contain file `N`'s first block (skipped here: its slot is not above
//! the state's), and the closing state may be one block short of what the next
//! file would add. The oracle is written around that, see [`Replay::oracle`].

use std::path::Path;
use std::time::Instant;

use ethlambda_state_transition::beacon::helpers::accessors::CommitteeCache;
use ethlambda_state_transition::beacon::stf::{self, ExecutionEngine};
use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::containers::{BeaconState, SignedBeaconBlock};
use ethlambda_types::beacon::preset;
use ethlambda_types::primitives::H256;
use eyre::{WrapErr as _, ensure, eyre};
use tracing::info;

use super::e2store::EraFile;
use super::report::{EraReport, Outcome};

/// Blocks between progress lines.
const PROGRESS_EVERY: u64 = 512;

/// Slots per era file.
pub(super) const SLOTS_PER_ERA: u64 = preset::SLOTS_PER_HISTORICAL_ROOT as u64;

fn hex(root: H256) -> String {
    format!("0x{}", hex::encode(root.0))
}

/// State carried from one era into the next, so a fork upgrade at the boundary
/// is crossed by this node's own `process_slots`.
struct Carried {
    era: u64,
    state: BeaconState,
}

pub(super) struct Replay<'a> {
    network: &'a str,
    config: &'a Config,
    engine: ExecutionEngine,
    /// One for the whole run, as the node holds one across its imports.
    committees: CommitteeCache,
    max_blocks: Option<u64>,
    carried: Option<Carried>,
}

impl<'a> Replay<'a> {
    pub(super) fn new(network: &'a str, config: &'a Config, max_blocks: Option<u64>) -> Self {
        Self {
            network,
            config,
            engine: ExecutionEngine::valid(),
            committees: CommitteeCache::default(),
            max_blocks,
            carried: None,
        }
    }

    /// Replay era `era`, starting from the state in `previous` unless the last
    /// era replayed was `era - 1`.
    ///
    /// Returns the report whether or not the era passed.
    pub(super) fn era(&mut self, era: u64, previous: &Path, current: &Path) -> EraReport {
        let mut report = EraReport::new(self.network, era, self.max_blocks);
        let started = Instant::now();
        info!(network = self.network, era, "Era replay starting");
        let result = self.replay(era, previous, current, &mut report);
        report.elapsed_secs = started.elapsed().as_secs_f64();
        if let Err(err) = result {
            // A failed era leaves a partially advanced state behind.
            self.carried = None;
            report.error = Some(format!("{err:#}"));
        }
        info!(
            network = self.network,
            era,
            blocks_applied = report.blocks_applied,
            elapsed_secs = format_args!("{:.1}", report.elapsed_secs),
            mean_ms_per_block = format_args!("{:.1}", report.mean_ms_per_block),
            ok = report.error.is_none(),
            "Era replay finished"
        );
        report
    }

    fn replay(
        &mut self,
        era: u64,
        previous: &Path,
        current: &Path,
        report: &mut EraReport,
    ) -> eyre::Result<()> {
        ensure!(era >= 1, "era 0 holds no blocks to replay");
        let first_slot = (era - 1) * SLOTS_PER_ERA;
        let end_slot = era * SLOTS_PER_ERA;

        let mut file = EraFile::open(current)?;
        let block_index = file
            .block_index()
            .ok_or_else(|| eyre!("{} has no block index", current.display()))?;
        ensure!(
            block_index.start_slot == first_slot && block_index.count() as u64 == SLOTS_PER_ERA,
            "{} indexes {} slots from {}, expected {SLOTS_PER_ERA} from {first_slot}",
            current.display(),
            block_index.count(),
            block_index.start_slot
        );

        let mut state = match self.carried.take() {
            Some(carried) if carried.era + 1 == era => {
                info!(era, "Continuing from the previous era's in-memory state");
                carried.state
            }
            _ => self.load_state(previous, first_slot)?,
        };

        let apply_started = Instant::now();
        let mut block_roots: Vec<(u64, H256)> = Vec::new();
        let mut stopped_early = false;
        for slot in first_slot..end_slot {
            let Some(bytes) = file.block_bytes(slot)? else {
                report.skipped_empty_slots += 1;
                continue;
            };
            let fork = self.config.fork_at_epoch(slot / preset::SLOTS_PER_EPOCH);
            let block = SignedBeaconBlock::from_ssz(fork, &bytes).map_err(|err| {
                eyre!("era {era} slot {slot}: block does not decode as {fork:?}: {err:?}")
            })?;
            ensure!(
                block.slot() == slot,
                "era {era}: the record indexed at slot {slot} holds a block for slot {}",
                block.slot()
            );
            drop(bytes);
            block_roots.push((slot, block.message_hash_tree_root()));

            if slot <= state.slot() {
                report.blocks_already_in_state += 1;
                continue;
            }
            if self
                .max_blocks
                .is_some_and(|max| report.blocks_applied >= max)
            {
                stopped_early = true;
                break;
            }
            let expected_state_root = block.state_root();
            stf::state_transition(
                &mut state,
                &block,
                true,
                self.config,
                &self.engine,
                &self.committees,
            )
            .map_err(|err| {
                eyre!(
                    "era {era} slot {slot}: block rejected: {err:?} \
                     (block commits to state_root {})",
                    hex(expected_state_root)
                )
            })?;
            report.blocks_applied += 1;
            if report.blocks_applied.is_multiple_of(PROGRESS_EVERY) {
                info!(
                    era,
                    %slot,
                    blocks_applied = report.blocks_applied,
                    elapsed_secs = format_args!("{:.0}", apply_started.elapsed().as_secs_f64()),
                    "Era replay progress"
                );
            }
        }
        report.apply_secs = apply_started.elapsed().as_secs_f64();
        if report.blocks_applied > 0 {
            report.mean_ms_per_block = report.apply_secs * 1000.0 / report.blocks_applied as f64;
        }

        // `--max-blocks` may exactly equal the era's block count, which is no
        // early stop; only a break leaves the state short of the era's end.
        if stopped_early {
            for name in ORACLE_CHECKS {
                report.check(
                    name,
                    Outcome::Skipped,
                    Some("--max-blocks stopped the era early".into()),
                );
            }
            return Ok(());
        }

        self.oracle(era, state, &block_roots, &mut file, report)
    }

    fn load_state(&self, path: &Path, expected_slot: u64) -> eyre::Result<BeaconState> {
        let mut file = EraFile::open(path)?;
        let bytes = file.state_bytes()?;
        let slot = BeaconState::slot_from_ssz(&bytes)
            .map_err(|err| eyre!("{}: state has no readable slot: {err:?}", path.display()))?;
        ensure!(
            slot == expected_slot,
            "{} holds a state at slot {slot}, expected {expected_slot}",
            path.display()
        );
        let fork = self.config.fork_at_epoch(slot / preset::SLOTS_PER_EPOCH);
        BeaconState::from_ssz(fork, &bytes).map_err(|err| {
            eyre!(
                "{}: state does not decode as {fork:?}: {err:?}",
                path.display()
            )
        })
    }

    /// Compare the replayed chain with the state stored in the era's own file.
    ///
    /// Three checks, in the order they can be made without file `N+1`:
    ///
    /// 1. `state_roots[end - 1]` of the stored state is the root of the state
    ///    after the last slot before the era boundary, which is what
    ///    `process_slot` records on the way out of it. Compared with our own
    ///    state advanced to `end - 1`. It holds whether or not a block sits at
    ///    `end`, because that block is applied after the boundary.
    /// 2. Every block's root against the stored `block_roots` window.
    /// 3. When the stored state's `latest_block_header` is older than `end`,
    ///    slot `end` is empty, so advancing our state to `end` must reproduce
    ///    the stored state outright, including any fork upgrade there. When a
    ///    block sits at `end` the stored state includes it and we do not have
    ///    it, so the full comparison is skipped.
    fn oracle(
        &mut self,
        era: u64,
        mut state: BeaconState,
        block_roots: &[(u64, H256)],
        file: &mut EraFile,
        report: &mut EraReport,
    ) -> eyre::Result<()> {
        let end_slot = era * SLOTS_PER_ERA;
        let bytes = file.state_bytes()?;
        let slot = BeaconState::slot_from_ssz(&bytes)
            .map_err(|err| eyre!("era {era}: stored state has no readable slot: {err:?}"))?;
        ensure!(
            slot == end_slot,
            "era {era}: the stored state is at slot {slot}, expected {end_slot}"
        );
        let fork = self.config.fork_at_epoch(slot / preset::SLOTS_PER_EPOCH);
        let stored = BeaconState::from_ssz(fork, &bytes)
            .map_err(|err| eyre!("era {era}: stored state does not decode as {fork:?}: {err:?}"))?;
        drop(bytes);

        // 1. state_roots at the last slot before the boundary.
        let last_slot = end_slot - 1;
        if state.slot() < last_slot {
            stf::process_slots(&mut state, last_slot, self.config)
                .wrap_err_with(|| format!("era {era}: advancing to slot {last_slot}"))?;
        }
        ensure!(
            state.slot() == last_slot,
            "era {era}: state is at slot {} after the era's blocks, expected {last_slot}",
            state.slot()
        );
        let expected = stored.state_roots()[(last_slot % SLOTS_PER_ERA) as usize];
        let actual = state.hash_tree_root();
        let result = compare(
            "state_roots[last slot]",
            era,
            last_slot,
            expected,
            actual,
            report,
        );
        result?;

        // 2. block roots.
        for &(slot, root) in block_roots {
            let expected = stored.block_roots()[(slot % SLOTS_PER_ERA) as usize];
            compare("block_roots", era, slot, expected, root, report)?;
        }
        report.check(
            "block_roots",
            Outcome::Passed,
            Some(format!("{} blocks", block_roots.len())),
        );

        // 3. the whole state, when slot `end` is empty.
        if stored.latest_block_header().slot < end_slot {
            stf::process_slots(&mut state, end_slot, self.config)
                .wrap_err_with(|| format!("era {era}: advancing to slot {end_slot}"))?;
            compare(
                "full_state_root",
                era,
                end_slot,
                stored.hash_tree_root(),
                state.hash_tree_root(),
                report,
            )?;
        } else {
            report.check(
                "full_state_root",
                Outcome::Skipped,
                Some(format!(
                    "slot {end_slot} holds a block, stored in the next era file"
                )),
            );
        }

        self.carried = Some(Carried { era, state });
        Ok(())
    }
}

const ORACLE_CHECKS: [&str; 3] = ["state_roots[last slot]", "block_roots", "full_state_root"];

/// Record one root comparison; a mismatch is a hard failure naming everything
/// needed to look it up.
fn compare(
    name: &'static str,
    era: u64,
    slot: u64,
    expected: H256,
    actual: H256,
    report: &mut EraReport,
) -> eyre::Result<()> {
    if expected == actual {
        // `block_roots` is recorded once for all its blocks by the caller.
        if name != "block_roots" {
            report.check(
                name,
                Outcome::Passed,
                Some(format!("slot {slot}: {}", hex(actual))),
            );
        }
        return Ok(());
    }
    let detail = format!(
        "era {era} slot {slot}: {name} mismatch: expected {}, actual {}",
        hex(expected),
        hex(actual)
    );
    report.check(name, Outcome::Failed, Some(detail.clone()));
    Err(eyre!(detail))
}
