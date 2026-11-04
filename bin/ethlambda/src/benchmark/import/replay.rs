//! Replaying a corpus through the real import path.
//!
//! Drives [`BlockChainServer::import_block`] directly, one block per turn: no
//! mailbox, no tick loop, no p2p. The only production entry points this
//! workload measures are the ones a live node's cascade already runs
//! ([`fork_choice::get_forkchoice_store`] to bootstrap, then `on_block` per
//! import), so a phase regression here is a regression a live node would
//! also see.
//!
//! # Memory
//!
//! Exactly one block is decoded, imported and dropped per turn; the manifest
//! is held, never the corpus's blocks. Nothing here keeps an
//! `Arc<BeaconState>` of its own: the state cache
//! ([`ethlambda_storage::Store`]'s `STATE_CACHE_CAPACITY`-bounded LRU) is the
//! only thing allowed to hold post-states, and a stray clone here would pin
//! an entry the LRU believes it evicted, raising the real ceiling silently.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ethlambda_blockchain::metrics::{BLOCK_ARRIVAL_PHASES, BLOCK_IMPORT_PHASES};
use ethlambda_blockchain::{BlockChainServer, ImportOutcome};
use ethlambda_p2p::beacon::decode;
use ethlambda_state_transition::beacon::fork_choice;
use ethlambda_storage::Store;
use ethlambda_storage::backend::RocksDBBackend;
use ethlambda_types::ShortRoot;
use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::containers::{BeaconState, SignedBeaconBlock};
use ethlambda_types::beacon::preset;
use ethlambda_types::primitives::H256;

use super::ReplayOptions;
use super::corpus::{ANCHOR_BLOCK_FILE, ANCHOR_STATE_FILE, Manifest, block_path, hex_root};
use crate::benchmark::PhaseTimer;
use crate::benchmark::report::common::{Environment, format_ms};
use crate::benchmark::report::import::{Params, Report, Sample};

/// The histogram `ImportTimings` writes to, read back by [`PhaseTimer`] the
/// same way the synthetic workload reads
/// `lean_block_proposal_attestation_build_phase_seconds`.
const IMPORT_PHASE_HISTOGRAM: &str = "lean_block_import_phase_seconds";

/// The phases a sample records: every per-block section, plus the
/// per-arrival sections that do not enclose the others.
///
/// `import_block` is one arrival per block, so those run at most once per
/// sample too, and `get_head` is where the head recomputation `on_block` runs
/// after every import is charged. `arrival` and `cascade` are left out
/// because they are spans around everything else, which as columns beside
/// their own parts would count the same time twice.
fn sampled_phases() -> impl Iterator<Item = &'static str> {
    let arrival_leaves = BLOCK_ARRIVAL_PHASES
        .iter()
        .copied()
        .filter(|phase| !matches!(*phase, "arrival" | "cascade"));
    BLOCK_IMPORT_PHASES.iter().copied().chain(arrival_leaves)
}

/// Replay every block a corpus at `dir` names, in manifest order, through a
/// freshly bootstrapped store: the warm-up blocks first, unsampled, then the
/// range.
///
/// Aborts on the first block that fails to decode or does not import, rather
/// than recording a partial result and continuing: every later block in a
/// corpus descends from the one before it, so a skip does not leave a
/// shorter valid run behind, it leaves a distribution over blocks applied to
/// the wrong parent.
pub(crate) async fn replay_corpus(dir: &Path, options: &ReplayOptions) -> eyre::Result<Report> {
    let manifest = Manifest::read(dir)?;
    eyre::ensure!(
        manifest.chain == "beacon",
        "corpus holds a {} chain, not a beacon one",
        manifest.chain
    );

    let spec = crate::network::NetworkSpec::parse(&options.network)?;
    let source = crate::network::NetworkSource::resolve(&spec)?;
    let config = source.config().clone();
    let genesis = source.genesis();
    eyre::ensure!(
        manifest.genesis_validators_root == hex_root(genesis.genesis_validators_root),
        "corpus was fetched against a different network: manifest says {}, \
         --network {} has {}",
        manifest.genesis_validators_root,
        options.network,
        hex_root(genesis.genesis_validators_root)
    );

    prepare_data_dir(&options.data_dir, options.force)?;

    let (anchor_state, anchor_block) = read_anchor(dir, &config)?;
    // A corpus fetched before `resolve_anchor` knew this rule can carry an
    // anchor mid-epoch, and would otherwise fail on its first block with an
    // assertion that names neither the anchor nor the fix.
    eyre::ensure!(
        anchor_state.slot() % preset::SLOTS_PER_EPOCH == 0,
        "the corpus's anchor state is at slot {}, which is not the first slot of an epoch, \
         so fork choice cannot anchor on it; re-fetch the corpus with this build",
        anchor_state.slot()
    );
    let backend = Arc::new(RocksDBBackend::open(&options.data_dir).map_err(|err| {
        eyre::eyre!(
            "opening the rocksdb store at {}: {err}",
            options.data_dir.display()
        )
    })?);
    // The same refusal startup makes, so a gloas corpus fails with its real
    // reason rather than partway through replay.
    crate::refuse_unfollowable_fork(anchor_state.fork_name())?;
    let store = fork_choice::get_forkchoice_store(backend, anchor_state, anchor_block, &config)?;
    // A clone, not a borrow: `Store::set_time_ms` writes to the shared
    // backend's metadata, so this clone's write is the write every other
    // handle (including `server`'s own `store` field) reads back. See the
    // module doc for why the clock has to be placed from this store's own
    // `config()` rather than the network-resolved `config` above: the two
    // disagree on `genesis_time`, and only the store's own copy is the one
    // `on_block`'s future-block check actually reads.
    let mut clock = store.clone();
    let mut server =
        BlockChainServer::for_replay(store, None, options.safe_slots_to_import_optimistically);

    let mut samples = Vec::with_capacity(manifest.slots.len());

    let warmup_total = manifest.warmup_slots.len();
    for (position, &slot) in manifest.warmup_slots.iter().enumerate() {
        let (block, block_root) = load_block(dir, &config, &mut clock, slot)?;
        let wall_seconds = import(&mut server, block, slot, block_root).await?;
        eprintln!(
            "warm-up {}/{warmup_total}: slot {slot} imported in {}",
            position + 1,
            format_ms(wall_seconds)
        );
        pause_between_blocks(options.block_delay).await;
    }

    let total = manifest.slots.len();
    for (iteration, &slot) in manifest.slots.iter().enumerate() {
        let (block, block_root) = load_block(dir, &config, &mut clock, slot)?;

        let timer = PhaseTimer::start(IMPORT_PHASE_HISTOGRAM);
        let wall_seconds = import(&mut server, block, slot, block_root).await?;
        let phases = timer.finish_at_most_once(sampled_phases())?;

        eprintln!(
            "block {}/{total}: slot {slot} imported in {}",
            iteration + 1,
            format_ms(wall_seconds)
        );
        samples.push(Sample {
            iteration: iteration as u64,
            slot,
            block_root: hex_root(block_root),
            wall_seconds,
            phases,
            outcome: "imported",
        });
        // After `finish_at_most_once` and the sample are recorded, so the
        // sleep is in no phase delta and no `wall_seconds`.
        pause_between_blocks(options.block_delay).await;
    }

    Ok(Report::new(
        Environment::collect(),
        params_from(&manifest, dir, options.block_delay),
        samples,
    ))
}

/// Read and decode the corpus block at `slot`, and place the store clock at
/// the start of that slot, so the block is neither from the future nor
/// arriving late.
fn load_block(
    dir: &Path,
    config: &Config,
    clock: &mut Store,
    slot: u64,
) -> eyre::Result<(SignedBeaconBlock, H256)> {
    let bytes = std::fs::read(block_path(dir, slot))?;
    let block = decode::decode_block(config, &bytes)
        .map_err(|err| eyre::eyre!("corpus block at slot {slot} does not decode: {err:?}"))?;
    let block_root = block.message_hash_tree_root();

    // `get_forkchoice_store` seeds the store's own genesis_time from the
    // *anchor state's* field, overriding whatever the network-resolved
    // `config` carried (`Store::init_beacon`, `crates/storage/src/store.rs`).
    // Reading it back from `clock.config()` here, rather than from the
    // `config` parameter, is what keeps this arithmetic on the same clock
    // `on_block`'s future-block check reads; computing it from the network's
    // config instead would silently disable that check whenever the two
    // disagree.
    let store_config = clock.config();
    let slot_start_ms = (store_config.genesis_time + slot * store_config.seconds_per_slot) * 1_000;
    clock.set_time_ms(slot_start_ms)?;

    Ok((block, block_root))
}

/// Import one block, returning the wall time of the `import_block` call
/// alone, and fail unless it imported.
async fn import(
    server: &mut BlockChainServer,
    block: SignedBeaconBlock,
    slot: u64,
    block_root: H256,
) -> eyre::Result<f64> {
    let started = Instant::now();
    let outcome = server.import_block(block).await;
    let wall_seconds = started.elapsed().as_secs_f64();
    eyre::ensure!(
        outcome == Some(ImportOutcome::Imported),
        "block at slot {slot} ({}) did not import: {outcome:?}",
        ShortRoot(&block_root.0)
    );
    Ok(wall_seconds)
}

/// Reads and decodes a corpus's anchor pair.
///
/// Mirrors `checkpoint_sync`'s own beacon path: the slot is peeked off the
/// state's own bytes to pick a fork (SSZ carries no type tag), and the
/// anchor block is decoded as a standard signed block, the shape a real
/// fetch (`/eth/v2/beacon/blocks/{id}`) always returns.
fn read_anchor(dir: &Path, config: &Config) -> eyre::Result<(BeaconState, SignedBeaconBlock)> {
    let state_bytes = std::fs::read(dir.join(ANCHOR_STATE_FILE))?;
    let slot = BeaconState::slot_from_ssz(&state_bytes)
        .map_err(|err| eyre::eyre!("anchor state slot does not decode: {err:?}"))?;
    let fork = decode::fork_at_slot(config, slot);
    let anchor_state = BeaconState::from_ssz(fork, &state_bytes)
        .map_err(|err| eyre::eyre!("anchor state does not decode as {fork:?}: {err:?}"))?;

    let block_bytes = std::fs::read(dir.join(ANCHOR_BLOCK_FILE))?;
    let anchor_block = decode::decode_block(config, &block_bytes)
        .map_err(|err| eyre::eyre!("anchor block does not decode: {err}"))?;

    Ok((anchor_state, anchor_block))
}

/// The report parameters a manifest already carries, so the loop above never
/// has to reconstruct them from samples.
fn params_from(manifest: &Manifest, dir: &Path, block_delay_ms: u64) -> Params {
    Params {
        mode: "import",
        corpus: dir.display().to_string(),
        network: manifest.network.clone(),
        anchor_block_root: manifest.anchor_block_root.clone(),
        anchor_slot: manifest.anchor_slot,
        warmup_blocks: manifest.warmup_slots.len(),
        range_start: manifest.range_start,
        range_end: manifest.range_end,
        blocks: manifest.slots.len(),
        block_delay_ms,
    }
}

/// Sleep `delay_ms` so the state writer can drain before the next block.
///
/// Called only between measured spans: a replay feeds blocks back to back,
/// faster than a live node's one block per slot, so without a pause the
/// importer can wait on the writer's queue and measure the writer instead of
/// the import.
async fn pause_between_blocks(delay_ms: u64) {
    if delay_ms > 0 {
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    }
}

/// Refuse a non-empty `data_dir` unless `--force`, which replaces it.
///
/// A stale RocksDB directory left over from a previous run would otherwise
/// resume that run's store, whose anchor may not agree with this corpus's,
/// rather than start the fresh one this replay's report claims to measure.
fn prepare_data_dir(data_dir: &Path, force: bool) -> eyre::Result<()> {
    let occupied = data_dir
        .read_dir()
        .map(|mut entries| entries.next().is_some())
        .unwrap_or(false);
    if occupied {
        eyre::ensure!(
            force,
            "{} already holds data; pass --force to replace it",
            data_dir.display()
        );
        std::fs::remove_dir_all(data_dir)?;
    }
    std::fs::create_dir_all(data_dir)?;
    Ok(())
}
