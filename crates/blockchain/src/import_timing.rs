//! End-to-end timing for one block's journey from the wire to a post-state.
//!
//! # Instants, not durations
//!
//! Every field here is an [`Instant`]: the moment a boundary was crossed.
//! Nothing in this module's capture path subtracts anything. A duration is an
//! interpretation of two timings, and only the consumer knows which pairs are
//! meaningful for the chain, the outcome and the holds a particular block
//! actually went through, so all the arithmetic lives in [`BlockImportReport`]
//! and nowhere else.
//!
//! `None` means the boundary was never crossed. That is what lets one report
//! serve both chains: a lean block leaves every beacon-only instant `None`, a
//! beacon block leaves `verify_*` `None`, and the printed tree simply omits
//! the rows that did not run rather than showing a column of zeros.
//!
//! # Why the holds are `_start`/`_end` pairs
//!
//! A block that is held does not walk the timeline once, it loops. Guards run
//! again for a block held for its parent; the availability check runs again
//! for one held for its custody columns. A single instant per boundary assumes
//! each boundary is crossed exactly once, so a second pass would overwrite the
//! first and the wait would disappear into whichever section straddled it.
//!
//! The three holds therefore carry explicit pairs, and so does every other
//! section, so that no row's meaning depends on which other rows happen to be
//! `Some`. A section that repeats keeps its first start and its last end; the
//! per-section timings of an abandoned pass are overwritten by the final pass,
//! which is why a held block's rows sum to slightly less than its end-to-end
//! time.
//!
//! # What the clock covers
//!
//! End to end is measured from the first instant recorded through to the last.
//! It deliberately spans holds: a block that waited two slots for its parent
//! reports those two slots, with a `parent_wait` row accounting for them.
//!
//! Where that first instant is depends on how the block arrived, because only
//! one path decodes a block itself:
//!
//! - **gossip** starts at `decode_start`, the moment the payload came off the
//!   wire, and so reports a `decode` row covering decompression and SSZ.
//! - **req/resp** starts at `queue_start`, the hand-off to this actor. Its
//!   codec had already turned the bytes into a block before any handler saw
//!   one, so there is no decode boundary left to take and the path reports no
//!   `decode` row at all. A zero would be worse than nothing: it reads as free
//!   work rather than as unmeasured work, and it would drag the decode
//!   histogram down with samples that measured nothing.
//! - **storage** (an ancestor walk pulling a block out of RocksDB, or a
//!   locally built one) starts at the pull, since no earlier moment is
//!   knowable.
//!
//! One consequence worth keeping in mind when reading the numbers: a gossip
//! block's total and a fetched block's total do not start at the same point in
//! the block's life, and a fetched block's total excludes the request round
//! trip entirely.

use std::time::{Duration, Instant};

use ethlambda_network_api::BlockSource;

use crate::metrics;
use ethlambda_types::{ShortRoot, primitives::H256};
use tracing::info;

/// Timings taken inside lean's `store::on_block`.
///
/// Separate from [`ImportTimings`] so that `store.rs` fills in only the
/// boundaries it owns and knows nothing about the arrival, hold and beacon
/// sections wrapped around it. The caller folds these in with
/// [`ImportTimings::absorb_store`].
#[derive(Debug, Clone, Copy, Default)]
pub struct StoreTimings {
    pub guards_start: Option<Instant>,
    pub guards_end: Option<Instant>,
    pub verify_structural_start: Option<Instant>,
    pub verify_structural_end: Option<Instant>,
    pub verify_crypto_start: Option<Instant>,
    pub verify_crypto_end: Option<Instant>,
    pub stf_start: Option<Instant>,
    pub stf_end: Option<Instant>,
    pub db_write_start: Option<Instant>,
    pub db_write_end: Option<Instant>,
    pub fc_head_start: Option<Instant>,
    pub fc_head_end: Option<Instant>,
}

/// Timings taken inside `store::verify_block_signatures`.
///
/// Returned rather than logged so the one caller that is not the import path
/// (the Hive test driver's `verify_signatures` endpoint) can ignore them.
#[derive(Debug, Clone, Copy, Default)]
pub struct VerifyTimings {
    pub structural_start: Option<Instant>,
    pub structural_end: Option<Instant>,
    pub crypto_start: Option<Instant>,
    pub crypto_end: Option<Instant>,
}

/// Every boundary one block crosses on its way to a post-state.
///
/// Carried alongside the block itself: through the actor mailbox in
/// `NewBlock`, through a hold in `BlockChainServer::held_timings`, and through
/// the import cascade's own queue. See the module documentation for why the
/// fields are timings rather than durations, and why the holds are pairs.
#[derive(Debug, Clone, Copy, Default)]
pub struct ImportTimings {
    /// How the block reached this node. Not a mark, but it travels with them
    /// for the same reason they do: only the arriving message knows it, and
    /// the report is built long after that message is gone.
    pub source: Option<BlockSource>,

    // --- Off-actor: the p2p side and the mailbox hop. ---
    /// The payload came off the wire, before decompression.
    pub decode_start: Option<Instant>,
    /// The block is decoded and about to be handed to the chain actor.
    pub decode_end: Option<Instant>,
    /// Handed to the actor.
    pub queue_start: Option<Instant>,
    /// The actor took the message off its mailbox.
    pub queue_end: Option<Instant>,

    // --- Hold: the block's slot has not started yet (beacon). ---
    pub defer_start: Option<Instant>,
    pub defer_end: Option<Instant>,

    /// What the mailbox handler did before handing the block to the import
    /// path: the gossip bookkeeping, the early-slot decision, and the
    /// store-clock catch-up, which can run a whole tick.
    pub admit_start: Option<Instant>,
    pub admit_end: Option<Instant>,

    // --- Hold: the parent has no post-state. ---
    pub parent_wait_start: Option<Instant>,
    pub parent_wait_end: Option<Instant>,

    /// From the parent's import completing to this block being popped off the
    /// cascade queue. Nonzero when one arrival unblocks several children and
    /// this one was not first in line.
    pub cascade_wait_start: Option<Instant>,
    pub cascade_wait_end: Option<Instant>,

    // --- The import pass proper. Overwritten by each pass, so these are the
    // --- final, successful pass's timings.
    /// Finality and future-slot guards, the already-imported check and the
    /// parent-state lookup, all of which run before the import call.
    ///
    /// Re-marked from scratch on every pass, not carried: a block held for its
    /// parent runs these again when it comes back, and keeping the first
    /// pass's start would stretch this section across the whole hold and
    /// double-count what `parent_wait` already reports.
    pub guards_start: Option<Instant>,
    pub guards_end: Option<Instant>,

    /// Lean: the checks `store::on_block` makes of its own before verifying
    /// anything, including loading the parent state and scanning the block for
    /// duplicate attestation data.
    pub preamble_start: Option<Instant>,
    pub preamble_end: Option<Instant>,

    /// Beacon: the custody-column availability check itself, not the wait.
    pub da_check_start: Option<Instant>,
    pub da_check_end: Option<Instant>,

    // --- Hold: custody columns have not all arrived (beacon). ---
    pub columns_wait_start: Option<Instant>,
    pub columns_wait_end: Option<Instant>,

    /// Beacon: the `engine_newPayload` round trip, including its retry ladder.
    /// I/O wait, not work.
    pub engine_start: Option<Instant>,
    pub engine_end: Option<Instant>,

    /// Lean: participant bounds checks and pubkey resolution.
    pub verify_structural_start: Option<Instant>,
    pub verify_structural_end: Option<Instant>,
    /// Lean: the leanVM multi-message aggregate verification.
    pub verify_crypto_start: Option<Instant>,
    pub verify_crypto_end: Option<Instant>,

    /// The state transition. On beacon this is `fork_choice::on_block`, which
    /// bundles the transition, the state root and the state write, so
    /// `db_write` stays `None` there.
    pub stf_start: Option<Instant>,
    pub stf_end: Option<Instant>,

    /// Lean: the block and post-state writes.
    pub db_write_start: Option<Instant>,
    pub db_write_end: Option<Instant>,

    /// Lean: `update_head`.
    pub fc_head_start: Option<Instant>,
    pub fc_head_end: Option<Instant>,

    /// Beacon: replaying the block's own attestations and slashings into fork
    /// choice, including the `LiveChain` scan they share.
    pub block_atts_start: Option<Instant>,
    pub block_atts_end: Option<Instant>,

    /// Whether every custody column for this block was already present the
    /// first time the block was looked at, before the parent check.
    ///
    /// This is what separates the two readings of an absent `columns_wait`
    /// row. `Some(true)`: the columns were never missing. `Some(false)` with
    /// no `columns_wait`: they landed while the block was held for its parent,
    /// so availability finished first. `None` on lean, which custodies none.
    pub da_complete_on_arrival: Option<bool>,
}

impl ImportTimings {
    /// The `source` label this block reports under, or `None` for a block
    /// that is not reported at all.
    ///
    /// Two values reach the metric, `gossip` and `sync`, and the two that do
    /// not are deliberate.
    ///
    /// [`BlockSource::Deferred`] never appears. It says how a block reached
    /// the actor this time, not how it reached the node, and a deferred block
    /// is a gossip or sync block that waited: reporting it separately would
    /// take it out of the population it belongs to, and the wait is already
    /// its own `defer` section. `Handler<NewBlock>` resolves it back to the
    /// source the block first arrived on before these timings are built, so a
    /// `Deferred` reaching here would be a defect rather than a case to label.
    ///
    /// A block this node built itself is not reported either: it crossed no
    /// wire, so its `decode` and `queue` sections are zeroes taken at the
    /// moment the import began, and mixing those into a wire source's
    /// percentiles would understate it.
    pub fn source_label(&self) -> Option<&'static str> {
        match self.source {
            Some(BlockSource::Gossip) => Some("gossip"),
            Some(BlockSource::Sync) => Some("sync"),
            Some(BlockSource::Deferred) | None => None,
        }
    }

    /// What the log calls this block's source, which unlike the metric label
    /// has a name for every case, a line costing nothing to write.
    pub fn source_name(&self) -> &'static str {
        match self.source {
            Some(BlockSource::Gossip) => "gossip",
            Some(BlockSource::Sync) => "sync",
            Some(BlockSource::Deferred) => "deferred",
            None => "local",
        }
    }

    /// Timings for a block whose earliest knowable moment is now.
    ///
    /// Used where a block enters the import path from storage rather than the
    /// wire: the ancestor walk in `process_or_pend_block`, and a locally built
    /// block being imported by its own proposer.
    pub fn starting_now() -> Self {
        let now = Instant::now();
        Self {
            // No decode: the block was already a block. Only `queue`, and an
            // empty one, so the report has a clock to start from.
            queue_start: Some(now),
            queue_end: Some(now),
            ..Self::default()
        }
    }

    /// Charge the bookkeeping that follows an import to whichever section it
    /// follows, by moving that section's end.
    ///
    /// Event emission, the finality eviction sweep and the gauge refresh used
    /// to be three sections of their own. Across 5248 imports on a mainnet
    /// follower none of them ever reached a millisecond, so they were three
    /// rows that never moved in every tree printed, and three label values on
    /// a histogram that never said anything. The work still happens and is
    /// still counted; it is simply counted where it happens, at the end of the
    /// last section that ran, which is `fc_head` on lean and `block_atts` on
    /// beacon.
    ///
    /// Extending the last section rather than the first keeps the sections
    /// contiguous: whatever ran last is what this follows.
    pub fn absorb_tail(&mut self, end: Instant) {
        let last = [
            &mut self.block_atts_end,
            &mut self.fc_head_end,
            &mut self.db_write_end,
            &mut self.stf_end,
        ]
        .into_iter()
        .filter(|slot| slot.is_some())
        .max_by_key(|slot| slot.expect("just filtered"));
        if let Some(slot) = last {
            *slot = Some(end);
        }
    }

    /// Fold in the timings lean's `store::on_block` took.
    pub fn absorb_store(&mut self, store: StoreTimings) {
        // Into `preamble`, not `guards`: the outer guards are this actor's own
        // and have already been marked by the time the store is called.
        self.preamble_start = store.guards_start;
        self.preamble_end = store.guards_end;
        self.verify_structural_start = store.verify_structural_start;
        self.verify_structural_end = store.verify_structural_end;
        self.verify_crypto_start = store.verify_crypto_start;
        self.verify_crypto_end = store.verify_crypto_end;
        self.stf_start = store.stf_start;
        self.stf_end = store.stf_end;
        self.db_write_start = store.db_write_start;
        self.db_write_end = store.db_write_end;
        self.fc_head_start = store.fc_head_start;
        self.fc_head_end = store.fc_head_end;
    }

    /// Fold in the timings `store::verify_block_signatures` took.
    pub fn absorb_verify(&mut self, verify: VerifyTimings) {
        self.verify_structural_start = verify.structural_start;
        self.verify_structural_end = verify.structural_end;
        self.verify_crypto_start = verify.crypto_start;
        self.verify_crypto_end = verify.crypto_end;
    }

    /// The first moment recorded, which is where end to end starts.
    ///
    /// Not always `decode_start`: only the gossip path decodes the block
    /// itself, so a fetched or replayed block's timeline begins at the moment
    /// it was handed to this actor.
    fn first_instant(&self) -> Option<Instant> {
        self.decode_start.or(self.queue_start)
    }

    /// The last moment recorded, whichever section it belongs to.
    fn last_instant(&self) -> Option<Instant> {
        self.rows()
            .into_iter()
            .filter_map(|row| row.end)
            .max()
            .or_else(|| self.first_instant())
    }

    /// Every section, in the order a block crosses them, whether or not it
    /// crossed this one.
    fn rows(&self) -> Vec<Row> {
        vec![
            Row::new("decode", self.decode_start, self.decode_end),
            Row::new("queue", self.queue_start, self.queue_end),
            Row::new("defer", self.defer_start, self.defer_end),
            Row::new("admit", self.admit_start, self.admit_end),
            Row::new("guards", self.guards_start, self.guards_end),
            Row::new("preamble", self.preamble_start, self.preamble_end),
            Row::new("parent_wait", self.parent_wait_start, self.parent_wait_end),
            Row::new(
                "cascade_wait",
                self.cascade_wait_start,
                self.cascade_wait_end,
            ),
            Row::new("da_check", self.da_check_start, self.da_check_end),
            Row::new(
                "columns_wait",
                self.columns_wait_start,
                self.columns_wait_end,
            ),
            Row::new("engine", self.engine_start, self.engine_end),
            Row::new(
                "verify_struct",
                self.verify_structural_start,
                self.verify_structural_end,
            ),
            Row::new(
                "verify_crypto",
                self.verify_crypto_start,
                self.verify_crypto_end,
            ),
            Row::new("stf", self.stf_start, self.stf_end),
            Row::new("db_write", self.db_write_start, self.db_write_end),
            Row::new("fc_head", self.fc_head_start, self.fc_head_end),
            Row::new("block_atts", self.block_atts_start, self.block_atts_end),
        ]
    }
}

/// One section of the timeline, resolved from its two timings.
#[derive(Debug, Clone, Copy)]
struct Row {
    name: &'static str,
    end: Option<Instant>,
    elapsed: Option<Duration>,
}

impl Row {
    fn new(name: &'static str, start: Option<Instant>, end: Option<Instant>) -> Self {
        let elapsed = match (start, end) {
            // `saturating_duration_since` rather than `-`: a pair of instants can
            // arrive out of order if a section's end was recorded on an
            // earlier pass than its start, and a panic in a logging path would
            // be a far worse outcome than a zero.
            (Some(start), Some(end)) => Some(end.saturating_duration_since(start)),
            _ => None,
        };
        Self { name, end, elapsed }
    }
}

/// One block's timings plus the context needed to make sense of them.
///
/// This is where every subtraction happens. Built at the end of an import,
/// consumed immediately by [`Self::log`].
pub struct BlockImportReport {
    pub slot: u64,
    pub block_root: H256,
    pub attestations: usize,
    /// What became of the block: `"imported"`, `"held"` or `"failed"`.
    pub outcome: &'static str,
    /// Milliseconds into its own slot at which the import finished, when the
    /// caller could work it out.
    pub slot_offset_ms: Option<i64>,
    pub timings: ImportTimings,
}

impl BlockImportReport {
    /// Total wall time from the payload leaving the wire to the last mark.
    pub fn end_to_end(&self) -> Option<Duration> {
        match (self.timings.first_instant(), self.timings.last_instant()) {
            (Some(start), Some(end)) => Some(end.saturating_duration_since(start)),
            _ => None,
        }
    }

    /// The tree's child lines, one per section that ran.
    ///
    /// Split from [`Self::log`] so the rendering can be asserted without a
    /// tracing subscriber: this is a pure function of the timings, and it is
    /// where every subtraction that reaches an operator's eyes happens.
    pub fn lines(&self) -> Vec<String> {
        let Some(e2e) = self.end_to_end() else {
            return Vec::new();
        };
        let rows: Vec<Row> = self
            .timings
            .rows()
            .into_iter()
            .filter(|row| row.elapsed.is_some())
            .collect();
        let Some(bottleneck) = rows
            .iter()
            .max_by_key(|row| row.elapsed.unwrap_or_default())
            .map(|row| row.name)
        else {
            return Vec::new();
        };

        let e2e_ms = ms(e2e);
        let last = rows.len() - 1;
        rows.iter()
            .enumerate()
            .map(|(index, row)| {
                let elapsed_ms = ms(row.elapsed.unwrap_or_default());
                let share = if e2e_ms > 0.0 {
                    (elapsed_ms / e2e_ms * 100.0).round() as u64
                } else {
                    0
                };
                let branch = if index == last { '`' } else { '|' };
                let marker = if row.name == bottleneck {
                    " << BOTTLENECK"
                } else {
                    ""
                };
                format!(
                    "  {branch}- {name:<13} {elapsed_ms:>9.2} ms  ({share:>2}%){marker}",
                    name = row.name,
                )
            })
            .collect()
    }

    /// The section that took longest, which is the one worth reading first.
    fn bottleneck(&self) -> Option<&'static str> {
        self.timings
            .rows()
            .into_iter()
            .filter(|row| row.elapsed.is_some())
            .max_by_key(|row| row.elapsed.unwrap_or_default())
            .map(|row| row.name)
    }

    /// Publish this block's sections to Prometheus.
    ///
    /// Separate from [`Self::log`] so the two can be reasoned about apart: the
    /// log is for the operator reading one block, this is for the dashboard
    /// reading a million. A section that did not run writes nothing rather
    /// than a zero, so a lean node never creates the beacon-only series.
    pub fn observe(&self) {
        let Some(source) = self.timings.source_label() else {
            return;
        };
        for row in self.timings.rows() {
            if let Some(elapsed) = row.elapsed {
                metrics::observe_block_import_phase(row.name, source, elapsed);
            }
        }
        // Only a finished import has a total. A held block's sections are all
        // real and are published above, but the span from the wire to wherever
        // it stopped is not an import time, and publishing it as one is what an
        // `outcome` label would have had to exist to undo.
        if self.outcome == "imported"
            && let Some(e2e) = self.end_to_end()
        {
            metrics::observe_block_import_phase(metrics::BLOCK_IMPORT_TOTAL_PHASE, source, e2e);
        }
    }

    /// Emit the tree.
    ///
    /// The header carries the fields worth querying; the child lines are for
    /// reading. Rows that never ran are omitted, so a lean block prints no
    /// beacon sections and vice versa.
    pub fn log(&self) {
        let Some(e2e) = self.end_to_end() else {
            return;
        };
        let lines = self.lines();
        if lines.is_empty() {
            return;
        }

        info!(
            slot = self.slot,
            block_root = %ShortRoot(&self.block_root.0),
            source = self.timings.source_name(),
            outcome = self.outcome,
            attestations = self.attestations,
            e2e_ms = format_args!("{:.2}", ms(e2e)),
            slot_offset_ms = self.slot_offset_ms,
            bottleneck = self.bottleneck(),
            da_complete_on_arrival = self.timings.da_complete_on_arrival,
            "Block import timing"
        );
        for line in lines {
            info!("{line}");
        }
    }
}

/// Timings taken once per arrival rather than once per block, so a cascade that
/// imports six children charges them once.
#[derive(Debug, Clone, Copy, Default)]
pub struct CascadeTimings {
    /// The `source` of the block whose arrival opened this cascade. Set by
    /// `on_block` from the arriving block's own timings.
    pub source: Option<BlockSource>,
    pub cascade_start: Option<Instant>,
    pub cascade_end: Option<Instant>,
    pub prune_start: Option<Instant>,
    pub prune_end: Option<Instant>,
    pub head_start: Option<Instant>,
    pub head_end: Option<Instant>,
    pub fcu_start: Option<Instant>,
    pub fcu_end: Option<Instant>,
}

/// Timings taken while re-running beacon fork choice after an import.
///
/// Returned by `recompute_beacon_head` rather than written through a borrow,
/// because its other caller is the tick, which has no report to put them in.
#[derive(Debug, Clone, Copy, Default)]
pub struct HeadTimings {
    pub head_start: Option<Instant>,
    pub head_end: Option<Instant>,
    pub fcu_start: Option<Instant>,
    pub fcu_end: Option<Instant>,
}

impl CascadeTimings {
    pub fn absorb_head(&mut self, head: HeadTimings) {
        self.head_start = head.head_start;
        self.head_end = head.head_end;
        self.fcu_start = head.fcu_start;
        self.fcu_end = head.fcu_end;
    }

    pub fn starting_now() -> Self {
        Self {
            cascade_start: Some(Instant::now()),
            ..Self::default()
        }
    }

    /// Publish the arrival-scope sections.
    ///
    /// `cascade` is the whole drain, which is why it is a phase here rather
    /// than the sum of the per-block metrics: those are per block, this is per
    /// arrival, and dividing one by the other's count is the mistake keeping
    /// them in separate metrics prevents.
    pub fn observe(&self, blocks: usize) {
        let source = match self.source {
            Some(BlockSource::Gossip) => "gossip",
            Some(BlockSource::Sync) => "sync",
            // Same two exclusions a block's own sections make; see
            // `ImportTimings::source_label`.
            Some(BlockSource::Deferred) | None => return,
        };
        metrics::observe_block_import_cascade_blocks(blocks);

        // The whole time this arrival held the actor: from the cascade opening
        // to the last thing done on its behalf, which is the head recomputation
        // when there is one and the prune otherwise.
        let last = [
            self.fcu_end,
            self.head_end,
            self.prune_end,
            self.cascade_end,
        ]
        .into_iter()
        .flatten()
        .max();
        for (phase, elapsed) in [
            ("arrival", span(self.cascade_start, last)),
            ("cascade", span(self.cascade_start, self.cascade_end)),
            ("prune", span(self.prune_start, self.prune_end)),
            ("get_head", span(self.head_start, self.head_end)),
            ("fcu", span(self.fcu_start, self.fcu_end)),
        ] {
            if let Some(elapsed) = elapsed {
                metrics::observe_block_import_phase(phase, source, elapsed);
            }
        }
    }

    /// Emit the one-line arrival summary.
    ///
    /// Skipped for the ordinary case of a single block with nothing after it:
    /// the per-block tree already said everything, and one line per block is
    /// enough without a second that repeats it.
    pub fn log(&self, blocks: usize) {
        let cascade = span(self.cascade_start, self.cascade_end);
        let prune = span(self.prune_start, self.prune_end);
        let head = span(self.head_start, self.head_end);
        let fcu = span(self.fcu_start, self.fcu_end);
        if blocks <= 1 && prune.is_none() && head.is_none() && fcu.is_none() {
            return;
        }
        let Some(cascade) = cascade else {
            return;
        };
        info!(
            blocks,
            cascade_ms = format_args!("{:.2}", ms(cascade)),
            prune_ms = prune.map(|d| format!("{:.2}", ms(d))),
            get_head_ms = head.map(|d| format!("{:.2}", ms(d))),
            fcu_ms = fcu.map(|d| format!("{:.2}", ms(d))),
            "Block arrival timing"
        );
    }
}

fn span(start: Option<Instant>, end: Option<Instant>) -> Option<Duration> {
    match (start, end) {
        (Some(start), Some(end)) => Some(end.saturating_duration_since(start)),
        _ => None,
    }
}

fn ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pair of instants whose start is `offset_ms` after `base` and which lasts
    /// `len_ms`.
    fn pair(base: Instant, offset_ms: u64, len_ms: u64) -> (Option<Instant>, Option<Instant>) {
        let start = base + Duration::from_millis(offset_ms);
        (Some(start), Some(start + Duration::from_millis(len_ms)))
    }

    #[test]
    fn rows_omit_sections_that_never_ran() {
        let base = Instant::now();
        let mut timings = ImportTimings::default();
        (timings.decode_start, timings.decode_end) = pair(base, 0, 3);
        (timings.stf_start, timings.stf_end) = pair(base, 3, 90);

        let present: Vec<&str> = timings
            .rows()
            .into_iter()
            .filter(|row| row.elapsed.is_some())
            .map(|row| row.name)
            .collect();
        assert_eq!(present, vec!["decode", "stf"]);
    }

    #[test]
    fn end_to_end_spans_a_parent_hold() {
        let base = Instant::now();
        let mut timings = ImportTimings::default();
        (timings.decode_start, timings.decode_end) = pair(base, 0, 3);
        // Held two whole slots waiting for a parent.
        (timings.parent_wait_start, timings.parent_wait_end) = pair(base, 3, 8_000);
        (timings.stf_start, timings.stf_end) = pair(base, 8_003, 90);

        let report = report(timings);
        let e2e = report.end_to_end().expect("both ends are marked");
        assert_eq!(e2e, Duration::from_millis(8_093));
    }

    #[test]
    fn the_two_waits_are_reported_separately() {
        let base = Instant::now();
        let mut timings = ImportTimings::default();
        (timings.decode_start, timings.decode_end) = pair(base, 0, 1);
        (timings.parent_wait_start, timings.parent_wait_end) = pair(base, 1, 1_200);
        (timings.columns_wait_start, timings.columns_wait_end) = pair(base, 1_300, 800);

        let waits: Vec<(&str, u128)> = timings
            .rows()
            .into_iter()
            .filter(|row| row.name.ends_with("_wait"))
            .filter_map(|row| row.elapsed.map(|d| (row.name, d.as_millis())))
            .collect();
        assert_eq!(
            waits,
            vec![("parent_wait", 1_200), ("columns_wait", 800)],
            "a parent hold and a column hold must never collapse into one row"
        );
    }

    #[test]
    fn an_out_of_order_pair_reports_zero_rather_than_panicking() {
        let base = Instant::now();
        let timings = ImportTimings {
            stf_start: Some(base + Duration::from_millis(10)),
            stf_end: Some(base),
            ..ImportTimings::default()
        };

        let row = timings
            .rows()
            .into_iter()
            .find(|row| row.name == "stf")
            .expect("stf row exists");
        assert_eq!(row.elapsed, Some(Duration::ZERO));
    }

    #[test]
    fn a_block_with_no_timings_produces_no_report() {
        let report = report(ImportTimings::default());
        assert!(report.end_to_end().is_none());
    }

    #[test]
    fn starting_now_anchors_the_clock_without_claiming_a_decode() {
        let timings = ImportTimings::starting_now();
        assert!(timings.decode_start.is_none());
        assert!(timings.queue_start.is_some());
        assert!(report(timings).end_to_end().is_some());
    }

    /// Only gossip decodes the block itself. A fetched one has no decode to
    /// report, and reporting a zero would put it in the decode histogram as
    /// free work rather than leaving it out.
    #[test]
    fn a_block_this_node_did_not_decode_starts_its_clock_at_the_mailbox() {
        let base = Instant::now();
        let mut timings = ImportTimings {
            source: Some(BlockSource::Sync),
            ..Default::default()
        };
        (timings.queue_start, timings.queue_end) = pair(base, 0, 40);
        (timings.stf_start, timings.stf_end) = pair(base, 40, 15);

        let report = report(timings);
        assert_eq!(report.end_to_end(), Some(Duration::from_millis(55)));
        let names: Vec<&str> = report
            .timings
            .rows()
            .into_iter()
            .filter(|row| row.elapsed.is_some())
            .map(|row| row.name)
            .collect();
        assert_eq!(names, vec!["queue", "stf"]);
    }

    #[test]
    fn the_tail_extends_the_last_section_that_ran() {
        let base = Instant::now();
        let tail_end = base + Duration::from_millis(110);

        // Lean: the last section is fc_head.
        let mut lean = ImportTimings::default();
        (lean.stf_start, lean.stf_end) = pair(base, 0, 90);
        (lean.db_write_start, lean.db_write_end) = pair(base, 90, 10);
        (lean.fc_head_start, lean.fc_head_end) = pair(base, 100, 5);
        lean.absorb_tail(tail_end);
        assert_eq!(
            lean.fc_head_end,
            Some(tail_end),
            "lean charges it to fc_head"
        );
        assert_eq!(
            lean.db_write_end,
            Some(base + Duration::from_millis(100)),
            "the sections before it are untouched"
        );

        // Beacon: the last section is block_atts, and there is no db_write or
        // fc_head to confuse it with.
        let mut beacon = ImportTimings::default();
        (beacon.stf_start, beacon.stf_end) = pair(base, 0, 90);
        (beacon.block_atts_start, beacon.block_atts_end) = pair(base, 90, 15);
        beacon.absorb_tail(tail_end);
        assert_eq!(beacon.block_atts_end, Some(tail_end));
        assert_eq!(beacon.stf_end, Some(base + Duration::from_millis(90)));
    }

    #[test]
    fn the_tail_of_an_import_that_ran_nothing_lands_nowhere() {
        // A re-delivered block whose post-state the store already held runs no
        // section at all, so there is nothing for the tail to extend and it
        // must not invent one.
        let mut timings = ImportTimings::default();
        timings.absorb_tail(Instant::now());
        assert!(timings.rows().into_iter().all(|row| row.elapsed.is_none()));
    }

    #[test]
    fn every_row_is_a_declared_phase_label() {
        let rows: Vec<&str> = ImportTimings::default()
            .rows()
            .into_iter()
            .map(|row| row.name)
            .collect();
        assert_eq!(
            rows,
            crate::metrics::BLOCK_IMPORT_PHASES,
            "the tree's sections and the metric's per-block `phase` labels are the same list \
             in the same order: a row added to one without the other either logs a section no \
             dashboard can find or declares a series nothing writes"
        );
    }

    #[test]
    fn a_locally_built_block_is_logged_but_not_measured() {
        let local = ImportTimings::default();
        assert_eq!(local.source_label(), None, "nothing to compare it against");
        assert_eq!(local.source_name(), "local", "still worth printing");
    }

    #[test]
    fn a_deferred_block_never_reaches_the_metric_as_its_own_source() {
        // `Handler<NewBlock>` resolves the re-delivery back to the source the
        // block first arrived on, so this state should not occur; if it ever
        // does, it must not open a third series.
        let deferred = ImportTimings {
            source: Some(BlockSource::Deferred),
            ..ImportTimings::default()
        };
        assert_eq!(deferred.source_label(), None);
        assert_eq!(deferred.source_name(), "deferred");
    }

    #[test]
    fn a_held_block_does_not_charge_its_wait_to_guards_as_well() {
        let base = Instant::now();
        let mut timings = ImportTimings::default();
        (timings.decode_start, timings.decode_end) = pair(base, 0, 1);
        // First pass: guards ran, then the block was held for its parent.
        (timings.guards_start, timings.guards_end) = pair(base, 1, 2);
        (timings.parent_wait_start, timings.parent_wait_end) = pair(base, 3, 8_000);
        // Second pass re-marks guards from scratch rather than keeping the
        // first pass's start, which would otherwise span the whole hold.
        (timings.guards_start, timings.guards_end) = pair(base, 8_003, 2);
        (timings.stf_start, timings.stf_end) = pair(base, 8_005, 90);

        let rows: Vec<(&str, u128)> = timings
            .rows()
            .into_iter()
            .filter_map(|row| row.elapsed.map(|d| (row.name, d.as_millis())))
            .collect();
        assert!(
            rows.contains(&("guards", 2)),
            "guards is one pass's worth, not the span across the hold: {rows:?}"
        );
        assert!(rows.contains(&("parent_wait", 8_000)));
        let total: u128 = rows.iter().map(|(_, ms)| ms).sum();
        assert!(
            total <= 8_095,
            "the sections must not sum past the end-to-end span: {rows:?}"
        );
    }

    #[test]
    fn only_a_finished_import_reports_a_total() {
        let base = Instant::now();
        let mut timings = ImportTimings {
            source: Some(BlockSource::Gossip),
            ..ImportTimings::default()
        };
        (timings.decode_start, timings.decode_end) = pair(base, 0, 3);
        (timings.columns_wait_start, timings.columns_wait_end) = pair(base, 3, 4_000);

        let mut held = report(timings);
        held.outcome = "held";
        assert!(
            held.end_to_end().is_some(),
            "the span exists and the log prints it"
        );
        // What `observe` does with it is the point: a held block publishes its
        // sections and no total, which is what keeps a four-second wait out of
        // the import-cost percentiles without an `outcome` label.
        assert_ne!(held.outcome, "imported");
    }

    #[test]
    fn renders_a_tree_with_the_slowest_section_marked() {
        let base = Instant::now();
        let mut timings = ImportTimings {
            source: Some(BlockSource::Gossip),
            ..ImportTimings::default()
        };
        (timings.decode_start, timings.decode_end) = pair(base, 0, 3);
        (timings.queue_start, timings.queue_end) = pair(base, 3, 18);
        (timings.verify_crypto_start, timings.verify_crypto_end) = pair(base, 21, 609);
        (timings.stf_start, timings.stf_end) = pair(base, 630, 94);

        let lines = report(timings).lines();
        assert_eq!(lines.len(), 4, "one line per section that ran");
        assert!(lines[0].contains("decode"), "sections keep timeline order");
        assert!(
            lines[0].starts_with("  |-"),
            "every line but the last branches"
        );
        assert!(
            lines[3].starts_with("  `-"),
            "the last line closes the tree"
        );
        assert!(
            lines[2].contains("verify_crypto") && lines[2].ends_with("<< BOTTLENECK"),
            "the slowest section is the marked one, got: {}",
            lines[2]
        );
        assert_eq!(
            lines
                .iter()
                .filter(|line| line.contains("BOTTLENECK"))
                .count(),
            1,
            "exactly one section is marked"
        );
    }

    #[test]
    fn a_report_with_nothing_to_say_renders_nothing() {
        assert!(report(ImportTimings::default()).lines().is_empty());
    }

    fn report(timings: ImportTimings) -> BlockImportReport {
        BlockImportReport {
            slot: 12_345,
            block_root: H256::ZERO,
            attestations: 42,
            outcome: "imported",
            slot_offset_ms: Some(2_812),
            timings,
        }
    }
}
