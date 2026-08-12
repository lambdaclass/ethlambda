//! Bring a restarted node's execution layer back in step with the consensus
//! chain, by replaying the payloads it has not executed yet.
//!
//! # Why this exists
//!
//! Block import is gated on execution: `import_gossiped_block` drops any block
//! whose payload the execution layer rejects. So an execution layer that is
//! behind the consensus chain is not a degraded state — it is terminal. Every
//! arriving block names a parent the execution layer does not have, fails with
//! `ParentNotFound`, and is dropped before the store sees it. The node stops
//! following the chain permanently, and no amount of checkpoint syncing helps:
//! that moves the consensus head *further* ahead, widening the gap.
//!
//! Persisting execution state alongside the consensus store removes the common
//! cause (a restart), but not every cause: the two stores are written
//! independently, so a crash between them, an operator wiping one, or a
//! consensus store restored from a checkpoint can all leave a gap.
//!
//! # How
//!
//! The Lean chain already contains every `ExecutionPayloadV3` in its block
//! bodies, so it *is* a complete execution-layer history — no new wire protocol
//! and no peers needed. Walk back from the consensus head until reaching a block
//! the execution layer already has, then replay forward from there.
//!
//! The cost is bounded by the size of the gap, not the length of the chain: a
//! node whose execution state is current walks back exactly one block and
//! replays nothing.

use ethlambda_ethrex_engine::EthrexEngine;
use ethlambda_storage::Store;
use ethlambda_types::{ShortRoot, block::Block};
use tracing::{info, warn};

/// Outcome of a resync attempt, for logging and tests.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ResyncReport {
    /// Payloads executed to close the gap.
    pub replayed: usize,
    /// Blocks skipped because their payload carries no execution-layer block —
    /// the pass-through shape a proposer emits when its own build failed.
    pub skipped: usize,
    /// True when the walk ran out of consensus blocks before reaching one the
    /// execution layer had, so the gap could not be closed.
    pub incomplete: bool,
}

/// Replay the payloads between the execution layer's head and the consensus
/// head.
///
/// Returns what it did. Never fails the caller: a node that cannot close the gap
/// should start and say so loudly rather than refuse to boot, since the operator
/// may be deliberately reusing a datadir.
pub async fn resync_execution_layer(store: &Store, engine: &EthrexEngine) -> ResyncReport {
    let mut report = ResyncReport::default();

    let head_root = match store.head() {
        Ok(root) if !root.is_zero() => root,
        // No consensus head yet (fresh genesis): nothing to replay.
        _ => return report,
    };

    // Walk back along parent links, collecting blocks the execution layer is
    // missing. Stops at the first block it already has, which is the common
    // ancestor of the two views.
    let mut missing: Vec<Block> = Vec::new();
    let mut root = head_root;
    loop {
        let block = match store.get_block(&root) {
            Ok(Some(block)) => block,
            Ok(None) | Err(_) => {
                // Ran out of history without meeting the execution layer. Only
                // reachable when the consensus store does not go back far enough
                // — a checkpoint-synced node, or a partially pruned datadir.
                report.incomplete = true;
                break;
            }
        };

        let payload_hash = block.body.execution_payload.block_hash;
        match engine.can_build_on(payload_hash).await {
            Ok(true) => break,
            Ok(false) => {}
            Err(err) => {
                warn!(%err, "Could not query the execution layer; skipping resync");
                return report;
            }
        }

        let parent_root = block.parent_root;
        missing.push(block);
        if parent_root.is_zero() {
            // Reached the anchor. Its payload is the EL genesis, which the
            // engine always has, so this means the chain does not link back to
            // the execution layer's genesis at all.
            report.incomplete = true;
            break;
        }
        root = parent_root;
    }

    if missing.is_empty() && !report.incomplete {
        // Logged even though there is nothing to do. "No output" is the same
        // thing an accidentally-skipped resync produces, and telling those two
        // apart from a log file afterwards is worth one line at startup.
        info!(
            head_slot = store.head_slot(),
            "Execution layer is in step with the consensus chain"
        );
        return report;
    }

    info!(
        blocks = missing.len(),
        head_slot = store.head_slot(),
        "Execution layer is behind the consensus chain; replaying payloads"
    );

    // Oldest first: each payload extends the one before it.
    for block in missing.iter().rev() {
        let payload = &block.body.execution_payload;

        // A pass-through payload repeats its parent hash instead of naming a new
        // execution-layer block: the proposer's build failed and no block was
        // produced. There is nothing to execute, and trying would fail the
        // block-hash check.
        if payload.block_hash == payload.parent_hash {
            report.skipped += 1;
            continue;
        }

        if let Err(err) = engine.execute_payload(payload, block.parent_root) {
            // Stop at the first failure rather than pressing on: every later
            // payload builds on this one, so they would all fail too and bury
            // the real error in noise.
            warn!(
                slot = block.slot,
                block_root = %ShortRoot(&payload.block_hash.0),
                %err,
                "Replay failed; execution layer left behind the consensus chain"
            );
            report.incomplete = true;
            return report;
        }
        report.replayed += 1;
    }

    if report.incomplete {
        warn!(
            replayed = report.replayed,
            "Could not fully resync the execution layer from the consensus chain. \
             This node will drop every block it receives. Wipe its data directory \
             and restart to rebuild from genesis."
        );
    } else {
        info!(
            replayed = report.replayed,
            skipped = report.skipped,
            "Execution layer resynced with the consensus chain"
        );
    }

    report
}
