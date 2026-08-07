//! Execution-layer hooks for the `BlockChain` actor.
//!
//! Lives in its own module so the EL integration keeps its footprint out of the
//! core actor in `lib.rs`. Every method short-circuits to a no-op when no
//! `--el-genesis` was configured, so a consensus-only node is unaffected.
//!
//! Policy throughout: the execution layer is never allowed to stall consensus.
//! Failures are logged and treated as "no payload" or "accept the block"; only
//! an explicit rejection of a *received* payload drops that block.

use ethlambda_state_transition::compute_time_at_slot;
use ethlambda_types::{
    block::SignedBlock, execution_payload::ExecutionPayloadV3, primitives::H256,
};
use tracing::{trace, warn};

use crate::BlockChainServer;

impl BlockChainServer {
    /// Point the execution layer at the current head / safe / finalized blocks.
    ///
    /// Fire-and-forget: the EL is informational here and never on the consensus
    /// critical path. The hashes are the `block_hash` fields read off the
    /// corresponding Lean blocks' execution payloads, so the EL only ever sees
    /// blocks it has already been given.
    ///
    /// At genesis all three are the EL genesis hash seeded into the anchor
    /// (see `State::from_genesis_with_el_hash`).
    pub(crate) fn notify_execution_layer(&self) {
        let Some(engine) = self.execution_engine.as_ref() else {
            return;
        };
        // Best-effort: a store read error degrades to the zero sentinel rather
        // than propagating, for the same reason the call itself is spawned.
        let finalized_root = self
            .store
            .latest_finalized()
            .map(|checkpoint| checkpoint.root)
            .unwrap_or_default();
        let head = self.el_hash_at(self.store.head().unwrap_or_default());
        let safe = self.el_hash_at(self.store.safe_target().unwrap_or_default());
        let finalized = self.el_hash_at(finalized_root);

        let engine = engine.clone();
        tokio::spawn(async move {
            engine
                .set_head(head, safe, finalized)
                .await
                .inspect(|()| trace!("EL head updated"))
                .inspect_err(|err| warn!(%err, "EL head update failed"))
        });
    }

    /// Resolve a Lean block root to its execution payload's `block_hash`.
    ///
    /// `H256::ZERO` is returned when `lean_root` is itself zero (uninitialized
    /// head), or when the block is missing from storage — defensive, since
    /// head/safe/finalized are always present, but a torn write should not crash
    /// the EL notifier.
    pub(crate) fn el_hash_at(&self, lean_root: H256) -> H256 {
        if lean_root.is_zero() {
            return H256::ZERO;
        }
        self.store
            .get_block(&lean_root)
            .ok()
            .flatten()
            .map(|block| block.body.execution_payload.block_hash)
            .unwrap_or(H256::ZERO)
    }

    /// Build the execution payload for the block this node is about to propose
    /// for `slot`. Runs inline at interval 4, immediately before the block is
    /// assembled.
    ///
    /// In-process this is a single synchronous library call, so there is nothing
    /// to pre-request or stash across intervals. Returns `None` when no EL is
    /// configured or the build fails, and the caller falls back to
    /// `synthetic_payload` so a block is still produced.
    ///
    /// `parent_beacon_block_root` is the current head: the proposed block's
    /// parent, and the value peers will pass back when they execute this
    /// payload.
    pub(crate) async fn build_execution_payload(&self, slot: u64) -> Option<ExecutionPayloadV3> {
        let engine = self.execution_engine.as_ref()?;
        let head_root = self.store.head().unwrap_or_default();
        let genesis_time = self.store.config().genesis_time;
        engine
            .build_payload(
                compute_time_at_slot(genesis_time, slot),
                // Zero until Lean defines a RANDAO mix.
                H256::ZERO,
                head_root,
                // Lean has no fee market or block rewards yet, so there is
                // nothing to direct anywhere. Add a configurable recipient when
                // that changes.
                [0u8; 20],
            )
            .await
            .inspect(|_| trace!(slot, "Built execution payload for proposal"))
            .inspect_err(
                |err| warn!(slot, %err, "EL payload build failed; using synthetic payload"),
            )
            .ok()
    }

    /// Execute a received block's payload against the execution layer.
    ///
    /// Returns `true` when the block should proceed to fork-choice insertion:
    /// no EL configured, or the EL executed the payload successfully. Returns
    /// `false` only when the EL rejects it, which means the payload is
    /// unexecutable on its own chain and importing the block would be pointless.
    ///
    /// `parent_beacon_block_root` must be the block's `parent_root` — the
    /// proposer committed the payload to that root when building it, and a
    /// different value fails the EL's block-hash check.
    pub(crate) fn validate_payload_with_el(
        &self,
        payload: &ExecutionPayloadV3,
        parent_beacon_block_root: H256,
    ) -> bool {
        let Some(engine) = self.execution_engine.as_ref() else {
            return true;
        };
        match engine.execute_payload(payload, parent_beacon_block_root) {
            Ok(()) => {
                trace!("EL executed payload");
                true
            }
            Err(err) => {
                warn!(%err, "EL rejected payload; dropping block");
                false
            }
        }
    }

    /// Import a gossiped block: execute its payload on the EL first, then hand
    /// the block to the store.
    ///
    /// When no EL is configured `validate_payload_with_el` is a no-op returning
    /// `true`. A rejection drops the block before it touches the store; pending
    /// children referencing it are never enqueued and age out via the standard
    /// slot-bound timeout.
    pub(crate) fn import_gossiped_block(&mut self, block: SignedBlock) {
        let payload = &block.message.body.execution_payload;
        if !self.validate_payload_with_el(payload, block.message.parent_root) {
            return;
        }
        self.on_block(block);
    }
}
