//! Execution-layer (Engine API) hooks for the `BlockChain` actor.
//!
//! Lives in its own module so the EL integration keeps its footprint out of
//! the core actor in `lib.rs`. All methods short-circuit to no-ops when no
//! `--execution-endpoint` is configured.

use ethlambda_ethrex_client::{ForkChoiceState, PayloadAttributesV3, PayloadStatusKind};
use ethlambda_state_transition::compute_time_at_slot;
use ethlambda_types::{
    block::SignedBlock, execution_payload::ExecutionPayloadV3, primitives::H256,
};
use tracing::{trace, warn};

use crate::BlockChainServer;

impl BlockChainServer {
    /// Send a forkchoice update to the execution layer via
    /// `engine_forkchoiceUpdatedV3` carrying the current head/safe/finalized
    /// EL block hashes (read from the corresponding Lean blocks'
    /// `execution_payload.block_hash`). Errors are logged but never
    /// propagated — the consensus loop must continue regardless of EL state.
    ///
    /// At genesis every triplet entry is `H256::ZERO` because the genesis
    /// `BlockBody::default()` carries an `ExecutionPayloadV3::default()`
    /// whose `block_hash` is zero. Subsequent slots advance once a real
    /// payload (from `engine_getPayload`) has been imported.
    pub(crate) fn notify_execution_layer(&self) {
        let Some(client) = self.execution_client.as_ref() else {
            return;
        };
        let state = self.current_el_forkchoice_state();
        let client = client.clone();
        tokio::spawn(async move {
            match client.forkchoice_updated_v3(state, None).await {
                Ok(resp) => trace!(
                    status = ?resp.payload_status.status,
                    "engine_forkchoiceUpdatedV3 ok"
                ),
                Err(err) => warn!(%err, "engine_forkchoiceUpdatedV3 failed"),
            }
        });
    }

    /// Compute the `ForkChoiceState` the EL should see right now: head/safe/
    /// finalized resolved from Lean roots to the corresponding execution
    /// payload `block_hash`es via `el_hash_at`. Shared by the per-slot
    /// notification (`notify_execution_layer`) and the build-mode
    /// `build_execution_payload`, so the EL sees the same view regardless of
    /// which call hits first.
    fn current_el_forkchoice_state(&self) -> ForkChoiceState {
        // Best-effort: the EL notification is informational, never on the
        // consensus critical path, so a store read error degrades to the zero
        // sentinel rather than propagating.
        let finalized_root = self
            .store
            .latest_finalized()
            .map(|checkpoint| checkpoint.root)
            .unwrap_or_default();
        ForkChoiceState {
            head_block_hash: self.el_hash_at(self.store.head().unwrap_or_default()),
            safe_block_hash: self.el_hash_at(self.store.safe_target().unwrap_or_default()),
            finalized_block_hash: self.el_hash_at(finalized_root),
        }
    }

    /// Resolve a Lean block root to its execution payload's `block_hash`.
    ///
    /// `H256::ZERO` fallback applies when:
    ///   * `lean_root` is itself zero (uninitialized head)
    ///   * the block is missing from storage (defensive — head/safe/
    ///     finalized are always present, but a torn write or pruning bug
    ///     shouldn't crash the EL notifier)
    ///
    /// At genesis the payload is `ExecutionPayloadV3::default()`, so its
    /// `block_hash` is `H256::ZERO` and the result naturally rolls back
    /// to the same sentinel.
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

    /// Synchronously build the target slot's execution payload for a proposer
    /// (Option A). Runs inline at interval 4, just before `propose_block`.
    ///
    /// Fires a build-mode `forkchoiceUpdated` (with `PayloadAttributes`)
    /// carrying the same real head/safe/finalized triplet
    /// `notify_execution_layer` uses, then immediately `getPayload`. The
    /// in-process EL builds with no network latency; the out-of-process path
    /// pays a single Engine-API roundtrip. No stashing across intervals.
    ///
    /// Returns `None` (caller falls back to `synthetic_payload`) when no EL is
    /// configured, the EL declines to build (`payload_id = None`, e.g.
    /// syncing), or either roundtrip fails.
    ///
    /// `parent_beacon_block_root` follows the lean-parent-root convention: the
    /// proposed block's parent is the current head, so the EL builds the payload
    /// committing to the same root validators will pass to `newPayload` as
    /// `block.parent_root`. `prev_randao` stays zero until Lean defines a RANDAO
    /// mix.
    pub(crate) async fn build_execution_payload(&self, slot: u64) -> Option<ExecutionPayloadV3> {
        let client = self.execution_client.as_ref()?.clone();
        let head_root = self.store.head().unwrap_or_default();
        let state = self.current_el_forkchoice_state();
        let genesis_time = self.store.config().expect("config exists").genesis_time;
        let attrs = PayloadAttributesV3 {
            timestamp: compute_time_at_slot(genesis_time, slot),
            prev_randao: H256::ZERO,
            suggested_fee_recipient: self.suggested_fee_recipient,
            withdrawals: vec![],
            parent_beacon_block_root: head_root,
        };
        let payload_id = match client.forkchoice_updated_v3(state, Some(attrs)).await {
            Ok(resp) => resp.payload_id?,
            Err(err) => {
                warn!(slot, %err, "forkchoiceUpdated (build mode) failed");
                return None;
            }
        };
        match client.get_payload(payload_id).await {
            Ok(payload) => {
                trace!(slot, "Built execution payload for proposal");
                Some(payload)
            }
            Err(err) => {
                warn!(slot, %err, "getPayload failed; falling back to synthetic payload");
                None
            }
        }
    }

    /// Submit a received block's execution payload to the EL for validation.
    ///
    /// Returns `true` when the block should proceed to fork-choice insertion
    /// (no EL configured, EL says VALID/SYNCING/ACCEPTED, or the EL roundtrip
    /// itself failed). Returns `false` only on the explicit `INVALID` /
    /// `INVALID_BLOCK_HASH` verdicts — those mean the EL claims the payload
    /// is unexecutable on its own chain, so importing the block would be
    /// pointless.
    ///
    /// Network errors and unparseable responses are permissive — same policy
    /// as `notify_execution_layer`: consensus must keep running regardless
    /// of EL state. Operators are expected to monitor the warn logs.
    /// `parent_beacon_block_root` must be the block's `parent_root` (the
    /// lean-parent-root convention): the proposer's build-mode FCU committed
    /// the EL payload to its head root, which becomes the proposed block's
    /// `parent_root` — mismatching values fail the EL's block-hash check.
    pub(crate) async fn validate_payload_with_el(
        &self,
        payload: &ExecutionPayloadV3,
        parent_beacon_block_root: H256,
    ) -> bool {
        let Some(client) = self.execution_client.as_ref() else {
            return true;
        };
        let result = client.new_payload(payload, parent_beacon_block_root).await;
        match result {
            Ok(status) => match status.status {
                PayloadStatusKind::Valid
                | PayloadStatusKind::Syncing
                | PayloadStatusKind::Accepted => {
                    trace!(status = ?status.status, "engine_newPayload ok");
                    true
                }
                PayloadStatusKind::Invalid | PayloadStatusKind::InvalidBlockHash => {
                    warn!(
                        status = ?status.status,
                        error = ?status.validation_error,
                        "engine_newPayload rejected payload; dropping block"
                    );
                    false
                }
            },
            Err(err) => {
                warn!(%err, "engine_newPayload transport failure; accepting block");
                true
            }
        }
    }

    /// Import a gossiped block: gate it on the EL, then hand it to the store.
    ///
    /// EL pre-check (Phase 3 of M6). When `--execution-endpoint` is unset
    /// `validate_payload_with_el` is a no-op that returns `true`. An INVALID
    /// verdict drops the block before it touches the store; pending children
    /// referencing it as parent are not enqueued because we never call
    /// `on_block`, and are pruned by the standard slot-bound timeout.
    pub(crate) async fn import_gossiped_block(&mut self, block: SignedBlock) {
        let payload = &block.message.body.execution_payload;
        let parent_beacon_block_root = block.message.parent_root;
        if !self
            .validate_payload_with_el(payload, parent_beacon_block_root)
            .await
        {
            return;
        }
        self.on_block(block);
    }
}
