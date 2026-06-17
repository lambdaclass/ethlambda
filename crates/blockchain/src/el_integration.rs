//! Execution-layer (Engine API) hooks for the `BlockChain` actor.
//!
//! Lives in its own module so the EL integration keeps its footprint out of
//! the core actor in `lib.rs`. All methods short-circuit to no-ops when no
//! `--execution-endpoint` is configured.

use ethlambda_ethrex_client::{ForkChoiceState, PayloadAttributesV3, PayloadStatusKind};
use ethlambda_state_transition::compute_time_at_slot;
use ethlambda_types::{
    ShortRoot, block::SignedBlock, execution_payload::ExecutionPayloadV3, primitives::H256,
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
    /// `request_payload_id_for_next_slot`, so the EL sees the same view
    /// regardless of which call hits first.
    fn current_el_forkchoice_state(&self) -> ForkChoiceState {
        ForkChoiceState {
            head_block_hash: self.el_hash_at(self.store.head()),
            safe_block_hash: self.el_hash_at(self.store.safe_target()),
            finalized_block_hash: self.el_hash_at(self.store.latest_finalized().root),
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
            .map(|block| block.body.execution_payload.block_hash)
            .unwrap_or(H256::ZERO)
    }

    /// At interval 4 of slot N-1, ask the EL to start building a payload
    /// for slot N if any of our validators is the slot-N proposer.
    ///
    /// Fires a build-mode `engine_forkchoiceUpdatedV3` carrying the same
    /// real head/safe/finalized triplet `notify_execution_layer` uses,
    /// plus `PayloadAttributesV3` with the correct slot timestamp. If the
    /// EL returns a `payload_id`, we stash it for `take_prepared_payload`
    /// to consume at interval 0 of slot N. When the EL is syncing it
    /// returns `payload_id = None` and we silently fall back to the
    /// synthetic payload path.
    ///
    /// `parent_beacon_block_root` follows the lean-parent-root convention:
    /// the proposed block's parent is the current head, so the EL builds the
    /// payload committing to the same root validators will pass to
    /// `engine_newPayload` as `block.parent_root`. `prev_randao` stays
    /// zero until Lean defines a RANDAO mix.
    pub(crate) async fn request_payload_id_for_next_slot(&mut self, current_slot: u64) {
        let Some(client) = self.execution_client.as_ref() else {
            return;
        };
        let next_slot = current_slot + 1;
        if self.get_our_proposer(next_slot).is_none() {
            return;
        }

        let head_root = self.store.head();
        let state = self.current_el_forkchoice_state();
        let attrs = PayloadAttributesV3 {
            timestamp: compute_time_at_slot(self.store.config().genesis_time, next_slot),
            prev_randao: H256::ZERO,
            suggested_fee_recipient: self.suggested_fee_recipient,
            withdrawals: vec![],
            parent_beacon_block_root: head_root,
        };
        let client = client.clone();
        match client.forkchoice_updated_v3(state, Some(attrs)).await {
            Ok(resp) => {
                if let Some(id) = resp.payload_id {
                    self.pending_payload_id = Some((next_slot, head_root, id));
                    trace!(
                        slot = next_slot,
                        status = ?resp.payload_status.status,
                        "Queued EL payload build for next slot",
                    );
                } else {
                    trace!(
                        slot = next_slot,
                        status = ?resp.payload_status.status,
                        "EL declined to start build (syncing or unknown head)",
                    );
                }
            }
            Err(err) => {
                warn!(slot = next_slot, %err, "engine_forkchoiceUpdatedV3 (build mode) failed");
            }
        }
    }

    /// At interval 0 of slot N, consume the `payload_id` stashed by
    /// `request_payload_id_for_next_slot` and fetch the now-built payload.
    ///
    /// Returns `None` (caller falls back to synthetic) on any of:
    ///   * no EL configured
    ///   * no stashed id (we weren't expecting to propose this slot, or
    ///     the build request was rejected at interval 4)
    ///   * stashed id is for a different slot (we missed a tick)
    ///   * the head moved since the build was requested — the prepared
    ///     payload's `parent_hash` and embedded `parent_beacon_block_root`
    ///     point at the old head, so the block would fail EL validation
    ///   * the `engine_getPayload` roundtrip failed
    pub(crate) async fn take_prepared_payload(&mut self, slot: u64) -> Option<ExecutionPayloadV3> {
        let client = self.execution_client.as_ref()?.clone();
        let (stashed_slot, build_head_root, payload_id) = self.pending_payload_id.take()?;
        if stashed_slot != slot {
            warn!(
                stashed_slot,
                slot, "Stashed payload_id doesn't match this slot; discarding"
            );
            return None;
        }
        let head_root = self.store.head();
        if build_head_root != head_root {
            warn!(
                slot,
                build_head_root = %ShortRoot(&build_head_root.0),
                head_root = %ShortRoot(&head_root.0),
                "Head moved since the EL build was requested; discarding stale payload_id"
            );
            return None;
        }
        match client.get_payload(payload_id).await {
            Ok(payload) => {
                trace!(slot, "Fetched execution payload from EL");
                Some(payload)
            }
            Err(err) => {
                warn!(slot, %err, "engine_getPayload failed; falling back to synthetic payload");
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
