//! The chain actor's import path for gloas execution payload envelopes.
//!
//! A gloas block carries only the builder's bid; the payload arrives apart from
//! it, in a `SignedExecutionPayloadEnvelope`, and fork choice weighs a FULL and
//! an EMPTY node per block. Three things can make the order of arrival wrong,
//! and each has a bounded queue here:
//!
//! ```text
//! envelope ─► block known (with post-state)? ─no─► awaiting_block[root]
//!               │yes
//!               ▼
//!           bid has commitments and a sampled column missing? ─yes─► awaiting_columns[root]
//!               │no
//!               ▼
//!           advance clock; on_execution_payload_envelope ─► record payload status
//!               ─► redrive blocks_awaiting_parent_payload[root] ─► recompute head
//!
//! gloas block ─► parent FULL and its payload not verified ─yes─► blocks_awaiting_parent_payload[parent]
//! ```
//!
//! Data availability moves here from the block: a gloas block's commitments are
//! in its bid, and the columns they commit to gate the envelope that reveals the
//! payload, not the block's own import.
//!
//! # Driving the queues
//!
//! Nothing here awaits inside the import path. A block import, a stored column
//! or a tick only pushes the root whose envelope may now be ready onto
//! [`EnvelopeQueues::work`]; the handler that ran it then calls
//! [`BlockChainServer::settle_envelopes`], which drains that list. That keeps
//! the cycle envelope, block import, envelope from being a recursion between
//! async functions.
//!
//! # What bounds this
//!
//! An envelope for a block this node has not imported cannot be judged, so
//! nobody has vouched for it: at most [`MAX_ENVELOPES_AWAITING_BLOCK_PER_SLOT`]
//! are kept for the slot they arrived in, and one per root. Blocks held for a
//! parent's payload are capped per parent by
//! [`MAX_BLOCKS_HELD_PER_PARENT_PAYLOAD`]. All three queues are swept at
//! finality by [`BlockChainServer::evict_envelope_queues_at_or_below_finality`].

use std::collections::{HashMap, VecDeque};

use ethlambda_state_transition::beacon::fork::ForkName;
use ethlambda_state_transition::beacon::fork_choice::{self, PayloadStatus, PayloadStatusEnum};
use ethlambda_state_transition::beacon::stf::ExecutionEngine;
use ethlambda_types::ShortRoot;
use ethlambda_types::beacon::containers::{DataColumnSidecar, SignedBeaconBlock, gloas};
use ethlambda_types::primitives::H256;
use tracing::{debug, error, info, trace, warn};

use crate::import_timing::ImportTimings;
use crate::{BlockChainServer, custody_columns_present, metrics};

/// How many envelopes for blocks this node has not imported may be held for one
/// slot.
///
/// A slot has one canonical block, and a short fork or an equivocating
/// proposer adds a few more. The envelope names its block by an unverified
/// root, so past this cap the extra roots at a slot are ones nobody can vouch
/// for.
pub(crate) const MAX_ENVELOPES_AWAITING_BLOCK_PER_SLOT: usize = 4;

/// How many blocks may wait on one parent's payload.
///
/// The children of a block that all name it as a FULL parent: one per slot the
/// chain skipped past it, plus equivocations.
pub(crate) const MAX_BLOCKS_HELD_PER_PARENT_PAYLOAD: usize = 4;

/// An envelope the actor is holding until it can be verified.
pub(crate) struct HeldEnvelope {
    envelope: gloas::SignedExecutionPayloadEnvelope,
    /// The slot the hold is evicted by: the slot the envelope arrived in while
    /// its block is unknown (the envelope names no slot), the block's own once
    /// it is.
    slot: u64,
    /// Unix milliseconds the envelope reached this node, which the store clock
    /// is advanced to before verifying so the timeliness deadlines are judged
    /// at arrival rather than at redrive.
    event_ms: u64,
}

impl HeldEnvelope {
    pub(crate) fn new(
        envelope: gloas::SignedExecutionPayloadEnvelope,
        slot: u64,
        event_ms: u64,
    ) -> Self {
        Self {
            envelope,
            slot,
            event_ms,
        }
    }
}

/// The three queues, and the list of roots whose envelope may have become
/// ready.
#[derive(Default)]
pub(crate) struct EnvelopeQueues {
    /// Envelopes whose block has no post-state yet, by the block's root.
    pub(crate) awaiting_block: HashMap<H256, HeldEnvelope>,
    /// Envelopes whose bid has commitments and whose sampled columns are not
    /// all stored, by the block's root.
    pub(crate) awaiting_columns: HashMap<H256, HeldEnvelope>,
    /// Blocks whose parent is FULL with a payload not yet verified, by the
    /// parent's root, each with its own slot. The block's bytes are in
    /// `Table::BlockHeaders`/`BlockBodies` as for any other held block.
    pub(crate) blocks_awaiting_parent_payload: HashMap<H256, HashMap<H256, u64>>,
    /// Roots to look at in [`BlockChainServer::settle_envelopes`].
    pub(crate) work: VecDeque<H256>,
    /// Roots whose envelope was verified since the last settle, whose waiting
    /// children [`BlockChainServer::settle_envelopes`] then releases.
    pub(crate) verified: VecDeque<H256>,
}

impl EnvelopeQueues {
    /// Whether `block_root` is a block held for its parent's payload.
    pub(crate) fn is_block_held(&self, block_root: &H256) -> bool {
        self.blocks_awaiting_parent_payload
            .values()
            .any(|children| children.contains_key(block_root))
    }

    fn is_empty(&self) -> bool {
        self.awaiting_block.is_empty()
            && self.awaiting_columns.is_empty()
            && self.blocks_awaiting_parent_payload.is_empty()
    }

    fn held_blocks(&self) -> usize {
        self.blocks_awaiting_parent_payload
            .values()
            .map(HashMap::len)
            .sum()
    }
}

/// The sampled columns an envelope still needs, or `None` if nothing is
/// outstanding.
///
/// A bid without commitments has no columns to wait for. With commitments,
/// every column this node samples must be stored: the spec's
/// `is_data_available` is vacuous over an empty list, so a partial set must
/// never reach fork choice as evidence.
pub(crate) fn missing_columns_for_envelope(
    commitment_count: usize,
    custody_columns: &[u64],
    present: &[u64],
) -> Option<Vec<u64>> {
    if commitment_count == 0 {
        return None;
    }
    let missing: Vec<u64> = custody_columns
        .iter()
        .copied()
        .filter(|index| !present.contains(index))
        .collect();
    (!missing.is_empty()).then_some(missing)
}

impl BlockChainServer {
    /// Take an envelope that passed gossip validation: verify it now, or hold
    /// it until what it waits on arrives. The caller then settles the queues.
    pub(crate) fn receive_envelope(
        &mut self,
        envelope: gloas::SignedExecutionPayloadEnvelope,
        event_ms: u64,
    ) {
        let config = self.store.config();
        let arrival_slot = fork_choice::get_current_slot(&self.store, &config);
        self.apply_or_hold_envelope(HeldEnvelope::new(envelope, arrival_slot, event_ms));
    }

    /// Verify `held` against its block, or put it back in the queue for what it
    /// is waiting on. `true` when the envelope was verified and recorded.
    fn apply_or_hold_envelope(&mut self, held: HeldEnvelope) -> bool {
        let root = held.envelope.message.beacon_block_root;
        if self.store.has_verified_payload(&root) {
            trace!(
                block_root = %ShortRoot(&root.0),
                "Dropping an envelope whose payload is already verified"
            );
            return false;
        }

        let has_state = self.store.has_state(&root).expect("DB read should succeed");
        let block = if has_state {
            self.store.get_signed_block(&root).ok().flatten()
        } else {
            None
        };
        let Some(block) = block else {
            self.hold_envelope_awaiting_block(root, held);
            return false;
        };

        let slot = block.slot();
        let finalized_slot = self
            .store
            .latest_finalized()
            .expect("finalized checkpoint exists")
            .slot;
        // Strictly below: the finalized block's own children may still name it
        // as their FULL parent.
        if slot < finalized_slot {
            trace!(%slot, "Dropping an envelope for a block below the finalized slot");
            return false;
        }

        let commitment_count = match &block {
            SignedBeaconBlock::Gloas(inner) => inner
                .message
                .body
                .signed_execution_payload_bid
                .message
                .blob_kzg_commitments
                .len(),
            SignedBeaconBlock::Phase0(_)
            | SignedBeaconBlock::Altair(_)
            | SignedBeaconBlock::Bellatrix(_)
            | SignedBeaconBlock::Capella(_)
            | SignedBeaconBlock::Deneb(_)
            | SignedBeaconBlock::Electra(_)
            | SignedBeaconBlock::Fulu(_)
            | SignedBeaconBlock::Lean(_) => {
                warn!(
                    %slot,
                    block_root = %ShortRoot(&root.0),
                    "Dropping an envelope: its block is not a gloas block"
                );
                return false;
            }
        };

        let present = self
            .store
            .data_column_indices_for(slot, &root)
            .expect("DB read should succeed");
        if let Some(missing) =
            missing_columns_for_envelope(commitment_count, &self.custody_columns, &present)
        {
            self.hold_envelope_awaiting_columns(root, slot, held, missing);
            return false;
        }

        let sidecars = if commitment_count == 0 {
            Vec::new()
        } else {
            match self.stored_gloas_columns(slot, &root) {
                Some(sidecars) => sidecars,
                None => {
                    // Present a moment ago and unreadable now: not worth
                    // guessing at, so wait for them to be stored again.
                    self.hold_envelope_awaiting_columns(root, slot, held, Vec::new());
                    return false;
                }
            }
        };

        self.advance_beacon_clock_to(held.event_ms);
        let config = self.store.config();
        // Without an execution client the follower trusts the payload, as it
        // already does for every pre-gloas block it imports (the engine's
        // verdict is `NotRequired` there), so the engine's part of
        // `verify_execution_payload_envelope` is answered "valid".
        let verdict = fork_choice::on_execution_payload_envelope(
            &mut self.store,
            &held.envelope,
            &config,
            &sidecars,
            &ExecutionEngine::valid(),
        );
        match verdict {
            Ok(()) => {
                info!(
                    %slot,
                    block_root = %ShortRoot(&root.0),
                    "Execution payload envelope verified"
                );
                // With a client configured the verdict is the client's to give
                // (a later change asks it); recording VALID without asking
                // would claim a validation that never happened.
                if self.engine.is_none() {
                    self.store.insert_beacon_block_payload_status(
                        root,
                        slot,
                        PayloadStatusEnum::Valid,
                    );
                }
                self.envelopes.verified.push_back(root);
                true
            }
            Err(err) => {
                // p2p judged the envelope before it got here, so no peer is
                // penalized from this side.
                warn!(
                    %slot,
                    block_root = %ShortRoot(&root.0),
                    ?err,
                    "Dropping an execution payload envelope that failed verification"
                );
                false
            }
        }
    }

    /// Every sampled column stored for `root`, decoded as gloas sidecars, or
    /// `None` if any is missing or not one.
    fn stored_gloas_columns(
        &self,
        slot: u64,
        root: &H256,
    ) -> Option<Vec<gloas::DataColumnSidecar>> {
        self.custody_columns
            .iter()
            .map(
                |&index| match self.store.get_data_column(slot, root, index) {
                    Ok(Some(DataColumnSidecar::Gloas(sidecar))) => Some(sidecar),
                    Ok(Some(DataColumnSidecar::Fulu(_))) | Ok(None) => None,
                    Err(err) => {
                        error!(%err, "Failed to read back a stored data column sidecar");
                        None
                    }
                },
            )
            .collect()
    }

    fn hold_envelope_awaiting_block(&mut self, root: H256, held: HeldEnvelope) {
        let queues = &mut self.envelopes;
        if queues.awaiting_block.contains_key(&root) {
            return;
        }
        let at_slot = queues
            .awaiting_block
            .values()
            .filter(|other| other.slot == held.slot)
            .count();
        if at_slot >= MAX_ENVELOPES_AWAITING_BLOCK_PER_SLOT {
            trace!(
                slot = held.slot,
                block_root = %ShortRoot(&root.0),
                "Dropping an envelope: its slot already holds the most unmatched envelopes allowed"
            );
            return;
        }
        debug!(
            block_root = %ShortRoot(&root.0),
            "Holding an envelope until its block is imported"
        );
        queues.awaiting_block.insert(root, held);
        self.publish_envelope_queues();
    }

    fn hold_envelope_awaiting_columns(
        &mut self,
        root: H256,
        slot: u64,
        mut held: HeldEnvelope,
        missing: Vec<u64>,
    ) {
        held.slot = slot;
        // One envelope per root; a re-delivery replaces nothing.
        if self.envelopes.awaiting_columns.contains_key(&root) {
            return;
        }
        info!(
            %slot,
            block_root = %ShortRoot(&root.0),
            missing = ?missing,
            "Holding an envelope: its custody columns have not all arrived yet"
        );
        self.envelopes.awaiting_columns.insert(root, held);
        if !missing.is_empty() {
            self.request_missing_columns(root, missing);
        }
        self.publish_envelope_queues();
    }

    /// Queue `root`'s envelope for a look in [`Self::settle_envelopes`], if one
    /// is waiting for the block to import.
    pub(crate) fn note_block_imported_for_envelope(&mut self, root: H256) {
        if self.envelopes.awaiting_block.contains_key(&root) {
            self.envelopes.work.push_back(root);
        }
    }

    /// Queue `root`'s envelope for a look, if one is waiting for columns.
    pub(crate) fn note_column_stored_for_envelope(&mut self, root: H256) {
        if self.envelopes.awaiting_columns.contains_key(&root) {
            self.envelopes.work.push_back(root);
        }
    }

    /// Once a slot: look at every envelope waiting for columns, and ask peers
    /// for whatever is still missing.
    pub(crate) fn redrive_envelopes_awaiting_columns(&mut self) {
        let held: Vec<(H256, u64)> = self
            .envelopes
            .awaiting_columns
            .iter()
            .map(|(&root, held)| (root, held.slot))
            .collect();
        for (root, slot) in held {
            let present = self
                .store
                .data_column_indices_for(slot, &root)
                .expect("DB read should succeed");
            let missing: Vec<u64> = self
                .custody_columns
                .iter()
                .copied()
                .filter(|index| !present.contains(index))
                .collect();
            if missing.is_empty() {
                self.envelopes.work.push_back(root);
            } else {
                self.request_missing_columns(root, missing);
            }
        }
    }

    /// The held envelope for `root` if what it waited on is now there.
    fn take_ready_envelope(&mut self, root: H256) -> Option<HeldEnvelope> {
        if self.envelopes.awaiting_block.contains_key(&root)
            && self.store.has_state(&root).expect("DB read should succeed")
        {
            return self.envelopes.awaiting_block.remove(&root);
        }
        let slot = self.envelopes.awaiting_columns.get(&root)?.slot;
        if custody_columns_present(&self.store, slot, &root, &self.custody_columns) {
            return self.envelopes.awaiting_columns.remove(&root);
        }
        None
    }

    /// Drain the roots pushed since the last call: verify each ready envelope,
    /// import the blocks that were waiting on each verified payload, and
    /// recompute the head once if anything changed.
    pub(crate) async fn settle_envelopes(&mut self) {
        let mut changed = false;
        loop {
            if let Some(root) = self.envelopes.work.pop_front() {
                if let Some(held) = self.take_ready_envelope(root) {
                    self.apply_or_hold_envelope(held);
                }
            } else if let Some(root) = self.envelopes.verified.pop_front() {
                changed = true;
                self.release_blocks_awaiting_parent_payload(root).await;
            } else {
                break;
            }
        }
        self.publish_envelope_queues();
        if changed {
            self.recompute_beacon_head().await;
        }
    }

    /// Whether `block` is a gloas block whose parent is FULL while that
    /// parent's payload is not yet verified: `on_block` would reject it with
    /// `is_payload_verified(store, block.parent_root)`.
    pub(crate) fn parent_payload_unverified(&self, block: &SignedBeaconBlock) -> bool {
        if block.fork_name() != ForkName::Gloas {
            return false;
        }
        matches!(
            fork_choice::get_parent_payload_status(&self.store, block),
            Ok(PayloadStatus::Full)
        ) && !fork_choice::is_payload_verified(&self.store, block.parent_root())
    }

    /// Keep `block` until its parent's envelope is verified.
    ///
    /// Written the way a block held for a missing parent is: no `LiveChain`
    /// entry, so it stays invisible to fork choice, and readable back by root.
    pub(crate) fn hold_block_for_parent_payload(
        &mut self,
        block: SignedBeaconBlock,
        timings: ImportTimings,
    ) {
        let slot = block.slot();
        let block_root = block.message_hash_tree_root();
        let parent_root = block.parent_root();

        let held_for_parent = self
            .envelopes
            .blocks_awaiting_parent_payload
            .get(&parent_root);
        if held_for_parent.is_some_and(|held| held.contains_key(&block_root)) {
            return;
        }
        if held_for_parent.is_some_and(|held| held.len() >= MAX_BLOCKS_HELD_PER_PARENT_PAYLOAD) {
            warn!(
                %slot,
                block_root = %ShortRoot(&block_root.0),
                parent_root = %ShortRoot(&parent_root.0),
                "Dropping a block: its parent already has the most children held for its payload"
            );
            return;
        }

        info!(
            %slot,
            block_root = %ShortRoot(&block_root.0),
            parent_root = %ShortRoot(&parent_root.0),
            "Holding block: its parent's execution payload is not verified yet"
        );
        self.store
            .insert_pending_block(block_root, block)
            .expect("DB insert should succeed");
        self.envelopes
            .blocks_awaiting_parent_payload
            .entry(parent_root)
            .or_default()
            .insert(block_root, slot);
        self.held_timings.insert(block_root, timings);
        self.publish_envelope_queues();
    }

    /// Re-import every block that waited on `parent_root`'s payload, now that
    /// it is verified.
    async fn release_blocks_awaiting_parent_payload(&mut self, parent_root: H256) {
        let Some(children) = self
            .envelopes
            .blocks_awaiting_parent_payload
            .remove(&parent_root)
        else {
            return;
        };
        self.publish_envelope_queues();
        for (block_root, slot) in children {
            let timings = self
                .held_timings
                .remove(&block_root)
                .unwrap_or_else(ImportTimings::starting_now);
            let Ok(Some(block)) = self.store.get_signed_block(&block_root) else {
                error!(
                    %slot,
                    block_root = %ShortRoot(&block_root.0),
                    "A block held for its parent's payload vanished from the store"
                );
                continue;
            };
            debug!(
                %slot,
                block_root = %ShortRoot(&block_root.0),
                "Parent payload verified; re-importing a held block"
            );
            self.on_block(block, timings).await;
        }
    }

    /// Forget `block_root` as a block held for a parent's payload. Called from
    /// the funnel every eviction goes through, so `held_timings` and the queue
    /// cannot outlive the block they describe.
    pub(crate) fn forget_block_held_for_parent_payload(&mut self, block_root: H256) {
        if !self.envelopes.is_block_held(&block_root) {
            return;
        }
        self.envelopes
            .blocks_awaiting_parent_payload
            .retain(|_, children| {
                children.remove(&block_root);
                !children.is_empty()
            });
        self.publish_envelope_queues();
    }

    /// Drop every queued envelope and held block that finality has superseded.
    ///
    /// The counterpart of [`Self::evict_held_blocks_at_or_below_finality`], run
    /// beside it: an envelope whose block never arrives, or a parent whose
    /// payload never does, would otherwise hold its entry for the node's whole
    /// uptime. Envelopes are kept at the finalized slot itself, since its
    /// children may still name it as their FULL parent.
    pub(crate) fn evict_envelope_queues_at_or_below_finality(&mut self) {
        if self.envelopes.is_empty() {
            return;
        }
        let finalized_slot = self
            .store
            .latest_finalized()
            .expect("finalized checkpoint exists")
            .slot;

        self.envelopes
            .awaiting_block
            .retain(|_, held| held.slot >= finalized_slot);
        self.envelopes
            .awaiting_columns
            .retain(|_, held| held.slot >= finalized_slot);

        let stale: Vec<H256> = self
            .envelopes
            .blocks_awaiting_parent_payload
            .values()
            .flat_map(|children| children.iter())
            .filter(|&(_, &slot)| slot <= finalized_slot)
            .map(|(&root, _)| root)
            .collect();
        for root in stale {
            self.discard_pending_subtree(root);
        }
        self.publish_envelope_queues();
    }

    pub(crate) fn publish_envelope_queues(&self) {
        metrics::set_envelopes_awaiting_block(self.envelopes.awaiting_block.len() as u64);
        metrics::set_envelopes_awaiting_columns(self.envelopes.awaiting_columns.len() as u64);
        metrics::set_blocks_awaiting_parent_payload(self.envelopes.held_blocks() as u64);
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use ethlambda_state_transition::beacon::config::Config;
    use ethlambda_storage::backend::InMemoryBackend;
    use ethlambda_types::beacon::containers::BeaconState;
    use libssz::SszDecode as _;

    use super::*;
    use crate::tests::{GENESIS_TIME, beacon_server, beacon_store};

    /// The mainnet preset with every fork active from genesis, as the fork
    /// choice fixtures that carry no `config.yaml` of their own are run.
    fn fixture_config() -> Config {
        ForkName::ALL
            .into_iter()
            .fold(Config::mainnet(), |config, fork| {
                config.with_fork_epoch(fork, 0)
            })
    }

    /// One fork choice fixture case, read the way the state transition crate's
    /// spec runner reads it.
    struct Case(PathBuf);

    impl Case {
        fn new(handler: &str, case: &str) -> Self {
            Self(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../consensus-spec-tests/tests/mainnet/gloas/fork_choice")
                    .join(handler)
                    .join("pyspec_tests")
                    .join(case),
            )
        }

        fn bytes(&self, name: &str) -> Vec<u8> {
            let path = self.0.join(format!("{name}.ssz_snappy"));
            let compressed = std::fs::read(&path)
                .unwrap_or_else(|err| panic!("reading {}: {err}", path.display()));
            snap::raw::Decoder::new()
                .decompress_vec(&compressed)
                .unwrap_or_else(|err| panic!("decompressing {}: {err}", path.display()))
        }

        fn block(&self, root_hex: &str) -> SignedBeaconBlock {
            let bytes = self.bytes(&format!("block_0x{root_hex}"));
            SignedBeaconBlock::from_ssz(ForkName::Gloas, &bytes).expect("block decodes")
        }

        fn envelope(&self, root_hex: &str) -> gloas::SignedExecutionPayloadEnvelope {
            let bytes = self.bytes(&format!("execution_payload_envelope_0x{root_hex}"));
            gloas::SignedExecutionPayloadEnvelope::from_ssz_bytes(&bytes).expect("envelope decodes")
        }

        /// A server over the case's anchor, its clock at `time` seconds.
        fn server(&self, time: u64) -> BlockChainServer {
            let state = BeaconState::from_ssz(ForkName::Gloas, &self.bytes("anchor_state"))
                .expect("anchor state decodes");
            let anchor = SignedBeaconBlock::Gloas(gloas::SignedBeaconBlock {
                message: libssz::SszDecode::from_ssz_bytes(&self.bytes("anchor_block"))
                    .expect("anchor block decodes"),
                signature: Default::default(),
            });
            let config = fixture_config();
            let backend = Arc::new(InMemoryBackend::new());
            let store = fork_choice::get_forkchoice_store(backend, state, anchor, &config)
                .expect("anchor store");
            let mut server = beacon_server(store);
            fork_choice::on_tick(&mut server.store, time, &config);
            server
        }
    }

    const TIEBREAK: &str = "get_head_full_payload_tiebreak";
    const PARENT: &str = "780218dcb4c1afc8ba72f325eb4f9ad43523356242345752d0e7a52391c15582";
    const CHILD: &str = "14f9d9ee25f47e0d8dd8ea7d01b206737e2aede3a7732d953546348511f58128";
    const PARENT_ENVELOPE: &str =
        "bba7bbe6c4fb93af68a15e1048436396821dfaf7af6e2a5049dbef906df6801e";

    fn root(hex_root: &str) -> H256 {
        let bytes: [u8; 32] = hex::decode(hex_root).unwrap().try_into().unwrap();
        H256(bytes)
    }

    fn head(server: &BlockChainServer) -> (H256, PayloadStatus) {
        let node = fork_choice::get_head_node(&server.store, &fixture_config()).expect("head");
        (node.root, node.payload_status)
    }

    #[tokio::test]
    #[cfg_attr(
        not(feature = "beacon-spec-tests"),
        ignore = "needs the fork choice fixtures; run `make consensus-spec-tests`"
    )]
    async fn a_gloas_block_imports_without_columns_and_is_not_held() {
        let case = Case::new("get_head", TIEBREAK);
        let mut server = case.server(12);
        server.custody_columns = (0..8).collect();

        server
            .on_block(case.block(PARENT), ImportTimings::default())
            .await;

        assert!(server.store.has_state(&root(PARENT)).unwrap());
        assert!(server.blocks_awaiting_columns.is_empty());
        assert!(server.envelopes.blocks_awaiting_parent_payload.is_empty());
    }

    #[tokio::test]
    #[cfg_attr(
        not(feature = "beacon-spec-tests"),
        ignore = "needs the fork choice fixtures; run `make consensus-spec-tests`"
    )]
    async fn an_envelope_ahead_of_its_block_is_held_then_applied_when_the_block_imports() {
        let case = Case::new("get_head", TIEBREAK);
        let mut server = case.server(12);

        server.receive_envelope(case.envelope(PARENT_ENVELOPE), 0);
        server.settle_envelopes().await;
        assert!(server.envelopes.awaiting_block.contains_key(&root(PARENT)));
        assert!(!server.store.has_verified_payload(&root(PARENT)));

        server
            .on_block(case.block(PARENT), ImportTimings::default())
            .await;
        // The import only queues the look; settling is the handler's step.
        assert!(!server.store.has_verified_payload(&root(PARENT)));
        server.settle_envelopes().await;

        assert!(server.envelopes.awaiting_block.is_empty());
        assert!(server.store.has_verified_payload(&root(PARENT)));
        assert_eq!(
            server.store.beacon_block_payload_status(root(PARENT)),
            PayloadStatusEnum::Valid
        );
        assert_eq!(head(&server), (root(PARENT), PayloadStatus::Full));
    }

    /// The `on_execution_payload_envelope` cases share one anchor and one
    /// first block, so the valid case's envelope fits the invalid-full-child
    /// case's chain: the one place a block built on a FULL parent exists.
    const FULL_CHILD_CASE: &str = "on_execution_payload_envelope_invalid_full_child";
    const FULL_PARENT: &str = "76bf14e70fc96a5a3442a46dff3bfb897d5568cdb4dc7e94419f625df2fcd9e5";
    const FULL_CHILD: &str = "7a25db19479cdcc24bd59bb8f5feaeee2e9b24bd25f5eddd54dd809c567b5e5b";

    fn valid_envelope_for_full_parent() -> gloas::SignedExecutionPayloadEnvelope {
        Case::new(
            "on_execution_payload_envelope",
            "on_execution_payload_envelope_valid",
        )
        .envelope("240ec2c17454f3e653fd3b43961e3c9a16770d336b0e882535c01f99b9223b41")
    }

    #[tokio::test]
    #[cfg_attr(
        not(feature = "beacon-spec-tests"),
        ignore = "needs the fork choice fixtures; run `make consensus-spec-tests`"
    )]
    async fn a_block_on_a_full_parent_waits_for_the_parents_envelope_then_imports() {
        let case = Case::new("on_execution_payload_envelope", FULL_CHILD_CASE);
        let mut server = case.server(12);
        server
            .on_block(case.block(FULL_PARENT), ImportTimings::default())
            .await;
        fork_choice::on_tick(&mut server.store, 24, &fixture_config());

        server
            .on_block(case.block(FULL_CHILD), ImportTimings::default())
            .await;

        // Held, not failed, and invisible to fork choice.
        assert!(!server.store.has_state(&root(FULL_CHILD)).unwrap());
        assert!(server.envelopes.is_block_held(&root(FULL_CHILD)));
        assert!(server.held_timings.contains_key(&root(FULL_CHILD)));
        assert_eq!(head(&server).0, root(FULL_PARENT));

        server.receive_envelope(valid_envelope_for_full_parent(), 0);
        server.settle_envelopes().await;

        assert!(server.store.has_state(&root(FULL_CHILD)).unwrap());
        assert!(server.envelopes.blocks_awaiting_parent_payload.is_empty());
        assert!(!server.held_timings.contains_key(&root(FULL_CHILD)));
        assert_eq!(head(&server).0, root(FULL_CHILD));
    }

    #[tokio::test]
    #[cfg_attr(
        not(feature = "beacon-spec-tests"),
        ignore = "needs the fork choice fixtures; run `make consensus-spec-tests`"
    )]
    async fn an_envelope_that_fails_verification_is_dropped_and_its_child_stays_held() {
        let case = Case::new(
            "on_execution_payload_envelope",
            "on_execution_payload_envelope_invalid_full_child",
        );
        let parent = "76bf14e70fc96a5a3442a46dff3bfb897d5568cdb4dc7e94419f625df2fcd9e5";
        let child = "7a25db19479cdcc24bd59bb8f5feaeee2e9b24bd25f5eddd54dd809c567b5e5b";
        let bad_envelope = "73c5948d041ccb171b9331c0eac4a3bb8cdcf01994916fee4c7493e63e890559";
        let mut server = case.server(12);
        server
            .on_block(case.block(parent), ImportTimings::default())
            .await;
        fork_choice::on_tick(&mut server.store, 24, &fixture_config());
        server
            .on_block(case.block(child), ImportTimings::default())
            .await;
        assert!(server.envelopes.is_block_held(&root(child)));

        server.receive_envelope(case.envelope(bad_envelope), 0);
        server.settle_envelopes().await;

        assert!(!server.store.has_verified_payload(&root(parent)));
        assert!(server.envelopes.awaiting_block.is_empty());
        assert!(server.envelopes.awaiting_columns.is_empty());
        assert!(server.envelopes.is_block_held(&root(child)));
        assert!(!server.store.has_state(&root(child)).unwrap());
    }

    #[tokio::test]
    #[cfg_attr(
        not(feature = "beacon-spec-tests"),
        ignore = "needs the fork choice fixtures; run `make consensus-spec-tests`"
    )]
    async fn an_envelope_for_an_already_verified_payload_is_ignored() {
        let case = Case::new("get_head", TIEBREAK);
        let mut server = case.server(12);
        server
            .on_block(case.block(PARENT), ImportTimings::default())
            .await;
        server.receive_envelope(case.envelope(PARENT_ENVELOPE), 0);
        assert!(server.store.has_verified_payload(&root(PARENT)));

        server.receive_envelope(case.envelope(PARENT_ENVELOPE), 0);

        assert!(server.envelopes.awaiting_block.is_empty());
        assert!(server.envelopes.awaiting_columns.is_empty());
    }

    #[test]
    fn an_envelope_waits_for_every_sampled_column_when_the_bid_has_commitments() {
        let custody = [2, 5, 9];
        // Nothing outstanding without commitments, whatever is stored.
        assert_eq!(missing_columns_for_envelope(0, &custody, &[]), None);
        // Some stored, some not: the rest are named, in custody order.
        assert_eq!(
            missing_columns_for_envelope(3, &custody, &[5]),
            Some(vec![2, 9])
        );
        // A column outside the sample does not count.
        assert_eq!(
            missing_columns_for_envelope(1, &custody, &[1, 2, 5]),
            Some(vec![9])
        );
        assert_eq!(missing_columns_for_envelope(1, &custody, &[9, 5, 2]), None);
    }

    #[tokio::test]
    #[cfg_attr(
        not(feature = "beacon-spec-tests"),
        ignore = "needs the fork choice fixtures; run `make consensus-spec-tests`"
    )]
    async fn a_stored_column_queues_only_an_envelope_that_waits_for_columns() {
        let case = Case::new("get_head", TIEBREAK);
        let mut server = case.server(12);
        let envelope = case.envelope(PARENT_ENVELOPE);

        server.note_column_stored_for_envelope(root(PARENT));
        assert!(server.envelopes.work.is_empty());

        server
            .envelopes
            .awaiting_columns
            .insert(root(PARENT), HeldEnvelope::new(envelope, 1, 0));
        server.note_column_stored_for_envelope(root(PARENT));
        assert_eq!(server.envelopes.work, VecDeque::from([root(PARENT)]));

        // Columns still missing: the look finds nothing ready, and the
        // envelope stays where it is.
        server.custody_columns = vec![3];
        server.settle_envelopes().await;
        assert!(
            server
                .envelopes
                .awaiting_columns
                .contains_key(&root(PARENT))
        );
    }

    #[tokio::test]
    #[cfg_attr(
        not(feature = "beacon-spec-tests"),
        ignore = "needs the fork choice fixtures; run `make consensus-spec-tests`"
    )]
    async fn unmatched_envelopes_are_capped_per_slot_and_per_root() {
        let case = Case::new("get_head", TIEBREAK);
        let mut server = case.server(12);
        let envelope = case.envelope(PARENT_ENVELOPE);
        let with_root = |byte: u8| {
            let mut envelope = envelope.clone();
            envelope.message.beacon_block_root = H256::repeat_byte(byte);
            envelope
        };

        for byte in 1..=MAX_ENVELOPES_AWAITING_BLOCK_PER_SLOT as u8 + 2 {
            server.receive_envelope(with_root(byte), 0);
        }
        // A second delivery of a held root changes nothing.
        server.receive_envelope(with_root(1), 0);

        assert_eq!(
            server.envelopes.awaiting_block.len(),
            MAX_ENVELOPES_AWAITING_BLOCK_PER_SLOT
        );
        assert!(
            server
                .envelopes
                .awaiting_block
                .contains_key(&H256::repeat_byte(1))
        );
    }

    #[tokio::test]
    #[cfg_attr(
        not(feature = "beacon-spec-tests"),
        ignore = "needs the fork choice fixtures; run `make consensus-spec-tests`"
    )]
    async fn blocks_held_for_one_parents_payload_are_capped() {
        let case = Case::new("get_head", TIEBREAK);
        let mut server = case.server(12);
        let child = case.block(CHILD);
        for extra in 0..MAX_BLOCKS_HELD_PER_PARENT_PAYLOAD as u64 + 2 {
            let mut block = child.clone();
            if let SignedBeaconBlock::Gloas(inner) = &mut block {
                inner.message.slot += extra;
            }
            server.hold_block_for_parent_payload(block, ImportTimings::default());
        }

        let held = &server.envelopes.blocks_awaiting_parent_payload;
        assert_eq!(held.len(), 1);
        assert_eq!(
            held[&child.parent_root()].len(),
            MAX_BLOCKS_HELD_PER_PARENT_PAYLOAD
        );
        assert_eq!(
            server.held_timings.len(),
            MAX_BLOCKS_HELD_PER_PARENT_PAYLOAD
        );
    }

    #[test]
    #[cfg_attr(
        not(feature = "beacon-spec-tests"),
        ignore = "needs the fork choice fixtures; run `make consensus-spec-tests`"
    )]
    fn finality_evicts_all_three_queues() {
        // The finalized slot is fixed at init, so the queues are filled
        // directly around it.
        let mut server = beacon_server(beacon_store(GENESIS_TIME, 10));
        let envelope = Case::new("get_head", TIEBREAK).envelope(PARENT_ENVELOPE);
        let held = |slot: u64| HeldEnvelope::new(envelope.clone(), slot, 0);
        let queues = &mut server.envelopes;
        queues.awaiting_block.insert(H256::repeat_byte(1), held(9));
        queues.awaiting_block.insert(H256::repeat_byte(2), held(11));
        queues
            .awaiting_columns
            .insert(H256::repeat_byte(3), held(9));
        queues
            .awaiting_columns
            .insert(H256::repeat_byte(4), held(10));
        let parent = H256::repeat_byte(5);
        queues.blocks_awaiting_parent_payload.insert(
            parent,
            HashMap::from([(H256::repeat_byte(6), 10), (H256::repeat_byte(7), 11)]),
        );
        server
            .held_timings
            .insert(H256::repeat_byte(6), ImportTimings::default());

        server.evict_envelope_queues_at_or_below_finality();

        let queues = &server.envelopes;
        assert_eq!(
            queues.awaiting_block.keys().collect::<Vec<_>>(),
            vec![&H256::repeat_byte(2)]
        );
        // The finalized slot itself stays: its children may name it as FULL.
        assert_eq!(
            queues.awaiting_columns.keys().collect::<Vec<_>>(),
            vec![&H256::repeat_byte(4)]
        );
        assert_eq!(
            queues.blocks_awaiting_parent_payload[&parent],
            HashMap::from([(H256::repeat_byte(7), 11)])
        );
        assert!(!server.held_timings.contains_key(&H256::repeat_byte(6)));
    }
}
