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

use ethlambda_engine::EngineError;
use ethlambda_network_api::{BlockSource, FetchRequest};
use ethlambda_state_transition::beacon::fork::ForkName;
use ethlambda_state_transition::beacon::fork_choice::{
    self, PayloadStatus, PayloadStatusEnum, PayloadValidity,
};
use ethlambda_state_transition::beacon::stf::ExecutionEngine;
use ethlambda_state_transition::beacon::stf::gloas as stf_gloas;
use ethlambda_types::ShortRoot;
use ethlambda_types::beacon::containers::{DataColumnSidecar, SignedBeaconBlock, gloas};
use ethlambda_types::primitives::{H256, HashTreeRoot as _};
use tracing::{debug, error, info, trace, warn};

use crate::beacon_engine;
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

/// How many distinct envelopes may be held for one block root this node has not
/// imported.
///
/// Nobody has checked these against a bid yet, so a forged envelope for a real
/// root must not be able to evict the honest one: the root keeps a few, and
/// when the block imports each is tried until one verifies.
pub(crate) const MAX_ENVELOPES_PER_UNMATCHED_ROOT: usize = 3;

/// How many slots an envelope for a block this node has not imported is kept.
///
/// A builder reveals its payload after the block it bid in, so the block
/// should reach this node within the slot or the next; an envelope still
/// unmatched after that is for a block that is not coming, or one the fetch
/// path (`FetchRequest::needs_envelope`) recovers later. Bounds the queue by
/// time where the per-slot and per-root caps bound it by count, so the total
/// stays finite while the chain does not finalize.
pub(crate) const ENVELOPE_AWAITING_BLOCK_TTL_SLOTS: u64 = 2;

/// How many blocks may wait on one parent's payload.
///
/// The children of a block that all name it as a FULL parent: one per slot the
/// chain skipped past it, plus equivocations.
pub(crate) const MAX_BLOCKS_HELD_PER_PARENT_PAYLOAD: usize = 4;

/// An envelope the actor is holding until it can be verified.
pub(crate) struct HeldEnvelope {
    envelope: gloas::SignedExecutionPayloadEnvelope,
    /// The envelope's own root, which tells a re-delivery from a different
    /// envelope for the same block.
    envelope_root: H256,
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
            envelope_root: envelope.hash_tree_root(),
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
    /// Envelopes whose block has no post-state yet, by the block's root, up to
    /// [`MAX_ENVELOPES_PER_UNMATCHED_ROOT`] distinct ones each.
    pub(crate) awaiting_block: HashMap<H256, Vec<HeldEnvelope>>,
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

/// The checks of `verify_execution_payload_envelope` that need only the block's
/// bid, not its post-state: the envelope is the one the bid promised.
fn envelope_matches_bid(
    envelope: &gloas::ExecutionPayloadEnvelope,
    bid: &gloas::ExecutionPayloadBid,
    block_slot: u64,
) -> bool {
    envelope.builder_index == bid.builder_index
        && envelope.payload.block_hash == bid.block_hash
        && envelope.payload.prev_randao == bid.prev_randao
        && envelope.payload.gas_limit == bid.gas_limit
        && envelope.execution_requests.hash_tree_root() == bid.execution_requests_root
        && envelope.payload.slot_number == block_slot
}

impl BlockChainServer {
    /// Take an envelope that passed gossip validation: verify it now, or hold
    /// it until what it waits on arrives. The caller then settles the queues.
    pub(crate) async fn receive_envelope(
        &mut self,
        envelope: gloas::SignedExecutionPayloadEnvelope,
        event_ms: u64,
    ) {
        let config = self.store.config();
        let arrival_slot = fork_choice::get_current_slot(&self.store, &config);
        self.apply_or_hold_envelope(HeldEnvelope::new(envelope, arrival_slot, event_ms))
            .await;
    }

    /// Verify `held` against its block, or put it back in the queue for what it
    /// is waiting on. `true` when the envelope was verified and recorded.
    async fn apply_or_hold_envelope(&mut self, held: HeldEnvelope) -> bool {
        let root = held.envelope.message.beacon_block_root;
        if self
            .store
            .beacon_block_payload_status(root)
            .is_invalidated()
        {
            trace!(
                block_root = %ShortRoot(&root.0),
                "Dropping an envelope whose payload the execution client found invalid"
            );
            return false;
        }
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
        let finalized = self
            .store
            .latest_finalized()
            .expect("finalized checkpoint exists");
        // Strictly below, and the finalized block exempted by name: its
        // children may still name it as their FULL parent, and the checkpoint
        // slot is an epoch boundary the finalized block can sit before.
        if slot < finalized.slot && root != finalized.root {
            trace!(%slot, "Dropping an envelope for a block below the finalized slot");
            return false;
        }

        let bid = match &block {
            SignedBeaconBlock::Gloas(inner) => {
                &inner.message.body.signed_execution_payload_bid.message
            }
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
        let commitment_count = bid.blob_kzg_commitments.len();

        // The cheap half of verification, before anything is held: only an
        // envelope that matches the bid its block committed to may occupy a
        // hold or cost a fetch. The signature is checked later, where an
        // envelope is parked (see `Self::hold_envelope_awaiting_columns`), or
        // by `on_execution_payload_envelope` when it is applied: gossip
        // validation does not reach it for an envelope it queued.
        if !envelope_matches_bid(&held.envelope.message, bid, slot) {
            warn!(
                %slot,
                block_root = %ShortRoot(&root.0),
                "Dropping an envelope that does not match its block's bid"
            );
            self.refetch_envelope_if_children_wait(root);
            return false;
        }

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
                    // Every sampled column was listed as stored a moment ago,
                    // so failing to read one back is a storage or decode
                    // fault, not a wait. Holding would name nothing missing
                    // and be redriven every slot for as long as the fault
                    // lasts, so the envelope is dropped (and asked for again
                    // if children wait on it).
                    warn!(
                        %slot,
                        block_root = %ShortRoot(&root.0),
                        "Dropping an envelope: a stored sampled column could not be read back"
                    );
                    self.refetch_envelope_if_children_wait(root);
                    return false;
                }
            }
        };

        // The execution client's verdict comes before the envelope is applied,
        // as `verify_execution_payload_envelope` orders it: its part is the
        // last check, and an `INVALID` payload never becomes a FULL node.
        // Without a client the follower trusts the payload, as it already does
        // for every pre-gloas block it imports (`NotRequired`).
        let status = match self.engine.clone() {
            None => PayloadStatusEnum::Valid,
            Some(client) => {
                // The client is asked only about an envelope the builder
                // signed: an unsigned copy carrying the honest block hash but a
                // different body would otherwise earn an `INVALID` verdict
                // that lands on the honest payload.
                if !self.envelope_signature_holds(root, &held.envelope) {
                    warn!(
                        %slot,
                        block_root = %ShortRoot(&root.0),
                        "Dropping an envelope with an invalid signature"
                    );
                    self.refetch_envelope_if_children_wait(root);
                    return false;
                }
                match beacon_engine::ask_envelope(&client, &block, &held.envelope).await {
                    Ok(PayloadValidity::Validated | PayloadValidity::NotRequired) => {
                        PayloadStatusEnum::Valid
                    }
                    Ok(PayloadValidity::Optimistic) => PayloadStatusEnum::Syncing,
                    Ok(PayloadValidity::Invalidated { latest_valid_hash }) => {
                        warn!(
                            %slot,
                            block_root = %ShortRoot(&root.0),
                            "Execution client found an envelope's payload invalid; not applying it"
                        );
                        self.condemn_payload_chain(root, latest_valid_hash);
                        // Children held for this payload are gone, and the
                        // head may have named a branch the verdict removed.
                        self.envelopes.verified.push_back(root);
                        return false;
                    }
                    Err(EngineError::EnvelopeMismatch(reason)) => {
                        warn!(
                            %slot,
                            block_root = %ShortRoot(&root.0),
                            reason,
                            "Dropping an envelope that does not match its block"
                        );
                        self.refetch_envelope_if_children_wait(root);
                        return false;
                    }
                    // No answer after the whole retry ladder. As for a block
                    // (`optimistic-sync.md`), the payload is not applied; the
                    // envelope is fetched again instead of held, so a client
                    // that comes back is asked afresh.
                    Err(err) => {
                        warn!(
                            %slot,
                            block_root = %ShortRoot(&root.0),
                            %err,
                            "No verdict from the execution client; not applying the envelope"
                        );
                        metrics::inc_engine_no_verdict();
                        self.request_missing_envelope(root);
                        return false;
                    }
                }
            }
        };

        self.advance_beacon_clock_to(held.event_ms);
        let config = self.store.config();
        // The engine's part of `verify_execution_payload_envelope` is answered
        // above; `VALID` and `SYNCING` both let the payload in (the CL has
        // verified it; the EL has not finished).
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
                    ?status,
                    "Execution payload envelope verified"
                );
                self.store
                    .insert_beacon_block_payload_status(root, slot, status);
                // Lets `latestValidHash` find this FULL node.
                self.store.insert_beacon_el_block_hash(
                    root,
                    slot,
                    held.envelope.message.payload.block_hash,
                );
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
                self.refetch_envelope_if_children_wait(root);
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
        if let Some(held_for_root) = queues.awaiting_block.get_mut(&root) {
            if held_for_root.len() >= MAX_ENVELOPES_PER_UNMATCHED_ROOT
                || held_for_root
                    .iter()
                    .any(|other| other.envelope_root == held.envelope_root)
            {
                return;
            }
            held_for_root.push(held);
            self.publish_envelope_queues();
            return;
        }
        let roots_at_slot = queues
            .awaiting_block
            .values()
            .filter(|others| others.iter().any(|other| other.slot == held.slot))
            .count();
        if roots_at_slot >= MAX_ENVELOPES_AWAITING_BLOCK_PER_SLOT {
            trace!(
                slot = held.slot,
                block_root = %ShortRoot(&root.0),
                "Dropping an envelope: its slot already holds the most unmatched roots allowed"
            );
            return;
        }
        debug!(
            block_root = %ShortRoot(&root.0),
            "Holding an envelope until its block is imported"
        );
        queues.awaiting_block.insert(root, vec![held]);
        self.publish_envelope_queues();
    }

    /// Whether `envelope`'s builder signature holds against the post-state of
    /// the block `root`, which must be imported. A state that cannot be read,
    /// or a builder the state does not know, reads as an invalid signature.
    fn envelope_signature_holds(
        &self,
        root: H256,
        envelope: &gloas::SignedExecutionPayloadEnvelope,
    ) -> bool {
        let Some(state) = self.store.get_state(&root).ok().flatten() else {
            return false;
        };
        stf_gloas::verify_execution_payload_envelope_signature(&state, envelope).unwrap_or(false)
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
        // Gossip validation answered `Queue` for an envelope whose block it
        // had not seen, before it reached the signature, so nothing has
        // checked this one yet. A forged copy carrying the honest payload and
        // a bad signature would otherwise take the root's one slot here and
        // shut the honest envelope out. One BLS verification per root, against
        // the state of the block it names.
        if !self.envelope_signature_holds(root, &held.envelope) {
            warn!(
                %slot,
                block_root = %ShortRoot(&root.0),
                "Dropping an envelope with an invalid signature"
            );
            self.refetch_envelope_if_children_wait(root);
            return;
        }
        info!(
            %slot,
            block_root = %ShortRoot(&root.0),
            ?missing,
            "Holding an envelope: its sampled columns have not all arrived yet"
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

    /// Once a slot: ask for the envelope of every parent that has blocks held
    /// for its payload and no envelope held or verified, so one failed fetch
    /// does not stall the child for good.
    pub(crate) fn redrive_missing_envelopes(&self) {
        for &parent_root in self.envelopes.blocks_awaiting_parent_payload.keys() {
            if !self.envelopes.awaiting_block.contains_key(&parent_root)
                && !self.envelopes.awaiting_columns.contains_key(&parent_root)
                && !self.store.has_verified_payload(&parent_root)
                && !self
                    .store
                    .beacon_block_payload_status(parent_root)
                    .is_invalidated()
            {
                self.request_missing_envelope(parent_root);
            }
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

    /// The held envelopes for `root` if what they waited on is now there.
    fn take_ready_envelopes(&mut self, root: H256) -> Vec<HeldEnvelope> {
        if self.envelopes.awaiting_block.contains_key(&root)
            && self.store.has_state(&root).expect("DB read should succeed")
        {
            return self
                .envelopes
                .awaiting_block
                .remove(&root)
                .unwrap_or_default();
        }
        let Some(slot) = self
            .envelopes
            .awaiting_columns
            .get(&root)
            .map(|held| held.slot)
        else {
            return Vec::new();
        };
        if custody_columns_present(&self.store, slot, &root, &self.custody_columns) {
            return self
                .envelopes
                .awaiting_columns
                .remove(&root)
                .into_iter()
                .collect();
        }
        Vec::new()
    }

    /// Drain the roots pushed since the last call: verify each ready envelope,
    /// import the blocks that were waiting on each verified payload, and
    /// recompute the head once if anything changed.
    pub(crate) async fn settle_envelopes(&mut self) {
        // Nothing to do on most ticks, and none at all on lean: leave the
        // gauges alone rather than rewriting them every interval.
        if self.envelopes.work.is_empty() && self.envelopes.verified.is_empty() {
            return;
        }
        let mut changed = false;
        loop {
            if let Some(root) = self.envelopes.work.pop_front() {
                // The first that verifies wins; the rest are forgeries or
                // duplicates of it. One parked for columns is enough too: it
                // matched the bid, whose block hash commits to the whole
                // payload, so a second bid-consistent candidate differs only
                // in a signature, which a parked one has had checked.
                for held in self.take_ready_envelopes(root) {
                    if self.apply_or_hold_envelope(held).await {
                        break;
                    }
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

        // The parent's payload was found invalid, so this block builds on a
        // FULL node that will never exist, and neither will its descendants.
        if self
            .store
            .beacon_block_payload_status(parent_root)
            .is_invalidated()
        {
            warn!(
                %slot,
                block_root = %ShortRoot(&block_root.0),
                parent_root = %ShortRoot(&parent_root.0),
                "Dropping a block: it builds on a payload the execution client found invalid"
            );
            self.discard_pending_subtree(block_root);
            return;
        }

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
            // Its own pending children would otherwise wait on a root that
            // never imports, and their descendants re-queue it.
            self.discard_pending_subtree(block_root);
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
        let arrived_by_sync = timings.source == Some(BlockSource::Sync);
        self.held_timings.insert(block_root, timings);
        self.publish_envelope_queues();
        // A synced block comes from a range batch, whose envelopes are already
        // being fetched alongside it. Asking again at once would fetch each
        // envelope twice, and each costs a post-state load and a signature
        // check; the once-a-slot re-ask covers any the range answer lacks.
        if !arrived_by_sync {
            self.request_missing_envelope(parent_root);
        }
    }

    /// Ask p2p for `root`'s envelope by root. The request carries nothing but
    /// the flag, since an envelope names its block and nothing else.
    pub(crate) fn request_missing_envelope(&self, root: H256) {
        if let Some(ref p2p) = self.p2p {
            let _ = p2p
                .fetch_block(FetchRequest {
                    block_root: root,
                    needs_block: false,
                    needs_envelope: true,
                    columns: Vec::new(),
                })
                .inspect_err(|err| {
                    error!(block_root = %ShortRoot(&root.0), %err, "Failed to request a missing envelope")
                });
        }
    }

    /// After an envelope was dropped: ask again if blocks wait on exactly it.
    fn refetch_envelope_if_children_wait(&self, root: H256) {
        if self
            .envelopes
            .blocks_awaiting_parent_payload
            .contains_key(&root)
        {
            self.request_missing_envelope(root);
        }
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
        let finalized = self
            .store
            .latest_finalized()
            .expect("finalized checkpoint exists");
        let finalized_slot = finalized.slot;

        // The finalized block's own envelope is exempt by name, as its
        // execution hash is from `prune_beacon_el_block_hashes`: the
        // checkpoint slot is an epoch boundary, and the block can sit before
        // a skipped one.
        let config = self.store.config();
        let current_slot = fork_choice::get_current_slot(&self.store, &config);
        self.envelopes.awaiting_block.retain(|root, held| {
            held.retain(|other| {
                let fresh =
                    other.slot.saturating_add(ENVELOPE_AWAITING_BLOCK_TTL_SLOTS) >= current_slot;
                fresh && (other.slot >= finalized_slot || *root == finalized.root)
            });
            !held.is_empty()
        });
        self.envelopes
            .awaiting_columns
            .retain(|root, held| held.slot >= finalized_slot || *root == finalized.root);

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
        let unmatched: usize = self.envelopes.awaiting_block.values().map(Vec::len).sum();
        metrics::set_envelopes_awaiting_block(unmatched as u64);
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

        server
            .receive_envelope(case.envelope(PARENT_ENVELOPE), 0)
            .await;
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

        server
            .receive_envelope(valid_envelope_for_full_parent(), 0)
            .await;
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

        server
            .receive_envelope(case.envelope(bad_envelope), 0)
            .await;
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
        server
            .receive_envelope(case.envelope(PARENT_ENVELOPE), 0)
            .await;
        assert!(server.store.has_verified_payload(&root(PARENT)));

        server
            .receive_envelope(case.envelope(PARENT_ENVELOPE), 0)
            .await;

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

    /// Gossip validation queues an envelope for an unseen block before it
    /// reaches the signature, so the actor checks it where it parks one: a
    /// copy with the honest payload and a bad signature, arriving first, must
    /// not take the root's one slot from the honest envelope.
    #[tokio::test]
    #[cfg_attr(
        not(feature = "beacon-spec-tests"),
        ignore = "needs the fork choice fixtures; run `make consensus-spec-tests`"
    )]
    async fn a_bad_signature_copy_does_not_take_the_parking_slot() {
        let case = Case::new("get_head", TIEBREAK);
        let mut server = case.server(12);
        server
            .on_block(case.block(PARENT), ImportTimings::default())
            .await;
        let honest = case.envelope(PARENT_ENVELOPE);
        let mut forged = honest.clone();
        forged.signature = Default::default();
        assert_ne!(forged.signature, honest.signature);

        server.hold_envelope_awaiting_columns(
            root(PARENT),
            1,
            HeldEnvelope::new(forged, 1, 0),
            vec![],
        );
        assert!(server.envelopes.awaiting_columns.is_empty());

        server.hold_envelope_awaiting_columns(
            root(PARENT),
            1,
            HeldEnvelope::new(honest.clone(), 1, 0),
            vec![],
        );
        assert_eq!(
            server.envelopes.awaiting_columns[&root(PARENT)].envelope,
            honest
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
            server.receive_envelope(with_root(byte), 0).await;
        }
        // A second delivery of a held root changes nothing.
        server.receive_envelope(with_root(1), 0).await;

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
        queues
            .awaiting_block
            .insert(H256::repeat_byte(1), vec![held(9)]);
        queues
            .awaiting_block
            .insert(H256::repeat_byte(2), vec![held(11)]);
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

    #[tokio::test]
    #[cfg_attr(
        not(feature = "beacon-spec-tests"),
        ignore = "needs the fork choice fixtures; run `make consensus-spec-tests`"
    )]
    async fn a_forged_envelope_for_a_root_does_not_evict_the_honest_one() {
        let case = Case::new("get_head", TIEBREAK);
        let mut server = case.server(12);
        let honest = case.envelope(PARENT_ENVELOPE);
        let forged = |gas_limit: u64| {
            let mut envelope = honest.clone();
            envelope.message.payload.gas_limit = gas_limit;
            envelope
        };

        // The forgeries arrive first and fill what the root may hold, bar one.
        for gas_limit in 1..MAX_ENVELOPES_PER_UNMATCHED_ROOT as u64 {
            server.receive_envelope(forged(gas_limit), 0).await;
        }
        server.receive_envelope(honest.clone(), 0).await;
        // A re-delivery of the honest one and a surplus forgery add nothing.
        server.receive_envelope(honest.clone(), 0).await;
        server.receive_envelope(forged(99), 0).await;
        assert_eq!(
            server.envelopes.awaiting_block[&root(PARENT)].len(),
            MAX_ENVELOPES_PER_UNMATCHED_ROOT
        );

        server
            .on_block(case.block(PARENT), ImportTimings::default())
            .await;
        server.settle_envelopes().await;

        assert!(server.store.has_verified_payload(&root(PARENT)));
        assert!(server.envelopes.awaiting_block.is_empty());
    }

    #[test]
    #[cfg_attr(
        not(feature = "beacon-spec-tests"),
        ignore = "needs the fork choice fixtures; run `make consensus-spec-tests`"
    )]
    fn the_finalized_blocks_own_envelope_survives_eviction() {
        // Finalized at slot 10, so the finalized root is the zero anchor of
        // `beacon_store`.
        let mut server = beacon_server(beacon_store(GENESIS_TIME, 10));
        let envelope = Case::new("get_head", TIEBREAK).envelope(PARENT_ENVELOPE);
        let finalized_root = server.store.latest_finalized().unwrap().root;
        server.envelopes.awaiting_block.insert(
            finalized_root,
            vec![HeldEnvelope::new(envelope.clone(), 3, 0)],
        );
        server
            .envelopes
            .awaiting_columns
            .insert(finalized_root, HeldEnvelope::new(envelope, 3, 0));

        server.evict_envelope_queues_at_or_below_finality();

        assert!(
            server
                .envelopes
                .awaiting_block
                .contains_key(&finalized_root)
        );
        assert!(
            server
                .envelopes
                .awaiting_columns
                .contains_key(&finalized_root)
        );
    }

    #[tokio::test]
    #[cfg_attr(
        not(feature = "beacon-spec-tests"),
        ignore = "needs the fork choice fixtures; run `make consensus-spec-tests`"
    )]
    async fn a_block_held_for_its_parents_payload_asks_p2p_for_the_envelope() {
        let case = Case::new("on_execution_payload_envelope", FULL_CHILD_CASE);
        let state_server = case.server(12);
        let (mut server, p2p) = crate::tests::beacon_server_recording(state_server.store.clone());
        server
            .on_block(case.block(FULL_PARENT), ImportTimings::default())
            .await;
        fork_choice::on_tick(&mut server.store, 24, &fixture_config());

        server
            .on_block(case.block(FULL_CHILD), ImportTimings::default())
            .await;

        let fetches = p2p.fetches.lock().unwrap();
        assert!(fetches.iter().any(|request| request.needs_envelope
            && !request.needs_block
            && request.block_root == root(FULL_PARENT)));
    }

    #[tokio::test]
    #[cfg_attr(
        not(feature = "beacon-spec-tests"),
        ignore = "needs the fork choice fixtures; run `make consensus-spec-tests`"
    )]
    async fn a_dropped_block_takes_its_pending_children_with_it() {
        let case = Case::new("get_head", TIEBREAK);
        let mut server = case.server(12);
        let child = case.block(CHILD);
        let held_roots: Vec<H256> = (0..MAX_BLOCKS_HELD_PER_PARENT_PAYLOAD as u64)
            .map(|extra| {
                let mut block = child.clone();
                if let SignedBeaconBlock::Gloas(inner) = &mut block {
                    inner.message.slot += extra;
                }
                let block_root = block.message_hash_tree_root();
                server.hold_block_for_parent_payload(block, ImportTimings::default());
                block_root
            })
            .collect();
        assert_eq!(held_roots.len(), MAX_BLOCKS_HELD_PER_PARENT_PAYLOAD);

        // One more, with a child pending on it: the cap drops the block and
        // the child goes too.
        let mut surplus = child.clone();
        if let SignedBeaconBlock::Gloas(inner) = &mut surplus {
            inner.message.slot += 50;
        }
        let surplus_root = surplus.message_hash_tree_root();
        let pending_child = H256::repeat_byte(0xcc);
        server.pending_blocks.insert(
            surplus_root,
            std::collections::HashSet::from([pending_child]),
        );
        server
            .pending_block_parents
            .insert(pending_child, surplus_root);

        server.hold_block_for_parent_payload(surplus, ImportTimings::default());

        assert!(server.pending_blocks.is_empty());
        assert!(server.pending_block_parents.is_empty());
    }

    /// A held child that came from range sync does not ask for its parent's
    /// envelope at once, since the range answer carries it; one that came from
    /// gossip does, as nothing else is fetching it.
    #[tokio::test]
    #[cfg_attr(
        not(feature = "beacon-spec-tests"),
        ignore = "needs the fork choice fixtures; run `make consensus-spec-tests`"
    )]
    async fn only_a_synced_held_child_skips_the_immediate_envelope_request() {
        for (source, asks) in [
            (Some(BlockSource::Sync), 0),
            (Some(BlockSource::Gossip), 1),
            (None, 1),
        ] {
            let case = Case::new("get_head", TIEBREAK);
            let mut server = case.server(12);
            let p2p = std::sync::Arc::new(crate::tests::RecordingP2P::default());
            server.p2p = Some(p2p.clone());
            let child = case.block(CHILD);
            let parent = child.parent_root();

            let timings = ImportTimings {
                source,
                ..ImportTimings::default()
            };
            server.hold_block_for_parent_payload(child, timings);

            let fetches = p2p.fetches.lock().unwrap();
            assert_eq!(fetches.len(), asks, "source {source:?}");
            assert!(fetches.iter().all(|request| request.needs_envelope
                && !request.needs_block
                && request.block_root == parent));
        }
    }

    #[test]
    fn each_slot_re_asks_for_the_envelope_of_a_parent_with_held_children() {
        let (mut server, p2p) =
            crate::tests::beacon_server_recording(beacon_store(GENESIS_TIME, 0));
        let parent = H256::repeat_byte(5);
        server
            .envelopes
            .blocks_awaiting_parent_payload
            .insert(parent, HashMap::from([(H256::repeat_byte(6), 3)]));

        server.redrive_missing_envelopes();
        server.redrive_missing_envelopes();

        let fetches = p2p.fetches.lock().unwrap();
        assert_eq!(fetches.len(), 2, "one ask per call, so one per slot");
        assert!(fetches.iter().all(|request| request.needs_envelope
            && !request.needs_block
            && request.block_root == parent));
    }

    #[test]
    #[cfg_attr(
        not(feature = "beacon-spec-tests"),
        ignore = "needs the fork choice fixtures; run `make consensus-spec-tests`"
    )]
    fn a_parent_whose_envelope_is_already_held_is_not_asked_for() {
        let (mut server, p2p) =
            crate::tests::beacon_server_recording(beacon_store(GENESIS_TIME, 0));
        let envelope = Case::new("get_head", TIEBREAK).envelope(PARENT_ENVELOPE);
        let parent = H256::repeat_byte(5);
        server
            .envelopes
            .blocks_awaiting_parent_payload
            .insert(parent, HashMap::from([(H256::repeat_byte(6), 3)]));
        server
            .envelopes
            .awaiting_block
            .insert(parent, vec![HeldEnvelope::new(envelope, 0, 0)]);

        server.redrive_missing_envelopes();

        assert!(p2p.fetches.lock().unwrap().is_empty());
    }

    #[test]
    #[cfg_attr(
        not(feature = "beacon-spec-tests"),
        ignore = "needs the fork choice fixtures; run `make consensus-spec-tests`"
    )]
    fn an_unmatched_envelope_ages_out_after_the_ttl() {
        // The store clock reads slot 10.
        let mut server = beacon_server(crate::tests::beacon_store_at_slot_10());
        let envelope = Case::new("get_head", TIEBREAK).envelope(PARENT_ENVELOPE);
        let fresh = H256::repeat_byte(1);
        let stale = H256::repeat_byte(2);
        let fresh_slot = 10 - ENVELOPE_AWAITING_BLOCK_TTL_SLOTS;
        server.envelopes.awaiting_block.insert(
            fresh,
            vec![HeldEnvelope::new(envelope.clone(), fresh_slot, 0)],
        );
        server
            .envelopes
            .awaiting_block
            .insert(stale, vec![HeldEnvelope::new(envelope, fresh_slot - 1, 0)]);

        server.evict_envelope_queues_at_or_below_finality();

        assert!(server.envelopes.awaiting_block.contains_key(&fresh));
        assert!(!server.envelopes.awaiting_block.contains_key(&stale));
    }

    #[test]
    #[cfg_attr(
        not(feature = "beacon-spec-tests"),
        ignore = "needs the fork choice fixtures; run `make consensus-spec-tests`"
    )]
    fn the_unmatched_queue_is_bounded_across_slots_by_the_ttl() {
        // Fill every slot the TTL keeps to the per-slot cap and per-root cap,
        // then read off the most the queue can hold.
        let mut server = beacon_server(crate::tests::beacon_store_at_slot_10());
        let envelope = Case::new("get_head", TIEBREAK).envelope(PARENT_ENVELOPE);
        for slot in 0..=10u64 {
            for byte in 0..MAX_ENVELOPES_AWAITING_BLOCK_PER_SLOT as u8 {
                let mut root_bytes = [0u8; 32];
                root_bytes[0] = slot as u8;
                root_bytes[1] = byte;
                server.envelopes.awaiting_block.insert(
                    H256(root_bytes),
                    vec![HeldEnvelope::new(envelope.clone(), slot, 0)],
                );
            }
        }

        server.evict_envelope_queues_at_or_below_finality();

        let kept: usize = server.envelopes.awaiting_block.values().map(Vec::len).sum();
        assert_eq!(
            kept,
            (ENVELOPE_AWAITING_BLOCK_TTL_SLOTS as usize + 1)
                * MAX_ENVELOPES_AWAITING_BLOCK_PER_SLOT
        );
    }

    #[tokio::test]
    #[cfg_attr(
        not(feature = "beacon-spec-tests"),
        ignore = "needs the fork choice fixtures; run `make consensus-spec-tests`"
    )]
    async fn a_gossip_payload_attestation_message_is_applied_to_its_blocks_votes() {
        let case = Case::new(
            "on_payload_attestation_message",
            "on_payload_attestation_message_valid",
        );
        let block = "76bf14e70fc96a5a3442a46dff3bfb897d5568cdb4dc7e94419f625df2fcd9e5";
        let message_name = "payload_attestation_message_0xeaae966a9a1931c94efc5ca0280b35bac86166ebf8d47a936156bbeb1e7179d1";
        let mut server = case.server(12);
        server
            .on_block(case.block(block), ImportTimings::default())
            .await;
        let message = gloas::PayloadAttestationMessage::from_ssz_bytes(&case.bytes(message_name))
            .expect("message decodes");
        let before = server.store.time_ms().unwrap();
        assert!(
            server
                .store
                .payload_timeliness_vote(&root(block))
                .expect("votes exist")
                .iter()
                .all(Option::is_none)
        );

        server.apply_payload_attestation_message(
            &message,
            &ethlambda_network_api::BlockArrival::now(),
        );

        assert!(server.store.time_ms().unwrap() >= before);
        assert!(
            server
                .store
                .payload_timeliness_vote(&root(block))
                .expect("votes exist")
                .contains(&Some(true))
        );
    }

    // ---------------------------------------------------------------------
    // The execution client's part: newPayloadV5 on envelope import and
    // forkchoiceUpdated for a gloas head.
    // ---------------------------------------------------------------------

    use ethlambda_engine::{EngineClient, JwtSecret};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;

    /// What the mock execution client answers and has been asked.
    #[derive(Default)]
    struct MockState {
        /// The `payloadStatus` object `engine_newPayloadV5` answers with.
        new_payload: String,
        /// The `payloadStatus` object `engine_forkchoiceUpdated*` answers with.
        forkchoice: String,
        /// Request bodies, in arrival order.
        requests: Vec<String>,
    }

    fn status_json(status: &str, latest_valid_hash: Option<H256>) -> String {
        let hash = latest_valid_hash.map_or("null".to_string(), |hash| format!("\"{hash:?}\""));
        format!(r#"{{"status":"{status}","latestValidHash":{hash},"validationError":null}}"#)
    }

    /// A hand-rolled JSON-RPC server answering by method name, like
    /// `ethlambda-engine`'s wire smoke tests but for many requests.
    async fn mock_engine(
        new_payload: String,
        forkchoice: String,
    ) -> (EngineClient, Arc<std::sync::Mutex<MockState>>) {
        let state = Arc::new(std::sync::Mutex::new(MockState {
            new_payload,
            forkchoice,
            requests: Vec::new(),
        }));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let addr = listener.local_addr().expect("bound address");
        let shared = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let shared = Arc::clone(&shared);
                tokio::spawn(async move {
                    let mut pending: Vec<u8> = Vec::new();
                    loop {
                        // One request: headers up to the blank line, then
                        // `Content-Length` bytes of body.
                        let (head_end, body_len) = loop {
                            if let Some(end) =
                                pending.windows(4).position(|window| window == b"\r\n\r\n")
                            {
                                let head = String::from_utf8_lossy(&pending[..end]).to_lowercase();
                                let len = head
                                    .lines()
                                    .find_map(|line| line.strip_prefix("content-length:"))
                                    .and_then(|value| value.trim().parse::<usize>().ok())
                                    .unwrap_or(0);
                                break (end + 4, len);
                            }
                            let mut chunk = [0u8; 16 * 1024];
                            match socket.read(&mut chunk).await {
                                Ok(0) | Err(_) => return,
                                Ok(read) => pending.extend_from_slice(&chunk[..read]),
                            }
                        };
                        while pending.len() < head_end + body_len {
                            let mut chunk = [0u8; 16 * 1024];
                            match socket.read(&mut chunk).await {
                                Ok(0) | Err(_) => return,
                                Ok(read) => pending.extend_from_slice(&chunk[..read]),
                            }
                        }
                        let body = String::from_utf8_lossy(&pending[head_end..head_end + body_len])
                            .to_string();
                        pending.drain(..head_end + body_len);

                        let result = {
                            let mut state = shared.lock().unwrap();
                            state.requests.push(body.clone());
                            if body.contains("engine_newPayloadV5") {
                                state.new_payload.clone()
                            } else {
                                state.forkchoice.clone()
                            }
                        };
                        let result = if body.contains("engine_newPayloadV5") {
                            result
                        } else {
                            format!(r#"{{"payloadStatus":{result},"payloadId":null}}"#)
                        };
                        let payload = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result}}}"#);
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{payload}",
                            payload.len()
                        );
                        if socket.write_all(response.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        let client = EngineClient::new(format!("http://{addr}"), JwtSecret::new([0x0f; 32]))
            .expect("a client");
        (client, state)
    }

    fn methods(state: &Arc<std::sync::Mutex<MockState>>) -> Vec<String> {
        state
            .lock()
            .unwrap()
            .requests
            .iter()
            .map(|body| {
                let rest = body.split("\"method\":\"").nth(1).expect("a method");
                rest.split('"').next().expect("closing quote").to_string()
            })
            .collect()
    }

    /// The `on_execution_payload_envelope` chain: a parent (FULL once its
    /// envelope is applied) and a child that builds on the FULL parent, held
    /// until the envelope verifies.
    async fn server_with_held_child(client: EngineClient) -> BlockChainServer {
        let case = Case::new("on_execution_payload_envelope", FULL_CHILD_CASE);
        let mut server = case.server(12);
        server.engine = Some(client);
        server
            .on_block(case.block(FULL_PARENT), ImportTimings::default())
            .await;
        fork_choice::on_tick(&mut server.store, 24, &fixture_config());
        server
            .on_block(case.block(FULL_CHILD), ImportTimings::default())
            .await;
        assert!(server.envelopes.is_block_held(&root(FULL_CHILD)));
        server
    }

    fn payload_hash(envelope: &gloas::SignedExecutionPayloadEnvelope) -> H256 {
        envelope.message.payload.block_hash
    }

    #[tokio::test]
    #[cfg_attr(
        not(feature = "beacon-spec-tests"),
        ignore = "needs the fork choice fixtures; run `make consensus-spec-tests`"
    )]
    async fn a_valid_verdict_applies_the_envelope_and_records_valid() {
        let (client, mock) =
            mock_engine(status_json("VALID", None), status_json("SYNCING", None)).await;
        let mut server = server_with_held_child(client).await;
        let envelope = valid_envelope_for_full_parent();

        server.receive_envelope(envelope.clone(), 0).await;
        server.settle_envelopes().await;

        assert!(server.store.has_verified_payload(&root(FULL_PARENT)));
        assert_eq!(
            server.store.beacon_block_payload_status(root(FULL_PARENT)),
            PayloadStatusEnum::Valid
        );
        assert_eq!(
            server.store.beacon_el_block_hash(root(FULL_PARENT)),
            Some(payload_hash(&envelope))
        );
        assert!(server.store.has_state(&root(FULL_CHILD)).unwrap());
        let methods = methods(&mock);
        assert_eq!(
            methods
                .iter()
                .filter(|m| *m == "engine_newPayloadV5")
                .count(),
            1
        );
        // The head is gloas, so forkchoiceUpdated is V4.
        assert!(methods.iter().any(|m| m == "engine_forkchoiceUpdatedV4"));
        assert!(!methods.iter().any(|m| m == "engine_forkchoiceUpdatedV3"));
    }

    #[tokio::test]
    #[cfg_attr(
        not(feature = "beacon-spec-tests"),
        ignore = "needs the fork choice fixtures; run `make consensus-spec-tests`"
    )]
    async fn a_syncing_verdict_applies_the_envelope_as_not_validated() {
        let (client, _mock) =
            mock_engine(status_json("SYNCING", None), status_json("SYNCING", None)).await;
        let mut server = server_with_held_child(client).await;

        server
            .receive_envelope(valid_envelope_for_full_parent(), 0)
            .await;
        server.settle_envelopes().await;

        assert!(server.store.has_verified_payload(&root(FULL_PARENT)));
        let status = server.store.beacon_block_payload_status(root(FULL_PARENT));
        assert_eq!(status, PayloadStatusEnum::Syncing);
        assert!(status.is_not_validated());
        assert!(server.store.has_state(&root(FULL_CHILD)).unwrap());
    }

    #[tokio::test]
    #[cfg_attr(
        not(feature = "beacon-spec-tests"),
        ignore = "needs the fork choice fixtures; run `make consensus-spec-tests`"
    )]
    async fn an_invalid_verdict_leaves_no_full_node_and_drops_the_full_child() {
        let (client, mock) =
            mock_engine(status_json("INVALID", None), status_json("SYNCING", None)).await;
        let mut server = server_with_held_child(client).await;

        server
            .receive_envelope(valid_envelope_for_full_parent(), 0)
            .await;
        server.settle_envelopes().await;

        assert!(!server.store.has_verified_payload(&root(FULL_PARENT)));
        assert_eq!(
            server.store.beacon_block_payload_status(root(FULL_PARENT)),
            PayloadStatusEnum::Invalid
        );
        // The child built on the FULL node, so it is gone; the parent block and
        // its EMPTY branch stay.
        assert!(!server.envelopes.is_block_held(&root(FULL_CHILD)));
        assert!(!server.store.has_state(&root(FULL_CHILD)).unwrap());
        assert!(server.store.block_index().contains_key(&root(FULL_PARENT)));
        assert_eq!(head(&server), (root(FULL_PARENT), PayloadStatus::Empty));

        // A second delivery is not asked about again, and a later block that
        // builds on the FULL node is dropped instead of held.
        server
            .receive_envelope(valid_envelope_for_full_parent(), 0)
            .await;
        let case = Case::new("on_execution_payload_envelope", FULL_CHILD_CASE);
        server
            .on_block(case.block(FULL_CHILD), ImportTimings::default())
            .await;
        assert!(!server.envelopes.is_block_held(&root(FULL_CHILD)));
        let asked = methods(&mock)
            .iter()
            .filter(|m| *m == "engine_newPayloadV5")
            .count();
        assert_eq!(asked, 1);
    }

    #[tokio::test]
    #[cfg_attr(
        not(feature = "beacon-spec-tests"),
        ignore = "needs the fork choice fixtures; run `make consensus-spec-tests`"
    )]
    async fn no_verdict_does_not_apply_the_envelope() {
        // Port 1 has nothing listening, so every attempt is refused at once.
        let client = EngineClient::new("http://127.0.0.1:1".to_string(), JwtSecret::new([0u8; 32]))
            .expect("client builds");
        let mut server = server_with_held_child(client).await;

        server
            .receive_envelope(valid_envelope_for_full_parent(), 0)
            .await;

        assert!(!server.store.has_verified_payload(&root(FULL_PARENT)));
        assert!(server.envelopes.is_block_held(&root(FULL_CHILD)));
    }

    /// The fixture payloads all hash to zero, which `forkchoiceUpdated` rightly
    /// treats as "nothing to say"; give `root`'s bid and cached payload a real
    /// hash so the call can be observed.
    fn give_payload_a_hash(server: &mut BlockChainServer, root: H256, hash: H256) {
        let mut block = server
            .store
            .get_signed_block(&root)
            .unwrap()
            .expect("block stored");
        let slot = block.slot();
        match &mut block {
            SignedBeaconBlock::Gloas(inner) => {
                inner
                    .message
                    .body
                    .signed_execution_payload_bid
                    .message
                    .block_hash = hash;
            }
            _ => panic!("a gloas block"),
        }
        server
            .store
            .insert_pending_block(root, block)
            .expect("overwrite");
        server.store.insert_beacon_el_block_hash(root, slot, hash);
    }

    /// A server whose only block is `FULL_PARENT`, its envelope applied with
    /// `new_payload`'s verdict, then given a nonzero payload hash and made the
    /// FULL head.
    async fn full_head_server(
        new_payload: &str,
        forkchoice: &str,
    ) -> (BlockChainServer, Arc<std::sync::Mutex<MockState>>, H256) {
        let (client, mock) = mock_engine(
            status_json(new_payload, None),
            status_json(forkchoice, None),
        )
        .await;
        let case = Case::new("on_execution_payload_envelope", FULL_CHILD_CASE);
        let mut server = case.server(12);
        server.engine = Some(client);
        server
            .on_block(case.block(FULL_PARENT), ImportTimings::default())
            .await;
        server
            .receive_envelope(valid_envelope_for_full_parent(), 0)
            .await;
        server.settle_envelopes().await;
        assert!(server.store.has_verified_payload(&root(FULL_PARENT)));

        let hash = H256::repeat_byte(0x42);
        give_payload_a_hash(&mut server, root(FULL_PARENT), hash);
        fork_choice::get_head(&mut server.store, &fixture_config()).expect("head");
        server
            .store
            .set_head_payload_status(root(FULL_PARENT), PayloadStatus::Full);
        (server, mock, hash)
    }

    #[tokio::test]
    #[cfg_attr(
        not(feature = "beacon-spec-tests"),
        ignore = "needs the fork choice fixtures; run `make consensus-spec-tests`"
    )]
    async fn the_forkchoice_hashes_follow_the_head_node_and_the_checkpoints_bids() {
        let (server, _mock, hash) = full_head_server("VALID", "SYNCING").await;
        let parent = server
            .store
            .get_signed_block(&root(FULL_PARENT))
            .unwrap()
            .unwrap();
        let bid = crate::beacon_payloads::bid_of(&parent).expect("gloas block");
        let anchor_root = server.store.beacon_finalized_checkpoint().root;
        let anchor = server
            .store
            .get_signed_block(&anchor_root)
            .unwrap()
            .unwrap();
        let anchor_parent_hash = crate::beacon_payloads::bid_of(&anchor)
            .expect("gloas anchor")
            .parent_block_hash;

        // A FULL head names the revealed payload; finalized and safe are the
        // checkpoint blocks' bids' parent hashes.
        let plan = crate::beacon_payloads::forkchoice_plan(&server.store, root(FULL_PARENT))
            .expect("a plan");
        assert!(plan.gloas);
        assert_eq!(plan.state.head_block_hash, hash);
        assert_eq!(plan.state.finalized_block_hash, anchor_parent_hash);
        assert_eq!(plan.state.safe_block_hash, anchor_parent_hash);

        // An EMPTY head names the payload before it.
        server
            .store
            .set_head_payload_status(root(FULL_PARENT), PayloadStatus::Empty);
        let plan = crate::beacon_payloads::forkchoice_plan(&server.store, root(FULL_PARENT))
            .expect("a plan");
        assert_eq!(plan.state.head_block_hash, bid.parent_block_hash);

        // No status for the head yet: nothing to say.
        server
            .store
            .set_head_payload_status(H256::repeat_byte(1), PayloadStatus::Full);
        assert!(
            crate::beacon_payloads::forkchoice_plan(&server.store, root(FULL_PARENT)).is_none()
        );
    }

    #[test]
    fn a_pre_gloas_head_keeps_its_own_hash_and_uses_forkchoice_v3() {
        let mut store = beacon_store(GENESIS_TIME, 0);
        let block = crate::tests::fulu_block(H256::ZERO, 1, 0);
        let block_root = block.message_hash_tree_root();
        store
            .insert_pending_block(block_root, block)
            .expect("insert");
        store.insert_beacon_el_block_hash(block_root, 1, H256::repeat_byte(7));

        let plan = crate::beacon_payloads::forkchoice_plan(&store, block_root).expect("a plan");

        assert!(!plan.gloas);
        assert_eq!(plan.state.head_block_hash, H256::repeat_byte(7));
    }

    #[tokio::test]
    #[cfg_attr(
        not(feature = "beacon-spec-tests"),
        ignore = "needs the fork choice fixtures; run `make consensus-spec-tests`"
    )]
    async fn a_gloas_head_sends_forkchoice_v4_with_the_custody_columns() {
        let (mut server, mock, hash) = full_head_server("VALID", "SYNCING").await;
        server.custody_columns = vec![0, 9];

        server.notify_forkchoice_updated().await;

        let last = mock
            .lock()
            .unwrap()
            .requests
            .last()
            .cloned()
            .expect("a request");
        assert!(last.contains("engine_forkchoiceUpdatedV4"));
        assert!(last.contains(&format!("{hash:?}")));
        // Columns 0 and 9 as a little-endian bitvector.
        assert!(last.contains("0x01020000000000000000000000000000"));
    }

    #[tokio::test]
    #[cfg_attr(
        not(feature = "beacon-spec-tests"),
        ignore = "needs the fork choice fixtures; run `make consensus-spec-tests`"
    )]
    async fn a_valid_forkchoice_response_promotes_optimistic_payloads() {
        let (mut server, mock, _hash) = full_head_server("SYNCING", "SYNCING").await;
        assert_eq!(
            server.store.beacon_block_payload_status(root(FULL_PARENT)),
            PayloadStatusEnum::Syncing
        );

        // Still syncing: nothing changes.
        server.notify_forkchoice_updated().await;
        assert_eq!(
            server.store.beacon_block_payload_status(root(FULL_PARENT)),
            PayloadStatusEnum::Syncing
        );

        mock.lock().unwrap().forkchoice = status_json("VALID", None);
        server.notify_forkchoice_updated().await;

        assert_eq!(
            server.store.beacon_block_payload_status(root(FULL_PARENT)),
            PayloadStatusEnum::Valid
        );
        assert!(!server.store.has_unvalidated_block_payloads());
    }

    #[tokio::test]
    #[cfg_attr(
        not(feature = "beacon-spec-tests"),
        ignore = "needs the fork choice fixtures; run `make consensus-spec-tests`"
    )]
    async fn an_invalid_forkchoice_response_unverifies_the_payload_and_keeps_the_block() {
        let (mut server, _mock, _hash) = full_head_server("SYNCING", "INVALID").await;

        server.notify_forkchoice_updated().await;

        assert!(!server.store.has_verified_payload(&root(FULL_PARENT)));
        assert_eq!(
            server.store.beacon_block_payload_status(root(FULL_PARENT)),
            PayloadStatusEnum::Invalid
        );
        assert!(server.store.block_index().contains_key(&root(FULL_PARENT)));
        assert_eq!(head(&server), (root(FULL_PARENT), PayloadStatus::Empty));
    }

    #[tokio::test]
    #[cfg_attr(
        not(feature = "beacon-spec-tests"),
        ignore = "needs the fork choice fixtures; run `make consensus-spec-tests`"
    )]
    async fn an_invalid_forkchoice_response_removes_a_child_built_on_the_full_payload() {
        let (mut server, _mock, hash) = full_head_server("SYNCING", "INVALID").await;
        // A child whose bid names the parent's payload as its own parent: the
        // fixture child, retargeted at the hash this test gave the payload.
        let case = Case::new("on_execution_payload_envelope", FULL_CHILD_CASE);
        let mut child = case.block(FULL_CHILD);
        let child_root = child.message_hash_tree_root();
        match &mut child {
            SignedBeaconBlock::Gloas(inner) => {
                inner
                    .message
                    .body
                    .signed_execution_payload_bid
                    .message
                    .parent_block_hash = hash;
            }
            _ => panic!("a gloas block"),
        }
        server
            .store
            .insert_pending_block(child_root, child)
            .expect("insert");
        let child_slot = server
            .store
            .get_signed_block(&child_root)
            .unwrap()
            .unwrap()
            .slot();
        server
            .store
            .insert_live_chain_entry(child_slot, child_root, root(FULL_PARENT));
        assert!(server.store.block_index().contains_key(&child_root));

        server.notify_forkchoice_updated().await;

        assert!(!server.store.block_index().contains_key(&child_root));
    }
}
