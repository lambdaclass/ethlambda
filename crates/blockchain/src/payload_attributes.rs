//! Beacon payload attributes: what a block at a slot asks the execution client
//! to build, for both block production and the `payload_attributes` event.
//!
//! Two halves share this module so that they cannot disagree:
//!
//! - **Preparation**, used by the Beacon API's `produceBlockV3`/`produceBlockV4`
//!   and by the event: advancing the head state to the proposal slot, the
//!   gloas parent-payload choice, the fee recipient, and the
//!   `PayloadAttributesV3`/`V4` built from them.
//! - **The event**, published by the chain actor. A third of a slot before
//!   each slot (Lighthouse's default `--prepare-payload-lookahead`), and again
//!   whenever the head moves after that point, the actor computes the next
//!   slot's attributes on a blocking worker and publishes them on the bus. It
//!   does so only when someone is subscribed, and only for a proposer a
//!   validator client registered through `prepare_beacon_proposer`, unless
//!   `--always-prepare-payload` asks for every slot. External block builders
//!   (buildoor, for one) build from this stream.
//!
//! Nothing is sent to the execution client ahead of `produceBlock`: the early
//! `forkchoiceUpdated` other clients send with these attributes is not done
//! here yet.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ethlambda_engine::ForkchoiceStateV1;
use ethlambda_engine::building::{PayloadAttributesV3, PayloadAttributesV4};
use ethlambda_state_transition::beacon::block_production::{
    PayloadInputs, advance_to_slot, payload_inputs,
};
use ethlambda_state_transition::beacon::builder_market::SharedBuilderMarket;
use ethlambda_state_transition::beacon::fork_choice::{
    advance_to_epoch_start, get_head_node, should_build_on_full,
};
use ethlambda_state_transition::beacon::gloas_block_production::{
    GloasPayloadInputs, gloas_payload_inputs,
};
use ethlambda_state_transition::beacon::gossip::proposer_preferences::dependent_root_at;
use ethlambda_state_transition::beacon::helpers::accessors::get_beacon_proposer_index;
use ethlambda_state_transition::beacon::helpers::fulu::lookahead_proposer;
use ethlambda_state_transition::beacon::helpers::misc::compute_start_slot_at_epoch;
use ethlambda_storage::{CacheKey, Chain, PubkeyIndexCache, Store};
use ethlambda_types::ShortRoot;
use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::containers::{
    BeaconState, SignedBeaconBlock,
    gloas::{ExecutionRequests, SignedProposerPreferences},
};
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::fork_choice::{ForkChoiceNode, PayloadStatus};
use ethlambda_types::beacon::primitives::{ExecutionAddress, Slot, ValidatorIndex};
use ethlambda_types::beacon::signing::compute_epoch_at_slot;
use ethlambda_types::primitives::H256;
use spawned_concurrency::message::Message;
use spawned_concurrency::tasks::{Context, Handler, send_after};
use tracing::{debug, warn};

use crate::BlockChainServer;
use crate::beacon_payloads::checkpoint_hash;
use crate::events::{
    PayloadAttributesEvent, PayloadAttributesEventData, PayloadAttributesEventV3,
    PayloadAttributesEventV4,
};

// ---------------------------------------------------------------------------
// Preparation, shared with block production
// ---------------------------------------------------------------------------

/// Each validator's execution-layer fee recipient, as its validator client
/// last named it through `prepare_beacon_proposer` (or a builder
/// registration). Read by block production, which puts the proposer's into
/// the payload attributes, and by the chain actor, which publishes
/// `payload_attributes` for the proposers named here. In memory only: a
/// validator client repeats the call (ethlambda's and Lighthouse's every
/// slot), so a restarted node relearns the map from its next one.
pub type FeeRecipients = Arc<Mutex<HashMap<ValidatorIndex, ExecutionAddress>>>;

/// The fee recipient `prepare_beacon_proposer` recorded for `proposer`.
pub fn prepared_fee_recipient(
    fee_recipients: &FeeRecipients,
    proposer: ValidatorIndex,
) -> Option<ExecutionAddress> {
    fee_recipients
        .lock()
        .expect("fee recipient lock poisoned")
        .get(&proposer)
        .copied()
}

/// What the chain actor reads to publish `payload_attributes`: the same fee
/// recipients and builder market block production reads, and whether to
/// prepare for every slot rather than only registered proposers'.
#[derive(Clone, Default)]
pub struct PayloadPreparation {
    pub fee_recipients: FeeRecipients,
    pub builder_market: SharedBuilderMarket,
    /// `--always-prepare-payload`.
    pub always_prepare: bool,
}

/// `head_state` (the post-state of `head_root`) advanced to `slot`.
///
/// When the advance crosses into `slot`'s epoch, it starts from the store's
/// memoized epoch-start state, the [`CacheKey::CheckpointState`] entry the
/// epoch precompute fills, and records that state on a miss, flushed and
/// hashed as the precompute leaves it. So a proposal at an epoch's first slot
/// does not repeat the epoch transition the precompute already ran, and a
/// precompute that runs after this finds its work done.
pub fn advance_for_proposal(
    store: &Store,
    head_root: H256,
    head_state: &BeaconState,
    slot: Slot,
    config: &Config,
) -> ethlambda_state_transition::beacon::error::Result<BeaconState> {
    let epoch = compute_epoch_at_slot(slot);
    if head_state.slot() >= compute_start_slot_at_epoch(epoch) {
        return advance_to_slot(head_state, slot, config);
    }
    let key = CacheKey::CheckpointState {
        epoch,
        root: head_root,
    };
    let epoch_start = match store.cached_state(key) {
        Some(state) => state,
        None => {
            let state = Arc::new(advance_to_epoch_start(head_state, epoch, config)?);
            store.cache_state(key, Arc::clone(&state));
            state
        }
    };
    advance_to_slot(&epoch_start, slot, config)
}

/// The forkchoice state a payload build on `head_block_hash` is started
/// with: safe and finalized are the checkpoint blocks' hashes, by the same
/// rule the head's own `forkchoiceUpdated` uses, so the two calls never
/// disagree.
pub fn building_forkchoice_state(store: &Store, head_block_hash: H256) -> ForkchoiceStateV1 {
    ForkchoiceStateV1 {
        head_block_hash,
        safe_block_hash: checkpoint_hash(store, store.beacon_justified_checkpoint().root),
        finalized_block_hash: checkpoint_hash(store, store.beacon_finalized_checkpoint().root),
    }
}

/// `PayloadAttributesV3` for a block on `head_root` (before gloas).
pub fn payload_attributes_v3(
    inputs: &PayloadInputs,
    fee_recipient: ExecutionAddress,
    head_root: H256,
) -> PayloadAttributesV3 {
    PayloadAttributesV3 {
        timestamp: inputs.timestamp,
        prev_randao: inputs.prev_randao,
        suggested_fee_recipient: fee_recipient,
        withdrawals: inputs.withdrawals.clone(),
        parent_beacon_block_root: head_root,
    }
}

/// Everything a gloas block at a slot builds on, read from the store and the
/// head state advanced to the slot.
pub struct GloasProposal {
    /// The head state advanced to the proposal slot.
    pub state: BeaconState,
    /// The payload inputs, with the target gas limit the proposer's
    /// preferences name when this node holds them.
    pub inputs: GloasPayloadInputs,
    pub proposer: ValidatorIndex,
    pub head_root: H256,
    pub head_slot: Slot,
    /// The parent envelope's requests when building on its full payload and
    /// the parent is gloas; empty otherwise.
    pub parent_requests: ExecutionRequests,
    /// The proposer's signed preferences for the slot, when this node holds
    /// them under the slot's dependent root.
    pub preferences: Option<SignedProposerPreferences>,
    /// The store's shared pubkey table.
    pub pubkey_indices: Arc<PubkeyIndexCache>,
}

/// Why a gloas proposal could not be prepared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalError {
    /// The slot is not after the head block.
    NotAfterHead,
    /// The proposal builds on the head's full payload, and this node does not
    /// hold the head's envelope.
    ParentEnvelopeMissing,
    /// Fork choice, the store or the state transition failed.
    Internal(&'static str),
}

/// Where a gloas payload's fee recipient came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeeRecipientSource {
    /// The proposer's signed preferences.
    Preferences,
    /// `prepare_beacon_proposer`.
    Prepared,
    /// Neither: the zero address.
    Unknown,
}

/// The fee recipient a self-built gloas payload pays: the proposer's signed
/// `preferences`', else `prepare_beacon_proposer`'s, else the zero address.
pub fn gloas_fee_recipient(
    fee_recipients: &FeeRecipients,
    proposer: ValidatorIndex,
    preferences: Option<&SignedProposerPreferences>,
) -> (ExecutionAddress, FeeRecipientSource) {
    if let Some(preferences) = preferences {
        return (
            preferences.message.fee_recipient,
            FeeRecipientSource::Preferences,
        );
    }
    match prepared_fee_recipient(fee_recipients, proposer) {
        Some(recipient) => (recipient, FeeRecipientSource::Prepared),
        None => (ExecutionAddress::ZERO, FeeRecipientSource::Unknown),
    }
}

/// `PayloadAttributesV4` for a gloas block with `inputs`, paying
/// `fee_recipient`.
pub fn payload_attributes_v4(
    inputs: &GloasPayloadInputs,
    fee_recipient: ExecutionAddress,
) -> PayloadAttributesV4 {
    PayloadAttributesV4 {
        v3: PayloadAttributesV3 {
            timestamp: inputs.timestamp,
            prev_randao: inputs.prev_randao,
            suggested_fee_recipient: fee_recipient,
            withdrawals: inputs.withdrawals.clone(),
            parent_beacon_block_root: inputs.parent_beacon_block_root,
        },
        slot_number: inputs.slot_number,
        target_gas_limit: inputs.target_gas_limit,
    }
}

/// The chain-side half of a gloas proposal at `slot` on `head_root`: pick the
/// parent payload branch, advance the head state to `slot`, and derive the
/// payload inputs from it.
pub fn prepare_gloas_proposal(
    store: &Store,
    market: &SharedBuilderMarket,
    head_root: H256,
    head_state: &BeaconState,
    slot: Slot,
) -> Result<GloasProposal, ProposalError> {
    let config = store.config();
    let head_slot = head_state.slot();
    if slot <= head_slot {
        return Err(ProposalError::NotAfterHead);
    }

    // The payload branch of the head: the one fork choice recorded, or, when
    // it has not been recorded for this head yet, a fresh walk.
    let payload_status = match store.head_payload_status() {
        Some(status) => status,
        None => {
            get_head_node(store, &config)
                .map_err(|_| ProposalError::Internal("fork choice could not name the head"))?
                .payload_status
        }
    };
    let node = ForkChoiceNode {
        root: head_root,
        payload_status,
    };
    let build_on_full = should_build_on_full(store, node, slot).map_err(|_| {
        ProposalError::Internal("could not decide which parent payload to build on")
    })?;
    debug_assert_ne!(payload_status, PayloadStatus::Pending);

    let head_is_gloas = matches!(
        store.get_signed_block(&head_root),
        Ok(Some(SignedBeaconBlock::Gloas(_)))
    );
    let parent_requests = if build_on_full && head_is_gloas {
        store
            .get_execution_payload_envelope(&head_root)
            .map_err(|_| ProposalError::Internal("store read failed"))?
            .ok_or(ProposalError::ParentEnvelopeMissing)?
            .message
            .execution_requests
    } else {
        ExecutionRequests::default()
    };

    let state =
        advance_for_proposal(store, head_root, head_state, slot, &config).map_err(|err| {
            warn!(%slot, %err, "Advancing the head state to the proposal slot failed");
            ProposalError::Internal("advancing the head state failed")
        })?;
    let proposer = get_beacon_proposer_index(&state)
        .map_err(|_| ProposalError::Internal("no proposer for the slot"))?;
    let pubkey_indices = store.pubkey_index_cache();
    let mut inputs = gloas_payload_inputs(
        &state,
        build_on_full,
        &parent_requests,
        &config,
        &pubkey_indices,
    )
    .map_err(|_| ProposalError::Internal("computing the payload attributes failed"))?;

    // The proposer's signed preferences for this slot, under the dependent root
    // the head's chain gives it. They name the fee recipient and gas target the
    // bids on the slot were judged against, so the self-build follows them too.
    let preferences = dependent_root_at(head_state, head_root, slot)
        .and_then(|dependent_root| market.preferences(slot, dependent_root))
        .filter(|signed| signed.message.validator_index == proposer);
    if let Some(preferences) = &preferences {
        inputs.target_gas_limit = preferences.message.target_gas_limit;
    }
    Ok(GloasProposal {
        state,
        inputs,
        proposer,
        head_root,
        head_slot,
        parent_requests,
        preferences,
        pubkey_indices,
    })
}

// ---------------------------------------------------------------------------
// The event
// ---------------------------------------------------------------------------

/// The `payload_attributes` event for a block at `proposal_slot` on
/// `head_root`, or `None` when the slot's proposer is not one this node
/// prepares for (or the slot's fork has no block production here).
///
/// The attributes are the ones `produceBlockV3`/`produceBlockV4` would send
/// for that block, from the same preparation. Runs a state transition to the
/// proposal slot, so it belongs on a blocking thread.
pub fn payload_attributes_event(
    store: &Store,
    preparation: &PayloadPreparation,
    head_root: H256,
    head_state: &BeaconState,
    proposal_slot: Slot,
) -> Result<Option<PayloadAttributesEvent>, String> {
    let config = store.config();
    let fork = config.fork_at_epoch(compute_epoch_at_slot(proposal_slot));
    let prepares_for = |proposer| {
        preparation.always_prepare
            || prepared_fee_recipient(&preparation.fee_recipients, proposer).is_some()
    };
    let data = match fork {
        ForkName::Fulu => {
            let state = advance_for_proposal(store, head_root, head_state, proposal_slot, &config)
                .map_err(|err| format!("advancing the head state failed: {err}"))?;
            let proposer = get_beacon_proposer_index(&state)
                .map_err(|err| format!("no proposer for the slot: {err}"))?;
            if !prepares_for(proposer) {
                return Ok(None);
            }
            let inputs = payload_inputs(&state, &config)
                .map_err(|err| format!("computing the payload inputs failed: {err}"))?;
            let fee_recipient = prepared_fee_recipient(&preparation.fee_recipients, proposer)
                .unwrap_or(ExecutionAddress::ZERO);
            let attributes = payload_attributes_v3(&inputs, fee_recipient, head_root);
            PayloadAttributesEventData::V3(PayloadAttributesEventV3 {
                proposer_index: proposer,
                proposal_slot,
                parent_block_number: inputs.parent_block_number,
                parent_block_root: head_root,
                parent_block_hash: inputs.parent_hash,
                payload_attributes: (&attributes).into(),
            })
        }
        ForkName::Gloas => {
            let proposal = prepare_gloas_proposal(
                store,
                &preparation.builder_market,
                head_root,
                head_state,
                proposal_slot,
            )
            .map_err(|err| format!("preparing the proposal failed: {err:?}"))?;
            if !prepares_for(proposal.proposer) {
                return Ok(None);
            }
            let (fee_recipient, _) = gloas_fee_recipient(
                &preparation.fee_recipients,
                proposal.proposer,
                proposal.preferences.as_ref(),
            );
            let attributes = payload_attributes_v4(&proposal.inputs, fee_recipient);
            let forkchoice = building_forkchoice_state(store, proposal.inputs.head_block_hash);
            PayloadAttributesEventData::V4(PayloadAttributesEventV4 {
                proposer_index: proposal.proposer,
                proposal_slot,
                parent_block_root: head_root,
                parent_block_hash: forkchoice.head_block_hash,
                safe_block_hash: forkchoice.safe_block_hash,
                finalized_block_hash: forkchoice.finalized_block_hash,
                payload_attributes: (&attributes).into(),
            })
        }
        ForkName::Phase0
        | ForkName::Altair
        | ForkName::Bellatrix
        | ForkName::Capella
        | ForkName::Deneb
        | ForkName::Electra
        | ForkName::Lean => return Ok(None),
    };
    Ok(Some(PayloadAttributesEvent {
        version: fork,
        data,
    }))
}

/// How far into a slot the next slot's attributes are first published: a
/// third of a slot before it ends, Lighthouse's default lookahead.
pub(crate) fn lookahead_start(slot_duration_ms: u64) -> Duration {
    Duration::from_millis(slot_duration_ms - slot_duration_ms / 3)
}

/// What one publication is for: the proposal slot and the head it builds on.
/// The head's payload status is part of it, since on gloas a payload arriving
/// for the same head changes which execution block the proposal extends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AttributesKey {
    pub(crate) proposal_slot: Slot,
    pub(crate) head_root: H256,
    pub(crate) payload_status: Option<PayloadStatus>,
}

/// The chain actor's publication state. Empty (and inert) on lean, which
/// has no `PayloadPreparation`.
#[derive(Default)]
pub(crate) struct PayloadAttributesPublisher {
    preparation: Option<PayloadPreparation>,
    /// The last key a worker finished for, whatever it found.
    published: Option<AttributesKey>,
    /// The key a worker is running for now. At most one runs.
    in_flight: Option<AttributesKey>,
}

impl PayloadAttributesPublisher {
    pub(crate) fn new(preparation: PayloadPreparation) -> Self {
        Self {
            preparation: Some(preparation),
            ..Self::default()
        }
    }
}

/// Everything [`should_prepare`] reads, gathered so the decision is a pure
/// function.
pub(crate) struct DecisionInputs {
    pub(crate) has_subscribers: bool,
    pub(crate) syncing: bool,
    /// Whether the wall clock is past [`lookahead_start`] of the current slot.
    pub(crate) past_lookahead: bool,
    pub(crate) key: AttributesKey,
    pub(crate) published: Option<AttributesKey>,
    pub(crate) in_flight: Option<AttributesKey>,
}

/// Whether to start a worker for `inputs.key`.
///
/// Not without a subscriber (nobody would hear it), while syncing (the head
/// is not the chain's), before the lookahead point, for a key already done,
/// or while a worker for the same proposal slot runs: that one re-checks when
/// it finishes, so a head that moved meanwhile is picked up then. A worker
/// for an earlier slot no longer blocks, so one that never reports back
/// costs a slot, not every slot after it.
pub(crate) fn should_prepare(inputs: &DecisionInputs) -> bool {
    inputs.has_subscribers
        && !inputs.syncing
        && inputs.past_lookahead
        && inputs
            .in_flight
            .is_none_or(|running| running.proposal_slot < inputs.key.proposal_slot)
        && inputs.published != Some(inputs.key)
}

/// Self-message armed at a slot's start, delivered at its lookahead point.
pub(crate) struct PayloadAttributesCheck;
impl Message for PayloadAttributesCheck {
    type Result = ();
}

/// A worker's result, sent back to the actor, which publishes it.
pub(crate) struct PayloadAttributesComputed {
    key: AttributesKey,
    result: Result<Option<PayloadAttributesEvent>, String>,
}
impl Message for PayloadAttributesComputed {
    type Result = ();
}

impl BlockChainServer {
    /// Arm the lookahead check for `slot`, from the once-per-slot tick at its
    /// start: the delay is the lookahead point less whatever of the slot the
    /// tick has already consumed.
    pub(crate) fn arm_payload_attributes_check(&self, slot: u64, ctx: &Context<Self>) {
        if self.store.chain() != Chain::Beacon || self.payload_attributes.preparation.is_none() {
            return;
        }
        let slot_duration_ms = self.store.config().slot_duration_ms;
        let into_slot = Duration::from_millis(self.ms_into_slot(slot).max(0) as u64);
        let delay = lookahead_start(slot_duration_ms).saturating_sub(into_slot);
        send_after(delay, ctx.clone(), PayloadAttributesCheck);
    }

    /// Start a worker for the next slot's attributes on the current head, if
    /// [`should_prepare`] allows one and the slot's proposer is one this node
    /// prepares for.
    ///
    /// Called at the lookahead point and after anything that can move the
    /// head (the tick, an import, an envelope), so a head that moves after
    /// the lookahead point is published again.
    pub(crate) fn maybe_prepare_payload_attributes(&mut self, ctx: &Context<Self>) {
        if self.store.chain() != Chain::Beacon {
            return;
        }
        let Some(preparation) = self.payload_attributes.preparation.clone() else {
            return;
        };
        let Some((_, head_root)) = self.store.beacon_head() else {
            return;
        };
        let current_slot = self.wall_clock_slot();
        let slot_duration_ms = self.store.config().slot_duration_ms;
        let ms_into_slot = self.ms_into_slot(current_slot).max(0) as u64;
        let key = AttributesKey {
            proposal_slot: current_slot + 1,
            head_root,
            payload_status: self.store.head_payload_status(),
        };
        let inputs = DecisionInputs {
            has_subscribers: self.events.has_subscribers(),
            syncing: self.sync_status.is_syncing(),
            past_lookahead: Duration::from_millis(ms_into_slot)
                >= lookahead_start(slot_duration_ms),
            key,
            published: self.payload_attributes.published,
            in_flight: self.payload_attributes.in_flight,
        };
        if !should_prepare(&inputs) {
            return;
        }
        let Ok(Some(head_state)) = self.store.get_state(&head_root) else {
            return;
        };
        // The cheap answer first: the head state's proposer lookahead names
        // the proposer without a state transition, so a slot nobody here
        // proposes costs no worker. When it cannot (a head epochs behind, or
        // one from before fulu), the worker decides on the advanced state.
        let wanted = preparation.always_prepare
            || match lookahead_proposer(&head_state, key.proposal_slot) {
                Some(proposer) => {
                    prepared_fee_recipient(&preparation.fee_recipients, proposer).is_some()
                }
                None => !preparation
                    .fee_recipients
                    .lock()
                    .expect("fee recipient lock poisoned")
                    .is_empty(),
            };
        if !wanted {
            self.payload_attributes.published = Some(key);
            return;
        }

        self.payload_attributes.in_flight = Some(key);
        let store = self.store.clone();
        let actor = ctx.actor_ref();
        tokio::task::spawn_blocking(move || {
            let result = payload_attributes_event(
                &store,
                &preparation,
                key.head_root,
                &head_state,
                key.proposal_slot,
            );
            let _ = actor.send(PayloadAttributesComputed { key, result });
        });
    }
}

impl Handler<PayloadAttributesCheck> for BlockChainServer {
    async fn handle(&mut self, _msg: PayloadAttributesCheck, ctx: &Context<Self>) {
        self.maybe_prepare_payload_attributes(ctx);
    }
}

impl Handler<PayloadAttributesComputed> for BlockChainServer {
    async fn handle(&mut self, msg: PayloadAttributesComputed, ctx: &Context<Self>) {
        let PayloadAttributesComputed { key, result } = msg;
        // A worker from an earlier slot that reports late (see
        // `should_prepare`) clears nothing of the one running now.
        let publisher = &mut self.payload_attributes;
        if publisher.in_flight == Some(key) {
            publisher.in_flight = None;
        }
        if publisher
            .published
            .is_none_or(|published| published.proposal_slot <= key.proposal_slot)
        {
            publisher.published = Some(key);
        }
        // Published only while it still describes the next slot's block on
        // the current head; a stale one is dropped, and the re-check below
        // starts the current head's.
        let current = self.wall_clock_slot() + 1 == key.proposal_slot
            && self.store.beacon_head().map(|(_, root)| root) == Some(key.head_root);
        match result {
            Ok(Some(event)) if current => {
                debug!(
                    proposal_slot = key.proposal_slot,
                    head_root = %ShortRoot(&key.head_root.0),
                    "Publishing payload attributes"
                );
                self.events.publish_payload_attributes(event);
            }
            Ok(_) => {}
            Err(err) => warn!(
                proposal_slot = key.proposal_slot,
                head_root = %ShortRoot(&key.head_root.0),
                %err,
                "Computing payload attributes failed"
            ),
        }
        self.maybe_prepare_payload_attributes(ctx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ChainEvent;
    use crate::events::BeaconPayloadAttributesV3;
    use ethlambda_state_transition::beacon::helpers::{
        altair::get_next_sync_committee, fulu::initialize_proposer_lookahead,
        test_state::with_signing_validators_at,
    };
    use ethlambda_storage::{ForkCheckpoints, backend::InMemoryBackend};
    use ethlambda_types::beacon::containers::capella::Withdrawal;
    use ethlambda_types::checkpoint::Checkpoint;

    /// A store anchored at a fulu head whose proposer lookahead and sync
    /// committee are filled in, under a schedule that puts every slot at
    /// fulu. The head's root and post-state come back with it.
    fn fulu_store() -> (Store, H256, Arc<BeaconState>) {
        let mut state = with_signing_validators_at(ForkName::Fulu, 64);
        let lookahead = initialize_proposer_lookahead(&state).unwrap();
        let sync_committee = get_next_sync_committee(&state).unwrap();
        let BeaconState::Fulu(inner) = &mut state else {
            unreachable!("built as fulu")
        };
        inner.proposer_lookahead = lookahead.try_into().unwrap();
        inner.current_sync_committee = sync_committee.clone();
        inner.next_sync_committee = sync_committee;
        let slot = state.slot();
        let block = crate::tests::bare_block(slot, H256::ZERO);
        let root = block.message_hash_tree_root();
        let mut store = Store::init_beacon(
            Arc::new(InMemoryBackend::default()),
            1_606_824_023,
            Config::mainnet().with_fork_epoch(ForkName::Fulu, 0),
            root,
            Checkpoint { root, slot },
            slot,
        );
        store.insert_signed_block(root, block).unwrap();
        store.insert_state(root, state).unwrap();
        store
            .update_checkpoints(ForkCheckpoints::head_only(root))
            .unwrap();
        let head_state = store.get_state(&root).unwrap().unwrap();
        (store, root, head_state)
    }

    fn preparation(always_prepare: bool) -> PayloadPreparation {
        PayloadPreparation {
            always_prepare,
            ..PayloadPreparation::default()
        }
    }

    #[test]
    fn a_registered_proposer_gets_the_attributes_block_production_would_send() {
        let (store, head_root, head_state) = fulu_store();
        let config = store.config();
        let proposal_slot = head_state.slot() + 1;
        let advanced = advance_to_slot(&head_state, proposal_slot, &config).unwrap();
        let proposer = get_beacon_proposer_index(&advanced).unwrap();
        let inputs = payload_inputs(&advanced, &config).unwrap();
        let fee_recipient = ExecutionAddress::repeat_byte(0xab);
        let preparation = preparation(false);
        preparation
            .fee_recipients
            .lock()
            .unwrap()
            .insert(proposer, fee_recipient);

        let event =
            payload_attributes_event(&store, &preparation, head_root, &head_state, proposal_slot)
                .unwrap()
                .expect("the proposer is registered");

        assert_eq!(event.version, ForkName::Fulu);
        let expected = payload_attributes_v3(&inputs, fee_recipient, head_root);
        assert_eq!(
            event.data,
            PayloadAttributesEventData::V3(PayloadAttributesEventV3 {
                proposer_index: proposer,
                proposal_slot,
                parent_block_number: inputs.parent_block_number,
                parent_block_root: head_root,
                parent_block_hash: inputs.parent_hash,
                payload_attributes: (&expected).into(),
            })
        );
    }

    #[test]
    fn an_unregistered_proposer_gets_nothing_unless_every_slot_is_prepared() {
        let (store, head_root, head_state) = fulu_store();
        let proposal_slot = head_state.slot() + 1;

        let event = payload_attributes_event(
            &store,
            &preparation(false),
            head_root,
            &head_state,
            proposal_slot,
        )
        .unwrap();
        assert_eq!(event, None);

        let event = payload_attributes_event(
            &store,
            &preparation(true),
            head_root,
            &head_state,
            proposal_slot,
        )
        .unwrap()
        .expect("every slot is prepared");
        let PayloadAttributesEventData::V3(data) = event.data else {
            panic!("a fulu slot carries V3 attributes");
        };
        assert_eq!(
            data.payload_attributes.suggested_fee_recipient,
            ExecutionAddress::ZERO
        );
    }

    /// Crossing into the next epoch starts from the memoized epoch-start
    /// state, records it for the precompute, and lands where a plain advance
    /// does.
    #[test]
    fn an_advance_across_an_epoch_records_the_epoch_start_state() {
        let (store, head_root, head_state) = fulu_store();
        let config = store.config();
        let next_epoch = compute_epoch_at_slot(head_state.slot()) + 1;
        let slot = compute_start_slot_at_epoch(next_epoch) + 1;
        let key = CacheKey::CheckpointState {
            epoch: next_epoch,
            root: head_root,
        };
        assert!(store.cached_state(key).is_none());

        let mut advanced =
            advance_for_proposal(&store, head_root, &head_state, slot, &config).unwrap();

        let mut expected = advance_to_slot(&head_state, slot, &config).unwrap();
        advanced.apply_pending_mutations();
        expected.apply_pending_mutations();
        assert_eq!(advanced.hash_tree_root(), expected.hash_tree_root());
        let cached = store.cached_state(key).expect("recorded on the miss");
        assert_eq!(cached.slot(), compute_start_slot_at_epoch(next_epoch));
    }

    #[test]
    fn the_v3_event_serializes_as_the_beacon_api_names_it() {
        let event = ChainEvent::BeaconPayloadAttributes(Box::new(PayloadAttributesEvent {
            version: ForkName::Fulu,
            data: PayloadAttributesEventData::V3(PayloadAttributesEventV3 {
                proposer_index: 123,
                proposal_slot: 10,
                parent_block_number: 9,
                parent_block_root: H256::repeat_byte(1),
                parent_block_hash: H256::repeat_byte(2),
                payload_attributes: BeaconPayloadAttributesV3 {
                    timestamp: 123_456,
                    prev_randao: H256::repeat_byte(3),
                    suggested_fee_recipient: ExecutionAddress::repeat_byte(4),
                    withdrawals: vec![Withdrawal {
                        index: 5,
                        validator_index: 10,
                        address: ExecutionAddress::repeat_byte(6),
                        amount: 15_640,
                    }],
                    parent_beacon_block_root: H256::repeat_byte(1),
                },
            }),
        }));
        assert_eq!(event.topic(), crate::Topic::PayloadAttributes);
        let hex = |byte: u8, len: usize| format!("0x{}", format!("{byte:02x}").repeat(len));
        assert_eq!(
            serde_json::to_value(&event).unwrap(),
            serde_json::json!({
                "version": "fulu",
                "data": {
                    "proposer_index": "123",
                    "proposal_slot": "10",
                    "parent_block_number": "9",
                    "parent_block_root": hex(1, 32),
                    "parent_block_hash": hex(2, 32),
                    "payload_attributes": {
                        "timestamp": "123456",
                        "prev_randao": hex(3, 32),
                        "suggested_fee_recipient": hex(4, 20),
                        "withdrawals": [{
                            "index": "5",
                            "validator_index": "10",
                            "address": hex(6, 20),
                            "amount": "15640",
                        }],
                        "parent_beacon_block_root": hex(1, 32),
                    },
                },
            })
        );
    }

    /// beacon-APIs' gloas example: no `parent_block_number`, the forkchoice
    /// state's safe and finalized hashes, and V4's two extra fields.
    #[test]
    fn the_v4_event_serializes_as_the_beacon_api_names_it() {
        let attributes = PayloadAttributesV4 {
            v3: PayloadAttributesV3 {
                timestamp: 123_456,
                prev_randao: H256::repeat_byte(3),
                suggested_fee_recipient: ExecutionAddress::ZERO,
                withdrawals: Vec::new(),
                parent_beacon_block_root: H256::repeat_byte(1),
            },
            slot_number: 10,
            target_gas_limit: 60_000_000,
        };
        let event = PayloadAttributesEvent {
            version: ForkName::Gloas,
            data: PayloadAttributesEventData::V4(PayloadAttributesEventV4 {
                proposer_index: 123,
                proposal_slot: 10,
                parent_block_root: H256::repeat_byte(1),
                parent_block_hash: H256::repeat_byte(2),
                safe_block_hash: H256::repeat_byte(7),
                finalized_block_hash: H256::repeat_byte(8),
                payload_attributes: (&attributes).into(),
            }),
        };
        let hex = |byte: u8| format!("0x{}", format!("{byte:02x}").repeat(32));
        assert_eq!(
            serde_json::to_value(&event).unwrap(),
            serde_json::json!({
                "version": "gloas",
                "data": {
                    "proposer_index": "123",
                    "proposal_slot": "10",
                    "parent_block_root": hex(1),
                    "parent_block_hash": hex(2),
                    "safe_block_hash": hex(7),
                    "finalized_block_hash": hex(8),
                    "payload_attributes": {
                        "timestamp": "123456",
                        "prev_randao": hex(3),
                        "suggested_fee_recipient": format!("0x{}", "00".repeat(20)),
                        "withdrawals": [],
                        "parent_beacon_block_root": hex(1),
                        "slot_number": "10",
                        "target_gas_limit": "60000000",
                    },
                },
            })
        );
    }

    fn key(proposal_slot: Slot) -> AttributesKey {
        AttributesKey {
            proposal_slot,
            head_root: H256([7; 32]),
            payload_status: None,
        }
    }

    fn inputs() -> DecisionInputs {
        DecisionInputs {
            has_subscribers: true,
            syncing: false,
            past_lookahead: true,
            key: key(10),
            published: Some(key(9)),
            in_flight: None,
        }
    }

    #[test]
    fn a_new_key_past_the_lookahead_is_prepared() {
        assert!(should_prepare(&inputs()));
    }

    #[test]
    fn nothing_is_prepared_without_a_subscriber_while_syncing_or_early() {
        let mut i = inputs();
        i.has_subscribers = false;
        assert!(!should_prepare(&i));
        let mut i = inputs();
        i.syncing = true;
        assert!(!should_prepare(&i));
        let mut i = inputs();
        i.past_lookahead = false;
        assert!(!should_prepare(&i));
    }

    #[test]
    fn a_key_already_published_is_not_prepared_again() {
        let mut i = inputs();
        i.published = Some(i.key);
        assert!(!should_prepare(&i));
    }

    #[test]
    fn a_new_head_or_payload_status_is_a_new_key() {
        let mut i = inputs();
        i.published = Some(AttributesKey {
            head_root: H256([8; 32]),
            ..i.key
        });
        assert!(should_prepare(&i));
        i.published = Some(AttributesKey {
            payload_status: Some(PayloadStatus::Empty),
            ..i.key
        });
        assert!(should_prepare(&i));
    }

    #[test]
    fn a_running_worker_blocks_a_second_one_for_its_slot() {
        let mut i = inputs();
        i.in_flight = Some(key(10));
        assert!(!should_prepare(&i));
        i.in_flight = Some(AttributesKey {
            head_root: H256([8; 32]),
            ..key(10)
        });
        assert!(!should_prepare(&i));
    }

    #[test]
    fn a_worker_for_an_earlier_slot_does_not_block() {
        let mut i = inputs();
        i.in_flight = Some(key(9));
        assert!(should_prepare(&i));
    }

    #[test]
    fn the_lookahead_starts_a_third_of_a_slot_before_the_next() {
        assert_eq!(lookahead_start(12_000), Duration::from_millis(8_000));
        assert_eq!(lookahead_start(6_000), Duration::from_millis(4_000));
    }
}
