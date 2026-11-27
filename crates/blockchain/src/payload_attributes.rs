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
//!   each slot (Lighthouse's default `--prepare-payload-lookahead`), the actor
//!   computes the next slot's attributes on a blocking worker and publishes
//!   them on the bus, then again whenever an input to them changes before the
//!   slot: the head, on gloas the parent payload branch (the head's payload
//!   arriving, or the PTC's votes on it) and the proposer's signed
//!   preferences, and the fee recipient `prepare_beacon_proposer` names
//!   ([`AttributesKey`]). It does so only when someone is subscribed, and
//!   only for a proposer a validator client registered through
//!   `prepare_beacon_proposer`, unless `--always-prepare-payload` asks for
//!   every slot. External block builders (buildoor, for one) build from this
//!   stream.
//!
//! On gloas and PQ, the same computation also starts the payload build ahead
//! of the slot, as every other consensus client does (lambdaclass/ethlambda#894):
//! with an execution client configured, the actor sends `forkchoiceUpdatedV4`
//! with the attributes and keeps the payload id in [`PreparedPayloads`]. Block
//! production collects that build at once when its own attributes match, and
//! otherwise starts one itself. This runs whether or not anyone is subscribed
//! to the event. Fulu proposals are not prepared this way.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ethlambda_engine::building::{PayloadAttributesV3, PayloadAttributesV4, PayloadId};
use ethlambda_engine::{CustodyColumns, EngineClient, ForkchoiceStateV1};
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
use ethlambda_state_transition::beacon::pq_block_production::pq_payload_inputs;
use ethlambda_storage::{CacheKey, Chain, PubkeyIndexCache, Store};
use ethlambda_types::ShortRoot;
use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::containers::{
    BeaconState, SignedBeaconBlock, SignedExecutionPayloadEnvelope,
    gloas::{ExecutionRequests, SignedProposerPreferences},
    pq,
};
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::fork_choice::{ForkChoiceNode, PayloadStatus};
use ethlambda_types::beacon::primitives::{ExecutionAddress, Slot, ValidatorIndex};
use ethlambda_types::beacon::signing::compute_epoch_at_slot;
use ethlambda_types::primitives::H256;
use spawned_concurrency::message::Message;
use spawned_concurrency::tasks::{Context, Handler, send_after};
use tracing::{debug, info, warn};

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
    /// The payload builds the actor started ahead of their slots, shared
    /// with block production.
    pub prepared_payloads: PreparedPayloads,
    /// The attestations of the next PQ block, packed and merged ahead of its
    /// slot alongside its payload build, shared with block production. See
    /// [`crate::pq_attestation_packing`].
    pub prepared_pq_attestations: crate::pq_attestation_packing::PreparedPqAttestations,
}

/// Payload builds started ahead of their slot, by the payload id the
/// execution client gave each.
///
/// The chain actor fills it once it sends `forkchoiceUpdatedV4` with the next
/// slot's attributes. Block production takes the entry its own attributes
/// match and collects that build with `getPayload` at once, rather than start
/// a build at the slot and wait for it. A build is named by its parent
/// payload and its attributes, which is what the execution client derives its
/// payload id from. The safe and finalized hashes are left out: they do not
/// change what is built, and they can move between the two calls, at an epoch
/// boundary for one.
#[derive(Clone, Default)]
pub struct PreparedPayloads(Arc<Mutex<Vec<PreparedPayload>>>);

#[derive(Debug, Clone)]
struct PreparedPayload {
    slot: Slot,
    parent_hash: H256,
    attributes: PayloadAttributesV4,
    payload_id: PayloadId,
}

/// The most builds held at once. One slot has more than one only when the
/// head or an attribute changed after the first, and each insert drops the
/// builds for earlier slots.
const MAX_PREPARED_PAYLOADS: usize = 8;

impl PreparedPayloads {
    /// Records the build the execution client started for `slot`, on the
    /// payload `parent_hash`, with `attributes`. Drops the builds for earlier
    /// slots, and an older build with the same inputs.
    pub fn insert(
        &self,
        slot: Slot,
        parent_hash: H256,
        attributes: PayloadAttributesV4,
        payload_id: PayloadId,
    ) {
        let mut held = self.0.lock().expect("prepared payloads lock poisoned");
        held.retain(|build| {
            build.slot >= slot
                && !(build.slot == slot
                    && build.parent_hash == parent_hash
                    && build.attributes == attributes)
        });
        held.push(PreparedPayload {
            slot,
            parent_hash,
            attributes,
            payload_id,
        });
        if held.len() > MAX_PREPARED_PAYLOADS {
            held.remove(0);
        }
    }

    /// Takes the payload id of the build started for `slot` on `parent_hash`
    /// with exactly `attributes`. A build is taken once: an execution client
    /// may stop building once `getPayload` has served it.
    pub fn take(
        &self,
        slot: Slot,
        parent_hash: H256,
        attributes: &PayloadAttributesV4,
    ) -> Option<PayloadId> {
        let mut held = self.0.lock().expect("prepared payloads lock poisoned");
        let index = held.iter().position(|build| {
            build.slot == slot
                && build.parent_hash == parent_hash
                && build.attributes == *attributes
        })?;
        Some(held.swap_remove(index).payload_id)
    }
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

/// Whether a gloas proposal at `slot` on `head_root` extends the head's
/// payload rather than building on its empty branch: [`should_build_on_full`]
/// for the head node, whose payload status is the one fork choice recorded,
/// or, when none is recorded for this head yet, a fresh walk's.
pub fn parent_builds_on_full(
    store: &Store,
    head_root: H256,
    slot: Slot,
) -> Result<bool, ProposalError> {
    let payload_status = match store.head_payload_status() {
        Some(status) => status,
        None => {
            get_head_node(store, &store.config())
                .map_err(|_| ProposalError::Internal("fork choice could not name the head"))?
                .payload_status
        }
    };
    builds_on_full(store, head_root, payload_status, slot)
}

/// [`should_build_on_full`] for the head node `(head_root, payload_status)`.
/// Reads the PTC's votes on the head, so its answer can change while the head
/// and its status do not.
fn builds_on_full(
    store: &Store,
    head_root: H256,
    payload_status: PayloadStatus,
    slot: Slot,
) -> Result<bool, ProposalError> {
    let node = ForkChoiceNode {
        root: head_root,
        payload_status,
    };
    let build_on_full = should_build_on_full(store, node, slot).map_err(|_| {
        ProposalError::Internal("could not decide which parent payload to build on")
    })?;
    debug_assert_ne!(payload_status, PayloadStatus::Pending);
    Ok(build_on_full)
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
    if slot <= head_state.slot() {
        return Err(ProposalError::NotAfterHead);
    }
    let build_on_full = parent_builds_on_full(store, head_root, slot)?;
    prepare_gloas_proposal_on(store, market, head_root, head_state, slot, build_on_full)
}

/// [`prepare_gloas_proposal`] with the parent payload branch already chosen,
/// for the event, which chose it when it decided to publish.
fn prepare_gloas_proposal_on(
    store: &Store,
    market: &SharedBuilderMarket,
    head_root: H256,
    head_state: &BeaconState,
    slot: Slot,
    build_on_full: bool,
) -> Result<GloasProposal, ProposalError> {
    let config = store.config();
    let head_slot = head_state.slot();
    if slot <= head_slot {
        return Err(ProposalError::NotAfterHead);
    }

    let head_is_gloas = matches!(
        store.get_signed_block(&head_root),
        Ok(Some(SignedBeaconBlock::Gloas(_)))
    );
    let parent_requests = if build_on_full && head_is_gloas {
        store
            .get_execution_payload_envelope(&head_root)
            .map_err(|_| ProposalError::Internal("store read failed"))?
            .ok_or(ProposalError::ParentEnvelopeMissing)?
            .as_gloas()
            .ok_or(ProposalError::Internal(
                "a gloas head with a non-gloas envelope",
            ))?
            .message
            .execution_requests
            .clone()
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

/// Everything a PQ block at a slot builds on: [`GloasProposal`]'s
/// counterpart for PQ's own production endpoint (`pq_blocks/{slot}`). PQ has
/// no proposer preferences in production, so the fee recipient is
/// `prepare_beacon_proposer`'s, else the zero address.
pub struct PqProposal {
    /// The head state advanced to the proposal slot.
    pub state: BeaconState,
    pub inputs: GloasPayloadInputs,
    pub proposer: ValidatorIndex,
    /// Whether the proposal extends the head's payload.
    pub build_on_full: bool,
    /// The parent envelope's requests when building on its full payload and
    /// the parent is PQ; empty otherwise.
    pub parent_requests: pq::ExecutionRequests,
}

/// The chain-side half of a PQ proposal at `slot` on `head_root`: pick the
/// parent payload branch, advance the head state to `slot`, and derive the
/// payload inputs from it. Shared by block production and the actor's
/// preparation ahead of the slot, so the two compute the same attributes.
pub fn prepare_pq_proposal(
    store: &Store,
    head_root: H256,
    head_state: &BeaconState,
    slot: Slot,
) -> Result<PqProposal, ProposalError> {
    if slot <= head_state.slot() {
        return Err(ProposalError::NotAfterHead);
    }
    let build_on_full = parent_builds_on_full(store, head_root, slot)?;
    prepare_pq_proposal_on(store, head_root, head_state, slot, build_on_full)
}

/// [`prepare_pq_proposal`] with the parent payload branch already chosen.
fn prepare_pq_proposal_on(
    store: &Store,
    head_root: H256,
    head_state: &BeaconState,
    slot: Slot,
    build_on_full: bool,
) -> Result<PqProposal, ProposalError> {
    let config = store.config();
    if slot <= head_state.slot() {
        return Err(ProposalError::NotAfterHead);
    }
    let head_is_pq = matches!(
        store.get_signed_block(&head_root),
        Ok(Some(SignedBeaconBlock::Pq(_)))
    );
    let parent_requests = if build_on_full && head_is_pq {
        match store
            .get_execution_payload_envelope(&head_root)
            .map_err(|_| ProposalError::Internal("store read failed"))?
        {
            Some(SignedExecutionPayloadEnvelope::Pq(envelope)) => {
                envelope.message.execution_requests.clone()
            }
            Some(_) => return Err(ProposalError::Internal("a PQ head with a non-PQ envelope")),
            None => return Err(ProposalError::ParentEnvelopeMissing),
        }
    } else {
        pq::ExecutionRequests::default()
    };
    let state =
        advance_for_proposal(store, head_root, head_state, slot, &config).map_err(|err| {
            warn!(%slot, %err, "Advancing the head state to the PQ proposal slot failed");
            ProposalError::Internal("advancing the head state failed")
        })?;
    let proposer = get_beacon_proposer_index(&state)
        .map_err(|_| ProposalError::Internal("no proposer for the slot"))?;
    let inputs = pq_payload_inputs(&state, build_on_full, &parent_requests, &config)
        .map_err(|_| ProposalError::Internal("computing the payload attributes failed"))?;
    Ok(PqProposal {
        state,
        inputs,
        proposer,
        build_on_full,
        parent_requests,
    })
}

// ---------------------------------------------------------------------------
// The event
// ---------------------------------------------------------------------------

/// A payload build to start ahead of its slot: the forkchoice state and the
/// attributes `forkchoiceUpdatedV4` is sent with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PayloadBuild {
    pub(crate) forkchoice: ForkchoiceStateV1,
    pub(crate) attributes: PayloadAttributesV4,
}

/// What a worker computed for the next slot's proposal: the
/// `payload_attributes` event (fulu and gloas), and the payload build to
/// start ahead of the slot (gloas and PQ).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NextPayload {
    pub(crate) event: Option<PayloadAttributesEvent>,
    pub(crate) build: Option<PayloadBuild>,
}

/// The `payload_attributes` event for a block at `proposal_slot` on
/// `head_root`, or `None` when the slot's proposer is not one this node
/// prepares for (or the slot's fork has no block production here).
#[cfg(test)]
pub(crate) fn payload_attributes_event(
    store: &Store,
    preparation: &PayloadPreparation,
    head_root: H256,
    head_state: &BeaconState,
    proposal_slot: Slot,
    build_on_full: Option<bool>,
) -> Result<Option<PayloadAttributesEvent>, String> {
    next_payload(
        store,
        preparation,
        head_root,
        head_state,
        proposal_slot,
        build_on_full,
    )
    .map(|next| next.and_then(|next| next.event))
}

/// What the next slot's proposal asks the execution client for, when the
/// proposer is one this node prepares for (`None` otherwise, or when the
/// slot's fork has no block production here).
///
/// The attributes are the ones block production would send for that block,
/// from the same preparation: `produceBlockV3`/`produceBlockV4`'s, and PQ's
/// `pq_blocks`. On gloas and PQ, `build_on_full` is the parent payload branch
/// the worker was keyed on ([`AttributesKey`]), so the result describes
/// exactly that branch; `None` leaves the choice to [`parent_builds_on_full`].
/// PQ has no `payload_attributes` event of its own here, only the build.
/// Runs a state transition to the proposal slot, so it belongs on a blocking
/// thread.
pub(crate) fn next_payload(
    store: &Store,
    preparation: &PayloadPreparation,
    head_root: H256,
    head_state: &BeaconState,
    proposal_slot: Slot,
    build_on_full: Option<bool>,
) -> Result<Option<NextPayload>, String> {
    let config = store.config();
    let fork = config.fork_at_epoch(compute_epoch_at_slot(proposal_slot));
    let prepares_for = |proposer| {
        preparation.always_prepare
            || prepared_fee_recipient(&preparation.fee_recipients, proposer).is_some()
    };
    let choose_build_on_full = || match build_on_full {
        Some(build_on_full) => Ok(build_on_full),
        None => parent_builds_on_full(store, head_root, proposal_slot)
            .map_err(|err| format!("choosing the parent payload failed: {err:?}")),
    };
    let next = match fork {
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
            let data = PayloadAttributesEventData::V3(PayloadAttributesEventV3 {
                proposer_index: proposer,
                proposal_slot,
                parent_block_number: inputs.parent_block_number,
                parent_block_root: head_root,
                parent_block_hash: inputs.parent_hash,
                payload_attributes: (&attributes).into(),
            });
            NextPayload {
                event: Some(PayloadAttributesEvent::new(fork, data)),
                build: None,
            }
        }
        ForkName::Gloas => {
            let build_on_full = choose_build_on_full()?;
            let proposal = prepare_gloas_proposal_on(
                store,
                &preparation.builder_market,
                head_root,
                head_state,
                proposal_slot,
                build_on_full,
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
            let data = PayloadAttributesEventData::V4(PayloadAttributesEventV4 {
                proposer_index: proposal.proposer,
                proposal_slot,
                parent_block_root: head_root,
                parent_block_hash: forkchoice.head_block_hash,
                safe_block_hash: forkchoice.safe_block_hash,
                finalized_block_hash: forkchoice.finalized_block_hash,
                payload_attributes: (&attributes).into(),
            });
            NextPayload {
                event: Some(PayloadAttributesEvent::new(fork, data)),
                build: Some(PayloadBuild {
                    forkchoice,
                    attributes,
                }),
            }
        }
        // PQ blocks are produced through their own endpoint (`pq_blocks`),
        // whose preparation this is too ([`prepare_pq_proposal`]).
        ForkName::Pq => {
            let build_on_full = choose_build_on_full()?;
            let proposal =
                prepare_pq_proposal_on(store, head_root, head_state, proposal_slot, build_on_full)
                    .map_err(|err| format!("preparing the proposal failed: {err:?}"))?;
            if !prepares_for(proposal.proposer) {
                return Ok(None);
            }
            let fee_recipient =
                prepared_fee_recipient(&preparation.fee_recipients, proposal.proposer)
                    .unwrap_or(ExecutionAddress::ZERO);
            let attributes = payload_attributes_v4(&proposal.inputs, fee_recipient);
            let forkchoice = building_forkchoice_state(store, proposal.inputs.head_block_hash);
            NextPayload {
                event: None,
                build: Some(PayloadBuild {
                    forkchoice,
                    attributes,
                }),
            }
        }
        ForkName::Phase0
        | ForkName::Altair
        | ForkName::Bellatrix
        | ForkName::Capella
        | ForkName::Deneb
        | ForkName::Electra
        | ForkName::Lean => return Ok(None),
        // EIP-8483 is not followed.
        ForkName::Eip8483 => return Ok(None),
    };
    Ok(Some(next))
}

/// How far into a slot the next slot's attributes are first published: a
/// third of a slot before it ends, Lighthouse's default lookahead.
pub(crate) fn lookahead_start(slot_duration_ms: u64) -> Duration {
    Duration::from_millis(slot_duration_ms - slot_duration_ms / 3)
}

/// Whether this moment may prepare at all: someone would use the result
/// (an event subscriber, or an execution client to start the build on), the
/// node is not syncing (its head is not the chain's), and the wall clock is
/// past [`lookahead_start`]. Asked before anything reads the head, the cheap
/// check first, since every payload attestation asks.
pub(crate) fn may_publish(
    has_subscribers: bool,
    syncing: bool,
    past_lookahead: impl FnOnce() -> bool,
) -> bool {
    has_subscribers && !syncing && past_lookahead()
}

/// What one publication is for: everything the event is built from that can
/// change between the lookahead point and the proposal slot. Two moments with
/// the same key would publish the same event, so a key is published once, and
/// a worker's result is published only while its key is still the current one
/// ([`attributes_key`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AttributesKey {
    pub(crate) proposal_slot: Slot,
    pub(crate) head_root: H256,
    /// The slot's proposer, when the head state's proposer lookahead names
    /// it without a state transition.
    pub(crate) proposer: Option<ValidatorIndex>,
    /// The fee recipient `prepare_beacon_proposer` recorded for `proposer`.
    pub(crate) fee_recipient: Option<ExecutionAddress>,
    /// Gloas and PQ: whether the proposal extends the head's payload. It
    /// follows the head's payload status and, for a head at the previous slot,
    /// the PTC's votes on that payload, so either can change it. `None` before
    /// gloas, and while no status is recorded for the head, in which case the
    /// worker chooses.
    pub(crate) build_on_full: Option<bool>,
    /// Gloas: the fee recipient and gas target of the proposer's signed
    /// preferences for the slot, once this node holds them.
    pub(crate) preferences: Option<(ExecutionAddress, u64)>,
}

/// The key for a publication at `proposal_slot` on `head_root`, whose
/// post-state is `head_state`. Reads no more than a few locks and the head's
/// PTC votes, since a payload attestation asks for it hundreds of times a
/// slot; the expensive part, the advance to the slot, is the worker's.
pub(crate) fn attributes_key(
    store: &Store,
    preparation: &PayloadPreparation,
    head_root: H256,
    head_state: &BeaconState,
    proposal_slot: Slot,
) -> AttributesKey {
    let proposer = lookahead_proposer(head_state, proposal_slot);
    let fee_recipient =
        proposer.and_then(|proposer| prepared_fee_recipient(&preparation.fee_recipients, proposer));
    let fork = store
        .config()
        .fork_at_epoch(compute_epoch_at_slot(proposal_slot));
    // No walk here when the status is missing (see the field).
    let build_on_full = || {
        store
            .head_payload_status()
            .and_then(|status| builds_on_full(store, head_root, status, proposal_slot).ok())
    };
    let (build_on_full, preferences) = match fork {
        ForkName::Gloas => {
            let preferences = dependent_root_at(head_state, head_root, proposal_slot)
                .and_then(|root| preparation.builder_market.preferences(proposal_slot, root))
                .map(|signed| {
                    (
                        signed.message.fee_recipient,
                        signed.message.target_gas_limit,
                    )
                });
            (build_on_full(), preferences)
        }
        // PQ production takes no proposer preferences.
        ForkName::Pq => (build_on_full(), None),
        _ => (None, None),
    };
    AttributesKey {
        proposal_slot,
        head_root,
        proposer,
        fee_recipient,
        build_on_full,
        preferences,
    }
}

/// How many workers may fail on one key before it is given up. A failure is
/// retried on the next event that re-checks, not at once, so a persistent one
/// costs this many state transitions rather than one per payload attestation.
const MAX_ATTEMPTS: u8 = 3;

/// The chain actor's publication state. Empty (and inert) on lean, which
/// has no `PayloadPreparation`.
#[derive(Default)]
pub(crate) struct PayloadAttributesPublisher {
    preparation: Option<PayloadPreparation>,
    /// The last key whose worker finished while it was current, having
    /// published its event or found no proposer to publish it for.
    published: Option<AttributesKey>,
    /// The key a worker is running for now. At most one runs.
    in_flight: Option<AttributesKey>,
    /// The last key a worker failed on, and how many have.
    failed: Option<(AttributesKey, u8)>,
}

impl PayloadAttributesPublisher {
    pub(crate) fn new(preparation: PayloadPreparation) -> Self {
        Self {
            preparation: Some(preparation),
            ..Self::default()
        }
    }

    /// Whether to start a worker for `key`.
    ///
    /// Not for a key already published, nor for one [`MAX_ATTEMPTS`] workers
    /// failed on, nor while a worker for the same proposal slot runs: that one
    /// re-checks when it finishes, so a key that changed meanwhile is picked
    /// up then. A worker for an earlier slot no longer blocks, so one that
    /// never reports back costs a slot, not every slot after it.
    pub(crate) fn wants(&self, key: AttributesKey) -> bool {
        self.in_flight
            .is_none_or(|running| running.proposal_slot < key.proposal_slot)
            && self.published != Some(key)
            && self
                .failed
                .is_none_or(|(failed, attempts)| failed != key || attempts < MAX_ATTEMPTS)
    }

    /// Records that a worker for `key` finished. `current` says whether `key`
    /// is still the one the node would publish now, `ok` whether the worker
    /// succeeded. Returns whether to re-check at once.
    pub(crate) fn finish(&mut self, key: AttributesKey, current: bool, ok: bool) -> bool {
        if self.in_flight == Some(key) {
            self.in_flight = None;
        }
        if ok {
            if current {
                self.published = Some(key);
            }
            if self.failed.is_some_and(|(failed, _)| failed == key) {
                self.failed = None;
            }
            return true;
        }
        let attempts = match self.failed {
            Some((failed, attempts)) if failed == key => attempts.saturating_add(1),
            _ => 1,
        };
        self.failed = Some((key, attempts));
        // A key that still holds is retried on the next event that re-checks,
        // not now; one that no longer holds gives way to the current key.
        !current
    }
}

/// Self-message armed at a slot's start, delivered at its lookahead point.
pub(crate) struct PayloadAttributesCheck;
impl Message for PayloadAttributesCheck {
    type Result = ();
}

/// A worker's result, sent back to the actor, which publishes its event and
/// starts its build.
pub(crate) struct PayloadAttributesComputed {
    key: AttributesKey,
    result: Result<Option<NextPayload>, String>,
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

    /// The current key for a publication at `proposal_slot`, with the head's
    /// post-state it was read from.
    fn current_attributes_key(
        &self,
        preparation: &PayloadPreparation,
        proposal_slot: Slot,
    ) -> Option<(AttributesKey, Arc<BeaconState>)> {
        let (_, head_root) = self.store.beacon_head()?;
        let head_state = self.store.get_state(&head_root).ok()??;
        let key = attributes_key(
            &self.store,
            preparation,
            head_root,
            &head_state,
            proposal_slot,
        );
        Some((key, head_state))
    }

    /// Start a worker for the next slot's attributes on the current head, if
    /// the moment allows one, the publisher
    /// [`wants`](PayloadAttributesPublisher::wants) the current key, and the
    /// slot's proposer is one this node prepares for.
    ///
    /// Called at the lookahead point and after anything that can change the
    /// key: the tick, an import (a block, an envelope, or the columns a held
    /// one waited for), a payload attestation, and proposer preferences.
    pub(crate) fn maybe_prepare_payload_attributes(&mut self, ctx: &Context<Self>) {
        if self.store.chain() != Chain::Beacon {
            return;
        }
        let Some(preparation) = self.payload_attributes.preparation.clone() else {
            return;
        };
        let current_slot = self.wall_clock_slot();
        let past_lookahead = || {
            let ms_into_slot = self.ms_into_slot(current_slot).max(0) as u64;
            Duration::from_millis(ms_into_slot)
                >= lookahead_start(self.store.config().slot_duration_ms)
        };
        // Gloas and PQ proposals start their payload build here, so they are
        // prepared with an execution client whether or not anyone listens.
        let builds_ahead = self.engine.is_some()
            && matches!(
                self.store
                    .config()
                    .fork_at_epoch(compute_epoch_at_slot(current_slot + 1)),
                ForkName::Gloas | ForkName::Pq
            );
        if !may_publish(
            self.events.has_subscribers() || builds_ahead,
            self.sync_status.is_syncing(),
            past_lookahead,
        ) {
            return;
        }
        let Some((key, head_state)) = self.current_attributes_key(&preparation, current_slot + 1)
        else {
            return;
        };
        if !self.payload_attributes.wants(key) {
            return;
        }
        // The cheap answer first: the head state's proposer lookahead names
        // the proposer without a state transition, so a slot nobody here
        // proposes costs no worker. When it cannot (a head epochs behind, or
        // one from before fulu), the worker decides on the advanced state.
        let wanted = preparation.always_prepare
            || match key.proposer {
                Some(_) => key.fee_recipient.is_some(),
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
            let result = next_payload(
                &store,
                &preparation,
                key.head_root,
                &head_state,
                key.proposal_slot,
                key.build_on_full,
            );
            let _ = actor.send(PayloadAttributesComputed { key, result });
        });
    }

    /// Ask the execution client to start building the next slot's payload,
    /// and record the build for block production to collect. Off the actor:
    /// it only waits on the execution client. Nothing is retried on failure,
    /// since production then starts its own build as it did before.
    fn start_payload_build(&self, key: AttributesKey, build: PayloadBuild) {
        let (Some(engine), Some(preparation)) = (
            self.engine.clone(),
            self.payload_attributes.preparation.as_ref(),
        ) else {
            return;
        };
        let prepared = preparation.prepared_payloads.clone();
        let custody = CustodyColumns::from_indices(self.custody_columns.iter().copied());
        tokio::spawn(start_build(engine, prepared, custody, key, build));

        // A PQ block's attestation proofs are merged now too, rather than at
        // the slot: everything the merge reads is already here (see
        // `pq_attestation_packing`).
        let proposal_epoch = compute_epoch_at_slot(key.proposal_slot);
        if self.store.config().fork_at_epoch(proposal_epoch) == ForkName::Pq
            && let Ok(Some(head_state)) = self.store.get_state(&key.head_root)
        {
            preparation.prepared_pq_attestations.start(
                self.store.clone(),
                key.head_root,
                head_state,
                key.proposal_slot,
            );
        }
    }
}

async fn start_build(
    engine: EngineClient,
    prepared: PreparedPayloads,
    custody: Option<CustodyColumns>,
    key: AttributesKey,
    build: PayloadBuild,
) {
    let proposal_slot = key.proposal_slot;
    let head_root = ShortRoot(&key.head_root.0);
    let PayloadBuild {
        forkchoice,
        attributes,
    } = build;
    match engine
        .forkchoice_updated_v4_with_attributes(&forkchoice, &attributes, custody)
        .await
    {
        Ok((_, Some(payload_id))) => {
            info!(
                proposal_slot,
                %head_root,
                build_on_full = ?key.build_on_full,
                "Started the next slot's payload build"
            );
            prepared.insert(
                proposal_slot,
                forkchoice.head_block_hash,
                attributes,
                payload_id,
            );
        }
        Ok((status, None)) => warn!(
            proposal_slot,
            %head_root,
            status = ?status.status,
            "The execution client declined to start the next slot's payload build"
        ),
        Err(err) => warn!(
            proposal_slot,
            %head_root,
            %err,
            "Starting the next slot's payload build failed"
        ),
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
        // Published only while its key is still the one the node would
        // publish now: the next slot's block, on the same head, payload
        // branch, fee recipient and preferences. Anything else is dropped,
        // and the re-check below starts the current key's worker.
        let current = self.wall_clock_slot() + 1 == key.proposal_slot
            && self
                .payload_attributes
                .preparation
                .as_ref()
                .and_then(|preparation| self.current_attributes_key(preparation, key.proposal_slot))
                .is_some_and(|(now, _)| now == key);
        let recheck = self.payload_attributes.finish(key, current, result.is_ok());
        match result {
            Ok(Some(NextPayload { event, build })) if current => {
                if let Some(event) = event
                    && self.events.has_subscribers()
                {
                    debug!(
                        proposal_slot = key.proposal_slot,
                        head_root = %ShortRoot(&key.head_root.0),
                        "Publishing payload attributes"
                    );
                    self.events.publish_payload_attributes(event);
                }
                if let Some(build) = build {
                    self.start_payload_build(key, build);
                }
            }
            Ok(_) => {}
            Err(err) => warn!(
                proposal_slot = key.proposal_slot,
                head_root = %ShortRoot(&key.head_root.0),
                %err,
                "Computing payload attributes failed"
            ),
        }
        if recheck {
            self.maybe_prepare_payload_attributes(ctx);
        }
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

        let event = payload_attributes_event(
            &store,
            &preparation,
            head_root,
            &head_state,
            proposal_slot,
            None,
        )
        .unwrap()
        .expect("the proposer is registered");

        assert_eq!(event.version, ForkName::Fulu.as_str());
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
            None,
        )
        .unwrap();
        assert_eq!(event, None);

        let event = payload_attributes_event(
            &store,
            &preparation(true),
            head_root,
            &head_state,
            proposal_slot,
            None,
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
        let event = ChainEvent::BeaconPayloadAttributes(Box::new(PayloadAttributesEvent::new(
            ForkName::Fulu,
            PayloadAttributesEventData::V3(PayloadAttributesEventV3 {
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
        )));
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
        let event = PayloadAttributesEvent::new(
            ForkName::Gloas,
            PayloadAttributesEventData::V4(PayloadAttributesEventV4 {
                proposer_index: 123,
                proposal_slot: 10,
                parent_block_root: H256::repeat_byte(1),
                parent_block_hash: H256::repeat_byte(2),
                safe_block_hash: H256::repeat_byte(7),
                finalized_block_hash: H256::repeat_byte(8),
                payload_attributes: (&attributes).into(),
            }),
        );
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

    /// On a fulu slot the key names the lookahead's proposer and its prepared
    /// fee recipient, so a registration after the lookahead point is a new
    /// key; the gloas-only fields stay empty.
    #[test]
    fn a_fulu_key_follows_the_proposers_registration() {
        let (store, head_root, head_state) = fulu_store();
        let proposal_slot = head_state.slot() + 1;
        let preparation = preparation(false);
        let before = attributes_key(&store, &preparation, head_root, &head_state, proposal_slot);
        let proposer = lookahead_proposer(&head_state, proposal_slot).expect("in the lookahead");
        assert_eq!(
            before,
            AttributesKey {
                proposal_slot,
                head_root,
                proposer: Some(proposer),
                fee_recipient: None,
                build_on_full: None,
                preferences: None,
            }
        );

        let fee_recipient = ExecutionAddress::repeat_byte(0xab);
        preparation
            .fee_recipients
            .lock()
            .unwrap()
            .insert(proposer, fee_recipient);
        let after = attributes_key(&store, &preparation, head_root, &head_state, proposal_slot);
        assert_eq!(after.fee_recipient, Some(fee_recipient));
        assert_ne!(after, before);
    }

    fn key(proposal_slot: Slot) -> AttributesKey {
        AttributesKey {
            proposal_slot,
            head_root: H256([7; 32]),
            proposer: Some(3),
            fee_recipient: Some(ExecutionAddress::repeat_byte(1)),
            build_on_full: Some(true),
            preferences: None,
        }
    }

    /// A publisher whose last publication was for the previous slot.
    fn idle_publisher() -> PayloadAttributesPublisher {
        PayloadAttributesPublisher {
            published: Some(key(9)),
            ..PayloadAttributesPublisher::default()
        }
    }

    #[test]
    fn nothing_is_published_without_a_subscriber_while_syncing_or_early() {
        assert!(may_publish(true, false, || true));
        assert!(!may_publish(false, false, || true));
        assert!(!may_publish(true, true, || true));
        assert!(!may_publish(true, false, || false));
        // The clock is not read once the subscriber check has answered.
        assert!(!may_publish(false, false, || unreachable!()));
    }

    #[test]
    fn a_new_key_is_wanted_and_a_published_one_is_not() {
        let mut publisher = idle_publisher();
        assert!(publisher.wants(key(10)));
        publisher.published = Some(key(10));
        assert!(!publisher.wants(key(10)));
    }

    /// Every input the event is built from that can change after the
    /// lookahead point: the head, the parent payload branch (a payload
    /// arriving, or the PTC voting it late), the proposer's preferences and
    /// its prepared fee recipient.
    #[test]
    fn any_changed_input_is_a_new_key() {
        let publisher = PayloadAttributesPublisher {
            published: Some(key(10)),
            ..PayloadAttributesPublisher::default()
        };
        let changed = [
            AttributesKey {
                head_root: H256([8; 32]),
                ..key(10)
            },
            AttributesKey {
                build_on_full: Some(false),
                ..key(10)
            },
            AttributesKey {
                preferences: Some((ExecutionAddress::repeat_byte(2), 60_000_000)),
                ..key(10)
            },
            AttributesKey {
                fee_recipient: Some(ExecutionAddress::repeat_byte(2)),
                ..key(10)
            },
        ];
        for key in changed {
            assert!(publisher.wants(key), "{key:?}");
        }
    }

    #[test]
    fn a_running_worker_blocks_a_second_one_for_its_slot() {
        let mut publisher = idle_publisher();
        publisher.in_flight = Some(key(10));
        assert!(!publisher.wants(key(10)));
        assert!(!publisher.wants(AttributesKey {
            head_root: H256([8; 32]),
            ..key(10)
        }));
    }

    #[test]
    fn a_worker_for_an_earlier_slot_does_not_block() {
        let mut publisher = idle_publisher();
        publisher.in_flight = Some(key(9));
        assert!(publisher.wants(key(10)));
    }

    #[test]
    fn a_current_result_is_published_and_rechecked() {
        let mut publisher = idle_publisher();
        publisher.in_flight = Some(key(10));
        assert!(publisher.finish(key(10), true, true));
        assert_eq!(publisher.in_flight, None);
        assert_eq!(publisher.published, Some(key(10)));
        assert!(!publisher.wants(key(10)));
    }

    /// A worker whose key changed while it ran (the head's payload arrived,
    /// say) is not recorded as published, and the re-check starts the
    /// current key's worker.
    #[test]
    fn a_stale_result_is_dropped_and_the_current_key_rechecked() {
        let mut publisher = idle_publisher();
        publisher.in_flight = Some(key(10));
        assert!(publisher.finish(key(10), false, true));
        assert_eq!(publisher.published, Some(key(9)));
        assert!(publisher.wants(AttributesKey {
            build_on_full: Some(false),
            ..key(10)
        }));
        // And should the inputs swing back, the dropped key is not mistaken
        // for one already published.
        assert!(publisher.wants(key(10)));
    }

    /// A failure leaves its key wanted, for the next event that re-checks
    /// rather than straight away, until [`MAX_ATTEMPTS`] workers failed on
    /// it; a success clears the count.
    #[test]
    fn a_failed_key_is_retried_later_up_to_the_cap() {
        let mut publisher = idle_publisher();
        for attempt in 1..=MAX_ATTEMPTS {
            assert!(publisher.wants(key(10)), "attempt {attempt}");
            publisher.in_flight = Some(key(10));
            assert!(!publisher.finish(key(10), true, false));
            assert_eq!(publisher.published, Some(key(9)));
        }
        assert!(!publisher.wants(key(10)));
        // Another key is not held back by this one's failures.
        let other = AttributesKey {
            head_root: H256([8; 32]),
            ..key(10)
        };
        assert!(publisher.wants(other));
        assert!(publisher.finish(other, true, true));
        assert_eq!(publisher.failed, Some((key(10), MAX_ATTEMPTS)));

        let mut publisher = idle_publisher();
        publisher.finish(key(10), true, false);
        publisher.finish(key(10), true, true);
        assert_eq!(publisher.failed, None);
        assert_eq!(publisher.published, Some(key(10)));
    }

    /// A worker that failed on a key no longer current gives way to the
    /// current key at once.
    #[test]
    fn a_failure_on_a_stale_key_rechecks_at_once() {
        let mut publisher = idle_publisher();
        assert!(publisher.finish(key(10), false, false));
    }

    fn attributes(slot: Slot) -> PayloadAttributesV4 {
        PayloadAttributesV4 {
            v3: PayloadAttributesV3 {
                timestamp: 12 * slot,
                prev_randao: H256::repeat_byte(3),
                suggested_fee_recipient: ExecutionAddress::repeat_byte(4),
                withdrawals: Vec::new(),
                parent_beacon_block_root: H256::repeat_byte(1),
            },
            slot_number: slot,
            target_gas_limit: 60_000_000,
        }
    }

    /// Production collects a build only when it asks for exactly what was
    /// prepared: the slot, the parent payload and every attribute.
    #[test]
    fn a_prepared_build_is_taken_only_for_its_own_inputs() {
        let prepared = PreparedPayloads::default();
        let parent = H256::repeat_byte(9);
        prepared.insert(10, parent, attributes(10), PayloadId([1; 8]));

        assert_eq!(prepared.take(11, parent, &attributes(10)), None);
        assert_eq!(
            prepared.take(10, H256::repeat_byte(8), &attributes(10)),
            None
        );
        let other_recipient = PayloadAttributesV4 {
            v3: PayloadAttributesV3 {
                suggested_fee_recipient: ExecutionAddress::repeat_byte(5),
                ..attributes(10).v3
            },
            ..attributes(10)
        };
        assert_eq!(prepared.take(10, parent, &other_recipient), None);

        assert_eq!(
            prepared.take(10, parent, &attributes(10)),
            Some(PayloadId([1; 8]))
        );
        // Once: the execution client may stop building after serving it.
        assert_eq!(prepared.take(10, parent, &attributes(10)), None);
    }

    /// A slot can hold a build per head or payload branch, the newest id
    /// replaces an older one with the same inputs, and a build for a later
    /// slot drops the earlier slots'.
    #[test]
    fn builds_are_kept_per_inputs_and_dropped_once_their_slot_passed() {
        let prepared = PreparedPayloads::default();
        let (first, second) = (H256::repeat_byte(1), H256::repeat_byte(2));
        prepared.insert(10, first, attributes(10), PayloadId([1; 8]));
        prepared.insert(10, second, attributes(10), PayloadId([2; 8]));
        prepared.insert(10, first, attributes(10), PayloadId([3; 8]));
        assert_eq!(
            prepared.take(10, first, &attributes(10)),
            Some(PayloadId([3; 8]))
        );

        prepared.insert(11, first, attributes(11), PayloadId([4; 8]));
        assert_eq!(prepared.take(10, second, &attributes(10)), None);
        assert_eq!(
            prepared.take(11, first, &attributes(11)),
            Some(PayloadId([4; 8]))
        );
    }

    #[test]
    fn the_lookahead_starts_a_third_of_a_slot_before_the_next() {
        assert_eq!(lookahead_start(12_000), Duration::from_millis(8_000));
        assert_eq!(lookahead_start(6_000), Duration::from_millis(4_000));
    }
}
