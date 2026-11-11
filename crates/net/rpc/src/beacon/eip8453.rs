//! EIP-8453's ("Decoupled Consensus") validator endpoints.
//!
//! No beacon-APIs specification exists for EIP-8453, so these are this node's
//! own, kept close to the standard endpoints' shapes: JSON with quoted
//! integers, `Eth-Consensus-Version` on fork-versioned bodies, the duties
//! envelope (`dependent_root`, `execution_optimistic`, `data`) for duties, and
//! the pool endpoints' `IndexedErrorMessage` for refused submissions. Prysm's
//! `decoupled-consensus-passing-spec-tests` branch serves its duties over
//! deprecated gRPC-gateway paths under `/eth/v1alpha1/validator/` for an
//! earlier design (`AvailableAttestation`, no payload status), which a client
//! of EIP-8453 as specified cannot use, so nothing here follows it.
//!
//! - `POST /eth/v1/validator/duties/attestation_committee/{epoch}`: each
//!   requested validator's attestation committee for the epoch
//!   (`get_attestation_committee_assignment`) and the slots of the epoch it
//!   attests in (`compute_attestation_committee_slot` for each round).
//! - `POST /eth/v1/validator/duties/head_vote/{epoch}`: the slots of the
//!   epoch each requested validator sits on the head vote committee in
//!   (`get_head_vote_committee_assignments`).
//! - `GET /eth/v1/validator/head_vote_data?slot`: the `HeadVoteData` a
//!   committee member of `slot` signs (`Eip8453Node::vote_head`).
//! - `GET /eth/v1/validator/finality_attestation_input?slot`: what an attester
//!   of `slot` selects its `AttestationData` from (target, justified, finalized
//!   height), or `204` when it must not attest. The signing record that turns
//!   these into data is the validator client's, so the node serves inputs.
//! - `POST /eth/v1/beacon/pool/head_votes`: signed `HeadVoteMessage`s, run
//!   through the `head_vote` gossip rules and the fork choice, then gossiped.
//!
//! FG attestations are submitted on `POST /eth/v2/beacon/pool/attestations`
//! with `Eth-Consensus-Version: eip8453` (see `pool.rs`, which hands them to
//! [`post_fg_attestations`]).
//!
//! The data endpoints answer for the protocol instant each input belongs to,
//! recorded by the shared [`SharedEip8453Node`] as its clock passes it: the
//! head vote deadline (`HEAD_VOTE_DUE_BPS`) for head vote data, and the
//! support cutoff (`SUPPORT_CUTOFF_BPS`) for the finality attestation input,
//! the first instant `get_ac_frame` answers in a slot. Asked before that
//! instant they answer `503`; asked about another slot than the node's
//! current one, `400`.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::{
    Extension, Json, Router,
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use ethlambda_network_api::RpcToP2PRef;
use ethlambda_state_transition::beacon::{
    eip8453_node::{DutyError, SharedEip8453Node},
    gossip::{IgnoreReason, Outcome, fg_attestation, head_vote},
    helpers::eip8453::{
        attestation_committee_slots, get_attestation_committee_assignments, get_head_vote_committee,
    },
};
use ethlambda_storage::Store;
use ethlambda_types::beacon::{
    config::Config,
    containers::{BeaconState, eip8453},
    fork::ForkName,
    preset,
    primitives::{BlsPubkey, CommitteeIndex, Epoch, Slot, ValidatorIndex},
    signing::{compute_epoch_at_slot, compute_start_slot_at_epoch},
};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::beacon::{
    ApiError, decode_list,
    pool::{Failure, batch_response},
    validator::{
        block_root_at_or_before, duties_response, epoch_upper_bound, head, parse_epoch,
        require_validated, state_for_epoch,
    },
};
use crate::shared::content::with_consensus_version;

pub(crate) fn routes() -> Router<Store> {
    Router::new()
        .route(
            "/eth/v1/validator/duties/attestation_committee/{epoch}",
            post(post_attestation_committee_duties),
        )
        .route(
            "/eth/v1/validator/duties/head_vote/{epoch}",
            post(post_head_vote_duties),
        )
        .route("/eth/v1/validator/head_vote_data", get(get_head_vote_data))
        .route(
            "/eth/v1/validator/finality_attestation_input",
            get(get_finality_attestation_input),
        )
        .route("/eth/v1/beacon/pool/head_votes", post(post_pool_head_votes))
}

/// The wall clock the EIP-8453 endpoints read, in Unix milliseconds: the
/// system's, unless a test fixed it.
///
/// The fork choice engine's duty inputs are a function of the instant they
/// are asked at, so a test that drives a node on a simulated clock (as the
/// in-process network does) layers a fixed one; the server layers none, and an
/// absent extension reads the system clock.
#[derive(Debug, Clone, Default)]
pub struct NodeClock(Option<Arc<AtomicU64>>);

impl NodeClock {
    /// A clock that reads `now_ms` until [`Self::set`] moves it.
    pub fn fixed(now_ms: u64) -> Self {
        Self(Some(Arc::new(AtomicU64::new(now_ms))))
    }

    /// Move a fixed clock. No effect on the system one.
    pub fn set(&self, now_ms: u64) {
        if let Some(fixed) = &self.0 {
            fixed.store(now_ms, Ordering::SeqCst);
        }
    }

    pub fn now_ms(&self) -> u64 {
        match &self.0 {
            Some(fixed) => fixed.load(Ordering::SeqCst),
            None => system_now_ms(),
        }
    }
}

fn system_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

/// The time an optional [`NodeClock`] extension reads.
pub(crate) fn now_ms(clock: Option<&Extension<NodeClock>>) -> u64 {
    clock.map_or_else(system_now_ms, |Extension(clock)| clock.now_ms())
}

/// Refuses an epoch the schedule does not place at EIP-8453 or later.
fn require_eip8453_epoch(config: &Config, epoch: Epoch) -> Result<(), ApiError> {
    if config.fork_at_epoch(epoch) >= ForkName::Eip8453 {
        Ok(())
    } else {
        Err(ApiError::BadRequest(
            "the epoch is before EIP8453_FORK_EPOCH: these duties do not exist there",
        ))
    }
}

fn parse_indices(indices: &[String]) -> Result<HashSet<ValidatorIndex>, ApiError> {
    indices
        .iter()
        .map(|index| index.parse::<ValidatorIndex>())
        .collect::<Result<HashSet<_>, _>>()
        .map_err(|_| ApiError::BadRequest("invalid validator index"))
}

/// The block root a duty of `epoch` computed from the chain ending in
/// `head_root` depends on.
///
/// Attestation committees depend only on which validators are active in the
/// epoch, which the registry fixes `MAX_SEED_LOOKAHEAD` epochs ahead, and head
/// vote committees are drawn at the epoch transition into `epoch - 1` (seed and
/// effective balances of the chain through the last slot of `epoch - 2`). So
/// the attester duties' definition, the block at
/// `compute_start_slot_at_epoch(epoch - 1) - 1`, is sound for both, and
/// conservative for attestation committees. The one exception is the head
/// vote committees of the fork epoch itself: `upgrade_to_eip8453` draws them
/// at the fork's first slot, from the chain through the last pre-fork block,
/// so they depend on the block at `compute_start_slot_at_epoch(epoch) - 1`.
fn dependent_slot(config: &Config, epoch: Epoch, head_votes: bool) -> Slot {
    let epoch = if head_votes && epoch == config.eip8453_fork_epoch {
        epoch
    } else {
        epoch.saturating_sub(1)
    };
    compute_start_slot_at_epoch(epoch).saturating_sub(1)
}

// ── Attestation committee duties ────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct AttestationCommitteeDuty {
    pubkey: BlsPubkey,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    validator_index: ValidatorIndex,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    committee_index: CommitteeIndex,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    committee_length: u64,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    validator_committee_index: u64,
    /// The slots of the epoch the committee attests in, one per round,
    /// ascending, as quoted decimals.
    slots: Vec<String>,
}

/// `POST /eth/v1/validator/duties/attestation_committee/{epoch}`, with the
/// validator indices to report on as a JSON array of decimal strings.
///
/// Every active validator sits on exactly one attestation committee an epoch
/// and attests once a round, in its committee's slot of that round. The epoch
/// bounds are the attester duties' (one before the head's, up to one past the
/// wall clock's), and so is the state: the head's, or the head advanced to the
/// epoch before `epoch` when that is further. An epoch before the fork is a
/// `400`. `dependent_root` is the block at
/// `compute_start_slot_at_epoch(epoch - 1) - 1`.
async fn post_attestation_committee_duties(
    Path(epoch): Path<String>,
    State(store): State<Store>,
    Json(indices): Json<Vec<String>>,
) -> Response {
    let computed =
        tokio::task::spawn_blocking(move || attestation_committee_duties(&store, &epoch, &indices))
            .await;
    duties_response(computed)
}

fn attestation_committee_duties(
    store: &Store,
    epoch: &str,
    indices: &[String],
) -> Result<serde_json::Value, ApiError> {
    let epoch = parse_epoch(epoch)?;
    let wanted = parse_indices(indices)?;
    let config = store.config();
    require_eip8453_epoch(&config, epoch)?;
    let (head_root, head_state) = head(store)?;
    let head_epoch = compute_epoch_at_slot(head_state.slot());
    if epoch + 1 < head_epoch || epoch > epoch_upper_bound(store, head_epoch) {
        return Err(ApiError::BadRequest(
            "epoch is outside the range the node serves duties for",
        ));
    }
    let state = if epoch > head_epoch + 1 {
        state_for_epoch(store, head_root, epoch - 1)?
    } else {
        head_state.clone()
    };
    let assignments =
        get_attestation_committee_assignments(&state, epoch, |index| wanted.contains(&index))
            .map_err(|_| ApiError::Internal("computing the attestation committees failed"))?;
    let mut duties = Vec::with_capacity(assignments.len());
    for (validator_index, assignment) in assignments {
        let pubkey = state
            .validator(validator_index)
            .map_err(|_| ApiError::Internal("a committee names an unknown validator"))?
            .pubkey;
        let slots = attestation_committee_slots(epoch, assignment.committee_index)
            .map_err(|_| ApiError::Internal("computing the committee's slots failed"))?;
        duties.push(AttestationCommitteeDuty {
            pubkey,
            validator_index,
            committee_index: assignment.committee_index,
            committee_length: assignment.committee_length,
            validator_committee_index: assignment.position,
            slots: slots.iter().map(u64::to_string).collect(),
        });
    }
    let dependent_root = block_root_at_or_before(
        &head_state,
        head_root,
        dependent_slot(&config, epoch, false),
    )?;
    Ok(serde_json::json!({
        "dependent_root": dependent_root,
        "execution_optimistic": store.is_beacon_optimistic(head_root),
        "data": duties,
    }))
}

// ── Head vote duties ────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct HeadVoteDuty {
    pubkey: BlsPubkey,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    validator_index: ValidatorIndex,
    /// The slots of the epoch the validator votes in, ascending, once each
    /// however many seats it holds in a slot's committee.
    slots: Vec<String>,
}

/// `POST /eth/v1/validator/duties/head_vote/{epoch}`, with the validator
/// indices to report on as a JSON array of decimal strings.
///
/// `get_head_vote_committee_assignments` reads the state's cached committee
/// window, which holds the previous, current and next epoch, so `epoch` is at
/// most one past the current one (the wall clock's or the head's, whichever is
/// later) and at least one before the head's. The head state answers as it is
/// when it is an EIP-8453 state of `epoch - 1` or later; otherwise (a heze head
/// before the fork, or a head lagging the clock) a copy is advanced to
/// `max(epoch - 1, EIP8453_FORK_EPOCH)`. A validator listed has at least one
/// slot. See [`dependent_slot`] for `dependent_root`.
async fn post_head_vote_duties(
    Path(epoch): Path<String>,
    State(store): State<Store>,
    Json(indices): Json<Vec<String>>,
) -> Response {
    let computed =
        tokio::task::spawn_blocking(move || head_vote_duties(&store, &epoch, &indices)).await;
    duties_response(computed)
}

fn head_vote_duties(
    store: &Store,
    epoch: &str,
    indices: &[String],
) -> Result<serde_json::Value, ApiError> {
    let epoch = parse_epoch(epoch)?;
    let wanted = parse_indices(indices)?;
    let config = store.config();
    require_eip8453_epoch(&config, epoch)?;
    let (head_root, head_state) = head(store)?;
    let head_epoch = compute_epoch_at_slot(head_state.slot());
    if epoch + 1 < head_epoch || epoch > epoch_upper_bound(store, head_epoch) {
        return Err(ApiError::BadRequest(
            "epoch is outside the range the node serves duties for",
        ));
    }
    let readable_from_head =
        matches!(*head_state, BeaconState::Eip8453(_)) && epoch <= head_epoch + 1;
    let state = if readable_from_head {
        head_state.clone()
    } else {
        let target = epoch.saturating_sub(1).max(config.eip8453_fork_epoch);
        state_for_epoch(store, head_root, target)?
    };

    let mut slots_of: BTreeMap<ValidatorIndex, Vec<Slot>> = BTreeMap::new();
    let start = compute_start_slot_at_epoch(epoch);
    for slot in start..start + preset::SLOTS_PER_EPOCH {
        let committee = get_head_vote_committee(&state, slot, &config)
            .map_err(|_| ApiError::Internal("the head vote committee is unavailable"))?;
        for &member in committee.iter() {
            if !wanted.contains(&member) {
                continue;
            }
            let slots = slots_of.entry(member).or_default();
            if slots.last() != Some(&slot) {
                slots.push(slot);
            }
        }
    }
    let mut duties = Vec::with_capacity(slots_of.len());
    for (validator_index, slots) in slots_of {
        let pubkey = state
            .validator(validator_index)
            .map_err(|_| ApiError::Internal("a committee names an unknown validator"))?
            .pubkey;
        duties.push(HeadVoteDuty {
            pubkey,
            validator_index,
            slots: slots.iter().map(u64::to_string).collect(),
        });
    }
    let dependent_root =
        block_root_at_or_before(&head_state, head_root, dependent_slot(&config, epoch, true))?;
    Ok(serde_json::json!({
        "dependent_root": dependent_root,
        "execution_optimistic": store.is_beacon_optimistic(head_root),
        "data": duties,
    }))
}

// ── Duty data ───────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct SlotQuery {
    slot: Slot,
}

/// A duty input the shared node could not give, as a response: the fork
/// choice not running yet, or the slot's instant not reached or missed, is a
/// `503` another node (or this one a moment later) may answer; a slot other
/// than the current one is the caller's mistake.
fn duty_error(err: DutyError) -> ApiError {
    match err {
        DutyError::Inactive => {
            ApiError::ServiceUnavailable("the EIP-8453 fork choice is not running yet")
        }
        DutyError::WrongSlot { .. } => {
            ApiError::BadRequest("the slot is not this node's current slot")
        }
        DutyError::NotYet { .. } => {
            ApiError::ServiceUnavailable("the slot's instant for this duty has not been reached")
        }
        DutyError::Missed { .. } => ApiError::ServiceUnavailable(
            "the slot's instant for this duty passed before this node computed it",
        ),
    }
}

fn require_eip8453_slot(config: &Config, slot: Slot) -> Result<(), ApiError> {
    if config.fork_at_epoch(compute_epoch_at_slot(slot)) >= ForkName::Eip8453 {
        Ok(())
    } else {
        Err(ApiError::BadRequest(
            "the slot is before EIP8453_FORK_EPOCH: it has no head votes or FG attestations",
        ))
    }
}

/// A JSON body tagged with EIP-8453's version, in the body and the header.
fn versioned(data: impl Serialize) -> Response {
    let response = crate::json_response(serde_json::json!({
        "version": ForkName::Eip8453.as_str(),
        "data": data,
    }));
    with_consensus_version(response, ForkName::Eip8453)
}

/// `GET /eth/v1/validator/head_vote_data?slot`: validator.md's "Head vote
/// data" for a committee member of `slot`, `get_ac_vote_head` as of the slot's
/// head vote deadline (`PAYLOAD_STATUS_PENDING` when it names the slot's own
/// block).
///
/// A slot before the fork is a `400`, as is one other than the node's current
/// slot; before the deadline, or with the fork choice not running, `503`. So
/// is a voted block whose execution payload is still unvalidated, as for
/// `attestation_data`.
async fn get_head_vote_data(
    Query(query): Query<SlotQuery>,
    State(store): State<Store>,
    Extension(node): Extension<SharedEip8453Node>,
    clock: Option<Extension<NodeClock>>,
) -> Response {
    let slot = query.slot;
    if let Err(err) = require_eip8453_slot(&store.config(), slot) {
        return err.into_response();
    }
    let now = now_ms(clock.as_ref());
    let data = match node.with(|n| n.vote_head(slot, now)) {
        Ok(Ok(data)) => eip8453::HeadVoteData::from(data),
        Ok(Err(err)) | Err(err) => return duty_error(err).into_response(),
    };
    if let Err(err) = require_validated(&store, data.beacon_block_root) {
        return err.into_response();
    }
    versioned(data)
}

/// What an attester selects its `AttestationData` from (validator.md,
/// "Attestation data"): the source state's target, and the head state's
/// justified checkpoint and finalized height.
#[derive(Debug, Serialize)]
struct FinalityAttestationInput {
    target: eip8453::HeightCheckpoint,
    justified: eip8453::HeightCheckpoint,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    finalized_height: u64,
}

/// `GET /eth/v1/validator/finality_attestation_input?slot`: the source and
/// head state reads of one `get_ac_frame` observation for an attester of
/// `slot`, at or after the slot's support cutoff (`Eip8453Node::
/// finality_attestation_input`), or `204 No Content` when there is no FG
/// source and the validator must not attest.
///
/// The validator client selects the data from these through its own
/// `FinalitySigningRecord`. Refusals as for [`get_head_vote_data`]: `400`
/// before the fork or for another slot than the current one, `503` before the
/// support cutoff or with the fork choice not running.
async fn get_finality_attestation_input(
    Query(query): Query<SlotQuery>,
    State(store): State<Store>,
    Extension(node): Extension<SharedEip8453Node>,
    clock: Option<Extension<NodeClock>>,
) -> Response {
    let slot = query.slot;
    if let Err(err) = require_eip8453_slot(&store.config(), slot) {
        return err.into_response();
    }
    let now = now_ms(clock.as_ref());
    let input = match node.with(|n| n.finality_attestation_input(slot, now)) {
        Ok(Ok(input)) => input,
        Ok(Err(err)) | Err(err) => return duty_error(err).into_response(),
    };
    match input {
        None => StatusCode::NO_CONTENT.into_response(),
        Some(input) => versioned(FinalityAttestationInput {
            target: input.target.into(),
            justified: input.justified.into(),
            finalized_height: input.finalized_height,
        }),
    }
}

// ── Submissions ─────────────────────────────────────────────────────────────

/// What a submitted message's gossip verdict means for the submitter: `Ok`
/// when it is now in the fork choice or the pool (a duplicate of one already
/// there included, as a resubmission after a timeout is), else why not.
fn submission_failure(outcome: Outcome) -> Option<std::borrow::Cow<'static, str>> {
    match outcome {
        Outcome::Accept | Outcome::Ignore(IgnoreReason::AlreadySeen) => None,
        other => {
            let (verdict, reason) = other.labels();
            Some(format!("{verdict}: {reason}").into())
        }
    }
}

/// `POST /eth/v1/beacon/pool/head_votes`: an array of signed
/// `HeadVoteMessage`s, JSON or SSZ (`Content-Type: application/octet-stream`).
///
/// Each runs through the `head_vote` gossip rules and, on `ACCEPT`, into the
/// fork choice (`gossip::head_vote::submit`), then is gossiped on `head_vote`.
/// A message already accepted counts as accepted and is not gossiped again.
/// `200` when every message was accepted, else `400` with the failures by
/// index, as the attestation pool endpoint answers; the rest were applied.
async fn post_pool_head_votes(
    State(store): State<Store>,
    Extension(node): Extension<SharedEip8453Node>,
    Extension(p2p): Extension<RpcToP2PRef>,
    clock: Option<Extension<NodeClock>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let messages = match decode_list::<eip8453::HeadVoteMessage>(&headers, &body) {
        Ok(messages) => messages,
        Err(err) => return err.into_response(),
    };
    let now = now_ms(clock.as_ref());
    let applied = tokio::task::spawn_blocking(move || {
        let mut failures = Vec::new();
        for (index, message) in messages.into_iter().enumerate() {
            let slot = message.data.slot;
            let validator = message.validator_index;
            let outcome = head_vote::submit(&store, &node, &message, now);
            let failure = match submission_failure(outcome) {
                Some(reason) => Some(reason),
                None if outcome == Outcome::Accept => p2p
                    .publish_head_vote(message)
                    .err()
                    .map(|_| "the network actor is not running".into()),
                None => None,
            };
            match failure {
                None => debug!(%slot, validator, "Accepted a head vote for gossip"),
                Some(reason) => {
                    warn!(%slot, validator, %reason, "Refused a submitted head vote");
                    failures.push(Failure {
                        index,
                        message: reason,
                    });
                }
            }
        }
        failures
    })
    .await;
    match applied {
        Ok(failures) => batch_response(failures, "some head votes failed validation"),
        Err(_) => ApiError::Internal("applying the head votes failed").into_response(),
    }
}

/// The EIP-8453 half of `POST /eth/v2/beacon/pool/attestations`
/// (`Eth-Consensus-Version: eip8453`): an array of EIP-8453
/// `SingleAttestation`s, JSON or SSZ.
///
/// Each runs through the `attestation_{subnet_id}` gossip rules on the subnet
/// its committee index names (`compute_subnet_for_attestation`) and, on
/// `ACCEPT`, into the shared node's pool for proposals
/// (`gossip::fg_attestation::submit`), then is gossiped on that subnet.
/// Failures as for [`post_pool_head_votes`].
pub(crate) async fn post_fg_attestations(
    store: Store,
    node: Option<SharedEip8453Node>,
    p2p: RpcToP2PRef,
    now: u64,
    headers: &HeaderMap,
    body: &[u8],
) -> Response {
    let attestations = match decode_list::<eip8453::SingleAttestation>(headers, body) {
        Ok(attestations) => attestations,
        Err(err) => return err.into_response(),
    };
    let Some(node) = node else {
        return duty_error(DutyError::Inactive).into_response();
    };
    let applied = tokio::task::spawn_blocking(move || {
        let config = store.config();
        let mut failures = Vec::new();
        for (index, attestation) in attestations.into_iter().enumerate() {
            let attester = attestation.attester_index;
            let epoch = attestation.epoch;
            let failure = if config.fork_at_epoch(epoch) < ForkName::Eip8453 {
                Some("the attestation's epoch is before EIP8453_FORK_EPOCH".into())
            } else {
                let subnet_id = fg_attestation::compute_subnet_for_attestation(
                    &config,
                    attestation.committee_index,
                );
                let outcome = fg_attestation::submit(&store, &node, &attestation, subnet_id, now);
                match submission_failure(outcome) {
                    Some(message) => Some(message),
                    None if outcome == Outcome::Accept => p2p
                        .publish_fg_attestation(subnet_id, attestation)
                        .err()
                        .map(|_| "the network actor is not running".into()),
                    None => None,
                }
            };
            match failure {
                None => debug!(epoch, attester, "Accepted an FG attestation for gossip"),
                Some(reason) => {
                    warn!(epoch, attester, %reason, "Refused a submitted FG attestation");
                    failures.push(Failure {
                        index,
                        message: reason,
                    });
                }
            }
        }
        failures
    })
    .await;
    match applied {
        Ok(failures) => batch_response(
            failures,
            "some attestations failed validation and were not published",
        ),
        Err(_) => ApiError::Internal("applying the attestations failed").into_response(),
    }
}

#[cfg(test)]
mod tests;
